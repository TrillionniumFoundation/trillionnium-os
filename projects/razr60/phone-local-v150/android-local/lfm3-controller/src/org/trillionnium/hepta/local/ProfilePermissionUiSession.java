package org.trillionnium.hepta.local;

import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import org.json.JSONObject;
import org.trillionnium.hepta.background.PermissionWindowObservation;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

/** Service-owned permission preparation, separate from LLM tools and root grants.
 * UI callbacks only enqueue one captured ordinary-deny choice. Binder work stays
 * on one process-wide worker and retains admission until its real finally block.
 */
final class ProfilePermissionUiSession {
    interface Listener { void onPermissionUiChanged(); }
    private static final ExecutorService WORKER=Executors.newSingleThreadExecutor();
    private static final AtomicReference<Work> ACTIVE=new AtomicReference<Work>();
    private final HeptaAccessibilityService service;
    private final Handler main=new Handler(Looper.getMainLooper());
    private final java.util.Set<Listener> listeners=new java.util.concurrent.CopyOnWriteArraySet<Listener>();
    private volatile Presentation presentation;
    private volatile VisibleOwner visibleOwner;

    /** MainActivity lifecycle and its real button create/revoke this identity.
     * A string, saved preview or a newly deserialized record cannot replace it. */
    private static final class VisibleOwner {
        final Object activity;
        final Work work;
        final ProfilePermissionInitialization.Preview preview;
        volatile boolean current=true;
        VisibleOwner(Object activity,Presentation shown){this.activity=activity;work=shown.work;preview=shown.preview;}
    }
    private static final class OwnerChoice implements ProfilePermissionInitialization.OwnerDenyChoice {
        final Work work;final VisibleOwner visible;final long selectedAt;
        OwnerChoice(Work work,VisibleOwner visible,long selectedAt){this.work=work;this.visible=visible;this.selectedAt=selectedAt;}
        @Override public void requireCurrent(ProfilePermissionInitialization.Preview expected,long now)throws Exception{
            work.check();Presentation shown=work.owner.presentation;
            if(now<selectedAt||now>=work.deadline||ACTIVE.get()!=work||work.ownerChoice!=this||!work.ownerDenyRequested
                    ||work.owner.visibleOwner!=visible||!visible.current||visible.work!=work||visible.preview!=expected
                    ||work.preview!=expected||shown==null||shown.work!=work||shown.preview!=expected)
                throw new IllegalStateException("ordinary owner deny choice is no longer visible/current for this permission request");
        }
    }

    static final class Presentation {
        final String taskId,message,state;
        final List<String> visibleOptions;
        final boolean denyAvailable,optionalLocation;
        private final Work work;
        private final ProfilePermissionInitialization.Preview preview;
        private Presentation(Work work,ProfilePermissionInitialization.Preview preview,String state,boolean denyAvailable){
            this.work=work;this.preview=preview;taskId=work.taskId;this.state=state;
            message=preview==null?"":preview.message;
            optionalLocation=preview!=null&&preview.optionalForExplicitRoute;
            List<String> labels=new ArrayList<String>();
            if(preview!=null)for(Map<String,Object> option:preview.visibleOptions){
                Object label=option.get("visible_label");if(label instanceof String&&!((String)label).isEmpty())labels.add((String)label);
            }
            visibleOptions=Collections.unmodifiableList(labels);this.denyAvailable=denyAvailable;
        }
    }
    ProfilePermissionUiSession(HeptaAccessibilityService service){if(service==null)throw new NullPointerException("service");this.service=service;}
    static boolean workPending(){return ACTIVE.get()!=null;}
    void bind(Listener listener){if(listener==null)throw new NullPointerException("listener");listeners.add(listener);notifyUi();}
    void unbind(Listener listener){listeners.remove(listener);}
    Presentation current(){return presentation;}
    /** Main-thread visibility bookkeeping only. It never starts or raises UI. */
    void ownerVisibility(Object activity,Presentation shown,boolean visible){
        if(Looper.myLooper()!=Looper.getMainLooper()||activity==null)throw new IllegalStateException("owner visibility must come from its main-thread Activity");
        VisibleOwner old=visibleOwner;
        boolean accept=visible&&shown!=null&&shown==presentation&&shown.preview!=null
                &&ACTIVE.get()==shown.work&&shown.work.owner==this&&!shown.work.cancelled();
        if(!accept){if(old!=null&&old.activity==activity){old.current=false;visibleOwner=null;}return;}
        if(old!=null&&old.current&&old.activity==activity&&old.work==shown.work&&old.preview==shown.preview)return;
        if(old!=null)old.current=false;
        visibleOwner=new VisibleOwner(activity,shown);
    }
    JSONObject evidence(String taskId){
        Presentation shown=presentation;Work active=ACTIVE.get();
        Work work=active!=null&&active.owner==this&&active.taskId.equals(taskId)?active:
                shown!=null&&shown.taskId.equals(taskId)?shown.work:null;
        if(work==null)return null;
        try{return new JSONObject().put("schema","hepta.permission-preparation-worker.v1").put("task_id",taskId)
                .put("worker_pending",ACTIVE.get()==work).put("worker_drained",work.done)
                .put("retired",work.retired).put("owner_deny_button_requested",work.ownerDenyRequested)
                .put("attempt_reserved",work.attemptReserved).put("attempt_result_written",work.attemptCompleted)
                .put("publication_sha256",work.publicationSha==null?JSONObject.NULL:work.publicationSha)
                .put("publication_elapsed_ms",work.publicationAt)
                .put("owner_visible_choice_registered",work.ownerChoice!=null)
                .put("deadline_elapsed_ms",work.deadline).put("business_model_used",false)
                .put("permission_grant_supported",false).put("automatic_retry",false)
                .put("visible_pixels_verified",false).put("ordinary_ui_state_published",work.preview!=null);}
        catch(org.json.JSONException impossible){throw new IllegalStateException(impossible);}
    }
    private void notifyUi(){
        for(final Listener listener:listeners)main.post(new Runnable(){public void run(){if(listeners.contains(listener))listener.onPermissionUiChanged();}});
    }
    private void publish(Work work,ProfilePermissionInitialization.Preview preview,String state,boolean deny){
        presentation=new Presentation(work,preview,state,deny);notifyUi();
    }
    /** Called only by MainActivity's current visible ordinary button. This is a
     * short flag operation; no Binder, file, native cancellation or waiting on UI. */
    boolean denyFromOwnerButton(Presentation expected,Object activity){
        Work work=ACTIVE.get();
        VisibleOwner visible=visibleOwner;
        if(Looper.myLooper()!=Looper.getMainLooper()||expected==null||expected!=presentation||work==null||work.owner!=this
                ||expected.work!=work||!expected.denyAvailable||visible==null||!visible.current||visible.activity!=activity
                ||visible.work!=work||visible.preview!=expected.preview)return false;
        synchronized(work.choice){
            if(work.retired||work.ownerDenyRequested||!work.waitingForOwner||work.preview!=expected.preview
                    ||work.cancelled()||SystemClock.elapsedRealtime()>=work.deadline)return false;
            work.ownerChoice=new OwnerChoice(work,visible,SystemClock.elapsedRealtime());
            work.ownerDenyRequested=true;work.waitingForOwner=false;work.choice.notifyAll();
        }
        publish(work,work.preview,"正在核对同一后台权限窗口并选择拒绝…",false);return true;
    }
    /** Immediate retirement is separate from the existing queued native cancel.
     * A stuck old Binder call still occupies ACTIVE and blocks later admission. */
    void retire(String taskId,String reason){
        Work work=ACTIVE.get();if(work==null||work.owner!=this||!work.taskId.equals(taskId))return;
        work.retired=true;synchronized(work.choice){work.choice.notifyAll();}
        VisibleOwner visible=visibleOwner;if(visible!=null&&visible.work==work){visible.current=false;visibleOwner=null;}
        publish(work,work.preview,"权限准备已停止，正在等待当前读取或点击退出。",false);
    }
    void prepare(String taskId,NativeAppGoal goal,TaskAuthorization.Gate authorization,
            QualificationScopeConfig.Bound scope,BackgroundSession background,File evidence,
            HeptaAccessibilityService.Cancellation cancellation,long originalDeadline)throws Exception{
        if(Looper.myLooper()==Looper.getMainLooper())throw new IllegalStateException("permission preparation waits only on controller worker");
        long now=SystemClock.elapsedRealtime();
        if(originalDeadline<=now)throw new IllegalStateException("permission preparation original task deadline expired");
        Work work=new Work(this,taskId,goal,authorization,scope,background,evidence,cancellation,
                Math.min(originalDeadline,now+ProfilePermissionInitialization.MAX_SESSION_MS));
        service.requirePermissionInitializationCurrent(taskId,scope,authorization,background,cancellation,work.deadline);
        if(!ACTIVE.compareAndSet(null,work))throw new IllegalStateException("previous permission work has not drained");
        VisibleOwner visible=visibleOwner;if(visible!=null)visible.current=false;visibleOwner=null;
        presentation=null;notifyUi();
        try{WORKER.execute(work);}
        catch(java.util.concurrent.RejectedExecutionException rejected){
            ACTIVE.compareAndSet(work,null);work.done=true;throw rejected;
        }
        // Unknown executor submission must retain admission. No caller-runs or
        // replacement executor can let another preparation overlap this scope.
        try{work.await();}
        finally{if(!work.done)retire(taskId,"controller_wait_abandoned");}
    }
    private static final class Work implements Runnable,ProfilePermissionInitialization.Platform,
            ProfilePermissionInitialization.Journal,ProfilePermissionInitialization.StatePublisher,ProfilePermissionAndroidAdapter.Guard {
        final ProfilePermissionUiSession owner;
        final String taskId;
        final NativeAppGoal goal;
        final TaskAuthorization.Gate authorization;
        final QualificationScopeConfig.Bound scope;
        final BackgroundSession background;
        final File evidence;
        final HeptaAccessibilityService.Cancellation cancellation;
        final long deadline;
        final Object choice=new Object(),finished=new Object();
        volatile boolean retired,done,waitingForOwner,ownerDenyRequested;
        volatile ProfilePermissionInitialization.Preview preview;
        volatile OwnerChoice ownerChoice;
        volatile String publicationSha;
        volatile long publicationAt=-1;
        ProfilePermissionAndroidAdapter adapter;
        Throwable failure;
        volatile boolean attemptReserved,attemptCompleted;
        Work(ProfilePermissionUiSession owner,String taskId,NativeAppGoal goal,TaskAuthorization.Gate authorization,
                QualificationScopeConfig.Bound scope,BackgroundSession background,File evidence,
                HeptaAccessibilityService.Cancellation cancellation,long deadline){
            if(taskId==null||!taskId.matches("[0-9a-f]{32}")||goal==null||authorization==null||scope==null
                    ||background==null||evidence==null||cancellation==null)throw new IllegalArgumentException("captured permission task required");
            this.owner=owner;this.taskId=taskId;this.goal=goal;this.authorization=authorization;this.scope=scope;
            this.background=background;this.evidence=evidence;this.cancellation=cancellation;this.deadline=deadline;
        }
        public long now(){return SystemClock.elapsedRealtime();}
        public boolean cancelled(){return retired||cancellation.isCancelled()
                ||!owner.service.permissionInitializationCurrent(taskId,scope,authorization,background);}
        public void check()throws Exception{
            if(cancelled()||now()>=deadline)throw new IllegalStateException("permission preparation cancelled, retired or expired");
        }
        public void authority()throws Exception{
            check();owner.service.requirePermissionInitializationCurrent(taskId,scope,authorization,background,cancellation,deadline);check();
        }
        public ProfilePermissionInitialization.Snapshot observe()throws Exception{check();return adapter.observe();}
        public boolean clickOrdinaryDeny(ProfilePermissionInitialization.Dispatch dispatch)throws Exception{check();return adapter.clickOrdinaryDeny(dispatch);}
        private String write(String leaf,Map<String,Object> value)throws Exception{
            byte[] bytes=new JSONObject(value).toString(2).getBytes(StandardCharsets.UTF_8);
            MobiMindPrivateFiles.writeNew(new File(evidence,leaf),bytes);return HeptaAccessibilityService.sha(bytes);
        }
        public ProfilePermissionInitialization.PublicationReceipt publish(ProfilePermissionInitialization.Preview value)throws Exception{
            check();if(preview!=null)throw new IllegalStateException("permission preview is already published for this preparation");
            publicationSha=write("profile-permission-preview.json",value.evidence());check();preview=value;
            waitingForOwner=!value.optionalForExplicitRoute;
            boolean deny=false;
            for(Map<String,Object> option:value.visibleOptions)if(Boolean.TRUE.equals(option.get("input_supported"))
                    &&Boolean.TRUE.equals(option.get("enabled")))deny=true;
            // Publication is ordinary application UI state, not a claim that a
            // hidden Activity rendered pixels. Never start/raise an Activity.
            owner.publish(this,value,value.optionalForExplicitRoute
                    ?"查询已指定出发与到达城市，正在核对并拒绝本次位置权限请求。"
                    :"后台应用出现系统权限请求。可查看原文并选择拒绝，或停止任务。",waitingForOwner&&deny);
            check();publicationAt=now();
            return new ProfilePermissionInitialization.PublicationReceipt(value,publicationAt,publicationSha,true);
        }
        public void reserve(Map<String,Object> attempt)throws Exception{
            check();if(attemptReserved)throw new IllegalStateException("permission input attempt cannot be replayed");
            // Reserve before IO: a failed or ambiguous journal write is still spent.
            attemptReserved=true;write("profile-permission-deny-attempt.json",attempt);check();
        }
        public void complete(Map<String,Object> result)throws Exception{
            if(!attemptReserved||attemptCompleted)throw new IllegalStateException("permission result has no unique reserved attempt");
            write("profile-permission-deny-result.json",result);attemptCompleted=true;
        }
        private String state()throws Exception{authority();String state=background.readPreparation(cancellation,deadline);check();return state;}
        private void waitBriefly()throws Exception{synchronized(choice){check();choice.wait(Math.min(100,Math.max(1,deadline-now())));}check();}
        private String readyOrPermission()throws Exception{
            for(;;){String state=state();if(!"WAITING".equals(state))return state;waitBriefly();}
        }
        @Override public void run(){
            try{
                authority();
                adapter=new ProfilePermissionAndroidAdapter(owner.service,background,new HeptaAccessibilityService.Cancellation(){
                    public boolean isCancelled(){return Work.this.cancelled();}},deadline,this);
                String initial=readyOrPermission();
                if("APP_READY".equals(initial))return;
                if(!"PERMISSION_PENDING".equals(initial))throw new IllegalStateException("unrecognized permission preparation state");
                ProfilePermissionInitialization.Snapshot first=observe();
                ProfilePermissionInitialization.Session session=new ProfilePermissionInitialization.Session(goal,background.ownerSha256,
                        first.identity,first.physicalIdentities,now(),deadline,new ProfilePermissionInitialization.ReadProvenance(){
                    public void require(PermissionWindowObservation observation,long now)throws Exception{
                        check();background.requirePermissionWindow(observation,now);
                    }
                });
                ProfilePermissionInitialization.Preview published=session.publish(first,this,this);
                ProfilePermissionInitialization.Receipt receipt;
                if(published.optionalForExplicitRoute){
                    receipt=session.denyOptionalLocationForExplicitRoute(published,this,this);
                }else{
                    synchronized(choice){while(!ownerDenyRequested){check();choice.wait(Math.min(100,Math.max(1,deadline-now())));}}
                    check();receipt=session.denyFromOwnerUi(published,ownerChoice,this,this);
                }
                check();owner.publish(this,published,receipt.apiAccepted
                        ?"拒绝请求已交给系统，正在重新核对后台应用页面。"
                        :"系统未接受拒绝请求，正在重新核对页面；不会重试该点击。",false);
                // A deny API return cannot grant continuation. Only a newly
                // authenticated ordinary-App readiness proof can end preparation.
                String after=null;long settle=Math.min(deadline,now()+2000);
                while(now()<settle){
                    after=state();if("APP_READY".equals(after))break;
                    if(!"WAITING".equals(after)&&!"PERMISSION_PENDING".equals(after))
                        throw new IllegalStateException("unexpected post-deny preparation state");
                    waitBriefly();
                }
                if(!"APP_READY".equals(after))throw new IllegalStateException("permission request remains or a new request appeared after the single deny attempt");
                authority();owner.publish(this,published,"后台应用权限准备已结束，继续核对原任务。",false);
            }catch(Throwable error){
                failure=error;owner.publish(this,preview,"权限准备未完成："+HeptaAccessibilityService.message(error),false);
            }finally{
                try{if(adapter!=null)adapter.close();}
                catch(Throwable close){if(failure==null)failure=close;else failure.addSuppressed(close);}
                if(!ACTIVE.compareAndSet(this,null)){
                    IllegalStateException changed=new IllegalStateException("permission worker slot identity changed");
                    if(failure==null)failure=changed;else failure.addSuppressed(changed);
                }
                synchronized(finished){done=true;finished.notifyAll();}
                owner.notifyUi();
            }
        }
        void await()throws Exception{
            synchronized(finished){
                while(!done){check();finished.wait(Math.min(50,Math.max(1,deadline-now())));}
                if(failure instanceof Exception)throw (Exception)failure;
                if(failure instanceof Error)throw (Error)failure;
                check();
            }
        }
    }
}
