package org.trillionnium.hepta.local;
import android.content.pm.*;
import android.os.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.json.JSONObject;
import org.trillionnium.hepta.background.FixedIntentTarget;

/** Actual MainActivity beginTask -> LocalTaskSession schedule -> full LocalTaskController.
 * Installed-app availability, Android display/IO and model endpoint are explicit host fakes.
 * A host model is a deterministic callback; no phone or model inference is started. */
public final class NativeAppRoutingEntryHostTest {
    static final String CTRIP="ctrip.android.view",HELPER=BackgroundTaskTarget.HELPER;
    static final String OWNER="查一下2099年11月17日北京到上海的单程机票，1名成人";
    static final List<String> names=new ArrayList<String>();static int assertions;
    interface Body{void run()throws Exception;}
    static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    static void test(String name,Body run)throws Exception{run.run();names.add(name);}
    static void rejects(Body run)throws Exception{
        boolean refused=false;try{run.run();}catch(IllegalArgumentException|IllegalStateException expected){refused=true;}
        check(refused,"expected actual identity/admission refusal");
    }
    static Set<String> packages(String... values){return new TreeSet<String>(Arrays.asList(values));}
    static BackgroundSession.Selection selection(String owner){return new BackgroundSession.Selection(
            BackgroundTaskTarget.resolveExplicitSelection(owner,CTRIP,packages(CTRIP,HELPER)));}
    static final class NativeUi extends ScopeUiFixture {
        String initial=CTRIP;boolean choiceCurrent=true;int checks;
        NativeUi(LocalTaskSession tasks,LocalModelEngine engine){super(tasks,engine);backgroundMode.setChecked(true);backgroundPackages.addAll(packages(CTRIP,HELPER));}
        @Override String selectedBackgroundPackage(){return initial;}
        @Override void requireCurrentBackgroundChoice(){checks++;if(!choiceCurrent)throw new IllegalStateException("synthetic changed installed/owner choice");}
    }
    static void installed(QualificationScopeHostTest.Env e)throws Exception{
        PackageInfo p=new PackageInfo();p.packageName=CTRIP;p.version=1779;
        p.applicationInfo=new ApplicationInfo();p.applicationInfo.packageName=CTRIP;p.applicationInfo.uid=12345;
        Path apk=e.dir.resolve("installed/ctrip-host-fixture.apk");
        QualificationScopeHostTest.write(apk,"SYNTHETIC HOST APP NOT INSTALLED BY THIS TEST".getBytes(StandardCharsets.UTF_8),0644);
        p.applicationInfo.sourceDir=apk.toString();e.pm.packages.put(CTRIP,p);
        e.service.launchable.put(CTRIP,"携程旅行");e.service.prepare(CTRIP);
    }
    static LocalModelEngine engine(QualificationScopeHostTest.Env e){
        return new LocalModelEngine(Paths.get(e.pm.packages.get("org.trillionnium.hepta.local").applicationInfo.sourceDir).toFile(),e.runtime);
    }
    static void flush(LocalTaskSession tasks)throws Exception{
        java.lang.reflect.Field f=LocalTaskSession.class.getDeclaredField("recoveryWorker");f.setAccessible(true);
        ExecutorService io=(ExecutorService)f.get(tasks);
        io.submit(()->{}).get(3,TimeUnit.SECONDS);Handler.drain();io.submit(()->{}).get(3,TimeUnit.SECONDS);Handler.drain();
    }
    static void uiPending(String owner)throws Exception{
        try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            installed(e);
            QualificationScopeHostTest.CountingModel model=new QualificationScopeHostTest.CountingModel(e,"done",CTRIP,null);
            e.service.testInference=model;LocalModelEngine engine=engine(e);LocalTaskSession tasks=new LocalTaskSession(e.service,engine);
            NativeUi ui=new NativeUi(tasks,engine);ui.taskInput.setText(owner);Handler.hold=true;
            check(ui.start(),"actual ordinary UI schedules native selection");
            BackgroundSession.Selection frozen=tasks.backgroundSelection;TaskAuthorization auth=tasks.taskAuthorization;
            check(frozen!=null&&frozen.taskTarget!=null&&CTRIP.equals(frozen.initialPackage),"actual Session receives explicit target");
            frozen.requireTaskTarget(owner,auth);
            JSONObject wire=frozen.json(),readback=new JSONObject(wire.toString());
            check(WebEvidenceReceipt.same(wire,readback),"nested original Selection survives actual canonical equality through host JSON IO");
            JSONObject changed=new JSONObject(wire.toString()),proof=changed.getJSONObject("owner_task_selection");
            proof.put("owner_sha256","0000000000000000000000000000000000000000000000000000000000000000");
            changed.put("owner_task_selection",proof);
            check(!WebEvidenceReceipt.same(wire,changed),"nested OWNER mutation is still rejected by unchanged canonical comparison");
            check(tasks.pending&&model.calls==0,"durable/pending boundary precedes synthetic model callback");
            check("user_button".equals(tasks.origin)&&tasks.instructionSha.equals(FixedIntentTarget.payloadSha256(owner)),"original owner and UI origin retained");
            check(!auth.allowedTools.contains("web.search")&&frozen.allowedPackages.equals(Collections.singletonList(CTRIP)),"no browser/helper in native scope");
            check(ui.checks==1,"actual beginTask checked current saved selection");
            ui.initial=HELPER;ui.backgroundPackages.clear();ui.backgroundPackages.add(HELPER);ui.taskInput.setText("改变后的下一条任务");
            check(tasks.backgroundSelection==frozen&&tasks.taskAuthorization==auth,"later UI edits cannot replace frozen references");
            frozen.requireTaskTarget(owner,auth);
            tasks.stop();flush(tasks);
            check(!tasks.pending&&model.calls==0&&e.service.effects()==0,"cancelled reservation cannot create helper/model/app action");
        }
    }
    static void liveNative(String owner)throws Exception{
        try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            installed(e);e.service.root.window.display=6;
            BackgroundSession.controllerDisplay=6;
            try{
                QualificationScopeHostTest.CountingModel model=new QualificationScopeHostTest.CountingModel(e,"done",CTRIP,null);
                e.controller=new LocalTaskController(e.service,model);
                BackgroundSession.Selection s=selection(owner);TaskAuthorization auth=TaskAuthorization.parse(owner).forExecutionSelection(s);
                final LocalTaskController.TaskResult[] terminal={null};CountDownLatch done=new CountDownLatch(1);
                check(e.controller.start(owner,null,auth,s,new LocalTaskController.Listener(){
                    public void onState(String v){}public void onFinished(LocalTaskController.TaskResult v){terminal[0]=v;done.countDown();}
                }),"actual Controller starts explicit native App");
                check(done.await(10,TimeUnit.SECONDS),"actual Controller returns terminal");
                check(model.calls==1&&e.service.effects()==0,"one deterministic model callback, no helper or app effect");
                check(terminal[0]!=null&&terminal[0].cleanupKnown&&!terminal[0].modelReportedSuccess,"routing alone cannot invent business success");
                check("partial".equals(terminal[0].status)||"failed".equals(terminal[0].status),"no provider result created by routing");
                check(e.service.taskWeb==null,"throwing Web constructor/IO boundary remains unreachable");
                Path entry=terminal[0].evidenceDirectory.toPath().resolve("background-bootstrap.json");
                check(Files.isRegularFile(entry),"actual native background initialization evidence exists");
            }finally{BackgroundSession.controllerDisplay=-1;}
        }
    }
    public static void main(String[] args)throws Exception{
        Path out=Paths.get(args[0]);Files.createDirectories(out);QualificationScopeHostTest.output=out;
        test("actual_ui_to_session_preserves_native_target_and_original_owner",()->uiPending(OWNER));
        test("actual_ui_null_native_goal_does_not_fallback_to_helper",()->uiPending(OWNER+"。不要点击"));
        test("actual_ui_refuses_stale_saved_app_selection_before_schedule",()->{
            try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
                installed(e);LocalModelEngine engine=engine(e);LocalTaskSession tasks=new LocalTaskSession(e.service,engine);
                NativeUi ui=new NativeUi(tasks,engine);ui.choiceCurrent=false;ui.taskInput.setText(OWNER);
                check(!ui.start()&&!tasks.pending&&tasks.backgroundSelection==null,"failed current-choice IO cannot schedule");
                check(e.service.lease==null&&e.service.effects()==0,"no synthetic lease or app effect");
            }
        });
        test("actual_ui_original_no_open_clause_refuses_background_bootstrap",()->{
            try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
                installed(e);LocalModelEngine engine=engine(e);LocalTaskSession tasks=new LocalTaskSession(e.service,engine);
                NativeUi ui=new NativeUi(tasks,engine);ui.taskInput.setText("查看携程当前页面。只允许等待和结束任务");
                check(!ui.start()&&!tasks.pending&&tasks.backgroundSelection==null,"binding does not add required open permission");
                check(e.service.lease==null&&e.service.effects()==0,"no effect after original tool restriction");
            }
        });
        test("actual_schedule_rejects_replacement_selection_before_journal_or_controller",()->{
            try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
                installed(e);LocalTaskSession tasks=new LocalTaskSession(e.service,engine(e));
                BackgroundSession.Selection s=selection(OWNER),replacement=new BackgroundSession.Selection(s.taskTarget);
                TaskAuthorization auth=TaskAuthorization.parse(OWNER).forExecutionSelection(s);
                rejects(()->tasks.schedule(OWNER,"user_button",null,null,auth,replacement,500));
                check(!tasks.pending&&tasks.controller==null&&e.service.lease==null,"refusal precedes reservation/controller");
                check(!Files.exists(e.dir.resolve("control-session.json")),"wrong Selection cannot create session record");
            }
        });
        test("actual_controller_start_rejects_replacement_selection_before_lease",()->{
            try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
                installed(e);QualificationScopeHostTest.CountingModel model=new QualificationScopeHostTest.CountingModel(e,"done",CTRIP,null);
                e.controller=new LocalTaskController(e.service,model);
                BackgroundSession.Selection s=selection(OWNER),replacement=new BackgroundSession.Selection(s.taskTarget);
                TaskAuthorization auth=TaskAuthorization.parse(OWNER).forExecutionSelection(s);
                rejects(()->e.controller.start(OWNER,null,auth,replacement,new LocalTaskController.Listener(){
                    public void onState(String v){}public void onFinished(LocalTaskController.TaskResult v){throw new AssertionError("rejected admission cannot complete");}
                }));
                check(!e.controller.isRunning()&&model.calls==0&&e.service.lease==null&&e.service.effects()==0,"no lease/model/effect after wrong Selection");
            }
        });
        test("actual_full_controller_native_flight_never_creates_web_session",()->liveNative(OWNER));
        test("actual_full_controller_unknown_native_goal_never_creates_web_session",()->liveNative("查看携程当前页面。不要点击"));
        JSONObject result=new JSONObject().put("schema","hepta.native-app-routing-entry-host.v1")
                .put("all_pass",true).put("cases",names.size()).put("assertions",assertions).put("case_names",names)
                .put("phone_operations",0).put("model_inference",false).put("android_runtime",false)
                .put("installed_app_and_display_io","synthetic boundary")
                .put("provider_or_business_verified",false);
        Files.write(out.resolve("CASES.json"),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(result.toString());
    }
}
