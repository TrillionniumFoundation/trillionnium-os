package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Read-only evidence for retiring one owned task; never a business window or input authority. */
public final class ProfilePermissionTransient {
    public static final String PACKAGE="com.android.permissioncontroller";
    public static final String COMPONENT=PACKAGE+"/com.android.permissioncontroller.permission.ui.GrantPermissionsActivity";
    public static final String ACTION="android.content.pm.action.REQUEST_PERMISSIONS";
    public static final String APK="/apex/com.android.permission/priv-app/PermissionController@W1VL36M-53-ST9.1/PermissionController.apk";
    public static final String APK_SHA="1eab1c53a6677c34442b032eb9bcc20834274fb485281d6f6b65754360280141";
    public static final String SIGNER="1837e156dc1364d316117b0ef986136babe4bd3f84fc2922484c2a396ed86ed5";
    public static final long MAX_AGE_MS=2000;
    private static final String COMP="[A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+";
    private static final Pattern TASK=Pattern.compile("( +)\\* Task\\{([^\\s{}]+) #([0-9]+) ([^{}\\r\\n]+)\\}");
    // Exact ActivityRecord.toString suffixes; finishing contributes its own inner '}'.
    private static final Pattern HIST=Pattern.compile("( +)\\* Hist +#([0-9]+): ActivityRecord\\{([^\\s{}]+) u([0-9]+) ("+COMP+") t([0-9]+)( f\\}| isExiting| f\\} isExiting)?\\}");

    /** Only ProfilePackages supplies this in production, from the same-user framework PM. */
    public static final class Authority {
        public final int user,uid;
        public final String configuredPackage,apk,apkSha,signer;
        public final long version;
        public final boolean system,privileged,installed,enabled;
        public Authority(int user,int uid,String configuredPackage,String apk,String apkSha,String signer,
                long version,boolean system,boolean privileged,boolean installed,boolean enabled)throws Exception {
            this.user=user;this.uid=uid;this.configuredPackage=configuredPackage;this.apk=apk;
            this.apkSha=apkSha;this.signer=signer;this.version=version;this.system=system;
            this.privileged=privileged;this.installed=installed;this.enabled=enabled;
            need(user>0&&uid==(long)user*100000+10335&&PACKAGE.equals(configuredPackage)
                    &&APK.equals(apk)&&APK_SHA.equals(apkSha)&&SIGNER.equals(signer)&&version==330000000L
                    &&system&&privileged&&installed&&enabled,"PROFILE_PERMISSION_SYSTEM_IDENTITY_UNPROVEN");
        }
        public boolean same(Authority other){return other!=null&&user==other.user&&uid==other.uid
                &&version==other.version&&system==other.system&&privileged==other.privileged
                &&installed==other.installed&&enabled==other.enabled&&Objects.equals(configuredPackage,other.configuredPackage)
                &&Objects.equals(apk,other.apk)&&Objects.equals(apkSha,other.apkSha)&&Objects.equals(signer,other.signer);}
    }

    /** Private construction. Serialized evidence cannot create or replay this authority. */
    public static final class Proof {
        private final ProfileTarget target;
        private final BackgroundOwnedSingleTask.Task root,leaf;
        private final Authority authority;
        private final long started;
        private final String digest,activity,resultTo;
        private Proof(ProfileTarget target,BackgroundOwnedSingleTask.Task root,BackgroundOwnedSingleTask.Task leaf,
                Authority authority,long started,String digest,String activity,String resultTo){
            this.target=target;this.root=root;this.leaf=leaf;this.authority=authority;this.started=started;
            this.digest=digest;this.activity=activity;this.resultTo=resultTo;
        }
        public void requireMatches(ProfileTarget target,BackgroundOwnedSingleTask.Task root,
                BackgroundOwnedSingleTask.Task leaf,long now)throws Exception{
            need(this.target.same(target)&&sameTaskInfo(this.root,root)&&sameTaskInfo(this.leaf,leaf)
                    &&now>=started&&now-started<=MAX_AGE_MS,"PROFILE_PERMISSION_PROOF_STALE_OR_CHANGED");
        }
        public Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();
            out.put("schema","hepta.profile-permission-transient.v1");out.put("source","bounded_framework_activity_chain_and_same_user_system_pm");
            out.put("display_id",leaf.display);out.put("root_task_id",root.id);out.put("leaf_task_id",leaf.id);
            out.put("user_id",authority.user);out.put("target_sha256",target.sha256);out.put("requester_uid",target.fullUid);
            out.put("permission_uid",authority.uid);out.put("component",COMPONENT);out.put("action",ACTION);
            out.put("activity_record",activity);out.put("result_to_activity_record",resultTo);
            out.put("activities_sha256",digest);out.put("system_apk_sha256",authority.apkSha);out.put("system_signer_sha256",authority.signer);
            out.put("observed_start_elapsed_ms",started);out.put("business_observation_allowed",false);
            out.put("permission_input_allowed",false);out.put("serialized_evidence_is_authority",false);
            return Collections.unmodifiableMap(out);
        }
    }

    public static boolean sameTaskInfo(BackgroundOwnedSingleTask.Task a,BackgroundOwnedSingleTask.Task b){
        return a!=null&&b!=null&&a.id==b.id&&a.display==b.display&&a.user==b.user&&a.parent==b.parent
                &&a.uid==b.uid&&a.topUid==b.topUid&&a.activities==b.activities&&a.running==b.running&&a.visible==b.visible
                &&Objects.equals(a.token,b.token)&&a.cookies.equals(b.cookies)&&Objects.equals(a.intentComponent,b.intentComponent)
                &&Objects.equals(a.base,b.base)&&Objects.equals(a.top,b.top)&&Objects.equals(a.real,b.real)&&Objects.equals(a.orig,b.orig);
    }

    /** A read may be retried only while its original live task capabilities remain identical.
     * A paired Activity-cookie retirement also needs the coordinator's retained private
     * capabilities. Neither signal is a permission proof, window, or cleanup authority. */
    static final class ReadChanged extends Exception {
        private static final long serialVersionUID=1L;
        final BackgroundOwnedSingleTask.Task root,leaf;final String code;
        private final BackgroundOwnedSingleTask.Task beforeRoot,beforeLeaf;
        private final Object retiredCookie;
        private ReadChanged(BackgroundOwnedSingleTask.Task root,BackgroundOwnedSingleTask.Task leaf,String code){
            this(root,leaf,root,leaf,null,code);
        }
        private ReadChanged(BackgroundOwnedSingleTask.Task beforeRoot,BackgroundOwnedSingleTask.Task beforeLeaf,
                BackgroundOwnedSingleTask.Task root,BackgroundOwnedSingleTask.Task leaf,Object retiredCookie,String code){
            super(code);this.beforeRoot=beforeRoot;this.beforeLeaf=beforeLeaf;
            this.root=root;this.leaf=leaf;this.retiredCookie=retiredCookie;this.code=code;
        }
        void requireRetainedCookieRetirement(BackgroundOwnedSingleTask.Task retainedRoot,
                BackgroundOwnedSingleTask.Task retainedLeaf,Object rootCookie,Object launchCookie)throws Exception{
            if(retiredCookie==null)return;
            need(sameTaskCapability(retainedRoot,beforeRoot)&&sameTaskCapability(retainedRoot,root)
                    &&rootCookie!=null&&!Objects.equals(rootCookie,launchCookie)
                    &&retainedRoot.cookies.contains(rootCookie)&&beforeRoot.cookies.contains(rootCookie)
                    &&root.cookies.contains(rootCookie),"PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ");
            // Initial admission still needs its live launch cookie. Only an already
            // claimed leaf may lose that Activity cookie, on the very same Binder.
            need(sameTaskCapability(retainedLeaf,beforeLeaf)&&sameTaskCapability(retainedLeaf,leaf)
                    &&launchCookie!=null&&Objects.equals(retiredCookie,launchCookie)
                    &&beforeRoot.cookies.contains(launchCookie)&&beforeLeaf.cookies.contains(launchCookie)
                    &&!root.cookies.contains(launchCookie)&&!leaf.cookies.contains(launchCookie),
                    "PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ");
        }
        void requireRoot(BackgroundOwnedSingleTask.Task current)throws Exception{
            need(sameReadIdentity(root,current),"PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ");
        }
        void requireLeaf(BackgroundOwnedSingleTask.Task current)throws Exception{
            need(sameReadIdentity(leaf,current),"PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ");
        }
        void requireAttempt(ReadChanged current)throws Exception{
            requireRoot(current.beforeRoot);requireLeaf(current.beforeLeaf);
        }
    }
    static boolean sameReadIdentity(BackgroundOwnedSingleTask.Task a,BackgroundOwnedSingleTask.Task b){
        return a!=null&&b!=null&&a.id>0&&a.token!=null&&b.token!=null
                &&a.id==b.id&&a.display==b.display&&a.user==b.user&&a.parent==b.parent&&a.uid==b.uid
                &&Objects.equals(a.token,b.token)&&a.cookies.equals(b.cookies)
                &&Objects.equals(a.intentComponent,b.intentComponent)&&Objects.equals(a.base,b.base)
                &&Objects.equals(a.real,b.real)&&Objects.equals(a.orig,b.orig);
    }
    private static boolean sameTaskCapability(BackgroundOwnedSingleTask.Task a,BackgroundOwnedSingleTask.Task b){
        return a!=null&&b!=null&&a.id>0&&a.token!=null&&b.token!=null
                &&a.id==b.id&&a.display==b.display&&a.user==b.user&&a.parent==b.parent&&a.uid==b.uid
                &&Objects.equals(a.token,b.token);
    }
    private static boolean sameReadCapability(BackgroundOwnedSingleTask.Task a,BackgroundOwnedSingleTask.Task b){
        return sameTaskCapability(a,b)&&Objects.equals(a.intentComponent,b.intentComponent)
                &&Objects.equals(a.base,b.base)&&Objects.equals(a.real,b.real)&&Objects.equals(a.orig,b.orig);
    }
    private static Object singleRemovedCookie(BackgroundOwnedSingleTask.Task before,BackgroundOwnedSingleTask.Task after){
        if(before==null||after==null||before.cookies.size()!=after.cookies.size()+1
                ||before.cookies.contains(null)||after.cookies.contains(null)
                ||new HashSet<Object>(before.cookies).size()!=before.cookies.size()
                ||new HashSet<Object>(after.cookies).size()!=after.cookies.size()
                ||!before.cookies.containsAll(after.cookies))return null;
        List<Object> removed=new ArrayList<Object>(before.cookies);removed.removeAll(after.cookies);
        if(removed.size()!=1)return null;
        List<Object> kept=new ArrayList<Object>(before.cookies);kept.remove(removed.get(0));
        return kept.equals(after.cookies)?removed.get(0):null;
    }
    private static boolean permissionExitPresentation(ProfileTarget target,BackgroundOwnedSingleTask.Task before,
            BackgroundOwnedSingleTask.Task after){
        return target!=null&&before!=null&&after!=null&&COMPONENT.equals(before.top)
                &&before.topUid==(long)target.profile.userId*100000+10335
                &&after.topUid==target.fullUid&&targetComponent(target,after.top)
                &&before.activities>=2&&before.activities<=2048&&after.activities==before.activities-1
                &&before.running&&before.visible&&after.running&&after.visible;
    }
    /** This admits only another read of the actual leaf; it grants no retry or authority. */
    static boolean mayReadRetiringPermissionRoot(ProfileTarget target,BackgroundOwnedSingleTask.Task before,
            BackgroundOwnedSingleTask.Task after){
        return sameReadCapability(before,after)&&permissionExitPresentation(target,before,after)
                &&singleRemovedCookie(before,after)!=null;
    }
    private static boolean knownReadPresentation(ProfileTarget target,BackgroundOwnedSingleTask.Task task,int permissionUid){
        return task!=null&&task.activities>0&&task.activities<=2048
                &&((task.topUid==target.fullUid&&targetComponent(target,task.top))
                    ||(task.topUid==permissionUid&&COMPONENT.equals(task.top)));
    }
    static void requireSameRead(ProfileTarget target,BackgroundOwnedSingleTask.Task root,
            BackgroundOwnedSingleTask.Task leaf,BackgroundOwnedSingleTask.Task currentRoot,
            BackgroundOwnedSingleTask.Task currentLeaf)throws Exception{
        if(!sameReadIdentity(root,currentRoot)&&mayReadRetiringPermissionRoot(target,root,currentRoot)){
            Object removed=singleRemovedCookie(root,currentRoot);
            need(sameReadCapability(leaf,currentLeaf)&&permissionExitPresentation(target,leaf,currentLeaf)
                    &&root.activities==leaf.activities&&currentRoot.activities==currentLeaf.activities
                    &&Objects.equals(removed,singleRemovedCookie(leaf,currentLeaf)),
                    "PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ");
            // The coordinator must still prove the exact retained root/leaf and its own
            // two cookies. Pin the after pair; none of this unstable read may be used.
            throw new ReadChanged(root,leaf,currentRoot,currentLeaf,removed,
                    "PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ");
        }
        need(sameReadIdentity(root,currentRoot),"PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ");
        need(sameReadIdentity(leaf,currentLeaf),"PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ");
        boolean rootSame=sameTaskInfo(root,currentRoot),leafSame=sameTaskInfo(leaf,currentLeaf);
        if(rootSame&&leafSame)return;
        String code=rootSame?"PROFILE_PERMISSION_LEAF_CHANGED_DURING_READ":"PROFILE_PERMISSION_ROOT_CHANGED_DURING_READ";
        need(target!=null&&knownReadPresentation(target,currentRoot,root.topUid)
                &&knownReadPresentation(target,currentLeaf,root.topUid),code);
        throw new ReadChanged(root,leaf,code);
    }
    /** Fixed-size, read-only mismatch diagnostics. Binder/cookie objects never leave the process. */
    static Map<String,Object> readMismatch(String phase,long observed,int rootCount,int leafCount,
            BackgroundOwnedSingleTask.Task root,BackgroundOwnedSingleTask.Task leaf,
            BackgroundOwnedSingleTask.Task currentRoot,BackgroundOwnedSingleTask.Task currentLeaf){
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("schema","hepta.profile-permission-read-mismatch.v1");out.put("phase",phase);
        out.put("observed_elapsed_ms",observed);out.put("root_count",rootCount);out.put("leaf_count",leafCount);
        out.put("root",readDifference(root,currentRoot));out.put("leaf",readDifference(leaf,currentLeaf));
        out.put("serialized_evidence_is_authority",false);out.put("allows_input_or_model_resumption",false);
        return Collections.unmodifiableMap(out);
    }
    private static Map<String,Object> readDifference(BackgroundOwnedSingleTask.Task before,BackgroundOwnedSingleTask.Task after){
        Map<String,Object> out=new LinkedHashMap<String,Object>();Map<String,Object> equal=new LinkedHashMap<String,Object>();
        out.put("before",readSummary(before));out.put("after",readSummary(after));
        if(before!=null&&after!=null){
            equal.put("task_id",before.id==after.id);equal.put("display_id",before.display==after.display);
            equal.put("user_id",before.user==after.user);equal.put("parent_task_id",before.parent==after.parent);
            equal.put("full_uid",before.uid==after.uid);equal.put("top_activity_info_uid",before.topUid==after.topUid);
            equal.put("activity_count",before.activities==after.activities);equal.put("running",before.running==after.running);
            equal.put("visible",before.visible==after.visible);equal.put("actual_binder",Objects.equals(before.token,after.token));
            equal.put("actual_cookies",before.cookies.equals(after.cookies));equal.put("intent",Objects.equals(before.intentComponent,after.intentComponent));
            equal.put("base",Objects.equals(before.base,after.base));equal.put("top",Objects.equals(before.top,after.top));
            equal.put("real",Objects.equals(before.real,after.real));equal.put("orig",Objects.equals(before.orig,after.orig));
        }
        out.put("equal_fields",Collections.unmodifiableMap(equal));
        out.put("complete_identity_equal",sameReadIdentity(before,after));out.put("complete_taskinfo_equal",sameTaskInfo(before,after));
        return Collections.unmodifiableMap(out);
    }
    private static Map<String,Object> readSummary(BackgroundOwnedSingleTask.Task task){
        if(task==null)return null;Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("task_id",task.id);out.put("display_id",task.display);out.put("user_id",task.user);
        out.put("parent_task_id",task.parent);out.put("full_uid",task.uid);out.put("top_activity_info_uid",task.topUid);
        out.put("activity_count",task.activities);out.put("running",task.running);out.put("visible",task.visible);
        out.put("actual_binder_present",task.token!=null);out.put("cookie_count",task.cookies.size());
        out.put("intent",boundedReadText(task.intentComponent));out.put("base",boundedReadText(task.base));
        out.put("top",boundedReadText(task.top));out.put("real",boundedReadText(task.real));out.put("orig",boundedReadText(task.orig));
        return Collections.unmodifiableMap(out);
    }
    private static String boundedReadText(String value){return value==null?null:value.length()<=256?value:value.substring(0,256);}

    private static final class TaskRow {
        int id,user,display,parent,indent;String token,body;
        final List<Integer> children=new ArrayList<Integer>();
        final List<String> detail=new ArrayList<String>();
        final List<Activity> activities=new ArrayList<Activity>();
    }
    private static final class Activity {
        int user,task,ordinal;String token,component;boolean finishing,exiting;final List<String> detail=new ArrayList<String>();
    }
    public static Proof verify(String dump,ProfileTarget target,BackgroundOwnedSingleTask.Task root,
            BackgroundOwnedSingleTask.Task leaf,Authority authority,long started,long now)throws Exception {
        need(dump!=null&&target!=null&&root!=null&&leaf!=null&&authority!=null,"PROFILE_PERMISSION_PROOF_ARGUMENTS");
        need(now>=started&&now-started<=MAX_AGE_MS,"PROFILE_PERMISSION_PROOF_STALE_OR_CHANGED");
        need(authority.user==target.profile.userId&&authority.uid/100000==target.profile.userId
                &&root.display==leaf.display&&root.display>0&&root.user==0&&root.parent==-1
                &&leaf.user==target.profile.userId&&leaf.parent==root.id&&leaf.uid==target.fullUid
                &&root.topUid==authority.uid&&leaf.topUid==authority.uid&&COMPONENT.equals(root.top)&&COMPONENT.equals(leaf.top)
                &&targetComponent(target,leaf.base)&&(root.base==null||Objects.equals(root.base,leaf.base))
                &&targetComponent(target,leaf.intentComponent)&&targetComponent(target,leaf.real)
                &&(leaf.orig==null||targetComponent(target,leaf.orig)),"PROFILE_PERMISSION_TASKINFO_NOT_PROVEN");
        byte[] raw=dump.getBytes(StandardCharsets.UTF_8);
        need(raw.length>0&&raw.length<=BackgroundOwnedSingleTask.MAX_DUMP_BYTES&&dump.indexOf('\0')<0
                &&dump.startsWith("ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n")
                &&!Pattern.compile("dump timed out|permission denial|exception while dumping",Pattern.CASE_INSENSITIVE).matcher(dump).find(),
                "PROFILE_PERMISSION_DUMP_INCOMPLETE");
        String[] lines=dump.split("\n",-1);int end=-1;
        for(int i=0;i<lines.length;i++)if("ActivityTaskSupervisor state:".equals(lines[i])){need(end<0,"PROFILE_PERMISSION_DUMP_INCOMPLETE");end=i;}
        need(end>1&&Pattern.compile("^  TaskOrganizerController:$",Pattern.MULTILINE).matcher(dump).find()
                &&Pattern.compile("^  SleepTokens=.+$",Pattern.MULTILINE).matcher(dump).find(),"PROFILE_PERMISSION_DUMP_INCOMPLETE");
        Map<Integer,TaskRow> rows=new LinkedHashMap<Integer,TaskRow>();Set<Integer> displays=new HashSet<Integer>();
        List<TaskRow> stack=new ArrayList<TaskRow>();TaskRow current=null;Activity activity=null;int display=-1;
        for(int i=1;i<end;i++){
            String line=lines[i];Matcher m;
            if(line.startsWith("Display #")){
                m=Pattern.compile("Display #([0-9]+) \\(activities from top to bottom\\):").matcher(line);
                need(m.matches(),"PROFILE_PERMISSION_DISPLAY_INVALID");display=number(m.group(1));
                need(displays.add(display),"PROFILE_PERMISSION_DISPLAY_DUPLICATE");stack.clear();current=null;activity=null;
            }else if(line.trim().startsWith("* Task")){
                m=TASK.matcher(line);need(m.matches()&&display>=0&&rows.size()<2048,"PROFILE_PERMISSION_TASK_ROW_INVALID");
                TaskRow row=new TaskRow();row.indent=m.group(1).length();row.token=m.group(2);row.id=number(m.group(3));row.body=m.group(4);
                while(!stack.isEmpty()&&stack.get(stack.size()-1).indent>=row.indent)stack.remove(stack.size()-1);
                row.parent=stack.isEmpty()?-1:stack.get(stack.size()-1).id;row.display=display;
                List<String> users=matches("(?:^| )U=([0-9]+)(?= |$)",row.body);need(users.size()==1,"PROFILE_PERMISSION_TASK_USER_UNKNOWN");
                row.user=number(users.get(0));need(row.id>0&&rows.put(row.id,row)==null,"PROFILE_PERMISSION_TASK_DUPLICATE");
                if(!stack.isEmpty())stack.get(stack.size()-1).children.add(row.id);stack.add(row);current=row;activity=null;
            }else if(line.trim().startsWith("* Hist")){
                m=HIST.matcher(line);need(m.matches()&&current!=null&&m.group(1).length()>current.indent,"PROFILE_PERMISSION_ACTIVITY_ROW_INVALID");
                Activity a=new Activity();a.ordinal=number(m.group(2));a.token=m.group(3);a.user=number(m.group(4));a.component=component(m.group(5));a.task=number(m.group(6));
                String suffix=m.group(7);a.finishing=suffix!=null&&suffix.contains(" f}");a.exiting=suffix!=null&&suffix.contains("isExiting");
                need(a.task==current.id&&current.activities.size()<2048,"PROFILE_PERMISSION_ACTIVITY_TASK_MISMATCH");
                current.activities.add(a);activity=a;
            }else if(activity!=null)activity.detail.add(line.trim());
            else if(current!=null)current.detail.add(line.trim());
        }
        need(displays.contains(0)&&displays.contains(root.display),"PROFILE_PERMISSION_DISPLAY_INCOMPLETE");
        TaskRow parent=rows.get(root.id),child=rows.get(leaf.id);
        need(parent!=null&&child!=null&&parent.user==0&&parent.display==root.display&&parent.parent==-1
                &&parent.activities.isEmpty()&&parent.children.equals(Collections.singletonList(leaf.id))
                &&child.parent==root.id&&child.user==target.profile.userId&&child.display==leaf.display&&child.children.isEmpty(),
                "PROFILE_PERMISSION_OWNED_HIERARCHY_CHANGED");
        need(one(parent.detail,"mCreatedByOrganizer=").equals("mCreatedByOrganizer=true"),"PROFILE_PERMISSION_ROOT_NOT_ORGANIZED");
        need(matches("(?:^| )A=([^ ]+)",child.body).equals(Collections.singletonList(target.fullUid+":"+target.packageName)),
                "PROFILE_PERMISSION_BASE_AFFINITY_CHANGED");
        for(TaskRow row:rows.values()){
            if(row.display==root.display)need(row.id==root.id||row.id==leaf.id,"PROFILE_PERMISSION_FOREIGN_TASK");
            for(Activity a:row.activities)if(a.user==target.profile.userId)need(row.id==leaf.id,"PROFILE_PERMISSION_FOREIGN_ACTIVITY");
        }
        List<Activity> chain=child.activities;
        need(chain.size()>=2&&chain.size()<=32,"PROFILE_PERMISSION_CHAIN_INCOMPLETE");
        // TaskInfo counts and selects its base from non-finishing activities. The full
        // raw chain below still supplies every identity, ordinal, and foreign check.
        int liveCount=0;Activity base=null;
        for(Activity a:chain)if(!a.finishing){liveCount++;base=a;}
        need(liveCount>=2&&liveCount==leaf.activities,"PROFILE_PERMISSION_CHAIN_INCOMPLETE");
        Set<String> tokens=new HashSet<String>();
        for(int i=0;i<chain.size();i++){
            Activity a=chain.get(i);need(a.user==target.profile.userId&&a.ordinal==chain.size()-1-i&&tokens.add(a.token),"PROFILE_PERMISSION_CHAIN_IDENTITY_CHANGED");
            if(i>0)need(targetComponent(target,a.component),"PROFILE_PERMISSION_FOREIGN_ACTIVITY");
            String owner=one(a.detail,"rootOfTask=");
            Matcher own=Pattern.compile("rootOfTask=(true|false) task=Task\\{([^\\s{}]+) #([0-9]+) [^{}]+\\}").matcher(owner);
            need(own.matches()&&own.group(2).equals(child.token)&&number(own.group(3))==leaf.id
                    &&own.group(1).equals(a==base?"true":"false"),"PROFILE_PERMISSION_PRESERVED_BASE_UNPROVEN");
            if(i>0)requireProcess(a,target.packageName,target.fullUid);
        }
        Activity top=chain.get(0);
        need(COMPONENT.equals(top.component)&&base.component.equals(leaf.base)&&!top.finishing&&!top.exiting
                &&!base.finishing&&!base.exiting,"PROFILE_PERMISSION_BASE_COMPONENT_CHANGED");
        need(one(top.detail,"packageName=").equals("packageName="+PACKAGE+" processName="+PACKAGE)
                &&one(top.detail,"launchedFromUid=").equals("launchedFromUid="+target.fullUid+" launchedFromPackage="+target.packageName+" launchedFromFeature=null userId="+target.profile.userId),
                "PROFILE_PERMISSION_CALLER_UNPROVEN");
        String intent=one(top.detail,"Intent { ");
        need(intent.endsWith(" }")&&matches("(?:^|[ {])act=([^\\s{}]+)",intent).equals(Collections.singletonList(ACTION))
                &&matches("(?:^|[ {])pkg=([^\\s{}]+)",intent).equals(Collections.singletonList(PACKAGE)),"PROFILE_PERMISSION_INTENT_UNPROVEN");
        List<String> cmp=matches("(?:^|[ {])cmp=([^\\s{}]+)",intent);
        need(cmp.size()==1&&component(cmp.get(0)).equals(COMPONENT)
                &&component(one(top.detail,"mActivityComponent=").substring(19)).equals(COMPONENT),"PROFILE_PERMISSION_COMPONENT_UNPROVEN");
        need(one(top.detail,"baseDir=").equals("baseDir="+authority.apk)
                &&one(top.detail,"dataDir=").equals("dataDir=/data/user_de/"+authority.user+"/"+PACKAGE)
                &&one(top.detail,"taskAffinity=").equals("taskAffinity="+authority.uid+":"+PACKAGE)
                &&one(top.detail,"state=").equals("state=RESUMED delayedResume=false finishing=false"),"PROFILE_PERMISSION_ACTIVITY_IDENTITY_UNPROVEN");
        requireProcess(top,PACKAGE,authority.uid);
        Matcher result=Pattern.compile("resultTo=ActivityRecord\\{([^\\s{}]+) u([0-9]+) ("+COMP+") t([0-9]+)\\} resultWho=@android:requestPermissions: resultCode=[0-9]+").matcher(one(top.detail,"resultTo="));
        need(result.matches()&&number(result.group(2))==target.profile.userId&&number(result.group(4))==leaf.id,
                "PROFILE_PERMISSION_RESULT_OWNER_UNPROVEN");
        String resultToken=result.group(1),resultComponent=component(result.group(3));int matched=0;
        for(int i=1;i<chain.size();i++)if(chain.get(i).token.equals(resultToken)&&chain.get(i).component.equals(resultComponent))matched++;
        need(matched==1,"PROFILE_PERMISSION_RESULT_TARGET_MISSING");
        return new Proof(target,root,leaf,authority,started,ProfileIdentity.sha(raw),top.token,resultToken);
    }
    private static void requireProcess(Activity activity,String pkg,int uid)throws Exception{
        Matcher proc=Pattern.compile("app=ProcessRecord\\{[^\\s{}]+ [1-9][0-9]*:"+Pattern.quote(pkg)+"(?::[A-Za-z0-9_.$]+)?/([^\\s{}]+)\\}").matcher(one(activity.detail,"app="));
        need(proc.matches(),"PROFILE_PERMISSION_PROCESS_UNPROVEN");String formatted=proc.group(1);
        Matcher app=Pattern.compile("u(0|[1-9][0-9]*)a(0|[1-9][0-9]*)").matcher(formatted);
        need(app.matches()&&number(app.group(2))<=79999&&(long)number(app.group(1))*100000+10000+number(app.group(2))==uid,
                "PROFILE_PERMISSION_PROCESS_UID_CHANGED");
    }
    private static List<String> matches(String regex,String value){
        List<String> out=new ArrayList<String>();Matcher m=Pattern.compile(regex).matcher(value);while(m.find())out.add(m.group(1));return out;
    }
    private static String one(List<String> rows,String prefix)throws Exception{
        String result=null;for(String row:rows)if(row.startsWith(prefix)){need(result==null,"PROFILE_PERMISSION_FIELD_DUPLICATE");result=row;}
        need(result!=null,"PROFILE_PERMISSION_FIELD_MISSING");return result;
    }
    private static String component(String raw)throws Exception{
        need(raw!=null&&raw.matches(COMP),"PROFILE_PERMISSION_COMPONENT_INVALID");int slash=raw.indexOf('/');
        String pkg=raw.substring(0,slash),name=raw.substring(slash+1);return pkg+"/"+(name.startsWith(".")?pkg+name:name);
    }
    private static boolean targetComponent(ProfileTarget target,String component){return component!=null&&component.startsWith(target.packageName+"/");}
    private static int number(String value)throws Exception{
        need(value.matches("0|[1-9][0-9]*"),"PROFILE_PERMISSION_INTEGER_INVALID");
        try{return Integer.parseInt(value);}catch(NumberFormatException e){throw new ProfileTaskPolicy.Refusal("PROFILE_PERMISSION_INTEGER_INVALID");}
    }
    private static void need(boolean ok,String reason)throws ProfileTaskPolicy.Refusal{ProfileTaskPolicy.need(ok,reason);}
}
