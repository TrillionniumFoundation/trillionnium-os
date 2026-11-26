package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/** Real archived 02d origin; only current framework samples are synthetic. */
public final class PublicProfileRecoveryForegroundHostTest {
    private static int cases,checks;
    private static final JSONArray names=new JSONArray();
    private interface Work {void run()throws Exception;}
    private PublicProfileRecoveryForegroundHostTest(){}
    private static void yes(boolean value){checks++;if(!value)throw new AssertionError("foreground recovery boundary");}
    private static void pass(String name,Work work)throws Exception{work.run();cases++;names.put(name);}
    private static void no(String name,Work work)throws Exception{
        try{work.run();}catch(Exception expected){checks++;cases++;names.put(name);return;}
        throw new AssertionError("accepted "+name);
    }
    private static Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> facts(){
        Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> out=new LinkedHashMap<Integer,PublicOwnGroupPhysicalFence.DisplayFacts>();
        out.put(0,new PublicOwnGroupPhysicalFence.DisplayFacts(0,"local:100",1,2,0,1224,2992));
        out.put(1,new PublicOwnGroupPhysicalFence.DisplayFacts(1,"local:101",1,1,0,1272,1080));return out;
    }
    private static String activities(String pkg,int user,int task){
        return "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
            +"Display #0 (activities from top to bottom):\n"
            +"  * Task{a1 #"+task+" type=standard A="+(user*100000+10367)+":"+pkg+" U="+user+"}\n"
            +"    * Hist #0: ActivityRecord{b1 u"+user+" "+pkg+"/.Main t"+task+"}\n"
            +"Display #1 (activities from top to bottom):\nActivityTaskSupervisor state:\n";
    }
    private static String windows(String pkg,int user,int task,boolean ime){
        return "WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)\n"
            +"  Display: mDisplayId=0\n"
            +"  mCurrentFocus=Window{c1 u"+user+" "+pkg+"/"+pkg+".Main}\n"
            +"  mFocusedApp=ActivityRecord{b1 u"+user+" "+pkg+"/.Main t"+task+"}\n"
            +"  mInputMethodWindow="+(ime?"Window{e1 u0 InputMethod}":"null")+"\n"
            +"  mImeInputTarget="+(ime?"Window{c1 u"+user+" "+pkg+"/"+pkg+".Main}":"null")+"\n"
            +"  mImeLayeringTarget=null\n  mImeControlTarget=null\n"
            +"  Display: mDisplayId=1\n  mCurrentFocus=null\n  mFocusedApp=null\n";
    }
    private static String internal(int index,int task,int user,int uid,String pkg,int display,String token){
        return "  * Recent #"+index+": Task{"+token+" #"+task+" type=standard A="+uid+":"+pkg+"}\n"
            +"    userId="+user+" effectiveUid="+uid+" mCallingUid="+uid+"\n"
            +"    taskId="+task+" rootTaskId="+task+"\n    affinity="+uid+":"+pkg+"\n"
            +"    intent={flg=0x10000000 cmp="+pkg+"/.Main}\n    mActivityComponent="+pkg+"/.Main\n"
            +"    Activities=[]\n    lastActiveTime=2000 (inactive for 0s)\n    lastDisplayId="+display+"\n";
    }
    private static String recent(int task,int uid,String pkg,int display,String token,String protectedPkg,String hidden){
        return "ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)\nmRecentsUid=1000\n"
            +"mRecentsComponent=ComponentInfo{com.example.recents/.Main}\nmFreezeTaskListReordering=false\n"
            +"mFreezeTaskListReorderingPendingTimeout=false\nmHiddenTasks=["+hidden+"]\n  Recent tasks:\n"
            +internal(0,task,uid/100000,uid,pkg,display,token)
            +internal(1,200,0,10370,protectedPkg,800,"dd")
            +"  Visible recent tasks (most recent first):\n  * RecentTaskInfo #0:\n"
            +"    id="+task+" userId="+(uid/100000)+" hasTask=false lastActiveTime=2000\n"
            +"    baseIntent=Intent { flg=0x10000000 cmp="+pkg+"/.Main }\n"
            +"    isExcluded=false displayId="+display+"\n    lastDisplayId="+display+"\n";
    }
    private static String baseline(){return recent(100,10367,"com.example.foreground",0,"aa","com.example.protected","");}
    private static JSONObject evidence(String raw,PublicProfileBusinessAbsenceRecovery.Request r)throws Exception{
        return new JSONObject(PublicProfileRecentHistory.absence(raw,r.target).evidence());
    }
    private static Map<Integer,String> capture(String act,String win,String rec,PublicProfileBusinessAbsenceRecovery.Request r)throws Exception{
        return PublicOwnGroupPhysicalFence.captureBusinessRecovery(act,win,rec,facts(),r.target);
    }
    private static JSONObject physical(Map<Integer,String> value){
        return new JSONObject().put("schema",PublicOwnGroupPhysicalFence.BUSINESS_RECOVERY_SCHEMA)
            .put("0",value.get(0)).put("1",value.get(1));
    }
    private static JSONObject proof(PublicProfileBusinessAbsenceRecovery.Request r,String first,String last)throws Exception{
        JSONObject out=PublicProfileBusinessRecoveryHostTest.syntheticProof(r);
        Map<Integer,String> ph=capture(activities("com.example.foreground",0,100),windows("com.example.foreground",0,100,false),first,r);
        out.getJSONObject("before").put("physical",physical(ph)).put("recents",evidence(first,r));
        out.getJSONObject("after").put("physical",physical(ph)).put("recents",evidence(last,r));return out;
    }
    private static void valid(PublicProfileBusinessAbsenceRecovery.Request r,JSONObject p)throws Exception{
        JSONObject accepted=PublicProfileBusinessAbsenceRecovery.validate(p,r,r.started+31,r.requestBoot);
        yes(accepted.getBoolean("current_absence_verified")&&!accepted.getBoolean("rewrites_business_outcome"));
    }
    private static ProfileTaskPolicy.Snapshot root(int id,int display,int user)throws Exception{
        return new ProfileTaskPolicy.Snapshot(Arrays.asList(new ProfileTaskPolicy.Root(id,display,user,1,true,
            "com.example.foreground/.Main","com.example.foreground/.Main",new int[0],new int[0],new String[0],new int[0][])));
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("manifest and archived originals required");
        Map<String,byte[]> raw=PublicProfileBusinessRecoveryHostTest.loadExternalOriginals(Paths.get(args[1]));
        PublicProfileBusinessRecoveryHostTest.Fixture f=new PublicProfileBusinessRecoveryHostTest.Fixture(
            PublicProfileBusinessAbsenceRecovery.object(Files.readAllBytes(Paths.get(args[0]))),raw);
        PublicProfileBusinessAbsenceRecovery.Request r=f.request();String before=baseline();
        pass("real_02d_released_origin_remains_unchanged",()->{
            yes(r.steps==4&&r.displayId==717&&r.historicalBrokerExitCode==0);
            yes(ProfileIdentity.sha(r.task("result.json")).equals("e6f4a1043df290b1064e59f98511113f9607e3bae768ff04d24f2ec0d16161c9"));
        });
        pass("main_activity_focus_and_ime_change_preserve_typed_physical_identity",()->{
            Map<Integer,String> a=capture(activities("com.example.foreground",0,100),windows("com.example.foreground",0,100,false),before,r);
            Map<Integer,String> b=capture(activities("com.example.browser",0,101),windows("com.example.browser",0,101,true),
                recent(101,10368,"com.example.browser",0,"ab","com.example.protected",""),r);
            yes(a.equals(b));
            yes(!PublicOwnGroupPhysicalFence.capture(activities("com.example.foreground",0,100),windows("com.example.foreground",0,100,false),before,facts(),10)
                .equals(PublicOwnGroupPhysicalFence.capture(activities("com.example.browser",0,101),windows("com.example.browser",0,101,true),
                recent(101,10368,"com.example.browser",0,"ab","com.example.protected",""),facts(),10)));
        });
        pass("safe_user0_focus_can_change_between_independent_dumps",()->{
            yes(capture(activities("com.example.foreground",0,100),windows("com.example.browser",0,101,true),before,r).size()==2);
        });
        pass("transient_user0_null_focus_does_not_claim_background_escape",()->{
            String w=windows("com.example.foreground",0,100,false).replace("mCurrentFocus=Window{c1 u0 com.example.foreground/com.example.foreground.Main}","mCurrentFocus=null");
            yes(capture(activities("com.example.foreground",0,100),w,before,r).size()==2);
        });
        pass("physical_recent_activity_changes_pass_full_absence_policy",()->{
            String after=before.replace("com.example.foreground/.Main","com.example.foreground/.Detail").replaceFirst("lastActiveTime=2000","lastActiveTime=2100")
                .replace("id=100 userId=0 hasTask=false lastActiveTime=2000","id=100 userId=0 hasTask=false lastActiveTime=2100")
                .replace("mFreezeTaskListReordering=false","mFreezeTaskListReordering=true");
            valid(r,proof(r,before,after));
        });
        pass("unrelated_physical_task_close_and_new_task_pass",()->{
            valid(r,proof(r,before,recent(101,10368,"com.example.browser",0,"ab","com.example.protected","")));
        });
        no("physical_uid_change_on_same_task_refuses",()->valid(r,proof(r,before,
            recent(100,10368,"com.example.foreground",0,"aa","com.example.protected",""))));
        no("physical_token_change_on_same_task_refuses",()->valid(r,proof(r,before,
            recent(100,10367,"com.example.foreground",0,"ab","com.example.protected",""))));
        no("physical_root_change_on_same_task_refuses",()->valid(r,proof(r,before,
            before.replace("taskId=100 rootTaskId=100","taskId=100 rootTaskId=101"))));
        no("foreign_virtual_history_change_refuses",()->valid(r,proof(r,before,
            recent(100,10367,"com.example.foreground",0,"aa","com.example.changed",""))));
        no("unresolved_hidden_history_change_refuses",()->valid(r,proof(r,before,
            recent(100,10367,"com.example.foreground",0,"aa","com.example.protected","Task{ef #999 type=standard A=10390:com.example.hidden}"))));
        no("target_uid_in_foreign_recent_refuses",()->valid(r,proof(r,before,
            recent(300,r.target.fullUid,"com.example.foreign",0,"ac","com.example.protected",""))));
        for(final int display:new int[]{0,1}){
            no("recorded_owned_leaf_on_physical_"+display+"_refuses",()->r.requireRecordedLiveAbsent(root(r.ownedLeafTaskId,display,0)));
            no("recorded_owned_root_on_physical_"+display+"_refuses",()->r.requireRecordedLiveAbsent(root(r.ownedRootTaskId,display,0)));
            no("target_uid_recent_on_physical_"+display+"_refuses",()->evidence(recent(300,r.target.fullUid,"com.example.foreign",display,"ac","com.example.protected",""),r));
        }
        no("recorded_display_reuse_refuses",()->r.requireRecordedLiveAbsent(root(999,r.displayId,0)));
        no("recorded_display_in_recents_refuses",()->r.requireRecordedRecentsAbsent(recent(100,10367,"com.example.foreground",r.displayId,"aa","com.example.protected","")));
        no("profile10_other_live_task_refuses",()->root(999,800,10).requireDedicatedEmpty(r.target));
        no("target_profile_activity_on_main_refuses",()->capture(activities("com.example.foreground",10,300),windows("com.example.foreground",0,100,false),before,r));
        no("target_profile_focus_on_main_refuses",()->capture(activities("com.example.foreground",0,100),windows("com.example.foreground",10,300,false),before,r));
        no("controller_focus_on_main_refuses",()->capture(activities("com.example.foreground",0,100),windows("org.trillionnium.hepta.local",0,300,false),before,r));
        no("target_profile_ime_target_on_main_refuses",()->capture(activities("com.example.foreground",0,100),
            windows("com.example.foreground",0,100,false).replace("mImeInputTarget=null","mImeInputTarget=Window{ef u10 com.xiaomi.shop/.Main}"),before,r));
        no("partial_windows_refuses",()->capture(activities("com.example.foreground",0,100),
            windows("com.example.foreground",0,100,false).replace("  mFocusedApp=null\n",""),before,r));
        no("physical_device_identity_change_refuses",()->{
            JSONObject p=proof(r,before,before);Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> different=facts();
            different.put(0,new PublicOwnGroupPhysicalFence.DisplayFacts(0,"local:999",1,2,0,1224,2992));
            p.getJSONObject("after").put("physical",physical(PublicOwnGroupPhysicalFence.captureBusinessRecovery(
                activities("com.example.foreground",0,100),windows("com.example.foreground",0,100,false),before,different,r.target)));valid(r,p);
        });
        no("legacy_physical_hash_cannot_claim_new_scope",()->{
            JSONObject p=proof(r,before,before);p.getJSONObject("before").getJSONObject("physical").remove("schema");valid(r,p);
        });
        no("incorrect_physical_schema_refuses",()->{
            JSONObject p=proof(r,before,before);p.getJSONObject("before").getJSONObject("physical").put("schema",PublicOwnGroupPhysicalFence.SCHEMA);valid(r,p);
        });
        for(Map.Entry<String,byte[]> e:raw.entrySet())yes(Arrays.equals(e.getValue(),r.original(e.getKey())));
        System.out.println(new JSONObject().put("passed",true).put("cases",cases).put("assertions",checks).put("case_names",names)
            .put("actual_policy_executed",true).put("current_framework_samples_synthetic",true).put("original_bytes_unchanged",true)
            .put("phone_operations",0));
    }
}
