package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/** Authored full section fixtures. No device, shell command or Android adapter. */
public final class PhysicalDisplayFenceHostTest {
    private static int cases,checks;
    interface Work{void run()throws Exception;}
    private static void yes(boolean ok,String m){checks++;if(!ok)throw new AssertionError(m);}
    private static void test(String n,Work w)throws Exception{w.run();cases++;System.out.println("PASS "+n);}
    private static void refuse(Work w)throws Exception{try{w.run();throw new AssertionError("accepted incomplete/foreign observation");}catch(IllegalArgumentException expected){checks++;}}
    static String activities(){return "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
            +"Display #0 (activities from top to bottom):\n  * Task{aa #100 type=standard A=10367:ctrip.android.view U=0 visible=true sz=1}\n"
            +"    * Hist #0: ActivityRecord{ab u0 ctrip.android.view/.Home t100}\n"
            +"Display #1 (activities from top to bottom):\n  * Task{ba #101 type=standard U=0 visible=false sz=1}\n"
            +"    * Hist #0: ActivityRecord{bb u0 com.example.cover/.Main t101}\n"
            +"Display #7 (activities from top to bottom):\n  * Task{ca #200 type=undefined U=0 visible=true sz=1}\n"
            +"    * Task{cb #300 type=undefined A=1010367:ctrip.android.view U=10 visible=true sz=1}\n"
            +"      * Hist #0: ActivityRecord{cc u10 ctrip.android.view/.Home t300}\n"
            +"\nActivityTaskSupervisor state:\n  SleepTokens=[]\n";}
    static String windows(){return "WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)\n"
            +"  Display: mDisplayId=0 (ownFocus=false)\n  mCurrentFocus=Window{ad u0 ctrip.android.view/ctrip.android.view.Home}\n"
            +"  mFocusedApp=ActivityRecord{ab u0 ctrip.android.view/.Home t100}\n  mImeInputTarget=null\n"
            +"  Display: mDisplayId=1 (ownFocus=false)\n  mCurrentFocus=null\n  mFocusedApp=null\n"
            +"  Display: mDisplayId=7 (ownFocus=true)\n  mCurrentFocus=Window{cd u10 com.android.permissioncontroller}\n"
            +"  mFocusedApp=ActivityRecord{ce u10 com.android.permissioncontroller/.Grant t300}\n";}
    static String row(int index,int id,int user,int uid,int display,String token,String pkg){return "  * Recent #"+index+": Task{"+token+" #"+id+" type=standard A="+uid+":"+pkg+"}\n"
            +"    userId="+user+" effectiveUid="+uid+" mCallingUid=0\n    intent={flg=0x10000000 cmp="+pkg+"/.Main}\n"
            +"    taskId="+id+" rootTaskId="+id+"\n    Activities=[]\n    mActivityComponent="+pkg+"/.Main\n    lastDisplayId="+display+"\n";}
    static String visible(int index,int id,int user,int display,String pkg){return "  * RecentTaskInfo #"+index+":\n"
            +"    id="+id+" userId="+user+" hasTask=true lastActiveTime=2000\n    isExcluded=false supportsSplitScreenMultiWindow=true\n"
            +"    baseIntent=Intent { flg=0x10000000 cmp="+pkg+"/.Main }\n    lastDisplayId="+display+"\n";}
    static String recents(boolean profile){return "ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)\nmRecentsUid=1000\n"
            +"mRecentsComponent=ComponentInfo{com.example.recents/.Main}\nmFreezeTaskListReordering=false\nmFreezeTaskListReorderingPendingTimeout=false\n"
            +"  Recent tasks:\n"+row(0,100,0,10367,0,"aa",ProfileTarget.CTRIP)+row(1,101,0,10368,1,"ba","com.example.cover")
            +(profile?row(2,300,10,1010367,7,"cb",ProfileTarget.CTRIP):"")+"  Visible recent tasks (most recent first):\n"
            +visible(0,100,0,0,ProfileTarget.CTRIP)+visible(1,101,0,1,"com.example.cover")+(profile?visible(2,300,10,7,ProfileTarget.CTRIP):"");}
    static Map<Integer,PhysicalDisplayFence.DisplayFacts> displays(){Map<Integer,PhysicalDisplayFence.DisplayFacts> m=new LinkedHashMap<Integer,PhysicalDisplayFence.DisplayFacts>();
        m.put(0,new PhysicalDisplayFence.DisplayFacts(0,"local:1000",1,2,0,1224,2992));m.put(1,new PhysicalDisplayFence.DisplayFacts(1,"local:1001",1,1,0,1080,1272));return m;}
    static Map<Integer,String> capture(String a,String w,String r){return PhysicalDisplayFence.capture(a,w,r,displays(),10);}
    static Map<Integer,String> baseline(){return capture(activities(),windows(),recents(true));}
    public static void main(String[] args)throws Exception{
        test("complete physical hierarchy focus and both recent sections produce two immutable hashes",()->{
            Map<Integer,String> value=baseline();yes(value.size()==2&&value.get(0).matches("[0-9a-f]{64}")&&value.get(1).matches("[0-9a-f]{64}"),"census invalid");
            try{value.clear();throw new AssertionError("mutable fence");}catch(UnsupportedOperationException expected){checks++;}
        });
        test("dedicated profile recent addition does not alter personal recents identity",()->yes(baseline().equals(capture(activities(),windows(),recents(false))),"owned profile confused with personal history"));
        test("recent activity clock alone is not a task identity change",()->yes(baseline().equals(capture(activities(),windows(),recents(true).replace("lastActiveTime=2000","lastActiveTime=6000"))),"clock caused false identity"));
        test("personal main task identity movement changes fingerprint",()->yes(!baseline().equals(capture(activities().replace("Task{aa #100","Task{af #100"),windows(),recents(true))),"task change ignored"));
        test("cover window focus change changes fingerprint",()->{
            String w=windows().replace("  mCurrentFocus=null\n  mFocusedApp=null","  mCurrentFocus=Window{bd u0 com.example.cover/com.example.cover.Main}\n  mFocusedApp=ActivityRecord{bb u0 com.example.cover/.Main t101}");
            yes(!baseline().equals(capture(activities(),w,recents(true))),"cover focus ignored");
        });
        test("IME target is part of physical fence",()->yes(!baseline().equals(capture(activities(),windows().replace("mImeInputTarget=null","mImeInputTarget=Window{ae u0 input}"),recents(true))),"IME ignored"));
        test("historical personal recent last display changes fence even with identical live tasks",()->yes(!baseline().equals(capture(activities(),windows(),recents(true).replace("lastDisplayId=1","lastDisplayId=8"))),"historical recent ignored"));
        test("personal hidden recent is included",()->{
            String r=recents(true).replace("  Recent tasks:\n","mHiddenTasks=[Task{aa #100 type=standard A=10367:ctrip.android.view}]\n  Recent tasks:\n");
            yes(!baseline().equals(capture(activities(),windows(),r)),"hidden recent ignored");
        });
        test("partial activity dump refuses",()->refuse(()->capture(activities().replace("ActivityTaskSupervisor state:","partial:"),windows(),recents(true))));
        test("duplicate physical display refuses",()->refuse(()->capture(activities().replace("Display #7","Display #0"),windows(),recents(true))));
        test("foreign profile activity on main refuses",()->refuse(()->capture(activities().replace("U=0 visible=true sz=1","U=10 visible=true sz=1").replace("{ab u0","{ab u10"),windows(),recents(true))));
        test("Hepta activity on physical display refuses",()->refuse(()->capture(activities().replace("{ab u0 ctrip.android.view/.Home","{ab u0 org.trillionnium.hepta.local/.MainActivity"),windows(),recents(true))));
        test("focus must match actual activity on this display",()->refuse(()->capture(activities(),windows().replace("mFocusedApp=ActivityRecord{ab u0","mFocusedApp=ActivityRecord{bb u0"),recents(true))));
        test("null focus on an ON panel refuses",()->refuse(()->capture(activities(),windows().replace("mCurrentFocus=Window{ad u0 ctrip.android.view/ctrip.android.view.Home}","mCurrentFocus=null").replace("mFocusedApp=ActivityRecord{ab u0 ctrip.android.view/.Home t100}","mFocusedApp=null"),recents(true))));
        test("partial physical window census refuses",()->refuse(()->capture(activities(),windows().replace("Display: mDisplayId=1","Display: mDisplayId=8"),recents(true))));
        test("recent visible section omission refuses",()->refuse(()->capture(activities(),windows(),recents(true).split("  Visible recent tasks")[0])));
        test("recent visible identity mismatch refuses",()->refuse(()->capture(activities(),windows(),recents(true).replace("id=100 userId=0 hasTask", "id=100 userId=10 hasTask"))));
        test("recent missing last display refuses",()->refuse(()->capture(activities(),windows(),recents(true).replace("    lastDisplayId=0\n", ""))));
        test("duplicate visible recent refuses",()->refuse(()->capture(activities(),windows(),recents(true).replace("id=101 userId=0 hasTask", "id=100 userId=0 hasTask"))));
        test("unresolved hidden identity refuses",()->refuse(()->capture(activities(),windows(),recents(true).replace("  Recent tasks:\n","mHiddenTasks=[Task{ee #999 type=standard}]\n  Recent tasks:\n"))));
        test("permission denial text is not a complete dump",()->refuse(()->capture(activities(),windows()+"Permission Denial\n",recents(true))));
        test("extra or missing physical DisplayManager object refuses",()->{Map<Integer,PhysicalDisplayFence.DisplayFacts> d=displays();d.remove(1);refuse(()->PhysicalDisplayFence.capture(activities(),windows(),recents(true),d,10));});
        test("profile-only preparation operations require profile version and exact fields",()->{
            String gen=ProfileBrokerHostTest.GEN,id=ProfileBrokerHostTest.REQUEST,sha=ProfileBrokerHostTest.target(10,1010367).sha256;
            for(String op:Arrays.asList("prepare","prepare_state","permission_window","prepare_done")){
                String extras=("prepare".equals(op)||"permission_window".equals(op))?",\"package\":\"ctrip.android.view\"":"";
                if("permission_window".equals(op))extras+=",\"window_id\":14,\"task_id\":300";
                String json="{\"version\":2,\"request_id\":\""+id+"\",\"generation\":\""+gen+"\",\"deadline_elapsed_ms\":2000,\"op\":\""+op+"\",\"target_sha256\":\""+sha+"\""+extras+"}";
                BrokerProtocol.Request parsed=BrokerProtocol.Request.parse(json.getBytes(StandardCharsets.UTF_8));yes(op.equals(parsed.operation),"new operation inaccessible");
                try{BrokerProtocol.Request.parse(json.replace("\"version\":2","\"version\":1").getBytes(StandardCharsets.UTF_8));throw new AssertionError("personal protocol accepted preparation");}
                catch(BrokerProtocol.Refusal expected){yes("OPERATION_NOT_ALLOWED".equals(expected.code),"unexpected nonprofile refusal");}
                try{BrokerProtocol.Request.parse(json.replace("}",",\"allow\":1}").getBytes(StandardCharsets.UTF_8));throw new AssertionError("grant field accepted");}
                catch(BrokerProtocol.Refusal expected){yes("REQUEST_FIELDS".equals(expected.code),"unexpected extra field refusal");}
            }
        });
        test("literal closing brace space and end terminate the same hexadecimal flags",()->{
            java.lang.reflect.Method intent=PhysicalDisplayFence.class.getDeclaredMethod("intent",String.class);intent.setAccessible(true);
            for(String value:new String[]{"flg=0x0000a","{flg=0x0000a}","{flg=0x0000a cmp=com.example/.Main}"})
                yes("a".equals(((String[])intent.invoke(null,value))[1]),"literal flag boundary changed");
        });
        test("flags adjacent to closing brace preserve full recents identity",()->{
            String value=recents(true);
            for(String pkg:new String[]{ProfileTarget.CTRIP,"com.example.cover"}){
                value=value.replace("    intent={flg=0x10000000 cmp="+pkg+"/.Main}",
                    "    intent={cmp="+pkg+"/.Main flg=0x10000000}");
                value=value.replace("    baseIntent=Intent { flg=0x10000000 cmp="+pkg+"/.Main }",
                    "    baseIntent=Intent { cmp="+pkg+"/.Main flg=0x10000000}");
            }
            yes(baseline().equals(capture(activities(),windows(),value)),"closing brace changed recents identity");
        });
        test("duplicate flags still refuse after literal brace compatibility fix",()->
            refuse(()->capture(activities(),windows(),recents(true).replace("flg=0x10000000 cmp=","flg=0x10000000 flg=0x10000000 cmp="))));
        System.out.println("{\"cases\":"+cases+",\"assertions\":"+checks+",\"all_pass\":true,\"android_adapter_executed\":false,\"phone_contacted\":false}");
    }
}
