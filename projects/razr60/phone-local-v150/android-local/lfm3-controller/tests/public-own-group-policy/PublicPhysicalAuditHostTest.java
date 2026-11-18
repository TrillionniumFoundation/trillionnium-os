package org.trillionnium.hepta.background;
import java.util.LinkedHashMap;
import java.util.Map;
/** Authored complete dump fixtures, including detached hidden references; no device proof. */
public final class PublicPhysicalAuditHostTest {
 private static int cases,checks;
 interface Work { void run() throws Exception; }
 static void yes(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
 static void test(String name,Work work)throws Exception{work.run();cases++;System.out.println("PASS "+name);}
 static void refuse(Work work)throws Exception{try{work.run();throw new AssertionError("unsafe dump accepted");}catch(IllegalArgumentException expected){checks++;}}
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
    static Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> displays(){Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> m=new LinkedHashMap<Integer,PublicOwnGroupPhysicalFence.DisplayFacts>();
        m.put(0,new PublicOwnGroupPhysicalFence.DisplayFacts(0,"local:1000",1,2,0,1224,2992));m.put(1,new PublicOwnGroupPhysicalFence.DisplayFacts(1,"local:1001",1,1,0,1080,1272));return m;}
    static Map<Integer,String> capture(String a,String w,String r){return PublicOwnGroupPhysicalFence.capture(a,w,r,displays(),10);}
    static Map<Integer,String> baseline(){return capture(activities(),windows(),recents(true));}

 static String hidden(String value){return recents(true).replace("  Recent tasks:\n","mHiddenTasks=["+value+"]\n  Recent tasks:\n");}
 static final String DETACHED="Task{2bbd66 #1182 type=standard A=10481:org.trillionnium.hepta.local}";
 static Map<Integer,String> from(String r){return capture(activities(),windows(),r);}
 public static void main(String[] args)throws Exception {
  test("full unknown-owner detached label is preserved without inventing ownership",()->{
    Map<Integer,String> a=from(hidden(DETACHED));yes(a.equals(from(hidden(DETACHED))),"same hidden reference changed");yes(!a.equals(baseline()),"hidden reference dropped");});
  test("unknown-owner hidden label is retained even without affinity",()->yes(!from(hidden("Task{ee #999 type=standard}")).equals(baseline()),"unknown owner dropped"));
  test("hidden token change changes complete audit",()->yes(!from(hidden(DETACHED)).equals(from(hidden(DETACHED.replace("2bbd66","2bbd67")))),"hidden token dropped"));
  test("hidden id change changes complete audit",()->yes(!from(hidden(DETACHED)).equals(from(hidden(DETACHED.replace("#1182","#1183")))),"hidden id dropped"));
  test("hidden affinity change changes complete audit",()->yes(!from(hidden(DETACHED)).equals(from(hidden(DETACHED.replace("10481:","10482:")))),"hidden affinity dropped"));
  test("hidden complete label fields cannot silently disappear",()->yes(!from(hidden(DETACHED)).equals(from(hidden(DETACHED.replace("type=standard","type=undefined")))),"hidden body dropped"));
  test("all hidden order is retained",()->{String other="Task{dd #999 type=standard}";yes(!from(hidden(DETACHED+", "+other)).equals(from(hidden(other+", "+DETACHED))),"hidden ordering dropped");});
  test("duplicate hidden task id refuses",()->refuse(()->from(hidden(DETACHED+", "+DETACHED.replace("2bbd66","2bbd67")))));
  test("duplicate hidden object token refuses",()->refuse(()->from(hidden(DETACHED+", "+DETACHED.replace("#1182","#1183")))));
  test("known internal hidden identity mismatch refuses",()->refuse(()->from(hidden("Task{af #100 type=standard A=10367:ctrip.android.view}"))));
  test("dedicated profile history is governed separately without hiding user zero",()->yes(baseline().equals(capture(activities(),windows(),recents(false))),"dedicated profile history treated as personal"));
  test("target zero mode keeps personal hierarchy and history",()->{
    Map<Integer,String> first=PublicOwnGroupPhysicalFence.capture(activities(),windows(),recents(true),displays(),0);
    Map<Integer,String> after=PublicOwnGroupPhysicalFence.capture(activities().replace("Task{aa #100","Task{af #100"),windows(),recents(true),displays(),0);
    yes(!first.equals(after),"user zero tasks were all excluded");});
  test("user physical changes produce changed audit, without being attributed to agent",()->yes(!baseline().equals(capture(activities(),windows().replace("mImeInputTarget=null","mImeInputTarget=Window{ae u0 input}"),recents(true))),"physical focus facts omitted"));
  test("profile still cannot escape to main",()->refuse(()->capture(activities().replace("U=0 visible=true sz=1","U=10 visible=true sz=1").replace("{ab u0","{ab u10"),windows(),recents(true))));
  test("complete hierarchy boundary is mandatory",()->refuse(()->capture(activities().replace("ActivityTaskSupervisor state:","partial:"),windows(),recents(true))));
  test("full visible recents boundary is mandatory",()->refuse(()->from(recents(true).split("  Visible recent tasks")[0])));
  test("malformed hidden residual refuses",()->refuse(()->from(hidden(DETACHED+", unknown"))));
  test("permission denied dump is not a real observation",()->refuse(()->capture(activities(),windows()+"Permission Denial\n",recents(true))));
  test("literal closing brace space and end terminate the same hexadecimal flags",()->{
    java.lang.reflect.Method intent=PublicOwnGroupPhysicalFence.class.getDeclaredMethod("intent",String.class);intent.setAccessible(true);
    for(String value:new String[]{"flg=0x0000a","{flg=0x0000a}","{flg=0x0000a cmp=com.example/.Main}"})
      yes("a".equals(((String[])intent.invoke(null,value))[1]),"literal flag boundary changed");
  });
  test("flags adjacent to closing brace preserve full recents identity",()->{
    String value=recents(true).replace("flg=0x10000000 cmp=","cmp=")
      .replace("/.Main}","/.Main flg=0x10000000}").replace("/.Main }","/.Main flg=0x10000000}");
    yes(baseline().equals(from(value)),"closing brace changed recents identity");
  });
  test("duplicate flags still refuse after literal brace compatibility fix",()->
    refuse(()->from(recents(true).replace("flg=0x10000000 cmp=","flg=0x10000000 flg=0x10000000 cmp="))));
  System.out.println("{\"cases\":"+cases+",\"assertions\":"+checks+",\"all_pass\":true,\"phone_contacted\":false,\"actual_framework_executed\":false}");
 }
}
