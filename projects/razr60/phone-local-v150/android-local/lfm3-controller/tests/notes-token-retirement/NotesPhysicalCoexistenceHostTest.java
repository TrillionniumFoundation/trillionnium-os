package org.trillionnium.hepta.background;

import android.app.ActivityTaskManager.RootTaskInfo;
import android.os.Binder;
import android.window.WindowContainerToken;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import org.json.JSONObject;

/** Explicit host scheduling and complete authored Android IO. All production
 * coordinator/adapter/parser bodies execute; no phone result is manufactured. */
public final class NotesPhysicalCoexistenceHostTest {
    private static int cases,checks;
    private static final List<String> names=new ArrayList<String>();
    interface Work {void run()throws Exception;}
    static void yes(boolean value){checks++;if(!value)throw new AssertionError("physical coexistence boundary");}
    static void test(String name,Work work)throws Exception{work.run();cases++;names.add(name);System.out.println("PASS "+name);}
    static String reason(Throwable error){while(error.getCause()!=null)error=error.getCause();return String.valueOf(error.getMessage());}
    static void reject(String code,Work work)throws Exception{
        try{work.run();}catch(Exception error){yes(code==null||reason(error).contains(code));return;}
        throw new AssertionError("unproved physical exception accepted: "+code);
    }
    static NotesTokenRetirementHostTest.World world()throws Exception{return new NotesTokenRetirementHostTest.World(1);}
    static void finish(NotesTokenRetirementHostTest.World w)throws Exception{w.run();w.released();yes(w.custody.known()&&w.calls==1&&w.forbidden==0);}
    static void noEffect(Consumer<NotesTokenRetirementHostTest.World> mutation)throws Exception{
        NotesTokenRetirementHostTest.World w=world();w.beforeEffect=mutation;reject(null,w::run);yes(w.calls==0&&!w.custody.known());
    }
    static void drop(NotesTokenRetirementHostTest.World w,int id){w.live.remove(id);w.recent.remove(id);}
    static final String OTHER="com.example.newapp/com.example.newapp.Main";
    static String hidden(int id,int uid,String pkg){
        return "mHiddenTasks=[Task{"+Integer.toHexString(id)+" #"+id+" type=standard A="+uid+":"+pkg+"}]\n";
    }
    public static void main(String[] args)throws Exception{
        test("physical state rotation focus IME activity and recents may change together",()->{
            NotesTokenRetirementHostTest.World w=world();
            final String beforeWindow=w.windows(),beforeRecents=w.recents();final boolean[] changed={false};
            final java.util.Map<Integer,String> beforeAudit=PublicOwnGroupPhysicalFence.capture(w.activities(),beforeWindow,beforeRecents,w.deviceFacts,0);
            w.beforeEffect=x->{x.physicalEpoch=2100;x.physicalSuffix="Window{ab u0 input}";x.live.get(100).numActivities=2;
                x.deviceFacts.put(0,new PublicOwnGroupPhysicalFence.DisplayFacts(0,"local:1000",1,2,1,2992,1224));
                yes(beforeWindow.contains("mImeInputTarget=null")&&x.windows().contains("mImeInputTarget=Window{ab u0 input}"));
                yes(!beforeWindow.equals(x.windows())&&!beforeRecents.equals(x.recents())&&x.recents().contains("lastActiveTime=2100"));
                yes(x.deviceFacts.get(0).rotation==1&&x.live.get(100).numActivities==2);
                yes(!beforeAudit.equals(PublicOwnGroupPhysicalFence.capture(x.activities(),x.windows(),x.recents(),x.deviceFacts,0)));
                changed[0]=true;};
            finish(w);yes(changed[0]&&Boolean.FALSE.equals(w.custody.evidence().get("physical_history_frozen")));
        });
        test("new unrelated personal app can become physical foreground",()->{
            NotesTokenRetirementHostTest.World w=world();w.beforeEffect=x->{x.add(102,0,11001,OTHER);x.focusedTask=102;};
            finish(w);yes(w.live.containsKey(102)&&w.live.containsKey(100));
        });
        test("owner can close unrelated main task during background cleanup",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1,x->{x.add(102,0,11001,OTHER);x.focusedTask=102;});
            w.beforeEffect=x->drop(x,100);finish(w);yes(!w.live.containsKey(100)&&w.live.containsKey(102));
        });
        test("physical recent may disappear without deleting its live task",()->{
            NotesTokenRetirementHostTest.World w=world();w.beforeEffect=x->x.recent.remove(100);finish(w);yes(w.live.containsKey(100));
        });
        test("recents freeze presentation flags are audited without freezing runtime",()->{
            NotesTokenRetirementHostTest.World w=world();
            w.beforeEffect=x->x.recentTransform=r->r.replace("mFreezeTaskListReordering=false","mFreezeTaskListReordering=true")
                    .replace("mFreezeTaskListReorderingPendingTimeout=false","mFreezeTaskListReorderingPendingTimeout=true");
            finish(w);
        });
        test("post returned physical switch settles through a complete new batch",()->{
            NotesTokenRetirementHostTest.World w=world();w.pending=true;final int[] reads={0};
            w.afterEffect=x->{drop(x,300);x.beforeRootRead=y->{if(++reads[0]==5){drop(y,100);y.add(102,0,11001,OTHER);y.focusedTask=102;}};};
            finish(w);yes(reads[0]>7&&w.live.containsKey(102)&&!w.live.containsKey(100));
        });
        test("physical switch between root and running queries settles as a full batch",()->{
            NotesTokenRetirementHostTest.World w=world();w.pending=true;final boolean[] changed={false};
            w.afterEffect=x->{drop(x,300);x.beforeRunningRead=y->{if(!changed[0]){changed[0]=true;drop(y,100);y.add(102,0,11001,OTHER);y.focusedTask=102;}};};
            finish(w);yes(changed[0]&&w.live.containsKey(102));
        });
        test("continuous physical census churn cannot become a partial sample",()->{
            NotesTokenRetirementHostTest.World w=world();w.pending=true;final int[] reads={0},active={100};
            w.afterEffect=x->{drop(x,300);x.beforeRootRead=y->{int n=++reads[0];if(n==5||n==12||n==19){
                drop(y,active[0]);active[0]=101+n;y.add(active[0],0,11001,OTHER);y.focusedTask=active[0];}};};
            reject("PHYSICAL_CENSUS_SETTLING",w::run);yes(w.calls==1&&!w.custody.known()&&reads[0]<=21);
            yes(w.evidence().getInt("pre_release_absence_reads")==0);
        });
        test("physical device unique ID replacement blocks first effect",()->
            noEffect(x->x.deviceFacts.put(0,new PublicOwnGroupPhysicalFence.DisplayFacts(0,"local:9999",1,2,0,1224,2992))));
        test("cover physical device replacement also blocks first effect",()->
            noEffect(x->x.deviceFacts.put(1,new PublicOwnGroupPhysicalFence.DisplayFacts(1,"local:9998",1,1,0,1080,1272))));
        test("physical Binder replacement is not a foreground update",()->
            noEffect(x->x.live.get(100).token=new WindowContainerToken(new Binder())));
        test("physical UID replacement is not a foreground update",()->
            noEffect(x->{x.live.get(100).effectiveUid++;x.live.get(100).topActivityInfo.applicationInfo.uid++;}));
        test("physical launch-cookie replacement is not an activity update",()->
            noEffect(x->x.live.get(100).launchCookies.add(new Binder())));
        test("Notes effective UID cannot use the physical exception",()->
            noEffect(x->x.live.get(100).effectiveUid=NotesTokenRetirementHostTest.UID));
        test("Notes top UID cannot use the physical exception",()->
            noEffect(x->x.live.get(100).topActivityInfo.applicationInfo.uid=NotesTokenRetirementHostTest.UID));
        test("Notes activity alias cannot use the physical exception",()->
            noEffect(x->x.live.get(100).origActivity=NotesTokenRetirementHostTest.component(NotesTokenRetirementHostTest.COMP)));
        test("physical Binder conflict between actual root and running queries refuses",()->{
            NotesTokenRetirementHostTest.World w=world();
            w.beforeEffect=x->x.beforeRunningRead=y->{y.beforeRunningRead=null;y.live.get(100).token=new WindowContainerToken(new Binder());};
            reject(null,w::run);yes(w.calls==0);
        });
        test("physical UID conflict between actual root and running queries refuses",()->{
            NotesTokenRetirementHostTest.World w=world();
            w.beforeEffect=x->x.beforeRunningRead=y->{y.beforeRunningRead=null;y.live.get(100).effectiveUid++;};
            reject(null,w::run);yes(w.calls==0);
        });
        test("protected virtual task cannot migrate into the physical exception",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1,x->x.add(500,9,11001,OTHER));
            w.beforeEffect=x->x.live.get(500).displayId=0;reject(null,w::run);yes(w.calls==0);
        });
        test("physical task cannot migrate onto another virtual display",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1,x->{x.add(102,0,11001,OTHER);x.focusedTask=102;});
            w.beforeEffect=x->x.live.get(100).displayId=9;reject(null,w::run);yes(w.calls==0);
        });
        test("physical task cannot silently migrate between main and cover",()->
            noEffect(x->x.live.get(101).displayId=0));
        test("root or parent changes cannot masquerade as physical activity",()->
            noEffect(x->{RootTaskInfo container=x.row(3,0,0,"com.android.shell/com.android.shell.Container");
                container.childTaskIds=new int[]{100};container.childTaskUserIds=new int[]{0};
                container.childTaskNames=new String[]{"ctrip.android.view/ctrip.android.view.Main"};
                x.live.put(3,container);x.live.get(100).parentTaskId=3;}));
        test("ordinary leaf cannot become root with same Binder UID and unavailable raw parent",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1,x->{
                x.add(102,0,11001,OTHER);x.ordinaryNestedLeaves.add(102);x.recent.remove(102);
                RootTaskInfo root=x.row(3,0,0,"com.android.shell/com.android.shell.Container");
                root.childTaskIds=new int[]{102};root.childTaskUserIds=new int[]{0};root.childTaskNames=new String[]{OTHER};
                x.live.put(3,root);
            });
            w.beforeEffect=x->{x.live.remove(3);x.ordinaryNestedLeaves.remove(102);};
            reject("PHYSICAL_TASK_LOCATION_CHANGED",w::run);yes(w.calls==0);
        });
        test("physical recent UID display and root must agree with actual live census",()->
            noEffect(x->x.recent.put(100,x.row(100,1,10367,"ctrip.android.view/ctrip.android.view.Main"))));
        test("physical recent token replacement is rejected",()->{
            NotesTokenRetirementHostTest.World w=world();
            w.beforeEffect=x->x.recentTransform=r->r.replace("Task{64 #100","Task{fe #100");
            reject(null,w::run);yes(w.calls==0);
        });
        for(String section:new String[]{"internal","visible","hidden"}){
            final String selected=section;
            test("Notes alias in "+section+" body is not exempted",()->{
                NotesTokenRetirementHostTest.World w=world();
                w.beforeEffect=x->{
                    if("internal".equals(selected))x.recentTransform=r->r.replace("    taskId=100 rootTaskId=100\n",
                            "    taskId=100 rootTaskId=100\n    mOriginalActivity=com.motorola.stylus/.Alias\n");
                    if("visible".equals(selected))x.recentTransform=r->r.replace("    id=100 userId=0 hasTask=true lastActiveTime=2000\n",
                            "    id=100 userId=0 hasTask=true lastActiveTime=2000\n    mOriginalActivity=com.motorola.stylus/.Alias\n");
                    if("hidden".equals(selected))x.hiddenPrefix="mHiddenTasks=[Task{64 #100 type=standard A=10367:ctrip.android.view I=com.motorola.stylus/.Alias}]\n";
                };
                reject(null,w::run);yes(w.calls==0);
            });
        }
        test("unresolved hidden record cannot become newly exempt physical history",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1,x->x.hiddenPrefix=hidden(900,11001,"com.example.newapp"));
            w.beforeEffect=x->x.add(900,0,11001,OTHER);
            reject("FOREIGN_HISTORY_CHANGED",w::run);yes(w.calls==0);
        });
        test("unresolved hidden record remains protected when removed",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1,x->x.hiddenPrefix=hidden(900,11001,"com.example.newapp"));
            w.beforeEffect=x->x.hiddenPrefix="";reject(null,w::run);yes(w.calls==0);
        });
        test("resolved physical record cannot leave an unclassified hidden survivor",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1,x->x.hiddenPrefix=hidden(100,10367,"ctrip.android.view"));
            w.beforeEffect=x->x.recent.remove(100);reject(null,w::run);yes(w.calls==0);
        });
        test("protected nonphysical recent body remains byte-preserved",()->{
            NotesTokenRetirementHostTest.World w=new NotesTokenRetirementHostTest.World(1,x->x.add(500,9,11001,OTHER));
            final String original=w.recents();
            w.beforeEffect=x->x.recentTransform=r->r.replace("    taskId=500 rootTaskId=500\n",
                    "    taskId=500 rootTaskId=500\n    newField=changed\n");
            try{w.run();throw new AssertionError("protected history accepted");}
            catch(IllegalStateException error){
                yes("NOTES_RETIREMENT_FOREIGN_HISTORY_CHANGED".equals(error.getMessage()));
                java.util.Map<String,Object> evidence=PublicPersonalNotesRetirement.historyDiagnostic(error);
                yes(evidence!=null&&Boolean.FALSE.equals(evidence.get("diagnostics_grant_authority"))
                        &&Boolean.FALSE.equals(evidence.get("release_evidence"))&&Boolean.TRUE.equals(evidence.get("raw_pair_complete")));
                JSONObject diagnostic=new JSONObject(evidence),pair=diagnostic.getJSONObject("raw_pair");
                yes("gzip-base64-concatenated-original-utf8".equals(pair.getString("encoding")));
                byte[] compressed=java.util.Base64.getDecoder().decode(pair.getString("data"));
                yes(compressed.length==pair.getInt("compressed_bytes")&&ProfileIdentity.sha(compressed).equals(pair.getString("compressed_sha256")));
                java.io.ByteArrayOutputStream decoded=new java.io.ByteArrayOutputStream();
                try(java.util.zip.GZIPInputStream in=new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(compressed))){
                    byte[] block=new byte[1024];int count;while((count=in.read(block))!=-1){
                        yes(decoded.size()+count<=32768);decoded.write(block,0,count);
                    }
                }
                byte[] combined=decoded.toByteArray();int split=diagnostic.getJSONObject("baseline").getInt("bytes");
                byte[] left=java.util.Arrays.copyOfRange(combined,0,split),right=java.util.Arrays.copyOfRange(combined,split,combined.length);
                yes(combined.length==pair.getInt("decoded_bytes")&&ProfileIdentity.sha(combined).equals(pair.getString("decoded_sha256")));
                yes(java.util.Arrays.equals(left,original.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                        &&java.util.Arrays.equals(right,w.recents().getBytes(java.nio.charset.StandardCharsets.UTF_8)));
                yes(ProfileIdentity.sha(left).equals(diagnostic.getJSONObject("baseline").getString("sha256"))
                        &&ProfileIdentity.sha(right).equals(diagnostic.getJSONObject("current").getString("sha256")));
                yes("nonphysical_and_unresolved_recents".equals(evidence.get("history_preservation_scope")));
            }
            yes(w.calls==0);
        });
        test("new physical task cannot reuse its numeric ID with a new Binder after a discarded batch",()->{
            NotesTokenRetirementHostTest.World w=world();w.pending=true;final int[] reads={0};
            w.afterEffect=x->{drop(x,300);x.beforeRootRead=y->{int n=++reads[0];
                if(n==1)y.add(102,0,11001,OTHER);if(n==5)drop(y,102);if(n==8)y.add(102,0,11001,OTHER);};};
            reject("PHYSICAL_TASK_IDENTITY_CHANGED",w::run);yes(w.calls==1&&w.evidence().getInt("pre_release_absence_reads")==0);
        });
        System.out.println(new JSONObject().put("schema","hepta.notes-physical-coexistence-host.v1").put("all_pass",true)
                .put("cases",cases).put("checks",checks).put("case_names",names).put("phone_operations",0)
                .put("framework_io_and_scheduling_are_authored",true).put("actual_failed_phone_raw_pair_available",false).toString());
    }
}
