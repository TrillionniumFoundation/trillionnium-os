package org.trillionnium.hepta.background;
import java.util.*;

/** Real pure custody/parser code; authored TaskInfo/token ports never prove a phone run. */
public final class PersonalNotesCustodyHostTest {
    static final String GEN="11111111-1111-4111-8111-111111111111",SHA=String.join("",Collections.nCopies(64,"a"));
    static final String PKG=PublicPersonalNotesCustody.PACKAGE,COMP=PKG+"/"+PKG+".Main";
    static final int UID=10482;
    static int cases,checks;
    interface Work{void run()throws Exception;}
    static void yes(boolean value){checks++;if(!value)throw new AssertionError("Notes custody boundary");}
    static void refuses(Work work)throws Exception{try{work.run();}catch(Exception expected){checks++;return;}throw new AssertionError("unproved Notes custody accepted");}
    static void test(String name,Work work)throws Exception{work.run();cases++;System.out.println("PASS "+name);}
    static ProfileTaskPolicy.Root root(int id,int display,String component)throws Exception{
        return new ProfileTaskPolicy.Root(id,display,0,1,true,component,component,new int[]{id},new int[]{0},new String[]{component},new int[][]{{0,0,100,100}});
    }
    static ProfileTaskPolicy.Snapshot global(int owned)throws Exception{
        List<ProfileTaskPolicy.Root> roots=new ArrayList<ProfileTaskPolicy.Root>();
        roots.add(root(100,0,"com.example.main/com.example.main.Main"));roots.add(root(101,1,"com.example.cover/com.example.cover.Main"));
        if(owned>0)roots.add(root(owned,7,COMP));return new ProfileTaskPolicy.Snapshot(roots);
    }
    static BackgroundOwnedSingleTask.Task task(int id,Object token,int uid,String comp){
        return new BackgroundOwnedSingleTask.Task(id,7,0,-1,uid,uid,1,token,Collections.emptyList(),comp,comp,comp,comp,null,true,true);
    }
    static PublicPersonalNotesCustody.Frame frame(int id,Object token,int uid,long now)throws Exception{
        List<PublicPersonalNotesCustody.Node> roots=id>0?Collections.singletonList(new PublicPersonalNotesCustody.Node(task(id,token,uid,COMP),Collections.emptyList())):Collections.emptyList();
        return new PublicPersonalNotesCustody.Frame(global(id),roots,now,now+1);
    }
    static String raw(){return PublicPhysicalAuditHostTest.recents(false);}
    static String withOwned(){return raw().replace("  Visible recent tasks (most recent first):\n",
            PublicPhysicalAuditHostTest.row(2,300,0,UID,7,"cc",PKG)+"  Visible recent tasks (most recent first):\n")
            +PublicPhysicalAuditHostTest.visible(2,300,0,7,PKG);}
    static PublicOwnGroupPhysicalFence.RecentCensus recents(String raw){return PublicOwnGroupPhysicalFence.inspectRecents(raw);}
    static PublicPersonalNotesCustody fresh()throws Exception{return new PublicPersonalNotesCustody(GEN,SHA,UID,global(-1),recents(raw()));}
    static PublicPersonalNotesCustody created()throws Exception{PublicPersonalNotesCustody custody=fresh();custody.beforeCreate();custody.bindDisplay(7);custody.markLaunch();return custody;}
    static void prepare(PublicPersonalNotesCustody custody,Object token)throws Exception{
        prepare(custody,token,raw());
    }
    static void prepare(PublicPersonalNotesCustody custody,Object token,String beforeRecents)throws Exception{
        custody.observe(frame(300,token,UID,100),101);custody.retireAdmission();custody.prepareRelease(frame(300,token,UID,110),recents(beforeRecents),111);
    }
    static PublicPersonalNotesCustody released(Object token)throws Exception{PublicPersonalNotesCustody custody=created();prepare(custody,token);custody.enterRelease();custody.releaseReturned();return custody;}
    static void absence(PublicPersonalNotesCustody custody,String raw,long when)throws Exception{custody.observeAbsence(global(-1),recents(raw),true,when,when+1,when+1);}
    static String hidden(String raw,String labels){return raw.replace("  Recent tasks:\n","mHiddenTasks=["+labels+"]\n  Recent tasks:\n");}
    public static void main(String[] args)throws Exception{
        test("display release return is insufficient until two real absence samples",()->{PublicPersonalNotesCustody c=released(new Object());yes(!c.known()&&c.retain());absence(c,raw(),200);yes(!c.known());absence(c,raw(),250);yes(c.known()&&!c.retain());yes(Boolean.FALSE.equals(c.evidence().get("caller_flag_is_cleanup_proof")));});
        test("caller cleanup preference is not any state transition",()->{PublicPersonalNotesCustody c=created();Map<String,Object> copied=new LinkedHashMap<String,Object>(c.evidence());copied.put("cleanup_known",true);yes(!c.known());refuses(c::enterRelease);});
        test("existing Notes live task refuses before display creation",()->refuses(()->new PublicPersonalNotesCustody(GEN,SHA,UID,global(300),recents(raw()))));
        test("existing Notes UID in complete recents refuses",()->{String notes=raw().replace("effectiveUid=10367","effectiveUid="+UID);refuses(()->new PublicPersonalNotesCustody(GEN,SHA,UID,global(-1),recents(notes)));});
        test("existing hidden Notes label refuses",()->refuses(()->new PublicPersonalNotesCustody(GEN,SHA,UID,global(-1),recents(hidden(raw(),"Task{ee #300 type=standard A=10482:"+PKG+"}")))));
        test("actual full leaf UID must equal installed Notes UID",()->{PublicPersonalNotesCustody c=created();refuses(()->c.observe(frame(300,new Object(),10483,100),101));yes(c.retain());refuses(c::enterRelease);});
        test("foreign actual component is not admitted by a Notes label",()->{PublicPersonalNotesCustody c=created();PublicPersonalNotesCustody.Frame frame=new PublicPersonalNotesCustody.Frame(global(300),Collections.singletonList(new PublicPersonalNotesCustody.Node(task(300,new Object(),UID,"com.other/com.other.Main"),Collections.emptyList())),100,101);refuses(()->c.observe(frame,101));});
        test("actual organizer and global task census must agree",()->{PublicPersonalNotesCustody c=created();PublicPersonalNotesCustody.Frame frame=new PublicPersonalNotesCustody.Frame(global(301),Collections.singletonList(new PublicPersonalNotesCustody.Node(task(300,new Object(),UID,COMP),Collections.emptyList())),100,101);refuses(()->c.observe(frame,101));});
        test("same numeric task ID cannot replace the observed Binder token",()->{PublicPersonalNotesCustody c=created();c.observe(frame(300,new Object(),UID,100),101);refuses(()->c.observe(frame(300,new Object(),UID,110),111));yes(c.retain());});
        test("preexisting hidden ID is never new task custody",()->{PublicPersonalNotesCustody c=new PublicPersonalNotesCustody(GEN,SHA,UID,global(-1),recents(hidden(raw(),"Task{ee #300 type=standard}")));c.beforeCreate();c.bindDisplay(7);refuses(()->c.observe(frame(300,new Object(),UID,100),101));});
        test("initial owned display binding cannot be replaced",()->{PublicPersonalNotesCustody c=created();refuses(()->c.bindDisplay(8));});
        test("late monitor evidence after retiring cannot block or reopen known cleanup",()->{Object token=new Object();PublicPersonalNotesCustody c=released(token);c.observe(frame(300,new Object(),10483,180),181);absence(c,raw(),200);absence(c,raw(),250);yes(c.known());});
        test("unknown pre-release identity keeps owner and prevents release entry",()->{PublicPersonalNotesCustody c=created();c.retireAdmission();refuses(()->c.prepareRelease(frame(300,new Object(),10483,100),recents(raw()),101));refuses(c::enterRelease);yes(c.retain()&&!c.known());});
        test("unknown lifecycle cannot be repaired by later empty snapshots",()->{PublicPersonalNotesCustody c=released(new Object());c.unresolved("actual_read_unknown");refuses(()->absence(c,raw(),200));yes(!c.known()&&c.retain());});
        test("observed task retained only in hidden recents blocks known",()->{PublicPersonalNotesCustody c=released(new Object());refuses(()->absence(c,hidden(raw(),"Task{ee #300 type=standard}"),200));yes(c.retain());});
        test("new detached unknown hidden reference is never assumed unrelated",()->{PublicPersonalNotesCustody c=released(new Object());refuses(()->absence(c,hidden(raw(),"Task{ee #999 type=standard}"),200));});
        test("old detached hidden label and order are preserved without ownership inference",()->{String a="Task{ee #998 type=standard}",b="Task{ff #999 type=standard}";String baseline=hidden(raw(),a+", "+b);PublicPersonalNotesCustody c=new PublicPersonalNotesCustody(GEN,SHA,UID,global(-1),recents(baseline));c.beforeCreate();c.bindDisplay(7);prepare(c,new Object(),baseline);c.enterRelease();c.releaseReturned();absence(c,baseline,200);absence(c,baseline,250);yes(c.known());});
        test("same proven owned recents can be pending then need two consecutive empty reads",()->{PublicPersonalNotesCustody c=created();prepare(c,new Object(),withOwned());c.enterRelease();c.releaseReturned();
            absence(c,withOwned(),200);yes(c.retain()&&!c.known()&&Boolean.FALSE.equals(c.evidence().get("identity_unknown")));absence(c,raw(),250);absence(c,withOwned(),300);absence(c,raw(),350);yes(!c.known());absence(c,raw(),400);yes(c.known()&&((Number)c.evidence().get("pending_owned_reads")).intValue()==2);});
        test("known live residue needs the same actual Binder token before pending",()->{Object token=new Object();PublicPersonalNotesCustody c=created();prepare(c,token,withOwned());c.enterRelease();c.releaseReturned();
            PublicPersonalNotesCustody.Frame still=frame(300,token,UID,200);c.observeAbsence(still.global,recents(withOwned()),still,true,200,201,201);yes(c.retain()&&!c.known());
            PublicPersonalNotesCustody.Frame replaced=frame(300,new Object(),UID,250);refuses(()->c.observeAbsence(replaced.global,recents(withOwned()),replaced,true,250,251,251));refuses(()->absence(c,raw(),300));});
        test("owned detached hidden residue keeps the frozen actual Task label token",()->{PublicPersonalNotesCustody c=created();prepare(c,new Object(),withOwned());c.enterRelease();c.releaseReturned();
            String label=recents(withOwned()).records.get(300).label;absence(c,hidden(raw(),label),200);yes(!c.known()&&Boolean.FALSE.equals(c.evidence().get("identity_unknown")));absence(c,raw(),250);absence(c,raw(),300);yes(c.known());});
        for(final String change:new String[]{"uid","token","history"})test("pending cannot wash away "+change+" changes",()->{PublicPersonalNotesCustody c=created();prepare(c,new Object(),withOwned());c.enterRelease();c.releaseReturned();
            String bad="uid".equals(change)?withOwned().replace("effectiveUid="+UID,"effectiveUid="+(UID+1)):"token".equals(change)?withOwned().replace("Task{cc #300","Task{cd #300"):withOwned().replace("Task{aa #100","Task{ab #100");
            refuses(()->absence(c,bad,200));refuses(()->absence(c,raw(),250));yes(c.retain()&&!c.known());});
        test("truncated visible recents cannot become complete absence",()->refuses(()->recents(raw().split("  Visible recent tasks")[0])));
        test("display absence false cannot be promoted by task absence",()->{PublicPersonalNotesCustody c=released(new Object());refuses(()->c.observeAbsence(global(-1),recents(raw()),false,200,201,201));});
        test("replayed timestamp does not count as a second absence read",()->{PublicPersonalNotesCustody c=released(new Object());absence(c,raw(),200);refuses(()->absence(c,raw(),200));yes(!c.known());});
        test("no creation is a separate internal fact not a caller flag",()->{PublicPersonalNotesCustody c=fresh();c.retireAdmission();c.notCreated();yes(c.known()&&!c.retain());PublicPersonalNotesCustody created=created();refuses(created::notCreated);});
        System.out.println("{\"cases\":"+cases+",\"assertions\":"+checks+",\"passed\":true,\"phone_contacted\":false}");
    }
}
