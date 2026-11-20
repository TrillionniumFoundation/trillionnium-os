package org.trillionnium.hepta.background;

import java.util.*;
import org.json.JSONObject;

/** Real custody and coordinator code. Dumps, Binder objects and clock are
 * authored host ports, never evidence that a phone or user was operated. */
public final class ForegroundConcurrencyHostTest {
    static int cases,checks;
    interface Work{void run()throws Exception;}
    static void yes(boolean value){checks++;if(!value)throw new AssertionError("foreground concurrency boundary");}
    static void test(String name,Work work)throws Exception{work.run();cases++;System.out.println("PASS "+name);}
    static void no(Work work)throws Exception{try{work.run();}catch(Exception expected){checks++;return;}throw new AssertionError("unproved custody accepted");}
    static final String PKG=PublicPersonalNotesCustody.PACKAGE,GEN=PersonalNotesCustodyHostTest.GEN,SHA=PersonalNotesCustodyHostTest.SHA;
    static final ProfileTarget TARGET=ProfileBrokerHostTest.target(10,1010367);
    static String row(int n,int id,int user,int uid,int display,String token,String pkg){
        return PublicPhysicalAuditHostTest.row(n,id,user,uid,display,token,pkg)
                .replace("    intent=","    affinity="+uid+":"+pkg+"\n    intent=")
                .replace("    lastDisplayId=","    lastActiveTime=2000 (inactive for 0s)\n    lastDisplayId=");
    }
    static String raw(int variant){
        boolean changed=variant>0;
        return "ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)\nmRecentsUid=1000\n"
                +"mRecentsComponent=ComponentInfo{com.example.recents/.Main}\nmFreezeTaskListReordering=false\nmFreezeTaskListReorderingPendingTimeout=false\n"
                +"  Recent tasks:\n"
                +(changed?row(0,102,0,10369,0,"ce","com.example.newapp"):row(0,100,0,10367,0,"aa",ProfileTarget.CTRIP))
                +row(1,101,0,10368,1,"ba","com.example.cover")+row(2,1430,10,1010285,9,"cc00009","com.motorola.maxesetting")
                +"  Visible recent tasks (most recent first):\n"
                +(changed?PublicPhysicalAuditHostTest.visible(0,102,0,0,"com.example.newapp"):PublicPhysicalAuditHostTest.visible(0,100,0,0,ProfileTarget.CTRIP))
                +PublicPhysicalAuditHostTest.visible(1,101,0,1,"com.example.cover");
    }
    static String withLeaf(String raw,int root,int leaf){
        String record=row(3,leaf,10,1010367,7,"aabb300",ProfileTarget.CTRIP).replace("rootTaskId="+leaf,"rootTaskId="+root);
        return raw.replace("  Visible recent tasks (most recent first):\n",record+"  Visible recent tasks (most recent first):\n");
    }
    static BackgroundOwnedSingleTask.Task root(int id){return new BackgroundOwnedSingleTask.Task(id,7,0,-1,0,-1,0,new Object(),
            Collections.emptyList(),null,null,null,null,null,false,false);}
    static BackgroundOwnedSingleTask.Task leaf(int id,BackgroundOwnedSingleTask.Task root){return new BackgroundOwnedSingleTask.Task(id,7,10,root.id,1010367,1010367,1,new Object(),
            Collections.emptyList(),ProfileBrokerHostTest.SPLASH,ProfileBrokerHostTest.SPLASH,ProfileBrokerHostTest.HOME,ProfileBrokerHostTest.SPLASH,null,true,true);}
    static PublicProfileRecentHistory.Baseline baseline()throws Exception{return new PublicProfileRecentHistory.Baseline(PublicProfileRecentHistory.absence(raw(0),TARGET),1000);}
    public static JSONObject profileEvidence(ProfileTarget target,long before,long after,int rootId,int leafId)throws Exception{
        PublicProfileRecentHistory.Baseline b=new PublicProfileRecentHistory.Baseline(PublicProfileRecentHistory.absence(raw(0),target),before);
        BackgroundOwnedSingleTask.Task r=root(rootId),l=leaf(leafId,r);
        b.observe(withLeaf(raw(0),rootId,leafId),target,r,l,7,before);
        b.observe(raw(1),target,r,l,7,after);return new JSONObject(b.evidence());
    }
    static final class Platform implements ProfileOwnedTask.Platform {
        final ProfileBrokerHostTest.Fake delegate=new ProfileBrokerHostTest.Fake();String current=raw(0);
        public ProfileTarget recheck(boolean ready){return delegate.recheck(ready);}
        public void guard()throws Exception{delegate.guard();}
        public long now(){return delegate.now();}
        public Object newCookie(){return delegate.newCookie();}
        public ProfileTaskPolicy.Snapshot snapshot()throws Exception{return delegate.snapshot();}
        public ProfileTaskPolicy.Recents recents(){throw new AssertionError("private recents path");}
        public String publicRecentsDump(){return delegate.recentsApp?withLeaf(current,200,300):current;}
        public List<BackgroundOwnedSingleTask.Task> roots(){return delegate.roots();}
        public List<BackgroundOwnedSingleTask.Task> children(Object token){return delegate.children(token);}
        public void createRoot(Object cookie){delegate.createRoot(cookie);}
        public void bindRoot(Object root,Object launch){delegate.bindRoot(root,launch);}
        public void removeLeaf(Object token)throws Exception{delegate.removeLeaf(token);}
        public boolean deleteRoot(Object token)throws Exception{return delegate.deleteRoot(token);}
        public void pause(){delegate.pause();}
        ProfileOwnedTask active()throws Exception{ProfileOwnedTask p=new ProfileOwnedTask(this,TARGET,ProfileBrokerHostTest.GEN,ProfileBrokerHostTest.REQUEST,7,baseline());
            p.prepare();p.beforeDispatch();delegate.launch();p.accepted(0);yes(p.observe());return p;}
    }
    static String notesRaw(int variant){return raw(variant);}
    static String notesOwned(String raw){return raw.replace("  Visible recent tasks (most recent first):\n",
            row(3,300,0,10482,7,"ddee300",PKG)+"  Visible recent tasks (most recent first):\n");}
    static String hiddenPhysical(String raw,int id){String label=PublicOwnGroupPhysicalFence.inspectRecents(raw).records.get(id).label;
        return raw.replace("  Recent tasks:\n","mHiddenTasks=["+label+"]\n  Recent tasks:\n");}
    static PublicPersonalNotesCustody notes(String gen,String scope,boolean hidden)throws Exception{
        String initial=hidden?hiddenPhysical(notesRaw(0),100):notesRaw(0);
        PublicPersonalNotesCustody c=new PublicPersonalNotesCustody(gen,scope,10482,PersonalNotesCustodyHostTest.global(-1),PublicOwnGroupPhysicalFence.inspectRecents(initial));
        c.beforeCreate();c.bindDisplay(7);c.markLaunch();Object token=new Object();
        c.observe(PersonalNotesCustodyHostTest.frame(300,token,10482,100),101);c.retireAdmission();
        c.prepareRelease(PersonalNotesCustodyHostTest.frame(300,token,10482,110),PublicOwnGroupPhysicalFence.inspectRecents(notesOwned(initial)),111);
        c.enterRelease();c.releaseReturned();return c;
    }
    static void absence(PublicPersonalNotesCustody c,String raw,long at)throws Exception{
        c.observeAbsence(PersonalNotesCustodyHostTest.global(-1),PublicOwnGroupPhysicalFence.inspectRecents(raw),true,at,at+1,at+1);
    }
    public static JSONObject notesEvidence(String gen,String scope)throws Exception{
        PublicPersonalNotesCustody c=notes(gen,scope,true);String changed=hiddenPhysical(notesRaw(1),102);
        absence(c,changed,200);absence(c,changed,250);return new JSONObject(c.evidence());
    }
    public static void main(String[] args)throws Exception{
        if(args.length==1){java.nio.file.Path out=java.nio.file.Paths.get(args[0]);java.nio.file.Files.createDirectory(out);
            java.nio.file.Files.write(out.resolve("profile-v2-producer.json"),(profileEvidence(TARGET,1000,1001,200,300).toString(2)+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            java.nio.file.Files.write(out.resolve("notes-v2-producer.json"),(notesEvidence(GEN,SHA).toString(2)+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
        test("runtime physical time and visible order are audit, strict recovery stays strict",()->{
            String changed=raw(0).replace("lastActiveTime=2000","lastActiveTime=3000");
            // Only physical rows change; preserve the dormant profile row's clock.
            int at=changed.indexOf("  * Recent #2:");changed=changed.substring(0,at)+changed.substring(at).replaceFirst("lastActiveTime=3000","lastActiveTime=2000");
            PublicProfileRecentHistory.Baseline b=baseline();b.requireTargetAbsent(changed,TARGET,1001);
            yes(Boolean.TRUE.equals(b.evidence().get("unrelated_physical_history_changes_observed")));
            final String value=changed;no(()->PublicProfileRecentHistory.absence(raw(0),TARGET).requireSame(PublicProfileRecentHistory.absence(value,TARGET),2));
        });
        test("actual profile coordinator continues across unrelated physical remove and add",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.current=raw(1);yes(p.observe());p.window(14,300,2000);p.retire(2400);
            yes(p.cleanupKnown());yes(f.delegate.mutations.equals(Arrays.asList("create","bind","remove_leaf","delete_root")));
            Map<?,?> proof=(Map<?,?>)p.cleanupEvidence().get("public_foreign_recent_history");
            yes("hepta.public-profile-history-custody.v2".equals(proof.get("schema"))&&Boolean.TRUE.equals(proof.get("unrelated_physical_history_changes_observed")));
            yes(Boolean.FALSE.equals(proof.get("foreign_dormant_history_preserved"))&&Boolean.TRUE.equals(proof.get("nonphysical_history_preserved")));
        });
        test("quickswitch presentation flags are separate audit and never global preservation",()->{
            PublicProfileRecentHistory.Baseline b=baseline();String changed=raw(0).replace("mFreezeTaskListReordering=false","mFreezeTaskListReordering=true")
                    .replace("mFreezeTaskListReorderingPendingTimeout=false","mFreezeTaskListReorderingPendingTimeout=true");
            b.requireTargetAbsent(changed,TARGET,1001);Map<String,Object> e=b.evidence();
            yes(Boolean.TRUE.equals(e.get("recents_presentation_changes_observed"))&&Boolean.FALSE.equals(e.get("unrelated_physical_history_changes_observed")));
            yes(Boolean.FALSE.equals(e.get("foreign_dormant_history_preserved"))&&Boolean.TRUE.equals(e.get("nonphysical_history_preserved")));
            no(()->PublicProfileRecentHistory.absence(raw(0),TARGET).requireSame(PublicProfileRecentHistory.absence(changed,TARGET),2));
        });
        test("first and last resolved physical hidden labels may appear and disappear",()->{
            PublicProfileRecentHistory.Baseline b=baseline();b.requireTargetAbsent(hiddenPhysical(raw(0),100),TARGET,1001);b.requireTargetAbsent(raw(0),TARGET,1002);
            yes(Boolean.TRUE.equals(b.evidence().get("recents_presentation_changes_observed"))&&Boolean.TRUE.equals(b.evidence().get("unrelated_physical_history_changes_observed")));
        });
        test("duplicate or malformed presentation fields remain incomplete input",()->{
            no(()->baseline().requireTargetAbsent(raw(0).replace("mFreezeTaskListReordering=false","mFreezeTaskListReordering=unknown"),TARGET,1001));
            no(()->baseline().requireTargetAbsent(raw(0).replace("mFreezeTaskListReordering=false","mFreezeTaskListReordering=false\nmFreezeTaskListReordering=true"),TARGET,1001));
        });
        test("target profile dormant change still latches refusal",()->{PublicProfileRecentHistory.Baseline b=baseline();
            no(()->b.requireTargetAbsent(raw(0).replace("cc00009","cc00008"),TARGET,1000));no(()->b.requireTargetAbsent(raw(0),TARGET,1001));yes(!b.ownedAbsent());});
        test("unrelated task on another virtual display is not exempt",()->no(()->baseline().requireTargetAbsent(raw(1).replace("lastDisplayId=0","lastDisplayId=8"),TARGET,1001)));
        test("owned recent escape to physical display remains refusal",()->{PublicProfileRecentHistory.Baseline b=baseline();BackgroundOwnedSingleTask.Task r=root(200),l=leaf(300,r);
            no(()->b.observe(withLeaf(raw(1),200,300).replace("lastDisplayId=7","lastDisplayId=0"),TARGET,r,l,7,1001));yes(!b.ownedAbsent());});
        test("foreign physical record cannot use retained owned root",()->{PublicProfileRecentHistory.Baseline b=baseline();BackgroundOwnedSingleTask.Task r=root(200);
            no(()->b.observe(raw(1).replace("rootTaskId=102","rootTaskId=200"),TARGET,r,null,7,1001));});
        test("owned recent token cannot reappear as a new physical ID",()->{PublicProfileRecentHistory.Baseline b=baseline();BackgroundOwnedSingleTask.Task r=root(200),l=leaf(300,r);
            b.observe(withLeaf(raw(0),200,300),TARGET,r,l,7,1000);no(()->b.observe(raw(1).replace("Task{ce #102","Task{aabb300 #102"),TARGET,r,l,7,1001));});
        for(final String change:new String[]{"token","uid","root"})test("same physical task retains "+change+" identity",()->{
            String bad="token".equals(change)?raw(0).replace("Task{aa #100","Task{ab #100"):"uid".equals(change)?raw(0).replace("effectiveUid=10367","effectiveUid=10399"):raw(0).replace("rootTaskId=100","rootTaskId=999");
            no(()->baseline().requireTargetAbsent(bad,TARGET,1001));});
        test("Notes two true absences permit unrelated physical and resolved hidden changes",()->{
            JSONObject e=notesEvidence(GEN,SHA);yes(e.getBoolean("cleanup_known")&&e.getInt("absence_reads")==2);
            yes(e.getBoolean("nonphysical_history_preserved")&&!e.getBoolean("prior_hidden_history_preserved"));
            yes(e.getBoolean("unrelated_physical_history_changes_observed")&&!e.getBoolean("physical_history_frozen"));
            yes("pre_release_to_absence".equals(e.getString("history_preservation_interval"))&&"initial_to_absence".equals(e.getString("hidden_history_preservation_interval")));});
        test("Notes cleanup permits typed quickswitch flags without calling them physical row changes",()->{
            PublicPersonalNotesCustody c=notes(GEN,SHA,false);String changed=notesRaw(0).replace("mFreezeTaskListReordering=false","mFreezeTaskListReordering=true");
            absence(c,changed,200);absence(c,changed,250);yes(c.known());
            yes(Boolean.TRUE.equals(c.evidence().get("recents_presentation_changes_observed"))&&Boolean.FALSE.equals(c.evidence().get("unrelated_physical_history_changes_observed")));
        });
        test("Notes new unowned target recents cannot become absence",()->{PublicPersonalNotesCustody c=notes(GEN,SHA,false);
            String bad=notesRaw(1).replace("  Visible recent tasks (most recent first):\n",row(3,301,0,10482,0,"ab301",PKG)+"  Visible recent tasks (most recent first):\n");
            no(()->absence(c,bad,200));yes(!c.known()&&c.retain());});
        test("Notes target UID hidden with a foreign package is still refused",()->{PublicPersonalNotesCustody c=notes(GEN,SHA,false);
            String bad=notesRaw(1).replace("  Recent tasks:\n","mHiddenTasks=[Task{ab301 #301 type=standard A=10482:com.other}]\n  Recent tasks:\n");
            no(()->absence(c,bad,200));yes(!c.known());});
        test("Notes foreign recent on own display vetoes cleanup",()->{PublicPersonalNotesCustody c=notes(GEN,SHA,false);
            no(()->absence(c,notesRaw(1).replace("lastDisplayId=0","lastDisplayId=7"),200));yes(c.retain());});
        test("Notes remaining owned recent on physical display vetoes cleanup",()->{PublicPersonalNotesCustody c=notes(GEN,SHA,false);
            no(()->absence(c,notesOwned(notesRaw(1)).replace("lastDisplayId=7","lastDisplayId=0"),200));yes(c.retain());});
        test("Notes owned token reused under different physical task ID vetoes cleanup",()->{PublicPersonalNotesCustody c=notes(GEN,SHA,false);
            no(()->absence(c,notesRaw(1).replace("Task{ce #102","Task{ddee300 #102"),200));yes(c.retain());});
        test("Notes unknown detached hidden record never gets physical exemption",()->{PublicPersonalNotesCustody c=notes(GEN,SHA,false);
            String bad=notesRaw(1).replace("  Recent tasks:\n","mHiddenTasks=[Task{ab999 #999 type=standard}]\n  Recent tasks:\n");no(()->absence(c,bad,200));});
        test("physical changes do not replace second absence read",()->{PublicPersonalNotesCustody c=notes(GEN,SHA,false);absence(c,notesRaw(1),200);yes(!c.known()&&c.retain());});
        test("target preexisting task admission remains strict",()->no(()->new PublicPersonalNotesCustody(GEN,SHA,10482,
                PersonalNotesCustodyHostTest.global(300),PublicOwnGroupPhysicalFence.inspectRecents(notesRaw(1)))));
        System.out.println(new JSONObject().put("passed",true).put("cases",cases).put("assertions",checks).put("phone_operations",0).put("framework_and_user_activity_synthetic",true));
    }
}
