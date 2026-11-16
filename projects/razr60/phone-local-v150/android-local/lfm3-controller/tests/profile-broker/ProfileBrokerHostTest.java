package org.trillionnium.hepta.background;

import java.util.*;

/** Framework fixtures are synthetic. These are host ownership/cleanup tests, not device qualification. */
public final class ProfileBrokerHostTest {
    interface Work {void run()throws Exception;}
    static int assertions;static final List<String> cases=new ArrayList<String>();
    static final String GEN="12345678-1234-4234-9234-123456789abc",REQUEST="22345678-1234-4234-9234-123456789abc";
    static final String SPLASH="ctrip.android.view/ctrip.business.splash.CtripSplashActivity";
    static final String HOME="ctrip.android.view/ctrip.android.view.home.CtripHomeActivity";
    static ProfileTarget target(long serial,int uid){return new ProfileTarget(new ProfileIdentity(10,serial,0,
            "android.os.usertype.profile.MANAGED"),uid,ProfileTarget.CTRIP,SPLASH,1779,
            Collections.singletonMap("base",repeat('a')),Collections.singleton(repeat('b')));}
    static String repeat(char c){char[] s=new char[64];Arrays.fill(s,c);return new String(s);}
    static void yes(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    static void reject(String code,Work work)throws Exception{
        try{work.run();throw new AssertionError("accepted: "+code);}catch(ProfileTaskPolicy.Refusal e){yes(code.equals(e.code),e.code+" != "+code);}
    }
    static void test(String name,Work work)throws Exception{work.run();cases.add(name);}
    static ProfileTaskPolicy.Root row(int id,int display,int user,int leaf,int leafUser,String name,boolean visible)throws Exception{
        return new ProfileTaskPolicy.Root(id,display,user,1,visible,HOME,HOME,
                new int[]{leaf},new int[]{leafUser},new String[]{name},new int[][]{{0,0,1080,2400}});
    }
    static String recent(int... identities){
        StringBuilder b=new StringBuilder("ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)\n"
                +"mRecentsUid=1000\nmRecentsComponent=ComponentInfo{a/b}\nmFreezeTaskListReordering=false\n"
                +"mFreezeTaskListReorderingPendingTimeout=false\n");
        if(identities.length>0){b.append("  Recent tasks:\n");
            for(int i=0;i<identities.length;i+=3){int id=identities[i],u=identities[i+1],uid=identities[i+2];
                b.append("  * Recent #").append(i/3).append(": Task{abc").append(id).append(" #").append(id).append(" type=standard}\n")
                    .append("    userId=").append(u).append(" effectiveUid=").append(uid).append(" mCallingUid=0\n")
                    .append("    taskId=").append(id).append(" rootTaskId=").append(id).append('\n')
                    .append("    Activities=[]\n");
            }
        }return b.toString();
    }
    static final class Fake implements ProfileOwnedTask.Platform {
        ProfileTarget actual=target(10,1010367);
        boolean root,app,recentsApp,foreign,personalMoved,wrongCookie,wrongUid,wrongUser,wrongParent;
        boolean removeThrows,keepRecents,deleteThrows,delayedDelete,pendingDelete,cancel;
        boolean initialProfileLive,initialProfileRecent,personalAdded,personalClosed;
        Object rootToken=new Object(),leafToken=new Object(),rootCookie,launchCookie;
        final List<String> mutations=new ArrayList<String>();long now=1000;
        @Override public ProfileTarget recheck(boolean ready){return actual;}
        @Override public void guard()throws Exception{if(cancel)throw new ProfileTaskPolicy.Refusal("CANCELLED");}
        @Override public long now(){return now;}
        @Override public Object newCookie(){return new Object();}
        @Override public ProfileTaskPolicy.Snapshot snapshot()throws Exception{
            List<ProfileTaskPolicy.Root> rows=new ArrayList<ProfileTaskPolicy.Root>();
            String launcher="com.android.launcher3/com.android.launcher3.Launcher";
            rows.add(new ProfileTaskPolicy.Root(50,0,0,1,true,launcher,launcher,
                    new int[]{50},new int[]{0},new String[]{launcher},new int[][]{{0,0,1080,2400}}));
            if(!personalClosed)rows.add(row(100,personalMoved?7:0,0,100,0,HOME,true));
            if(personalAdded)rows.add(row(102,0,0,102,0,HOME,true));
            if(root){int leaf=app?300:200;
                rows.add(new ProfileTaskPolicy.Root(200,7,0,app?1:0,app,app?SPLASH:null,app?HOME:null,
                        new int[]{leaf},new int[]{app?(wrongUser?0:10):0},new String[]{app?HOME:"unknown"},
                        new int[][]{{0,0,1080,2400}}));}
            if(initialProfileLive)rows.add(row(400,0,0,401,10,HOME,false));
            if(foreign)rows.add(row(402,7,0,403,10,HOME,false));
            return new ProfileTaskPolicy.Snapshot(rows);
        }
        @Override public ProfileTaskPolicy.Recents recents()throws Exception{
            if(initialProfileRecent)return ProfileTaskPolicy.Recents.parse(recent(100,0,10367,401,10,1010367));
            return ProfileTaskPolicy.Recents.parse(recentsApp?recent(100,0,10367,300,10,1010367):recent(100,0,10367));
        }
        BackgroundOwnedSingleTask.Task rootRow(){return new BackgroundOwnedSingleTask.Task(200,7,0,-1,0,app?1010367:-1,
                app?1:0,rootToken,Collections.singletonList(rootCookie),null,app?SPLASH:null,app?HOME:null,null,null,app,app);}
        BackgroundOwnedSingleTask.Task leafRow(){return new BackgroundOwnedSingleTask.Task(300,7,wrongUser?0:10,wrongParent?900:200,
                wrongUid?10367:1010367,wrongUid?10367:1010367,1,leafToken,
                Collections.singletonList(wrongCookie?new Object():launchCookie),SPLASH,SPLASH,HOME,SPLASH,null,true,true);}
        @Override public List<BackgroundOwnedSingleTask.Task> roots(){return root?Collections.singletonList(rootRow()):Collections.emptyList();}
        @Override public List<BackgroundOwnedSingleTask.Task> children(Object token){
            yes(rootToken.equals(token),"wrong root token query");return app?Collections.singletonList(leafRow()):Collections.emptyList();}
        @Override public void createRoot(Object cookie){yes(!root,"root reused");rootCookie=cookie;root=true;mutations.add("create");}
        @Override public void bindRoot(Object token,Object cookie){yes(rootToken.equals(token),"bind arbitrary token");launchCookie=cookie;mutations.add("bind");}
        @Override public void removeLeaf(Object token)throws Exception{
            yes(leafToken.equals(token),"remove arbitrary task");mutations.add("remove_leaf");
            if(removeThrows)throw new ProfileTaskPolicy.Refusal("REMOVE_FAILED");app=false;if(!keepRecents)recentsApp=false;
        }
        @Override public boolean deleteRoot(Object token)throws Exception{
            yes(rootToken.equals(token)&&!app,"delete nonempty or foreign root");mutations.add("delete_root");
            if(deleteThrows)throw new ProfileTaskPolicy.Refusal("DELETE_FAILED");
            if(delayedDelete)pendingDelete=true;else root=false;return true;
        }
        @Override public void pause(){now+=20;if(pendingDelete){root=false;pendingDelete=false;}}
        void launch(){app=true;recentsApp=true;}
    }
    static ProfileOwnedTask prepared(Fake f)throws Exception{
        ProfileOwnedTask task=new ProfileOwnedTask(f,target(10,1010367),GEN,REQUEST,7);task.prepare();return task;
    }
    static ProfileOwnedTask active(Fake f)throws Exception{
        ProfileOwnedTask task=prepared(f);task.beforeDispatch();f.launch();task.accepted(0);yes(task.observe(),"not observed");return task;
    }
    public static void main(String[] args)throws Exception{
        test("personal same-package task is preserved while new profile leaf is owned",()->{
            Fake f=new Fake();ProfileOwnedTask p=active(f);
            WindowOwnership w=p.window(14,300,2000);
            yes(w.userId==10&&w.fullUid==1010367&&w.userSerial==10,"full profile identity");
            WindowOwnership decoded=WindowOwnership.fromWire(w.wire(),f.actual);
            decoded.requireMatches(f.actual,GEN,7,14,300,1001);
            String token=w.taskTokenId;
            p.retire(2400);yes(p.cleanupKnown(),"cleanup not confirmed");
            List<?> owned=(List<?>)p.cleanupEvidence().get("owned_tasks");
            yes(owned.size()==1&&token.equals(((Map<?,?>)owned.get(0)).get("task_token_id")),"token continuity");
            yes(f.mutations.equals(Arrays.asList("create","bind","remove_leaf","delete_root")),"unexpected mutation");
            yes(f.snapshot().leaves.get(100).display==0,"personal task moved");
        });
        test("stopped target-profile child under user-zero root rejects before mutation",()->{
            Fake f=new Fake();f.initialProfileLive=true;
            reject("PROFILE_ALREADY_HAS_LEAF_TASK",()->prepared(f));yes(f.mutations.isEmpty(),"mutated");
        });
        test("target-profile raw recents rejects even without active task",()->{
            Fake f=new Fake();f.initialProfileRecent=true;
            reject("PROFILE_ALREADY_HAS_RECENT_TASK",()->prepared(f));yes(f.mutations.isEmpty(),"mutated");
        });
        test("profile newly populated between prepare and dispatch rejects",()->{
            Fake f=new Fake();ProfileOwnedTask p=prepared(f);f.initialProfileRecent=true;
            reject("PROFILE_ALREADY_HAS_RECENT_TASK",()->p.beforeDispatch());yes(!p.started(),"launch marked");
        });
        test("same user ID with recreated profile serial rejects",()->{
            Fake f=new Fake();ProfileOwnedTask p=prepared(f);f.actual=target(11,1010367);
            reject("PROFILE_INSTALLATION_IDENTITY_CHANGED",()->p.beforeDispatch());yes(!p.started(),"launch marked");
        });
        test("different installed full UID rejects",()->{
            Fake f=new Fake();ProfileOwnedTask p=prepared(f);f.actual=target(10,1010368);
            reject("PROFILE_INSTALLATION_IDENTITY_CHANGED",()->p.beforeDispatch());
        });
        test("actual accessibility task ID must equal owned leaf",()->{
            Fake f=new Fake();ProfileOwnedTask p=active(f);reject("PROFILE_WINDOW_TASK_MISMATCH",()->p.window(14,100,2000));
        });
        test("parent-remapped UID cannot corroborate target window",()->{
            Fake f=new Fake();ProfileOwnedTask p=active(f);f.wrongUid=true;
            reject("PROFILE_NEW_LEAF_NOT_PROVEN",()->p.window(14,300,2000));
        });
        test("actual child user is not inherited from root",()->{
            Fake f=new Fake();ProfileOwnedTask p=active(f);f.wrongUser=true;
            reject("PROFILE_NEW_LEAF_NOT_PROVEN",()->p.window(14,300,2000));
        });
        test("leaf cookie and parent are independently required",()->{
            Fake f=new Fake();ProfileOwnedTask p=active(f);f.wrongCookie=true;
            reject("PROFILE_NEW_LEAF_NOT_PROVEN",()->p.observe());f.wrongCookie=false;f.wrongParent=true;
            reject("PROFILE_NEW_LEAF_NOT_PROVEN",()->p.observe());
        });
        test("foreign profile task forbids removal of any task",()->{
            Fake f=new Fake();ProfileOwnedTask p=active(f);f.foreign=true;
            reject("PROFILE_FOREIGN_ROOT_ON_DISPLAY",()->p.retire(2400));
            yes(!f.mutations.contains("remove_leaf")&&!p.cleanupKnown(),"foreign cleanup mutated");
        });
        test("foreign user-zero root on owned display rejects without main repair",()->{
            Fake f=new Fake();ProfileOwnedTask p=active(f);f.personalMoved=true;
            reject("PROFILE_FOREIGN_ROOT_ON_DISPLAY",()->p.retire(2400));
            yes(!f.mutations.contains("remove_leaf"),"repaired personal task");
        });
        test("foreign raw recent vetoes cleanup before owned removal",()->{
            Fake f=new Fake();ProfileOwnedTask p=active(f);f.initialProfileRecent=true;
            reject("PROFILE_FOREIGN_RECENT_TASK",()->p.retire(2400));
            yes(!f.mutations.contains("remove_leaf")&&!p.cleanupKnown(),"foreign recent ignored");
        });
        test("personal same-package close does not block own-profile observation or cleanup",()->{
            Fake f=new Fake();ProfileOwnedTask p=active(f);f.personalClosed=true;
            yes(p.observe(),"personal close blocked profile");p.window(14,300,2000);p.retire(2400);
            yes(p.cleanupKnown()&&((List<?>)p.personalAudit().get("absent_task_ids")).equals(Collections.singletonList(100)),"close not audited");
        });
        test("personal same-package reopen is audit-only while profile remains independently owned",()->{
            Fake f=new Fake();ProfileOwnedTask p=active(f);f.personalClosed=true;f.personalAdded=true;
            yes(p.observe(),"personal reopen blocked profile");p.window(14,300,2000);p.retire(2400);
            yes(p.cleanupKnown()&&((List<?>)p.personalAudit().get("new_task_ids")).equals(Collections.singletonList(102)),"reopen not audited");
            yes(f.snapshot().leaves.get(102).display==0,"personal reopened task affected");
        });
        test("uncertain launch reply may clean only actual cookie-bound new leaf",()->{
            Fake f=new Fake();ProfileOwnedTask p=prepared(f);p.beforeDispatch();f.launch();
            p.retire(2400);yes(p.cleanupKnown(),"cookie-owned uncertain start not retired");
        });
        test("dispatched launch without observed leaf cannot claim empty success",()->{
            Fake f=new Fake();ProfileOwnedTask p=prepared(f);p.beforeDispatch();
            reject("PROFILE_RETIRE_ABSENCE_UNCONFIRMED",()->p.retire(1100));yes(!p.cleanupKnown(),"invented owned absence");
        });
        test("removed live task with retained raw recent blocks root and release",()->{
            Fake f=new Fake();ProfileOwnedTask p=active(f);f.keepRecents=true;
            reject("PROFILE_LEAF_RETIRE_NOT_CONFIRMED",()->p.retire(1100));
            yes(!f.mutations.contains("delete_root")&&!p.cleanupKnown(),"recents bypass");
        });
        test("delayed own empty root disappearance is observed before success",()->{
            Fake f=new Fake();ProfileOwnedTask p=active(f);f.delayedDelete=true;p.retire(2400);
            yes(p.cleanupKnown()&&!f.root&&f.now>1000,"premature root absence");
        });
        test("leaf removal failure retains custody and refuses release",()->{
            Fake f=new Fake();ProfileOwnedTask p=active(f);f.removeThrows=true;
            ProfileDisplayCustody c=new ProfileDisplayCustody();c.beforeCreate();
            reject("REMOVE_FAILED",()->p.retire(2400));c.unresolved();c.tasksVerified();
            yes(c.retain()&&!c.mayRelease()&&!c.known()&&!p.cleanupKnown(),"retire failure released");
        });
        test("unknown display create must retain process custody",()->{
            ProfileDisplayCustody c=new ProfileDisplayCustody();c.beforeCreate();c.unresolved();
            yes(c.retain()&&!c.mayRelease(),"unknown create escaped");
            try{c.displayVerifiedAbsent();throw new AssertionError("unknown release");}catch(IllegalStateException good){assertions++;}
        });
        test("root deletion error never means full cleanup",()->{
            Fake f=new Fake();ProfileOwnedTask p=active(f);f.deleteThrows=true;
            reject("DELETE_FAILED",()->p.retire(2400));yes(!p.cleanupKnown()&&f.root,"root deletion assumed");
        });
        test("task absence alone does not permit process exit",()->{
            ProfileDisplayCustody c=new ProfileDisplayCustody();c.beforeCreate();c.tasksVerified();
            yes(c.mayRelease()&&c.retain()&&!c.known(),"binder owner exited before display absence");
            c.displayVerifiedAbsent();yes(c.known()&&!c.retain(),"confirmed display retained");
        });
        test("cancel and fixed deadline prevent new window proof",()->{
            Fake f=new Fake();ProfileOwnedTask p=active(f);f.cancel=true;
            reject("CANCELLED",()->p.window(14,300,2000));f.cancel=false;f.now=2000;
            reject("PROFILE_WINDOW_DEADLINE",()->p.window(14,300,2000));
        });
        test("missing/mismatched/duplicate child arrays reject",()->{
            reject("PROFILE_CHILD_ARRAYS_INCOMPLETE",()->new ProfileTaskPolicy.Root(100,0,0,1,true,HOME,HOME,
                    new int[]{100},new int[0],new String[]{HOME},new int[][]{{0,0,1,1}}));
            reject("PROFILE_CHILD_ARRAYS_INCOMPLETE",()->new ProfileTaskPolicy.Root(100,0,0,1,true,HOME,HOME,
                    new int[]{100},null,new String[]{HOME},new int[][]{{0,0,1,1}}));
            reject("PROFILE_CHILD_IDENTITY_INVALID",()->new ProfileTaskPolicy.Root(100,0,0,1,true,HOME,HOME,
                    new int[]{100,100},new int[]{0,10},new String[]{HOME,HOME},new int[][]{{0,0,1,1},{0,0,1,1}}));
        });
        test("child arrays are snapshotted, not caller mutable authority",()->{
            int[] users={10};ProfileTaskPolicy.Root r=new ProfileTaskPolicy.Root(100,0,0,1,false,HOME,HOME,
                    new int[]{100},users,new String[]{HOME},new int[][]{{0,0,1,1}});users[0]=0;
            ProfileTaskPolicy.Snapshot s=new ProfileTaskPolicy.Snapshot(Collections.singletonList(r));
            reject("PROFILE_ALREADY_HAS_LEAF_TASK",()->s.requireDedicatedEmpty(target(10,1010367)));
        });
        test("raw recents require actual user fields and complete detail",()->{
            reject("PROFILE_RECENT_UID_USER_MISMATCH",()->ProfileTaskPolicy.Recents.parse(recent(100,0,1010367)));
            try{ProfileTaskPolicy.Recents.parse(recent(100,0,10367).replace("userId=0","userId=?"));
                throw new AssertionError("unknown recent user accepted");}
            catch(ProfileTaskPolicy.Refusal good){yes("PROFILE_RECENT_USER_UNKNOWN".equals(good.code),good.code);}
            try{ProfileTaskPolicy.Recents.parse(recent(100,0,10367).replace("    Activities=[]\n",""));
                throw new AssertionError("truncated recents accepted");}
            catch(BackgroundOwnedSingleTask.Refusal good){yes("RECENTS_TASK_DETAIL_INCOMPLETE".equals(good.code),good.code);}
        });
        System.out.println("{\"schema\":\"hepta.profile-broker-host-tests.v1\",\"passed\":true,\"cases\":"+cases.size()
                +",\"assertions\":"+assertions+",\"framework_fixtures_synthetic\":true,\"phone_contacted\":false}");
        for(String name:cases)System.out.println("PASS "+name);
    }
}
