package org.trillionnium.hepta.background;

import java.util.Arrays;

/** Actual production guard with authored complete framework-shaped task snapshots. */
public final class PublicTaskFenceHostTest {
    private static int cases,assertions;
    private static final String GEN="4f17304e-9991-4d2d-93a4-513ee8113552";
    interface Work{void run()throws Exception;}
    static void yes(boolean b,String m){assertions++;if(!b)throw new AssertionError(m);}
    static void test(String n,Work w)throws Exception{w.run();cases++;System.out.println("PASS "+n);}
    static void refuse(Work w,String code)throws Exception{try{w.run();throw new AssertionError("unsafe task accepted");}catch(BrokerProtocol.Refusal e){yes(code.equals(e.code),"unexpected refusal "+e.code);}}
    static ProfileTaskPolicy.Root row(int id,int display,int rootUser,int childId,int childUser)throws Exception{
        String name="com.example.app/com.example.app.Main";
        return new ProfileTaskPolicy.Root(id,display,rootUser,1,true,name,name,new int[]{childId},new int[]{childUser},new String[]{name},new int[][]{{0,0,500,500}});
    }
    static ProfileTaskPolicy.Snapshot snapshot(ProfileTaskPolicy.Root... roots)throws Exception{return new ProfileTaskPolicy.Snapshot(Arrays.asList(roots));}
    static ProfileTaskPolicy.Snapshot initial()throws Exception{return snapshot(row(100,0,0,100,0),row(101,1,0,101,0));}
    static PublicOwnGroupTaskFence fence(int target)throws Exception{return new PublicOwnGroupTaskFence(initial(),target,GEN);}
    public static void main(String[] args)throws Exception{
        test("ordinary user can change physical tasks during profile work",()->{PublicOwnGroupTaskFence f=fence(10);
            f.observe(snapshot(row(102,0,0,102,0),row(101,1,0,101,0),row(200,7,0,300,10)),7,100);
            yes(Boolean.FALSE.equals(f.evidence().get("physical_user_activity_frozen")),"main user frozen");});
        test("target user zero does not exclude or reject every personal task",()->{PublicOwnGroupTaskFence f=fence(0);
            f.observe(snapshot(row(102,0,0,102,0),row(101,1,0,101,0),row(300,7,0,300,0)),7,100);
            yes(Boolean.FALSE.equals(f.evidence().get("retired")),"all user zero tasks rejected");});
        test("profile leaf on main is rejected even under user zero root",()->{PublicOwnGroupTaskFence f=fence(10);
            refuse(()->f.observe(snapshot(row(100,0,0,300,10),row(101,1,0,101,0)),7,100),"PUBLIC_TARGET_PROFILE_ON_PHYSICAL_DISPLAY");});
        test("profile leaf on cover is rejected",()->{PublicOwnGroupTaskFence f=fence(10);
            refuse(()->f.observe(snapshot(row(100,0,0,100,0),row(101,1,0,300,10)),7,100),"PUBLIC_TARGET_PROFILE_ON_PHYSICAL_DISPLAY");});
        test("dedicated target profile on a different virtual display is rejected",()->{PublicOwnGroupTaskFence f=fence(10);
            refuse(()->f.observe(snapshot(row(100,0,0,100,0),row(101,1,0,101,0),row(300,9,10,300,10)),7,100),"PUBLIC_TARGET_PROFILE_ON_FOREIGN_DISPLAY");});
        test("historical task cannot be reparented into owned display",()->{PublicOwnGroupTaskFence f=fence(0);
            refuse(()->f.observe(snapshot(row(102,0,0,102,0),row(101,1,0,101,0),row(100,7,0,100,0)),7,100),"PUBLIC_PREEXISTING_TASK_MOVED_TO_OWNED_DISPLAY");});
        test("actually observed owned task later on main is rejected",()->{PublicOwnGroupTaskFence f=fence(0);
            f.observe(snapshot(row(100,0,0,100,0),row(101,1,0,101,0),row(300,7,0,300,0)),7,100);
            refuse(()->f.observe(snapshot(row(300,0,0,300,0),row(101,1,0,101,0)),7,200),"PUBLIC_OBSERVED_OWNED_TASK_ESCAPED");});
        test("owned task cannot move to any other virtual display",()->{PublicOwnGroupTaskFence f=fence(0);
            f.observe(snapshot(row(100,0,0,100,0),row(101,1,0,101,0),row(300,7,0,300,0)),7,100);
            refuse(()->f.observe(snapshot(row(100,0,0,100,0),row(101,1,0,101,0),row(300,9,0,300,0)),7,200),"PUBLIC_OBSERVED_OWNED_TASK_ESCAPED");});
        test("owned task absence is allowed but is not a cleanup proof",()->{PublicOwnGroupTaskFence f=fence(0);
            f.observe(snapshot(row(100,0,0,100,0),row(101,1,0,101,0),row(300,7,0,300,0)),7,100);f.observe(initial(),7,200);
            yes(Boolean.FALSE.equals(f.evidence().get("task_mutation_authority"))&&Boolean.FALSE.equals(f.evidence().get("recents_unchanged_claimed")),"read fence invented authority");});
        test("failed guard never becomes live after a corrected snapshot",()->{PublicOwnGroupTaskFence f=fence(10);
            refuse(()->f.observe(snapshot(row(100,0,10,100,10),row(101,1,0,101,0)),7,100),"PUBLIC_TARGET_PROFILE_ON_PHYSICAL_DISPLAY");
            refuse(()->f.observe(initial(),7,200),"PUBLIC_TASK_FENCE_UNAVAILABLE");});
        test("owned display identity cannot change",()->{PublicOwnGroupTaskFence f=fence(0);f.observe(initial(),7,100);
            refuse(()->f.observe(initial(),8,200),"PUBLIC_TASK_FENCE_DISPLAY_CHANGED");});
        System.out.println("{\"cases\":"+cases+",\"assertions\":"+assertions+",\"all_pass\":true,\"phone_contacted\":false,\"actual_framework_executed\":false}");
    }
}
