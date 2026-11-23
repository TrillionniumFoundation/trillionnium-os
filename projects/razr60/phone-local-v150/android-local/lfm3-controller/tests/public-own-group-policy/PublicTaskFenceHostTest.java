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
    static PublicOwnGroupTaskFence.LocationRoot locationRoot(int id,int display,int rootUser,int[] children,int[] childUsers,String[] names)throws Exception{
        int[][] bounds=new int[children.length][];for(int i=0;i<children.length;i++)bounds[i]=new int[]{0,0,500,500};
        return new PublicOwnGroupTaskFence.LocationRoot(id,display,rootUser,children,childUsers,names,bounds);
    }
    static PublicOwnGroupTaskFence.LocationRoot located(int id,int display,int rootUser,int child,int user)throws Exception{
        return locationRoot(id,display,rootUser,new int[]{child},new int[]{user},new String[]{"com.example.app/com.example.app.Main"});
    }
    static PublicOwnGroupTaskFence.Census locations(PublicOwnGroupTaskFence.LocationRoot... roots)throws Exception{
        return new PublicOwnGroupTaskFence.Census(Arrays.asList(roots));
    }
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
        test("location census retains active root and raw unknown empty anchor without granting App authority",()->{
            PublicOwnGroupTaskFence f=fence(0);
            f.observe(locations(located(100,0,0,100,0),located(101,1,0,101,0),
                locationRoot(200,7,0,new int[]{201,202},new int[]{0,0},new String[]{"unknown","com.xiaomi.shop/com.xiaomi.shop2.activity.MainActivity"})),7,100);
            yes(Arrays.asList(200,201,202).equals(f.evidence().get("observed_owned_task_ids")),"complete root/anchor/app locations retained");
            yes(Boolean.FALSE.equals(f.evidence().get("task_mutation_authority"))&&!Boolean.TRUE.equals(f.evidence().get("recents_unchanged_claimed")),"location observation grants no identity/removal proof");
        });
        test("location census uses actual profile child user under a user zero container",()->{
            PublicOwnGroupTaskFence f=fence(10);
            f.observe(locations(located(100,0,0,100,0),located(101,1,0,101,0),located(200,7,0,300,10)),7,100);
            yes(Arrays.asList(200,300).equals(f.evidence().get("observed_owned_task_ids")),"user zero root and user ten leaf both retained");
            PublicOwnGroupTaskFence main=fence(10);
            refuse(()->main.observe(locations(located(100,0,0,300,10),located(101,1,0,101,0)),7,100),"PUBLIC_TARGET_PROFILE_ON_PHYSICAL_DISPLAY");
            PublicOwnGroupTaskFence foreign=fence(10);
            refuse(()->foreign.observe(locations(located(100,0,0,100,0),located(101,1,0,101,0),located(200,9,0,300,10)),7,100),"PUBLIC_TARGET_PROFILE_ON_FOREIGN_DISPLAY");
        });
        test("location census refuses unknown users incomplete parallel arrays and bounds",()->{
            refuse(()->locationRoot(200,7,0,new int[]{201},new int[]{-1},new String[]{"unknown"}),"PUBLIC_TASK_LOCATION_CHILD_IDENTITY_INVALID");
            refuse(()->locationRoot(200,7,0,new int[]{201},null,new String[]{"unknown"}),"PUBLIC_TASK_LOCATION_ARRAYS_INCOMPLETE");
            refuse(()->locationRoot(200,7,0,new int[]{201},new int[0],new String[]{"unknown"}),"PUBLIC_TASK_LOCATION_ARRAYS_INCOMPLETE");
            refuse(()->locationRoot(200,7,0,new int[]{201},new int[]{0},new String[0]),"PUBLIC_TASK_LOCATION_ARRAYS_INCOMPLETE");
            refuse(()->locationRoot(200,7,0,new int[]{201},new int[]{0},new String[]{null}),"PUBLIC_TASK_LOCATION_CHILD_NAME_UNAVAILABLE");
            for(int[] bound:new int[][]{null,new int[]{0,0,1},new int[]{5,0,4,9},new int[]{0,0,500,32769}})
                refuse(()->new PublicOwnGroupTaskFence.LocationRoot(200,7,0,new int[]{201},new int[]{0},new String[]{"unknown"},new int[][]{bound}),"PUBLIC_TASK_LOCATION_CHILD_BOUNDS_INVALID");
            refuse(()->new PublicOwnGroupTaskFence.LocationRoot(200,7,0,new int[]{201},new int[]{0},new String[]{"unknown"},null),"PUBLIC_TASK_LOCATION_ARRAYS_INCOMPLETE");
        });
        test("location census refuses duplicate root or leaf identifiers and incomplete root lists",()->{
            refuse(()->locations(located(200,7,0,201,0),located(200,7,0,202,0)),"PUBLIC_TASK_LOCATION_ROOT_DUPLICATE");
            refuse(()->locations(located(200,7,0,201,0),located(202,7,0,201,0)),"PUBLIC_TASK_LOCATION_LEAF_DUPLICATE_OR_BOUND");
            refuse(()->locationRoot(200,7,0,new int[]{201,201},new int[]{0,0},new String[]{"unknown","unknown"}),"PUBLIC_TASK_LOCATION_CHILD_IDENTITY_INVALID");
            refuse(()->locations(),"PUBLIC_TASK_LOCATION_ROOT_QUERY_INCOMPLETE");
            refuse(()->new PublicOwnGroupTaskFence.Census(null),"PUBLIC_TASK_LOCATION_ROOT_QUERY_INCOMPLETE");
            refuse(()->locations((PublicOwnGroupTaskFence.LocationRoot)null),"PUBLIC_TASK_LOCATION_ROOT_DUPLICATE");
        });
        test("location census copies inputs and preserves relocation escape and irreversible refusal",()->{
            int[] ids={201},users={0};String[] names={"unknown"};
            PublicOwnGroupTaskFence.Census original=locations(located(100,0,0,100,0),located(101,1,0,101,0),locationRoot(200,7,0,ids,users,names));
            ids[0]=100;users[0]=10;names[0]=null;PublicOwnGroupTaskFence f=fence(0);f.observe(original,7,100);
            yes(Arrays.asList(200,201).equals(f.evidence().get("observed_owned_task_ids")),"later array mutation cannot replace recorded identity");
            refuse(()->f.observe(locations(located(100,0,0,201,0),located(101,1,0,101,0)),7,200),"PUBLIC_OBSERVED_OWNED_TASK_ESCAPED");
            refuse(()->f.observe(original,7,300),"PUBLIC_TASK_FENCE_UNAVAILABLE");
            PublicOwnGroupTaskFence historical=fence(0);
            refuse(()->historical.observe(locations(located(102,0,0,102,0),located(101,1,0,101,0),located(200,7,0,100,0)),7,100),"PUBLIC_PREEXISTING_TASK_MOVED_TO_OWNED_DISPLAY");
            PublicOwnGroupTaskFence escaped=fence(0);escaped.observe(original,7,100);
            refuse(()->escaped.observe(locations(located(100,0,0,100,0),located(101,1,0,101,0),located(200,9,0,201,0)),7,200),"PUBLIC_OBSERVED_OWNED_TASK_ESCAPED");
        });
        System.out.println("{\"cases\":"+cases+",\"assertions\":"+assertions+",\"all_pass\":true,\"phone_contacted\":false,\"actual_framework_executed\":false}");
    }
}
