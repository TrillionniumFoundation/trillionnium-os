package org.trillionnium.hepta.background;

import android.content.ComponentName;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Actual production snapshot method and policy; framework reflection fields are explicit surrogates. */
public final class BrokerTaskSnapshotHostTest {
    public static final class Root {
        public int displayId, numActivities;
        public boolean visible;
        public ComponentName topActivity, baseActivity;
        public int[] childTaskIds;
        public String[] childTaskNames;
        Root(int display,int activities,boolean shown,String... names) {
            displayId=display;numActivities=activities;visible=shown;childTaskNames=names;
            childTaskIds=new int[names.length];for(int i=0;i<names.length;i++)childTaskIds[i]=i+4;
        }
    }
    public static final class Tasks {
        final List<Object> roots;
        Tasks(Object... values){roots=Arrays.asList(values);}
        public List<Object> getAllRootTaskInfos(){return roots;}
    }
    private static final List<String> passed=new ArrayList<String>();
    interface Check {void run()throws Exception;}
    private static void test(String name,Check c)throws Exception{c.run();passed.add(name);}
    private static void refusal(String code,Check c)throws Exception{
        try{c.run();}catch(BrokerProtocol.Refusal e){if(code.equals(e.code))return;throw e;}
        throw new AssertionError("expected "+code);
    }
    private static BrokerTaskSnapshotFixture actual(Root r)throws Exception{return new BrokerTaskSnapshotFixture(new Tasks(r));}
    private static Root empty(){return new Root(0,0,false,"unknown","unknown");}
    public static void main(String[] args)throws Exception{
        // Genuine Razr dump: organizer root #3, child #4/#5, both invisible with sz=0/no Hist.
        test("razr_empty_organizer_unknown_children",()->actual(empty()).requireNoOtherDisplay("com.motorola.cn.calculator",7));
        test("unknown_with_nonzero_activity_count_refused",()->{Root r=empty();r.numActivities=1;refusal("TASK_COMPONENT_UNRESOLVED",()->actual(r).requireNoOtherDisplay("com.example.app",7));});
        test("unknown_visible_root_refused",()->{Root r=empty();r.visible=true;refusal("TASK_COMPONENT_UNRESOLVED",()->actual(r).requireNoOtherDisplay("com.example.app",7));});
        test("unknown_with_top_component_refused",()->{Root r=empty();r.topActivity=new ComponentName("com.example.app","Top");refusal("TASK_COMPONENT_UNRESOLVED",()->actual(r).requireNoOtherDisplay("com.example.app",7));});
        test("unknown_with_base_component_refused",()->{Root r=empty();r.baseActivity=new ComponentName("com.example.app","Base");refusal("TASK_COMPONENT_UNRESOLVED",()->actual(r).requireNoOtherDisplay("com.example.app",7));});
        for(String name:new String[]{null,"", "unresolved", "unknown/", "bad;package"})test("empty_does_not_ignore_malformed_"+String.valueOf(name),()->refusal("TASK_COMPONENT_UNRESOLVED",()->actual(new Root(0,0,false,name)).requireNoOtherDisplay("com.example.app",7)));
        test("zero_count_known_component_still_blocks_main",()->refusal("APP_ALREADY_ON_MAIN_DISPLAY",()->actual(new Root(0,0,false,"com.example.app/.Main","unknown")).requireNoOtherDisplay("com.example.app",7)));
        test("zero_count_known_package_still_blocks_other_display",()->refusal("APP_ALREADY_ON_OTHER_DISPLAY",()->actual(new Root(1,0,false,"com.example.app","unknown")).requireNoOtherDisplay("com.example.app",7)));
        test("active_component_main_task_remains_blocked",()->{Root r=new Root(0,1,true,"com.example.app/.Main");r.topActivity=new ComponentName("com.example.app","Main");refusal("APP_ALREADY_ON_MAIN_DISPLAY",()->actual(r).requireNoOtherDisplay("com.example.app",7));});
        test("matching_target_display_remains_allowed",()->actual(new Root(7,1,true,"com.example.app/.Main")).requireNoOtherDisplay("com.example.app",7));
        test("negative_activity_count_refused",()->{Root r=empty();r.numActivities=-1;refusal("TASK_SNAPSHOT_BOUNDS",()->actual(r).requireNoOtherDisplay("com.example.app",7));});
        test("incomplete_child_arrays_still_refused",()->{Root r=empty();r.childTaskIds=new int[]{4};refusal("TASK_SNAPSHOT_INCOMPLETE",()->actual(r).requireNoOtherDisplay("com.example.app",7));});
        test("missing_activity_field_refused",()->{
            try{new BrokerTaskSnapshotFixture(new Tasks(new Object())).requireNoOtherDisplay("com.example.app",7);}
            catch(NoSuchFieldException expected){return;}throw new AssertionError("missing framework field accepted");
        });
        System.out.println("{\"schema\":\"hepta.background-task-snapshot-host.v1\",\"passed\":"+passed.size()+",\"failed\":0,\"framework_fields_are_fixtures\":true,\"android_runtime\":false,\"phone_actions\":false}");
    }
}
