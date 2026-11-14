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

/** Exact production geometry block; only Display/DisplayManager/clock calls are host IO fixtures. */
final class BrokerDisplayGeometryHostTest {
    private static final List<String> passed=new ArrayList<String>();
    private static int checks;
    interface Check {void run()throws Exception;}
    private static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
    private static void test(String name,Check c)throws Exception{
        android.os.SystemClock.now=100;android.os.SystemClock.step=1;c.run();passed.add(name);
    }
    private static void refusal(String code,Check c)throws Exception{
        try{c.run();}catch(BrokerProtocol.Refusal e){check(code.equals(e.code),"wrong refusal: "+e.code);return;}
        throw new AssertionError("expected "+code);
    }
    private static android.view.Display main(int width,int height,int density){
        return new android.view.Display(0,"Main display",width,height,density,0);
    }
    private static android.view.Display main(){return main(1224,2992,480);}
    private static android.hardware.display.DisplayManager manager(android.view.Display first,android.view.Display second){
        return new android.hardware.display.DisplayManager(first,second,new android.view.Display(1,"Cover display",1080,1272,360,2));
    }
    private static BrokerDisplayGeometryFixture.DisplayGeometry capture(android.view.Display first,android.view.Display second)throws Exception{
        return BrokerDisplayGeometryFixture.DisplayGeometry.snapshotDefault(manager(first,second));
    }
    public static void main(String[] args)throws Exception{
        test("actual_default0_geometry_not_cover1",()->{
            android.hardware.display.DisplayManager m=manager(main(),main());
            BrokerDisplayGeometryFixture.DisplayGeometry g=BrokerDisplayGeometryFixture.DisplayGeometry.snapshotDefault(m);
            check(g.displayId==0&&g.width==1224&&g.height==2992&&g.density==480&&g.rotation==0,"actual default tuple");
            check(m.requested.equals(Arrays.asList(0,0)),"exactly two explicit default-display reads");
            check(g.endedElapsed>=g.startedElapsed,"snapshot observation span");
        });
        test("rotated_logical_dimensions_preserved",()->{
            android.view.Display a=main(2992,1224,480),b=main(2992,1224,480);a.rotation=b.rotation=1;
            BrokerDisplayGeometryFixture.DisplayGeometry g=capture(a,b);
            check(g.width==2992&&g.height==1224&&g.rotation==1,"do not swap already-rotated dimensions");
        });
        test("logical_override_not_physical_mode",()->{
            BrokerDisplayGeometryFixture.DisplayGeometry g=capture(main(1080,2400,400),main(1080,2400,400));
            check(g.width==1080&&g.height==2400&&g.density==400,"logical override preserved");
        });
        test("old_tuple_only_when_observed_on_default",()->{
            BrokerDisplayGeometryFixture.DisplayGeometry g=capture(main(720,1280,240),main(720,1280,240));
            check(g.width==720&&g.height==1280&&g.density==240,"observed tuple still legal");
        });
        test("missing_manager_refused",()->refusal("DISPLAY_GEOMETRY_UNAVAILABLE",()->BrokerDisplayGeometryFixture.DisplayGeometry.snapshotDefault(null)));
        test("missing_default_does_not_fall_back_to_cover",()->refusal("DISPLAY_GEOMETRY_UNAVAILABLE",()->capture(null,null)));
        test("wrong_default_id_refused",()->{android.view.Display a=main();a.id=1;refusal("DISPLAY_GEOMETRY_UNAVAILABLE",()->capture(a,a));});
        test("invalid_default_refused",()->{android.view.Display a=main();a.valid=false;refusal("DISPLAY_GEOMETRY_UNAVAILABLE",()->capture(a,a));});
        test("default_disappears_between_reads",()->refusal("DISPLAY_GEOMETRY_UNAVAILABLE",()->capture(main(),null)));
        for(int field=0;field<5;field++){
            final int changed=field;
            test("default_changes_between_reads_"+field,()->{
                android.view.Display second=main();
                if(changed==0)second.width++;else if(changed==1)second.height++;else if(changed==2)second.density++;
                else if(changed==3)second.rotation=1;else second.name="Replaced display";
                refusal("DEFAULT_DISPLAY_GEOMETRY_CHANGED",()->capture(main(),second));
            });
        }
        test("rotation_changes_during_metrics_read",()->{
            android.view.Display a=main();a.afterMetrics=()->a.rotation=1;
            refusal("DISPLAY_GEOMETRY_CHANGED_DURING_READ",()->capture(a,a));
        });
        test("display_invalidated_during_metrics_read",()->{
            android.view.Display a=main();a.afterMetrics=()->a.valid=false;
            refusal("DISPLAY_GEOMETRY_CHANGED_DURING_READ",()->capture(a,a));
        });
        test("identity_changes_during_metrics_read",()->{
            android.view.Display a=main();a.afterMetrics=()->a.id=1;
            refusal("DISPLAY_GEOMETRY_CHANGED_DURING_READ",()->capture(a,a));
        });
        for(String name:new String[]{null,"",String.join("",Collections.nCopies(257,"x"))}){
            test("invalid_display_name_"+(name==null?"null":name.length()),()->{
                android.view.Display a=main();a.name=name;
                refusal("DISPLAY_GEOMETRY_CHANGED_DURING_READ",()->capture(a,a));
            });
        }
        int[][] invalid={{0,2992,480},{1224,0,480},{-1,2992,480},{1224,-1,480},
            {4097,100,480},{100,4097,480},{4000,4001,480},{Integer.MAX_VALUE,Integer.MAX_VALUE,480},
            {1224,2992,79},{1224,2992,1001},{1224,2992,0}};
        for(int i=0;i<invalid.length;i++){
            final int[] v=invalid[i];test("allocation_or_density_bound_"+i,()->refusal("DISPLAY_GEOMETRY_BOUNDS",()->capture(main(v[0],v[1],v[2]),main(v[0],v[1],v[2]))));
        }
        test("exact_16m_pixel_limit_allowed",()->{
            BrokerDisplayGeometryFixture.DisplayGeometry g=capture(main(4000,4000,480),main(4000,4000,480));
            check((long)g.width*g.height==16000000L,"exact pixel limit");
        });
        test("rotation_enum_bound",()->{android.view.Display a=main();a.rotation=4;refusal("DISPLAY_GEOMETRY_BOUNDS",()->capture(a,a));});
        test("backwards_elapsed_clock_refused",()->{android.os.SystemClock.step=-1;refusal("DISPLAY_GEOMETRY_BOUNDS",()->capture(main(),main()));});
        test("negative_elapsed_clock_refused",()->{android.os.SystemClock.now=-2;refusal("DISPLAY_GEOMETRY_BOUNDS",()->capture(main(),main()));});
        test("framework_failure_propagates_without_fallback",()->{
            android.view.Display a=main();a.afterMetrics=()->{throw new SecurityException("fixture");};
            try{capture(a,a);throw new AssertionError("framework error accepted");}catch(SecurityException expected){check("fixture".equals(expected.getMessage()),"original error");}
        });
        test("virtual_readback_same_tuple_allowed",()->{
            BrokerDisplayGeometryFixture.DisplayGeometry g=capture(main(),main());
            android.view.Display v=new android.view.Display(6,"hepta-bg-test",1224,2992,480,0);
            check(g.sameSize(BrokerDisplayGeometryFixture.DisplayGeometry.read(v,6)),"VD exact tuple");
        });
        for(int field=0;field<3;field++){
            final int changed=field;test("virtual_readback_changed_tuple_"+field,()->{
                BrokerDisplayGeometryFixture.DisplayGeometry g=capture(main(),main());
                android.view.Display v=new android.view.Display(6,"hepta-bg-test",1224,2992,480,0);
                if(changed==0)v.width++;else if(changed==1)v.height++;else v.density++;
                check(!g.sameSize(BrokerDisplayGeometryFixture.DisplayGeometry.read(v,6)),"mismatched VD tuple cannot pass");
            });
        }
        test("virtual_readback_wrong_id_refused",()->refusal("DISPLAY_GEOMETRY_UNAVAILABLE",()->BrokerDisplayGeometryFixture.DisplayGeometry.read(main(),6)));
        test("snapshot_not_mutated_by_later_default_changes",()->{
            android.view.Display a=main();BrokerDisplayGeometryFixture.DisplayGeometry g=capture(a,a);a.width=720;a.height=1280;a.density=240;
            check(g.width==1224&&g.height==2992&&g.density==480,"snapshot remains immutable");
        });
        test("receipt_records_actual_numeric_geometry",()->{
            BrokerDisplayGeometryFixture.DisplayGeometry g=capture(main(),main());java.util.Map<String,Object> e=g.evidence();
            check(e.get("display_id").equals(0)&&e.get("width").equals(1224)&&e.get("height").equals(2992)&&e.get("density").equals(480),"receipt tuple");
            check(e.get("pixels").equals(3662208L)&&e.get("max_pixels").equals(16000000L),"receipt allocation limits");
            check("android.view.Display.getRealMetrics".equals(e.get("metrics_source")),"actual API named");
        });
        StringBuilder names=new StringBuilder("[");for(String name:passed){if(names.length()>1)names.append(',');names.append('"').append(name).append('"');}names.append(']');
        System.out.println("{\"schema\":\"hepta.background-display-geometry-host.v1\",\"passed\":"+passed.size()+",\"assertions\":"+checks+",\"case_names\":"+names+",\"failed\":0,\"framework_calls_are_fixtures\":true,\"android_runtime\":false,\"phone_actions\":false}");
    }
}
