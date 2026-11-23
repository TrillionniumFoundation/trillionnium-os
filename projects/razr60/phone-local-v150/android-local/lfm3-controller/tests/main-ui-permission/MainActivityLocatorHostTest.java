package org.trillionnium.hepta.local;

import android.view.Display;
import org.trillionnium.hepta.background.PublicPermissionControllerUi;

/** Executes the exact production capture method against explicit inert Activity IO. */
public final class MainActivityLocatorHostTest {
    private static int cases,assertions;
    private static final java.util.List<String> names=new java.util.ArrayList<String>();
    interface Work {void run();}
    static void yes(boolean ok,String message){assertions++;if(!ok)throw new AssertionError(message);}
    static void test(String name,Work work){work.run();cases++;names.add(name);}
    static void refuse(Work work){try{work.run();throw new AssertionError("invalid UI accepted");}
        catch(IllegalArgumentException expected){assertions++;}}
    static MainActivity fresh(){android.os.Looper.main=true;return new MainActivity();}
    static final class OtherActivity extends MainActivity {}
    public static void main(String[] args){
        test("exact focused MainActivity records actual UID PID task display and owner",()->{
            PublicPermissionControllerUi.Locator l=fresh().capture("owner");
            yes(l.uid==10481&&l.pid==2020&&l.task==100&&l.display==0,"actual identity");
            yes(l.ownerSha256.equals("4c1029697ee358715d3a14a2add817c4b01651440de808371f78165ac90dc581"),"actual owner bytes");});
        test("valid cover MainActivity keeps its actual physical display",()->{
            MainActivity a=fresh();a.display=new Display(1);yes(a.capture("owner").display==1,"cover display");});
        test("virtual display preserves strict no-exemption path",()->{
            MainActivity a=fresh();a.display=new Display(7);a.focus=false;yes(a.capture("owner")==null,"VD locator forbidden");});
        test("off-main-thread callback refuses",()->{MainActivity a=fresh();android.os.Looper.main=false;refuse(()->a.capture("owner"));});
        test("missing invalid or negative actual display refuses",()->{
            MainActivity a=fresh();a.display=null;refuse(()->a.capture("owner"));
            a.display=new Display(0);a.display.valid=false;refuse(()->a.capture("owner"));
            a.display=new Display(-1);refuse(()->a.capture("owner"));});
        test("different Activity class and component refuse",()->{
            fresh();refuse(()->new OtherActivity().capture("owner"));
            MainActivity a=fresh();a.component=new android.content.ComponentName("org.trillionnium.hepta.local","org.trillionnium.hepta.local.Other");
            refuse(()->a.capture("owner"));});
        test("finishing destroyed unfocused and hidden source refuse",()->{
            MainActivity a=fresh();a.finishing=true;refuse(()->a.capture("owner"));
            a.finishing=false;a.destroyed=true;refuse(()->a.capture("owner"));
            a.destroyed=false;a.focus=false;refuse(()->a.capture("owner"));
            a.focus=true;a.window.decor.shown=false;refuse(()->a.capture("owner"));});
        test("different application UID and missing actual task refuse",()->{
            MainActivity a=fresh();a.application.uid=10482;refuse(()->a.capture("owner"));
            a.application.uid=10481;a.task=0;refuse(()->a.capture("owner"));});
        System.out.println(new org.json.JSONObject().put("schema","hepta.main-activity-locator-host.v1")
                .put("all_pass",true).put("cases",cases).put("assertions",assertions).put("case_names",names)
                .put("activity_io_synthetic",true).put("actual_production_method_executed",true)
                .put("phone_operations",0).put("android_main_screen_executed",false));
    }
}
