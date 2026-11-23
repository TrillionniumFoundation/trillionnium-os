package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileIdentity;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;

/** Actual receipt, Frame and rejection consumers on explicit synthetic host
 * values. No Android, phone, model, pixels, effects or business result. */
public final class NativeAxConsumersHostTest {
    private static final List<String> names=new ArrayList<String>();
    private static int assertions;
    private static final String GEN="11111111-1111-1111-1111-111111111111";
    private static final String PKG="com.xiaomi.shop";
    private interface Work {void run()throws Exception;}
    private static void test(String name,Work w)throws Exception{
        if(names.contains(name))throw new AssertionError("duplicate case");
        try{w.run();names.add(name);}catch(Exception|AssertionError e){throw new AssertionError(name,e);}
    }
    private static void yes(boolean b){assertions++;if(!b)throw new AssertionError("false assertion");}
    private static void rejects(Work w)throws Exception{
        try{w.run();}catch(IllegalArgumentException expected){assertions++;return;}
        throw new AssertionError("expected refusal");
    }
    private static String repeat(char c,int n){StringBuilder s=new StringBuilder();for(int i=0;i<n;i++)s.append(c);return s.toString();}
    private static String h(char c){return repeat(c,64);}
    private static Map<String,Object> map(){return new TreeMap<String,Object>();}
    @SuppressWarnings("unchecked") private static Map<String,Object> obj(Map<String,Object> m,String k){return (Map<String,Object>)m.get(k);}
    private static int number(Map<String,Object> m,String k){return ((Number)m.get(k)).intValue();}
    private static long clock(Map<String,Object> m,String k){return ((Number)m.get(k)).longValue();}
    private static String text(Map<String,Object> m,String k){return (String)m.get(k);}
    private static Map<String,Object> binding(WindowOwnership profile){
        Map<String,Object> b=map();
        b.put("task_id",repeat('a',32));b.put("owner_sha256",h('a'));b.put("execution_target_sha256",h('b'));
        b.put("task_authorization_sha256",h('c'));b.put("actual_selection_sha256",h('d'));b.put("native_goal_sha256",h('e'));
        b.put("observation_id",repeat('b',32));b.put("package",PKG);b.put("background_generation",GEN);
        b.put("app_tree_sha256",h('f'));b.put("observation_state_sha256",h('1'));
        b.put("display_id",7);b.put("window_id",13);b.put("rotation",0);b.put("width",1000);b.put("height",2000);
        b.put("left",0);b.put("top",0);b.put("right",1000);b.put("bottom",2000);
        b.put("captured_elapsed_ms",220L);b.put("original_census_captured_elapsed_ms",205L);
        b.put("profile_window",profile==null?null:profile.evidence());
        b.put("profile_action_identity",profile==null?null:NativeAppEvidence.profileActionIdentity(profile));
        return b;
    }
    private static Map<String,Object> node(){
        Map<String,Object> n=map();
        n.put("path","0");n.put("parent_class","");n.put("package",PKG);n.put("window_id",13);
        n.put("class","android.view.ViewGroup");n.put("view_id","");n.put("text","");n.put("description","");n.put("label","");
        n.put("ref_signature_sha256",h('2'));n.put("bounds",Arrays.asList(0,0,1000,2000));n.put("children",0);
        for(String k:Arrays.asList("visible","enabled","clickable","action_click"))n.put(k,true);
        for(String k:Arrays.asList("editable","scrollable","focused","password","selected","checkable","checked"))n.put(k,false);
        n.put("scroll_actions","");n.put("ime_enter","");n.put("input_sha256",null);return n;
    }
    private static Map<String,Object> watermark(){Map<String,Object> m=map();for(String k:Arrays.asList("events","content","unknown","boundary"))m.put(k,0L);return m;}
    private static Map<String,Object> census(Map<String,Object> b,long begin,long end){
        Map<String,Object> c=map(),id=new TreeMap<String,Object>(b);
        for(String k:Arrays.asList("observation_id","captured_elapsed_ms","profile_window","profile_action_identity","original_census_captured_elapsed_ms"))id.remove(k);
        c.put("identity",id);c.put("nodes",Collections.singletonList(node()));c.put("reported_windows",Collections.singletonMap("window",13));
        c.put("window",Collections.singletonMap("window_id",13));c.put("complete",true);c.put("truncated",false);c.put("visited",1);
        for(String k:Arrays.asList("pending","child_slots_omitted","node_budget_omissions","text_budget_omissions"))c.put(k,0);
        c.put("profile_window",b.get("profile_window"));c.put("profile_owner",b.get("profile_action_identity"));
        c.put("census_captured_elapsed_ms",begin+5);c.put("read_started_elapsed_ms",begin);c.put("read_completed_elapsed_ms",end);
        return c;
    }
    private static Map<String,Object> receipt(Map<String,Object> b){
        Map<String,Object> r=map();r.put("schema","hepta.native-ax-capture.v1");r.put("kind","native_ax");r.put("binding",b);
        for(String k:Arrays.asList("visual_model","screenshot_present","publication_refreshes_capture_age","grants_action_authority","business_completion_verified"))r.put(k,false);
        r.put("first",census(b,200,210));r.put("second",census(b,230,240));
        r.put("request_started_elapsed_ms",100L);r.put("request_deadline_elapsed_ms",12000L);r.put("sealed_elapsed_ms",250L);
        r.put("capture_watermark",watermark());r.put("second_start_watermark",watermark());r.put("second_completed_watermark",watermark());
        r.put("complete_census_endpoint_frozen",true);return r;
    }
    private static ObservationCaptureEvidence capture(Map<String,Object> b){
        Map<String,Object> r=receipt(b);byte[] bytes=ObservationCaptureEvidence.nativeAxBytes(r);
        return ObservationCaptureEvidence.fromSealedNativeAx(r,bytes,ObservationCaptureEvidence.hash(bytes));
    }
    private static NativeAppEvidence.Node retained(){
        return new NativeAppEvidence.Node("n1",PKG,"android.view.ViewGroup","","","","0","",h('2'),"",
                0,0,1000,2000,true,false,true,false,false,false,false,false,Collections.<String>emptySet());
    }
    private static NativeAppEvidence.Frame frame(Map<String,Object> b,String screen,ObservationCaptureEvidence c,
            WindowOwnership p,boolean truncated,boolean complete,boolean metadata){
        return new NativeAppEvidence.Frame(text(b,"task_id"),text(b,"owner_sha256"),text(b,"execution_target_sha256"),
                text(b,"task_authorization_sha256"),text(b,"actual_selection_sha256"),text(b,"observation_id"),text(b,"package"),
                text(b,"background_generation"),text(b,"app_tree_sha256"),text(b,"observation_state_sha256"),screen,h('3'),h('4'),
                number(b,"display_id"),number(b,"window_id"),number(b,"rotation"),number(b,"width"),number(b,"height"),
                number(b,"left"),number(b,"top"),number(b,"right"),number(b,"bottom"),clock(b,"captured_elapsed_ms"),
                truncated,complete,Collections.singletonList(retained()),1,metadata,p,c);
    }
    private static NativeAppEvidence.Frame legacy(String screen){
        Map<String,Object> b=binding(null);
        return new NativeAppEvidence.Frame(text(b,"task_id"),text(b,"owner_sha256"),text(b,"execution_target_sha256"),
                text(b,"task_authorization_sha256"),text(b,"actual_selection_sha256"),text(b,"observation_id"),text(b,"package"),
                text(b,"background_generation"),text(b,"app_tree_sha256"),text(b,"observation_state_sha256"),screen,h('3'),h('4'),
                7,13,0,1000,2000,0,0,1000,2000,220L,false,true,Collections.singletonList(retained()),1,true,null);
    }
    private static WindowOwnership profile(int uid,String proof){
        ProfileIdentity p=new ProfileIdentity(10,10L,0,"android.os.usertype.profile.MANAGED");
        ProfileTarget t=new ProfileTarget(p,uid,PKG,PKG+"/com.xiaomi.shop.MainActivity",20261010L,
                Collections.singletonMap("base",h('5')),Collections.singleton(h('6')));
        return new WindowOwnership(t,GEN,7,13,101,100,"22222222-2222-2222-2222-222222222222",proof,10,10L,uid,150L,2000L);
    }
    private static NativeActionSnapshotCheck.Snapshot snapshot(Map<String,Object> b,long captured){
        Map<String,Object> e=map();
        e.put("task_id",b.get("task_id"));e.put("owner_sha256",b.get("owner_sha256"));e.put("target_sha256",b.get("execution_target_sha256"));
        e.put("authorization_sha256",b.get("task_authorization_sha256"));e.put("selection_sha256",b.get("actual_selection_sha256"));
        e.put("installed_set_sha256",h('7'));e.put("goal_sha256",b.get("native_goal_sha256"));e.put("background_generation",b.get("background_generation"));
        e.put("origin_observation_id",b.get("observation_id"));
        for(String k:Arrays.asList("package","display_id","window_id","rotation","width","height"))e.put(k,b.get(k));
        e.put("root_bounds",Arrays.asList(number(b,"left"),number(b,"top"),number(b,"right"),number(b,"bottom")));
        e.put("window_metadata_sha256",h('8'));e.put("reported_windows_sha256",h('9'));e.put("reported_windows_complete",true);
        e.put("ime_visibility","hidden");e.put("captured_elapsed_ms",captured);e.put("full_native_complete",true);e.put("visited",1);
        for(String k:Arrays.asList("pending","node_omissions","text_omissions","child_omissions"))e.put(k,0);
        if(b.get("profile_action_identity")!=null)e.putAll(obj(b,"profile_action_identity"));
        Map<String,Object> n=node();n.put("package",b.get("package"));n.put("window_id",b.get("window_id"));n.put("bounds",e.get("root_bounds"));
        return new NativeActionSnapshotCheck.Snapshot(e,Collections.singletonList(new NativeActionSnapshotCheck.Node(n)));
    }
    private static NativeActionSnapshotCheck.Intent intent(NativeActionSnapshotCheck.Snapshot s){
        Map<String,Object> id=map();for(String k:NativeActionSnapshotCheck.IDENTITY)id.put(k,s.env.get(k));
        if(s.env.containsKey("profile_target_sha256"))for(String k:NativeActionSnapshotCheck.PROFILE_IDENTITY)id.put(k,s.env.get(k));
        return new NativeActionSnapshotCheck.Intent(NativeActionSnapshotCheck.SEARCH,PKG,"0","",h('2'),repeat('c',32),"n1",h('a'),null,id,300L,5000L);
    }
    private static Map<String,Object> rejection(Map<String,Object> b,String screen,ObservationCaptureEvidence c,long oldClock){
        NativeActionSnapshotCheck.Snapshot old=snapshot(b,oldClock),fresh=snapshot(b,350L);
        return NativeActionSnapshotCheck.rejectionEvidence(intent(old),old,fresh,400L,repeat('d',32),screen,h('3'),"actual refusal preserved",c);
    }
    private static Object changed(String key,Object old){
        if(key.equals("background_generation"))return "99999999-9999-9999-9999-999999999999";
        if(key.equals("package"))return "other.native.app";
        if(old instanceof String)return repeat('9',((String)old).length());
        if(key.equals("rotation"))return 1;
        return old instanceof Long?Long.valueOf(((Long)old)+1):Integer.valueOf(((Integer)old)+1);
    }
    public static void main(String[] args)throws Exception{
        final Map<String,Object> b=binding(null);final ObservationCaptureEvidence ax=capture(b);
        test("legacy_pixel_constructor_and_same_source_still_require_real_hash",()->{
            NativeAppEvidence.Frame a=legacy(h('a')),z=legacy(h('a'));yes(a.sameSource(z));yes(a.sameCapture(null,h('a')));
            yes(!a.sameCapture(null,null));yes("pixels".equals(a.evidence().get("capture_kind")));yes(Boolean.TRUE.equals(a.evidence().get("screenshot_observed")));
        });
        test("legacy_null_screenshot_is_not_ax",()->rejects(()->legacy(null)));
        test("legacy_bad_screenshot_hash_is_refused",()->rejects(()->legacy("native_ax")));
        test("valid_ax_frame_has_typed_receipt_and_no_pixel_claim",()->{
            NativeAppEvidence.Frame f=frame(b,null,ax,null,false,true,true);
            yes(f.screenshotSha==null);yes(f.capture==ax);yes("native_ax".equals(f.captureKind));
            yes(f.evidence().get("screen_sha256")==null);yes(Boolean.FALSE.equals(f.evidence().get("screenshot_observed")));
            yes(f.sameCapture(capture(binding(null)),null));yes(f.sameSource(frame(binding(null),null,capture(binding(null)),null,false,true,true)));
        });
        test("ax_with_pixel_hash_is_refused",()->rejects(()->frame(b,h('a'),ax,null,false,true,true)));
        test("ax_truncated_frame_is_refused",()->rejects(()->frame(b,null,ax,null,true,true,true)));
        test("ax_incomplete_frame_is_refused",()->rejects(()->frame(b,null,ax,null,false,false,true)));
        test("ax_without_observed_window_metadata_is_refused",()->rejects(()->frame(b,null,ax,null,false,true,false)));
        test("ax_and_pixels_never_share_source",()->{
            NativeAppEvidence.Frame f=frame(b,null,ax,null,false,true,true),p=legacy(h('a'));
            yes(!f.sameSource(p));yes(!p.sameSource(f));yes(!f.sameCapture(null,null));yes(!f.sameCapture(ax,h('a')));yes(!p.sameCapture(ax,h('a')));
        });
        test("different_sealed_bytes_with_same_binding_are_different_sources",()->{
            Map<String,Object> r=receipt(binding(null));r.put("diagnostic_marker","different actual bytes");
            byte[] bytes=ObservationCaptureEvidence.nativeAxBytes(r);ObservationCaptureEvidence other=ObservationCaptureEvidence.fromSealedNativeAx(r,bytes,ObservationCaptureEvidence.hash(bytes));
            yes(!frame(b,null,ax,null,false,true,true).sameCapture(other,null));yes(!ax.sameSource(other));
        });
        test("sealed_capture_copies_input_maps_and_bytes",()->{
            Map<String,Object> r=receipt(binding(null));byte[] bytes=ObservationCaptureEvidence.nativeAxBytes(r);
            ObservationCaptureEvidence c=ObservationCaptureEvidence.fromSealedNativeAx(r,bytes,ObservationCaptureEvidence.hash(bytes));
            obj(r,"binding").put("task_id",repeat('f',32));bytes[0]=0;yes(c.sameSource(ax));
        });
        test("wrong_receipt_kind_cannot_construct_ax_capture",()->{
            Map<String,Object> r=receipt(binding(null));r.put("kind","pixels");
            rejects(()->ObservationCaptureEvidence.nativeAxBytes(r));
        });
        test("wrong_persisted_receipt_bytes_cannot_construct_ax_capture",()->{
            Map<String,Object> r=receipt(binding(null));byte[] bytes=ObservationCaptureEvidence.nativeAxBytes(r);
            bytes[bytes.length-1]=' ';rejects(()->ObservationCaptureEvidence.fromSealedNativeAx(r,bytes,ObservationCaptureEvidence.hash(bytes)));
        });
        test("wrong_persisted_receipt_hash_cannot_construct_ax_capture",()->{
            Map<String,Object> r=receipt(binding(null));byte[] bytes=ObservationCaptureEvidence.nativeAxBytes(r);
            rejects(()->ObservationCaptureEvidence.fromSealedNativeAx(r,bytes,h('0')));
        });
        for(final String key:Arrays.asList("task_id","owner_sha256","execution_target_sha256","task_authorization_sha256","actual_selection_sha256",
                "observation_id","package","background_generation","app_tree_sha256","observation_state_sha256",
                "display_id","window_id","rotation","width","height","left","top","right","bottom","captured_elapsed_ms")){
            test("frame_rejects_wrong_"+key,()->{Map<String,Object> bad=binding(null);bad.put(key,changed(key,bad.get(key)));
                rejects(()->frame(bad,null,ax,null,false,true,true));});
        }
        final WindowOwnership p=profile(1012345,"33333333-3333-3333-3333-333333333333");
        final Map<String,Object> pb=binding(p);final ObservationCaptureEvidence pa=capture(pb);
        test("profile_frame_retains_exact_full_window_proof",()->{
            NativeAppEvidence.Frame f=frame(pb,null,pa,p,false,true,true);yes(f.profileWindow==p);yes(f.evidence().get("actual_profile_window").equals(p.evidence()));
        });
        test("profile_frame_missing_original_profile_is_refused",()->rejects(()->frame(pb,null,pa,null,false,true,true)));
        test("profile_frame_foreign_full_uid_is_refused",()->{
            WindowOwnership foreign=profile(1012346,"33333333-3333-3333-3333-333333333333");
            rejects(()->frame(pb,null,pa,foreign,false,true,true));
        });
        test("new_equal_owner_profile_proof_cannot_replace_original_capture_proof",()->{
            WindowOwnership fresh=profile(1012345,"44444444-4444-4444-4444-444444444444");
            rejects(()->frame(pb,null,pa,fresh,false,true,true));
        });
        test("legacy_rejection_diagnostic_keeps_pixel_hash_gate",()->{
            NativeActionSnapshotCheck.Snapshot o=snapshot(b,205),f=snapshot(b,350);
            Map<String,Object> d=NativeActionSnapshotCheck.rejectionEvidence(intent(o),o,f,400,repeat('d',32),h('a'),h('3'),"refusal");
            yes("pixels".equals(d.get("original_capture_kind")));yes(h('a').equals(d.get("original_screen_sha256")));yes(Boolean.FALSE.equals(d.get("grants_dispatch")));
            rejects(()->NativeActionSnapshotCheck.rejectionEvidence(intent(o),o,f,400,repeat('d',32),null,h('3'),"refusal"));
        });
        test("ax_rejection_keeps_real_type_without_screen_hash",()->{
            Map<String,Object> d=rejection(b,null,ax,205L);yes("native_ax".equals(d.get("original_capture_kind")));
            yes(d.get("original_screen_sha256")==null);yes(Boolean.FALSE.equals(d.get("original_screenshot_observed")));
            yes(Boolean.FALSE.equals(d.get("grants_dispatch")));yes(Boolean.TRUE.equals(d.get("original_refusal_preserved")));
            yes(((Map<?,?>)d.get("original_capture")).get("receipt_sha256").equals(ax.receiptSha256));
        });
        test("ax_rejection_cannot_smuggle_pixel_hash",()->rejects(()->rejection(b,h('a'),ax,205L)));
        test("ax_rejection_preserves_original_census_clock_not_phone_capture_clock",()->rejects(()->rejection(b,null,ax,220L)));
        for(final String key:Arrays.asList("task_id","owner_sha256","execution_target_sha256","task_authorization_sha256","actual_selection_sha256",
                "native_goal_sha256","observation_id","background_generation","display_id","window_id","rotation","width","height","left","top","right","bottom")){
            test("rejection_rejects_wrong_"+key,()->{Map<String,Object> bad=binding(null);bad.put(key,changed(key,bad.get(key)));
                rejects(()->rejection(bad,null,ax,205L));});
        }
        test("profile_rejection_binds_full_uid_parent_leaf_and_token_tuple",()->{
            Map<String,Object> d=rejection(pb,null,pa,205L);yes("native_ax".equals(d.get("original_capture_kind")));
            Map<String,Object> foreign=binding(profile(1012346,"33333333-3333-3333-3333-333333333333"));
            rejects(()->rejection(foreign,null,pa,205L));
        });
        test("profile_rejection_cannot_drop_profile_mode",()->rejects(()->rejection(b,null,pa,205L)));
        Map<String,Object> out=map();out.put("schema","hepta.native-ax-consumers-host.v1");out.put("all_pass",true);
        out.put("cases",names.size());out.put("assertions",assertions);out.put("case_names",names);
        out.put("actual_frame_and_rejection_classes",true);out.put("actual_capture_receipt_class",true);out.put("synthetic_census_and_platform_values",true);
        out.put("android_execution",false);out.put("phone_operations",0);out.put("model_executed",false);
        out.put("platform_dispatch_executed",false);out.put("business_completion_verified",false);
        Files.write(Paths.get(args[0]),(new JSONObject(out).toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println(new JSONObject(out).toString());
    }
}
