package org.trillionnium.hepta.local;
import static org.trillionnium.hepta.local.NativeActionSnapshotCheckHostTest.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.*;
/** Complete portable synthetic census; no captured device identities or phone qualification. */
final class NativeCarouselCurrentnessHostTest {
    interface Work{void run()throws Exception;}
    interface Change{void apply(Fixture f);}
    static JSONObject synthetic;
    static void yes(boolean v,String why){IntegrationChecks.yes(v,why);}
    static void one(String name,Work w)throws Exception{IntegrationChecks.one(name,()->w.run());}
    static String directions(JSONObject row)throws Exception{
        List<String> names=new ArrayList<String>();JSONArray a=row.getJSONArray("scroll_directions");
        for(int i=0;i<a.length();i++)names.add(a.getString(i));return ObservedScrollActions.observed(names).fingerprintInput();
    }
    static Fixture carousel(String purpose)throws Exception{
        Fixture f=form(purpose);Map<String,Object> a=f.nodes.get("0/0/7");JSONObject row=synthetic.getJSONObject("before_anchor");
        a.put("class",row.getString("class_name"));JSONArray b=row.getJSONArray("bounds");
        a.put("bounds",rect(b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3)));
        a.put("scrollable",true);a.put("scroll_actions",directions(row));
        f.nodes.get("0/0/7/0").put("bounds",rect(80,2580,480,2640));changedText(f,"0/0/7/0",synthetic.getString("before_header"));f.link();return f;
    }
    static Fixture changed(Fixture old)throws Exception{
        Fixture f=fresh(old);f.nodes.get("0/0/7").put("scroll_actions",directions(synthetic.getJSONObject("after_anchor")));
        f.nodes.get("0/0/7").put("ref_signature_sha256",NativeActionSnapshotCheck.hash("new horizontal metadata"));
        changedText(f,"0/0/7/0",synthetic.getString("after_header"));return f;
    }
    static void allow(Fixture a,Fixture z){
        Map<String,Object> p=compare(a,z);yes(Boolean.FALSE.equals(p.get("grants_dispatch")),"predicate never permits an effect");
        yes(Boolean.FALSE.equals(p.get("business_verified")),"no business result");
        yes(Boolean.FALSE.equals(p.get("changed_paths_truncated")),"complete comparison retains all changes");
        yes(((List<?>)p.get("changed_paths")).contains("0/0/7"),"anchor change remains recorded");
    }
    static void bad(String name,Change c)throws Exception{
        one(name,()->{Fixture a=carousel(NativeActionSnapshotCheck.QUERY),z=changed(a);c.apply(z);
            IntegrationChecks.rejects(()->compare(a,z),"unsafe branch change must reject");});
    }
    static void initialize(Path source)throws Exception{
        synthetic=new JSONObject(new String(Files.readAllBytes(source.resolve("tests/native-query-reservation/fixtures/synthetic-carousel.json")),StandardCharsets.UTF_8));
    }
    static void positive()throws Exception{
        one("complete_disjoint_horizontal_query_carousel_scroll_metadata",()->{
            Fixture a=carousel(NativeActionSnapshotCheck.QUERY),z=changed(a);allow(a,z);
            yes(a.nodes.get(a.target).equals(z.nodes.get(z.target)),"original selected query control remains exact");
        });
    }
    static void run(Path source)throws Exception{
        initialize(source);positive();
        one("complete_disjoint_horizontal_date_carousel_scroll_metadata",()->{Fixture a=carousel(NativeActionSnapshotCheck.YEAR);allow(a,changed(a));});
        one("all_carousel_descendants_compared_beyond_diagnostic_eight",()->{
            Fixture a=carousel(NativeActionSnapshotCheck.QUERY);
            for(int i=1;i<12;i++)a.add("0/0/7/"+i,"android.widget.TextView","","old"+i,"",rect(40,2670+i*20,740,2685+i*20));a.link();
            Fixture z=changed(a);for(int i=1;i<12;i++)changedText(z,"0/0/7/"+i,"new"+i);
            yes(((List<?>)compare(a,z).get("changed_paths")).size()==13,"full thirteen differences considered");
        });
        bad("carousel_anchor_bounds_change",z->z.nodes.get("0/0/7").put("bounds",rect(41,2400,760,2980)));
        bad("carousel_anchor_overlaps_form",z->z.nodes.get("0/0/7").put("bounds",rect(40,1200,760,2980)));
        bad("carousel_descendant_crosses_form",z->z.nodes.get("0/0/7/0").put("bounds",rect(40,1100,700,1300)));
        bad("carousel_unknown_scroll_actions",z->z.nodes.get("0/0/7").put("scroll_actions",ObservedScrollActions.UNKNOWN.fingerprintInput()));
        bad("carousel_malformed_scroll_actions",z->z.nodes.get("0/0/7").put("scroll_actions","hepta.observed-scroll-actions.v1|observed|right|forward"));
        bad("carousel_vertical_scroll_actions",z->z.nodes.get("0/0/7").put("scroll_actions",ObservedScrollActions.observed(Arrays.asList("up","down")).fingerprintInput()));
        bad("carousel_no_horizontal_direction",z->z.nodes.get("0/0/7").put("scroll_actions",ObservedScrollActions.observed(Collections.singletonList("forward")).fingerprintInput()));
        for(String key:Arrays.asList("selected","focused","editable","password","checkable","checked")){
            final String k=key;bad("carousel_sensitive_descendant_"+k,z->z.nodes.get("0/0/7/0").put(k,true));
        }
        for(String key:Arrays.asList("visible","enabled","scrollable")){
            final String k=key;bad("carousel_anchor_"+k+"_change",z->z.nodes.get("0/0/7").put(k,false));
        }
        bad("carousel_protected_form_change",z->changedText(z,"0/0/2/1","广州"));
        bad("carousel_query_ref_change",z->z.nodes.get(z.target).put("ref_signature_sha256",NativeActionSnapshotCheck.hash("different target")));
        bad("carousel_protected_scroll_metadata_change",z->z.nodes.get("0/0/2/6").put("scroll_actions","changed protected metadata"));
        bad("carousel_actual_ancestor_change",z->z.nodes.get("0/0").put("focused",true));
        bad("carousel_duplicate_form_role",z->z.nodes.get("0/0/7/0").put("view_id",NativeActionSnapshotCheck.CP+"tv_depart_city"));
        bad("carousel_overlay_role",z->{z.nodes.get("0/0/7/0").put("view_id","单程TripSwitcherDate");z.nodes.get("0/0/7/0").put("description","单程TripSwitcherDate");});
        bad("carousel_other_branch_changed",z->z.nodes.get("0/0/6").put("focused",true));
        bad("carousel_window_changed",z->z.env.put("window_metadata_sha256",NativeActionSnapshotCheck.hash("new window")));
        bad("carousel_incomplete_census",z->z.env.put("node_omissions",1));
        bad("carousel_unknown_ime",z->z.env.put("ime_visibility","unknown"));
        bad("carousel_wrong_actual_parent",z->z.nodes.get("0/0/7/0").put("parent_class","android.webkit.WebView"));
        one("vertical_container_never_uses_horizontal_exception",()->{
            Fixture a=carousel(NativeActionSnapshotCheck.QUERY);a.nodes.get("0/0/7").put("class","android.widget.ScrollView");a.link();Fixture z=changed(a);
            IntegrationChecks.rejects(()->compare(a,z),"vertical class stays rejected");
        });
        one("scroll_action_cannot_create_click_comparison_intent",()->{
            Fixture a=carousel(NativeActionSnapshotCheck.QUERY);a.purpose="scroll";IntegrationChecks.rejects(()->a.intent(),"scroll purpose not admitted");
        });
        one("query_cannot_select_carousel_target",()->{
            Fixture a=carousel(NativeActionSnapshotCheck.QUERY);a.click("0/0/7");a.target="0/0/7";a.label="";Fixture z=changed(a);
            IntegrationChecks.rejects(()->compare(a,z),"query must select actual unchanged query control");
        });
    }
    public static void main(String[] args)throws Exception{
        initialize(Paths.get(args[0]));positive();
        if(args.length>2&&args[2].equals("legacy"))throw new AssertionError("previous comparator unexpectedly passed carousel regression");
        IntegrationChecks.finish(Paths.get(args[1]),"hepta.native-carousel-regression-host.v1","Portable complete synthetic census with known horizontal scroll metadata; no captured device records or phone execution.");
    }
}
