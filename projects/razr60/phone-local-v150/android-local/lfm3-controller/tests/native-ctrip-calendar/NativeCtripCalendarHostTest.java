package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;

/** Actual saved foreground UIAutomator XML through the unchanged production
 * child-label collector and parsers. NodeRef/window/task/lease/model/dispatch
 * fields are explicit host fixtures. This is not a background phone result. */
final class NativeCtripCalendarHostTest {
    static final String PREFIX="ctrip.android.view:id/";
    static Path own,legacy;static int assertions;static final List<String> names=new ArrayList<String>();
    interface Test {void run()throws Exception;}
    interface Change {void apply(N n);}
    static void check(boolean value,String reason){assertions++;if(!value)throw new AssertionError(reason);}
    static void one(String name,Test t)throws Exception{check(!names.contains(name),"unique test identity");t.run();names.add(name);}
    static NativeAppProviderHostTest.Harness harness(String name)throws Exception{
        NativeAppProviderHostTest.fixtures=own;return new NativeAppProviderHostTest.Harness("calendar-"+name);
    }
    static NativeAppEvidence.Frame actual()throws Exception{return harness("actual").frame("main-calendar.xml");}
    static NativeCtripFlightPage.Page page(NativeAppEvidence.Frame f){return NativeCtripFlightPage.inspect(NativeAppProviderHostTest.goal(),f);}
    static NativeAppEvidence.Node node(NativeAppEvidence.Frame f,String id){
        NativeAppEvidence.Node result=null;for(NativeAppEvidence.Node n:f.nodes)if((PREFIX+id).equals(n.viewId)){
            if(result!=null)throw new AssertionError("ambiguous fixture resource "+id);result=n;
        }if(result==null)throw new AssertionError("fixture resource absent "+id);return result;
    }
    static NativeAppEvidence.Node title(NativeAppEvidence.Frame f,String text,boolean sticky){
        NativeAppEvidence.Node list=node(f,"calendar_list");String path=list.path.substring(0,list.path.lastIndexOf('/'))+"/1/0/0";
        NativeAppEvidence.Node result=null;for(NativeAppEvidence.Node n:f.nodes)if((PREFIX+"calendar_month_title_left_tv").equals(n.viewId)&&text.equals(n.text)&&path.equals(n.path)==sticky){
            if(result!=null)throw new AssertionError("ambiguous fixture title");result=n;
        }if(result==null)throw new AssertionError("fixture title absent "+text+" sticky="+sticky);return result;
    }
    static final class N {
        String id,pkg,cls,vid,text,desc,path,parent,sig,label;int l,t,r,b;
        boolean enabled,password,clickable,editable,scrollable;Boolean selected,checkable,checked;Set<String> directions;
        N(NativeAppEvidence.Node n){id=n.id;pkg=n.packageName;cls=n.className;vid=n.viewId;text=n.text;desc=n.description;path=n.path;parent=n.parentClass;sig=n.signature;label=n.label;l=n.left;t=n.top;r=n.right;b=n.bottom;
            enabled=n.enabled;password=n.password;clickable=n.clickable;editable=n.editable;scrollable=n.scrollable;selected=n.selected;checkable=n.checkable;checked=n.checked;directions=n.scrollDirections;}
        NativeAppEvidence.Node build(){return new NativeAppEvidence.Node(id,pkg,cls,vid,text,desc,path,parent,sig,label,l,t,r,b,enabled,password,clickable,editable,scrollable,selected,checkable,checked,directions);}
    }
    static NativeAppEvidence.Frame frame(NativeAppEvidence.Frame f,List<NativeAppEvidence.Node> nodes,boolean truncated){
        return new NativeAppEvidence.Frame(f.taskId,f.ownerSha,f.targetSha,f.authorizationSha,f.selectionSha,f.observationId,f.packageName,f.generation,
                f.treeSha,f.stateSha,f.screenshotSha,f.sourceRecordSha,f.completionFrameSha,f.displayId,f.windowId,f.rotation,f.width,f.height,f.left,f.top,f.right,f.bottom,f.capturedElapsedMs,truncated,!truncated,nodes,f.windowType,f.metadataObserved);
    }
    static NativeAppEvidence.Frame change(NativeAppEvidence.Frame f,NativeAppEvidence.Node target,Change c){
        List<NativeAppEvidence.Node> out=new ArrayList<NativeAppEvidence.Node>();for(NativeAppEvidence.Node n:f.nodes){if(n==target){N x=new N(n);c.apply(x);out.add(x.build());}else out.add(n);}return frame(f,out,false);
    }
    static NativeAppEvidence.Frame without(NativeAppEvidence.Frame f,NativeAppEvidence.Node target){List<NativeAppEvidence.Node> out=new ArrayList<NativeAppEvidence.Node>(f.nodes);out.remove(target);return frame(f,out,false);}
    static void denied(NativeAppEvidence.Frame f){NativeCtripFlightPage.Page p=page(f);check(!p.calendarYearHeadersAdmitted(),"mutated graph must not admit year");check(!p.calendarStickyHeaderPairVerified,"mutated graph cannot assert pair");check(p.dates.isEmpty()&&p.quotes.isEmpty(),"no inferred date or quote");}
    @SuppressWarnings("unchecked") static Map<String,Object> map(Object o){return (Map<String,Object>)o;}
    @SuppressWarnings("unchecked") static List<Map<String,Object>> rows(Object o){return (List<Map<String,Object>>)o;}
    static JSONObject json(Path p)throws Exception{return new JSONObject(new String(Files.readAllBytes(p),StandardCharsets.UTF_8));}
    static NativeAppEvidence.Frame blank(NativeAppProviderHostTest.Harness h)throws Exception{
        NativeAppEvidence.Frame synthetic=h.frame("main-calendar.xml");JSONObject raw=json(own.resolve("actual-empty-background.json"));List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();
        JSONArray items=raw.getJSONArray("nodes");for(int i=0;i<items.length();i++){JSONObject n=items.getJSONObject(i),position=n.getJSONObject("native_tree_position"),selection=n.getJSONObject("native_selection_state");JSONArray b=n.getJSONArray("bounds");
            String text=n.optString("text",""),desc=n.optString("description","");
            nodes.add(new NativeAppEvidence.Node(n.getString("id"),n.getString("package"),n.getString("class_name"),n.optString("view_id",""),text,desc,position.getString("path"),position.getString("parent_class"),
                    n.getString("node_app_tree_sha256"),text.isEmpty()?desc:text,b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3),true,false,n.optBoolean("clickable",false),false,false,
                    selection.getBoolean("selected"),selection.getBoolean("checkable"),selection.getBoolean("checked"),Collections.<String>emptySet()));
        }
        // Original retained XML/JSON facts; task/window/NodeRef admission remains
        // a labelled host boundary, never represented as the original task.
        return new NativeAppEvidence.Frame(synthetic.taskId,synthetic.ownerSha,synthetic.targetSha,synthetic.authorizationSha,synthetic.selectionSha,synthetic.observationId,synthetic.packageName,synthetic.generation,
                raw.getString("app_tree_sha256"),raw.getString("observation_state_sha256"),raw.getString("screen_sha256"),NativeAppEvidence.hash(new String(Files.readAllBytes(own.resolve("actual-empty-background.json")),StandardCharsets.UTF_8)),synthetic.completionFrameSha,
                synthetic.displayId,synthetic.windowId,raw.getInt("rotation"),raw.getInt("screen_width"),raw.getInt("screen_height"),0,0,720,1280,synthetic.capturedElapsedMs,false,true,nodes,1,true);
    }
    static void cases()throws Exception{
        one("actual_foreground_xml_keeps_five_titles_as_four_month_facts",()->{
            NativeAppEvidence.Frame f=actual();NativeCtripFlightPage.Page p=page(f);
            check(NativeCtripFlightPage.CALENDAR.equals(p.phase),"actual calendar recognized");check(p.calendarYearHeadersAdmitted()&&p.calendarStickyHeaderPairVerified,"narrow pair year admission");
            check(p.calendarMonths.size()==4,"Feb must remain, not be dropped to satisfy three-month legacy bound");
            check(Arrays.asList(11,12,1,2).equals(Arrays.asList(p.calendarMonths.get(0).get("month"),p.calendarMonths.get(1).get("month"),p.calendarMonths.get(2).get("month"),p.calendarMonths.get(3).get("month"))),"actual four-month order");
            Map<String,Object> pair=map(p.calendarMonths.get(0).get("sticky_header_pair"));check("hepta.ctrip-sticky-month-pair.v1".equals(pair.get("schema")),"typed pair");
            for(String key:Arrays.asList("content_header","sticky_header","calendar_list")){Map<String,Object> fact=map(pair.get(key));NativeAppEvidence.Node n=f.byId.get(fact.get("node_id"));
                check(n!=null&&n.path.equals(fact.get("native_tree_path"))&&n.signature.equals(fact.get("node_ref_signature")),"same original node/path/signature "+key);}
            check(title(f,"2026年11月",false).fact("text").equals(pair.get("content_header")),"clipped original fact retained");check(title(f,"2026年11月",true).fact("text").equals(pair.get("sticky_header")),"sticky original fact retained");
            Set<Object> headers=new HashSet<Object>();for(Map<String,Object> m:p.calendarMonths)headers.add(m.get("node_id"));headers.add(map(pair.get("sticky_header")).get("node_id"));check(headers.size()==5,"every original header retained");
            check(Boolean.FALSE.equals(pair.get("day_cells_or_selected_date_inferred"))&&p.dates.isEmpty()&&p.quotes.isEmpty(),"no calendar day/selected date/price inference");
        });
        one("pair_evidence_is_deeply_immutable",()->{Map<String,Object> pair=map(page(actual()).calendarMonths.get(0).get("sticky_header_pair"));boolean refused=false;try{map(pair.get("sticky_header")).put("raw","2027年11月");}catch(UnsupportedOperationException expected){refused=true;}check(refused,"nested original facts immutable");});
        one("actual_model_calendar_then_back_same_form_is_required_for_year",()->{
            NativeAppProviderHostTest.Harness h=harness("roundtrip");h.observe("main-form17.xml");check(h.target("query_observed_form")==null,"initial form/owner cannot supply year");
            h.perform("inspect_departure_year","main-calendar.xml");check(h.target("return_from_calendar")!=null&&h.target("query_observed_form")==null,"calendar only grants return");
            check(!Boolean.TRUE.equals(map(h.session.evidence().get("progress")).get("calendar_year_proved")),"inspection alone not full proof");
            h.perform("return_from_calendar","main-form17.xml");check(h.target("query_observed_form")!=null,"same form return grants query admission");
            Map<String,Object> progress=map(h.session.evidence().get("progress"));check(Boolean.TRUE.equals(progress.get("calendar_year_proved")),"year roundtrip complete");
            List<Map<String,Object>> transitions=rows(progress.get("transitions"));Map<String,Object> header=map(transitions.get(0).get("calendar_month_header"));check(header.containsKey("sticky_header_pair"),"pair evidence survives actual Session transition");
            check(Boolean.FALSE.equals(transitions.get(0).get("owner_year_used_as_observed_value")),"not supplied by OWNER");
            check(!h.gate.verified(h.completion)&&!h.session.domain().resultReady,"query admission does not mean query/result/completion");
            ActionDecision actual=h.action("query_observed_form");h.session.domain().requireCurrent(actual);check(actual.nodeLabel.equals(h.frame.byId.get(actual.nodeId).label),"later action still binds exact current NodeRef/label");
        });
        one("different_form_after_back_does_not_close_calendar_year",()->{
            NativeAppProviderHostTest.Harness h=harness("changed-form");h.observe("main-form17.xml");h.perform("inspect_departure_year","main-calendar.xml");
            NativeAppProviderHostTest.fixtures=legacy;h.perform("return_from_calendar","form14.xml");check(h.target("query_observed_form")==null,"changed date cannot close proof");check(!Boolean.TRUE.equals(map(h.session.evidence().get("progress")).get("calendar_year_proved")),"no proved year");
        });
        one("direct_calendar_without_model_date_action_cannot_prove_year",()->{NativeAppProviderHostTest.Harness h=harness("initial-calendar");h.observe("main-calendar.xml");h.perform("return_from_calendar","main-form17.xml");check(h.target("query_observed_form")==null,"initial calendar has no actual inspection chain");});
        one("stale_undispatched_calendar_action_cannot_prove_year",()->{NativeAppProviderHostTest.Harness h=harness("stale");h.observe("main-form17.xml");ActionDecision a=h.action("inspect_departure_year");h.issue(a,false,false,true);h.observe("main-calendar.xml");h.perform("return_from_calendar","main-form17.xml");check(h.target("query_observed_form")==null,"stale callback is not inspection");});
        one("actual_blank_background_frame_still_has_no_calendar_or_day",()->{NativeCtripFlightPage.Page p=page(blank(harness("empty")));check(NativeCtripFlightPage.UNAVAILABLE.equals(p.phase),"actual blank frame remains unavailable");check(!p.calendarYearHeadersAdmitted()&&p.dates.isEmpty()&&p.quotes.isEmpty(),"no inference from dim screenshot or footer");});
        one("legacy_unique_calendar_and_original_roundtrip_still_pass",()->{NativeAppProviderHostTest.Harness h=harness("legacy");NativeAppProviderHostTest.fixtures=legacy;h.year();NativeCtripFlightPage.Page p=page(h.frame("calendar14.xml"));check(p.calendarYearHeadersAdmitted()&&!p.calendarStickyHeaderPairVerified,"legacy <=3 stays same source path");check(h.target("query_observed_form")!=null,"legacy roundtrip intact");});
        one("four_unique_headers_without_verified_pair_do_not_expand_year_gate",()->{NativeAppEvidence.Frame f=actual();NativeCtripFlightPage.Page p=page(without(f,title(f,"2026年11月",true)));check(NativeCtripFlightPage.CALENDAR.equals(p.phase)&&p.calendarMonths.size()==4,"all legacy facts retained");check(!p.calendarYearHeadersAdmitted(),"unique four lacks verified pair");});
        one("sticky_conflicting_year_is_rejected_even_when_all_labels_unique",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2026年11月",true),n->n.text="2027年11月"));});
        one("sticky_conflicting_month_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2026年11月",true),n->n.text="2026年12月"));});
        one("third_same_month_header_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2026年12月",false),n->n.text="2026年11月"));});
        one("nonconsecutive_content_months_are_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2027年1月",false),n->n.text="2027年2月"));});
        one("conflicting_content_year_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2027年1月",false),n->n.text="2028年1月"));});
        one("invalid_month_literal_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2027年1月",false),n->n.text="2027年13月"));});
        one("month_prefix_suffix_are_not_normalized",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2026年11月",true),n->n.text="2026年11月 "));});
        one("missing_actual_list_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(without(f,node(f,"calendar_list")));});
        one("wrong_list_class_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,node(f,"calendar_list"),n->n.cls="android.view.View"));});
        one("unscrollable_list_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,node(f,"calendar_list"),n->n.scrollable=false));});
        one("disabled_list_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,node(f,"calendar_list"),n->n.enabled=false));});
        one("wrong_list_parent_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,node(f,"calendar_list"),n->n.parent="android.widget.LinearLayout"));});
        one("sticky_wrong_sibling_branch_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2026年11月",true),n->n.path=n.path.replace("/1/0/0","/7/0/0")));});
        one("content_title_outside_same_list_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2026年12月",false),n->n.path="0/99/6/0/0"));});
        one("content_wrong_row_depth_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2026年12月",false),n->n.path=n.path+"/0"));});
        one("wrong_first_content_row_index_is_rejected",()->{NativeAppEvidence.Frame f=actual();String list=node(f,"calendar_list").path;denied(change(f,title(f,"2026年11月",false),n->n.path=list+"/99/0/0"));});
        one("disabled_sticky_title_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2026年11月",true),n->n.enabled=false));});
        one("clickable_month_title_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2026年12月",false),n->n.clickable=true));});
        one("different_native_parent_class_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2026年11月",true),n->n.parent="android.widget.FrameLayout"));});
        one("nonempty_month_description_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2026年11月",true),n->n.desc="另一个月份"));});
        one("sticky_alignment_mismatch_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2026年11月",true),n->n.l++));});
        one("content_not_clipped_at_list_top_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2026年11月",false),n->n.t++));});
        one("content_overlapping_sticky_geometry_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2026年11月",false),n->n.b=640));});
        one("sticky_overlapping_next_month_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2026年11月",true),n->n.b=1120));});
        one("content_geometry_not_ordered_is_rejected",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2027年1月",false),n->{n.t=1100;n.b=1150;}));});
        one("foreign_same_resource_header_cannot_be_silently_omitted",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2027年2月",false),n->n.pkg="other.package"));});
        one("offscreen_same_resource_header_cannot_be_silently_omitted",()->{NativeAppEvidence.Frame f=actual();denied(change(f,title(f,"2027年2月",false),n->{n.t=3000;n.b=3100;}));});
        one("fifth_semantic_month_exceeds_verified_bound",()->{NativeAppEvidence.Frame f=actual();N n=new N(title(f,"2027年2月",false));n.id="n9999";n.path=node(f,"calendar_list").path+"/25/0/0";n.text="2027年3月";n.t=2600;n.b=2687;List<NativeAppEvidence.Node> out=new ArrayList<NativeAppEvidence.Node>(f.nodes);out.add(n.build());denied(frame(f,out,false));});
        one("truncated_collection_never_uses_sticky_pair",()->{NativeAppEvidence.Frame f=actual();denied(frame(f,f.nodes,true));});
    }
    public static void main(String[] args)throws Exception{
        own=Paths.get(args[0]);legacy=Paths.get(args[1]);cases();Map<String,Object> out=NativeAppEvidence.map();out.put("schema","hepta.native-ctrip-calendar-host.v1");out.put("all_pass",true);out.put("cases",names.size());out.put("assertions",assertions);out.put("case_names",names);
        out.put("phone_operations",0);out.put("android_runtime",false);out.put("model_executed",false);out.put("business_verified",false);out.put("fixture_origin","actual_manual_main_display_UIAutomator_XML_and_actual_failed_background_JSON");
        out.put("xml_text_paths_geometry_actual",true);out.put("bound_background_frame_actual",false);out.put("task_lease_window_noderef_and_dispatch_modelled",true);out.put("negative_mutations_synthetic",true);
        out.put("retained_provider_harness",true);out.put("calendar_day_coordinates_authorized",false);Files.write(Paths.get(args[2]),(new JSONObject(out).toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);System.out.println(new JSONObject(out).toString());
    }
}
