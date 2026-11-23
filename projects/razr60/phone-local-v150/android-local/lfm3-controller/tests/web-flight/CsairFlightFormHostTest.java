package org.trillionnium.hepta.local;

import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/** Real external manual DOM + mutated unit negatives. Never a task/business proof. */
public final class CsairFlightFormHostTest {
    private static int assertions;
    private static final List<String> passed=new ArrayList<String>();
    private interface Mutation {void apply(JSONObject dom)throws Exception;}
    private static void check(boolean ok,String message){assertions++;if(!ok)throw new AssertionError(message);}
    private static JSONObject copy(JSONObject o)throws Exception{return new JSONObject(o.toString());}
    private static JSONObject find(JSONObject dom,String id,String tag,boolean visible)throws Exception{
        JSONObject result=null;JSONArray nodes=dom.getJSONArray("nodes");
        for(int i=0;i<nodes.length();i++){JSONObject n=nodes.getJSONObject(i);
            if(id.equals(n.get("id"))&&tag.equals(n.get("tag"))&&Boolean.valueOf(visible).equals(n.get("visible_in_viewport"))){
                if(result!=null)throw new AssertionError("fixture selector ambiguous "+id);result=n;
            }}
        if(result==null)throw new AssertionError("fixture selector missing "+id);return result;
    }
    private static JSONObject byPath(JSONObject dom,String path)throws Exception{
        JSONArray nodes=dom.getJSONArray("nodes");
        for(int i=0;i<nodes.length();i++)if(path.equals(nodes.getJSONObject(i).getString("path")))return nodes.getJSONObject(i);
        throw new AssertionError("fixture path missing "+path);
    }
    private static JSONObject ownText(JSONObject dom,String text)throws Exception{
        JSONObject found=null;JSONArray nodes=dom.getJSONArray("nodes");
        for(int i=0;i<nodes.length();i++){JSONObject n=nodes.getJSONObject(i);
            if(text.equals(n.get("text"))&&Boolean.TRUE.equals(n.get("visible_in_viewport"))){
                if(found!=null)throw new AssertionError("fixture text ambiguous "+text);found=n;}}
        if(found==null)throw new AssertionError("fixture text missing "+text);return found;
    }
    private static void reject(JSONObject actual,String name,Mutation change)throws Exception{
        JSONObject changed=copy(actual);change.apply(changed);
        boolean rejected=false;
        try{CsairFlightForm.read(changed);}catch(Exception expected){rejected=true;}
        check(rejected,"accepted invalid DOM: "+name);passed.add(name);
    }
    private static JSONObject duplicate(JSONObject dom,JSONObject original,String suffix)throws Exception{
        JSONObject n=copy(original);String parent=original.getString("parent_path");
        n.put("path",parent+"/"+suffix);dom.getJSONArray("nodes").put(n);return n;
    }
    private static String hash(byte[] raw)throws Exception{
        StringBuilder out=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(raw))
            out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();
    }
    public static void main(String[] args)throws Exception{
        check(args.length==3,"external actual diagnostic, expected SHA and new result are required");
        Path input=Paths.get(args[0]),out=Paths.get(args[2]);check(!Files.exists(out),"create-only result");
        byte[] original=Files.readAllBytes(input);check(hash(original).equals(args[1]),"actual original fixture SHA");
        JSONObject diagnostic=new JSONObject(new String(original,StandardCharsets.UTF_8));
        check(Boolean.TRUE.equals(diagnostic.get("diagnostic_unbound"))&&Boolean.FALSE.equals(diagnostic.get("business_verified")),
                "manual fixture scope");
        JSONObject capture=diagnostic.getJSONObject("capture");String domRaw=capture.getString("dom_raw_utf8");
        check(hash(domRaw.getBytes(StandardCharsets.UTF_8)).equals(capture.getString("dom_sha256")),"actual DOM bytes");
        JSONObject dom=new JSONObject(domRaw);
        check(dom.getJSONArray("nodes").length()==795&&dom.getInt("visited")==795,"complete real initial form fixture");
        CsairFlightForm actual=CsairFlightForm.read(dom);
        check(actual!=null,"actual known official form recognized");
        check(actual.departurePlaceholder&&actual.arrivalPlaceholder,"actual cities are placeholders");
        check(actual.displayedMonth.intValue()==11&&actual.displayedDay.intValue()==13&&"周五".equals(actual.displayedWeekday),
                "actual partial displayed date");
        check(actual.adults==1&&actual.children==0&&actual.infants==0,"actual passenger counts");
        check(actual.singlePanelPath.equals(find(dom,"single","div",true).getString("path"))
                &&!actual.singlePanelPath.equals(actual.singleTabPath),"duplicate ID tag distinction");
        check(actual.evidence().get("displayed_year")==null&&actual.evidence().get("selected_departure_city")==null
                &&actual.evidence().get("selected_arrival_city")==null,"unknown year/route not inferred");
        check(Boolean.FALSE.equals(actual.evidence().get("query_ready_verified"))
                &&Boolean.FALSE.equals(actual.evidence().get("query_executed"))
                &&Boolean.FALSE.equals(actual.evidence().get("flight_results_verified"))
                &&Boolean.FALSE.equals(actual.evidence().get("grants_tool_authority")),"form is no action/result authority");
        int hiddenDep=0;for(int i=0;i<dom.getJSONArray("nodes").length();i++){
            JSONObject n=dom.getJSONArray("nodes").getJSONObject(i);
            if("depport".equals(n.get("id"))&&Boolean.FALSE.equals(n.get("visible_in_viewport")))hiddenDep++;}
        check(hiddenDep==2,"actual hidden multistage duplicates retained");
        passed.add("actual_795_node_empty_form_data_only");
        reject(dom,"duplicate_visible_departure",d->duplicate(d,find(d,"depport","div",true),"9001"));
        reject(dom,"duplicate_visible_arrival",d->duplicate(d,find(d,"arrport","div",true),"9002"));
        reject(dom,"duplicate_visible_date",d->duplicate(d,find(d,"depDate","div",true),"9003"));
        reject(dom,"duplicate_visible_query",d->duplicate(d,find(d,"queryBtn","button",true),"9004"));
        reject(dom,"visible_return_date",d->find(d,"arrDate","div",false).put("visible_in_viewport",true));
        reject(dom,"visible_multistage_panel",d->find(d,"multistage","div",false).put("visible_in_viewport",true));
        reject(dom,"missing_hidden_return_region",d->find(d,"arrDate","div",false).put("id","unreviewed"));
        reject(dom,"missing_hidden_multi_region",d->find(d,"multistage","div",false).put("id","unreviewed"));
        reject(dom,"single_li_cannot_replace_panel",d->find(d,"single","div",true).put("id","not_single"));
        reject(dom,"query_outside_current_tab",d->find(d,"queryBtn","button",true).put("parent_path","0"));
        reject(dom,"hidden_current_departure",d->find(d,"depport","div",true).put("visible_in_viewport",false));
        reject(dom,"hidden_current_ancestor",d->{
            JSONObject target=find(d,"depport","div",true);byPath(d,target.getString("parent_path")).put("visible_in_viewport",false);});
        reject(dom,"string_visibility_is_not_boolean",d->find(d,"depport","div",true).put("visible_in_viewport","true"));
        reject(dom,"incomplete_dom",d->d.put("truncated",true));
        reject(dom,"truncation_reason_is_not_ignored",d->d.getJSONArray("truncation_reasons").put("budget"));
        reject(dom,"unknown_dom_schema",d->d.put("schema","unknown"));
        reject(dom,"uncommitted_loading_document",d->d.put("ready_state","loading"));
        reject(dom,"different_origin",d->d.put("href","https://example.invalid/booking_new/").put("origin","https://example.invalid"));
        reject(dom,"http_origin",d->d.put("href","http://m.csair.com/booking_new/").put("origin","http://m.csair.com"));
        reject(dom,"userinfo_url",d->d.put("href","https://evil@m.csair.com/booking_new/"));
        reject(dom,"root_parent_forged",d->byPath(d,"0").put("parent_path","0/1"));
        reject(dom,"duplicate_dom_path",d->d.getJSONArray("nodes").put(copy(find(d,"queryBtn","button",true))));
        reject(dom,"unknown_date_rendering",d->ownText(d,"11月13日").put("text","2026年11月13日"));
        reject(dom,"invalid_displayed_month",d->ownText(d,"11月13日").put("text","13月13日"));
        reject(dom,"two_displayed_dates",d->{JSONObject n=duplicate(d,ownText(d,"11月13日"),"9005");n.put("text","11月14日");});
        reject(dom,"wrong_single_tab_label",d->find(d,"single","li",true).put("text","往返"));
        reject(dom,"unobserved_query_label",d->find(d,"queryBtn","button",true).put("text","提交订单"));
        reject(dom,"non_numeric_passenger",d->{JSONObject p=ownText(d,"成人");byPath(d,p.getString("path")+"/0").put("text","一");});
        reject(dom,"duplicate_passenger_count",d->{JSONObject p=ownText(d,"成人");duplicate(d,byPath(d,p.getString("path")+"/0"),"9006");});
        JSONObject two=copy(dom);JSONObject adult=ownText(two,"成人");byPath(two,adult.getString("path")+"/0").put("text","2");
        CsairFlightForm other=CsairFlightForm.read(two);check(other.adults==2&&Boolean.FALSE.equals(other.evidence().get("query_ready_verified")),
                "actual passenger mismatch must remain data, not overwritten by OWNER");passed.add("passenger_two_is_not_one");
        JSONObject disabled=copy(dom);find(disabled,"queryBtn","button",true).put("disabled",true);
        check(CsairFlightForm.read(disabled).query.disabled,"actual disabled query retained");passed.add("disabled_query_retained");
        JSONObject city=copy(dom);JSONObject dep=find(city,"depport","div",true);
        byPath(city,dep.getString("path")+"/0").put("text","广州");
        CsairFlightForm filled=CsairFlightForm.read(city);
        check(!filled.departurePlaceholder&&filled.evidence().get("selected_departure_city")==null
                &&Boolean.FALSE.equals(filled.evidence().get("query_ready_verified")),"unreviewed selected city shape not promoted");
        passed.add("city_text_is_not_verified_route");
        check(java.util.Arrays.equals(original,Files.readAllBytes(input)),"actual diagnostic unchanged");
        JSONObject result=new JSONObject().put("schema","hepta.csair-form-host-test.v1").put("all_pass",true)
            .put("cases",passed.size()).put("assertions",assertions).put("case_names",new JSONArray(passed))
            .put("actual_external_manual_diagnostic_sha256",hash(original)).put("actual_dom_sha256",capture.getString("dom_sha256"))
            .put("actual_dom_nodes",795).put("mutated_inputs_are_unit_negatives",true)
            .put("phone_commands_executed",0).put("task_bound_evidence",false).put("query_executed",false).put("business_verified",false);
        Files.write(out,(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),java.nio.file.StandardOpenOption.CREATE_NEW);
        System.out.println("CsairFlightFormHostTest cases="+passed.size()+" assertions="+assertions);
    }
}
