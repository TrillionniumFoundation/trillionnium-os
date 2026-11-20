package org.trillionnium.hepta.local;

import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Exact full manual city DOM, with separately labelled in-memory unit mutations. */
public final class CsairCityPickerHostTest {
    private static int assertions;
    private static final List<String> passed=new ArrayList<String>();
    private interface Mutation {void apply(JSONObject dom)throws Exception;}
    private static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    private static JSONObject copy(JSONObject value)throws Exception{return new JSONObject(value.toString());}
    private static String hash(byte[] value)throws Exception{
        StringBuilder out=new StringBuilder();
        for(byte b:MessageDigest.getInstance("SHA-256").digest(value))
            out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
        return out.toString();
    }
    private static JSONObject path(JSONObject dom,String expected)throws Exception{
        JSONObject found=null;JSONArray nodes=dom.getJSONArray("nodes");
        for(int i=0;i<nodes.length();i++)if(expected.equals(nodes.getJSONObject(i).get("path"))){
            check(found==null,"unique fixture path");found=nodes.getJSONObject(i);
        }
        check(found!=null,"fixture path exists: "+expected);return found;
    }
    private static JSONObject text(JSONObject dom,String label)throws Exception{
        JSONObject found=null;JSONArray nodes=dom.getJSONArray("nodes");
        for(int i=0;i<nodes.length();i++){
            JSONObject n=nodes.getJSONObject(i);
            if(label.equals(n.get("text"))&&Boolean.TRUE.equals(n.get("visible_in_viewport"))){
                check(found==null,"unique visible fixture label: "+label);found=n;
            }
        }
        check(found!=null,"visible fixture label exists: "+label);return found;
    }
    private static JSONObject duplicate(JSONObject dom,JSONObject original,String suffix)throws Exception{
        JSONObject n=copy(original);n.put("path",original.getString("parent_path")+"/"+suffix);
        dom.getJSONArray("nodes").put(n);return n;
    }
    private static void reject(JSONObject actual,String name,Mutation mutation,boolean choose)throws Exception{
        JSONObject changed=copy(actual);mutation.apply(changed);boolean rejected=false;
        try{CsairCityPicker p=CsairCityPicker.read(changed);if(choose&&p!=null)p.city("北京");}
        catch(IllegalArgumentException expected){rejected=true;}
        check(rejected,"invalid city DOM accepted: "+name);passed.add(name);
    }
    public static void main(String[] args)throws Exception{
        check(args.length==3,"actual fixture, full hash and new output required");
        Path input=Paths.get(args[0]),output=Paths.get(args[2]);check(!Files.exists(output),"new result");
        byte[] original=Files.readAllBytes(input);
        check(original.length==308728&&hash(original).equals(args[1]),"full original city diagnostic bytes");
        JSONObject diagnostic=new JSONObject(new String(original,StandardCharsets.UTF_8));
        check(Boolean.TRUE.equals(diagnostic.get("diagnostic_unbound"))
                &&Boolean.FALSE.equals(diagnostic.get("business_verified")),"manual fixture is not task evidence");
        JSONObject capture=diagnostic.getJSONObject("capture");
        String domRaw=capture.getString("dom_raw_utf8");byte[] domBytes=domRaw.getBytes(StandardCharsets.UTF_8);
        check(domBytes.length==255602&&hash(domBytes).equals(capture.getString("dom_sha256"))
                &&"0b9651aa4ce631cfac705ab194b901ca073b6b73384a62bc28f221e75287e17d".equals(hash(domBytes)),
                "actual entire DOM bytes");
        JSONObject dom=new JSONObject(domRaw);
        check(dom.getJSONArray("nodes").length()==795&&dom.getInt("visited")==795,"all original 795 nodes present");
        CsairCityPicker picker=CsairCityPicker.read(dom);
        check(picker!=null&&"departure".equals(picker.kind)&&"选择出发地".equals(picker.title),"actual departure picker");
        check(picker.cities.size()==19,"complete actual hot-city list");
        List<String> expected=Arrays.asList("北京","长沙","成都","重庆","广州","哈尔滨","海口","杭州","昆明","南京",
                "三亚","上海","沈阳","深圳","武汉","乌鲁木齐","厦门","西安","郑州");
        for(int i=0;i<expected.size();i++){
            check(expected.get(i).equals(picker.cities.get(i).text),"actual city order "+i);
            check(!picker.cities.get(i).disabled,"actual city enabled flag retained");
        }
        check(picker.city("北京")==picker.cities.get(0)&&picker.city("上海")==picker.cities.get(11),"full exact city match");
        check(picker.city("北")==null&&picker.city("北京市")==null&&picker.city("深圳机场")==null,"no substring/airport/city expansion");
        check(Boolean.FALSE.equals(picker.evidence().get("city_selection_verified"))
                &&Boolean.FALSE.equals(picker.evidence().get("query_executed"))
                &&Boolean.FALSE.equals(picker.evidence().get("grants_tool_authority"))
                &&Boolean.FALSE.equals(picker.evidence().get("css_to_screen_mapping_used")),"DOM is data only");
        passed.add("actual_795_nodes_complete_departure_picker");
        reject(dom,"unknown_schema",d->d.put("schema","unknown"),false);
        reject(dom,"truncated",d->d.put("truncated",true),false);
        reject(dom,"truncation_reason",d->d.getJSONArray("truncation_reasons").put("budget"),false);
        reject(dom,"loading_document",d->d.put("ready_state","loading"),false);
        reject(dom,"foreign_origin",d->d.put("href","https://example.invalid/booking_new/").put("origin","https://example.invalid"),false);
        reject(dom,"wrong_same_site_route",d->d.put("href","https://m.csair.com/account/"),false);
        reject(dom,"userinfo",d->d.put("href","https://other@m.csair.com/booking_new/"),false);
        reject(dom,"http",d->d.put("href","http://m.csair.com/booking_new/"),false);
        reject(dom,"bad_port",d->d.put("href","https://m.csair.com:8443/booking_new/"),false);
        reject(dom,"duplicate_path",d->d.getJSONArray("nodes").put(copy(text(d,"北京"))),false);
        reject(dom,"wrong_parent",d->text(d,"北京").put("parent_path","0"),false);
        reject(dom,"missing_ancestor",d->path(d,picker.pickerPath).put("path","0/9999"),false);
        reject(dom,"root_parent",d->path(d,"0").put("parent_path","0/1"),false);
        reject(dom,"string_visibility",d->text(d,"北京").put("visible_in_viewport","true"),false);
        reject(dom,"string_disabled",d->text(d,"北京").put("disabled","false"),false);
        reject(dom,"wrong_aria_type",d->text(d,"北京").put("aria_disabled",false),false);
        reject(dom,"duplicate_title",d->duplicate(d,text(d,"选择出发地"),"9900"),false);
        reject(dom,"duplicate_hot_label",d->duplicate(d,text(d,"热门城市"),"9901"),false);
        reject(dom,"wrong_query_box",d->path(d,picker.queryBoxPath).put("id","unknown"),false);
        reject(dom,"wrong_picker_identity",d->path(d,picker.pickerPath).put("id","unreviewed"),false);
        reject(dom,"two_hot_lists",d->duplicate(d,path(d,picker.hotListPath),"9902"),false);
        reject(dom,"non_li_direct_child",d->text(d,"北京").put("tag","button"),false);
        reject(dom,"unreviewed_city_id",d->text(d,"北京").put("id","beijing"),false);
        reject(dom,"unreviewed_city_role",d->text(d,"北京").put("role","button"),false);
        reject(dom,"unreviewed_city_aria_label",d->text(d,"北京").put("aria_label","付款"),false);
        reject(dom,"compound_city_label",d->text(d,"北京").put("text","北京/首都"),false);
        reject(dom,"city_descendant_added",d->{
            JSONObject n=copy(text(d,"北京"));String p=n.getString("path");
            n.put("path",p+"/0").put("parent_path",p).put("tag","span");d.getJSONArray("nodes").put(n);
        },false);
        reject(dom,"duplicate_requested_city",d->duplicate(d,text(d,"北京"),"9903"),true);
        reject(dom,"disabled_duplicate_still_ambiguous",d->duplicate(d,text(d,"北京"),"9904").put("disabled",true),true);
        JSONObject hidden=copy(dom);text(hidden,"北京").put("visible_in_viewport",false);
        check(CsairCityPicker.read(hidden).city("北京")==null,"hidden requested city never authorized");
        passed.add("hidden_city_has_no_match");
        JSONObject disabled=copy(dom);text(disabled,"北京").put("disabled",true);
        CsairCityPicker disabledPicker=CsairCityPicker.read(disabled);
        check(disabledPicker.city("北京")==null&&disabledPicker.cities.get(0).disabled,"disabled state not overwritten");
        passed.add("disabled_city_retained_no_match");
        JSONObject aria=copy(dom);text(aria,"北京").put("aria_disabled","true");
        check(CsairCityPicker.read(aria).city("北京")==null,"aria disabled state retained");passed.add("aria_disabled_city");
        JSONObject noTitle=copy(dom);text(noTitle,"选择出发地").put("visible_in_viewport",false);
        check(CsairCityPicker.read(noTitle)==null,"unknown current picker has no capability");passed.add("no_visible_title");
        JSONObject hiddenAncestor=copy(dom);path(hiddenAncestor,picker.pickerPath).put("visible_in_viewport",false);
        check(CsairCityPicker.read(hiddenAncestor)==null,"hidden picker ancestor has no capability");passed.add("hidden_picker_ancestor");
        JSONObject arrival=copy(dom);text(arrival,"选择出发地").put("text","选择目的地");
        check("arrival".equals(CsairCityPicker.read(arrival).kind),"explicit unit mutation tests arrival branch only");
        passed.add("unit_mutated_arrival_title_not_phone_evidence");
        check(Arrays.equals(original,Files.readAllBytes(input)),"original phone diagnostic unchanged");
        JSONObject result=new JSONObject().put("schema","hepta.csair-city-picker-host.v1").put("all_pass",true)
                .put("cases",passed.size()).put("assertions",assertions).put("case_names",new JSONArray(passed))
                .put("actual_external_manual_diagnostic_sha256",hash(original)).put("actual_dom_sha256",hash(domBytes))
                .put("actual_dom_nodes",795).put("mutated_inputs_are_unit_tests",true)
                .put("phone_commands_executed",0).put("city_action_executed",false).put("query_executed",false)
                .put("task_bound_evidence",false).put("business_verified",false);
        Files.write(output,(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println("CsairCityPickerHostTest cases="+passed.size()+" assertions="+assertions);
    }
}
