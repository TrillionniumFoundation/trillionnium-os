package org.trillionnium.hepta.local;

import org.json.JSONArray;
import org.json.JSONObject;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads the real public city-picker structure. Labels and DOM paths are data,
 * never coordinates, Android node identities, selected-city proof or authority.
 */
final class CsairCityPicker {
    static final String SCHEMA="hepta.csair-observed-city-picker.v1";
    static final class City {
        final String text,path;
        final boolean disabled;
        City(JSONObject node)throws Exception{
            text=string(node,"text");path=string(node,"path");
            disabled=flag(node,"disabled")||"true".equals(node.get("aria_disabled"));
        }
        Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();
            out.put("text",text);out.put("dom_path",path);out.put("dom_tag","li");out.put("dom_id","");
            out.put("dom_disabled",disabled);out.put("dom_visibility_is_native_visibility",false);
            return out;
        }
    }
    final String kind,title,titlePath,pickerPath,queryBoxPath,hotListPath;
    final List<City> cities;
    private CsairCityPicker(String title,String titlePath,String pickerPath,String queryBoxPath,
                            String hotListPath,List<City> cities){
        this.title=title;this.titlePath=titlePath;this.pickerPath=pickerPath;this.queryBoxPath=queryBoxPath;
        this.hotListPath=hotListPath;kind="选择出发地".equals(title)?"departure":"arrival";
        this.cities=Collections.unmodifiableList(new ArrayList<City>(cities));
    }
    /** No known picker returns null; a recognized but ambiguous picker is refused. */
    static CsairCityPicker read(JSONObject dom)throws Exception{
        URI url=new URI(string(dom,"href"));
        need("https".equals(url.getScheme())&&"m.csair.com".equals(url.getHost())
                &&url.getRawUserInfo()==null&&(url.getPort()==-1||url.getPort()==443)
                &&"/booking_new/".equals(url.getPath())&&"https://m.csair.com".equals(string(dom,"origin"))
                &&"complete".equals(string(dom,"ready_state")),"actual ready official booking document required");
        Index index=new Index(dom);
        List<JSONObject> titles=new ArrayList<JSONObject>();
        for(JSONObject n:index.nodes.values())if("div".equals(string(n,"tag"))&&index.visible(n)
                &&("选择出发地".equals(string(n,"text"))||"选择目的地".equals(string(n,"text"))))titles.add(n);
        if(titles.isEmpty())return null;
        need(titles.size()==1,"one visible city-picker title required");
        JSONObject title=titles.get(0),header=index.parent(title),picker=index.parent(header),box=index.parent(picker);
        plainDiv(title);plainDiv(header);plainDiv(picker);
        need("div".equals(string(box,"tag"))&&"queryBox".equals(string(box,"id"))
                &&index.visible(box),"city picker must be a direct child of the visible query box");
        List<JSONObject> forms=index.visibleId("div","flightQuery");
        need(forms.size()==1&&index.descendant(box,forms.get(0))&&index.visibleId("div","queryBox").size()==1,
                "same unique visible official form and query box required");
        List<JSONObject> hotLabels=new ArrayList<JSONObject>();
        for(JSONObject n:index.nodes.values())if(index.descendant(n,picker)&&index.visible(n)
                &&"div".equals(string(n,"tag"))&&"热门城市".equals(string(n,"text")))hotLabels.add(n);
        need(hotLabels.size()==1,"one actual hot-city section label required");
        JSONObject hot=hotLabels.get(0),section=index.parent(hot),content=index.parent(section);
        plainDiv(hot);plainDiv(section);plainDiv(content);
        need(index.parent(content)==picker&&content!=header,"hot-city section belongs to the current picker");
        List<JSONObject> lists=index.children(section,"ul");
        need(lists.size()==1&&index.visible(lists.get(0)),"one direct visible hot-city list required");
        JSONObject list=lists.get(0);
        need(string(list,"id").isEmpty()&&string(list,"text").isEmpty(),"plain actual hot-city list required");
        List<City> cities=new ArrayList<City>();
        for(JSONObject n:index.children(list,null)){
            need("li".equals(string(n,"tag")),"unreviewed hot-city list child");
            if(!index.visible(n))continue;
            need(string(n,"id").isEmpty()&&string(n,"role").isEmpty()
                    &&string(n,"name").isEmpty()&&string(n,"aria_label").isEmpty()
                    &&string(n,"text").matches("[\\p{IsHan}]{2,12}")
                    &&index.children(n,null).isEmpty(),"one plain full city label per actual list item");
            cities.add(new City(n));
        }
        need(!cities.isEmpty()&&cities.size()<=64,"bounded complete visible hot-city list required");
        return new CsairCityPicker(string(title,"text"),string(title,"path"),string(picker,"path"),
                string(box,"path"),string(list,"path"),cities);
    }
    /** Count before disabled filtering; a second matching label is not silently discarded. */
    City city(String exactOwnerCity){
        City found=null;
        for(City city:cities)if(city.text.equals(exactOwnerCity)){
            need(found==null,"duplicate visible requested city");found=city;
        }
        return found==null||found.disabled?null:found;
    }
    Map<String,Object> evidence(){
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("schema",SCHEMA);out.put("kind",kind);out.put("title",title);
        out.put("title_dom_path",titlePath);out.put("picker_dom_path",pickerPath);
        out.put("query_box_dom_path",queryBoxPath);out.put("hot_city_list_dom_path",hotListPath);
        List<Map<String,Object>> values=new ArrayList<Map<String,Object>>();
        for(City city:cities)values.add(city.evidence());out.put("visible_hot_cities",values);
        out.put("city_selection_verified",false);out.put("airport_choice_inferred",false);
        out.put("query_executed",false);out.put("grants_tool_authority",false);
        out.put("css_to_screen_mapping_used",false);return out;
    }
    private static void plainDiv(JSONObject node)throws Exception{
        need(node!=null&&"div".equals(string(node,"tag"))&&string(node,"id").isEmpty(),"actual plain picker div required");
    }
    private static final class Index {
        final Map<String,JSONObject> nodes=new LinkedHashMap<String,JSONObject>();
        Index(JSONObject dom)throws Exception{
            String schema=string(dom,"schema");
            need(("hepta.fixed-top-document-dom.v2".equals(schema)||"hepta.fixed-top-document-dom.v3".equals(schema)),"actual geometry-aware fixed DOM required");
            need(Boolean.FALSE.equals(dom.get("truncated"))&&dom.getJSONArray("truncation_reasons").length()==0,
                    "complete bounded DOM required");
            JSONArray rows=dom.getJSONArray("nodes");need(rows.length()>0&&rows.length()<=1024,"bounded DOM nodes");
            for(int i=0;i<rows.length();i++){
                JSONObject n=rows.getJSONObject(i);String path=string(n,"path");
                need(path.matches("0(?:/[0-9]{1,5}){0,32}")&&!nodes.containsKey(path),"unique exact DOM path");
                need(string(n,"tag").matches("[a-z][a-z0-9:-]{0,63}"),"actual tag");
                for(String k:new String[]{"id","role","name","aria_label","text"})string(n,k);
                flag(n,"visible_in_viewport");flag(n,"disabled");
                Object aria=n.get("aria_disabled");need(aria==JSONObject.NULL||aria instanceof String,"aria disabled type");
                nodes.put(path,n);
            }
            need(nodes.containsKey("0"),"actual document root required");
            for(JSONObject n:nodes.values()){
                String path=string(n,"path");Object parent=n.get("parent_path");
                if("0".equals(path))need(parent==JSONObject.NULL,"document root parent");
                else need(parent instanceof String&&nodes.containsKey(parent)
                        &&path.substring(0,path.lastIndexOf('/')).equals(parent),"complete direct DOM ancestry");
            }
        }
        JSONObject parent(JSONObject n)throws Exception{
            need(n!=null&&n.get("parent_path") instanceof String,"actual parent required");
            JSONObject parent=nodes.get(n.getString("parent_path"));need(parent!=null,"parent missing");return parent;
        }
        boolean descendant(JSONObject n,JSONObject ancestor)throws Exception{
            return string(n,"path").startsWith(string(ancestor,"path")+"/");
        }
        boolean visible(JSONObject n)throws Exception{
            while(true){
                if(!flag(n,"visible_in_viewport"))return false;
                if("0".equals(string(n,"path")))return true;
                n=parent(n);
            }
        }
        List<JSONObject> children(JSONObject parent,String tag)throws Exception{
            List<JSONObject> result=new ArrayList<JSONObject>();String path=string(parent,"path");
            for(JSONObject n:nodes.values())if(path.equals(n.get("parent_path"))&&(tag==null||tag.equals(string(n,"tag"))))result.add(n);
            return result;
        }
        List<JSONObject> visibleId(String tag,String id)throws Exception{
            List<JSONObject> result=new ArrayList<JSONObject>();
            for(JSONObject n:nodes.values())if(tag.equals(string(n,"tag"))&&id.equals(string(n,"id"))&&visible(n))result.add(n);
            return result;
        }
    }
    private static String string(JSONObject object,String key)throws Exception{
        need(object!=null,"actual object required");Object value=object.get(key);
        need(value instanceof String&&((String)value).length()<=4096,"bounded actual string: "+key);return (String)value;
    }
    private static boolean flag(JSONObject object,String key)throws Exception{
        Object value=object.get(key);need(value instanceof Boolean,"actual boolean: "+key);return Boolean.TRUE.equals(value);
    }
    private static void need(boolean ok,String why){if(!ok)throw new IllegalArgumentException(why);}
}
