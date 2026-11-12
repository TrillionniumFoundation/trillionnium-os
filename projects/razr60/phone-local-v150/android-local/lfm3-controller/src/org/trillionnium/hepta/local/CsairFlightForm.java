package org.trillionnium.hepta.local;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Data-only reading of the actual official booking form.
 * DOM visibility is not screen visibility and no result grants an Android action.
 * The initial real capture has placeholders and no displayed year; those are
 * preserved as unknown query values rather than filled from the requested goal.
 */
final class CsairFlightForm {
    static final String SCHEMA="hepta.csair-observed-query-form.v1";
    private static final Pattern PATH=Pattern.compile("0(?:/[0-9]{1,5}){0,32}");
    private static final Pattern MONTH_DAY=Pattern.compile("([0-9]{1,2})月([0-9]{1,2})日");

    static final class Control {
        final String id,path,tag,requiredLabel;
        final List<String> visibleTexts;
        final boolean disabled;
        Control(JSONObject node,String label,List<String> texts)throws Exception{
            id=text(node,"id");path=text(node,"path");tag=text(node,"tag");
            requiredLabel=label;visibleTexts=Collections.unmodifiableList(new ArrayList<String>(texts));
            disabled=flag(node,"disabled")||"true".equals(node.get("aria_disabled"));
        }
        Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();
            out.put("dom_path",path);out.put("dom_id",id);out.put("dom_tag",tag);
            out.put("required_label",requiredLabel);out.put("observed_visible_texts",visibleTexts);
            out.put("dom_disabled",disabled);out.put("dom_visibility_is_native_visibility",false);
            return out;
        }
    }
    final String formPath,queryBoxPath,tabContentPath,singlePanelPath,singleTabPath;
    final Control departure,arrival,departureDate,query;
    final boolean departurePlaceholder,arrivalPlaceholder,returnDateHidden,multiPanelHidden;
    final Integer displayedMonth,displayedDay;
    final String displayedWeekday;
    final int adults,children,infants;
    private CsairFlightForm(Index index,JSONObject form,JSONObject box,JSONObject tabs,JSONObject single,
            JSONObject singleTab,JSONObject dep,JSONObject arr,JSONObject date,JSONObject button,
            JSONObject passengers,boolean returnHidden,boolean multiHidden)throws Exception{
        formPath=text(form,"path");queryBoxPath=text(box,"path");tabContentPath=text(tabs,"path");
        singlePanelPath=text(single,"path");singleTabPath=text(singleTab,"path");
        departure=new Control(dep,"出发城市",index.visibleTexts(dep));
        arrival=new Control(arr,"到达城市",index.visibleTexts(arr));
        departureDate=new Control(date,"出发日期",index.visibleTexts(date));
        query=new Control(button,"查询",index.visibleTexts(button));
        need(departure.visibleTexts.contains(departure.requiredLabel)
                &&arrival.visibleTexts.contains(arrival.requiredLabel)
                &&departureDate.visibleTexts.contains(departureDate.requiredLabel)
                &&query.visibleTexts.size()==1&&"查询".equals(query.visibleTexts.get(0)),
                "actual field labels are missing or ambiguous");
        departurePlaceholder=only(departure.visibleTexts,"出发城市");
        arrivalPlaceholder=only(arrival.visibleTexts,"到达城市");
        returnDateHidden=returnHidden;multiPanelHidden=multiHidden;
        Integer month=null,day=null;String weekday=null;
        for(String value:departureDate.visibleTexts){
            Matcher match=MONTH_DAY.matcher(value);
            if(match.matches()){
                need(month==null,"multiple displayed departure dates");
                int m=Integer.parseInt(match.group(1)),d=Integer.parseInt(match.group(2));
                need(m>=1&&m<=12&&d>=1&&d<=31,"invalid observed month/day");
                month=Integer.valueOf(m);day=Integer.valueOf(d);
            }else if(value.matches("周[一二三四五六日天]")){
                need(weekday==null,"multiple displayed departure weekdays");weekday=value;
            }else need("出发日期".equals(value),"unreviewed departure date display");
        }
        displayedMonth=month;displayedDay=day;displayedWeekday=weekday;
        adults=index.passenger(passengers,"成人");children=index.passenger(passengers,"儿童");infants=index.passenger(passengers,"婴儿");
    }

    /** Unsupported pages return null. A recognized but ambiguous form is rejected. */
    static CsairFlightForm read(JSONObject dom)throws Exception{
        java.net.URI url=new java.net.URI(text(dom,"href"));
        need("https".equals(url.getScheme())&&"m.csair.com".equals(url.getHost())
                &&url.getRawUserInfo()==null&&(url.getPort()==-1||url.getPort()==443)
                &&"/booking_new/".equals(url.getPath())&&"https://m.csair.com".equals(text(dom,"origin"))
                &&"complete".equals(text(dom,"ready_state")),"actual ready official booking document required");
        Index index=new Index(dom);
        List<JSONObject> forms=index.visible("div","flightQuery",null,false);
        if(forms.isEmpty())return null;
        need(forms.size()==1,"multiple visible official form roots");
        JSONObject form=forms.get(0),box=index.oneVisible("div","queryBox",form,false);
        JSONObject tabs=index.oneVisible("div","tabContent",box,false);
        JSONObject control=index.oneVisible("div","tabControl",box,false);
        JSONObject single=index.oneVisible("div","single",tabs,true);
        JSONObject singleTab=index.oneVisible("li","single",control,false);
        need("单程".equals(text(singleTab,"text")),"actual single trip tab label differs");
        JSONObject dep=index.oneVisible("div","depport",single,false);
        JSONObject arr=index.oneVisible("div","arrport",single,false);
        JSONObject date=index.oneVisible("div","depDate",single,false);
        JSONObject query=index.oneVisible("button","queryBtn",tabs,true);
        JSONObject passengers=index.oneVisible("div","psgBox",tabs,true);
        // Hidden multistage fields genuinely repeat these IDs. Only one visible
        // instance anywhere in this form may map to the current native AX ID.
        for(String id:new String[]{"depport","arrport","depDate"})
            need(index.visible("div",id,form,false).size()==1,"duplicate visible field: "+id);
        need(index.visible("button","queryBtn",form,false).size()==1,"duplicate visible query");
        need(index.all("div","arrDate",single,false).size()==1
                &&index.all("div","multistage",tabs,true).size()==1,"actual hidden return/multistage regions required");
        boolean returnHidden=index.visible("div","arrDate",single,false).isEmpty();
        boolean multiHidden=index.visible("div","multistage",tabs,true).isEmpty();
        need(returnHidden&&multiHidden,"return or multistage form is currently visible");
        return new CsairFlightForm(index,form,box,tabs,single,singleTab,dep,arr,date,query,passengers,returnHidden,multiHidden);
    }

    Map<String,Object> evidence(){
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("schema",SCHEMA);
        out.put("form_dom_path",formPath);out.put("query_box_dom_path",queryBoxPath);
        out.put("tab_content_dom_path",tabContentPath);out.put("single_panel_dom_path",singlePanelPath);
        out.put("single_tab_dom_path",singleTabPath);out.put("return_date_hidden",returnDateHidden);
        out.put("multistage_panel_hidden",multiPanelHidden);out.put("departure_control",departure.evidence());
        out.put("arrival_control",arrival.evidence());out.put("departure_date_control",departureDate.evidence());
        out.put("query_control",query.evidence());out.put("departure_is_placeholder",departurePlaceholder);
        out.put("arrival_is_placeholder",arrivalPlaceholder);out.put("selected_departure_city",null);
        out.put("selected_arrival_city",null);out.put("displayed_month",displayedMonth);
        out.put("displayed_day",displayedDay);out.put("displayed_weekday",displayedWeekday);
        out.put("displayed_year",null);out.put("complete_departure_date_verified",false);
        out.put("adults",adults);out.put("children",children);out.put("infants",infants);
        out.put("query_ready_verified",false);out.put("query_executed",false);
        out.put("flight_results_verified",false);out.put("grants_tool_authority",false);
        return out;
    }

    private static final class Index {
        final Map<String,JSONObject> nodes=new LinkedHashMap<String,JSONObject>();
        Index(JSONObject dom)throws Exception{
            String schema=text(dom,"schema");
            need("hepta.fixed-top-document-dom.v1".equals(schema)||"hepta.fixed-top-document-dom.v2".equals(schema),
                    "actual fixed observer DOM schema required");
            need(Boolean.FALSE.equals(dom.get("truncated"))&&dom.getJSONArray("truncation_reasons").length()==0,
                    "complete bounded DOM required");
            JSONArray rows=dom.getJSONArray("nodes");
            need(rows.length()>0&&rows.length()<=1024,"DOM node count");
            for(int i=0;i<rows.length();i++){
                JSONObject node=rows.getJSONObject(i);String path=text(node,"path");
                need(PATH.matcher(path).matches()&&!nodes.containsKey(path),"unique exact DOM paths required");
                need(text(node,"tag").matches("[a-z][a-z0-9:-]{0,63}"),"DOM tag shape");
                for(String key:new String[]{"id","role","name","aria_label","text"})text(node,key);
                flag(node,"visible_in_viewport");flag(node,"disabled");
                Object aria=node.get("aria_disabled");need(aria==JSONObject.NULL||aria instanceof String,"aria disabled type");
                nodes.put(path,node);
            }
            need(nodes.containsKey("0"),"actual document root required");
            for(Map.Entry<String,JSONObject> row:nodes.entrySet()){
                String path=row.getKey();Object parent=row.getValue().get("parent_path");
                if("0".equals(path))need(parent==JSONObject.NULL,"document root parent");
                else need(parent instanceof String&&nodes.containsKey(parent)
                        &&path.substring(0,path.lastIndexOf('/')).equals(parent),"complete direct DOM ancestry required");
            }
        }
        List<JSONObject> all(String tag,String id,JSONObject ancestor,boolean direct)throws Exception{
            List<JSONObject> found=new ArrayList<JSONObject>();String parent=ancestor==null?null:text(ancestor,"path");
            for(JSONObject node:nodes.values())if(tag.equals(text(node,"tag"))&&id.equals(text(node,"id"))
                    &&within(node,parent,direct))found.add(node);
            return found;
        }
        List<JSONObject> visible(String tag,String id,JSONObject ancestor,boolean direct)throws Exception{
            List<JSONObject> found=new ArrayList<JSONObject>();String parent=ancestor==null?null:text(ancestor,"path");
            for(JSONObject node:nodes.values())if(tag.equals(text(node,"tag"))&&id.equals(text(node,"id"))
                    &&visibleThrough(node,parent)&&within(node,parent,direct))found.add(node);
            return found;
        }
        JSONObject oneVisible(String tag,String id,JSONObject ancestor,boolean direct)throws Exception{
            List<JSONObject> found=visible(tag,id,ancestor,direct);
            need(found.size()==1,"one actual visible "+tag+"#"+id+" required");return found.get(0);
        }
        boolean within(JSONObject node,String parent,boolean direct)throws Exception{
            if(parent==null)return true;
            return direct?parent.equals(node.get("parent_path")):text(node,"path").startsWith(parent+"/");
        }
        boolean visibleThrough(JSONObject node,String ancestor)throws Exception{
            JSONObject cursor=node;
            while(cursor!=null){
                if(!flag(cursor,"visible_in_viewport"))return false;
                String path=text(cursor,"path");
                if(ancestor==null||path.equals(ancestor))return true;
                Object parent=cursor.get("parent_path");cursor=parent instanceof String?nodes.get(parent):null;
            }
            return false;
        }
        List<String> visibleTexts(JSONObject root)throws Exception{
            String prefix=text(root,"path");Set<String> values=new LinkedHashSet<String>();int characters=0;
            for(JSONObject node:nodes.values())if((text(node,"path").equals(prefix)||text(node,"path").startsWith(prefix+"/"))
                    &&visibleThrough(node,prefix)){
                String value=text(node,"text");if(!value.isEmpty()&&values.add(value)){
                    characters+=value.length();need(values.size()<=12&&characters<=256,"bounded complete field text required");
                }
            }
            return new ArrayList<String>(values);
        }
        int passenger(JSONObject root,String label)throws Exception{
            List<JSONObject> parents=new ArrayList<JSONObject>();String path=text(root,"path");
            for(JSONObject node:nodes.values())if("div".equals(text(node,"tag"))&&label.equals(text(node,"text"))
                    &&within(node,path,false)&&visibleThrough(node,path))parents.add(node);
            need(parents.size()==1,"one observed passenger label required: "+label);
            String parent=text(parents.get(0),"path");List<JSONObject> numbers=new ArrayList<JSONObject>();
            for(JSONObject node:nodes.values())if("span".equals(text(node,"tag"))&&parent.equals(node.get("parent_path"))
                    &&visibleThrough(node,parent))numbers.add(node);
            need(numbers.size()==1,"one direct observed passenger count required: "+label);
            String value=text(numbers.get(0),"text");need(value.matches("[0-9]"),"bounded actual passenger count");
            return Integer.parseInt(value);
        }
    }
    private static boolean only(List<String> values,String label){return values.size()==1&&label.equals(values.get(0));}
    private static String text(JSONObject value,String key)throws Exception{
        Object raw=value.get(key);need(raw instanceof String,"actual string required: "+key);
        String text=(String)raw;need(text.length()<=4096,"bounded actual string");return text;
    }
    private static boolean flag(JSONObject value,String key)throws Exception{
        Object raw=value.get(key);need(raw instanceof Boolean,"actual boolean required: "+key);return raw==Boolean.TRUE;
    }
    private static void need(boolean ok,String message){if(!ok)throw new IllegalArgumentException(message);}
}
