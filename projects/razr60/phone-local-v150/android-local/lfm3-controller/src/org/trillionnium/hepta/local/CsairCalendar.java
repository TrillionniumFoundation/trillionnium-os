package org.trillionnium.hepta.local;

import org.json.JSONArray;
import org.json.JSONObject;
import java.net.URI;
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
 * Data-only interpretation of the observed Csair calendar.
 * No date comes from URL parameters, a requested goal, cell position or "today".
 * This class never maps CSS to pixels, publishes an AX identity or grants a click.
 */
final class CsairCalendar {
    static final String SCHEMA = "hepta.csair-observed-calendar.v1";
    private static final Pattern PATH = Pattern.compile("0(?:/(?:0|[1-9][0-9]{0,4})){0,32}");
    private static final Pattern MONTH = Pattern.compile("([1-9][0-9]{3})年([1-9]|1[0-2])月");
    private static final Pattern DAY = Pattern.compile("[1-9]|[12][0-9]|3[01]");
    private static final Pattern ISO = Pattern.compile("([1-9][0-9]{3})-([0][1-9]|1[0-2])-([0][1-9]|[12][0-9]|3[01])");
    private static final String[] WEEK = {"日","一","二","三","四","五","六"};

    static final class Month {
        final int year,month;
        final String headerText,headerPath,monthPath,dayListPath;
        final boolean zeroHeightDayList;
        final Map<String,Object> headerEvidence;
        Month(Index index,JSONObject header,JSONObject panel,JSONObject list,int y,int m)throws Exception{
            year=y;month=m;headerText=text(header,"text");headerPath=text(header,"path");
            monthPath=text(panel,"path");dayListPath=text(list,"path");
            zeroHeightDayList=index.zeroHeightLayoutList(list);
            headerEvidence=index.nodeEvidence(header);
        }
        Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();
            out.put("year",year);out.put("month",month);out.put("header_text",headerText);
            out.put("header_dom_path",headerPath);out.put("month_dom_path",monthPath);
            out.put("day_list_dom_path",dayListPath);out.put("zero_height_layout_list",zeroHeightDayList);
            out.put("original_header",headerEvidence);return out;
        }
    }

    static final class DateTarget {
        final int year,month,day;
        final String isoDate,monthHeaderText,monthHeaderPath,monthPath,dayListPath,dayPath,dayText,domId;
        final boolean domDisabled,domVisibleInViewport,zeroHeightDayList;
        final List<Map<String,Object>> originalAncestors;
        DateTarget(Index index,Month observed,JSONObject node,int d)throws Exception{
            year=observed.year;month=observed.month;day=d;
            isoDate=String.format(java.util.Locale.ROOT,"%04d-%02d-%02d",year,month,day);
            monthHeaderText=observed.headerText;monthHeaderPath=observed.headerPath;
            monthPath=observed.monthPath;dayListPath=observed.dayListPath;
            dayPath=text(node,"path");dayText=text(node,"text");domId=text(node,"id");
            domDisabled=index.disabledThrough(node);domVisibleInViewport=flag(node,"visible_in_viewport");
            zeroHeightDayList=observed.zeroHeightDayList;
            originalAncestors=index.ancestry(node);
        }
        Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();
            out.put("year",year);out.put("month",month);out.put("day",day);out.put("iso_date",isoDate);
            out.put("month_header_text",monthHeaderText);out.put("month_header_dom_path",monthHeaderPath);
            out.put("month_dom_path",monthPath);out.put("day_list_dom_path",dayListPath);
            out.put("day_dom_path",dayPath);out.put("day_dom_tag","li");out.put("day_dom_id",domId);
            out.put("observed_day_text",dayText);out.put("dom_disabled",domDisabled);
            out.put("dom_visible_in_viewport",domVisibleInViewport);
            out.put("zero_height_layout_list",zeroHeightDayList);out.put("original_dom_ancestors",originalAncestors);
            out.put("native_visibility_verified",false);out.put("native_action_click_verified",false);
            out.put("css_to_screen_mapping_verified",false);out.put("selected_date_verified",false);
            out.put("grants_tool_authority",false);return out;
        }
    }

    static final class Selection {
        final boolean ready;
        final String reason,requestedIsoDate;
        final DateTarget target;
        Selection(String requested,DateTarget observed,String why){
            requestedIsoDate=requested;target=observed;
            ready=observed!=null&&!observed.domDisabled;reason=why;
        }
        Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();
            out.put("requested_iso_date",requestedIsoDate);out.put("exact_date_metadata_ready",ready);
            out.put("reason",reason);out.put("observed_target",target==null?null:target.evidence());
            out.put("selected_date_verified",false);out.put("query_ready_verified",false);
            out.put("grants_tool_authority",false);return out;
        }
    }

    final String titlePath,pagePath,weekdaysPath,calendarViewportPath,monthsPath;
    final boolean headerOnly;
    final List<Month> months;
    final List<DateTarget> dates;
    private CsairCalendar(String title,String page,String week,String viewport,String holder,
            List<Month> observedMonths,List<DateTarget> observedDates){
        titlePath=title;pagePath=page;weekdaysPath=week;calendarViewportPath=viewport;monthsPath=holder;
        months=Collections.unmodifiableList(new ArrayList<Month>(observedMonths));
        dates=Collections.unmodifiableList(new ArrayList<DateTarget>(observedDates));
        headerOnly=months.isEmpty();
    }

    /** Non-calendar official routes return null; malformed recognized calendars fail closed. */
    static CsairCalendar read(JSONObject dom)throws Exception{
        URI uri=new URI(text(dom,"href"));
        need("https".equals(uri.getScheme())&&"m.csair.com".equals(uri.getHost())
                &&uri.getRawUserInfo()==null&&(uri.getPort()==-1||uri.getPort()==443)
                &&"https://m.csair.com".equals(text(dom,"origin")),"official Csair document required");
        String fragment=uri.getRawFragment();
        if(!"/booking_new/".equals(uri.getRawPath())||fragment==null
                ||!("/newCalendar".equals(fragment)||fragment.startsWith("/newCalendar?")))return null;
        need("complete".equals(text(dom,"ready_state")),"complete calendar document required");
        Index index=new Index(dom);
        List<JSONObject> appRoots=index.match("div","root",null);
        need(appRoots.size()==1&&index.visibleThrough(appRoots.get(0),null),"one observed app root required");
        JSONObject app=appRoots.get(0);
        List<JSONObject> titles=index.texts("div","选择日期",text(app,"path"));
        need(titles.size()==1&&index.visibleThrough(titles.get(0),null),"one visible calendar title required");
        JSONObject title=titles.get(0),bar=index.parent(title,"div"),header=index.parent(bar,"div");
        JSONObject page=index.parent(header,"div"),shell=index.parent(page,"div");
        need(index.parent(shell,"div")==app&&text(title,"path").equals(text(bar,"path")+"/1")
                &&text(bar,"path").equals(text(header,"path")+"/0")
                &&text(header,"path").equals(text(page,"path")+"/0"),"observed calendar title ancestry differs");
        JSONObject body=index.require(text(page,"path")+"/1","div");
        JSONObject weekHolder=index.require(text(body,"path")+"/0","div");
        JSONObject week=index.require(text(weekHolder,"path")+"/0","ul");
        need(index.layoutListVisible(week)&&index.visibleThrough(weekHolder,null),
                "observed weekday row container required");
        List<JSONObject> weekDays=index.children(week);
        need(weekDays.size()==7,"exact seven weekday labels required");
        for(int i=0;i<WEEK.length;i++){
            JSONObject n=weekDays.get(i);
            need("li".equals(text(n,"tag"))&&WEEK[i].equals(text(n,"text"))
                    &&text(n,"path").equals(text(week,"path")+"/"+i)
                    &&index.visibleThrough(n,text(week,"path")),"actual ordered weekday row differs");
        }
        JSONObject viewport=index.require(text(body,"path")+"/2","div");
        JSONObject holder=index.require(text(viewport,"path")+"/0","div");
        List<Month> months=new ArrayList<Month>();List<DateTarget> dates=new ArrayList<DateTarget>();
        Set<String> monthKeys=new LinkedHashSet<String>(),dateKeys=new LinkedHashSet<String>();
        List<JSONObject> panels=index.children(holder);
        need(panels.size()<=24,"bounded calendar month panels required");
        for(JSONObject panel:panels){
            need("div".equals(text(panel,"tag")),"calendar month panel tag differs");
            List<JSONObject> children=index.children(panel);
            need(children.size()==2&&"h1".equals(text(children.get(0),"tag"))
                    &&"ul".equals(text(children.get(1),"tag")),"actual month header/list structure required");
            JSONObject h=children.get(0),list=children.get(1);
            if(!index.visibleThrough(h,null))continue;
            Matcher match=MONTH.matcher(text(h,"text"));
            need(match.matches(),"visible month must contain explicit year and month");
            int y=Integer.parseInt(match.group(1)),m=Integer.parseInt(match.group(2));
            need(monthKeys.add(y+"-"+m),"duplicate visible year-month heading");
            need(index.layoutListVisible(list),"day-list layout not covered by actual observed structure");
            Month observed=new Month(index,h,panel,list,y,m);months.add(observed);
            List<JSONObject> days=index.children(list);need(days.size()<=42,"bounded month grid required");
            for(JSONObject day:days){
                need("li".equals(text(day,"tag")),"month grid has an unreviewed direct child");
                if(!index.visibleThrough(day,text(list,"path")))continue;
                String label=text(day,"text");
                // Blank leading cells, holiday words and "today" do not establish a numeric date.
                if(!DAY.matcher(label).matches())continue;
                int number=Integer.parseInt(label);need(number<=daysInMonth(y,m),"invalid literal calendar day");
                DateTarget value=new DateTarget(index,observed,day,number);
                need(dateKeys.add(value.isoDate),"duplicate visible exact date");
                dates.add(value);
            }
        }
        // A visible heading elsewhere cannot silently be attached to a different month grid.
        for(JSONObject h:index.match("h1",null,text(app,"path"))){
            if(index.visibleThrough(h,null))need(text(h,"path").startsWith(text(holder,"path")+"/"),
                    "visible calendar heading is outside the observed month container");
        }
        return new CsairCalendar(text(title,"path"),text(page,"path"),text(week,"path"),
                text(viewport,"path"),text(holder,"path"),months,dates);
    }

    Selection forDate(String iso)throws Exception{
        need(iso!=null,"explicit requested date required");Matcher match=ISO.matcher(iso);
        need(match.matches(),"canonical requested yyyy-mm-dd required");
        int y=Integer.parseInt(match.group(1)),m=Integer.parseInt(match.group(2)),d=Integer.parseInt(match.group(3));
        need(d<=daysInMonth(y,m),"invalid requested calendar date");
        DateTarget target=null;
        for(DateTarget value:dates)if(value.year==y&&value.month==m&&value.day==d){
            need(target==null,"ambiguous exact target date");target=value;
        }
        if(target==null)return new Selection(iso,null,headerOnly?"recognized_calendar_header_only":"requested_literal_date_not_observed");
        return new Selection(iso,target,target.domDisabled?"observed_target_dom_disabled":"explicit_literal_year_month_day_observed");
    }

    Map<String,Object> evidence(){
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("schema",SCHEMA);
        out.put("recognized_calendar",true);out.put("recognized_but_not_ready",headerOnly);
        out.put("title_dom_path",titlePath);out.put("page_dom_path",pagePath);out.put("weekdays_dom_path",weekdaysPath);
        out.put("calendar_viewport_dom_path",calendarViewportPath);out.put("months_dom_path",monthsPath);
        List<Map<String,Object>> observedMonths=new ArrayList<Map<String,Object>>();
        for(Month value:months)observedMonths.add(value.evidence());
        List<Map<String,Object>> observedDates=new ArrayList<Map<String,Object>>();
        for(DateTarget value:dates)observedDates.add(value.evidence());
        out.put("observed_months",observedMonths);out.put("observed_literal_dates",observedDates);
        out.put("url_date_used_as_evidence",false);out.put("relative_today_inferred",false);
        out.put("native_visibility_verified",false);out.put("selected_date_verified",false);
        out.put("query_ready_verified",false);out.put("grants_tool_authority",false);return out;
    }

    private static final class Index {
        final Map<String,JSONObject> nodes=new LinkedHashMap<String,JSONObject>();
        Index(JSONObject dom)throws Exception{
            String schema=text(dom,"schema");
            need("hepta.fixed-top-document-dom.v2".equals(schema)||"hepta.fixed-top-document-dom.v3".equals(schema)||"hepta.fixed-top-document-dom.v4".equals(schema),
                    "actual fixed observer v2/v3 DOM required");
            need(!flag(dom,"truncated")&&dom.getJSONArray("truncation_reasons").length()==0,"complete DOM required");
            JSONArray rows=dom.getJSONArray("nodes");need(rows.length()>0&&rows.length()<=1024,"bounded DOM nodes");
            Object visited=dom.get("visited");
            need((visited instanceof Integer||visited instanceof Long)&&((Number)visited).longValue()==rows.length(),
                    "complete visited/node count required");
            for(int i=0;i<rows.length();i++){
                JSONObject n=rows.getJSONObject(i);String path=text(n,"path");
                need(PATH.matcher(path).matches()&&!nodes.containsKey(path),"unique canonical DOM paths");
                need(text(n,"tag").matches("[a-z][a-z0-9:-]{0,63}"),"DOM tag shape");
                for(String key:new String[]{"id","role","name","aria_label","text"})text(n,key);
                flag(n,"visible_in_viewport");flag(n,"disabled");flag(n,"iframe_contents_read");
                need(n.get("aria_disabled")==JSONObject.NULL||n.get("aria_disabled") instanceof String,"aria-disabled type");
                rectangle(n);nodes.put(path,n);
            }
            need(nodes.containsKey("0")&&"html".equals(text(nodes.get("0"),"tag")),"actual document root");
            for(JSONObject n:nodes.values()){
                String path=text(n,"path");Object parent=n.get("parent_path");
                if("0".equals(path))need(parent==JSONObject.NULL,"root parent");
                else need(parent instanceof String&&nodes.containsKey(parent)
                        &&path.substring(0,path.lastIndexOf('/')).equals(parent),"complete direct ancestry");
            }
        }
        JSONObject require(String path,String tag)throws Exception{
            JSONObject n=nodes.get(path);need(n!=null&&tag.equals(text(n,"tag")),"expected calendar node: "+path);return n;
        }
        JSONObject parent(JSONObject node,String tag)throws Exception{return require(text(node,"parent_path"),tag);}
        List<JSONObject> children(JSONObject parent)throws Exception{
            String path=text(parent,"path");List<JSONObject> out=new ArrayList<JSONObject>();
            for(JSONObject n:nodes.values())if(path.equals(n.get("parent_path")))out.add(n);
            for(int i=0;i<out.size();i++)need(text(out.get(i),"path").equals(path+"/"+i),"ordered complete direct children");
            return out;
        }
        List<JSONObject> match(String tag,String id,String ancestor)throws Exception{
            List<JSONObject> out=new ArrayList<JSONObject>();
            for(JSONObject n:nodes.values())if(tag.equals(text(n,"tag"))&&(id==null||id.equals(text(n,"id")))
                    &&(ancestor==null||text(n,"path").startsWith(ancestor+"/")))out.add(n);
            return out;
        }
        List<JSONObject> texts(String tag,String value,String ancestor)throws Exception{
            List<JSONObject> out=new ArrayList<JSONObject>();
            for(JSONObject n:match(tag,null,ancestor))if(value.equals(text(n,"text"))&&visibleThrough(n,null))out.add(n);
            return out;
        }
        boolean zeroHeightLayoutList(JSONObject n)throws Exception{
            double[] r=rectangle(n);
            return "ul".equals(text(n,"tag"))&&!flag(n,"visible_in_viewport")
                    &&r[2]>r[0]&&r[3]==r[1]&&text(n,"text").isEmpty();
        }
        boolean layoutListVisible(JSONObject n)throws Exception{
            return (flag(n,"visible_in_viewport")&&positive(n))||zeroHeightLayoutList(n);
        }
        boolean visibleThrough(JSONObject node,String singleLayoutList)throws Exception{
            JSONObject cursor=node;
            while(cursor!=null){
                boolean exception=text(cursor,"path").equals(singleLayoutList)&&zeroHeightLayoutList(cursor);
                if(!exception&&(!flag(cursor,"visible_in_viewport")||!positive(cursor)))return false;
                Object p=cursor.get("parent_path");cursor=p instanceof String?nodes.get(p):null;
            }
            return true;
        }
        boolean disabledThrough(JSONObject node)throws Exception{
            JSONObject cursor=node;
            while(cursor!=null){
                if(flag(cursor,"disabled")||"true".equals(cursor.get("aria_disabled")))return true;
                Object p=cursor.get("parent_path");cursor=p instanceof String?nodes.get(p):null;
            }
            return false;
        }
        List<Map<String,Object>> ancestry(JSONObject node)throws Exception{
            List<Map<String,Object>> out=new ArrayList<Map<String,Object>>();JSONObject cursor=node;
            while(cursor!=null){out.add(nodeEvidence(cursor));Object p=cursor.get("parent_path");cursor=p instanceof String?nodes.get(p):null;}
            Collections.reverse(out);return Collections.unmodifiableList(out);
        }
        Map<String,Object> nodeEvidence(JSONObject n)throws Exception{
            Map<String,Object> out=new LinkedHashMap<String,Object>();
            for(String k:new String[]{"path","tag","id","text"})out.put(k,text(n,k));
            out.put("parent_path",n.get("parent_path")==JSONObject.NULL?null:n.get("parent_path"));
            out.put("visible_in_viewport",flag(n,"visible_in_viewport"));out.put("disabled",flag(n,"disabled"));
            out.put("aria_disabled",n.get("aria_disabled")==JSONObject.NULL?null:n.get("aria_disabled"));
            double[] rect=rectangle(n);List<Double> values=new ArrayList<Double>();
            for(double value:rect)values.add(Double.valueOf(value));
            out.put("original_rect_css_pixels",Collections.unmodifiableList(values));
            return Collections.unmodifiableMap(out);
        }
        boolean positive(JSONObject n)throws Exception{double[] r=rectangle(n);return r[2]>r[0]&&r[3]>r[1];}
    }
    private static double[] rectangle(JSONObject n)throws Exception{
        JSONArray raw=n.getJSONArray("rect_css_pixels");need(raw.length()==4,"four original DOM rect values");
        double[] out=new double[4];
        for(int i=0;i<4;i++){Object value=raw.get(i);need(value instanceof Number,"numeric DOM rect");
            out[i]=((Number)value).doubleValue();need(!Double.isNaN(out[i])&&!Double.isInfinite(out[i])
                    &&Math.abs(out[i])<=1000000,"finite bounded original DOM rect");}
        need(out[2]>=out[0]&&out[3]>=out[1],"ordered original DOM rect");return out;
    }
    private static int daysInMonth(int year,int month){
        need(month>=1&&month<=12,"month range");
        if(month==2)return year%4==0&&(year%100!=0||year%400==0)?29:28;
        return month==4||month==6||month==9||month==11?30:31;
    }
    private static String text(JSONObject n,String key)throws Exception{
        Object value=n.get(key);need(value instanceof String&&((String)value).length()<=4096,"bounded string: "+key);
        return (String)value;
    }
    private static boolean flag(JSONObject n,String key)throws Exception{
        Object value=n.get(key);need(value instanceof Boolean,"boolean: "+key);return value==Boolean.TRUE;
    }
    private static void need(boolean ok,String message){if(!ok)throw new IllegalArgumentException(message);}
}
