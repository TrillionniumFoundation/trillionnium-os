package org.trillionnium.hepta.local;

import java.math.BigDecimal;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Version-specific reading of actual Ctrip native fields. A Page is neither a
 * successful query nor an action grant. NativeAppSession supplies the immutable
 * task/installed-App binding and the actual model/action/query/date chain.
 */
final class NativeCtripFlightPage {
    static final String PACKAGE=NativeAppGoal.CTRIP_PACKAGE;
    static final long VERSION_CODE=1779;
    static final String BASE_APK_SHA256="666ce1e8234682c89247d5109c5cfa36451c6e67238ee38a545c2d84c88360fa";
    // Correct full APK identity is checked by NativeAppSession; this provider
    // deliberately exposes no installed-identity override or version fallback.
    static final String HOME="ctrip_home",FORM="ctrip_single_flight_form",CALENDAR="ctrip_native_calendar";
    static final String RESULTS="ctrip_single_flight_results",OVERLAY="ctrip_research_overlay",UNAVAILABLE="unavailable";
    private static final String PREFIX="ctrip.android.view:id/";
    private static final Pattern FORM_DATE=Pattern.compile("([0-9]{1,2})月([0-9]{1,2})日(今天|明天|后天|周[一二三四五六日天])");
    private static final Pattern MONTH=Pattern.compile("([0-9]{4})年([0-9]{1,2})月");
    private static final Pattern CARD=Pattern.compile("第([A-Z0-9]{2}[0-9]{3,4})航班");
    private static final Pattern AMOUNT=Pattern.compile("([1-9][0-9]{0,6}(?:\\.[0-9]{1,2})?) ?");
    private static final Pattern TIME=Pattern.compile("(?:[01][0-9]|2[0-3]):[0-5][0-9]");
    private static final Set<String> DATE_IDS=immutable("日期","前一天日期","当天日期","后一天日期");
    private static final Set<String> DATE_CONTROLS=immutable("星期, 日期, 最低价","前一天时间","当天时间","后一天时间");
    private NativeCtripFlightPage() {}

    static boolean supported(NativeAppGoal goal){return goal!=null&&NativeAppGoal.FLIGHT_RESULTS.equals(goal.kind)
            &&PACKAGE.equals(goal.packageName)&&"北京".equals(goal.fromCity)&&"上海".equals(goal.toCity)
            &&goal.adults==1&&goal.children==0&&goal.infants==0;}

    static final class Form {
        final NativeAppEvidence.Node from,to,date,adults,children,infants,query,trip,economy;
        final int month,day;
        final String suffix,scopePath;
        private Form(NativeAppEvidence.Node from,NativeAppEvidence.Node to,NativeAppEvidence.Node date,
                NativeAppEvidence.Node adults,NativeAppEvidence.Node children,NativeAppEvidence.Node infants,
                NativeAppEvidence.Node query,NativeAppEvidence.Node trip,NativeAppEvidence.Node economy,int month,int day,String suffix,String scope){
            this.from=from;this.to=to;this.date=date;this.adults=adults;this.children=children;this.infants=infants;
            this.query=query;this.trip=trip;this.economy=economy;this.month=month;this.day=day;this.suffix=suffix;scopePath=scope;
        }
        LocalDate relativeDate(LocalDate actualTaskLocalDate){
            if(actualTaskLocalDate==null)return null;
            int offset="今天".equals(suffix)?0:"明天".equals(suffix)?1:"后天".equals(suffix)?2:-1;
            if(offset<0)return null;LocalDate d=actualTaskLocalDate.plusDays(offset);
            return d.getMonthValue()==month&&d.getDayOfMonth()==day?d:null;
        }
        boolean matches(LocalDate date){return date!=null&&date.getMonthValue()==month&&date.getDayOfMonth()==day;}
        Map<String,Object> evidence(){Map<String,Object> o=NativeAppEvidence.map();o.put("schema","hepta.ctrip-native-form.v1");o.put("same_form_path",scopePath);
            o.put("from",from.fact("text"));o.put("to",to.fact("text"));o.put("departure_date",date.fact("text"));
            o.put("trip_type",trip.fact("description"));o.put("cabin",economy.fact("description"));
            o.put("adults",adults.fact("text"));o.put("children",children.fact("text"));o.put("infants",infants.fact("text"));
            o.put("query_control",query.fact("text"));o.put("year_observed_in_form",false);o.put("year_must_be_proved_by_task_clock_or_observed_calendar_and_action_chain",true);return o;}
    }

    static final class DateCell {
        final NativeAppEvidence.Node control,date;
        final int month,day;
        final boolean fullMonthDay;
        private DateCell(NativeAppEvidence.Node control,NativeAppEvidence.Node date,int month,int day,boolean full){this.control=control;this.date=date;this.month=month;this.day=day;fullMonthDay=full;}
        Map<String,Object> evidence(){Map<String,Object> o=NativeAppEvidence.map();o.put("control",control.fact("description"));o.put("date",date.fact("text"));
            o.put("full_month_day_format",fullMonthDay);o.put("android_selected_claimed",false);o.put("relative_role_name_used_as_selected",false);return o;}
    }

    static final class Quote {
        final String flightNumber,departureTime,arrivalTime,departureAirport,arrivalAirport,carrier,cabin,amountDecimal,currency;
        final String observationId,frameSourceSha,wrapperPath,headerPath,fingerprint,semanticFingerprint;
        final List<String> displayTags;
        private final Map<String,Object> fields;
        private Quote(NativeAppEvidence.Frame frame,String number,NativeAppEvidence.Node wrapper,NativeAppEvidence.Node header,
                NativeAppEvidence.Node depart,NativeAppEvidence.Node arrive,NativeAppEvidence.Node depAirport,NativeAppEvidence.Node arrAirport,
                NativeAppEvidence.Node carrier,NativeAppEvidence.Node cabin,NativeAppEvidence.Node price,NativeAppEvidence.Node currency,List<NativeAppEvidence.Node> tags){
            flightNumber=number;departureTime=depart.text;arrivalTime=arrive.text;departureAirport=depAirport.text;arrivalAirport=arrAirport.text;
            this.carrier=carrier.text;this.cabin=cabin.text;Matcher match=AMOUNT.matcher(price.text);need(match.matches(),"exact displayed amount");
            amountDecimal=new BigDecimal(match.group(1)).stripTrailingZeros().toPlainString();this.currency="CNY";
            observationId=frame.observationId;frameSourceSha=frame.sourceRecordSha;wrapperPath=wrapper.path;headerPath=header.path;
            List<String> texts=new ArrayList<String>();for(NativeAppEvidence.Node n:tags)texts.add(n.text);displayTags=Collections.unmodifiableList(texts);
            Map<String,Object> f=NativeAppEvidence.map();f.put("card_wrapper",wrapper.fact("description"));f.put("card_header",header.fact("description"));
            f.put("departure_time",depart.fact("text"));f.put("arrival_time",arrive.fact("text"));f.put("departure_airport",depAirport.fact("text"));f.put("arrival_airport",arrAirport.fact("text"));
            f.put("carrier",carrier.fact("text"));f.put("cabin",cabin.fact("text"));f.put("amount",price.fact("text"));f.put("currency",currency.fact("text"));
            List<Map<String,Object>> tagEvidence=new ArrayList<Map<String,Object>>();for(NativeAppEvidence.Node n:tags)tagEvidence.add(n.fact("text"));f.put("display_tags",tagEvidence);
            fields=NativeAppEvidence.immutableMap(f);fingerprint=NativeAppEvidence.fingerprint(f);semanticFingerprint=NativeAppEvidence.fingerprint(modelView());
        }
        Map<String,Object> modelView(){Map<String,Object> o=NativeAppEvidence.map();o.put("flight_number",flightNumber);o.put("departure_time",departureTime);o.put("arrival_time",arrivalTime);
            o.put("departure_airport",departureAirport);o.put("arrival_airport",arrivalAirport);o.put("carrier_label",carrier);o.put("cabin_label",cabin);
            o.put("currency",currency);o.put("displayed_amount_decimal",amountDecimal);o.put("display_tags",displayTags);
            o.put("quote_kind","current_displayed_native_economy_card");o.put("tax_and_fee_status","not_stated_in_observed_card");
            o.put("operating_carrier_inferred",false);o.put("availability_or_checkout_price_verified",false);o.put("lowest_of_all_flights_claimed",false);return o;}
        Map<String,Object> evidence(){Map<String,Object> o=modelView();o.put("schema","hepta.ctrip-native-flight-card.v1");o.put("observation_id",observationId);
            o.put("phone_observation_record_sha256",frameSourceSha);o.put("wrapper_path",wrapperPath);o.put("header_path",headerPath);o.put("fields",fields);o.put("field_fingerprint_sha256",fingerprint);
            o.put("same_frame_and_same_card",true);o.put("query_or_task_completion_proved_by_card",false);return o;}
    }

    static final class Page {
        final NativeAppEvidence.Frame frame;
        final String phase,missing;
        final Form form;
        final NativeAppEvidence.Node homeFlight,fromHeader,toHeader,resultRoot;
        final List<DateCell> dates;
        final List<Quote> quotes;
        final List<Map<String,Object>> rejectedCards,calendarMonths;
        final boolean calendarStickyHeaderPairVerified;
        private Page(NativeAppEvidence.Frame frame,String phase,String missing,Form form,NativeAppEvidence.Node home,
                NativeAppEvidence.Node from,NativeAppEvidence.Node to,NativeAppEvidence.Node root,List<DateCell> dates,List<Quote> quotes,
                List<Map<String,Object>> rejected,List<Map<String,Object>> months){
            this(frame,phase,missing,form,home,from,to,root,dates,quotes,rejected,months,false);
        }
        private Page(NativeAppEvidence.Frame frame,String phase,String missing,Form form,NativeAppEvidence.Node home,
                NativeAppEvidence.Node from,NativeAppEvidence.Node to,NativeAppEvidence.Node root,List<DateCell> dates,List<Quote> quotes,
                List<Map<String,Object>> rejected,List<Map<String,Object>> months,boolean stickyHeaderPairVerified){
            this.frame=frame;this.phase=phase;this.missing=missing;this.form=form;homeFlight=home;fromHeader=from;toHeader=to;resultRoot=root;
            calendarStickyHeaderPairVerified=stickyHeaderPairVerified;
            this.dates=Collections.unmodifiableList(new ArrayList<DateCell>(dates));this.quotes=Collections.unmodifiableList(new ArrayList<Quote>(quotes));
            rejectedCards=Collections.unmodifiableList(new ArrayList<Map<String,Object>>(rejected));calendarMonths=Collections.unmodifiableList(new ArrayList<Map<String,Object>>(months));
        }
        boolean calendarYearHeadersAdmitted(){return CALENDAR.equals(phase)&&!calendarMonths.isEmpty()
                &&(calendarMonths.size()<=3||(calendarStickyHeaderPairVerified&&calendarMonths.size()==4));}
        Map<String,Object> evidence(){Map<String,Object> o=NativeAppEvidence.map();o.put("schema","hepta.ctrip-native-page.v1");o.put("phase",phase);o.put("missing",missing);o.put("frame",frame.evidence());
            o.put("provider_version_code",VERSION_CODE);o.put("package",PACKAGE);o.put("supported_route_scope","Beijing_to_Shanghai_single_adult");
            if(form!=null)o.put("form",form.evidence());if(homeFlight!=null)o.put("home_flight_control",homeFlight.fact("description"));
            if(fromHeader!=null)o.put("from_header",fromHeader.fact("text"));if(toHeader!=null)o.put("to_header",toHeader.fact("text"));
            List<Map<String,Object>> dateFacts=new ArrayList<Map<String,Object>>();for(DateCell c:dates)dateFacts.add(c.evidence());o.put("date_strip",dateFacts);
            List<Map<String,Object>> quoteFacts=new ArrayList<Map<String,Object>>();for(Quote q:quotes)quoteFacts.add(q.evidence());o.put("displayed_cards",quoteFacts);o.put("rejected_cards",rejectedCards);o.put("calendar_months",calendarMonths);
            if(calendarStickyHeaderPairVerified)o.put("calendar_header_resolution","one_same_month_sticky_and_content_pair_with_consecutive_visible_months");
            o.put("query_executed_by_this_page",false);o.put("business_verified",false);o.put("grants_tool_authority",false);return o;}
        /** Infer a bounded calendar continuation from an already proved query
         * date. Role strings such as 当天 are intentionally not used as selection.
         * Task completion additionally requires a target-date query form/action.
         */
        Map<String,LocalDate> resolvedDates(LocalDate provedQueryDate){
            if(!RESULTS.equals(phase)||provedQueryDate==null||dates.size()<3)return Collections.emptyMap();
            int selected=-1;for(int i=0;i<dates.size();i++)if(dates.get(i).fullMonthDay){if(selected>=0)return Collections.emptyMap();selected=i;}
            if(selected<0)return Collections.emptyMap();DateCell full=dates.get(selected);LocalDate selectedDate=null;
            for(int year=provedQueryDate.getYear()-1;year<=provedQueryDate.getYear()+1;year++)try{
                LocalDate d=LocalDate.of(year,full.month,full.day);
                if(Math.abs(java.time.temporal.ChronoUnit.DAYS.between(provedQueryDate,d))<=14){if(selectedDate!=null)return Collections.emptyMap();selectedDate=d;}
            }catch(DateTimeException ignored){/* no date from this year */}
            if(selectedDate==null)return Collections.emptyMap();Map<String,LocalDate> result=new LinkedHashMap<String,LocalDate>();
            for(int i=0;i<dates.size();i++){DateCell cell=dates.get(i);LocalDate d=selectedDate.plusDays(i-selected);
                if(d.getDayOfMonth()!=cell.day||(cell.fullMonthDay&&d.getMonthValue()!=cell.month))return Collections.emptyMap();
                result.put(cell.control.id,d);}
            return Collections.unmodifiableMap(result);
        }
        LocalDate displayedMonthDay(LocalDate provedQueryDate){Map<String,LocalDate> resolved=resolvedDates(provedQueryDate);
            for(DateCell d:dates)if(d.fullMonthDay)return resolved.get(d.control.id);return null;}
    }

    static Page inspect(NativeAppGoal goal,NativeAppEvidence.Frame frame){
        need(frame!=null,"actual frame required");
        if(!supported(goal))return empty(frame,UNAVAILABLE,"native_provider_not_admitted_for_goal");
        if(!goal.ownerSha256.equals(frame.ownerSha))return empty(frame,UNAVAILABLE,"native_frame_owner_differs");
        if(!PACKAGE.equals(frame.packageName))return empty(frame,UNAVAILABLE,"foreign_app_window");
        if(!frame.metadataObserved||frame.windowType!=1)return empty(frame,UNAVAILABLE,"actual_application_window_metadata_missing");
        if(!frame.collectionComplete||frame.nodesTruncated)return empty(frame,UNAVAILABLE,"actual_native_collection_incomplete");
        try{
            // This sheet leaves the underlying native flight tree exposed. Its
            // mere presence vetoes every quote in that same observation.
            if(anyRole(frame,"列表页头部重新搜索")||anyRole(frame,"单程TripSwitcherCity")||anyRole(frame,"单程TripSwitcherDate"))
                return empty(frame,OVERLAY,"research_sheet_covers_underlying_flights");
            List<NativeAppEvidence.Node> query=findId(frame,PREFIX+"bt_submit_inquire");
            if(!query.isEmpty())return form(goal,frame);
            if(anyRole(frame,"单程列表页"))return results(goal,frame);
            List<NativeAppEvidence.Node> months=findId(frame,PREFIX+"calendar_month_title_left_tv");
            if(!months.isEmpty()){
                if(repeatedMonthText(months)||(months.size()>3&&hasStickyMonthPath(frame,months)))
                    return stickyCalendar(frame,months);
                List<Map<String,Object>> values=new ArrayList<Map<String,Object>>();Set<String> distinct=new TreeSet<String>();
                for(NativeAppEvidence.Node n:months){Matcher m=MONTH.matcher(n.text);need(m.matches()&&distinct.add(n.text),"unambiguous actual month headers required");
                    LocalDate.of(Integer.parseInt(m.group(1)),Integer.parseInt(m.group(2)),1);Map<String,Object> x=n.fact("text");x.put("year",Integer.valueOf(m.group(1)));x.put("month",Integer.valueOf(m.group(2)));values.add(x);}
                return new Page(frame,CALENDAR,"day_cells_not_exposed_by_native_provider",null,null,null,null,null,Collections.<DateCell>emptyList(),Collections.<Quote>emptyList(),Collections.<Map<String,Object>>emptyList(),values);
            }
            List<NativeAppEvidence.Node> tiles=findId(frame,PREFIX+"home_grid_flight_widget");
            if(tiles.size()==1){NativeAppEvidence.Node tile=tiles.get(0);
                if(tile.label.isEmpty())need(resourceHomeClick(frame,tile.id),"exact installed-provider home resource control required");
                else{
                    need(clickable(frame,tile),"actual home flight control required");
                    List<NativeAppEvidence.Node> labels=findText(frame,"机票");int matched=0;for(NativeAppEvidence.Node n:labels)if(n.within(tile))matched++;
                    need(matched==1,"unique same-tile flight label required");
                }
                return new Page(frame,HOME,null,null,tile,null,null,null,Collections.<DateCell>emptyList(),Collections.<Quote>emptyList(),Collections.<Map<String,Object>>emptyList(),Collections.<Map<String,Object>>emptyList());}
            return empty(frame,UNAVAILABLE,"native_page_provider_not_recognized");
        }catch(IllegalArgumentException rejected){return empty(frame,UNAVAILABLE,"native_page_fields_rejected: "+bounded(rejected.getMessage(),180));}
        catch(DateTimeException rejected){return empty(frame,UNAVAILABLE,"native_calendar_value_rejected: "+bounded(rejected.getMessage(),180));}
    }

    /** Resolve only the observed v1779 sticky/content duplication. All original
     * header facts survive; no calendar day or coordinate capability is made.
     * Unique legacy headers retain their existing path and <=3 year-proof gate.
     */
    private static boolean repeatedMonthText(List<NativeAppEvidence.Node> months){
        Set<String> text=new TreeSet<String>();for(NativeAppEvidence.Node n:months)if(!text.add(n.text))return true;return false;
    }
    private static boolean hasStickyMonthPath(NativeAppEvidence.Frame frame,List<NativeAppEvidence.Node> months){
        List<NativeAppEvidence.Node> lists=findId(frame,PREFIX+"calendar_list");
        if(lists.size()!=1||lists.get(0).path==null||lists.get(0).path.lastIndexOf('/')<0)return false;
        String path=parent(lists.get(0).path)+"/1/0/0";
        for(NativeAppEvidence.Node n:months)if(path.equals(n.path))return true;return false;
    }
    private static LocalDate monthValue(NativeAppEvidence.Node n){
        Matcher m=MONTH.matcher(n.text);need(m.matches(),"literal complete calendar month required");
        return LocalDate.of(Integer.parseInt(m.group(1)),Integer.parseInt(m.group(2)),1);
    }
    private static Page stickyCalendar(NativeAppEvidence.Frame frame,List<NativeAppEvidence.Node> months){
        need(months.size()>=3&&months.size()<=5,"bounded sticky calendar month graph required");
        int allHeaders=0;for(NativeAppEvidence.Node n:frame.nodes)if((PREFIX+"calendar_month_title_left_tv").equals(n.viewId))allHeaders++;
        need(allHeaders==months.size(),"no unusable or foreign calendar header may be ignored");
        NativeAppEvidence.Node list=oneId(frame,PREFIX+"calendar_list");
        need("android.widget.ListView".equals(list.className)&&"android.widget.FrameLayout".equals(list.parentClass)
                &&list.enabled&&list.scrollable&&!list.editable&&!list.password&&list.path.endsWith("/0"),"actual enabled calendar list required");
        String stickyPath=parent(list.path)+"/1/0/0";
        List<NativeAppEvidence.Node> content=new ArrayList<NativeAppEvidence.Node>();NativeAppEvidence.Node sticky=null;
        for(NativeAppEvidence.Node n:months){
            need("android.widget.TextView".equals(n.className)&&"android.widget.LinearLayout".equals(n.parentClass)
                    &&n.enabled&&!n.password&&!n.editable&&!n.clickable&&!n.scrollable&&n.description.isEmpty(),"actual plain month title required");
            monthValue(n);
            if(stickyPath.equals(n.path)){need(sticky==null,"one sticky month title required");sticky=n;}
            else{
                need(n.within(list)&&n.path.substring(list.path.length()+1).matches("(?:0|[1-9][0-9]{0,5})/0/0"),"month title must belong to the same list content row");
                content.add(n);
            }
        }
        need(sticky!=null&&content.size()>=2&&content.size()<=4,"one sticky title and bounded complete content month sequence required");
        Collections.sort(content,new Comparator<NativeAppEvidence.Node>(){public int compare(NativeAppEvidence.Node a,NativeAppEvidence.Node b){return Integer.compare(a.top,b.top);}});
        NativeAppEvidence.Node first=content.get(0);
        need(first.path.equals(list.path+"/0/0/0")&&first.text.equals(sticky.text)
                &&first.left==sticky.left&&first.right==sticky.right&&first.top==list.top
                &&first.bottom<=sticky.top&&first.bottom-first.top<sticky.bottom-sticky.top
                &&sticky.left>=list.left&&sticky.right<=list.right&&sticky.top>=list.top&&sticky.bottom<=list.bottom
                &&sticky.bottom<content.get(1).top,"same clipped first month and sibling sticky title geometry required");
        LocalDate previous=null;NativeAppEvidence.Node previousNode=null;int previousIndex=-1;
        List<Map<String,Object>> values=new ArrayList<Map<String,Object>>();
        for(NativeAppEvidence.Node n:content){
            LocalDate month=monthValue(n);String row=n.path.substring(list.path.length()+1);int index=Integer.parseInt(row.substring(0,row.indexOf('/')));
            if(previous!=null)need(previous.plusMonths(1).equals(month)&&previousNode.bottom<n.top&&index>previousIndex,"consecutive ordered content month headers required");
            Map<String,Object> x=n.fact("text");x.put("year",month.getYear());x.put("month",month.getMonthValue());
            if(n==first){Map<String,Object> pair=NativeAppEvidence.map();pair.put("schema","hepta.ctrip-sticky-month-pair.v1");
                pair.put("content_header",first.fact("text"));pair.put("sticky_header",sticky.fact("text"));pair.put("calendar_list",list.fact("description"));
                pair.put("same_literal_month",true);pair.put("same_observation",true);pair.put("day_cells_or_selected_date_inferred",false);
                x.put("sticky_header_pair",NativeAppEvidence.immutableMap(pair));}
            values.add(x);previous=month;previousNode=n;previousIndex=index;
        }
        return new Page(frame,CALENDAR,"day_cells_not_exposed_by_native_provider",null,null,null,null,null,
                Collections.<DateCell>emptyList(),Collections.<Quote>emptyList(),Collections.<Map<String,Object>>emptyList(),values,true);
    }

    private static Page form(NativeAppGoal goal,NativeAppEvidence.Frame frame){
        NativeAppEvidence.Node from=oneId(frame,PREFIX+"tv_depart_city"),to=oneId(frame,PREFIX+"tv_arrival_city"),date=oneId(frame,PREFIX+"tv_depart_date");
        NativeAppEvidence.Node adults=oneId(frame,PREFIX+"tv_adult_count"),children=oneId(frame,PREFIX+"tv_child_count"),infants=oneId(frame,PREFIX+"tv_baby_count"),query=oneId(frame,PREFIX+"bt_submit_inquire");
        need(goal.fromCity.equals(from.text)&&goal.toCity.equals(to.text)&&"1成人".equals(adults.text)&&"0儿童".equals(children.text)&&"0婴儿".equals(infants.text),"observed route/passengers differ from immutable goal");
        need("查 询".equals(query.text)&&clickable(frame,query),"actual normal query button required");
        need(clickable(frame,date),"actual departure date control required");
        String scope=parent(parent(query.path));for(NativeAppEvidence.Node n:java.util.Arrays.asList(from,to,date,adults,children,infants))need(n.path.startsWith(scope+"/"),"query input lies outside same native form");
        NativeAppEvidence.Node trip=oneDescription(frame,"单程","android.widget.LinearLayout"),round=oneDescription(frame,"往返","android.widget.LinearLayout"),multi=oneDescription(frame,"多程","android.widget.LinearLayout");
        need(Boolean.TRUE.equals(trip.selected)&&Boolean.FALSE.equals(round.selected)&&Boolean.FALSE.equals(multi.selected)
                &&parent(trip.path).equals(parent(round.path))&&parent(trip.path).equals(parent(multi.path))
                &&trip.path.startsWith(parent(scope)+"/"),"actual single-trip selection required");
        NativeAppEvidence.Node economy=oneDescription(frame,"经济舱","android.widget.LinearLayout");need(Boolean.TRUE.equals(economy.selected)&&economy.path.startsWith(scope+"/"),"actual economy choice required");
        Matcher m=FORM_DATE.matcher(date.text);need(m.matches(),"literal visible form departure date required");
        int month=Integer.parseInt(m.group(1)),day=Integer.parseInt(m.group(2));LocalDate.of(2000,month,day);
        Form f=new Form(from,to,date,adults,children,infants,query,trip,economy,month,day,m.group(3),scope);
        return new Page(frame,FORM,null,f,null,null,null,null,Collections.<DateCell>emptyList(),Collections.<Quote>emptyList(),Collections.<Map<String,Object>>emptyList(),Collections.<Map<String,Object>>emptyList());
    }

    private static Page results(NativeAppGoal goal,NativeAppEvidence.Frame frame){
        NativeAppEvidence.Node root=oneRole(frame,"单程列表页");
        NativeAppEvidence.Node from=oneRole(frame,"列表页头部出发城市"),to=oneRole(frame,"列表页头部到达城市");
        need(from.within(root)&&to.within(root)&&goal.fromCity.equals(from.text)&&goal.toCity.equals(to.text),"actual result header route required");
        List<DateCell> dates=dateCells(frame,root);
        List<Quote> quotes=new ArrayList<Quote>();List<Map<String,Object>> rejected=new ArrayList<Map<String,Object>>();
        for(NativeAppEvidence.Node header:frame.nodes){Matcher c=CARD.matcher(header.description);
            if(!c.matches()||!header.description.equals(header.viewId)||!header.within(root))continue;
            String number=c.group(1);try{Quote quote=quote(frame,root,header,number);need(quotes.size()<8,"visible card bound exceeded");quotes.add(quote);}
            catch(IllegalArgumentException invalid){Map<String,Object> x=NativeAppEvidence.map();x.put("header",header.fact("description"));x.put("flight_number",number);x.put("reason",bounded(invalid.getMessage(),180));rejected.add(x);}
        }
        return new Page(frame,RESULTS,quotes.isEmpty()?"no_complete_admitted_economy_card":null,null,null,from,to,root,dates,quotes,rejected,Collections.<Map<String,Object>>emptyList());
    }

    private static List<DateCell> dateCells(NativeAppEvidence.Frame frame,NativeAppEvidence.Node root){
        List<DateCell> result=new ArrayList<DateCell>();Set<String> controls=new TreeSet<String>();String commonParent=null;int full=0;
        for(NativeAppEvidence.Node leaf:frame.nodes){
            if(!DATE_IDS.contains(leaf.viewId)||!leaf.viewId.equals(leaf.description)||!leaf.within(root))continue;
            NativeAppEvidence.Node control=null;
            for(NativeAppEvidence.Node n:frame.nodes)if(DATE_CONTROLS.contains(n.description)&&clickable(frame,n)&&leaf.within(n)){
                if(control==null||n.path.length()>control.path.length())control=n;
            }
            need(control!=null&&controls.add(control.id),"unique actual date control ancestor required");
            String parent=parent(control.path);if(commonParent==null)commonParent=parent;else need(commonParent.equals(parent),"date cells span different native strips");
            int month=0,day;boolean isFull=leaf.text.matches("[0-9]{2}-[0-9]{2}");
            if(isFull){month=Integer.parseInt(leaf.text.substring(0,2));day=Integer.parseInt(leaf.text.substring(3));LocalDate.of(2000,month,day);full++;}
            else{need(leaf.text.matches("[1-9]|[12][0-9]|3[01]"),"literal calendar day required");day=Integer.parseInt(leaf.text);}
            result.add(new DateCell(control,leaf,month,day,isFull));
        }
        need(result.size()>=3&&result.size()<=8&&full==1,"exactly one visible full month/day in a bounded date strip required");
        Collections.sort(result,new Comparator<DateCell>(){public int compare(DateCell a,DateCell b){return Integer.compare(a.control.left,b.control.left);}});
        for(int i=1;i<result.size();i++)need(result.get(i-1).control.right<=result.get(i).control.left
                &&result.get(i-1).control.top==result.get(i).control.top&&result.get(i-1).control.bottom==result.get(i).control.bottom,"ordered nonoverlapping same-row date controls required");
        return result;
    }

    private static Quote quote(NativeAppEvidence.Frame frame,NativeAppEvidence.Node resultRoot,NativeAppEvidence.Node header,String number){
        need(clickable(frame,header),"actual flight header required");
        NativeAppEvidence.Node wrapper=null;
        for(NativeAppEvidence.Node n:frame.nodes)if("S_FLT_N_List_Flight_Label_Infor_Actual_Total".equals(n.viewId)&&n.viewId.equals(n.description)
                &&n.within(resultRoot)&&header.within(n)&&(wrapper==null||n.path.length()>wrapper.path.length()))wrapper=n;
        need(wrapper!=null,"complete flight wrapper, including sibling tag rows, required");
        int headers=0;for(NativeAppEvidence.Node n:frame.nodes)if(n.within(wrapper)&&CARD.matcher(n.description).matches()&&n.viewId.equals(n.description))headers++;
        need(headers==1,"same wrapper must contain one flight header");
        String role="第"+number+"航班";
        NativeAppEvidence.Node depart=oneCard(frame,header,role+"出发时间"),arrive=oneCard(frame,header,role+"到达时间");
        NativeAppEvidence.Node depAirport=oneCard(frame,header,role+"出发机场+航站楼"),arrAirport=oneCard(frame,header,role+"到达机场+航站楼");
        NativeAppEvidence.Node carrier=oneCard(frame,header,role+"航司信息"),cabin=oneCard(frame,header,role+"舱等信息"),price=oneCard(frame,header,role+"价格");
        need(TIME.matcher(depart.text).matches()&&TIME.matcher(arrive.text).matches(),"complete displayed flight times required");
        need(depAirport.text.matches("(?:大兴|首都)(?:T[1-9])?")&&arrAirport.text.matches("(?:浦东|虹桥)(?:T[1-9])?"),"airport labels must correspond to this admitted route");
        need(carrier.text.matches("[\\p{IsHan}]{2,8} "+number)&&cabin.text.matches("经济舱(?:[1-9](?:\\.[0-9])?折)?"),"same flight carrier and explicit economy label required");
        need(AMOUNT.matcher(price.text).matches(),"exact displayed price field required");
        NativeAppEvidence.Node currency=null;for(NativeAppEvidence.Node n:frame.nodes)if(n.within(header)&&parent(n.path).equals(parent(price.path))&&"¥".equals(n.text)){
            need(currency==null,"ambiguous same-price currency");currency=n;}
        need(currency!=null,"same price block RMB symbol required");
        List<NativeAppEvidence.Node> tags=new ArrayList<NativeAppEvidence.Node>();
        for(NativeAppEvidence.Node n:frame.nodes)if(n.within(wrapper)){
            need(!n.text.contains("…")&&!n.description.contains("…"),"truncated flight wrapper text");
            if(n.viewId.startsWith(role+"价格标签")||n.description.startsWith(role+"价格标签"))need(n.text.isEmpty(),"restricted promotional card is not an ordinary adult quote");
            need(!n.text.matches(".*(?:新会员|新客|周岁|学生|家庭出行|亲子|儿童专享|婴儿专享|领券|券后|补贴后).*"),"card includes an unadmitted eligibility or coupon condition");
            if(!n.text.isEmpty()&&n.description.startsWith(role+"未展开的"))tags.add(n);
            if(n.description.startsWith(role)&&n.text.matches(".*(?:次日|后天|跨天|中转|经停).*"))throw new IllegalArgumentException("unimplemented date-offset or connection fields");
        }
        return new Quote(frame,number,wrapper,header,depart,arrive,depAirport,arrAirport,carrier,cabin,price,currency,tags);
    }

    /** A version-bound native adapter capability, never an inferred AX label.
     * NativeAppSession separately verifies the complete installed APK identity
     * before every observation and action. This narrow branch describes the
     * actual v1779 cold-home grid whose five image tiles expose no AX text.
     * The model must still select the exact current node with node_label="".
     */
    static boolean resourceHomeClick(NativeAppEvidence.Frame frame,String nodeId){
        try{
            need(frame!=null&&PACKAGE.equals(frame.packageName)&&frame.metadataObserved&&frame.windowType==1
                    &&frame.collectionComplete&&!frame.nodesTruncated,"complete native application frame required");
            need(!anyRole(frame,"列表页头部重新搜索")&&!anyRole(frame,"单程TripSwitcherCity")
                    &&!anyRole(frame,"单程TripSwitcherDate")&&!anyRole(frame,"单程列表页")
                    &&findId(frame,PREFIX+"bt_submit_inquire").isEmpty()
                    &&findId(frame,PREFIX+"calendar_month_title_left_tv").isEmpty(),"home-only resource capability required");
            NativeAppEvidence.Node tile=oneId(frame,PREFIX+"home_grid_flight_widget");
            need(tile.id.equals(nodeId)&&tile==frame.byId.get(nodeId)&&tile.label.isEmpty()
                    &&tile.text.isEmpty()&&tile.description.isEmpty(),"same actual empty-label flight node required");
            String pagerPath=parent(tile.path);NativeAppEvidence.Node pager=null;
            for(NativeAppEvidence.Node n:frame.nodes)if(pagerPath.equals(n.path)){
                need(pager==null,"one actual parent pager required");pager=n;
            }
            need(frame.usable(pager)&&"androidx.viewpager.widget.ViewPager".equals(pager.className)
                    &&"android.widget.FrameLayout".equals(pager.parentClass)&&pager.enabled&&!pager.password
                    &&pager.scrollable&&!pager.editable,"actual home pager required");
            String[] ids={"home_grid_hotel_widget","home_grid_flight_widget","home_grid_train_widget","home_grid_travel_widget","home_grid_strategy_widget"};
            NativeAppEvidence.Node previous=null;
            for(int i=0;i<ids.length;i++){
                NativeAppEvidence.Node n=oneId(frame,PREFIX+ids[i]);
                need(n.within(pager)&&n.path.equals(pager.path+"/"+i)&&"android.view.ViewGroup".equals(n.className)
                        &&pager.className.equals(n.parentClass)&&n.enabled&&n.clickable&&!n.editable&&!n.scrollable&&!n.password
                        &&Boolean.FALSE.equals(n.selected)&&Boolean.FALSE.equals(n.checkable)&&Boolean.FALSE.equals(n.checked),
                        "same actual enabled image-tile row required");
                if(previous!=null)need(previous.right<=n.left&&previous.top==n.top&&previous.bottom==n.bottom,
                        "ordered nonoverlapping same-row home anchors required");
                previous=n;
            }
            return true;
        }catch(IllegalArgumentException rejected){return false;}
    }

    private static NativeAppEvidence.Node oneCard(NativeAppEvidence.Frame frame,NativeAppEvidence.Node header,String role){
        List<NativeAppEvidence.Node> values=new ArrayList<NativeAppEvidence.Node>();
        for(NativeAppEvidence.Node n:frame.nodes)if(role.equals(n.viewId)&&role.equals(n.description)&&n.within(header)&&frame.usable(n))values.add(n);
        need(values.size()==1,"unique same-header field required: "+role);return values.get(0);
    }
    private static List<NativeAppEvidence.Node> findId(NativeAppEvidence.Frame f,String id){List<NativeAppEvidence.Node> r=new ArrayList<NativeAppEvidence.Node>();for(NativeAppEvidence.Node n:f.nodes)if(id.equals(n.viewId)&&f.usable(n))r.add(n);return r;}
    private static List<NativeAppEvidence.Node> findText(NativeAppEvidence.Frame f,String text){List<NativeAppEvidence.Node> r=new ArrayList<NativeAppEvidence.Node>();for(NativeAppEvidence.Node n:f.nodes)if(text.equals(n.text)&&f.usable(n))r.add(n);return r;}
    private static NativeAppEvidence.Node oneId(NativeAppEvidence.Frame f,String id){List<NativeAppEvidence.Node> r=findId(f,id);need(r.size()==1,"unique actual id required: "+id);return r.get(0);}
    private static boolean anyRole(NativeAppEvidence.Frame f,String role){for(NativeAppEvidence.Node n:f.nodes)if(role.equals(n.viewId)&&role.equals(n.description)&&f.usable(n))return true;return false;}
    private static NativeAppEvidence.Node oneRole(NativeAppEvidence.Frame f,String role){NativeAppEvidence.Node v=oneId(f,role);need(role.equals(v.description),"native role description/id mismatch");return v;}
    private static NativeAppEvidence.Node oneDescription(NativeAppEvidence.Frame f,String text,String cls){List<NativeAppEvidence.Node> r=new ArrayList<NativeAppEvidence.Node>();for(NativeAppEvidence.Node n:f.nodes)if(text.equals(n.description)&&cls.equals(n.className)&&f.usable(n))r.add(n);need(r.size()==1,"unique selected control required: "+text);return r.get(0);}
    private static boolean clickable(NativeAppEvidence.Frame f,NativeAppEvidence.Node n){return f.usable(n)&&n.enabled&&n.clickable&&!n.password&&!n.label.isEmpty();}
    private static Page empty(NativeAppEvidence.Frame f,String phase,String missing){return new Page(f,phase,missing,null,null,null,null,null,Collections.<DateCell>emptyList(),Collections.<Quote>emptyList(),Collections.<Map<String,Object>>emptyList(),Collections.<Map<String,Object>>emptyList());}
    private static String parent(String path){need(path!=null&&path.lastIndexOf('/')>=0,"actual native ancestor missing");return path.substring(0,path.lastIndexOf('/'));}
    private static String bounded(String s,int max){return s==null?"unknown":s.length()<=max?s:s.substring(0,max);}
    private static Set<String> immutable(String... values){return Collections.unmodifiableSet(new TreeSet<String>(java.util.Arrays.asList(values)));}
    private static void need(boolean yes,String why){NativeAppEvidence.need(yes,why);}
}
