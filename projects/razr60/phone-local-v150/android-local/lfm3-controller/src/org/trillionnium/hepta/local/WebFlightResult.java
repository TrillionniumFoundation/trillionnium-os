package org.trillionnium.hepta.local;

import java.math.BigDecimal;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Binding and lifetime of one observed public flight result. This class does
 * not parse a website, establish DOM/AX field provenance, or grant an action.
 * A compiled provider must produce Page only after its actual DOM/native checks.
 * No JSON/model-output constructor or provider fallback is supplied here.
 */
final class WebFlightResult {
    static final String SCHEMA="hepta.csair-displayed-flight-result.v1";
    static final String FLIGHTS="displayed_flights",NONE="no_flights_displayed";
    private final Query query;
    private final Page page;
    private final Object publication;
    private final Map<String,Object> record;

    /** Shared by every immutable progression snapshot of one live helper lease. */
    static final class Lifetime {
        private boolean active=true;
        private Query query;
        synchronized boolean active(){return active;}
        synchronized void retire(){active=false;if(query!=null){query.publication=null;query.verifiedLatest=null;}}
        synchronized void activate(Query actual){
            need(active&&query==null,"one accepted native query per original lease");query=actual;
        }
    }

    static final class Scope {
        final String task,owner,contract,authorization,binding,generation,instance;
        final int display,window;
        Scope(String task,String owner,String contract,String authorization,String binding,
              String generation,String instance,int display,int window){
            need(id(task)&&hex(owner)&&hex(contract)&&hex(authorization)&&hex(binding),"complete task/owner/authority binding");
            need(generation!=null&&generation.matches("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
                    &&text(instance,128)&&display>0&&window>=0,"complete background/helper window binding");
            this.task=task;this.owner=owner;this.contract=contract;this.authorization=authorization;
            this.binding=binding;this.generation=generation;this.instance=instance;this.display=display;this.window=window;
        }
        boolean same(Scope value){
            return value!=null&&task.equals(value.task)&&owner.equals(value.owner)&&contract.equals(value.contract)
                    &&authorization.equals(value.authorization)&&binding.equals(value.binding)
                    &&generation.equals(value.generation)&&instance.equals(value.instance)
                    &&display==value.display&&window==value.window;
        }
    }

    static final class Frame {
        final Scope scope;
        final String observation,state,dom,url;
        final long epoch,start,end;
        Frame(Scope scope,String observation,String state,String dom,String url,long epoch,long start,long end){
            need(scope!=null&&id(observation)&&hex(state)&&hex(dom),"complete current native/DOM frame binding");
            need(officialUrl(url)&&epoch>=0&&start>=0&&end>=start,"actual official URL and capture clocks");
            this.scope=scope;this.observation=observation;this.state=state;this.dom=dom;this.url=url;
            this.epoch=epoch;this.start=start;this.end=end;
        }
        boolean same(Frame value){
            return sameObservation(value)&&dom.equals(value.dom)&&start==value.start&&end==value.end;
        }
        boolean sameObservation(Frame value){
            return value!=null&&scope.same(value.scope)&&observation.equals(value.observation)&&state.equals(value.state)
                    &&url.equals(value.url)&&epoch==value.epoch;
        }
    }

    /** Issued by WebFlightProgress from its reserved, accepted native outcome. */
    static final class Query {
        final Lifetime lifetime;
        final Frame before;
        final String run,node,fromCity,toCity,date,id;
        final long start,end;
        private Frame latest;
        private Frame verifiedLatest;
        private Object publication;
        private String publishedSemantics;
        private long publicationSequence;
        Query(Lifetime lifetime,Frame before,String run,String node,String fromCity,String toCity,String date,
              boolean accepted,boolean dispatched,boolean stale,boolean entered,long start,long end){
            need(lifetime!=null&&lifetime.active()&&before!=null,"live query lifetime required");
            need(id(run)&&text(node,128)&&city(fromCity)&&city(toCity)&&!fromCity.equals(toCity),"actual query identity and route");
            exactDate(date);
            need(accepted&&dispatched&&!stale&&entered&&before.end<=start&&start<=end,
                    "accepted nonstale actual native query and monotonic dispatch required");
            this.lifetime=lifetime;this.before=before;this.run=run;this.node=node;
            this.fromCity=fromCity;this.toCity=toCity;this.date=date;this.start=start;this.end=end;
            StringBuilder key=new StringBuilder("hepta.csair-query-result-binding.v1");
            for(Object value:new Object[]{before.scope.task,before.scope.owner,before.scope.contract,
                    before.scope.authorization,before.scope.binding,before.scope.generation,before.scope.instance,
                    before.scope.display,before.scope.window,before.observation,before.state,before.dom,before.url,
                    before.epoch,run,node,fromCity,toCity,date,start,end})field(key,value);
            id=sha(key.toString());
            lifetime.activate(this);
        }
        boolean active(){synchronized(lifetime){return lifetime.active&&lifetime.query==this;}}
        /** Called by progression for every actual captured native observation,
         * including fresh pre-dispatch recaptures of the same native frame.
         * An old immutable domain can keep audit data but loses publication
         * authority when the current observation/navigation is replaced. */
        void observed(Frame current){
            synchronized(lifetime){
                need(active()&&current!=null,"live result observation required");
                if(!before.scope.same(current.scope)||current.start<end||current.epoch<before.epoch
                        ||latest!=null&&(current.epoch<latest.epoch||current.start<latest.start)){
                    lifetime.retire();throw new IllegalArgumentException("flight result: observation identity or time regressed");
                }
                if(latest==null||!latest.sameObservation(current))advancePublication();
                latest=current;
                // A newly read capture is not a newly verified result. In
                // particular, unchanged AX identity cannot carry old result
                // authority across unparsed DOM changes or a failed provider.
                verifiedLatest=null;
            }
        }
        private void advancePublication(){
            need(publicationSequence<Long.MAX_VALUE,"bounded observation publication sequence");
            publication=new Object();publicationSequence++;publishedSemantics=null;
        }
    }

    /** A complete row after provider-specific DOM and native association checks.
     * Unknown tax/condition contents remain explicitly unreported, never zero. */
    static final class Row {
        final String recordPath,flightNumber,departureAirport,arrivalAirport,departureDate,departureTime,
                arrivalDate,arrivalTime,amount,currency,taxState,taxText,conditionState,conditionText;
        private final Map<String,Object> fields,proof;
        Row(String recordPath,String flightNumber,String departureAirport,String arrivalAirport,
            String departureDate,String departureTime,String arrivalDate,String arrivalTime,
            String amount,String currency,String taxState,String taxText,String conditionState,String conditionText,
            Map<String,Object> verifiedFieldProof){
            need(path(recordPath)&&flightNumber!=null&&flightNumber.matches("[A-Z0-9]{2}[0-9]{1,4}[A-Z]?"),"bounded actual flight record/number");
            need(text(departureAirport,96)&&text(arrivalAirport,96)&&!departureAirport.equals(arrivalAirport),"actual departure and arrival airports");
            LocalDate dep=exactDate(departureDate),arr=exactDate(arrivalDate);
            LocalTime dt=exactTime(departureTime),at=exactTime(arrivalTime);
            need(!arr.isBefore(dep)&&!arr.isAfter(dep.plusDays(3))
                    &&(arr.isAfter(dep)||at.isAfter(dt)),"actual ordered complete departure/arrival dates and times");
            need(amount!=null&&amount.matches("(?:0|[1-9][0-9]{0,6})(?:\\.[0-9]{1,2})?")
                    &&new BigDecimal(amount).signum()>0&&currency!=null&&currency.matches("[A-Z]{3}"),
                    "actual positive public price and explicit currency");
            condition(taxState,taxText);condition(conditionState,conditionText);
            this.recordPath=recordPath;this.flightNumber=flightNumber;this.departureAirport=departureAirport;
            this.arrivalAirport=arrivalAirport;this.departureDate=departureDate;this.departureTime=departureTime;
            this.arrivalDate=arrivalDate;this.arrivalTime=arrivalTime;this.amount=amount;this.currency=currency;
            this.taxState=taxState;this.taxText=taxText;this.conditionState=conditionState;this.conditionText=conditionText;
            need(verifiedFieldProof!=null&&!verifiedFieldProof.isEmpty(),"provider field-association proof required");
            proof=immutableMap(verifiedFieldProof);
            Map<String,Object> out=new LinkedHashMap<String,Object>();
            out.put("record_dom_path",recordPath);out.put("flight_number",flightNumber);
            out.put("departure_airport",departureAirport);out.put("arrival_airport",arrivalAirport);
            out.put("departure_date",departureDate);out.put("departure_time",departureTime);
            out.put("arrival_date",arrivalDate);out.put("arrival_time",arrivalTime);
            out.put("amount_decimal",amount);out.put("currency",currency);out.put("price_scope","displayed_public_flight_row_price");
            out.put("taxes_state",taxState);out.put("taxes_raw",taxText);
            out.put("conditions_state",conditionState);out.put("conditions_raw",conditionText);
            fields=immutableMap(out);
        }
        Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<String,Object>(fields);out.put("provider_field_proof",proof);return immutableMap(out);
        }
        Map<String,Object> modelView(){return fields;}
    }

    /** A typed provider result for one exact captured frame. Constructing this
     * carrier alone never proves that a provider read the actual website. */
    static final class Page {
        final Frame frame;
        final String provider,kind,fromCity,toCity,date,emptyMessage,semanticSha;
        final List<Row> rows;
        private final Map<String,Object> proof;
        Page(Frame frame,String provider,String kind,String fromCity,String toCity,String date,
             List<Row> rows,String emptyMessage,Map<String,Object> verifiedPageProof){
            need(frame!=null&&provider!=null&&provider.matches("[a-z0-9][a-z0-9._-]{0,95}"),"actual provider/version and frame");
            need(city(fromCity)&&city(toCity)&&!fromCity.equals(toCity),"actual displayed route");exactDate(date);
            need(rows!=null&&rows.size()<=32&&verifiedPageProof!=null&&!verifiedPageProof.isEmpty(),"bounded provider page proof");
            need(FLIGHTS.equals(kind)&&!rows.isEmpty()&&emptyMessage==null
                    ||NONE.equals(kind)&&rows.isEmpty()&&text(emptyMessage,512),"complete flight rows or explicit terminal no-flight message");
            Set<String> paths=new HashSet<String>(),records=new HashSet<String>();List<Row> copy=new ArrayList<Row>();
            for(Row row:rows){
                need(row!=null&&date.equals(row.departureDate)&&paths.add(row.recordPath)
                        &&records.add(row.flightNumber+"\n"+row.departureDate+"\n"+row.departureTime+"\n"+row.departureAirport+"\n"+row.arrivalAirport),
                        "unique same-date complete flight rows");copy.add(row);
            }
            this.frame=frame;this.provider=provider;this.kind=kind;this.fromCity=fromCity;this.toCity=toCity;
            this.date=date;this.rows=Collections.unmodifiableList(copy);this.emptyMessage=emptyMessage;
            proof=immutableMap(verifiedPageProof);
            StringBuilder key=new StringBuilder("hepta.csair-observed-result-semantics.v1");
            for(Object value:new Object[]{provider,kind,fromCity,toCity,date,emptyMessage})field(key,value);
            for(Row row:copy)for(Object value:row.fields.values())field(key,value);
            semanticSha=sha(key.toString());
        }
    }

    static WebFlightResult bind(Query actualQuery,Frame current,Page actualPage){
        need(actualQuery!=null&&actualQuery.active()&&current!=null&&actualPage!=null,"live dispatched query and parsed current page");
        synchronized(actualQuery.lifetime){
            need(actualQuery.active()&&actualQuery.publication!=null&&actualQuery.latest!=null
                    &&actualQuery.latest.same(current),"result is not for the latest actual captured frame");
            need(actualQuery.before.scope.same(current.scope)&&actualPage.frame.same(current),"result belongs to another task/lease/frame");
            need(current.start>=actualQuery.end&&current.epoch>=actualQuery.before.epoch
                    &&!current.observation.equals(actualQuery.before.observation)&&!current.dom.equals(actualQuery.before.dom),
                    "fresh changed result document captured after the actual query");
            need(actualQuery.fromCity.equals(actualPage.fromCity)&&actualQuery.toCity.equals(actualPage.toCity)
                    &&actualQuery.date.equals(actualPage.date),"actual displayed result route/date differ from original query");
            // Fresh readback of the same native observation may retain its
            // publication only when the independently parsed result is identical.
            if(actualQuery.publishedSemantics!=null&&!actualQuery.publishedSemantics.equals(actualPage.semanticSha))
                actualQuery.advancePublication();
            actualQuery.publishedSemantics=actualPage.semanticSha;
            WebFlightResult verified=new WebFlightResult(actualQuery,actualPage);
            // The combined immutable record has its own aggregate budget and
            // may reject even separately valid row/page evidence. Only its
            // successful construction can publish current result authority.
            actualQuery.verifiedLatest=current;
            return verified;
        }
    }
    private WebFlightResult(Query query,Page page){
        this.query=query;this.page=page;publication=query.publication;Frame frame=page.frame;Scope scope=frame.scope;
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("schema",SCHEMA);out.put("result_kind",page.kind);out.put("provider",page.provider);
        out.put("task_id",scope.task);out.put("owner_sha256",scope.owner);out.put("contract_sha256",scope.contract);
        out.put("authorization_sha256",scope.authorization);out.put("binding_sha256",scope.binding);
        out.put("background_generation",scope.generation);out.put("webview_instance",scope.instance);
        out.put("display_id",scope.display);out.put("window_id",scope.window);out.put("navigation_epoch",frame.epoch);
        out.put("observation_id",frame.observation);out.put("observation_state_sha256",frame.state);
        out.put("dom_sha256",frame.dom);out.put("committed_url",frame.url);
        out.put("capture_started_elapsed_ms",frame.start);out.put("capture_ended_elapsed_ms",frame.end);
        out.put("query_binding_id",query.id);out.put("query_model_run_id",query.run);out.put("query_node_id",query.node);
        out.put("query_publication_sequence",query.publicationSequence);
        out.put("query_before_observation_id",query.before.observation);out.put("query_before_dom_sha256",query.before.dom);
        out.put("query_before_navigation_epoch",query.before.epoch);
        out.put("query_dispatch_before_elapsed_ms",query.start);out.put("query_dispatch_after_elapsed_ms",query.end);
        out.put("from_city",page.fromCity);out.put("to_city",page.toCity);out.put("departure_date",page.date);
        out.put("observed_result_semantic_sha256",page.semanticSha);out.put("empty_result_message",page.emptyMessage);
        List<Map<String,Object>> rows=new ArrayList<Map<String,Object>>();for(Row row:page.rows)rows.add(row.evidence());
        out.put("flights",rows);out.put("displayed_flight_count",rows.size());out.put("provider_page_proof",page.proof);
        out.put("result_scope","current_complete_visible_records_on_observed_official_page");
        out.put("all_available_flights_enumerated",false);out.put("server_response_payload_verified",false);
        out.put("price_at_booking_verified",false);out.put("business_verified",false);
        out.put("grants_tool_authority",false);out.put("final_native_and_cleanup_gates_verified",false);
        out.put("display_summary",summary(page));record=immutableMap(out);
    }
    boolean matches(Query expected,Frame current){synchronized(query.lifetime){
        return query==expected&&query.active()&&publication==query.publication&&query.latest!=null
                &&query.verifiedLatest!=null&&query.latest.same(query.verifiedLatest)
                &&query.latest.sameObservation(current)&&page.frame.same(current);
    }}
    String semanticSha(){return page.semanticSha;}
    String queryId(){return query.id;}
    Map<String,Object> evidence(){return record;}
    Map<String,Object> modelView(){
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("result_kind",page.kind);
        out.put("from_city",page.fromCity);out.put("to_city",page.toCity);out.put("departure_date",page.date);
        out.put("displayed_flight_count",page.rows.size());out.put("empty_result_message",page.emptyMessage);
        List<Map<String,Object>> rows=new ArrayList<Map<String,Object>>();
        for(int i=0;i<Math.min(8,page.rows.size());i++)rows.add(page.rows.get(i).modelView());
        out.put("flights",rows);out.put("additional_records_in_private_evidence",Math.max(0,page.rows.size()-rows.size()));
        out.put("all_available_flights_enumerated",false);out.put("grants_tool_authority",false);return immutableMap(out);
    }
    private static String summary(Page page){
        String prefix="已核对南航官网当前显示的 "+page.date+" "+page.fromCity+"到"+page.toCity+" 查询结果。";
        if(NONE.equals(page.kind))return prefix+"页面明确显示："+page.emptyMessage;
        StringBuilder out=new StringBuilder(prefix).append("当前可见完整航班记录 ").append(page.rows.size()).append(" 条：");
        for(int i=0;i<Math.min(8,page.rows.size());i++){
            Row row=page.rows.get(i);out.append('\n').append(row.flightNumber).append("，")
                    .append(row.departureDate).append(' ').append(row.departureTime).append(' ').append(row.departureAirport)
                    .append(" → ").append(row.arrivalDate).append(' ').append(row.arrivalTime).append(' ').append(row.arrivalAirport)
                    .append("；页面价格 ").append(row.currency).append(' ').append(row.amount)
                    .append("；税费：").append("displayed".equals(row.taxState)?row.taxText:"当前页面未注明")
                    .append("；条件：").append("displayed".equals(row.conditionState)?row.conditionText:"当前页面未注明").append('。');
        }
        if(page.rows.size()>8)out.append("\n其余当前页记录保留在本次结果凭据中。");
        return out.append("\n以上为观察时的公开页面价格；下单价格及全部可售航班范围尚未核验。").toString();
    }
    private static void condition(String state,String raw){
        need("displayed".equals(state)&&text(raw,512)||"not_stated_on_current_page".equals(state)&&raw==null,
                "actual condition text or explicit current-page absence");
    }
    private static LocalDate exactDate(String value){
        need(value!=null&&value.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}"),"complete literal ISO date");
        LocalDate date=LocalDate.parse(value);need(date.toString().equals(value),"canonical complete date");return date;
    }
    private static LocalTime exactTime(String value){
        need(value!=null&&value.matches("[0-9]{2}:[0-9]{2}"),"complete literal departure/arrival time");return LocalTime.parse(value);
    }
    private static boolean officialUrl(String value){
        if(!text(value,2048))return false;
        try{URI uri=new URI(value);return "https".equals(uri.getScheme())&&"m.csair.com".equals(uri.getHost())
                &&uri.getRawUserInfo()==null&&(uri.getPort()==-1||uri.getPort()==443)
                &&uri.getRawPath()!=null&&uri.getRawPath().startsWith("/");}catch(Exception invalid){return false;}
    }
    private static boolean city(String value){return value!=null&&value.matches("[\\p{IsHan}]{2,12}");}
    private static boolean path(String value){return value!=null&&value.matches("0(?:/[0-9]{1,5}){0,32}");}
    private static boolean id(String value){return value!=null&&value.matches("[0-9a-f]{32}");}
    private static boolean hex(String value){return value!=null&&value.matches("[0-9a-f]{64}");}
    private static boolean text(String value,int bound){
        if(value==null||value.isEmpty()||value.length()>bound)return false;
        for(int i=0;i<value.length();i++)if(Character.isISOControl(value.charAt(i)))return false;
        return true;
    }
    private static void field(StringBuilder out,Object value){
        if(value==null){out.append("|-1:");return;}String text=String.valueOf(value);out.append('|').append(text.length()).append(':').append(text);
    }
    private static String sha(String value){
        try{byte[] digest=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            char[] hex="0123456789abcdef".toCharArray();StringBuilder out=new StringBuilder(64);
            for(byte b:digest)out.append(hex[(b>>>4)&15]).append(hex[b&15]);return out.toString();
        }catch(Exception impossible){throw new IllegalStateException(impossible);}
    }
    @SuppressWarnings("unchecked") private static Map<String,Object> immutableMap(Map<String,Object> value){
        return (Map<String,Object>)immutable(value,0,new int[]{50000});
    }
    private static Object immutable(Object value,int depth,int[] remaining){
        need(depth<=24&&--remaining[0]>=0,"bounded immutable provider evidence");
        if(value==null||value instanceof Boolean||value instanceof Integer||value instanceof Long)return value;
        if(value instanceof String){need(((String)value).length()<=16384,"bounded provider text");return value;}
        if(value instanceof Double){need(!Double.isNaN((Double)value)&&!Double.isInfinite((Double)value),"finite provider number");return value;}
        if(value instanceof Map){Map<String,Object> out=new LinkedHashMap<String,Object>();
            for(Map.Entry<?,?> entry:((Map<?,?>)value).entrySet()){
                need(entry.getKey() instanceof String,"provider evidence keys must be text");
                out.put((String)entry.getKey(),immutable(entry.getValue(),depth+1,remaining));
            }return Collections.unmodifiableMap(out);
        }
        if(value instanceof List){List<Object> out=new ArrayList<Object>();
            for(Object item:(List<?>)value)out.add(immutable(item,depth+1,remaining));return Collections.unmodifiableList(out);
        }
        throw new IllegalArgumentException("flight result: unsupported mutable provider evidence type");
    }
    private static void need(boolean condition,String why){if(!condition)throw new IllegalArgumentException("flight result: "+why);}
}
