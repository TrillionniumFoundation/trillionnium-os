package org.trillionnium.hepta.local;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One lease's actual model selection and one public-query attempt.
 * The only constructors are fed by the original executor outcome and fresh
 * captured domains. A requested city/year or a planned click is never readback.
 */
final class WebFlightProgress {
    static final String QUERY="submit_public_flight_query_once";
    private final WebFlightResult.Lifetime lifetime;
    private final WebFlightDomain anchor;
    private final Confirmation departure,arrival,date;
    private final Pending pending;
    private final Query query;

    private WebFlightProgress(WebFlightResult.Lifetime lifetime,WebFlightDomain anchor,Confirmation departure,Confirmation arrival,
                              Confirmation date,Pending pending,Query query){
        this.lifetime=lifetime;
        this.anchor=anchor;this.departure=departure;this.arrival=arrival;
        this.date=date;this.pending=pending;this.query=query;
    }
    static WebFlightProgress begin(WebFlightDomain frame){
        need(frame!=null,"actual flight domain required");
        return new WebFlightProgress(new WebFlightResult.Lifetime(),frame,null,null,null,null,null);
    }
    boolean matches(WebFlightDomain frame){
        return lifetime.active()&&frame!=null&&anchor.taskId.equals(frame.taskId)&&anchor.ownerSha.equals(frame.ownerSha)
                &&anchor.contractSha.equals(frame.contractSha)&&anchor.authorizationSha.equals(frame.authorizationSha)
                &&anchor.bindingSha.equals(frame.bindingSha)&&anchor.generation.equals(frame.generation)
                &&anchor.instance.equals(frame.instance)&&anchor.displayId==frame.displayId
                &&anchor.windowId==frame.windowId&&frame.epoch>=anchor.epoch;
    }
    boolean hasConfirmedCities(){return departure!=null&&arrival!=null;}
    boolean selectionPending(){return pending!=null;}
    boolean queryAttempted(){return query!=null;}
    boolean queryDispatched(){return query!=null&&query.outcomeObserved&&query.nativeCallEntered
            &&query.accepted&&query.dispatched&&!query.stale&&lifetime.active();}
    void retire(){lifetime.retire();}
    WebFlightResult bindResult(WebFlightDomain current,WebFlightResult.Page actualPage){
        need(matches(current)&&queryDispatched()&&query.resultBinding!=null,
                "result needs this live lease's actual accepted query");
        return WebFlightResult.bind(query.resultBinding,current.resultFrame(),actualPage);
    }
    boolean acceptsResult(WebFlightResult result,WebFlightDomain current){
        return result!=null&&matches(current)&&queryDispatched()&&query.resultBinding!=null
                &&result.matches(query.resultBinding,current.resultFrame());
    }
    boolean selectionConfirmed(String kind,WebFlightDomain now){
        need(matches(now),"selection belongs to another flight lease");
        Confirmation value="departure".equals(kind)?departure:"arrival".equals(kind)?arrival:date;
        return value!=null&&now.form!=null&&now.nativeValueMatches(kind)
                &&literalMatches(kind,now)&&now.captureStarted>=value.afterCaptureStarted&&now.epoch>=value.afterEpoch;
    }
    boolean queryReady(WebFlightDomain now){
        return matches(now)&&pending==null&&query==null&&now.form!=null
                &&now.form.adults==1&&now.form.children==0&&now.form.infants==0
                &&selectionConfirmed("departure",now)&&selectionConfirmed("arrival",now)
                &&selectionConfirmed("date",now)&&now.queryCandidate!=null;
    }
    /** Saved durably by the caller before any possible native query invocation. */
    WebFlightProgress reserveQuery(WebFlightDomain before,ActionDecision action,String run){
        need(matches(before)&&queryReady(before)&&pending==null,"actual flight selections are not query-ready");
        before.requireCurrent(action);
        need("click".equals(action.action)&&QUERY.equals(before.purpose(action.nodeId))
                &&run!=null&&run.matches("[0-9a-f]{32}"),"one model-bound query control required");
        return new WebFlightProgress(lifetime,anchor,departure,arrival,date,null,new Query(before,action,run));
    }
    boolean isQueryAction(ActionDecision action,String run){
        return query!=null&&action!=null&&query.run.equals(run)&&"click".equals(action.action)
                &&query.before.observationId.equals(action.observationId)&&query.action.nodeId.equals(action.nodeId);
    }
    boolean reservedFor(WebFlightDomain before,ActionDecision action,String run){
        return query!=null&&!query.outcomeObserved&&matches(before)&&query.run.equals(run)
                &&query.before.observationId.equals(before.observationId)
                &&query.action.nodeId.equals(action.nodeId)&&"click".equals(action.action);
    }
    /** This consumes the actual result, including false/unknown dispatch facts. */
    WebFlightProgress outcome(WebFlightDomain before,ActionDecision action,String run,
            boolean accepted,boolean dispatched,boolean stale,boolean nativeQueryCallEntered,long start,long end){
        need(matches(before)&&action!=null&&run!=null&&run.matches("[0-9a-f]{32}")
                &&before.observationId.equals(action.observationId)
                &&before.captureEnded>=0&&before.captureEnded<=start&&start<=end,
                "actual same-lease model dispatch and monotonic clocks required");
        if(!"click".equals(action.action))return this;
        before.requireCurrent(action);
        String purpose=before.purpose(action.nodeId);
        need(purpose!=null,"actual observed flight capability required");
        if(QUERY.equals(purpose)){
            need(reservedFor(before,action,run),"query reservation missing or already consumed");
            need(!accepted||nativeQueryCallEntered,"accepted query requires actual native call entry");
            return new WebFlightProgress(lifetime,anchor,departure,arrival,date,null,
                    new Query(lifetime,query,accepted,dispatched,stale,nativeQueryCallEntered,start,end));
        }
        need(query==null,"no page action after a query attempt");
        if(!accepted||!dispatched||stale)return this;
        String kind=selectionKind(purpose);
        if(kind!=null){
            need(pending==null,"prior flight selection has no actual readback yet");
            if("date".equals(kind))need(hasConfirmedCities()
                    &&before.goal.departureDate.toString().equals(before.capability(action.nodeId).get("observed_iso_date"))
                    &&Boolean.TRUE.equals(before.capability(action.nodeId).get("native_parent_relationship_claimed")),
                    "full literal calendar date and actual native month/list relation required");
            return new WebFlightProgress(lifetime,anchor,departure,arrival,"date".equals(kind)?date:null,
                    new Pending(before,action,run,kind,start,end),null);
        }
        // Reopening a field invalidates its older confirmation even if the next
        // page has not loaded. An old year cannot survive a new date edit.
        if("choose_departure_city".equals(purpose))
            return new WebFlightProgress(lifetime,anchor,null,arrival,null,null,null);
        if("choose_arrival_city".equals(purpose))
            return new WebFlightProgress(lifetime,anchor,departure,null,null,null,null);
        if("choose_departure_date".equals(purpose))
            return new WebFlightProgress(lifetime,anchor,departure,arrival,null,null,null);
        return this;
    }
    /** Fresh capture only. No click, retry, URL construction or OWNER rewriting. */
    WebFlightProgress observed(WebFlightDomain now){
        if(!matches(now)){lifetime.retire();need(false,"flight progress cannot move to another lease, window or identity");}
        if(now.captureStarted<0)return this;
        if(query!=null){
            if(query.resultBinding!=null&&now.captureStarted>=query.end)query.resultBinding.observed(now.resultFrame());
            if(query.outcomeObserved&&query.after==null&&now.captureStarted>=query.end)
                return new WebFlightProgress(lifetime,anchor,departure,arrival,date,null,new Query(query,now));
            return this;
        }
        Confirmation dep=departure,arr=arrival,day=date;
        if(now.form!=null){
            if(dep!=null&&!literalMatches("departure",now))dep=null;
            if(arr!=null&&!literalMatches("arrival",now))arr=null;
            if(day!=null&&!literalMatches("date",now))day=null;
        }
        Pending wait=pending;
        if(wait!=null&&now.form!=null&&now.captureStarted>=wait.end&&now.epoch>=wait.before.epoch
                &&now.nativeValueMatches(wait.kind)&&literalMatches(wait.kind,now)){
            Confirmation confirmed=new Confirmation(wait,now);
            if("departure".equals(wait.kind))dep=confirmed;
            else if("arrival".equals(wait.kind))arr=confirmed;
            else day=confirmed;
            wait=null;
        }
        if(dep==departure&&arr==arrival&&day==date&&wait==pending)return this;
        return new WebFlightProgress(lifetime,anchor,dep,arr,day,wait,null);
    }
    Map<String,Object> evidence(WebFlightDomain now){
        need(matches(now),"flight evidence scope");
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("schema","hepta.csair-model-query-progress.v1");
        out.put("task_id",anchor.taskId);out.put("owner_sha256",anchor.ownerSha);
        out.put("contract_sha256",anchor.contractSha);out.put("authorization_sha256",anchor.authorizationSha);
        out.put("binding_sha256",anchor.bindingSha);out.put("background_generation",anchor.generation);
        out.put("webview_instance",anchor.instance);out.put("display_id",anchor.displayId);out.put("window_id",anchor.windowId);
        out.put("departure_selection",departure==null?null:departure.evidence);
        out.put("arrival_selection",arrival==null?null:arrival.evidence);
        out.put("complete_date_selection",date==null?null:date.evidence);
        out.put("selection_readback_pending",pending==null?null:pending.evidence);
        out.put("current_departure_value_verified",selectionConfirmed("departure",now));
        out.put("current_arrival_value_verified",selectionConfirmed("arrival",now));
        out.put("current_complete_date_verified",selectionConfirmed("date",now));
        out.put("query_ready",queryReady(now));out.put("query_attempted",queryAttempted());
        out.put("query_native_dispatch_confirmed",queryDispatched());
        out.put("query_attempt",query==null?null:query.evidence());
        out.put("query_retry_permitted",false);out.put("results_verified",false);
        out.put("business_verified",false);out.put("grants_tool_authority",false);
        return Collections.unmodifiableMap(out);
    }
    private boolean literalMatches(String kind,WebFlightDomain now){
        if(now.form==null)return false;
        if("departure".equals(kind))return anchor.goal.fromCity.equals(now.form.departureCityLiteral);
        if("arrival".equals(kind))return anchor.goal.toCity.equals(now.form.arrivalCityLiteral);
        return "date".equals(kind)&&now.form.displayedMonth!=null&&now.form.displayedDay!=null
                &&now.form.displayedMonth.intValue()==anchor.goal.departureDate.getMonthValue()
                &&now.form.displayedDay.intValue()==anchor.goal.departureDate.getDayOfMonth()
                &&(now.form.displayedWeekday==null||weekday(anchor.goal.departureDate.getDayOfWeek().getValue()).equals(now.form.displayedWeekday)
                        ||anchor.goal.departureDate.getDayOfWeek().getValue()==7&&"周天".equals(now.form.displayedWeekday));
    }
    private static String weekday(int day){return "周"+new String[]{"一","二","三","四","五","六","日"}[day-1];}
    private static String selectionKind(String purpose){
        if("choose_departure_city_from_immutable_owner".equals(purpose))return "departure";
        if("choose_arrival_city_from_immutable_owner".equals(purpose))return "arrival";
        if("choose_departure_date_from_immutable_owner".equals(purpose))return "date";
        return null;
    }
    private static final class Pending {
        final WebFlightDomain before;final ActionDecision action;final String run,kind;final long start,end;
        final Map<String,Object> evidence;
        Pending(WebFlightDomain before,ActionDecision action,String run,String kind,long start,long end){
            this.before=before;this.action=action;this.run=run;this.kind=kind;this.start=start;this.end=end;
            Map<String,Object> out=dispatch(before,action,run,start,end);
            out.put("selection_kind",kind);out.put("accepted",true);out.put("dispatched",true);out.put("stale",false);
            out.put("source_capability",before.capability(action.nodeId));
            out.put("after_form_verified",false);evidence=Collections.unmodifiableMap(out);
        }
    }
    private static final class Confirmation {
        final long afterCaptureStarted,afterEpoch;final Map<String,Object> evidence;
        Confirmation(Pending pending,WebFlightDomain after){
            afterCaptureStarted=after.captureStarted;afterEpoch=after.epoch;
            Map<String,Object> out=new LinkedHashMap<String,Object>(pending.evidence);
            out.put("after_observation_id",after.observationId);out.put("after_dom_sha256",after.domSha);
            out.put("after_native_url",after.url);out.put("after_navigation_epoch",after.epoch);
            out.put("after_capture_started_elapsed_ms",after.captureStarted);
            out.put("after_form_verified",true);out.put("native_field_readback",after.nativeReadbacks.get(pending.kind));
            out.put("selected_literal_value","departure".equals(pending.kind)?after.form.departureCityLiteral:
                    "arrival".equals(pending.kind)?after.form.arrivalCityLiteral:
                            pending.before.goal.departureDate.toString());
            out.put("displayed_year",null);
            out.put("year_source","date".equals(pending.kind)?"actual_clicked_calendar_month_header":null);
            out.put("year_from_url_or_today",false);evidence=Collections.unmodifiableMap(out);
        }
    }
    private static final class Query {
        final WebFlightDomain before,after;final ActionDecision action;final String run;
        final WebFlightResult.Query resultBinding;
        final boolean outcomeObserved,accepted,dispatched,stale,nativeCallEntered;final long start,end;
        Query(WebFlightDomain before,ActionDecision action,String run){
            this.before=before;this.action=action;this.run=run;after=null;outcomeObserved=false;
            accepted=false;dispatched=false;stale=false;nativeCallEntered=false;start=-1;end=-1;
            resultBinding=null;
        }
        Query(WebFlightResult.Lifetime lifetime,Query original,boolean accepted,boolean dispatched,boolean stale,boolean entered,long start,long end){
            before=original.before;action=original.action;run=original.run;after=null;outcomeObserved=true;
            this.accepted=accepted;this.dispatched=dispatched;this.stale=stale;nativeCallEntered=entered;this.start=start;this.end=end;
            resultBinding=accepted&&dispatched&&!stale&&entered?new WebFlightResult.Query(lifetime,before.resultFrame(),run,action.nodeId,
                    before.goal.fromCity,before.goal.toCity,before.goal.departureDate.toString(),accepted,dispatched,stale,entered,start,end):null;
        }
        Query(Query original,WebFlightDomain after){
            before=original.before;action=original.action;run=original.run;this.after=after;outcomeObserved=original.outcomeObserved;
            accepted=original.accepted;dispatched=original.dispatched;stale=original.stale;
            nativeCallEntered=original.nativeCallEntered;start=original.start;end=original.end;
            resultBinding=original.resultBinding;
        }
        Map<String,Object> evidence(){
            Map<String,Object> out=dispatch(before,action,run,start,end);
            out.put("source","actual_controller_query_reservation_and_executor_outcome");
            out.put("reservation_consumed",true);out.put("outcome_observed",outcomeObserved);
            out.put("native_action_click_call_entered",nativeCallEntered);
            out.put("accepted",outcomeObserved?Boolean.valueOf(accepted):null);
            out.put("dispatched",outcomeObserved?Boolean.valueOf(dispatched):null);
            out.put("stale",outcomeObserved?Boolean.valueOf(stale):null);
            out.put("before_verified_form",before.form.evidence());
            out.put("before_selection_chain",before.progressEvidence());
            out.put("query_control",before.capability(action.nodeId));
            out.put("after_observation_id",after==null?null:after.observationId);
            out.put("after_native_url",after==null?null:after.url);
            out.put("after_navigation_epoch",after==null?null:Long.valueOf(after.epoch));
            out.put("after_dom_sha256",after==null?null:after.domSha);
            out.put("after_capture_started_elapsed_ms",after==null?null:Long.valueOf(after.captureStarted));
            out.put("server_query_completed",false);out.put("flight_results_verified",false);
            return Collections.unmodifiableMap(out);
        }
    }
    private static Map<String,Object> dispatch(WebFlightDomain before,ActionDecision action,String run,long start,long end){
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("model_run_id",run);out.put("model_issued",true);out.put("action",action.action);out.put("node_id",action.nodeId);
        out.put("before_observation_id",before.observationId);out.put("before_dom_sha256",before.domSha);
        out.put("before_native_url",before.url);out.put("before_navigation_epoch",before.epoch);
        out.put("before_capture_ended_elapsed_ms",before.captureEnded);
        out.put("dispatch_before_elapsed_ms",start<0?null:Long.valueOf(start));
        out.put("dispatch_after_elapsed_ms",end<0?null:Long.valueOf(end));
        return out;
    }
    private static void need(boolean yes,String reason){WebEvidenceJson.need(yes,reason);}
}
