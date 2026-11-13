package org.trillionnium.hepta.local;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** One immutable native-App query task. This class has no Android dispatch,
 * coordinate, network, model, restart or retry API. Every transition consumes
 * the original controller's actual model decision and action receipt. */
final class NativeAppSession {
    static final String SCHEMA="hepta.native-app-session.v1";
    static final long OBSERVED_TRANSITION_MS=15000;
    static final int MAX_OBSERVATIONS=96,MAX_ACTIONS=20;
    interface Journal {void write(String leaf,Map<String,Object> value)throws Exception;}
    interface InstalledVerifier {void verify()throws Exception;}
    final String taskId,selectionSha,generation;
    final int displayId;
    final TaskAuthorization.Gate authorization;
    final BackgroundTaskTarget.SelectionBinding selection;
    final BackgroundTaskTarget target;
    final NativeAppGoal goal;
    final NativeAppEvidence.Installed installed;
    private final Journal journal;
    private final InstalledVerifier installedVerifier;
    private final Map<String,String> observations=new LinkedHashMap<String,String>();
    private final List<Map<String,Object>> transitions=new ArrayList<Map<String,Object>>();
    private final Set<LocalDate> queryAttempts=new TreeSet<LocalDate>(),dateAttempts=new TreeSet<LocalDate>();
    private final Set<String> usedRuns=new TreeSet<String>();
    private NativeAppDomain current;
    private NativeCtripFlightPage.Page flight;
    private NativeXiaomiProductPage.Page product;
    private Attempt inFlight,pending,lastDone;
    private int ordinal,observationOrdinal;
    private boolean retired,terminalConsumed,invalid,productQueryAttempted;
    private String invalidReason;
    private LocalDate calendarProposedDate,confirmedFormDate,lastQueryDate;
    private Map<String,Object> calendarInspection,calendarYearProof,lastQueryProof,productQueryProof,productOpenProof;
    private String productSemantic;
    private SuccessClaim acceptedClaim;

    NativeAppSession(String task,TaskAuthorization.Gate auth,BackgroundTaskTarget.SelectionBinding selected,
            NativeAppEvidence.Installed installed,String selectionSha,String generation,int display,
            InstalledVerifier verifier,Journal journal)throws Exception{
        need(NativeAppEvidence.id(task)&&auth!=null&&task.equals(auth.taskId)&&selected!=null&&selected.executionTarget()!=null,"same task and Selection required");
        auth.authorization.requireCompletionSelection(selected);BackgroundTaskTarget t=selected.executionTarget();
        need(t.explicitSelection&&!t.webHelper()&&BackgroundTaskTarget.NATIVE_APP.equals(t.route)&&t.nativeGoal!=null
                &&t.effectivePackages.size()==1&&t.effectivePackages.contains(t.packageName),"recognized explicit singleton native route required");
        t.requireOwner(auth.authorization.immutableOwner());
        need(t.nativeGoal.ownerSha256.equals(auth.authorization.instructionSha256)&&t.nativeGoal.packageName.equals(t.packageName),"same immutable native goal required");
        need(NativeAppEvidence.sha(selectionSha)&&NativeAppEvidence.backgroundGeneration(generation)&&display>0&&verifier!=null&&journal!=null,"actual background lease and journal required");
        requireInstalled(t.nativeGoal,installed);verifier.verify();
        taskId=task;authorization=auth;selection=selected;target=t;goal=t.nativeGoal;this.installed=installed;
        this.selectionSha=selectionSha;this.generation=generation;displayId=display;installedVerifier=verifier;this.journal=journal;
        Map<String,Object> e=base();e.put("installed_app",installed.evidence());e.put("selection_projection_sha256",selectionSha);
        e.put("goal",goal.evidence());e.put("background_generation",generation);e.put("display_id",display);
        e.put("model_actions_required",true);e.put("screenshots_used_as_text",false);e.put("automatic_actions_or_replay",false);
        e.put("query_result_verified",false);journal.write("native-app-binding.json",e);
    }
    private static void requireInstalled(NativeAppGoal goal,NativeAppEvidence.Installed value){
        need(value!=null&&goal.packageName.equals(value.packageName)&&value.apkHashes.size()==1,"complete admitted native APK identity required");
        if(NativeCtripFlightPage.supported(goal))need(value.versionCode==NativeCtripFlightPage.VERSION_CODE
                &&NativeCtripFlightPage.BASE_APK_SHA256.equals(value.apkHashes.get("base")),"Ctrip provider APK/version differs");
        else if(NativeAppGoal.PRODUCT_PRICE.equals(goal.kind)&&NativeAppGoal.XIAOMI_PACKAGE.equals(goal.packageName))
            need(value.versionCode==20261010L&&"95883c057eb15bc6e50a82f2e22da13b77980871624f60a2fb9e50cfdf4a8373".equals(value.apkHashes.get("base")),"Xiaomi provider APK/version differs");
        else throw new IllegalArgumentException("native App provider not implemented for this immutable goal");
    }
    private void live(){need(!retired&&!invalid,"native task retired or invalid: "+invalidReason);authorization.ready();
        authorization.authorization.requireCompletionSelection(selection);need(selection.executionTarget()==target&&target.nativeGoal==goal,"native Selection object changed");}
    void verifyInstalled()throws Exception{installedVerifier.verify();}
    NativeAppDomain domain(){live();need(current!=null,"current native observation missing");return current;}
    NativeAppDomain domainFor(NotesCompletionEvidence.Frame frame){NativeAppDomain d=domain();
        need(frame!=null&&d.frame.observationId.equals(frame.observationId)&&d.frame.completionFrameSha.equals(TaskCompletionGate.webFrameSha(frame)),"native action domain is not the current actual frame");return d;}
    private void requireFrame(NativeAppEvidence.Frame f){need(f!=null&&taskId.equals(f.taskId)&&goal.ownerSha256.equals(f.ownerSha)
                &&target.targetSha256.equals(f.targetSha)&&authorization.authorization.sha256.equals(f.authorizationSha)
                &&selectionSha.equals(f.selectionSha)&&goal.packageName.equals(f.packageName)&&generation.equals(f.generation)
                &&displayId==f.displayId,"native observation task/owner/target/authorization/lease differs");}

    /** Called only after the corresponding full PhoneObservation bytes have
     * been written create-only. A later frame never replaces an earlier one. */
    void observed(NativeAppEvidence.Frame frame)throws Exception{
        live();requireFrame(frame);verifyInstalled();
        String old=observations.get(frame.observationId);
        if(old!=null){need(old.equals(frame.sourceRecordSha)&&current!=null&&current.frame.sameSource(frame),"observation ID reused or old frame replayed");return;}
        need(inFlight==null,"native observation cannot advance before its action outcome");
        need(++observationOrdinal<=MAX_OBSERVATIONS,"native observation budget exhausted");
        if(current!=null)need(frame.capturedElapsedMs>=current.frame.capturedElapsedMs,"native observation clock moved backwards");
        observations.put(frame.observationId,frame.sourceRecordSha);acceptedClaim=null;
        flight=NativeCtripFlightPage.supported(goal)?NativeCtripFlightPage.inspect(goal,frame):null;
        product=NativeAppGoal.XIAOMI_PACKAGE.equals(goal.packageName)?NativeXiaomiProductPage.inspect(goal,frame):null;
        if(pending!=null)advancePending(frame);
        current=buildDomain(frame);
        Map<String,Object> e=base();e.put("frame",frame.evidence());e.put("provider",flight!=null?flight.evidence():product.evidence());
        e.put("domain",current.evidence());e.put("progress",progress());
        journal.write(String.format(java.util.Locale.ROOT,"native-app-page-%04d.json",observationOrdinal),e);
    }
    private NativeAppDomain buildDomain(NativeAppEvidence.Frame frame){
        Set<String> clicks=new TreeSet<String>();Map<String,String> edits=new TreeMap<String,String>(),purposes=new TreeMap<String,String>();
        Map<String,Object> view=NativeAppEvidence.map(),result=null;List<String> missing=new ArrayList<String>();boolean back=false;
        String phase=flight!=null?flight.phase:product.phase;
        if(!frame.metadataObserved||frame.windowType!=1||!frame.collectionComplete||frame.nodesTruncated){missing.add("complete_actual_native_application_frame_required");}
        else if(pending!=null){missing.add("waiting_for_actual_post_action_page");view.put("pending_purpose",pending.purpose);}
        else if(flight!=null){
            view.put("from",goal.fromCity);view.put("to",goal.toCity);view.put("requested_departure_date",goal.departureDate.toString());
            view.put("adults",goal.adults);view.put("calendar_year_proved",calendarYearProof!=null);
            view.put("last_explicit_query_date",lastQueryDate==null?null:lastQueryDate.toString());
            if(NativeCtripFlightPage.HOME.equals(phase))grant(clicks,purposes,flight.homeFlight,"open_flight_form");
            else if(NativeCtripFlightPage.FORM.equals(phase)){
                view.put("observed_form_date",flight.form.date.text);view.put("observed_passengers","1成人/0儿童/0婴儿");
                if(calendarYearProof==null){grant(clicks,purposes,flight.form.date,"inspect_departure_year");missing.add("actual_calendar_year_round_trip_missing");}
                else if(confirmedFormDate!=null&&flight.form.matches(confirmedFormDate)&&queryAttempts.size()<2&&!queryAttempts.contains(confirmedFormDate)){
                    grant(clicks,purposes,flight.form.query,"query_observed_form");view.put("query_date",confirmedFormDate.toString());
                    view.put("exploratory_non_target_query",!goal.departureDate.equals(confirmedFormDate));
                }else missing.add("new_proved_form_date_or_query_budget_missing");
            }else if(NativeCtripFlightPage.CALENDAR.equals(phase)){
                view.put("calendar_month_headers",flight.calendarMonths);back=true;purposes.put("back","return_from_calendar");
                missing.add("native_day_cells_unavailable_no_coordinate_permission");
            }else if(NativeCtripFlightPage.OVERLAY.equals(phase)){
                back=true;purposes.put("back","dismiss_research_sheet");missing.add("overlay_blocks_all_underlying_results");
            }else if(NativeCtripFlightPage.RESULTS.equals(phase)){
                LocalDate shown=lastQueryDate==null?null:flight.displayedMonthDay(lastQueryDate);view.put("observed_departure_date",shown==null?null:shown.toString());
                if(lastQueryProof!=null&&goal.departureDate.equals(lastQueryDate)&&goal.departureDate.equals(shown)&&!flight.quotes.isEmpty()){
                    result=flightResult(frame);List<Map<String,Object>> quotes=new ArrayList<Map<String,Object>>();for(NativeCtripFlightPage.Quote q:flight.quotes){if(quotes.size()==3)break;quotes.add(q.modelView());}
                    view.put("current_displayed_economy_cards",quotes);view.put("additional_visible_admitted_cards",Math.max(0,flight.quotes.size()-quotes.size()));
                }else if(lastQueryProof==null||shown==null){back=true;purposes.put("back","verify_form_after_result_date");missing.add("same_task_explicit_query_missing");}
                else if(goal.departureDate.equals(shown)){back=true;purposes.put("back","verify_form_after_result_date");missing.add("target_date_form_and_explicit_query_required");}
                else{
                    Map<String,LocalDate> dates=flight.resolvedDates(lastQueryDate);String chosen=null;long best=Long.MAX_VALUE;
                    long distance=java.time.temporal.ChronoUnit.DAYS.between(shown,goal.departureDate);
                    for(Map.Entry<String,LocalDate> e:dates.entrySet()){
                        long progress=java.time.temporal.ChronoUnit.DAYS.between(shown,e.getValue());long remaining=Math.abs(java.time.temporal.ChronoUnit.DAYS.between(e.getValue(),goal.departureDate));
                        if(progress!=0&&Long.signum(progress)==Long.signum(distance)&&remaining<Math.abs(distance)&&remaining<best&&!dateAttempts.contains(e.getValue())){chosen=e.getKey();best=remaining;}
                    }
                    if(chosen!=null){grant(clicks,purposes,frame.byId.get(chosen),"navigate_departure_date:"+dates.get(chosen));view.put("actual_date_target",dates.get(chosen).toString());}
                    else missing.add("no_current_native_date_target_toward_owner_date");
                }
                if(result==null&&flight.missing!=null)missing.add(flight.missing);
            }else missing.add(flight.missing==null?"native_flight_page_unrecognized":flight.missing);
        }else{
            view.putAll(product.modelView());
            for(String id:product.clickIds){String purpose=product.purposes.get(id);
                if("open_exact_product".equals(purpose)&&productQueryProof==null)continue;
                if(("submit_exact_suggestion".equals(purpose)||"submit_product_query".equals(purpose))&&productQueryAttempted)continue;
                grant(clicks,purposes,frame.byId.get(id),purpose);
            }
            for(Map.Entry<String,String> e:product.editValues.entrySet()){edits.put(e.getKey(),e.getValue());purposes.put(e.getKey(),product.purposes.get(e.getKey()));}
            if(product.quote!=null&&"detail_display".equals(product.quote.kind)){
                if(productOpenProof!=null&&productSemantic!=null&&productSemantic.equals(product.quote.semanticFingerprint))result=productResult(frame);
                else{back=true;purposes.put("back","return_to_owned_product_search");missing.add("actual_model_query_and_same_card_detail_navigation_required");}
            }
            if(product.quote!=null&&"search_card".equals(product.quote.kind)&&productQueryProof==null){back=true;purposes.put("back","return_to_owned_product_search");}
            missing.addAll(product.missing);
        }
        if(result==null&&missing.isEmpty())missing.add("native_query_action_chain_not_complete");
        return new NativeAppDomain(frame,phase,clicks,edits,purposes,back,view,result,missing);
    }
    private static void grant(Set<String> ids,Map<String,String> purposes,NativeAppEvidence.Node node,String purpose){need(node!=null&&purpose!=null,"actual query target and purpose required");ids.add(node.id);purposes.put(node.id,purpose);}

    private static final class Attempt {
        final int ordinal,step;final String run,purpose;final ActionDecision action;final NativeAppDomain before;
        final NativeCtripFlightPage.Page flight;final NativeXiaomiProductPage.Page product;final long started;
        final LocalDate date;long finished;Map<String,Object> receipt;
        Attempt(int ordinal,int step,String run,ActionDecision action,NativeAppDomain before,String purpose,
                NativeCtripFlightPage.Page flight,NativeXiaomiProductPage.Page product,long started,LocalDate date){
            this.ordinal=ordinal;this.step=step;this.run=run;this.action=action;this.before=before;this.purpose=purpose;
            this.flight=flight;this.product=product;this.started=started;this.date=date;
        }
        Map<String,Object> evidence(){Map<String,Object> e=NativeAppEvidence.map();e.put("ordinal",ordinal);e.put("step",step);e.put("model_run_id",run);
            e.put("action",action.action);e.put("purpose",purpose);e.put("node_id",action.nodeId);e.put("node_label",action.nodeLabel);
            e.put("literal_type_text",action.text);e.put("done_status",action.status);e.put("before",before.frame.evidence());
            e.put("dispatch_started_elapsed_ms",started);e.put("dispatch_finished_elapsed_ms",finished==0?null:Long.valueOf(finished));
            e.put("expected_date",date==null?null:date.toString());e.put("actual_action_receipt",receipt);return e;}
    }
    void beforeModelAction(int step,ActionDecision action,String run,long now)throws Exception{
        live();verifyInstalled();need(current!=null&&inFlight==null&&step>0&&step<=MAX_ACTIONS&&NativeAppEvidence.id(run)&&usedRuns.add(run),"one actual bounded model action required");
        current.requireCurrent(action);authorization.frame().requireDecision(action);need(++ordinal<=MAX_ACTIONS,"native action budget exhausted");
        String purpose="back".equals(action.action)?current.purposes.get("back"):action.nodeId==null?action.action:current.purposes.get(action.nodeId);
        LocalDate date=null;
        if("query_observed_form".equals(purpose)){need(confirmedFormDate!=null&&flight!=null&&flight.form!=null&&flight.form.matches(confirmedFormDate)
                    &&calendarYearProof!=null&&queryAttempts.size()<2&&queryAttempts.add(confirmedFormDate),"one explicit query per proved date, maximum two");date=confirmedFormDate;}
        else if(purpose!=null&&purpose.startsWith("navigate_departure_date:")){date=LocalDate.parse(purpose.substring("navigate_departure_date:".length()));
            need(lastQueryProof!=null&&date.equals(flight.resolvedDates(lastQueryDate).get(action.nodeId))&&dateAttempts.add(date),"one actual date-strip proposal per date");}
        else if("verify_form_after_result_date".equals(purpose))date=flight==null||lastQueryDate==null?null:flight.displayedMonthDay(lastQueryDate);
        else if("submit_exact_suggestion".equals(purpose)||"submit_product_query".equals(purpose)){need(!productQueryAttempted,"native product query already attempted");productQueryAttempted=true;}
        if(!"wait".equals(action.action)&&!"done".equals(action.action)){acceptedClaim=null;lastDone=null;
            if(!"open_exact_product".equals(purpose)){productOpenProof=null;productSemantic=null;}}
        inFlight=new Attempt(ordinal,step,run,action,current,purpose,flight,product,now,date);
        Map<String,Object> e=base();e.put("attempt",inFlight.evidence());e.put("same_owner_authorization",authorization.frame().evidence());e.put("dispatch_occurred",false);
        journal.write(String.format(java.util.Locale.ROOT,"native-app-attempt-%02d.json",ordinal),e);
    }
    void modelActionOutcome(ActionDecision action,String run,boolean accepted,boolean dispatched,boolean stale,String receiptSha,long finished)throws Exception{
        live();Attempt a=inFlight;need(a!=null&&a.action==action&&a.run.equals(run)&&finished>=a.started&&NativeAppEvidence.sha(receiptSha),"same native action and durable receipt required");
        Map<String,Object> outcome=NativeAppEvidence.map();outcome.put("accepted",accepted);outcome.put("dispatched",dispatched);outcome.put("stale",stale);
        outcome.put("step_action_record_sha256",receiptSha);outcome.put("model_issued",true);a.finished=finished;a.receipt=NativeAppEvidence.immutableMap(outcome);
        Map<String,Object> e=base();e.put("attempt",a.evidence());journal.write(String.format(java.util.Locale.ROOT,"native-app-outcome-%02d.json",a.ordinal),e);inFlight=null;
        if(stale&&!dispatched)return;
        if(!accepted||stale){invalidate("native_action_receipt_not_accepted");return;}
        if("wait".equals(action.action))return;
        if("done".equals(action.action)){lastDone=a;return;}
        need(dispatched,"native action effect not dispatched");
        need(pending==null,"new native action while preceding transition unresolved");pending=a;
    }
    private void advancePending(NativeAppEvidence.Frame frame){
        Attempt a=pending;need(a!=null&&a.receipt!=null&&frame.capturedElapsedMs>=a.finished,"post-action native frame precedes outcome");
        if(frame.capturedElapsedMs-a.finished>OBSERVED_TRANSITION_MS){invalidate("actual_native_transition_observation_deadline");return;}
        boolean complete=false;Map<String,Object> proof=NativeAppEvidence.map();proof.put("attempt",a.evidence());proof.put("after",frame.evidence());
        if(flight!=null){
            String p=a.purpose;
            if("inspect_departure_year".equals(p)&&NativeCtripFlightPage.CALENDAR.equals(flight.phase)&&a.flight.form!=null){
                LocalDate proposed=null;Map<String,Object> header=null;
                for(Map<String,Object> m:flight.calendarMonths)if(((Integer)m.get("month")).intValue()==a.flight.form.month){
                    need(proposed==null,"calendar has ambiguous source year for the selected form month");
                    proposed=LocalDate.of(((Integer)m.get("year")).intValue(),a.flight.form.month,a.flight.form.day);header=m;}
                need(proposed!=null&&flight.calendarMonths.size()<=3,"actual same-month calendar title required");
                proof.put("calendar_month_header",header);proof.put("form_before",a.flight.form.evidence());proof.put("year_source","actual_native_calendar_month_title_after_model_date_control");
                proof.put("owner_year_used_as_observed_value",false);calendarProposedDate=proposed;calendarInspection=NativeAppEvidence.immutableMap(proof);complete=true;
            }else if("return_from_calendar".equals(p)&&NativeCtripFlightPage.FORM.equals(flight.phase)){
                if(calendarProposedDate!=null&&calendarInspection!=null&&flight.form.matches(calendarProposedDate)){
                    proof.put("inspection",calendarInspection);proof.put("form_after",flight.form.evidence());proof.put("proved_departure_date",calendarProposedDate.toString());
                    calendarYearProof=NativeAppEvidence.immutableMap(proof);confirmedFormDate=calendarProposedDate;
                }
                calendarProposedDate=null;calendarInspection=null;complete=true;
            }else if("query_observed_form".equals(p)&&NativeCtripFlightPage.RESULTS.equals(flight.phase)&&a.date.equals(flight.displayedMonthDay(a.date))){
                proof.put("calendar_year_round_trip",calendarYearProof);proof.put("query_form",a.flight.form.evidence());proof.put("query_date",a.date.toString());
                proof.put("result_date_strip",dateEvidence(flight));lastQueryDate=a.date;lastQueryProof=NativeAppEvidence.immutableMap(proof);complete=true;
            }else if(p!=null&&p.startsWith("navigate_departure_date:")&&NativeCtripFlightPage.RESULTS.equals(flight.phase)
                    &&a.date.equals(flight.displayedMonthDay(lastQueryDate))){proof.put("actual_result_date_strip",dateEvidence(flight));proof.put("proved_date",a.date.toString());complete=true;}
            else if("verify_form_after_result_date".equals(p)&&NativeCtripFlightPage.FORM.equals(flight.phase)){
                confirmedFormDate=a.date!=null&&calendarYearProof!=null&&flight.form.matches(a.date)?a.date:null;
                proof.put("form_after",flight.form.evidence());proof.put("proved_departure_date",confirmedFormDate==null?null:confirmedFormDate.toString());complete=true;
            }else if("open_flight_form".equals(p)&&NativeCtripFlightPage.FORM.equals(flight.phase))complete=true;
            else if("dismiss_research_sheet".equals(p)&&!NativeCtripFlightPage.OVERLAY.equals(flight.phase)&&!NativeCtripFlightPage.UNAVAILABLE.equals(flight.phase))complete=true;
        }else{
            if(("submit_exact_suggestion".equals(a.purpose)||"submit_product_query".equals(a.purpose))&&product.quote!=null&&"search_card".equals(product.quote.kind)){
                proof.put("search_result_quote",product.quote.evidence());productQueryProof=NativeAppEvidence.immutableMap(proof);complete=true;
            }else if("open_exact_product".equals(a.purpose)&&product.quote!=null&&"detail_display".equals(product.quote.kind)){
                need(productQueryProof!=null&&a.product.quote!=null&&"search_card".equals(a.product.quote.kind)
                        &&a.product.quote.amountDecimal.equals(product.quote.amountDecimal)&&a.product.quote.currency.equals(product.quote.currency),"same queried product/card and displayed price required");
                proof.put("query",productQueryProof);proof.put("search_card",a.product.quote.evidence());proof.put("detail",product.quote.evidence());
                productOpenProof=NativeAppEvidence.immutableMap(proof);productSemantic=product.quote.semanticFingerprint;complete=true;
            }else if("set_product_query".equals(a.purpose)||"open_search".equals(a.purpose)||"return_to_owned_product_search".equals(a.purpose)){
                complete=!"unrecognized_native_page".equals(product.phase)&&!"observation_unavailable".equals(product.phase);
            }
        }
        if(complete){transitions.add(NativeAppEvidence.immutableMap(proof));pending=null;}
    }
    private static List<Map<String,Object>> dateEvidence(NativeCtripFlightPage.Page page){List<Map<String,Object>> out=new ArrayList<Map<String,Object>>();for(NativeCtripFlightPage.DateCell d:page.dates)out.add(d.evidence());return out;}
    private Map<String,Object> flightResult(NativeAppEvidence.Frame f){
        Map<String,Object> out=resultBase(f,"hepta.native-ctrip-displayed-flight-result.v1");out.put("from_city",goal.fromCity);out.put("to_city",goal.toCity);
        out.put("departure_date",goal.departureDate.toString());out.put("adults",1);out.put("children",0);out.put("infants",0);
        out.put("calendar_year_round_trip",calendarYearProof);out.put("same_task_target_date_explicit_query",lastQueryProof);
        out.put("current_date_strip",dateEvidence(flight));List<Map<String,Object>> cards=new ArrayList<Map<String,Object>>();for(NativeCtripFlightPage.Quote q:flight.quotes)cards.add(q.evidence());out.put("displayed_cards",cards);
        out.put("tax_and_fee_status","not_stated_in_observed_card");out.put("lowest_of_all_flights_claimed",false);out.put("availability_or_checkout_price_verified",false);
        StringBuilder s=new StringBuilder("携程原生应用当前展示 ").append(goal.departureDate).append(' ').append(goal.fromCity).append("到").append(goal.toCity).append("，1名成人经济舱：");
        for(int i=0;i<Math.min(3,flight.quotes.size());i++){NativeCtripFlightPage.Quote q=flight.quotes.get(i);if(i>0)s.append("；");s.append(q.flightNumber).append(' ').append(q.departureTime).append('–').append(q.arrivalTime).append(' ').append(q.departureAirport).append('→').append(q.arrivalAirport).append("，人民币").append(q.amountDecimal).append("元");if(!q.displayTags.isEmpty())s.append("，").append(q.displayTags);}
        s.append("。这是所见航班卡报价；税费及最终结算价未在本次观测中确认。");out.put("display_summary",s.toString());return out;
    }
    private Map<String,Object> productResult(NativeAppEvidence.Frame f){Map<String,Object> out=resultBase(f,"hepta.native-xiaomi-displayed-product-price.v1");
        out.put("model",goal.productModel);out.put("actual_query_and_card_navigation",productOpenProof);out.put("detail_quote",product.quote.evidence());
        out.put("display_summary","小米商城原生应用当前展示 "+product.quote.modelRaw+"：人民币"+product.quote.amountDecimal+"元。已从本次搜索结果进入同商品详情核对；未下单，最终结算和库存未确认。");return out;}
    private Map<String,Object> resultBase(NativeAppEvidence.Frame f,String schema){Map<String,Object> e=base();e.put("schema",schema);e.put("goal",goal.evidence());
        e.put("installed_app",installed.evidence());e.put("current_frame",f.evidence());e.put("business_verified_before_terminal",false);e.put("external_model",false);return e;}
    private Map<String,Object> progress(){Map<String,Object> e=NativeAppEvidence.map();e.put("actual_model_actions",ordinal);e.put("calendar_year_proved",calendarYearProof!=null);
        e.put("proved_form_date",confirmedFormDate==null?null:confirmedFormDate.toString());e.put("last_query_date",lastQueryDate==null?null:lastQueryDate.toString());
        List<String> dates=new ArrayList<String>();for(LocalDate d:queryAttempts)dates.add(d.toString());e.put("explicit_query_attempt_dates",dates);
        e.put("product_query_observed",productQueryProof!=null);e.put("product_detail_navigation_observed",productOpenProof!=null);e.put("pending",pending==null?null:pending.evidence());e.put("transitions",transitions);return e;}
    private Map<String,Object> base(){Map<String,Object> e=NativeAppEvidence.map();e.put("schema",SCHEMA);e.put("task_id",taskId);
        e.put("owner_sha256",goal.ownerSha256);e.put("execution_target_sha256",target.targetSha256);e.put("authorization_sha256",authorization.authorization.sha256);return e;}
    private void invalidate(String reason){invalid=true;invalidReason=reason;acceptedClaim=null;}

    static final class SuccessClaim {
        final NativeAppSession session;final int step;final String run,frameSha,observation;final Map<String,Object> result;
        private SuccessClaim(NativeAppSession s,int step,String run,NativeAppEvidence.Frame frame,Map<String,Object> result){session=s;this.step=step;this.run=run;frameSha=frame.completionFrameSha;observation=frame.observationId;this.result=NativeAppEvidence.immutableMap(result);}
    }
    boolean ready(NotesCompletionEvidence.Frame frame){return !retired&&!invalid&&current!=null&&current.resultReady&&frame!=null
            &&current.frame.observationId.equals(frame.observationId)&&current.frame.completionFrameSha.equals(TaskCompletionGate.webFrameSha(frame))&&pending==null&&inFlight==null;}
    SuccessClaim acceptSuccess(int step,String run,NotesCompletionEvidence.Frame frame,boolean finalWholeTreeStable){
        live();acceptedClaim=null;
        if(!finalWholeTreeStable||!ready(frame)||lastDone==null||lastDone.step!=step||!lastDone.run.equals(run)
                ||!"success".equals(lastDone.action.status)||!lastDone.before.resultReady
                ||!lastDone.before.frame.treeSha.equals(current.frame.treeSha)||lastDone.before.frame.windowId!=current.frame.windowId
                ||lastDone.before.frame.rotation!=current.frame.rotation)return null;
        acceptedClaim=new SuccessClaim(this,step,run,current.frame,current.resultRecord());return acceptedClaim;
    }
    void retire()throws Exception{if(retired)return;retired=true;
        Map<String,Object> e=base();e.put("action_domain_retired",true);e.put("pending_action",inFlight!=null||pending!=null);
        e.put("invalid",invalid);e.put("invalid_reason",invalidReason);e.put("accepted_completion_candidate",acceptedClaim!=null);
        e.put("progress",progress());journal.write("native-app-retired.json",e);
    }
    Map<String,Object> terminal(NotesCompletionEvidence.Frame frame,TaskAuthorization.Frame owner,int step,String run,
            boolean modelSuccess,boolean cleanup,boolean backgroundReleased,boolean scopeRechecked,boolean installedRechecked,
            boolean cancelled,boolean processStarted,boolean processExitObserved,Integer exitCode,boolean receiptValid,
            String workerTask,String workerGeneration,String workerReceiptSha){
        SuccessClaim claim=acceptedClaim;acceptedClaim=null;boolean first=!terminalConsumed;terminalConsumed=true;
        boolean snapshot=first&&retired&&!invalid&&claim!=null&&claim.session==this&&claim.step==step&&claim.run.equals(run)
                &&frame!=null&&claim.observation.equals(frame.observationId)&&claim.frameSha.equals(TaskCompletionGate.webFrameSha(frame))
                &&frame.displayId==displayId&&generation.equals(frame.backgroundGeneration)&&inFlight==null&&pending==null;
        boolean ownerBound=owner!=null&&owner.authorization==authorization.authorization&&taskId.equals(owner.taskId)&&owner.successAllowed();
        boolean nativeBound=processStarted&&processExitObserved&&Integer.valueOf(0).equals(exitCode)&&receiptValid
                &&taskId.equals(workerTask)&&NativeAppEvidence.id(workerGeneration)&&NativeAppEvidence.sha(workerReceiptSha);
        boolean passed=snapshot&&modelSuccess&&cleanup&&backgroundReleased&&scopeRechecked&&installedRechecked&&ownerBound&&!cancelled&&nativeBound;
        Map<String,Object> e=base();e.put("schema","hepta.native-app-terminal-completion.v1");e.put("one_terminal_attempt",first);
        e.put("action_domain_retired",retired);e.put("same_final_native_result_snapshot",snapshot);e.put("model_success_claim_verified",snapshot);
        e.put("all_cleanup_known",cleanup);e.put("background_released",backgroundReleased);e.put("scope_rechecked_after_worker_exit",scopeRechecked);
        e.put("installed_app_rechecked_after_cleanup",installedRechecked);e.put("owner_rechecked",ownerBound);e.put("cancelled",cancelled);
        e.put("native_normal0_parent_session_bound",nativeBound);e.put("worker_task_id",workerTask);e.put("worker_generation",workerGeneration);e.put("worker_receipt_sha256",workerReceiptSha);
        e.put("completion_verified",passed);e.put("business_verified",passed);e.put("terminal_binding_and_cleanup_verified",passed);
        e.put("observation_chain_verified",snapshot);e.put("actual_query_transitions",transitions);e.put("public_native_result",claim==null?null:claim.result);
        e.put("missing",passed?Collections.emptyList():Collections.singletonList("native_final_task_identity_or_query_or_cleanup_missing"));return NativeAppEvidence.immutableMap(e);
    }
    Map<String,Object> evidence(){Map<String,Object> e=base();e.put("progress",progress());e.put("invalid",invalid);e.put("invalid_reason",invalidReason);e.put("action_domain_retired",retired);
        e.put("current_domain",current==null?null:current.evidence());return e;}
    Map<String,Object> promptEvidence(){return current==null?Collections.<String,Object>singletonMap("missing","current_native_observation_missing"):current.promptEvidence();}
    Map<String,Object> resultRecord(){return current==null?null:current.resultRecord();}
    List<String> missing(){return current==null?Collections.singletonList("current_native_observation_missing"):current.missing;}
    private static void need(boolean value,String reason){NativeAppEvidence.need(value,reason);}
}
