package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/** Host-reviewable, single-use protocol state. There is intentionally no global
 * Session registration, DecisionGrammar factory, touch port or ActionExecution.
 * No return value grants dispatch. Real model receipt + Session/Gate + slot +
 * fresh producer + privileged one-shot input proof are mandatory future seams.
 */
final class NativeCalendarDateProtocol implements AutoCloseable {
    interface Clock {long elapsedRealtime();}
    static final long ACTION_MS=8000L;
    final NativeCalendarDateEnvelope source;
    final String grammar,grammarSha256;
    private boolean modelConsumed,claimConsumed,closed;
    private String runId,rawSha256;
    private long modelCompleted,deadline;
    private NativeCalendarDateIntent intent;
    private Consumption consumption;

    NativeCalendarDateProtocol(NativeCalendarDateEnvelope source){
        need(source!=null,"original calendar pixel envelope required");this.source=source;
        grammar=grammar(source);grammarSha256=MobiMindContract.sha(grammar.getBytes(StandardCharsets.UTF_8));
    }
    /** One original model output only; malformed or refused output cannot regain
     * this protocol instance. Caller must later prove this actual run's complete
     * GUI-Owl request/raw/grammar/frame receipt before any dispatch connection.
     */
    synchronized NativeCalendarDateIntent propose(String raw,String actualRunId,long completed,
            long originalActionDeadline,long originalTaskDeadline)throws Exception{
        need(!closed&&!modelConsumed,"calendar protocol model slot already consumed");modelConsumed=true;
        try{
            need(NativeAppEvidence.id(actualRunId)&&completed>=source.facts.capturedElapsedMs
                    &&originalActionDeadline>completed&&originalActionDeadline-completed<=ACTION_MS
                    &&originalActionDeadline<=originalTaskDeadline,"original run and bounded unchanged task/action clocks required");
            source.requireUnchangedOriginal();
            intent=NativeCalendarDateIntent.parse(raw,source);runId=actualRunId;rawSha256=NativeAppEvidence.hash(raw);
            modelCompleted=completed;deadline=originalActionDeadline;return intent;
        }catch(Exception failure){closed=true;throw failure;}
    }
    /** Consumes the sole local protocol claim BEFORE any failure or handoff.
     * Even an invalid/expired fresh frame cannot be retried with this object.
     * This does not mark an actual effect entered, and cannot mint an input permit.
     */
    synchronized Consumption consumeFresh(NativeCalendarDateEnvelope fresh,Clock clock)throws Exception{
        need(!closed&&intent!=null&&modelConsumed&&!claimConsumed,"one unconsumed original proposal required");claimConsumed=true;
        try{
            requireDeadline(clock);source.requireUnchangedOriginal();source.requireFreshReplacement(fresh,modelCompleted,clock);
            need(fresh.monthRegion.contains(intent.cell),"cell no longer belongs to the same target month");long finalNow=requireDeadline(clock);
            consumption=new Consumption(this,fresh,finalNow);return consumption;
        }catch(Exception failure){closed=true;throw failure;}
    }
    private long requireDeadline(Clock clock){need(clock!=null,"actual elapsed-realtime clock required");long now=clock.elapsedRealtime();
        need(now>=modelCompleted&&now<deadline,"original calendar action deadline expired");return now;}
    /** Only an assessment of a full later FORM, never an action/selected-date
     * receipt. In this unconnected prototype even a match leaves date_verified=false.
     * The original year fact and later month/day are explicitly separate.
     */
    synchronized Map<String,Object> assessForm(Consumption own,NativeAppEvidence.Frame after,long actualReadElapsed){
        need(!closed&&own!=null&&own==consumption&&own.protocol==this&&claimConsumed&&after!=null,"same consumed protocol required");
        NativeAppEvidence.Frame before=source.facts;
        need(after.collectionComplete&&!after.nodesTruncated&&after.metadataObserved&&after.windowType==1
                &&(after.capture==null||!after.capture.formHistory())&&!before.observationId.equals(after.observationId)
                &&after.capturedElapsedMs>own.consumedElapsed&&actualReadElapsed>=after.capturedElapsedMs
                &&actualReadElapsed-after.capturedElapsedMs<=NativeCalendarDateEnvelope.FRESH_CAPTURE_MS,
                "new complete current FORM required; history cannot close date selection");
        need(before.taskId.equals(after.taskId)&&before.ownerSha.equals(after.ownerSha)&&before.targetSha.equals(after.targetSha)
                &&before.authorizationSha.equals(after.authorizationSha)&&before.selectionSha.equals(after.selectionSha)
                &&before.generation.equals(after.generation)&&before.packageName.equals(after.packageName)
                &&before.displayId==after.displayId&&NativeAppEvidence.sameProfileOwner(before.profileWindow,after.profileWindow),
                "FORM task/lease/target/profile owner changed");
        NativeAppEvidence.requireProfileTarget(source.profile,after.profileWindow);
        need(after.profileWindow!=null,"FORM actual full-UID window missing");
        after.profileWindow.requireMatches(source.profile,after.generation,after.displayId,after.windowId,after.profileWindow.taskId,actualReadElapsed);
        NativeCtripFlightPage.Page page=NativeCtripFlightPage.inspect(source.goal,after);
        boolean match=NativeCtripFlightPage.FORM.equals(page.phase)&&page.form!=null&&page.form.matches(source.goal.departureDate);
        Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("schema","hepta.native-calendar-form-assessment.v1");
        e.put("source_calendar",source.evidence());e.put("requested_date",source.goal.departureDate.toString());e.put("form_frame",after.evidence());
        e.put("target_month_day_and_route_passengers_match",match);e.put("year_observed_in_calendar",source.observedMonth.getYear());
        e.put("year_observed_in_form",false);e.put("actual_single_effect_receipt_attached",false);
        e.put("date_selection_verified",false);e.put("query_executed",false);e.put("business_verified",false);
        return NativeAppEvidence.immutableMap(e);
    }
    synchronized boolean consumed(){return claimConsumed;}
    synchronized boolean closed(){return closed;}
    @Override public synchronized void close(){closed=true;}
    static final class Consumption {
        private final NativeCalendarDateProtocol protocol;
        final NativeCalendarDateEnvelope fresh;
        final long consumedElapsed;
        private Consumption(NativeCalendarDateProtocol p,NativeCalendarDateEnvelope f,long at){protocol=p;fresh=f;consumedElapsed=at;}
        Map<String,Object> evidence(){Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("schema","hepta.native-calendar-protocol-consumption.v1");
            e.put("model_run_id",protocol.runId);e.put("raw_sha256",protocol.rawSha256);e.put("grammar_sha256",protocol.grammarSha256);
            e.put("source",protocol.source.evidence());e.put("fresh_capture",fresh.evidence());e.put("intent",protocol.intent.evidence());
            e.put("model_completed_elapsed_ms",protocol.modelCompleted);e.put("original_action_deadline_elapsed_ms",protocol.deadline);
            e.put("protocol_consumed_elapsed_ms",consumedElapsed);e.put("replay_allowed",false);
            e.put("actual_input_started",false);e.put("grants_broker_or_service_authority",false);return NativeAppEvidence.immutableMap(e);}
    }
    private static String grammar(NativeCalendarDateEnvelope e){
        String rule=literal("{")+" ws "+field("reason","reason-string")+comma()+field("action",value(NativeCalendarDateIntent.ACTION))
                +comma()+field("observation_id",value(e.facts.observationId))+comma()+field("package",value(NativeAppGoal.CTRIP_PACKAGE))
                +comma()+field("goal_sha256",value(e.goal.contractSha256))+comma()+field("date",value(e.goal.departureDate.toString()))
                +comma()+field("screen_sha256",value(e.pngSha256))+comma()+field("left","pixel-int")+comma()+field("top","pixel-int")
                +comma()+field("right","pixel-int")+comma()+field("bottom","pixel-int")+" ws "+literal("}");
        return "root ::= ws select-date ws\nselect-date ::= "+rule+"\nreason-string ::= "+literal("\"")+" json-char{1,96} "+literal("\"")
                +"\njson-char ::= [^\"\\\\\\x00-\\x1F] | "+literal("\\")+" [\"\\\\/bfnrt]\npixel-int ::= \"0\" | [1-9] [0-9]{0,3}\nws ::= [ \\t\\n\\r]{0,8}\n";
    }
    private static String field(String key,String expression){return value(key)+" ws "+literal(":")+" ws "+expression;}
    private static String comma(){return " ws "+literal(",")+" ws ";}
    private static String value(String text){return literal("\""+jsonEscape(text)+"\"");}
    private static String literal(String text){return "\""+text.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r").replace("\t","\\t")+"\"";}
    private static String jsonEscape(String text){return text.replace("\\","\\\\").replace("\"","\\\"");}
    private static void need(boolean ok,String why){if(!ok)throw new IllegalArgumentException(why);}
}
