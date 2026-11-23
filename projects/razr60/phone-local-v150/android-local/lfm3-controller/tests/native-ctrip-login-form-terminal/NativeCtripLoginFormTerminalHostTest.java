package org.trillionnium.hepta.local;
import android.net.LocalSocket;
import android.os.SystemClock;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.background.WindowOwnership;

/** Full actual Session/Domain/Phone/capture chain. Prior actions and Android IO
 * are explicit synthetic host outcomes, not live effects or new phone evidence.
 * The immutable existing login/XML fixtures provide page structure; all task,
 * clock and ownership values are synthetic. No account values are emitted. */
public final class NativeCtripLoginFormTerminalHostTest {
    interface Work {void run()throws Exception;}
    static int assertions;
    static final List<String> names=new ArrayList<String>();
    static final List<Map<String,Object>> results=new ArrayList<Map<String,Object>>();
    static void check(boolean value,String reason){assertions++;if(!value)throw new AssertionError(reason);}
    static void reject(Work w,String reason)throws Exception{boolean refused=false;try{w.run();}
        catch(IllegalArgumentException|IllegalStateException|IOException|ActionDecision.InvalidActionException e){refused=true;}
        check(refused,reason);}
    static void one(String name,Work w){
        LocalSocket.reset();SystemClock.now=NativeFormHistoryConsumersHostTest.START;
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);names.add(name);int before=assertions;
        try{w.run();row.put("passed",true);}catch(Throwable e){row.put("passed",false);row.put("error",e.toString());
            java.io.StringWriter stack=new java.io.StringWriter();e.printStackTrace(new java.io.PrintWriter(stack));row.put("stack",stack.toString());}
        row.put("assertions",assertions-before);results.add(row);
    }
    static JSONObject progress(NativeAppSession s){return new JSONObject(s.evidence()).getJSONObject("progress");}
    static final class Env implements AutoCloseable {
        final NativeFormHistoryConsumersHostTest.Fixture actual;
        final NativeAppProviderHostTest.Harness raw=new NativeAppProviderHostTest.Harness("explicit-terminal:"+UUID.randomUUID());
        NativeAppEvidence.Frame current;NotesCompletionEvidence.Frame completion;long now=NativeFormHistoryConsumersHostTest.START+500;
        int step;String run;
        Env()throws Exception{this(NativeFormHistoryConsumersHostTest.OWNER);}
        Env(String owner)throws Exception{actual=new NativeFormHistoryConsumersHostTest.Fixture(owner);}
        NativeAppEvidence.Frame remap(NativeAppEvidence.Frame f)throws Exception{
            WindowOwnership w=actual.window(f.capturedElapsedMs);List<NotesCompletionEvidence.Node> retained=new ArrayList<NotesCompletionEvidence.Node>();
            for(NativeAppEvidence.Node n:f.nodes)retained.add(new NotesCompletionEvidence.Node(n.id,n.packageName,n.text,n.label,n.viewId,null,
                    new int[]{n.left,n.top,n.right,n.bottom},n.editable,n.clickable,n.scrollable,n.enabled,n.password,ObservedChildText.notApplicable(),n.signature));
            completion=new NotesCompletionEvidence.Frame(f.observationId,f.packageName,96,actual.env.session.displayId(),
                    actual.env.session.generation,f.windowType,f.metadataObserved,f.nodesTruncated,retained);
            return new NativeAppEvidence.Frame(actual.task.taskId,actual.task.goal.ownerSha256,actual.task.target.targetSha256,
                    actual.authority.sha256,actual.selectionSha,f.observationId,f.packageName,actual.env.session.generation,
                    f.treeSha,f.stateSha,f.screenshotSha,NativeAppEvidence.hash("synthetic-rebound:"+f.sourceRecordSha),
                    TaskCompletionGate.webFrameSha(completion),actual.env.session.displayId(),96,f.rotation,f.width,f.height,
                    f.left,f.top,f.right,f.bottom,f.capturedElapsedMs,f.nodesTruncated,f.collectionComplete,f.nodes,f.windowType,f.metadataObserved,w);
        }
        void accept(NativeAppEvidence.Frame f)throws Exception{current=f;now=f.capturedElapsedMs+300;SystemClock.now=now;actual.task.observed(f);}
        void xml(String name)throws Exception{raw.time=now+100;accept(remap(raw.frame(name)));}
        void login()throws Exception{raw.time=now+100;accept(remap(NativeCtripLoginLoadingHostTest.frame(raw,NativeCtripLoginLoadingHostTest.login())));}
        ActionDecision action(String kind,String status,String node)throws Exception{
            JSONObject j=new JSONObject().put("action",kind).put("package",current.packageName).put("observation_id",current.observationId);
            if(node!=null)j.put("node_id",node).put("node_label",current.byId.get(node).label);
            if("done".equals(kind))j.put("status",status).put("summary","synthetic incomplete result");
            if("wait".equals(kind))j.put("milliseconds",100);
            if("type".equals(kind))j.put("text","synthetic forbidden input");
            return ActionDecision.parse(j.toString(),ActionDecision.IME_ACTION_SCHEMA);
        }
        ActionDecision purpose(String purpose)throws Exception{
            for(Map.Entry<String,String> e:actual.task.domain().purposes.entrySet())if(purpose.equals(e.getValue()))
                return action("back".equals(e.getKey())?"back":"click",null,"back".equals(e.getKey())?null:e.getKey());
            throw new AssertionError("missing original purpose "+purpose);
        }
        void issue(ActionDecision a,boolean accepted,boolean dispatched,boolean stale)throws Exception{
            run=UUID.randomUUID().toString().replace("-","");now+=10;SystemClock.now=now;actual.gate.check(a,run);
            actual.task.beforeModelAction(++step,a,run,now);
            actual.task.modelActionOutcome(a,run,accepted,dispatched,stale,NativeAppEvidence.hash("synthetic-outcome:"+step),++now);
        }
        void issue(String p)throws Exception{issue(purpose(p),true,true,false);}
        void atLogin(String day)throws Exception{
            xml("form"+day+".xml");issue("inspect_departure_year");xml("calendar14.xml");issue("return_from_calendar");
            xml("form"+day+".xml");issue("query_observed_form");xml("result"+day+".xml");login();
            check(NativeCtripFlightPage.LOGIN_REQUIRED.equals(actual.task.domain().phase),"actual provider login recognition");
            check(actual.task.domain().purposes.containsValue(NativeCtripFlightPage.LOGIN_EXIT),"same actual query admits one return");
        }
        NativeFormHistoryConsumersHostTest.Pack typed(boolean history)throws Exception{
            NativeFormHistoryConsumersHostTest.Pack p=new NativeFormHistoryConsumersHostTest.Pack(actual,now+100,history,history);
            completion=p.completion;accept(p.frame);return p;
        }
        NativeFormHistoryConsumersHostTest.Pack returned(boolean history)throws Exception{
            atLogin("17");issue(NativeCtripFlightPage.LOGIN_EXIT);return typed(history);
        }
        DecisionGrammar grammar(){
            NativeAppDomain d=actual.task.domain();Map<String,String> labels=new TreeMap<String,String>();
            for(NativeAppEvidence.Node n:current.nodes)labels.put(n.id,n.label);
            return DecisionGrammar.createImeAuthorized(current.observationId,current.packageName,Collections.<String>emptySet(),
                d.clickIds,d.editValues.keySet(),Collections.<String,ObservedScrollActions>emptyMap(),Collections.<String,ObservedImeEnter>emptyMap(),
                ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,current.observationId,current.packageName,labels),
                ObservedAppLabels.create(ObservedAppLabels.SCHEMA,current.observationId,current.packageName,Collections.<String,String>emptyMap()),
                actual.gate.frame(),true,d.toolMask(new HashSet<String>(Arrays.asList("click","type","back","open","scroll","submit","wait","done"))),d.resultReady);
        }
        void incompleteOnly(){
            NativeAppDomain d=actual.task.domain();JSONObject p=progress(actual.task);
            check(p.isNull("pending")&&p.getBoolean("flight_login_exit_attempted")&&p.getBoolean("flight_login_returned_to_form"),"one navigation closes and remains spent");
            check(d.incompleteLoginReturn&&!d.resultReady&&d.resultRecord()==null&&d.clickIds.isEmpty()&&d.editValues.isEmpty()&&!d.backAllowed,"no input or result authority");
            check(d.toolMask(null).equals(Collections.singleton("done"))&&d.doneStatuses().equals(new TreeSet<String>(Arrays.asList("failure","partial"))),"only incomplete done");
            check(!actual.task.ready(completion)&&actual.task.acceptSuccess(step,run,completion,true)==null,"cannot complete");
            actual.task.requireModelPlanning();
        }
        public void close()throws IOException{actual.close();}
    }
    public static void main(String[] args)throws Exception{
        Path out=Paths.get(args[0]);NativeProfileIdentityHostTest.workspace=Paths.get(args[1]);Files.createDirectories(NativeProfileIdentityHostTest.workspace);
        NativeAppProviderHostTest.fixtures=Paths.get(args[2]);NativeCtripLoginLoadingHostTest.fixtures=Paths.get(args[2]);
        one("typed_history_phone_to_session_closes_only_login_navigation",()->{try(Env e=new Env()){
            NativeFormHistoryConsumersHostTest.Pack p=e.returned(true);e.incompleteOnly();
            check(p.observed.captureKind.equals(ObservationCaptureEvidence.NATIVE_AX_FORM_HISTORY)&&p.frame.capture==p.capture,"actual Phone/copy preserves typed receipt");
            check(p.frame.capturedElapsedMs==p.start+100,"original A clock retained");
            check(Boolean.FALSE.equals(p.capture.formHistoryEvidence().get("business_completion_verified")),"history is no business proof");
        }});
        one("equal_native_ax_form_closes_only_login_navigation",()->{try(Env e=new Env()){NativeFormHistoryConsumersHostTest.Pack p=e.returned(false);e.incompleteOnly();check(p.frame.captureKind.equals(ObservationCaptureEvidence.NATIVE_AX),"actual equal AX kind");}});
        one("actual_authorized_grammar_and_domain_allow_only_incomplete_done",()->{try(Env e=new Env()){
            e.returned(true);DecisionGrammar g=e.grammar();check(g.actions.equals(Collections.singletonList("done"))&&!g.successAllowed,"actual authorized grammar excludes further tools and success");
            check(g.doneStatuses.equals(new TreeSet<String>(Arrays.asList("failure","partial"))),"actual grammar statuses");
            for(String kind:Arrays.asList("wait","back","click","type"))reject(()->e.actual.task.domain().requireCurrent(e.action(kind,null,("click".equals(kind)||"type".equals(kind))?e.current.nodes.get(0).id:null)),"no continuation "+kind);
            reject(()->e.actual.task.domain().requireCurrent(e.action("done","success",null)),"no success");
        }});
        one("done_failure_keeps_original_noneffect_null_guard",()->{try(Env e=new Env()){
            e.returned(true);ActionDecision a=e.action("done","failure",null);String r=UUID.randomUUID().toString().replace("-","");
            e.actual.gate.check(a,r);e.actual.task.beforeModelAction(++e.step,a,r,e.now+1);
            check(e.actual.task.actionGuard(a,r,e.current.observationId,e.now+2,e.now+8002)==null,"no effect guard");
            e.actual.task.modelActionOutcome(a,r,true,false,false,NativeAppEvidence.hash("synthetic-noneffect"),e.now+3);check(!e.actual.task.ready(e.completion),"failure never becomes success");
        }});
        one("done_partial_keeps_original_noneffect_null_guard",()->{try(Env e=new Env()){
            e.returned(true);ActionDecision a=e.action("done","partial",null);String r=UUID.randomUUID().toString().replace("-","");
            e.actual.gate.check(a,r);e.actual.task.beforeModelAction(++e.step,a,r,e.now+1);
            check(e.actual.task.actionGuard(a,r,e.current.observationId,e.now+2,e.now+8002)==null,"no effect guard");
            e.actual.task.modelActionOutcome(a,r,true,false,false,NativeAppEvidence.hash("synthetic-noneffect-partial"),e.now+3);check(!e.actual.task.ready(e.completion),"partial never becomes success");
        }});
        one("later_login_cannot_restart_exit_or_account_flow",()->{try(Env e=new Env()){e.returned(true);e.login();e.incompleteOnly();check(!e.actual.task.domain().purposes.containsValue(NativeCtripFlightPage.LOGIN_EXIT),"sticky once budget");}});
        one("later_result_cards_cannot_reopen_terminal_business_authority",()->{try(Env e=new Env()){e.returned(true);e.xml("result17.xml");e.incompleteOnly();check(e.actual.task.domain().resultRecord()==null,"cached later cards not completion");}});
        one("legacy_pixel_form_retains_existing_pending_contract",()->{try(Env e=new Env()){e.atLogin("17");e.issue(NativeCtripFlightPage.LOGIN_EXIT);e.xml("form17.xml");check(!progress(e.actual.task).isNull("pending")&&!e.actual.task.domain().incompleteLoginReturn,"new nativeText admission does not alter pixel contract");}});
        one("different_query_date_form_does_not_close_navigation",()->{try(Env e=new Env()){e.atLogin("14");e.issue(NativeCtripFlightPage.LOGIN_EXIT);e.typed(true);check(!progress(e.actual.task).isNull("pending")&&!progress(e.actual.task).getBoolean("flight_login_returned_to_form"),"17 cannot close original 14 query");}});
        one("form_without_actual_query_login_exit_cannot_create_terminal_proof",()->{try(Env e=new Env()){e.login();e.typed(true);check(!progress(e.actual.task).getBoolean("flight_login_returned_to_form")&&!e.actual.task.domain().incompleteLoginReturn,"no manufactured navigation proof");}});
        one("stale_unentered_login_return_cannot_create_arrival_proof",()->{try(Env e=new Env()){
            e.atLogin("17");e.issue(e.purpose(NativeCtripFlightPage.LOGIN_EXIT),false,false,true);e.typed(true);
            check(progress(e.actual.task).getBoolean("flight_login_exit_attempted")&&!progress(e.actual.task).getBoolean("flight_login_returned_to_form"),"spent unentered proposal is not navigation");
        }});
        one("original_fifteen_second_transition_budget_is_not_renewed",()->{try(Env e=new Env()){
            e.atLogin("17");e.issue(NativeCtripFlightPage.LOGIN_EXIT);e.now+=15001;e.typed(true);
            reject(()->e.actual.task.domain(),"late complete form cannot renew transition");
        }});
        one("foreign_actual_session_typed_receipt_cannot_close_navigation",()->{try(Env e=new Env();Env foreign=new Env()){
            e.atLogin("17");e.issue(NativeCtripFlightPage.LOGIN_EXIT);NativeFormHistoryConsumersHostTest.Pack p=foreign.typed(true);
            reject(()->e.actual.task.observed(p.frame),"different lease/selection/capture is rejected");
            check(!progress(e.actual.task).isNull("pending"),"foreign frame does not retire pending");
        }});
        one("query_history_and_single_exit_are_preserved_without_result_promotion",()->{try(Env e=new Env()){
            e.atLogin("17");JSONObject before=progress(e.actual.task);e.issue(NativeCtripFlightPage.LOGIN_EXIT);e.typed(true);JSONObject after=progress(e.actual.task);
            check(before.get("last_query_date").equals(after.get("last_query_date"))&&before.get("proved_form_date").equals(after.get("proved_form_date")),"actual prior query/date retained");
            check(before.getJSONArray("explicit_query_attempt_dates").toString().equals(after.getJSONArray("explicit_query_attempt_dates").toString()),"query attempts never reset");
            JSONArray transitions=after.getJSONArray("transitions");JSONObject last=transitions.getJSONObject(transitions.length()-1);
            check(last.getBoolean("navigation_only")&&!last.getBoolean("query_or_result_proof_created")&&!last.getBoolean("business_transition_verified"),"arrival cannot create result evidence");
            check(last.getBoolean("login_exit_ended_without_target_result"),"explicit truthful ending");
        }});
        NativeCtripCalendarMinimumHostTest.run(Paths.get(args[3]));
        boolean pass=true;for(Map<String,Object> r:results)pass&=Boolean.TRUE.equals(r.get("passed"));
        Map<String,Object> result=new LinkedHashMap<String,Object>();result.put("schema","hepta.native-ctrip-login-form-terminal-host.v1");result.put("all_pass",pass);
        result.put("case_names",names);result.put("cases",names.size());result.put("assertions",assertions);result.put("results",results);
        result.put("phone_operations",0);result.put("model_executed",false);result.put("business_verified",false);result.put("android_producer_tested",false);result.put("platform_effect_tested",false);
        result.put("boundary","Full actual Session/Domain/Phone/capture with synthetic host identity, clock, Android transport and prior action outcomes. Existing redacted page/XML fixtures remain unchanged.");
        Files.write(out,(new JSONObject(result).toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println("login form terminal "+names.size()+" cases / "+assertions+" assertions / pass="+pass);if(!pass)System.exit(1);
    }
}
