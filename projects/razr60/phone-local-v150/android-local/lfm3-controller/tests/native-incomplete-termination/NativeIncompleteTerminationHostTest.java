package org.trillionnium.hepta.local;

import android.net.LocalSocket;
import android.os.SystemClock;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.JSONObject;
import org.trillionnium.hepta.background.FixedIntentTarget;

/** Real added controller method/branch and real Session/Frame/grammar/phase
 * consumers. Android IO, installed checks and service lease carrier are explicit
 * host fixtures. No actual model, input, phone cleanup or success is claimed. */
public final class NativeIncompleteTerminationHostTest {
    private static final List<String> names=new ArrayList<String>();
    private static final List<Map<String,Object>> results=new ArrayList<Map<String,Object>>();
    private static int assertions;
    private static Path output;
    interface Work {void run()throws Exception;}
    static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    static String id(){return UUID.randomUUID().toString().replace("-","");}
    static void reject(Work body)throws Exception{
        boolean failed=false;
        try{body.run();}
        catch(Exception expected){failed=true;}
        check(failed,"actual refusal required");
    }
    static void one(String name,Work body){
        LocalSocket.reset();SystemClock.now=NativeFormHistoryConsumersHostTest.START;
        if(names.contains(name))throw new AssertionError("duplicate case");names.add(name);
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);int before=assertions;
        try{body.run();row.put("passed",true);}
        catch(Throwable failure){
            row.put("passed",false);row.put("error",failure.toString());
            java.io.StringWriter stack=new java.io.StringWriter();failure.printStackTrace(new java.io.PrintWriter(stack));
            row.put("stack",stack.toString());
        }
        row.put("assertions",assertions-before);results.add(row);
    }
    static final class Fixture implements AutoCloseable {
        final NativeFormHistoryConsumersHostTest.Fixture nativeOwner;
        final NativeFormHistoryConsumersHostTest.Pack pack;
        final NativeAppSession task;final TaskAuthorization.Gate gate;
        final NotesTaskPhaseGuard notes;final CalculatorTaskInputGuard calculator;
        final NotesTaskPhaseGuard.Domain notesDomain;final CalculatorTaskInputGuard.Domain calculatorDomain;
        final HeptaAccessibilityService service=new HeptaAccessibilityService();
        final ControllerIncompleteTerminalFixture controller;
        final Path directory;
        DecisionGrammar grammar;
        Fixture(boolean history)throws Exception{
            LocalSocket.reset();SystemClock.now=NativeFormHistoryConsumersHostTest.START;
            nativeOwner=new NativeFormHistoryConsumersHostTest.Fixture();
            pack=history?nativeOwner.history():nativeOwner.equalAx();task=nativeOwner.task;gate=nativeOwner.gate;
            task.observed(pack.frame);
            notes=new NotesTaskPhaseGuard(task.taskId,gate.authorization);
            calculator=new CalculatorTaskInputGuard(task.taskId,gate.authorization);
            notesDomain=notes.prepare(null,pack.completion).bind(Collections.<String>emptySet(),Collections.<String>emptySet(),
                    Collections.<String>emptySet(),Collections.<String,FixedIntentTarget>emptyMap());
            notes.publish(notesDomain);
            calculatorDomain=calculator.prepare(pack.completion).bind(Collections.<String>emptySet(),Collections.<String>emptySet(),
                    Collections.<String>emptySet(),Collections.<String,FixedIntentTarget>emptyMap(),Collections.<String>emptySet(),
                    Collections.<String,ObservedScrollActions>emptyMap());
            calculator.publish(calculatorDomain);
            service.fixtureBind(task.taskId,gate,notes,calculator);
            controller=new ControllerIncompleteTerminalFixture(service,task);
            grammar=grammar(pack.observation,new TreeSet<String>(Arrays.asList("failure","partial")));
            configure(grammar);
            directory=Files.createDirectory(output.resolve(id()));
        }
        DecisionGrammar grammar(String observation,Set<String> statuses){
            ObservedTargetLabels targets=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,observation,
                    pack.observed.packageName,Collections.<String,String>emptyMap());
            ObservedAppLabels apps=ObservedAppLabels.create(ObservedAppLabels.SCHEMA,observation,
                    pack.observed.packageName,Collections.<String,String>emptyMap());
            return DecisionGrammar.createFixedIntentAuthorized(observation,pack.observed.packageName,Collections.<String>emptySet(),
                    Collections.<String>emptySet(),Collections.<String>emptySet(),Collections.<String,ObservedScrollActions>emptyMap(),
                    Collections.<String,ObservedImeEnter>emptyMap(),targets,apps,gate.frame(),true,
                    Collections.<String,FixedIntentTarget>emptyMap(),Collections.<String,String>emptyMap(),
                    Collections.singleton("done"),false,statuses);
        }
        void configure(DecisionGrammar value){controller.configure(value,notesDomain,calculatorDomain,task.domain());}
        ActionDecision decision(String status)throws Exception{
            JSONObject raw=new JSONObject().put("reason","根据当前实际原生表单结束本次未完成任务")
                    .put("action","done").put("observation_id",pack.observation).put("package",pack.observed.packageName)
                    .put("status",status).put("summary","当前没有取得目标日期的完整航班结果");
            return ActionDecision.parse(raw.toString(),grammar.schema);
        }
        ControllerIncompleteTerminalFixture.Route route(ActionDecision a,String run,int step)throws Exception{
            return controller.route(task.taskId,directory.toFile(),step,pack.observed,a,run,gate,SystemClock.now+8000);
        }
        Path receiptPath(int step){return directory.resolve(String.format(Locale.ROOT,"step-%02d-controller-terminal.json",step));}
        JSONObject receipt(int step)throws Exception{return new JSONObject(new String(Files.readAllBytes(receiptPath(step)),StandardCharsets.UTF_8));}
        int outcomes(){
            int count=0;
            for(Map<String,Object> record:nativeOwner.journal){
                Object attempt=record.get("attempt");
                if(attempt instanceof Map&&((Map<?,?>)attempt).get("actual_action_receipt")!=null)count++;
            }
            return count;
        }
        Map<?,?> lastOutcome(){
            for(int i=nativeOwner.journal.size()-1;i>=0;i--){
                Object a=nativeOwner.journal.get(i).get("attempt");
                if(a instanceof Map&&((Map<?,?>)a).get("actual_action_receipt") instanceof Map)
                    return (Map<?,?>)((Map<?,?>)a).get("actual_action_receipt");
            }
            throw new AssertionError("actual outcome journal missing");
        }
        void verifyAccepted(ActionDecision a,String run,String status)throws Exception{
            ControllerIncompleteTerminalFixture.Route r=route(a,run,1);
            check(!r.originalPath&&status.equals(r.finalStatus),"actual early branch must finish incomplete");
            check(r.summary.contains(a.summary),"actual failure explanation retained");
            JSONObject receipt=receipt(1);
            check("hepta.controller-incomplete-terminal.v1".equals(receipt.getString("schema")),"explicit terminal receipt kind");
            check("controller".equals(receipt.getString("actor"))&&receipt.getBoolean("model_issued"),"controller consumes actual model decision");
            check(receipt.getBoolean("accepted")&&receipt.getBoolean("terminal_accepted"),"only validated terminal accepted");
            for(String key:Arrays.asList("dispatched","stale","service_perform_called","ui_freshness_checked",
                    "fresh_post_observation_performed","source_observation_is_post_action","business_completion_verified"))
                check(!receipt.getBoolean(key),"no invented UI/completion fact: "+key);
            check(receipt.isNull("action_execution"),"no fabricated action worker");
            check(task.taskId.equals(receipt.getString("task_id"))&&run.equals(receipt.getString("model_run_id")),"actual task/run bound");
            check(pack.observation.equals(receipt.getString("observation_id"))&&pack.capture.kind.equals(receipt.getString("source_capture_kind")),"original typed source retained");
            check(!Files.exists(directory.resolve("step-01-action.json")),"no platform action receipt synthesized");
            Map<?,?> outcome=lastOutcome();check(outcomes()==1,"one actual native outcome");
            check(Boolean.TRUE.equals(outcome.get("accepted"))&&Boolean.FALSE.equals(outcome.get("dispatched")),"native Session records actual no-effect acceptance");
            check(ObservationCaptureEvidence.hash(Files.readAllBytes(receiptPath(1))).equals(outcome.get("step_action_record_sha256")),"native journal SHA binds actual durable bytes");
            check(!task.ready(pack.completion),"failure must never make result ready");
        }
        public void close()throws IOException{nativeOwner.close();}
    }
    public static void main(String[] args)throws Exception{
        output=Paths.get(args[1]);Files.createDirectories(output);
        NativeProfileIdentityHostTest.workspace=output;
        one("historical_failure_consumes_without_ui_or_post_observation",()->{
            try(Fixture f=new Fixture(true)){
                SystemClock.now=f.pack.captured+60000;
                f.verifyAccepted(f.decision("failure"),id(),"failed");
                check(f.pack.capture.formHistory(),"actual historical typed Phone source");
            }
        });
        one("historical_partial_consumes_without_ui_or_success",()->{
            try(Fixture f=new Fixture(true)){f.verifyAccepted(f.decision("partial"),id(),"partial");}
        });
        one("ordinary_ax_failure_keeps_actual_native_journal",()->{
            try(Fixture f=new Fixture(false)){f.verifyAccepted(f.decision("failure"),id(),"failed");check(!f.pack.capture.formHistory(),"ordinary AX source");}
        });
        one("same_model_run_cannot_be_consumed_twice",()->{
            try(Fixture f=new Fixture(true)){
                ActionDecision a=f.decision("failure");String run=id();f.verifyAccepted(a,run,"failed");
                byte[] before=Files.readAllBytes(f.receiptPath(1));reject(()->f.route(a,run,2));
                check(f.outcomes()==1&&!Files.exists(f.receiptPath(2)),"used run refused before new accepted receipt");
                check(Arrays.equals(before,Files.readAllBytes(f.receiptPath(1))),"old terminal bytes unchanged");
            }
        });
        one("wrong_task_is_rejected_before_terminal_journal",()->{
            try(Fixture f=new Fixture(true)){
                int count=f.nativeOwner.journal.size();ActionDecision a=f.decision("failure");
                reject(()->f.controller.route(id(),f.directory.toFile(),1,f.pack.observed,a,id(),f.gate,SystemClock.now+8000));
                check(f.nativeOwner.journal.size()==count&&!Files.exists(f.receiptPath(1)),"wrong task has no attempted outcome");
            }
        });
        one("same_value_different_gate_is_rejected",()->{
            try(Fixture f=new Fixture(true)){
                TaskAuthorization.Gate other=f.gate.authorization.bind(f.task.taskId);ActionDecision a=f.decision("failure");
                reject(()->f.controller.route(f.task.taskId,f.directory.toFile(),1,f.pack.observed,a,id(),other,SystemClock.now+8000));
                check(f.outcomes()==0&&!Files.exists(f.receiptPath(1)),"different actual Gate unavailable");
            }
        });
        one("service_replaced_gate_is_rejected",()->{
            try(Fixture f=new Fixture(true)){
                f.service.fixtureBind(f.task.taskId,f.gate.authorization.bind(f.task.taskId),f.notes,f.calculator);
                reject(()->f.route(f.decision("failure"),id(),1));
                check(f.outcomes()==0&&!Files.exists(f.receiptPath(1)),"verbatim service current-Gate check rejects replacement");
            }
        });
        one("wrong_observation_grammar_is_rejected",()->{
            try(Fixture f=new Fixture(true)){
                f.configure(f.grammar(id(),new TreeSet<String>(Arrays.asList("failure","partial"))));
                reject(()->f.route(f.decision("failure"),id(),1));
                check(f.outcomes()==0&&!Files.exists(f.receiptPath(1)),"actual app-label grammar binding rejects wrong observation");
            }
        });
        one("excluded_done_status_is_rejected",()->{
            try(Fixture f=new Fixture(true)){
                f.configure(f.grammar(f.pack.observation,Collections.singleton("partial")));
                reject(()->f.route(f.decision("failure"),id(),1));
                check(f.outcomes()==0&&!Files.exists(f.receiptPath(1)),"actual grammar status ceiling retained");
            }
        });
        one("retired_or_replaced_native_domain_is_rejected",()->{
            try(Fixture f=new Fixture(true)){
                NativeFormHistoryConsumersHostTest.Pack newer=f.nativeOwner.history();f.task.observed(newer.frame);
                reject(()->f.route(f.decision("failure"),id(),1));
                check(f.outcomes()==0&&!Files.exists(f.receiptPath(1)),"old same-task domain object is unusable");
            }
            try(Fixture f=new Fixture(true)){
                f.task.retire();reject(()->f.route(f.decision("failure"),id(),1));
                check(f.outcomes()==0,"actual retired Session refuses");
            }
        });
        one("success_remains_on_original_controller_path",()->{
            try(Fixture f=new Fixture(true)){
                ActionDecision a=f.decision("success");int count=f.nativeOwner.journal.size();
                ControllerIncompleteTerminalFixture.Route r=f.route(a,id(),1);
                check(r.originalPath&&"unchanged".equals(r.finalStatus),"success is not consumed by new branch");
                check(f.nativeOwner.journal.size()==count&&!Files.exists(f.receiptPath(1)),"no fabricated success receipt");
                reject(()->f.grammar.requireCompletionStatus(a));
                check(!f.task.ready(f.pack.completion),"original completion contract still required");
            }
        });
        one("non_native_failure_remains_on_original_path",()->{
            try(Fixture f=new Fixture(true)){
                f.controller.activeNativeTask=null;ControllerIncompleteTerminalFixture.Route r=f.route(f.decision("failure"),id(),1);
                check(r.originalPath&&!Files.exists(f.receiptPath(1)),"non-native route unchanged");
            }
        });
        one("cancelled_task_cannot_consume",()->{
            try(Fixture f=new Fixture(true)){
                f.controller.cancelled.set(true);reject(()->f.route(f.decision("failure"),id(),1));
                check(f.outcomes()==0&&!Files.exists(f.receiptPath(1)),"cancel refuses before new journal");
            }
        });
        one("expired_task_cannot_consume",()->{
            try(Fixture f=new Fixture(true)){
                ActionDecision a=f.decision("failure");
                reject(()->f.controller.route(f.task.taskId,f.directory.toFile(),1,f.pack.observed,a,id(),f.gate,SystemClock.now-1));
                check(f.outcomes()==0&&!Files.exists(f.receiptPath(1)),"original task deadline remains authoritative");
            }
        });
        one("receipt_collision_never_creates_accepted_outcome",()->{
            try(Fixture f=new Fixture(true)){
                byte[] original="preexisting-record".getBytes(StandardCharsets.UTF_8);
                Files.write(f.receiptPath(1),original,StandardOpenOption.CREATE_NEW);
                reject(()->f.route(f.decision("failure"),id(),1));
                check(f.outcomes()==0&&Arrays.equals(original,Files.readAllBytes(f.receiptPath(1))),"write refusal cannot become accepted outcome");
                f.task.retire();Map<String,Object> retired=f.nativeOwner.journal.get(f.nativeOwner.journal.size()-1);
                check(Boolean.TRUE.equals(retired.get("pending_action")),"unsealed native attempt remains visible at retirement");
            }
        });
        one("invalid_model_run_is_rejected",()->{
            try(Fixture f=new Fixture(true)){
                reject(()->f.route(f.decision("failure"),"not-an-actual-run-id",1));
                check(f.outcomes()==0&&!Files.exists(f.receiptPath(1)),"actual Gate validates model run identity");
            }
        });
        one("native_retirement_and_terminal_cannot_promote_failure",()->{
            try(Fixture f=new Fixture(true)){
                String run=id();f.verifyAccepted(f.decision("failure"),run,"failed");f.task.retire();
                Map<String,Object> retired=f.nativeOwner.journal.get(f.nativeOwner.journal.size()-1);
                check(Boolean.TRUE.equals(retired.get("action_domain_retired"))&&Boolean.FALSE.equals(retired.get("pending_action")),"real outcome cleared inFlight before retirement");
                Map<String,Object> terminal=f.task.terminal(f.pack.completion,f.gate.frame(),1,run,false,false,false,false,false,
                        false,false,false,null,false,f.task.taskId,null,null);
                check(Boolean.FALSE.equals(terminal.get("completion_verified"))&&Boolean.FALSE.equals(terminal.get("business_verified")),"actual terminal never promotes incomplete claim");
                check(Boolean.FALSE.equals(terminal.get("all_cleanup_known")),"absence of real cleanup is not synthesized");
            }
        });
        one("malformed_done_raw_is_rejected_by_actual_parser",()->{
            try(Fixture f=new Fixture(true)){
                String raw=new JSONObject().put("reason","host").put("action","done").put("status","failure")
                        .put("summary","incomplete").put("package",f.pack.observed.packageName)
                        .put("observation_id",f.pack.observation).put("node_id","n1").toString();
                reject(()->ActionDecision.parse(raw,f.grammar.schema));
                check(f.outcomes()==0&&!Files.exists(f.receiptPath(1)),"malformed tool never reaches consumer");
            }
        });
        boolean passed=true;for(Map<String,Object> row:results)passed&=Boolean.TRUE.equals(row.get("passed"));
        Map<String,Object> report=new LinkedHashMap<String,Object>();report.put("all_pass",passed);
        report.put("cases",names.size());report.put("assertions",assertions);report.put("case_names",names);report.put("results",results);
        report.put("model_executed",false);report.put("platform_effect_tested",false);report.put("real_cleanup_tested",false);
        report.put("actual_methods_executed","LTC new incomplete consumer/branch, Session/Frame/parser/grammar/phase gates and same-Gate service checks");
        Files.write(Paths.get(args[0]),(new JSONObject(report).toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println(new JSONObject(report).toString());if(!passed)System.exit(1);
    }
}
