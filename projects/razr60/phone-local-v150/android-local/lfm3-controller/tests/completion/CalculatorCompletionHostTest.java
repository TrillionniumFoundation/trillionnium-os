package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Frame;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Node;

/** All UI/Android/model inputs are synthetic. No replay of unavailable historical bytes. */
public final class CalculatorCompletionHostTest {
    private static final String P=CalculatorCompletionEvidence.PACKAGE,F=CalculatorCompletionEvidence.FORMULA,R=CalculatorCompletionEvidence.RESULT;
    private static final String H="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",TASK=id(5000);
    private static final String GENERATION="11111111-1111-1111-1111-111111111111";
    private static final String OWNER=owner("31","47");
    private static final List<String> passed=new ArrayList<String>();private static int observations=100;
    interface Case{void run()throws Exception;}
    static void test(String name,Case body)throws Exception{body.run();passed.add(name);System.out.println("PASS "+name);}
    static void check(boolean b,String why){if(!b)throw new AssertionError(why);}
    static String id(int n){return String.format(Locale.ROOT,"%032x",n);}
    static String owner(String left,String right){return "打开计算器，在当前主输入区计算 "+left+" 乘以 "+right+"，确认当前结果框显示计算结果后结束任务。";}
    static Node n(String id,String text,String view,boolean editable){return new Node(id,P,text,text,view,editable?ObservedImeEnter.hash(text):null,new int[]{10,100,500,200},editable,true,false,true,false);}
    static Frame frame(String formula,String result,String key){
        return new Frame(id(++observations),P,7,5,GENERATION,1,true,false,Arrays.asList(
                n("n0",result,R,true),n("n1",formula,F,true),n("n2",key,P+":id/synthetic_observed_key",false)));
    }
    static Frame with(Frame f,List<Node> nodes){return new Frame(id(++observations),f.packageName,f.windowId,f.displayId,f.backgroundGeneration,f.windowType,f.metadataObserved,f.nodesTruncated,nodes);}
    static Frame domain(Frame f,int window,int display,String generation){return new Frame(id(++observations),P,window,display,generation,1,true,false,f.nodes);}
    static NotesCompletionEvidence.Installed installed(){return new NotesCompletionEvidence.Installed(P,10003,Collections.singletonMap("base",H));}
    static TaskCompletionGate gate(){return gate(OWNER);}
    static TaskCompletionGate gate(String owner){TaskCompletionGate g=new TaskCompletionGate(TASK,owner,TaskAuthorization.parse(owner));g.bindInstalled(installed());return g;}
    static ActionDecision action(Frame f,String tool,String node,String text)throws Exception{
        JSONObject o=new JSONObject().put("reason","synthetic model action against supplied observed target").put("action",tool).put("observation_id",f.observationId).put("package",P);
        if("click".equals(tool)||"type".equals(tool)){
            Node target=null;for(Node n:f.nodes)if(n.id.equals(node))target=n;
            o.put("node_label",target==null?"missing":ObservedTargetLabels.project(target.label)).put("node_id",node);
        }
        if("type".equals(tool))o.put("text",text);
        if("done".equals(tool))o.put("status","success").put("summary","model claim only");
        if("wait".equals(tool))o.put("duration_ms",100);
        return ActionDecision.parse(o.toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA);
    }
    static Frame typedInput(TaskCompletionGate g)throws Exception{
        Frame before=frame("","0","="),after=frame("","31×47","=");
        g.action(1,id(1),action(before,"type","n0","31×47"),true,true,false,before,after,null);return after;
    }
    static Frame typed(TaskCompletionGate g)throws Exception{
        Frame before=typedInput(g),after=frame("31×47","1457","=");
        g.action(2,id(2),action(before,"click","n2",null),true,true,false,before,after,null);return after;
    }
    static Frame keys(TaskCompletionGate g)throws Exception{
        String expression=g.contract.calculator.expression;Frame after=null;int step=0;
        for(int index=0;index<expression.length();index++){
            String key=expression.substring(index,index+1),prior=index==0?"0":expression.substring(0,index);
            Frame before=frame("",prior,key);after=frame("",expression.substring(0,index+1),key);
            g.action(++step,id(step),action(before,"click","n2",null),true,true,false,before,after,null);
        }
        Frame before=frame("",expression,"=");after=frame(expression,g.contract.calculator.result,"=");
        g.action(++step,id(step),action(before,"click","n2",null),true,true,false,before,after,null);return after;
    }
    static boolean fields(Frame f){return CalculatorCompletionEvidence.fields(f,CalculatorCompletionEvidence.Goal.parse(OWNER),installed()).matched;}
    static void pureCases()throws Exception{
        test("exact_owner_template_local_product_and_no_answer_in_prompt",()->{
            TaskCompletionGate g=gate();check(TaskCompletionGate.CALCULATOR.equals(g.contract.kind),"complete owner recognized");
            check("31×47".equals(g.contract.calculator.expression)&&"1457".equals(g.contract.calculator.result),"independent expected value");
            check("493".equals(gate(owner("17","29")).contract.calculator.result),"second exact driver owner supported");
            check("999999998000000001".equals(gate(owner("999999999","999999999")).contract.calculator.result),"bounded multiplication avoids overflow");
            check(!new JSONObject(g.prompt(frame("","0","="))).toString().contains("1457"),"oracle answer never added to prompt");
            for(String s:Arrays.asList("不要"+OWNER,"“"+OWNER+"”",OWNER+"再新建笔记。",OWNER+"\n",OWNER.replace("乘以","加上"),owner("031","47"),owner("1000000000","47"),OWNER.replace("31","３１"),OWNER.replace("31","31+1"))){
                TaskCompletionGate unknown=new TaskCompletionGate(TASK,s,TaskAuthorization.parse(s));check(!TaskCompletionGate.CALCULATOR.equals(unknown.contract.kind),"unsupported owner remains unknown: "+s);
            }
        });
        test("full_model_primary_type_then_equal_current_pair_verifies",()->{TaskCompletionGate g=gate();Frame f=typed(g);check(g.successClaim(3,id(3),f).verified,"primary expression readback then actual equal and current pair verifies");});
        test("formula_only_type_cannot_borrow_preexisting_expected_result",()->{
            for(String originalFormula:Arrays.asList("","7×11")){
                TaskCompletionGate g=gate();Frame before=frame(originalFormula,"1457","="),after=frame("31×47","1457","=");
                g.action(1,id(1),action(before,"type","n1","31×47"),true,true,false,before,after,null);
                check(!g.successClaim(2,id(2),after).verified,"editing formula beside a preexisting answer is not calculation");
                check(Boolean.FALSE.equals(((Map<?,?>)g.prompt(after).get("calculator")).get("input_expression_observed_after_model_tool")),"formula target cannot establish primary input entry");
            }
            TaskCompletionGate g=gate();Frame before=frame("","0","="),expression=frame("","31×47","="),after=frame("31×47","1457","=");
            g.action(1,id(1),action(before,"type","n1","31×47"),true,true,false,before,expression,null);
            g.action(2,id(2),action(expression,"click","n2",null),true,true,false,expression,after,null);
            check(!g.verified(after),"formula-target type cannot start a proof even if primary text also changes");
        });
        test("primary_type_requires_expression_readback_and_never_produces_result",()->{
            for(String initial:Arrays.asList("0","1457")){
                TaskCompletionGate g=gate();Frame before=frame("",initial,"="),after=frame("31×47","1457","=");
                g.action(1,id(1),action(before,"type","n0","31×47"),true,true,false,before,after,null);
                check(!g.successClaim(2,id(2),after).verified,"direct final pair after type has no primary expression readback");
                Frame expression=frame("","31×47","=");
                g.action(3,id(3),action(expression,"click","n2",null),true,true,false,expression,after,null);
                check(!g.verified(after),"late equals cannot recover missing model expression-entry proof");
            }
        });
        test("primary_expression_type_without_actual_equal_remains_partial",()->{
            TaskCompletionGate g=gate();Frame expression=typedInput(g),after=frame("31×47","1457","=");
            check(!g.successClaim(2,id(2),expression).verified,"expression input by itself is not a result");
            g.observed(after);check(!g.successClaim(3,id(3),after).verified,"unbound passive result observation does not replace actual equals action");
        });
        test("typed_expression_requires_accepted_dispatched_fresh_equal_click",()->{
            for(int mode=0;mode<4;mode++){
                TaskCompletionGate g=gate();Frame before=typedInput(g),after=frame("31×47","1457","=");
                if(mode==3)before=frame("","31×47","菜单");
                g.action(2,id(2),action(before,"click","n2",null),mode!=0,mode!=1,mode==2,before,after,null);
                check(!g.verified(after),"only accepted dispatched nonstale equals creates calculation proof");
            }
        });
        test("all_observed_key_prefixes_then_equal_verify",()->{TaskCompletionGate g=gate();Frame f=keys(g);check(g.successClaim(7,id(7),f).verified,"every model key and equals transition required");TaskCompletionGate other=gate(owner("17","29"));check(other.verified(keys(other)),"second prepared goal uses same proof path");});
        test("preexisting_expected_pair_done_is_partial",()->{TaskCompletionGate g=gate();Frame f=frame("31×47","1457","=");g.observed(f);check(!g.successClaim(1,id(1),f).verified,"preexisting pair is not this task computation");});
        test("only_last_digit_or_equal_on_preexisting_expression_cannot_verify",()->{
            for(String initial:Arrays.asList("31×4","31×47")){
                TaskCompletionGate g=gate();String label=initial.endsWith("47")?"=":"7";Frame b=frame("",initial,label),a=frame("31×47","1457",label);
                g.action(1,id(1),action(b,"click","n2",null),true,true,false,b,a,null);check(!g.verified(a),"initial partial expression has no this-task key chain");
            }
        });
        test("initial_correct_value_and_unrelated_click_cannot_verify",()->{TaskCompletionGate g=gate();Frame b=frame("31×47","1457","菜单"),a=frame("31×47","1457","菜单");g.action(1,id(1),action(b,"click","n2",null),true,true,false,b,a,null);check(!g.verified(a),"irrelevant actual effect cannot claim old result");});
        test("history_row_click_cannot_supply_key_or_result_proof",()->{
            TaskCompletionGate g=gate();Frame base=frame("","0","3"),b=with(base,Arrays.asList(base.nodes.get(0),base.nodes.get(1),n("n2","3",P+":id/item_result",false))),a=frame("","3","3");
            g.action(1,id(1),action(b,"click","n2",null),true,true,false,b,a,null);
            check(Integer.valueOf(0).equals(((Map<?,?>)g.prompt(a).get("calculator")).get("observed_key_prefix_length")),"historical node is never an input key");
            Frame finalBase=frame("31×47","1457","=");
            check(!fields(with(finalBase,Arrays.asList(finalBase.nodes.get(0),n("n1","31×47",P+":id/item_formula",true)))) ,"history formula never substitutes current formula");
            check(!fields(with(finalBase,Arrays.asList(n("n0","1457",P+":id/item_result",true),finalBase.nodes.get(1)))) ,"history result never substitutes current result");
        });
        test("arbitrary_numbers_wrong_formula_and_noncanonical_result_refused",()->{
            for(String value:Arrays.asList("1458","11457","1457abc","1,457","1457.0","1.457e3","１４５７","1457\n"))check(!fields(frame("31×47",value,"=")),"exact canonical result required: "+value);
            check(!fields(frame("47×31","1457","=")),"same product from different expression rejected");
            Frame b=frame("","0","=");TaskCompletionGate g=gate();Frame a=frame("31×47","1457","=");
            g.action(1,id(1),action(b,"type","n0","1457"),true,true,false,b,a,null);check(!g.verified(a),"typing oracle answer cannot supply calculation proof");
        });
        test("current_field_uniqueness_complete_hash_and_scope_required",()->{
            Frame f=frame("31×47","1457","=");List<Node> duplicate=new ArrayList<Node>(f.nodes);duplicate.add(n("n3","1457",R,true));check(!fields(with(f,duplicate)),"duplicate current result refused");
            Node bad=new Node("n0",P,"1457","1457",R,H,new int[]{10,100,500,200},true,true,false,true,false);
            check(!fields(with(f,Arrays.asList(bad,f.nodes.get(1)))),"complete input digest mismatch refused");
            check(!fields(new Frame(f.observationId,P,7,5,GENERATION,1,true,true,f.nodes)),"truncated node graph refused");
            check(!fields(new Frame(f.observationId,P,7,5,GENERATION,1,false,false,f.nodes)),"unobserved metadata refused");
            check(!fields(new Frame(f.observationId,"other.pkg",7,5,GENERATION,1,true,false,f.nodes)),"wrong root package refused");
            check(!fields(domain(f,7,5,null)),"secondary display without generation refused");
            check(!fields(domain(f,7,0,GENERATION)),"foreground with generation refused");
        });
        test("rejected_undispatched_stale_and_replayed_actions_never_verify",()->{
            for(int mode=0;mode<4;mode++){
                TaskCompletionGate g=gate();Frame b=frame("","0","="),a=frame("31×47","1457","=");if(mode==3)a=new Frame(b.observationId,P,7,5,GENERATION,1,true,false,a.nodes);
                g.action(1,id(1),action(b,"type","n0","31×47"),mode!=0,mode!=1,mode==2,b,a,null);check(!g.verified(a),"dispatch and distinct live observations required");
            }
            TaskCompletionGate g=gate();Frame f=typed(g),b=frame("","0","=");g.action(1,id(1),action(b,"type","n0","31×47"),true,true,false,b,f,null);check(!g.verified(f),"replayed model step cannot retain proof");
        });
        test("cross_window_display_generation_and_changed_final_are_refused",()->{
            for(Frame a:Arrays.asList(domain(frame("31×47","1457","="),8,5,GENERATION),domain(frame("31×47","1457","="),7,6,GENERATION),domain(frame("31×47","1457","="),7,5,"22222222-2222-2222-2222-222222222222"))){
                TaskCompletionGate g=gate();Frame b=frame("","0","=");g.action(1,id(1),action(b,"type","n0","31×47"),true,true,false,b,a,null);check(!g.verified(a),"transition cannot cross window/display/generation");
            }
            TaskCompletionGate g=gate();Frame f=typed(g);check(!g.successClaim(3,id(3),f,false).verified,"controller final instability prevents success");
            g.observed(frame("31×47","1458","="));check(!g.verified(f),"changed observation retires result proof even if old frame is replayed");
        });
        test("exact_action_target_run_and_nonderived_key_origin_required",()->{
            Frame b=frame("","0","3"),a=frame("","3","3");
            for(String which:Arrays.asList("label","node")){
                TaskCompletionGate g=gate();JSONObject raw=new JSONObject().put("reason","synthetic wrong target").put("action","click").put("observation_id",b.observationId).put("package",P)
                        .put("node_label","label".equals(which)?"wrong":"3").put("node_id","node".equals(which)?"n9":"n2");
                g.action(1,id(1),ActionDecision.parse(raw.toString(),ActionDecision.FIXED_INTENT_ACTION_SCHEMA),true,true,false,b,a,null);
                check(Integer.valueOf(0).equals(((Map<?,?>)g.prompt(a).get("calculator")).get("observed_key_prefix_length")),"actual source label and node required");
            }
            Node key=new Node("n2",P,"3","3",P+":id/synthetic_observed_key",null,new int[]{10,100,500,200},false,true,false,true,false,
                    new ObservedChildText.Result("3","derived",false,1,Collections.<ObservedChildText.Source>emptyList()),null);
            Frame derived=with(b,Arrays.asList(b.nodes.get(0),b.nodes.get(1),key));TaskCompletionGate g=gate();
            g.action(1,id(1),action(derived,"click","n2",null),true,true,false,derived,a,null);
            check(Integer.valueOf(0).equals(((Map<?,?>)g.prompt(a).get("calculator")).get("observed_key_prefix_length")),"derived key text cannot be a key source");
            g=gate();Frame result=typed(g),initial=frame("","0","=");g.action(3,id(1),action(initial,"type","n0","31×47"),true,true,false,initial,result,null);check(!g.verified(result),"native run cannot be reused under a larger step");
        });
        test("interrupted_prefix_and_retired_window_cannot_resume_old_proof",()->{
            TaskCompletionGate g=gate();Frame b=frame("","0","3"),a=frame("","3","3");g.action(1,id(1),action(b,"click","n2",null),true,true,false,b,a,null);
            g.observed(frame("","9","1"));b=frame("","3","1");a=frame("","31","1");g.action(2,id(2),action(b,"click","n2",null),true,true,false,b,a,null);
            check(Integer.valueOf(0).equals(((Map<?,?>)g.prompt(a).get("calculator")).get("observed_key_prefix_length")),"changed prefix cannot borrow retired progress");
            g=gate();Frame result=typed(g);g.observed(domain(result,8,5,GENERATION));check(!g.verified(result),"old completed frame cannot survive a window change");
        });
        test("missing_and_invalidated_installed_identity_refused",()->{
            TaskCompletionGate missing=new TaskCompletionGate(TASK,OWNER,TaskAuthorization.parse(OWNER));Frame f=typed(missing);check(!missing.verified(f),"no package identity no proof");
            TaskCompletionGate g=gate();f=typed(g);g.invalidateInstalled("synthetic installation changed");check(!g.verified(f),"changed APK cannot retain completion");
        });
    }

    static PhoneObservation.Node row(String id,String text,String view){return new PhoneObservation.Node(id,P,"EditText",view,text,"",new Rect(10,100,500,200),true,true,false,true,true,false,ObservedChildText.notApplicable(),ObservedScrollActions.observed(Collections.<String>emptyList()),ObservedImeEnter.UNKNOWN,ObservedImeEnter.hash(text),false);}
    static final class Model implements LocalInference {
        final QualificationScopeHostTest.Env e;final String mode;int calls,ends;String task;String formula="",primary="0";
        final CountDownLatch finalVerifyEntered=new CountDownLatch(1),releaseFinalVerify=new CountDownLatch(1);
        volatile boolean finalVerifyStackObserved;
        Model(QualificationScopeHostTest.Env e,String mode){this.e=e;this.mode=mode;}
        public LocalRuntimeConfig configuration(){return e.runtime;}
        public void beginTask(String id){task=id;}
        void setup(){
            e.service.prepare(P);e.service.node.text="3";e.service.node.viewId=P+":id/synthetic_observed_key";
            e.service.node.editable=false;e.service.node.scrollable=false;
            formula="preexisting".equals(mode)?"31×47":"";primary="preexisting".equals(mode)?"1457":"0";
            e.service.observationDigest=()->ObservedImeEnter.hash(formula+"|"+primary+"|"+e.service.node.text);
            e.service.observationRows=()->Arrays.asList(
                    new PhoneObservation.Node("n0",P,"Button",e.service.node.viewId,e.service.node.text,"",new Rect(10,300,500,400),true,false,false,true,true,false,ObservedChildText.notApplicable(),ObservedScrollActions.observed(Collections.<String>emptyList()),ObservedImeEnter.UNKNOWN,null,false),
                    row("n1",formula,F),row("n2",primary,R));
            e.service.effectHook=()->{
                int actions=e.service.node.actions;
                if(actions<=5){primary="31×47".substring(0,actions);e.service.node.text=actions<5?"31×47".substring(actions,actions+1):"=";}
                else{formula="31×47";primary="wrong_result".equals(mode)?"1458":"1457";e.service.node.text="=";}
            };
        }
        public TaskCleanup endTask(){
            ends++;if("changed_apk".equals(mode))try{QualificationScopeHostTest.write(Paths.get(e.pm.packages.get(P).applicationInfo.sourceDir),"changed installed bytes".getBytes(StandardCharsets.UTF_8),0644);}catch(Exception error){throw new IllegalStateException(error);}
            if(mode.startsWith("stop_in_final_verify"))e.service.packageManagerReadHook=()->{
                for(StackTraceElement frame:Thread.currentThread().getStackTrace())
                    if(frame.getClassName().equals("org.trillionnium.hepta.local.QualificationScopeConfig$CompletionInstalledIdentity")&&"verify".equals(frame.getMethodName()))finalVerifyStackObserved=true;
                if(!finalVerifyStackObserved)throw new AssertionError("IO hook must execute inside actual completion-installed verify");
                e.service.packageManagerReadHook=null;finalVerifyEntered.countDown();
                try{if(!releaseFinalVerify.await(5,TimeUnit.SECONDS))throw new AssertionError("host must release final identity verification");}
                catch(InterruptedException error){Thread.currentThread().interrupt();throw new IllegalStateException(error);}
            };
            if("stop_in_final_verify_unknown_cleanup".equals(mode))return new TaskCleanup(false,true,false,null,id(99),task,false,null);
            return new TaskCleanup(true,true,true,0,id(99),task,!"bad_cleanup".equals(mode),H);
        }
        public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,int maximum,long timeout,Callback callback){
            calls++;try{
                check(prompt.endsWith("\nOWNER\n"+OWNER),"immutable owner preserved");
                if(calls==1&&!"preexisting".equals(mode))check(!prompt.contains("1457"),"expected answer never supplied before model computes");
                String tool=calls<=6&&!"preexisting".equals(mode)?"click":"done";
                JSONObject action=new JSONObject().put("reason","synthetic actual-controller IO action").put("action",tool).put("package",P).put("observation_id",grammar.observationId);
                if("click".equals(tool))action.put("node_label",ObservedTargetLabels.project(e.service.node.text)).put("node_id","n0");
                else action.put("status","success").put("summary","synthetic model success claim");
                callback.onSuccess(action.toString(),id(calls));
            }catch(Exception error){throw new IllegalStateException(error);}return ()->{};
        }
    }
    static void controllerCase(String mode,boolean verified)throws Exception{
        try(QualificationScopeHostTest.Env e=new QualificationScopeHostTest.Env(false)){
            Model m=new Model(e,mode);m.setup();e.controller=new LocalTaskController(e.service,m);
            CountDownLatch done=new CountDownLatch(1);LocalTaskController.TaskResult[] result=new LocalTaskController.TaskResult[1];
            check(e.controller.start(OWNER,null,new LocalTaskController.Listener(){public void onState(String state){}public void onFinished(LocalTaskController.TaskResult r){result[0]=r;done.countDown();}}),"ordinary controller starts");
            if(mode.startsWith("stop_in_final_verify")){
                try{check(m.finalVerifyEntered.await(10,TimeUnit.SECONDS),"actual final identity verification reaches Android IO boundary");e.controller.stop();}
                finally{m.releaseFinalVerify.countDown();}
            }
            check(done.await(10,TimeUnit.SECONDS),"actual controller terminates");LocalTaskController.TaskResult r=result[0];
            check(r!=null&&r.completionVerified==verified,"completion differs: "+mode+" / "+(r==null?"null":r.status+" "+r.summary));
            boolean cleanupExpected=!"stop_in_final_verify_unknown_cleanup".equals(mode);
            check(r.cleanupKnown==cleanupExpected&&r.modelReportedSuccess&&m.ends==1,"model claim and single cleanup retained");
            if(mode.startsWith("stop_in_final_verify")){
                check(m.finalVerifyStackObserved,"Stop occurred while real installed identity verifier was active");
                check((cleanupExpected?"cancelled":"blocked").equals(r.status),"final Stop must cancel unless unresolved cleanup takes precedence");
            }
            check(e.service.node.actions==("preexisting".equals(mode)?0:6),"no synthetic effect beyond real production dispatch");
            JSONObject terminal=FixedIntentIntegrationHostTest.json(r.evidenceDirectory.toPath().resolve("result.json"));
            check(terminal.getBoolean("goal_independently_verified")==verified,"public verification bit follows complete terminal predicate");
            check(r.status.equals(terminal.getString("status")),"terminal evidence status equals published result");
            check(Files.isRegularFile(r.evidenceDirectory.toPath().resolve("completion-installed-identity.json")),"actual controller captures calculator installation");
        }
    }
    public static void main(String[] args)throws Exception{
        Path out=Paths.get(args[0]);Files.createDirectories(out);QualificationScopeHostTest.output=out;
        pureCases();
        test("actual_controller_calculator_keys_and_readback_completes",()->controllerCase("complete",true));
        test("actual_controller_preexisting_correct_value_is_partial",()->controllerCase("preexisting",false));
        test("actual_controller_wrong_result_is_partial",()->controllerCase("wrong_result",false));
        test("actual_controller_installed_calculator_rechecked_after_cleanup",()->controllerCase("changed_apk",false));
        test("actual_controller_native_cleanup_receipt_required",()->controllerCase("bad_cleanup",false));
        test("actual_controller_stop_during_final_identity_verify_cancels",()->controllerCase("stop_in_final_verify",false));
        test("actual_controller_stop_during_final_identity_verify_preserves_unknown_cleanup_block",()->controllerCase("stop_in_final_verify_unknown_cleanup",false));
        Files.write(out.resolve("TEST-RESULTS.json"),new JSONObject().put("all_pass",true).put("checks",passed.size()).put("cases",passed)
                .put("actual_controller",true).put("android_and_model_io_are_fakes",true).put("phone_tested",false)
                .put("historical_original_bytes_replayed",false).toString(2).getBytes(StandardCharsets.UTF_8));
    }
}
