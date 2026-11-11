package org.trillionnium.hepta.local;

import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;
import org.json.JSONObject;
import static org.trillionnium.hepta.local.QualificationScopeHostTest.*;

/** Actual snapshot/dispatcher/controller methods, with synthetic Android nodes and model IO only. */
final class BackgroundFreshnessHostTest {
    static final int DISPLAY=6;
    static final String RUN="dddddddddddddddddddddddddddddddd";
    static final class GraphSetup {
        final BackgroundObservationFixture fixture=new BackgroundObservationFixture();
        final AccessibilityNodeInfo root=new AccessibilityNodeInfo(SETTINGS,7),child=new AccessibilityNodeInfo(SETTINGS,7);
        GraphSetup(){
            fixture.background=BackgroundSession.fixture("snapshot-only",DISPLAY,Collections.singleton(SETTINGS));
            root.text="container";root.clickable=false;root.viewId="synthetic:id/root";
            root.bounds=new android.graphics.Rect(0,0,1080,2400);root.window.display=DISPLAY;root.window.root=root;
            child.text="old";child.viewId="synthetic:id/field";child.editable=true;child.window.display=DISPLAY;
            root.children.add(child);fixture.windows.add(root.window);
            fixture.foreground=new AccessibilityNodeInfo(FOREIGN[0],99);
        }
        PhoneObservation capture(){return fixture.snapshot();}
    }
    static PhoneObservation.Node field(PhoneObservation value,String id){
        for(PhoneObservation.Node row:value.nodes)if(id.equals(row.viewId))return row;
        throw new AssertionError("missing synthetic node "+id);
    }
    static void freshnessFailure(Runnable action){
        try{action.run();throw new AssertionError("expected snapshot freshness refusal");}
        catch(IllegalStateException changed){check(changed.getMessage().startsWith("stale:"),"explicit transient snapshot failure: "+changed);}
    }
    static void identityFailure(Runnable action){
        try{action.run();throw new AssertionError("expected snapshot identity refusal");}
        catch(IllegalStateException changed){check(!changed.getMessage().startsWith("stale:"),"identity must stay terminal");}
    }
    static void budgetFailure(Runnable action){
        try{action.run();throw new AssertionError("expected read budget refusal");}
        catch(IllegalStateException stopped){check("synthetic read deadline".equals(stopped.getMessage()),"deadline must not be swallowed as a missing label/frame");}
    }
    static void snapshots()throws Exception{
        test("background_snapshot_refreshes_root_before_metadata_and_children_before_text",()->{
            GraphSetup s=new GraphSetup();s.root.onRefresh=()->s.root.className="FreshRoot";s.child.onRefresh=()->s.child.text="fresh";
            PhoneObservation value=s.capture();
            check("FreshRoot".equals(value.windowMetadata.rootClass)&&"fresh".equals(field(value,"synthetic:id/field").text),"actual graph must publish refreshed data");
            check(s.root.refreshes==1&&s.child.refreshes==1&&s.fixture.foregroundReads==0,"refresh root and each visited child, no main-display read");
        });
        test("background_snapshot_old_and_fresh_field_produce_distinct_tree_identity",()->{
            GraphSetup s=new GraphSetup();PhoneObservation before=s.capture();s.child.onRefresh=()->s.child.text="fresh";PhoneObservation after=s.capture();
            check(!before.treeSha256.equals(after.treeSha256)&&!before.state.appTreeSha256.equals(after.state.appTreeSha256),"fresh body changes both graph and app identity");
            check("old".equals(field(before,"synthetic:id/field").text),"published prior observation remains immutable");
        });
        test("background_snapshot_failed_root_refresh_is_transient_without_partial_frame",()->{
            GraphSetup s=new GraphSetup();s.root.refreshResult=false;freshnessFailure(s::capture);
            check(s.root.recycles==1&&s.child.refreshes==0&&s.fixture.foregroundReads==0,"failed root is released and no other display consulted");
        });
        test("background_snapshot_failed_child_refresh_releases_partial_graph",()->{
            GraphSetup s=new GraphSetup();s.child.refreshResult=false;freshnessFailure(s::capture);
            check(s.root.recycles>=2&&s.child.recycles==1,"both traversal references and captured graph are released");
        });
        test("background_snapshot_missing_child_is_transient",()->{
            GraphSetup s=new GraphSetup();s.root.children.set(0,null);freshnessFailure(s::capture);check(s.fixture.foregroundReads==0,"no display fallback");
        });
        test("background_snapshot_refreshes_noninteractive_descendant_label_before_parent_identity",()->{
            GraphSetup s=new GraphSetup();s.root.text="";s.root.clickable=true;s.root.actionOverride=Collections.singletonList(new AccessibilityNodeInfo.AccessibilityAction(AccessibilityNodeInfo.ACTION_CLICK));
            s.child.editable=false;s.child.clickable=false;s.child.actionOverride=Collections.emptyList();s.child.onRefresh=()->s.child.text="fresh label";
            PhoneObservation value=s.capture();check("fresh label".equals(field(value,"synthetic:id/root").childText.text),"parent label cannot retain cached child text");
        });
        test("background_snapshot_failed_label_child_refresh_cannot_be_suppressed_as_empty_label",()->{
            GraphSetup s=new GraphSetup();s.root.text="";s.root.clickable=true;
            s.child.editable=false;s.child.clickable=false;s.child.actionOverride=Collections.emptyList();s.child.refreshResult=false;
            freshnessFailure(s::capture);
        });
        test("background_snapshot_refreshed_foreign_root_is_terminal",()->{
            GraphSetup s=new GraphSetup();s.root.onRefresh=()->s.root.pkg=FOREIGN[0];identityFailure(s::capture);check(s.fixture.foregroundReads==0,"no fallback");
        });
        test("background_snapshot_wrong_display_and_ime_roots_are_never_traversed",()->{
            GraphSetup s=new GraphSetup();AccessibilityNodeInfo foreign=new AccessibilityNodeInfo(FOREIGN[0],99);foreign.window.root=foreign;foreign.window.layer=999;
            AccessibilityNodeInfo ime=new AccessibilityNodeInfo("synthetic.ime",8);ime.window.root=ime;ime.window.display=DISPLAY;ime.window.type=AccessibilityWindowInfo.TYPE_INPUT_METHOD;ime.window.layer=999;
            s.fixture.windows.add(foreign.window);s.fixture.windows.add(ime.window);s.capture();
            check(foreign.refreshes==0&&ime.refreshes==0&&s.fixture.foregroundReads==0,"selected immutable display application only");
        });
        test("background_snapshot_refresh_work_retains_production_traversal_bound",()->{
            GraphSetup s=new GraphSetup();s.root.children.clear();
            for(int i=0;i<400;i++){AccessibilityNodeInfo child=new AccessibilityNodeInfo(SETTINGS,7);child.clickable=false;child.window.display=DISPLAY;s.root.children.add(child);}
            PhoneObservation value=s.capture();int refreshed=s.root.refreshes;for(AccessibilityNodeInfo child:s.root.children)refreshed+=child.refreshes;
            check(value.nodesTruncated&&refreshed==320&&s.root.children.get(319).refreshes==0,"no refresh outside existing MAX_VISITED");
        });
        test("foreground_snapshot_retains_existing_refresh_behavior",()->{
            GraphSetup s=new GraphSetup();s.fixture.background=null;s.fixture.foreground=s.root;s.root.window.display=0;s.child.window.display=0;s.capture();
            check(s.fixture.foregroundReads==1&&s.root.refreshes==0&&s.child.refreshes==0,"background fix does not change foreground sampler");
        });
        test("observation_budget_after_root_acquisition_releases_root",()->{
            GraphSetup s=new GraphSetup();final boolean[] acquired={false};final int[] checks={0};
            s.root.onRefresh=()->acquired[0]=true;
            budgetFailure(()->s.fixture.budgetedSnapshot(()->{if(acquired[0]&&++checks[0]==2)throw new IllegalStateException("synthetic read deadline");}));
            check(s.root.recycles==1&&s.child.refreshes==0,"root acquired before graph metadata is still released on budget expiry");
        });
        test("observation_budget_during_child_refresh_releases_partial_graph",()->{
            GraphSetup s=new GraphSetup();final boolean[] expired={false};s.child.onRefresh=()->expired[0]=true;
            budgetFailure(()->s.fixture.budgetedSnapshot(()->{if(expired[0])throw new IllegalStateException("synthetic read deadline");}));
            check(s.root.recycles>=2&&s.child.recycles==1,"cancelled traversal releases captured root and child ownership");
        });
        test("observation_budget_in_label_collector_is_not_suppressed",()->{
            GraphSetup s=new GraphSetup();s.root.text="";s.root.clickable=true;
            s.child.editable=false;s.child.clickable=false;s.child.actionOverride=Collections.emptyList();
            final boolean[] expired={false};s.child.onRefresh=()->expired[0]=true;
            budgetFailure(()->s.fixture.budgetedSnapshot(()->{if(expired[0])throw new IllegalStateException("synthetic read deadline");}));
            check(s.child.recycles==1&&s.fixture.foregroundReads==0,"label helper cannot turn cancelled background work into an empty fresh label");
        });
        test("foreground_observation_budget_after_root_acquisition_releases_root",()->{
            GraphSetup s=new GraphSetup();s.fixture.background=null;s.fixture.foreground=s.root;s.root.window.display=0;
            final int[] checks={0};budgetFailure(()->s.fixture.budgetedSnapshot(()->{if(++checks[0]==3)throw new IllegalStateException("synthetic read deadline");}));
            check(s.root.recycles==1&&s.root.refreshes==0,"foreground root remains owned even when expiry precedes metadata");
        });
    }
    static final class DispatchSetup implements AutoCloseable {
        final Env env=new Env(false);final HeptaAccessibilityService service=env.service;final BackgroundSession background;
        DispatchSetup()throws Exception{
            env.bind(null);background=BackgroundSession.fixture(env.task,DISPLAY,new LinkedHashSet<String>(Arrays.asList(SETTINGS,SEARCH)));
            service.bindBackgroundSession(env.task,background);service.root.window.display=DISPLAY;service.node.window.display=DISPLAY;capture();
        }
        void capture(){service.observe(env.task,env.dir.toFile(),()->false,Long.MAX_VALUE,new HeptaAccessibilityService.ObservationCallback(){
            public void onObservation(PhoneObservation value){}public void onError(String error){throw new AssertionError(error);}});}
        ActionDecision action(String kind)throws Exception{return ActionDecision.parse(raw(service.current,kind),ActionDecision.IME_ACTION_SCHEMA);}
        HeptaAccessibilityService.ActionOutcome run(ActionDecision action){
            PhoneObservation observed=service.current;ObservedTargetLabels targets=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,observed.id,observed.packageName,
                    Collections.singletonMap("n0",ObservedTargetLabels.project(observed.nodes.get(0).label())));
            final HeptaAccessibilityService.ActionOutcome[] reply={null};service.perform(env.task,observed,action,targets,service.taskAuthorization,RUN,()->false,value->reply[0]=value);
            check(reply[0]!=null,"synchronous fake result");return reply[0];
        }
        public void close(){background.close();env.close();}
    }
    static String raw(PhoneObservation observed,String kind)throws Exception{
        JSONObject value=new JSONObject().put("reason","依据本次观察决定下一步").put("action",kind).put("observation_id",observed.id).put("package",observed.packageName);
        if("type".equals(kind)||"click".equals(kind)||"scroll".equals(kind)||"submit".equals(kind))
            value.put("node_label",ObservedTargetLabels.project(observed.nodes.get(0).label())).put("node_id","n0");
        if("type".equals(kind))value.put("text","replacement");if("scroll".equals(kind))value.put("direction","forward");
        if("done".equals(kind))value.put("status","partial").put("summary","synthetic model ended; no business success claim");
        return value.toString();
    }
    static void stale(DispatchSetup s,HeptaAccessibilityService.ActionOutcome result)throws Exception{
        check(!result.accepted&&!result.dispatched&&result.stale&&s.service.effects()==0,"freshness refusal has zero dispatch and requests new inference");
        check(!result.qualificationScope.getBoolean("scope_refused")&&!s.env.bound.restricted(),"stale does not poison original scope");
    }
    static void terminal(DispatchSetup s,HeptaAccessibilityService.ActionOutcome result){
        check(!result.accepted&&!result.dispatched&&!result.stale&&s.service.effects()==0,"identity/authority failure stays terminal with zero effects");
    }
    static void dispatch()throws Exception{
        for(String kind:new String[]{"click","type","scroll","submit"})test("background_"+kind+"_content_change_is_stale_not_scope_refusal",()->{try(DispatchSetup s=new DispatchSetup()){
            ActionDecision action=s.action(kind);s.service.node.onRefresh=()->s.service.node.text="changed";stale(s,s.run(action));
        }});
        test("background_missing_ref_is_terminal",()->{try(DispatchSetup s=new DispatchSetup()){
            ActionDecision action=ActionDecision.parse(new JSONObject(raw(s.service.current,"click")).put("node_id","n999").toString(),ActionDecision.IME_ACTION_SCHEMA);terminal(s,s.run(action));
        }});
        test("background_invalid_label_stays_terminal_before_stale_node_refresh",()->{try(DispatchSetup s=new DispatchSetup()){
            ActionDecision action=ActionDecision.parse(new JSONObject(raw(s.service.current,"type")).put("node_label","forged").toString(),ActionDecision.IME_ACTION_SCHEMA);
            s.service.node.onRefresh=()->s.service.node.text="changed";terminal(s,s.run(action));check(s.service.node.refreshes==0,"invalid pair is rejected before freshness branch");
        }});
        test("background_failed_node_refresh_is_stale_without_dispatch",()->{try(DispatchSetup s=new DispatchSetup()){
            s.service.node.refreshResult=false;stale(s,s.run(s.action("click")));
        }});
        for(String changed:new String[]{"foreign_package","other_allowed_package","window","window_object","display","type"})test("background_identity_"+changed+"_never_becomes_stale",()->{try(DispatchSetup s=new DispatchSetup()){
            s.service.node.onRefresh=()->{
                s.service.node.text="changed";
                if("foreign_package".equals(changed))s.service.node.pkg=FOREIGN[0];
                if("other_allowed_package".equals(changed))s.service.node.pkg=SEARCH;
                if("window".equals(changed))s.service.node.windowId=8;
                if("window_object".equals(changed))s.service.node.window.id=8;
                if("display".equals(changed))s.service.node.window.display=0;
                if("type".equals(changed))s.service.node.window.type=AccessibilityWindowInfo.TYPE_INPUT_METHOD;
            };terminal(s,s.run(s.action("type")));
        }});
        test("background_retired_during_refresh_is_terminal_even_when_content_changed",()->{try(DispatchSetup s=new DispatchSetup()){
            s.service.node.onRefresh=()->{s.background.close();s.service.node.text="changed";};terminal(s,s.run(s.action("click")));
        }});
        test("background_new_scope_file_is_terminal_before_refresh",()->{try(DispatchSetup s=new DispatchSetup()){
            ActionDecision action=s.action("click");s.env.writeConfig();s.service.node.onRefresh=()->s.service.node.text="changed";
            terminal(s,s.run(action));check(s.service.node.refreshes==0,"scope identity is checked first");
        }});
        test("background_final_predispatch_change_does_not_replay_old_action",()->{try(DispatchSetup s=new DispatchSetup()){
            // First refresh is initial background check, second is core validation,
            // third is the final immediately-before-effect check in this fixture.
            s.service.node.onRefresh=()->{if(s.service.node.refreshes==3)s.service.node.text="changed at final gate";};
            stale(s,s.run(s.action("click")));check(s.service.node.refreshes==3,"exercise final gate, not first check");
        }});
        test("background_fresh_type_is_exact_replacement_without_implicit_submit",()->{try(DispatchSetup s=new DispatchSetup()){
            HeptaAccessibilityService.ActionOutcome result=s.run(s.action("type"));
            check(result.accepted&&result.dispatched&&!result.stale&&s.service.effects()==1,"one permitted fresh type");
            check("replacement".equals(s.service.node.text)&&s.service.node.lastAction==AccessibilityNodeInfo.ACTION_SET_TEXT,"whole field replacement only");
        }});
        test("background_consumed_submit_stale_during_journal_is_terminal_not_retry",()->{try(DispatchSetup s=new DispatchSetup()){
            s.service.node.imePresent=true;s.service.node.imeLabel="搜索";
            SubmitAttemptGuard ledger=new SubmitAttemptGuard(s.env.task,attempt->s.service.node.text="changed during durable journal");
            s.service.bindSubmitAttempts(s.env.task,ledger);s.capture();String input=s.service.current.nodes.get(0).inputTextSha256;
            HeptaAccessibilityService.ActionOutcome result=s.run(s.action("submit"));terminal(s,result);
            check(result.imeSubmit!=null&&result.imeSubmit.getBoolean("attempt_consumed")&&!result.imeSubmit.getBoolean("automatic_retry_allowed"),"consumed stale is never reusable");
            check(!ledger.available(SETTINGS,input),"consumption survives zero platform effect");
        }});
    }
    static void controller(boolean continuous)throws Exception{
        try(Env e=new Env(false)){
            BackgroundSession.controllerDisplay=DISPLAY;e.service.root.window.display=DISPLAY;e.service.node.window.display=DISPLAY;
            final List<String> observations=new ArrayList<String>(),prompts=new ArrayList<String>();final int[] calls={0};
            LocalInference model=new LocalInference(){
                public LocalRuntimeConfig configuration(){return e.runtime;}
                public TaskCleanup endTask(){return TaskCleanup.noWorker();}
                public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,int max,long timeout,Callback callback){
                    try{
                        int step=++calls[0];observations.add(e.service.current.id);prompts.add(prompt);
                        String answer=raw(e.service.current,continuous||step==1?"click":"done");
                        if(continuous||step==1)e.service.node.onRefresh=()->{e.service.node.onRefresh=null;e.service.node.text="fresh observation "+step;};
                        callback.onSuccess(answer,String.format(Locale.ROOT,"%032x",step));return ()->{};
                    }catch(Exception error){throw new IllegalStateException(error);}
                }
            };
            e.controller=new LocalTaskController(e.service,model);final LocalTaskController.TaskResult[] result={null};CountDownLatch completed=new CountDownLatch(1);
            String owner="在设置应用检查当前页面，依据新观察执行。";
            check(e.controller.start(owner,null,TaskAuthorization.parse(owner),new BackgroundSession.Selection(SETTINGS,Collections.singleton(SETTINGS)),new LocalTaskController.Listener(){
                public void onState(String state){}public void onFinished(LocalTaskController.TaskResult value){result[0]=value;completed.countDown();}}),"ordinary background controller starts");
            check(completed.await(10,TimeUnit.SECONDS),"controller terminates");
            check(e.service.effects()==0&&result[0].cleanupKnown&&!result[0].modelReportedSuccess,"no stale action, automatic replay, or synthetic success");
            check(new HashSet<String>(observations).size()==calls[0],"every retry invokes model with a genuinely new observation id");
            JSONObject rejected=new JSONObject(new String(Files.readAllBytes(result[0].evidenceDirectory.toPath().resolve("step-01-action.json")),StandardCharsets.UTF_8));
            check(rejected.getBoolean("stale")&&!rejected.getBoolean("dispatched")&&!rejected.getJSONObject("qualification_scope").getBoolean("scope_refused"),"actual task receipt preserves retry reason without scope poison");
            if(continuous)check(calls[0]==3&&result[0].steps==3&&"failed".equals(result[0].status)&&result[0].summary.contains("连续变化"),"existing two-retry ceiling is unchanged");
            else check(calls[0]==2&&result[0].steps==2&&prompts.get(1).contains("fresh observation 1")&&prompts.get(1).contains("action_rejected"),"second inference sees new body and prior rejection, never a re-issued old action");
        }finally{BackgroundSession.controllerDisplay=-1;}
    }
    static void run()throws Exception{
        snapshots();dispatch();
        test("background_controller_stale_reobserves_and_calls_model_before_next_action",()->controller(false));
        test("background_controller_continuous_stale_stops_after_existing_two_retries",()->controller(true));
    }
}
