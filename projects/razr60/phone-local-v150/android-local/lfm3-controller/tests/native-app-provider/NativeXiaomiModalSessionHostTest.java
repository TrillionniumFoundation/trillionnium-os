package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;

/** Actual production Session/Domain/parser/TCG. Modal nodes come from the saved
 * ordinary task; other pages retain original public exploration XML. Task,
 * lease, installed verifier, model callbacks, dispatch and cleanup are explicit
 * host doubles. This neither sends Back nor proves a phone business result. */
final class NativeXiaomiModalSessionHostTest {
    private static final String OWNER=ActualXiaomiImageModalFixture.OWNER;
    private static final String PACKAGE=NativeAppGoal.XIAOMI_PACKAGE;
    private static final String GENERATION="12345678-1234-4234-8234-123456789abc";
    private static final String DISMISS="dismiss_image_modal_once";
    private static final String APK="95883c057eb15bc6e50a82f2e22da13b77980871624f60a2fb9e50cfdf4a8373";
    private static final List<String> names=new ArrayList<String>();
    private static Path fixtures,replayFixtures;private static int checks;
    private interface Test {void run()throws Exception;}
    private static String sha(String value){return NativeAppEvidence.hash(value);}
    private static String id(String value){return sha(value).substring(0,32);}
    private static void check(boolean value,String reason){checks++;if(!value)throw new AssertionError(reason);}
    private static void one(String name,Test test)throws Exception{if(names.contains(name))throw new AssertionError("duplicate case");test.run();names.add(name);}
    private static void rejects(Test test,String reason)throws Exception{
        checks++;try{test.run();}catch(IllegalArgumentException|IllegalStateException|ActionDecision.InvalidActionException expected){return;}
        throw new AssertionError(reason);
    }
    private static final class Binding implements BackgroundTaskTarget.SelectionBinding {
        final BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(OWNER,PACKAGE,Collections.singleton(PACKAGE));
        public BackgroundTaskTarget executionTarget(){return target;}
    }
    private static final class Harness {
        final String task;final Binding selection=new Binding();final TaskAuthorization auth;
        final TaskAuthorization.Gate owner;final TaskCompletionGate completionGate;final NativeAppSession session;
        final List<Map<String,Object>> journal=new ArrayList<Map<String,Object>>();
        NativeAppEvidence.Frame frame;NotesCompletionEvidence.Frame completion;int observations,step;long clock=1000;
        String run;boolean installedCurrent=true;
        Harness(String label)throws Exception{
            task=id("synthetic-modal-task:"+label);auth=TaskAuthorization.parse(OWNER).forExecutionSelection(selection);owner=auth.bind(task);
            completionGate=new TaskCompletionGate(task,OWNER,auth,selection);
            session=new NativeAppSession(task,owner,selection,new NativeAppEvidence.Installed(PACKAGE,10485,20261010L,Collections.singletonMap("base",APK)),
                    sha("synthetic-selection:"+selection.target.targetSha256),GENERATION,7,
                    new NativeAppSession.InstalledVerifier(){public void verify(){if(!installedCurrent)throw new IllegalStateException("synthetic installed identity changed");}},
                    new NativeAppSession.Journal(){public void write(String leaf,Map<String,Object> value){
                        Map<String,Object> record=NativeAppEvidence.map();record.put("leaf",leaf);record.put("value",NativeAppEvidence.immutableMap(value));journal.add(record);
                    }});
            completionGate.bindNativeSession(session);
        }
        NativeAppEvidence.Frame make(List<NativeAppEvidence.Node> nodes,String graph,int window,int width,int height,int left,int top,int right,int bottom)throws Exception{
            observations++;clock+=10;String obs=id(task+":synthetic-frame:"+observations);
            List<NotesCompletionEvidence.Node> retained=new ArrayList<NotesCompletionEvidence.Node>();
            for(NativeAppEvidence.Node n:nodes)retained.add(new NotesCompletionEvidence.Node(n.id,n.packageName,n.text,n.label,n.viewId,null,
                    new int[]{n.left,n.top,n.right,n.bottom},n.editable,n.clickable,n.scrollable,n.enabled,n.password,ObservedChildText.notApplicable(),n.signature));
            completion=new NotesCompletionEvidence.Frame(obs,PACKAGE,window,7,GENERATION,1,true,false,retained);
            return new NativeAppEvidence.Frame(task,selection.target.ownerSha256,selection.target.targetSha256,auth.sha256,
                    sha("synthetic-selection:"+selection.target.targetSha256),obs,PACKAGE,GENERATION,graph,graph,
                    sha("synthetic-screen:"+obs),sha("synthetic-phone-record:"+obs+":"+graph),TaskCompletionGate.webFrameSha(completion),
                    7,window,0,width,height,left,top,right,bottom,clock,false,true,nodes,1,true);
        }
        NativeAppEvidence.Frame modalFrame()throws Exception{
            NativeAppEvidence.Frame original=ActualXiaomiImageModalFixture.frame();
            return make(original.nodes,original.treeSha,703,original.width,original.height,original.left,original.top,original.right,original.bottom);
        }
        NativeAppEvidence.Frame xmlFrame(String leaf)throws Exception{
            NativeXmlFixture.Snapshot xml=NativeXmlFixture.read(fixtures.resolve(leaf));int[] b=xml.rootBounds;
            return make(xml.nodes,xml.sourceSha256,702,b[2],b[3],b[0],b[1],b[2],b[3]);
        }
        void observe(NativeAppEvidence.Frame next)throws Exception{frame=next;session.observed(frame);completionGate.observed(completion);}
        void modal()throws Exception{observe(modalFrame());}
        void actualModal(JSONObject raw)throws Exception{
            JSONArray actual=raw.getJSONArray("nodes");check(actual.length()==2,"actual R18 modal has two retained nodes");
            JSONObject census=raw.getJSONObject("collection");
            check(!raw.getBoolean("nodes_truncated")&&census.getInt("visited_nodes")==3&&census.getInt("retained_nodes")==2
                    &&census.getInt("retained_text_utf16")==0&&census.getInt("pending_nodes_at_stop")==0
                    &&census.getInt("child_slots_omitted_by_traversal_limit")==0&&census.getInt("nodes_omitted_by_node_limit")==0
                    &&census.getInt("nodes_omitted_by_text_limit")==0,"complete actual image-only traversal");
            List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();
            for(int i=0;i<actual.length();i++){
                JSONObject n=actual.getJSONObject(i),position=n.getJSONObject("native_tree_position"),selected=n.getJSONObject("native_selection_state");
                JSONArray bounds=n.getJSONArray("bounds");
                check(!n.has("text")&&!n.has("description")&&!n.has("view_id")&&n.getBoolean("clickable")
                        &&selected.getBoolean("observed"),"original unlabeled clickable image facts retained");
                nodes.add(new NativeAppEvidence.Node(n.getString("id"),n.getString("package"),n.getString("class_name"),"","","",
                        position.getString("path"),position.getString("parent_class"),n.getString("node_app_tree_sha256"),"",
                        bounds.getInt(0),bounds.getInt(1),bounds.getInt(2),bounds.getInt(3),
                        !n.optBoolean("disabled",false),n.optBoolean("editable",false),n.getBoolean("clickable"),
                        n.optBoolean("scrollable",false),n.optBoolean("password",false),
                        Boolean.valueOf(selected.getBoolean("selected")),Boolean.valueOf(selected.getBoolean("checkable")),
                        Boolean.valueOf(selected.getBoolean("checked")),Collections.<String>emptySet()));
            }
            JSONObject window=raw.getJSONObject("window");JSONArray b=window.getJSONArray("root_bounds");
            check(window.getInt("display_id")==244&&window.getInt("window_id")==1296&&window.getInt("type")==1,
                    "fixture remains the actual business display/window");
            observe(make(nodes,raw.getString("app_tree_sha256"),703,raw.getInt("screen_width"),raw.getInt("screen_height"),
                    b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3)));
        }
        ActionDecision waitAction()throws Exception{return ActionDecision.parse(new JSONObject().put("action","wait")
                .put("observation_id",frame.observationId).put("package",PACKAGE).put("duration_ms",1000).toString(),ActionDecision.IME_ACTION_SCHEMA);}
        void xml(String leaf)throws Exception{observe(xmlFrame(leaf));}
        String node(String purpose){for(Map.Entry<String,String> e:session.domain().purposes.entrySet())if(purpose.equals(e.getValue()))return e.getKey();return null;}
        ActionDecision action(String purpose)throws Exception{
            String node=node(purpose);check(node!=null,"actual purpose missing: "+purpose+" "+session.evidence());
            JSONObject value=new JSONObject().put("action","back".equals(node)?"back":session.domain().editValues.containsKey(node)?"type":"click")
                    .put("package",PACKAGE).put("observation_id",frame.observationId);
            if(!"back".equals(node)){value.put("node_id",node).put("node_label",frame.byId.get(node).label);
                if(session.domain().editValues.containsKey(node))value.put("text",session.domain().editValues.get(node));}
            return ActionDecision.parse(value.toString(),ActionDecision.IME_ACTION_SCHEMA);
        }
        ActionDecision back(String observation,String pkg)throws Exception{return ActionDecision.parse(new JSONObject().put("action","back")
                .put("observation_id",observation).put("package",pkg).toString(),ActionDecision.IME_ACTION_SCHEMA);}
        void issue(ActionDecision decision,boolean accepted,boolean dispatched,boolean stale)throws Exception{
            step++;clock+=10;run=id(task+":synthetic-model-callback:"+step);owner.check(decision,run);
            session.beforeModelAction(step,decision,run,clock);
            session.modelActionOutcome(decision,run,accepted,dispatched,stale,sha("synthetic-durable-action-receipt:"+run),++clock);
        }
        void perform(String purpose,String leaf)throws Exception{issue(action(purpose),true,true,false);xml(leaf);}
        void returnedHome()throws Exception{modal();perform(DISMISS,"home.xml");}
        Map<?,?> progress(){return (Map<?,?>)session.evidence().get("progress");}
        void noQueryOrResult(){check(Boolean.FALSE.equals(progress().get("product_query_observed")),"Back is not query proof");
            check(Boolean.FALSE.equals(progress().get("product_detail_navigation_observed")),"Back is not detail proof");
            check(!session.domain().resultReady&&session.resultRecord()==null,"Back is not a price result");}
        void pendingOnly(){check(progress().get("pending")!=null,"transition must remain pending");
            check(!session.domain().backAllowed&&session.domain().clickIds.isEmpty()&&session.domain().editValues.isEmpty(),"pending page has no new navigation or search");noQueryOrResult();}
        void queryAndDetail()throws Exception{
            returnedHome();perform(NativeXiaomiProductPage.SEARCH_ICON,"search-entry.xml");perform("set_product_query","suggestions.xml");
            String submit=node("submit_exact_suggestion")!=null?"submit_exact_suggestion":"submit_product_query";
            perform(submit,"results.xml");perform("open_exact_product","detail.xml");
            check(session.domain().resultReady&&completionGate.verified(completion),"original exact query/card/detail chain still required and usable");
        }
        void claim()throws Exception{
            ActionDecision done=ActionDecision.parse(new JSONObject().put("action","done").put("package",PACKAGE).put("observation_id",frame.observationId)
                    .put("status","success").put("summary","synthetic host result; no phone query").toString(),ActionDecision.IME_ACTION_SCHEMA);
            issue(done,true,false,false);xml("detail.xml");check(completionGate.successClaim(step,run,completion,true).verified,"fresh final same graph is required");
        }
        Map<String,Object> terminal(boolean cleanup)throws Exception{
            session.retire();return completionGate.terminalNativeCheck(session,completion,owner.frame(),step,run,true,cleanup,true,true,true,false,
                    true,true,Integer.valueOf(0),true,task,id("synthetic-worker"),sha("synthetic-parent-session-receipt")).evidence;
        }
    }
    private static NativeAppEvidence.Frame changed(NativeAppEvidence.Frame f,String task,String owner,String generation,int display,boolean complete,boolean truncated){
        return new NativeAppEvidence.Frame(task,owner,f.targetSha,f.authorizationSha,f.selectionSha,f.observationId,f.packageName,generation,
                f.treeSha,f.stateSha,f.screenshotSha,f.sourceRecordSha,f.completionFrameSha,display,f.windowId,f.rotation,f.width,f.height,
                f.left,f.top,f.right,f.bottom,f.capturedElapsedMs,truncated,complete,f.nodes,f.windowType,f.metadataObserved);
    }
    public static void main(String[] args)throws Exception{
        fixtures=Paths.get(args[0]);replayFixtures=Paths.get(args[2]);
        one("modal_session_grants_only_one_context_bound_back_not_image_click_or_result",()->{
            Harness h=new Harness("backonly");h.modal();NativeAppDomain d=h.session.domain();
            check(NativeXiaomiProductPage.IMAGE_MODAL.equals(d.phase)&&d.backAllowed,"actual modal shape can offer Back");
            check(d.clickIds.isEmpty()&&d.editValues.isEmpty()&&d.purposes.equals(Collections.singletonMap("back",DISMISS)),"no image target or search command");
            check(d.toolMask(null).equals(new TreeSet<String>(Arrays.asList("back","done"))),"static modal admits navigation or truthful end, not loading waits");
            check(d.toolMask(Collections.singleton("wait")).isEmpty()&&d.toolMask(Collections.<String>emptySet()).isEmpty(),"original mask is still intersected");h.noQueryOrResult();
        });
        one("modal_back_closes_only_on_fresh_supported_home_without_query_proof",()->{
            Harness h=new Harness("returnhome");h.returnedHome();check(h.progress().get("pending")==null&&h.node(NativeXiaomiProductPage.SEARCH_ICON)!=null,"fresh home restores original search action");
            check(Boolean.TRUE.equals(h.progress().get("product_modal_exit_attempted")),"single proposal is recorded");
            List<?> transitions=(List<?>)h.progress().get("transitions");check(transitions.size()==1,"one observed navigation transition");
            Map<?,?> proof=(Map<?,?>)transitions.get(0);check(Boolean.TRUE.equals(proof.get("navigation_only"))&&Boolean.FALSE.equals(proof.get("query_or_result_proof_created")),"proof explicitly excludes business/query authority");h.noQueryOrResult();
        });
        one("modal_back_same_modal_after_dispatch_keeps_pending_and_zero_targets",()->{Harness h=new Harness("same");h.modal();h.issue(h.action(DISMISS),true,true,false);h.modal();h.pendingOnly();});
        one("modal_back_unknown_page_never_counts_as_dismissal",()->{
            Harness h=new Harness("unknown");h.modal();h.issue(h.action(DISMISS),true,true,false);
            h.observe(h.make(Collections.<NativeAppEvidence.Node>emptyList(),sha("unknown"),702,720,1280,0,0,720,1280));h.pendingOnly();
        });
        one("modal_back_search_input_is_not_the_required_home",()->{Harness h=new Harness("input");h.modal();h.issue(h.action(DISMISS),true,true,false);h.xml("search-entry.xml");h.pendingOnly();});
        one("modal_back_cached_result_cannot_create_query_proof",()->{Harness h=new Harness("results");h.modal();h.issue(h.action(DISMISS),true,true,false);h.xml("results.xml");h.pendingOnly();});
        one("modal_back_cached_detail_cannot_create_price_completion",()->{Harness h=new Harness("detail");h.modal();h.issue(h.action(DISMISS),true,true,false);h.xml("detail.xml");h.pendingOnly();});
        one("modal_back_original_fifteen_second_transition_deadline_is_preserved",()->{
            Harness h=new Harness("deadline");h.modal();h.issue(h.action(DISMISS),true,true,false);h.clock+=15001;h.xml("home.xml");
            rejects(()->h.session.domain(),"expired navigation cannot recover through later home");
        });
        one("modal_back_stale_undispatched_proposal_is_consumed_without_retry",()->{
            Harness h=new Harness("stale");h.modal();h.issue(h.action(DISMISS),false,false,true);h.modal();
            check(Boolean.TRUE.equals(h.progress().get("product_modal_exit_attempted"))&&h.progress().get("pending")==null,"stale proposal consumed without fabricated effect");
            check(!h.session.domain().backAllowed,"stale attempt does not authorize automatic redispatch");h.noQueryOrResult();
        });
        one("modal_back_rejected_effect_invalidates_the_session",()->{
            Harness h=new Harness("rejected");h.modal();h.issue(h.action(DISMISS),false,true,false);
            rejects(()->h.xml("home.xml"),"rejected effect cannot be repaired by a later matching home");
        });
        one("modal_back_requires_same_task_owner_generation_display",()->{
            Harness h=new Harness("binding");NativeAppEvidence.Frame f=h.modalFrame();
            rejects(()->h.session.observed(changed(f,id("foreign-task"),f.ownerSha,f.generation,f.displayId,true,false)),"foreign task");
            rejects(()->h.session.observed(changed(f,f.taskId,sha("foreign-owner"),f.generation,f.displayId,true,false)),"foreign owner");
            rejects(()->h.session.observed(changed(f,f.taskId,f.ownerSha,"12345678-1234-4234-8234-123456789abd",f.displayId,true,false)),"foreign lease");
            rejects(()->h.session.observed(changed(f,f.taskId,f.ownerSha,f.generation,8,true,false)),"foreign display");
        });
        one("modal_back_incomplete_or_truncated_observation_has_no_navigation",()->{
            for(boolean truncated:new boolean[]{false,true}){Harness h=new Harness("incomplete"+truncated);NativeAppEvidence.Frame f=h.modalFrame();
                h.session.observed(changed(f,f.taskId,f.ownerSha,f.generation,f.displayId,false,truncated));check(!h.session.domain().backAllowed,"incomplete frame cannot offer Back");}
        });
        one("modal_back_installed_identity_is_rechecked_before_model_action",()->{
            Harness h=new Harness("installed");h.modal();ActionDecision back=h.action(DISMISS);h.installedCurrent=false;
            rejects(()->h.issue(back,true,true,false),"changed installed App cannot use existing modal proposal");
        });
        one("modal_back_wrong_action_frame_or_package_is_rejected",()->{
            Harness h=new Harness("actionbinding");h.modal();
            rejects(()->h.session.domain().requireCurrent(h.back(id("stale-observation"),PACKAGE)),"wrong action observation");
            rejects(()->h.session.domain().requireCurrent(h.back(h.frame.observationId,NativeAppGoal.CTRIP_PACKAGE)),"wrong action package");
        });
        one("modal_images_never_gain_click_or_done_success_authority",()->{
            Harness h=new Harness("noclick");h.modal();
            rejects(()->h.session.domain().requireCurrent(ActionDecision.parse(new JSONObject().put("action","click").put("package",PACKAGE)
                    .put("observation_id",h.frame.observationId).put("node_id","n1").put("node_label","").toString(),ActionDecision.IME_ACTION_SCHEMA)),"visible cross never becomes inferred click target");
            rejects(()->h.session.domain().requireCurrent(ActionDecision.parse(new JSONObject().put("action","done").put("package",PACKAGE)
                    .put("observation_id",h.frame.observationId).put("status","success").put("summary","not a query").toString(),ActionDecision.IME_ACTION_SCHEMA)),"modal is never a business result");
        });
        one("modal_back_retired_task_cannot_dispatch",()->{Harness h=new Harness("retired");h.modal();ActionDecision back=h.action(DISMISS);h.session.retire();rejects(()->h.issue(back,true,true,false),"retired task has no action authority");});
        one("modal_back_after_committed_product_query_is_not_admitted",()->{
            Harness h=new Harness("postquery");h.xml("suggestions.xml");h.perform(h.node("submit_exact_suggestion")!=null?"submit_exact_suggestion":"submit_product_query","results.xml");
            check(Boolean.TRUE.equals(h.progress().get("product_query_observed")),"real original query transition in host fixture");h.modal();
            check(!h.session.domain().backAllowed&&h.session.domain().clickIds.isEmpty()&&!h.session.domain().resultReady,"pre-query bound excludes later modal");
        });
        one("modal_back_after_completed_home_return_cannot_be_repeated",()->{Harness h=new Harness("repeat");h.returnedHome();h.modal();check(!h.session.domain().backAllowed,"only one modal proposal in task");h.noQueryOrResult();});
        one("modal_back_replayed_original_frame_cannot_prove_home_transition",()->{
            Harness h=new Harness("replay");h.modal();NativeAppEvidence.Frame before=h.frame;h.issue(h.action(DISMISS),true,true,false);h.session.observed(before);
            check(h.progress().get("pending")!=null,"same saved frame is not post-Back evidence");rejects(()->h.issue(h.back(before.observationId,PACKAGE),true,true,false),"replay does not restore consumed Back");
        });
        one("modal_home_return_and_cleanup_alone_never_complete_price_goal",()->{
            Harness h=new Harness("noprice");h.returnedHome();check(!h.completionGate.verified(h.completion),"home is not price evidence");
            check(!Boolean.TRUE.equals(h.terminal(true).get("completion_verified")),"normal SDK cleanup cannot manufacture a result");
        });
        one("modal_home_query_card_detail_final_normal0_composition_remains_usable",()->{
            Harness h=new Harness("complete");h.queryAndDetail();h.claim();Map<String,Object> terminal=h.terminal(true);
            check(Boolean.TRUE.equals(terminal.get("completion_verified")),"full explicitly synthetic query/final/cleanup composition");
            check(Boolean.TRUE.equals(terminal.get("native_normal0_parent_session_bound")),"worker receipt binding remains necessary");
        });
        one("modal_completed_price_chain_still_refuses_unknown_cleanup",()->{
            Harness h=new Harness("cleanup");h.queryAndDetail();h.claim();check(!Boolean.TRUE.equals(h.terminal(false).get("completion_verified")),"navigation fix never weakens cleanup");
        });
        one("actual_r18_fourteen_waits_are_refused_before_one_modal_back",()->{
            Harness h=new Harness("actual-r18-waits");
            for(int i=1;i<=14;i++){
                JSONObject before=readReplay(String.format(java.util.Locale.ROOT,"step-%02d-before.json",i));
                JSONObject model=readReplay(String.format(java.util.Locale.ROOT,"step-%02d-model-0.json",i));
                JSONObject action=new JSONObject(model.getString("raw_text"));
                check(before.getString("observation_id").equals(model.getString("observation_id"))
                        &&before.getString("observation_id").equals(action.getString("observation_id"))
                        &&"wait".equals(action.getString("action"))&&action.getInt("duration_ms")==1000,
                        "preserved R18 model really chose a one-second wait on this frame");
                h.actualModal(before);NativeAppDomain domain=h.session.domain();
                check(domain.backAllowed&&domain.toolMask(null).equals(new TreeSet<String>(Arrays.asList("back","done")))
                        &&domain.purposes.equals(Collections.singletonMap("back",DISMISS)),"same actual shape retains only its original Back");
                action.put("observation_id",h.frame.observationId); // Explicit host identity rebinding, never a live capability.
                ActionDecision replay=ActionDecision.parse(action.toString(),ActionDecision.IME_ACTION_SCHEMA);
                rejects(()->domain.requireCurrent(replay),"actual repeated wait cannot enter candidate domain");h.noQueryOrResult();
            }
            JSONObject before=readReplay("step-15-before.json"),model=readReplay("step-15-model-0.json");
            JSONObject done=new JSONObject(model.getString("raw_text"));
            check("done".equals(done.getString("action"))&&"failure".equals(done.getString("status"))
                    &&before.getString("observation_id").equals(done.getString("observation_id")),"actual final incomplete end is retained");
            h.actualModal(before);done.put("observation_id",h.frame.observationId);
            h.session.domain().requireCurrent(ActionDecision.parse(done.toString(),ActionDecision.IME_ACTION_SCHEMA));
            check(h.progress().get("pending")==null&&!Boolean.TRUE.equals(h.progress().get("product_modal_exit_attempted")),
                    "host replay performs no Back and fabricates no effect");h.noQueryOrResult();
        });
        one("modal_back_animation_wait_preserves_real_pending_and_original_deadline",()->{
            Harness h=new Harness("pending-wait");h.modal();h.issue(h.action(DISMISS),true,true,false);
            Map<?,?> original=(Map<?,?>)h.progress().get("pending");Object finished=original.get("dispatch_finished_elapsed_ms");
            h.modal();h.pendingOnly();NativeAppDomain waiting=h.session.domain();
            check(waiting.toolMask(null).equals(new TreeSet<String>(Arrays.asList("wait","done"))),
                    "fresh still-visible modal after actual Back may settle without another navigation");
            waiting.requireCurrent(h.waitAction());h.issue(h.waitAction(),true,false,false);h.modal();h.pendingOnly();
            check(finished.equals(((Map<?,?>)h.progress().get("pending")).get("dispatch_finished_elapsed_ms")),
                    "a model wait does not replace or renew the actual Back receipt");
            h.clock=((Number)finished).longValue()+14980;h.modal();h.session.domain().requireCurrent(h.waitAction());
            check(!h.session.domain().backAllowed,"near-deadline animation wait still cannot repeat Back");
            h.clock=((Number)finished).longValue()+15001;h.xml("home.xml");
            rejects(()->h.session.domain(),"waiting did not extend the original fifteen-second observation deadline");
        });
        one("modal_stale_unentered_back_cannot_be_retried_or_waited_indefinitely",()->{
            Harness h=new Harness("stale-wait");h.modal();h.issue(h.action(DISMISS),false,false,true);h.modal();
            check(h.progress().get("pending")==null&&Boolean.TRUE.equals(h.progress().get("product_modal_exit_attempted")),
                    "stale proposal consumed without invented dispatch");
            check(h.session.domain().toolMask(null).equals(Collections.singleton("done")),"no loading wait or retry after unentered consumed proposal");
            rejects(()->h.session.domain().requireCurrent(h.waitAction()),"no real pending effect permits waiting");h.noQueryOrResult();
        });
        one("modal_navigation_and_pending_guidance_survive_native_projection",()->{
            Harness h=new Harness("projected-hint");h.modal();
            Map<?,?> provider=(Map<?,?>)h.session.domain().promptEvidence().get("provider");
            check(provider.get("next_goal") instanceof String&&((String)provider.get("next_goal")).contains("back"),
                    "one existing Back is described as a model decision, not an inferred image control");
            JSONObject original=new JSONObject().put("completion",new JSONObject().put("native_app",new JSONObject(h.session.domain().promptEvidence())));
            JSONObject projected=VisualPromptProjection.projectNative(original).getJSONObject("completion").getJSONObject("native_app");
            check(projected.getBoolean("back_allowed")&&DISMISS.equals(projected.getJSONObject("read_only_query_targets").getString("back"))
                    &&provider.get("next_goal").equals(projected.getJSONObject("provider").getString("next_goal")),
                    "metadata projection retains exact existing Back and navigation guidance");
            h.issue(h.action(DISMISS),true,true,false);h.modal();
            JSONObject pending=new JSONObject(h.session.domain().promptEvidence()).getJSONObject("provider");
            check(DISMISS.equals(pending.getString("pending_purpose"))&&pending.getString("next_goal").contains("wait"),
                    "real dispatched transition retains explicit animation waiting guidance");
            check(!h.session.domain().backAllowed&&h.session.domain().clickIds.isEmpty(),"waiting guidance grants no second Back or image click");
        });
        JSONObject out=new JSONObject().put("schema","hepta.native-xiaomi-modal-session-host.v1").put("all_pass",true).put("cases",names.size()).put("assertions",checks).put("case_names",new JSONArray(names))
                .put("phone_operations",0).put("android_runtime",false).put("model_executed",false).put("business_verified",false)
                .put("boundary","Original modal DTO nodes and public XML; actual production Session/Domain/TCG; synthetic task, lease, installed verifier, action receipt and SDK/cleanup. No Back dispatched.");
        Files.write(Paths.get(args[1]),(out.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);System.out.println(out.toString());
    }
    private static JSONObject readReplay(String name)throws Exception{return new JSONObject(new String(Files.readAllBytes(replayFixtures.resolve(name)),StandardCharsets.UTF_8));}
    private NativeXiaomiModalSessionHostTest(){}
}
