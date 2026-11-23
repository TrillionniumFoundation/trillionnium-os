package org.trillionnium.hepta.local;

import android.content.Context;
import android.graphics.Rect;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;

/** Exact six public structural records from the failed native v65 observation.
 * Full Android authority, other nodes, task/model/lease and installed verifier
 * remain explicit host boundaries. No screenshot, phone or model is executed.
 */
final class NativeResourceHomeHostTest {
    static final String OWNER="查一下2026年11月17日北京到上海的单程机票，1名成人";
    static Path fixture,privateRoot;static int checks,serial;
    static final List<String> names=new ArrayList<String>();
    interface Test {void run()throws Exception;}
    static void check(boolean yes,String why){checks++;if(!yes)throw new AssertionError(why);}
    static void reject(Test t,String why)throws Exception{checks++;try{t.run();}catch(IllegalArgumentException|IllegalStateException|ActionDecision.InvalidActionException expected){return;}throw new AssertionError(why);}
    static void one(String name,Test t)throws Exception{t.run();names.add(name);}
    static String hash(String text){return NativeAppEvidence.hash(text);}
    static String id(String text){return hash(text).substring(0,32);}
    static JSONObject raw()throws Exception{return new JSONObject(new String(Files.readAllBytes(fixture),StandardCharsets.UTF_8));}
    static JSONObject node(JSONObject raw,String id){JSONArray rows=raw.getJSONArray("nodes");for(int i=0;i<rows.length();i++)if(id.equals(rows.getJSONObject(i).getString("id")))return rows.getJSONObject(i);throw new AssertionError("source node missing");}
    static final class Env {
        final String task=id("synthetic-resource-home-task:"+(++serial));
        final BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(OWNER,NativeAppGoal.CTRIP_PACKAGE,Collections.singleton(NativeAppGoal.CTRIP_PACKAGE));
        final BackgroundSession.Selection selection=new BackgroundSession.Selection(target);
        final TaskAuthorization authorization=TaskAuthorization.parse(OWNER).forExecutionSelection(selection);
        final TaskAuthorization.Gate owner=authorization.bind(task);
        final BackgroundSession background;final NativeAppEvidence.Frame frame;final NativeAppSession session;
        boolean installedCurrent=true;int journalWrites;
        Env(JSONObject raw)throws Exception{
            Path dir=privateRoot.resolve("case-"+serial);Files.createDirectories(dir);Context context=new Context(dir.toFile());
            background=new BackgroundSession(context,task,OWNER,selection,new QualificationScopeConfig.FilesRoot(context));
            java.lang.reflect.Field display=BackgroundSession.class.getDeclaredField("displayId");display.setAccessible(true);display.setInt(background,7);
            final List<PhoneObservation.Node> nodes=new ArrayList<PhoneObservation.Node>();
            JSONArray rows=raw.getJSONArray("nodes");
            for(int i=0;i<rows.length();i++){
                final JSONObject n=rows.getJSONObject(i);JSONArray b=n.getJSONArray("bounds");
                JSONObject pos=n.getJSONObject("native_tree_position"),sel=n.getJSONObject("native_selection_state");
                ObservedChildText.Result child=ObservedChildText.collect(n,new ObservedChildText.Reader<JSONObject>(){
                    public ObservedChildText.Metadata metadata(JSONObject x){return new ObservedChildText.Metadata(true,true,x.optBoolean("clickable"),x.optBoolean("clickable"),x.optBoolean("editable"),x.optBoolean("password"),false);}
                    public String text(JSONObject x){return x.optString("text","");}public String description(JSONObject x){return x.optString("description","");}
                    public String identity(JSONObject x){return x.getString("node_app_tree_sha256");}public String viewId(JSONObject x){return x.optString("view_id","");}
                    public int childCount(JSONObject x){return 0;}public JSONObject child(JSONObject x,int at){throw new AssertionError("source image tiles have zero AX children");}public void release(JSONObject x){}
                });
                Set<String> directions=new TreeSet<String>();JSONArray ds=n.getJSONArray("scroll_directions");for(int k=0;k<ds.length();k++)directions.add(ds.getString(k));
                nodes.add(new PhoneObservation.Node(n.getString("id"),n.getString("package"),n.getString("class_name"),n.optString("view_id",""),n.optString("text",""),n.optString("description",""),
                        new Rect(b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3)),n.optBoolean("clickable"),n.optBoolean("editable"),n.optBoolean("scrollable"),n.optBoolean("enabled",true),false,n.optBoolean("password"),child,
                        ObservedScrollActions.observed(directions),ObservedImeEnter.UNKNOWN,null,false,n.getString("node_app_tree_sha256"),pos.getString("path"),pos.getString("parent_class"),sel.getBoolean("selected"),sel.getBoolean("checkable"),sel.getBoolean("checked")));
            }
            String obs=id("synthetic-home-observation:"+task);int w=raw.getInt("screen_width"),h=raw.getInt("screen_height");boolean truncated=raw.optBoolean("synthetic_truncated");int type=raw.optInt("synthetic_window_type",1);
            List<NotesCompletionEvidence.Node> completionNodes=new ArrayList<NotesCompletionEvidence.Node>();
            for(PhoneObservation.Node n:nodes)completionNodes.add(new NotesCompletionEvidence.Node(n.id,n.packageName,n.text,n.label(),n.viewId,null,new int[]{n.bounds.left,n.bounds.top,n.bounds.right,n.bounds.bottom},n.editable,n.clickable,n.scrollable,n.enabled,n.password,n.childText,n.observedAppTreeSignature));
            NotesCompletionEvidence.Frame completion=new NotesCompletionEvidence.Frame(obs,target.packageName,90,7,background.generation,type,true,truncated,completionNodes);
            PhoneObservation.CollectionStats stats=new PhoneObservation.CollectionStats(1536,512,6144,nodes.size(),nodes.size(),0,0,truncated?1:0,0,0,1);
            PhoneObservation observed=new PhoneObservation(obs,target.packageName,100,w,h,0,90,new Rect(0,0,w,h),dir.resolve("synthetic-image-never-opened.png").toFile(),hash("synthetic-six-node-screen"),hash("synthetic-six-node-state"),
                    new ObservationState(hash("synthetic-subset-tree:"+raw.toString()),ImeVisibility.UNKNOWN),ObservedWindowMetadata.observed(new int[]{0,0,w,h},"android.widget.FrameLayout",type,7,new int[]{0,0,w,h},""),truncated,nodes,
                    background.generation,target.packageName,Collections.singletonList(target.packageName),stats,selection.json(),target.ownerSha256);
            frame=NativeAppObservation.copy(task,owner,background,observed,completion,hash("synthetic-subset-phone-record:"+raw.toString()));
            session=new NativeAppSession(task,owner,selection,new NativeAppEvidence.Installed(target.packageName,10367,1779,Collections.singletonMap("base",NativeCtripFlightPage.BASE_APK_SHA256)),NativeAppObservation.selectionSha(selection),background.generation,7,
                    new NativeAppSession.InstalledVerifier(){public void verify(){if(!installedCurrent)throw new IllegalStateException("synthetic installed identity changed");}},new NativeAppSession.Journal(){public void write(String leaf,Map<String,Object> value){journalWrites++;}});
            session.observed(frame);
        }
        NativeAppDomain domain(){return session.domain();}
        ActionDecision click(String targetId,String label,String observation)throws Exception{
            return ActionDecision.parse("{\"action\":\"click\",\"observation_id\":"+JSONObject.quote(observation)+",\"package\":"+JSONObject.quote(target.packageName)+",\"node_label\":"+JSONObject.quote(label)+",\"node_id\":"+JSONObject.quote(targetId)+"}",ActionDecision.IME_ACTION_SCHEMA);
        }
        ObservedTargetLabels labels(){Map<String,String> labels=new TreeMap<String,String>();for(NativeAppEvidence.Node n:frame.nodes)labels.put(n.id,n.label);return ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,frame.observationId,frame.packageName,labels);}
    }
    static void noGrant(JSONObject r)throws Exception{Env e=new Env(r);check(e.domain().clickIds.isEmpty()&&e.domain().resourceClickIds.isEmpty()&&!e.domain().resultReady,"malformed home cannot produce an action or result");}
    public static void main(String[] args)throws Exception{
        fixture=Paths.get(args[0]);privateRoot=Paths.get(args[1]);Files.createDirectories(privateRoot);Path output=Paths.get(args[2]);
        one("actual_cold_home_subset_keeps_empty_label_and_exact_resource_target",()->{Env e=new Env(raw());check(NativeCtripFlightPage.HOME.equals(e.domain().phase),"real unlabeled cold-home structure recognized");check(e.domain().clickIds.equals(Collections.singleton("n15"))&&e.domain().resourceClickIds.equals(Collections.singleton("n15")),"only exact flight image tile granted");check(e.frame.byId.get("n15").label.isEmpty()&&e.frame.byId.get("n15").text.isEmpty()&&e.frame.byId.get("n15").description.isEmpty(),"no visual label fabricated");check(!e.domain().resultReady&&e.journalWrites==2,"observation performs no query or automatic action");e.domain().requireCurrent(e.click("n15","",e.frame.observationId));});
        one("resource_evidence_names_original_id_path_signature_and_no_inferred_label",()->{Env e=new Env(raw());JSONObject d=new JSONObject(e.domain().promptEvidence()).getJSONObject("resource_clicks").getJSONObject("n15");check(d.getString("view_id").equals("ctrip.android.view:id/home_grid_flight_widget")&&d.getString("native_tree_path").equals("0/0/1"),"observed structure retained");check(d.getString("node_ref_signature").equals(e.frame.byId.get("n15").signature)&&d.getString("node_label").isEmpty()&&!d.getBoolean("visible_label_inferred"),"exact original empty pair and signature retained");});
        one("ordinary_empty_text_policy_and_other_home_icons_remain_denied",()->{Env e=new Env(raw());check(!PromptActionDomain.textOnlyClickLabel(""),"general unnamed text-only clicks remain disabled");check(!e.domain().permitsResourceClick("n14")&&!e.domain().permitsResourceClick("n16"),"neighbor images have no purpose grant");reject(()->e.domain().requireCurrent(e.click("n14","",e.frame.observationId)),"empty labels never resolve another ID");});
        one("exact_empty_pair_survives_actual_authorized_grammar",()->{Env e=new Env(raw());DecisionGrammar g=DecisionGrammar.createImeAuthorized(e.frame.observationId,e.frame.packageName,Collections.<String>emptySet(),e.domain().clickIds,Collections.<String>emptySet(),Collections.<String,ObservedScrollActions>emptyMap(),Collections.<String,ObservedImeEnter>emptyMap(),e.labels(),ObservedAppLabels.create(ObservedAppLabels.SCHEMA,e.frame.observationId,e.frame.packageName,Collections.<String,String>emptyMap()),e.owner.frame(),true,e.domain().toolMask(new HashSet<String>(Arrays.asList("click","wait","done"))),false);check(g.actions.contains("click")&&!g.successAllowed,"empty resource branch retains click and cannot complete");PromptActionDomain.requireTextOnlyClick(e.click("n15","",e.frame.observationId),g.targets,e.domain().clickIds);});
        one("invented_visual_flight_label_is_rejected",()->{Env e=new Env(raw());reject(()->e.domain().requireCurrent(e.click("n15","机票",e.frame.observationId)),"resource purpose cannot rewrite AX label");});
        one("stale_frame_cannot_reuse_empty_resource_pair",()->{Env e=new Env(raw());reject(()->e.domain().requireCurrent(e.click("n15","",id("foreign-observation"))),"same current observation mandatory");});
        one("repeat_policy_removal_cannot_be_readded_by_resource_capability",()->{Env e=new Env(raw());check(e.domain().clicks(Collections.<String>emptySet()).isEmpty(),"domain only intersects");reject(()->PromptActionDomain.requireTextOnlyClick(e.click("n15","",e.frame.observationId),e.labels(),Collections.<String>emptySet()),"removed current click stays rejected");});
        one("wrong_native_phase_or_purpose_cannot_mint_resource_click",()->{Env e=new Env(raw());reject(()->new NativeAppDomain(e.frame,"unavailable",Collections.singleton("n15"),Collections.<String,String>emptyMap(),Collections.singletonMap("n15","open_flight_form"),false,Collections.<String,Object>emptyMap(),null,Collections.<String>emptyList()),"home phase mandatory");reject(()->new NativeAppDomain(e.frame,NativeCtripFlightPage.HOME,Collections.singleton("n15"),Collections.<String,String>emptyMap(),Collections.singletonMap("n15","purchase"),false,Collections.<String,Object>emptyMap(),null,Collections.<String>emptyList()),"only read-only flight form purpose");});
        one("missing_neighbor_resource_refuses_home_identity",()->{JSONObject r=raw();node(r,"n18").put("view_id","ctrip.android.view:id/unknown");noGrant(r);});
        one("duplicate_flight_resource_refuses_ambiguous_identity",()->{JSONObject r=raw();node(r,"n18").put("view_id","ctrip.android.view:id/home_grid_flight_widget");noGrant(r);});
        one("disabled_resource_refuses_click",()->{JSONObject r=raw();node(r,"n15").put("enabled",false);noGrant(r);});
        one("overlapping_neighbor_refuses_grid_identity",()->{JSONObject r=raw();node(r,"n16").getJSONArray("bounds").put(0,280);noGrant(r);});
        one("changed_parent_path_refuses_grid_identity",()->{JSONObject r=raw();node(r,"n15").getJSONObject("native_tree_position").put("path","0/8/1");noGrant(r);});
        one("wrong_widget_class_refuses_resource_identity",()->{JSONObject r=raw();node(r,"n15").put("class_name","android.webkit.WebView");noGrant(r);});
        one("password_resource_refuses_click",()->{JSONObject r=raw();node(r,"n15").put("password",true);noGrant(r);});
        one("selected_state_refuses_image_tile",()->{JSONObject r=raw();node(r,"n15").getJSONObject("native_selection_state").put("selected",true);noGrant(r);});
        one("incomplete_collection_cannot_authorize_resource_click",()->{JSONObject r=raw();r.put("synthetic_truncated",true);reject(()->new Env(r),"actual adapter rejects incomplete authoritative completion frame");});
        one("nonapplication_window_cannot_authorize_resource_click",()->{JSONObject r=raw();r.put("synthetic_window_type",2);reject(()->new Env(r),"actual adapter rejects a nonapplication authoritative completion frame");});
        one("changed_installed_app_is_rechecked_before_resource_action",()->{Env e=new Env(raw());ActionDecision a=e.click("n15","",e.frame.observationId);e.installedCurrent=false;reject(()->e.session.beforeModelAction(1,a,id("synthetic-model-run"),120),"installed verifier still precedes native action");});
        one("model_action_must_still_supply_actual_dispatch_outcome",()->{Env e=new Env(raw());ActionDecision a=e.click("n15","",e.frame.observationId);String run=id("synthetic-valid-model-run");e.owner.check(a,run);e.session.beforeModelAction(1,a,run,120);check(!e.domain().resultReady&&e.journalWrites==3,"model acceptance alone is no result");e.session.modelActionOutcome(a,run,true,true,false,hash("synthetic-durable-receipt"),121);check(!e.domain().resultReady&&e.journalWrites==4,"even dispatch needs actual next page and full query chain");});
        JSONObject result=new JSONObject().put("schema","hepta.native-resource-home-host.v1").put("all_pass",true).put("cases",names.size()).put("assertions",checks).put("case_names",new JSONArray(names))
                .put("phone_operations",0).put("android_runtime",false).put("model_executed",false).put("business_verified",false)
                .put("boundary","Actual full PhoneObservation/NativeAppObservation/NativeCtripFlightPage/NativeAppSession/NativeAppDomain/ActionDecision/DecisionGrammar; six exact native grid records. Full-frame completeness, task/lease/installed/model and dispatch are explicit host fixtures; no service/Android execution.");
        Files.write(output,(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);System.out.println(result.toString());
    }
}
