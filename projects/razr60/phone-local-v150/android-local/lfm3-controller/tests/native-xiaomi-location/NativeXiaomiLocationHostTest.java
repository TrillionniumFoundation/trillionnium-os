package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;

/** Public derived accessibility fixture retaining the complete popup node shape.
 * Node values, tree positions, UI signatures and geometry match the private source.
 * Record IDs, device-local identity, clocks and non-UI hashes are synthetic; private
 * paths and live-capability wires are omitted. Software identity hashes are retained.
 * This is not the byte-exact private capture or runtime qualification. Model callbacks,
 * installed verifier and post-click pages are explicit host values. No phone input
 * or real modal dismissal is claimed. */
public final class NativeXiaomiLocationHostTest {
    static final String OWNER="在小米商城搜索小米路由器AX3000T，读取实际商品页面显示的当前售价并说明商品型号。只查询，不购买、不提交订单、不支付。";
    static final String PKG="com.xiaomi.shop",GEN="12345678-1234-4234-8234-123456789abc";
    static final String DECLINE=NativeXiaomiProductPage.DECLINE_LOCATION;
    static final String APK="95883c057eb15bc6e50a82f2e22da13b77980871624f60a2fb9e50cfdf4a8373";
    static final String SIGNER="c9009d01ebf9f5d0302bc71b2fe9aa9a47a432bba17308a3111b75d7b2149025";
    static final String OBS_SHA="eb0f3e7e82a8dc45fe879df0ddfced6d49aa1d204de564a2f588b5d267925331";
    static final String OBS_FILE="public-location-observation.json";
    static JSONObject observed,derivedRecord;static Path source;static ProfileTarget fixtureTarget;
    static final List<String> names=new ArrayList<String>();static int assertions;
    interface Work {void run()throws Exception;}
    interface Change {void apply(JSONObject o)throws Exception;}
    static void yes(boolean v,String reason){assertions++;if(!v)throw new AssertionError(reason);}
    static void one(String name,Work work)throws Exception{yes(!names.contains(name),"unique case");work.run();names.add(name);}
    static void rejects(Work work,String reason)throws Exception{assertions++;try{work.run();}catch(IllegalArgumentException|IllegalStateException|ActionDecision.InvalidActionException expected){return;}throw new AssertionError(reason);}
    static String hash(String x){return NativeAppEvidence.hash(x);}
    static String id(String x){return hash(x).substring(0,32);}
    static JSONObject copy(JSONObject j){return new JSONObject(j.toString());}
    static JSONObject node(JSONObject o,int i){return o.getJSONArray("nodes").getJSONObject(i);}
    static List<NativeAppEvidence.Node> nodes(JSONObject o){
        List<NativeAppEvidence.Node> out=new ArrayList<NativeAppEvidence.Node>();JSONArray rows=o.getJSONArray("nodes");
        for(int i=0;i<rows.length();i++){
            JSONObject n=rows.getJSONObject(i),p=n.getJSONObject("native_tree_position"),s=n.getJSONObject("native_selection_state");
            JSONArray b=n.getJSONArray("bounds");String text=n.optString("text",""),desc=n.optString("description","");
            String label=ObservedTargetLabels.project(!text.isEmpty()?text:!desc.isEmpty()?desc:n.optString("child_text",""));
            Boolean selected=s.optBoolean("observed")?Boolean.valueOf(s.getBoolean("selected")):null;
            Set<String> directions=new TreeSet<String>();JSONArray ds=n.optJSONArray("scroll_directions");
            if(ds!=null)for(int k=0;k<ds.length();k++)directions.add(ds.getString(k));
            out.add(new NativeAppEvidence.Node(n.getString("id"),n.getString("package"),n.getString("class_name"),n.optString("view_id",""),
                    text,desc,p.getString("path"),p.getString("parent_class"),n.optString("node_app_tree_sha256",null),label,
                    b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3),n.optBoolean("enabled",true),n.optBoolean("password"),
                    n.optBoolean("clickable"),n.optBoolean("editable"),n.optBoolean("scrollable"),selected,
                    selected==null?null:Boolean.valueOf(s.getBoolean("checkable")),selected==null?null:Boolean.valueOf(s.getBoolean("checked")),directions));
        }return out;
    }
    static final class Binding implements BackgroundTaskTarget.SelectionBinding {
        final BackgroundTaskTarget target;
        Binding(ProfileTarget profile){target=profile==null?BackgroundTaskTarget.resolveExplicitSelection(OWNER,PKG,Collections.singleton(PKG))
                :BackgroundTaskTarget.resolveExplicitSelection(OWNER,PKG,Collections.singleton(PKG),profile);}
        public BackgroundTaskTarget executionTarget(){return target;}
    }
    static final class Harness {
        final String task;final ProfileTarget profile;final Binding binding;final TaskAuthorization auth;final TaskAuthorization.Gate gate;
        final NativeAppSession session;final List<Map<String,Object>> journal=new ArrayList<Map<String,Object>>();
        long clock=1000408;int seq,step,verifies;boolean installedCurrent=true,failJournal;String run;
        NativeAppEvidence.Frame frame;
        Harness(String label)throws Exception{this(label,fixtureTarget);}
        Harness(String label,ProfileTarget profile)throws Exception{
            task=id("explicit-host-location-task:"+label);this.profile=profile;binding=new Binding(profile);
            auth=TaskAuthorization.parse(OWNER).forExecutionSelection(binding);gate=auth.bind(task);
            NativeAppEvidence.Installed installed=profile==null?new NativeAppEvidence.Installed(PKG,12345,20261010,Collections.singletonMap("base",APK))
                    :new NativeAppEvidence.Installed(profile);
            session=new NativeAppSession(task,gate,binding,installed,hash("explicit-host-selection"),GEN,42,
                    ()->{verifies++;if(!installedCurrent)throw new IllegalStateException("explicit host installation changed");},
                    (leaf,value)->{if(failJournal&&leaf.startsWith("native-app-attempt"))throw new IllegalStateException("explicit host journal failure");
                        Map<String,Object> entry=new LinkedHashMap<String,Object>();entry.put("leaf",leaf);entry.put("value",value);journal.add(entry);});
        }
        WindowOwnership window(int window){return profile==null?null:new WindowOwnership(profile,GEN,42,window,1000123,456,
                "22222222-2222-4222-8222-222222222222","11111111-1111-4111-8111-111111111111",profile.profile.userId,
                profile.profile.serial,profile.fullUid,clock-1,clock+3000);}
        NativeAppEvidence.Frame make(List<NativeAppEvidence.Node> ns,String tree,int window,int width,int height,
                int left,int top,int right,int bottom,boolean complete,boolean truncated,boolean metadata,int type,WindowOwnership proof){
            return new NativeAppEvidence.Frame(task,binding.target.ownerSha256,binding.target.targetSha256,auth.sha256,
                    hash("explicit-host-selection"),id(task+":frame:"+(++seq)),PKG,GEN,tree,tree,hash("explicit-host-pixels:"+seq),
                    hash("explicit-host-record:"+seq),hash("explicit-host-completion:"+seq),42,window,0,width,height,left,top,right,bottom,
                    clock,truncated,complete,ns,type,metadata,proof);
        }
        NativeAppEvidence.Frame from(JSONObject o,boolean proof){
            clock+=10;List<NativeAppEvidence.Node> ns=nodes(o);JSONObject w=o.getJSONObject("window"),c=o.getJSONObject("collection");JSONArray b=w.getJSONArray("bounds");
            boolean complete=c.getInt("retained_nodes")==ns.size()&&c.getInt("pending_nodes_at_stop")==0
                    &&c.getLong("child_slots_omitted_by_traversal_limit")==0&&c.getInt("nodes_omitted_by_node_limit")==0
                    &&c.getInt("nodes_omitted_by_text_limit")==0&&c.getJSONArray("truncation_reasons").length()==0;
            return make(ns,o.getString("app_tree_sha256"),w.getInt("window_id"),o.getInt("screen_width"),o.getInt("screen_height"),
                    b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3),complete,o.getBoolean("nodes_truncated"),
                    "observed".equals(w.getString("metadata_status")),w.getInt("type"),proof?window(w.getInt("window_id")):null);
        }
        void observe(NativeAppEvidence.Frame f)throws Exception{frame=f;session.observed(f);}
        void location()throws Exception{observe(from(copy(observed),true));}
        void xml(String name)throws Exception{
            clock+=10;NativeXmlFixture.Snapshot s=NativeXmlFixture.read(source.resolve("tests/native-xiaomi-product/fixtures/"+name));int[] b=s.rootBounds;
            observe(make(s.nodes,s.sourceSha256,1600,b[2],b[3],b[0],b[1],b[2],b[3],true,false,true,1,window(1600)));
        }
        void image()throws Exception{
            clock+=10;NativeAppEvidence.Frame f=ActualXiaomiImageModalFixture.frame();
            observe(make(f.nodes,f.treeSha,1601,f.width,f.height,f.left,f.top,f.right,f.bottom,true,false,true,1,window(1601)));
        }
        String target(String purpose){for(Map.Entry<String,String> e:session.domain().purposes.entrySet())if(purpose.equals(e.getValue()))return e.getKey();return null;}
        ActionDecision click(String node)throws Exception{return ActionDecision.parse(new JSONObject().put("action","click").put("package",PKG)
                .put("observation_id",frame.observationId).put("node_id",node).put("node_label",frame.byId.get(node).label).toString(),ActionDecision.IME_ACTION_SCHEMA);}
        ActionDecision action(String purpose)throws Exception{
            String node=target(purpose);yes(node!=null,"actual domain purpose required: "+purpose);
            String kind="back".equals(node)?"back":session.domain().editValues.containsKey(node)?"type":"click";
            JSONObject j=new JSONObject().put("action",kind).put("package",PKG).put("observation_id",frame.observationId);
            if(!"back".equals(node)){j.put("node_id",node).put("node_label",frame.byId.get(node).label);if("type".equals(kind))j.put("text",session.domain().editValues.get(node));}
            return ActionDecision.parse(j.toString(),ActionDecision.IME_ACTION_SCHEMA);
        }
        void begin(ActionDecision a)throws Exception{run=id(task+":explicit-host-model:"+(++step));clock+=10;gate.check(a,run);session.beforeModelAction(step,a,run,clock);}
        void issue(ActionDecision a,boolean accepted,boolean dispatched,boolean stale)throws Exception{
            begin(a);session.modelActionOutcome(a,run,accepted,dispatched,stale,hash("explicit-host-receipt:"+run),++clock);
        }
        void perform(String purpose,String next)throws Exception{issue(action(purpose),true,true,false);xml(next);}
        Map<?,?> progress(){return (Map<?,?>)session.evidence().get("progress");}
        void noBusiness(){yes(!session.domain().resultReady&&session.resultRecord()==null,"decline is not a product result");
            yes(Boolean.FALSE.equals(progress().get("product_query_observed")),"decline is not query proof");
            yes(Boolean.FALSE.equals(progress().get("product_detail_navigation_observed")),"decline is not detail proof");}
    }
    static NativeXiaomiProductPage.Page inspect(JSONObject o)throws Exception{
        Harness h=new Harness("pure-shape");NativeAppEvidence.Frame f=h.from(o,true);return NativeXiaomiProductPage.inspect(h.binding.target.nativeGoal,f);
    }
    static void noTarget(JSONObject o)throws Exception{
        try{NativeXiaomiProductPage.Page p=inspect(o);yes(!NativeXiaomiProductPage.OPTIONAL_LOCATION.equals(p.phase)&&p.clickIds.isEmpty()&&p.quote==null,"changed prompt cannot grant a decline");}
        catch(IllegalArgumentException expected){yes(expected.getMessage()!=null,"invalid complete frame rejected");}
    }
    static void mutation(String name,Change change)throws Exception{one(name,()->{JSONObject o=copy(observed);change.apply(o);noTarget(o);});}
    static ProfileTarget install(long version,String apk,Set<String> signers){return new ProfileTarget(fixtureTarget.profile,fixtureTarget.fullUid,PKG,
            fixtureTarget.component,version,Collections.singletonMap("base",apk),signers);}
    static void cases()throws Exception{
        one("public_derived_record_preserves_complete_three_node_location_prompt",()->{
            yes(observed.getJSONArray("nodes").length()==3&&observed.getJSONObject("collection").getInt("visited_nodes")==4,"full original root plus three leaves");
            NativeXiaomiProductPage.Page p=inspect(copy(observed));yes(NativeXiaomiProductPage.OPTIONAL_LOCATION.equals(p.phase),"actual prompt classified");
            yes(p.clickIds.equals(Collections.singleton("n1"))&&p.purposes.equals(Collections.singletonMap("n1",DECLINE)),"only original negative NodeRef is proposed");
            yes(p.editValues.isEmpty()&&p.quote==null,"no editor or quote invented");
            yes(p.evidence().toString().contains("enable_control_not_granted")&&p.evidence().toString().contains("开启定位"),"positive branch retained as observed excluded evidence");
        });
        one("derived_profile_session_grants_original_decline_label_only",()->{
            Harness h=new Harness("grant");h.location();NativeAppDomain d=h.session.domain();
            yes(d.clickIds.equals(Collections.singleton("n1"))&&!d.backAllowed&&d.editValues.isEmpty(),"only negative control, no Back/type");
            yes(d.toolMask(null).equals(new TreeSet<String>(Arrays.asList("click","wait","done"))),"existing original tool ceiling");
            d.requireCurrent(h.click("n1"));rejects(()->d.requireCurrent(h.click("n2")),"enable-location never allowed");
            rejects(()->d.requireCurrent(h.click("n0")),"message never clickable");
            Map<?,?> view=(Map<?,?>)d.promptEvidence().get("provider");yes(Boolean.TRUE.equals(view.get("decline_action_available")),"only verified binding exposes guidance");
            yes(view.get("next_goal").toString().contains("暂不开启"),"model receives literal original target guidance");h.noBusiness();
        });
        for(int i=0;i<3;i++){final int n=i;
            mutation("exact_resource_id_"+i,o->node(o,n).put("view_id","com.xiaomi.shop:id/nav_text"));
            mutation("exact_complete_literal_"+i,o->node(o,n).put("text",node(o,n).getString("text")+"…"));
            mutation("exact_class_"+i,o->node(o,n).put("class_name","android.widget.Button"));
            mutation("exact_parent_"+i,o->node(o,n).getJSONObject("native_tree_position").put("parent_class","android.widget.LinearLayout"));
            mutation("exact_path_"+i,o->node(o,n).getJSONObject("native_tree_position").put("path","0/9/"+n));
            mutation("empty_description_"+i,o->node(o,n).put("description","另一个语义"));
            mutation("enabled_"+i,o->node(o,n).put("enabled",false));
            mutation("password_"+i,o->node(o,n).put("password",true));
            mutation("not_editable_"+i,o->node(o,n).put("editable",true));
            mutation("not_scrollable_"+i,o->node(o,n).put("scrollable",true));
            mutation("empty_scroll_actions_"+i,o->node(o,n).put("scroll_directions",new JSONArray().put("forward")));
            mutation("observed_selection_"+i,o->node(o,n).getJSONObject("native_selection_state").put("observed",false));
            mutation("unselected_"+i,o->node(o,n).getJSONObject("native_selection_state").put("selected",true));
            mutation("not_checkable_"+i,o->node(o,n).getJSONObject("native_selection_state").put("checkable",true));
            mutation("unchecked_"+i,o->node(o,n).getJSONObject("native_selection_state").put("checked",true));
            mutation("actual_clickable_role_"+i,o->node(o,n).put("clickable",n==0));
            mutation("exact_package_"+i,o->node(o,n).put("package","com.android.permissioncontroller"));
        }
        mutation("missing_leaf_is_not_a_complete_prompt",o->{o.getJSONArray("nodes").remove(2);o.getJSONObject("collection").put("retained_nodes",2);});
        mutation("extra_interactive_leaf_refuses_entire_prompt",o->{JSONObject n=copy(node(o,1)).put("id","n3");n.getJSONObject("native_tree_position").put("path","0/3");o.getJSONArray("nodes").put(n);o.getJSONObject("collection").put("retained_nodes",4);});
        mutation("duplicate_path_refuses_entire_prompt",o->node(o,2).getJSONObject("native_tree_position").put("path","0/1"));
        mutation("duplicate_node_id_refuses_entire_prompt",o->node(o,2).put("id","n1"));
        mutation("missing_signature_refuses_original_reference",o->node(o,1).remove("node_app_tree_sha256"));
        mutation("system_permission_window_is_not_app_prompt",o->o.getJSONObject("window").put("type",3));
        mutation("unknown_window_metadata_refuses_prompt",o->o.getJSONObject("window").put("metadata_status","unknown"));
        mutation("fullscreen_root_is_not_observed_modal",o->o.getJSONObject("window").put("bounds",new JSONArray(new int[]{0,0,1224,2992})));
        mutation("clipped_node_refuses_prompt",o->node(o,1).put("bounds",new JSONArray(new int[]{0,1576,595,1698})));
        mutation("overlapping_choices_refuse_prompt",o->node(o,1).put("bounds",new JSONArray(new int[]{170,1576,700,1698})));
        mutation("message_button_overlap_refuses_prompt",o->node(o,0).put("bounds",new JSONArray(new int[]{170,1300,1054,1600})));
        mutation("misaligned_choices_refuse_prompt",o->node(o,2).put("bounds",new JSONArray(new int[]{629,1577,1054,1698})));
        mutation("missing_graph_population_refuses_prompt",o->o.getJSONObject("collection").put("retained_nodes",4));
        mutation("pending_graph_nodes_refuse_prompt",o->o.getJSONObject("collection").put("pending_nodes_at_stop",1));
        mutation("omitted_child_slot_refuses_prompt",o->o.getJSONObject("collection").put("child_slots_omitted_by_traversal_limit",1));
        mutation("omitted_text_refuses_prompt",o->o.getJSONObject("collection").put("nodes_omitted_by_text_limit",1));
        mutation("truncated_graph_refuses_prompt",o->o.put("nodes_truncated",true));
        mutation("changed_decline_is_not_semantic_fuzzy_match",o->node(o,1).put("text","同意并继续"));
        mutation("changed_enable_makes_unknown_dialog",o->node(o,2).put("text","登录"));
        one("wrong_version_and_complete_apk_identity_keep_original_rejection",()->{
            rejects(()->new Harness("version",install(20261011L,APK,Collections.singleton(SIGNER))),"different version");
            rejects(()->new Harness("apk",install(20261010L,hash("different APK"),Collections.singleton(SIGNER))),"different base APK");
        });
        one("changed_or_extra_signer_never_grants_new_decline",()->{
            for(Set<String> signers:Arrays.asList(Collections.singleton(hash("other signer")),new TreeSet<String>(Arrays.asList(SIGNER,hash("extra signer"))))){
                Harness h=new Harness("signer"+signers,install(20261010L,APK,signers));h.location();yes(h.session.domain().clickIds.isEmpty(),"unqualified signer cannot use parser candidate");
            }
        });
        one("ordinary_user0_without_typed_signer_does_not_gain_new_permission",()->{Harness h=new Harness("personal",null);h.location();yes(h.session.domain().clickIds.isEmpty()&&!h.session.domain().backAllowed,"new branch remains qualified managed-profile only");});
        one("actual_profile_window_proof_is_still_required",()->{Harness h=new Harness("missingproof");rejects(()->h.observe(h.from(copy(observed),false)),"no synthetic missing-window fallback");});
        one("fresh_installed_verifier_runs_before_decline_proposal",()->{Harness h=new Harness("changedinstall");h.location();ActionDecision a=h.action(DECLINE);h.installedCurrent=false;rejects(()->h.begin(a),"changed package cannot use old candidate");yes(h.step==1,"one actual host proposal only");});
        one("decline_uses_original_strict_action_path_without_variation_guard",()->{Harness h=new Harness("strict");h.location();ActionDecision a=h.action(DECLINE);h.begin(a);
            yes(h.session.actionGuard(a,h.run,h.frame.observationId,h.clock,h.clock+8000)==null,"new purpose cannot gain graph-variation comparison");
            yes(Boolean.TRUE.equals(h.progress().get("product_modal_exit_attempted")),"single proposal consumed before dispatch");h.noBusiness();});
        one("same_prompt_after_accepted_click_remains_pending_without_second_target",()->{Harness h=new Harness("same");h.location();h.issue(h.action(DECLINE),true,true,false);h.location();
            yes(h.progress().get("pending")!=null&&h.session.domain().clickIds.isEmpty()&&!h.session.domain().backAllowed,"no repeated click while awaiting transition");h.noBusiness();});
        one("stale_undispatched_decline_consumes_same_budget_without_retry",()->{Harness h=new Harness("stale");h.location();h.issue(h.action(DECLINE),false,false,true);h.location();
            yes(Boolean.TRUE.equals(h.progress().get("product_modal_exit_attempted"))&&h.session.domain().clickIds.isEmpty(),"stale does not mint a replacement decline");h.noBusiness();});
        one("unknown_dispatch_cannot_advance_or_replay_without_outcome",()->{Harness h=new Harness("unknown");h.location();h.begin(h.action(DECLINE));rejects(()->h.location(),"missing outcome keeps original action unresolved");yes(h.journal.size()==3,"only binding, observation and attempt journal");});
        one("rejected_dispatched_decline_invalidates_session",()->{Harness h=new Harness("reject");h.location();h.issue(h.action(DECLINE),false,true,false);rejects(()->h.xml("home.xml"),"later home cannot repair rejected effect");});
        one("failed_attempt_journal_does_not_free_single_use_budget",()->{Harness h=new Harness("journal");h.location();ActionDecision a=h.action(DECLINE);h.failJournal=true;rejects(()->h.begin(a),"journal write refused");h.failJournal=false;rejects(()->h.location(),"inflight intent remains unresolved");});
        one("original_fifteen_second_transition_bound_is_not_extended",()->{Harness h=new Harness("late");h.location();h.issue(h.action(DECLINE),true,true,false);h.clock+=15001;h.xml("home.xml");rejects(()->h.session.domain(),"late home cannot restore authority");});
        for(String page:Arrays.asList("search-entry.xml","results.xml","detail.xml")){final String leaf=page;one("unrelated_post_decline_"+page+"_is_not_home_proof",()->{Harness h=new Harness("pending:"+leaf);h.location();h.issue(h.action(DECLINE),true,true,false);h.xml(leaf);
            yes(h.progress().get("pending")!=null&&h.session.domain().clickIds.isEmpty(),"only fresh home resolves navigation");h.noBusiness();});}
        one("fresh_home_resolves_only_navigation_not_product_price",()->{Harness h=new Harness("home");h.location();h.perform(DECLINE,"home.xml");
            yes(h.progress().get("pending")==null&&h.target("open_search")!=null,"original fresh home query entry restored");List<?> transitions=(List<?>)h.progress().get("transitions");yes(transitions.size()==1,"one transition");
            Map<?,?> t=(Map<?,?>)transitions.get(0);yes(Boolean.TRUE.equals(t.get("optional_location_decline_observed"))&&Boolean.FALSE.equals(t.get("query_or_result_proof_created")),"navigation evidence only");h.noBusiness();});
        one("location_then_image_modal_shares_existing_one_exit_budget",()->{Harness h=new Harness("location-image");h.location();h.perform(DECLINE,"home.xml");h.image();yes(!h.session.domain().backAllowed&&h.session.domain().clickIds.isEmpty(),"second modal exit not added");});
        one("image_modal_then_location_shares_existing_one_exit_budget",()->{Harness h=new Harness("image-location");h.image();h.perform("dismiss_image_modal_once","home.xml");h.location();yes(h.session.domain().clickIds.isEmpty()&&!h.session.domain().backAllowed,"existing image use consumes shared budget");});
        one("full_original_query_card_detail_chain_is_still_required",()->{Harness h=new Harness("business");h.location();h.perform(DECLINE,"home.xml");h.noBusiness();h.perform("open_search","search-entry.xml");h.perform("set_product_query","suggestions.xml");
            String submit=h.target("submit_exact_suggestion")==null?"submit_product_query":"submit_exact_suggestion";h.perform(submit,"results.xml");yes(!h.session.domain().resultReady,"card alone remains insufficient");h.perform("open_exact_product","detail.xml");
            yes(h.session.domain().resultReady&&Boolean.TRUE.equals(h.progress().get("product_query_observed"))&&Boolean.TRUE.equals(h.progress().get("product_detail_navigation_observed")),"original host exact model/quote/navigation chain still used");});
    }
    public static void main(String[] args)throws Exception{
        source=Paths.get(args[0]);Path fixture=source.resolve("tests/native-xiaomi-location/fixtures/"+OBS_FILE);byte[] bytes=Files.readAllBytes(fixture);
        yes(bytes.length==35411&&NativeAppEvidence.hash(new String(bytes,StandardCharsets.UTF_8)).equals(OBS_SHA),"exact reviewed public derived fixture bytes");
        derivedRecord=new JSONObject(new String(bytes,StandardCharsets.UTF_8));observed=derivedRecord.getJSONObject("observation");
        fixtureTarget=ProfileTarget.fromWire(observed.getJSONObject("background_session").getString("profile_target_wire"));
        yes(fixtureTarget.fullUid==1012345&&fixtureTarget.profile.userId==10&&fixtureTarget.profile.serial==20,"explicit synthetic profile identity from the public fixture");
        yes(fixtureTarget.signerSha256.equals(Collections.singleton(SIGNER))&&fixtureTarget.apkHashes.equals(Collections.singletonMap("base",APK)),"preserved software signer/APK set");
        cases();JSONObject result=new JSONObject().put("schema","hepta.native-xiaomi-location-host.v1").put("all_pass",true)
                .put("cases",names.size()).put("assertions",assertions).put("case_names",new JSONArray(names)).put("derived_fixture_sha256",OBS_SHA)
                .put("private_originals_modified",false).put("public_fixture_is_exact_capture",false).put("synthetic_record_identity",true).put("phone_operations",0).put("model_executed",false).put("platform_dispatch_executed",false)
                .put("business_verified",false).put("phone_runtime_qualified",false).put("post_decline_pages_are_explicit_host_sequence",true);
        Files.write(Paths.get(args[1]),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(result.toString());
    }
}
