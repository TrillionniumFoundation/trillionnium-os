package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;

/** Compiles with complete actual production classes. Frozen real capture replay
 * and explicitly labelled parser-DTO counterfactuals, never Android authority. */
public final class NativeXiaomiDirectCardHostTest {
    private static final String OWNER="在小米商城搜索小米路由器AX3000T，读取实际商品页面显示的当前售价并说明商品型号。只查询，不购买、不提交订单、不支付。";
    private static final String TITLE="Xiaomi路由器AX3000T";
    private static final String[] IDS={
        "572304edf78a4ba89228579022176658","56f9d4f20b0044ac93059628dd9f3913","aeff5d24618b4a2f9ec9ff9ad3392e67"};
    private static final List<Map<String,Object>> RESULTS=new ArrayList<Map<String,Object>>();
    private static int assertions;
    private static boolean candidate;
    private NativeXiaomiDirectCardHostTest(){}
    private interface Check {void run() throws Exception;}
    private interface Mutation {void apply(List<JSONObject> nodes);}
    private static void need(boolean yes,String why){assertions++;if(!yes)throw new AssertionError(why);}
    private static String hash(byte[] bytes){return NativeAppEvidence.hash(new String(bytes,StandardCharsets.UTF_8));}
    private static JSONObject object(Path p)throws Exception{return new JSONObject(new String(Files.readAllBytes(p),StandardCharsets.UTF_8));}
    private static Map<String,Object> map(){return new LinkedHashMap<String,Object>();}
    private static void run(String name,String kind,Check check){
        Map<String,Object> row=map();row.put("name",name);row.put("fixture_kind",kind);
        int before=assertions;
        try{check.run();row.put("passed",true);}
        catch(Exception|AssertionError error){row.put("passed",false);row.put("error",error.getClass().getName()+": "+error.getMessage());}
        row.put("assertions",assertions-before);RESULTS.add(row);
    }
    private static final class Fixture {
        final JSONObject frame,wire,receipt;
        final ObservationCaptureEvidence capture;
        final WindowOwnership window;
        final List<JSONObject> nodes=new ArrayList<JSONObject>();
        final NativeAppEvidence.Frame actual;
        Fixture(Path dir,String id,int page)throws Exception{
            Path framePath=dir.resolve("native-app-frame-"+id+".json");
            Path axPath=dir.resolve(id+"-native-ax.json");
            byte[] frameBytes=Files.readAllBytes(framePath),axBytes=Files.readAllBytes(axPath);
            frame=new JSONObject(new String(frameBytes,StandardCharsets.UTF_8));
            JSONObject old=object(dir.resolve(String.format("native-app-page-%04d.json",page)));
            wire=old.getJSONObject("frame");receipt=new JSONObject(new String(axBytes,StandardCharsets.UTF_8));
            need(id.equals(frame.getString("observation_id"))&&id.equals(wire.getString("observation_id")),"same actual observation");
            need(hash(frameBytes).equals(wire.getString("phone_observation_record_sha256")),"complete original frame SHA");
            need(hash(axBytes).equals(wire.getJSONObject("capture").getString("receipt_sha256")),"complete original AX SHA");
            need(axBytes.length==wire.getJSONObject("capture").getInt("receipt_bytes"),"complete AX byte count");
            need("search_results_unverified".equals(old.getJSONObject("provider").getString("phase")),"archived original refusal");
            need(old.getJSONObject("provider").getJSONArray("missing").toList().equals(
                    Collections.<Object>singletonList("actual_clickable_product_card_required")),"exact archived failed predicate");
            capture=ObservationCaptureEvidence.fromSealedNativeAx(receipt.toMap(),axBytes,hash(axBytes));
            ProfileTarget target=ProfileTarget.fromWire(frame.getJSONObject("background_session").getString("profile_target_wire"));
            JSONObject w=wire.getJSONObject("actual_profile_window");
            window=new WindowOwnership(target,w.getString("generation"),w.getInt("display_id"),w.getInt("window_id"),
                    w.getInt("task_id"),w.getInt("parent_task_id"),w.getString("task_token_id"),w.getString("proof_id"),
                    w.getInt("user_id"),w.getLong("user_serial"),w.getInt("full_uid"),w.getLong("observed_elapsed_ms"),w.getLong("expires_elapsed_ms"));
            need(window.sha256.equals(w.getString("proof_sha256")),"original complete profile-window identity");
            need(target.versionCode==20261010L,"same actual Xiaomi version");
            need(target.sha256.equals("b87c9b12660fcdd9c2bf1b8e77cc6fcf9428cdeb4ccd02908b59fc9f1b39f7c4"),"same installed target identity");
            Map<String,JSONObject> first=index(receipt.getJSONObject("first").getJSONArray("nodes"));
            Map<String,JSONObject> second=index(receipt.getJSONObject("second").getJSONArray("nodes"));
            JSONArray retained=frame.getJSONArray("nodes");
            need(retained.length()==51&&wire.getInt("retained_nodes")==51,"all 51 real retained nodes");
            for(int i=0;i<retained.length();i++){
                JSONObject n=retained.getJSONObject(i),position=n.getJSONObject("native_tree_position");
                String path=position.getString("path");JSONObject raw=second.get(path);
                need(raw!=null&&raw.similar(first.get(path)),"same full census raw node: "+path);
                need(raw.getBoolean("visible")&&raw.getString("package").equals(n.getString("package"))
                        &&raw.getString("class").equals(n.getString("class_name"))
                        &&raw.getString("parent_class").equals(position.getString("parent_class"))
                        &&raw.getJSONArray("bounds").similar(n.getJSONArray("bounds")),"exact raw retained projection: "+path);
                need(raw.getString("text").equals(n.optString("text","")),"raw text is not child_text: "+path);
                need(raw.getBoolean("clickable")==n.optBoolean("clickable",false)
                        &&raw.getBoolean("scrollable")==n.optBoolean("scrollable",false),"actual interaction flags: "+path);
                JSONObject spec=new JSONObject(raw.toString());
                spec.put("id",n.getString("id"));spec.put("scroll_directions",n.getJSONArray("scroll_directions"));
                nodes.add(spec);
            }
            actual=build(nodes,wire);
            need(actual.capture!=null&&actual.capture.nativeText()&&actual.screenshotSha==null,"typed AX full receipt replay");
            need(actual.ownerSha.equals(NativeAppGoal.parse(OWNER,NativeAppGoal.XIAOMI_PACKAGE).ownerSha256),"immutable exact owner");
            need(NativeAppEvidence.fingerprint(actual.evidence()).equals(NativeAppEvidence.fingerprint(wire.toMap())),
                    "complete Frame evidence reproduced with explicit null keys and integral numeric normalization");
        }
        private static Map<String,JSONObject> index(JSONArray array){
            Map<String,JSONObject> out=new LinkedHashMap<String,JSONObject>();
            for(int i=0;i<array.length();i++){JSONObject n=array.getJSONObject(i);String path=n.getString("path");
                need(out.put(path,n)==null,"no duplicate full census path");}
            return out;
        }
        NativeAppEvidence.Frame build(List<JSONObject> specs,JSONObject meta){
            List<NativeAppEvidence.Node> built=new ArrayList<NativeAppEvidence.Node>();
            for(JSONObject n:specs){
                JSONArray b=n.getJSONArray("bounds");Set<String> dirs=new LinkedHashSet<String>();
                JSONArray ds=n.getJSONArray("scroll_directions");
                for(int i=0;i<ds.length();i++)dirs.add(ds.getString(i));
                built.add(new NativeAppEvidence.Node(n.getString("id"),n.getString("package"),n.getString("class"),
                    n.getString("view_id"),n.getString("text"),n.getString("description"),n.getString("path"),n.getString("parent_class"),
                    n.isNull("ref_signature_sha256")?null:n.getString("ref_signature_sha256"),n.getString("label"),
                    b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3),n.getBoolean("enabled"),n.getBoolean("password"),
                    n.getBoolean("clickable"),n.getBoolean("editable"),n.getBoolean("scrollable"),
                    bool(n,"selected"),bool(n,"checkable"),bool(n,"checked"),dirs));
            }
            JSONObject b=receipt.getJSONObject("binding");
            return new NativeAppEvidence.Frame(meta.getString("task_id"),meta.getString("owner_sha256"),meta.getString("execution_target_sha256"),
                    meta.getString("task_authorization_sha256"),meta.getString("actual_selection_sha256"),meta.getString("observation_id"),
                    meta.getString("package"),meta.getString("background_generation"),meta.getString("app_tree_sha256"),
                    meta.getString("observation_state_sha256"),null,meta.getString("phone_observation_record_sha256"),
                    meta.getString("completion_frame_sha256"),meta.getInt("display_id"),meta.getInt("window_id"),meta.getInt("rotation"),
                    b.getInt("width"),b.getInt("height"),b.getInt("left"),b.getInt("top"),b.getInt("right"),b.getInt("bottom"),
                    meta.getLong("captured_elapsed_ms"),meta.getBoolean("nodes_truncated"),meta.getBoolean("actual_collection_complete"),
                    built,meta.getInt("window_type"),meta.getBoolean("window_metadata_observed"),window,capture);
        }
        NativeAppEvidence.Frame mutate(Mutation edit){
            List<JSONObject> copy=new ArrayList<JSONObject>();for(JSONObject n:nodes)copy.add(new JSONObject(n.toString()));
            edit.apply(copy);
            // Counterfactual DTOs are separately labelled. They are not sealed
            // current observations or fresh NodeRefs, and grant no action.
            return build(copy,new JSONObject(wire.toString()));
        }
    }
    private static Boolean bool(JSONObject n,String key){return n.isNull(key)?null:Boolean.valueOf(n.getBoolean(key));}
    private static JSONObject node(List<JSONObject> ns,String id){
        for(JSONObject n:ns)if(id.equals(n.getString("id")))return n;
        throw new AssertionError("missing mutation node "+id);
    }
    private static void put(List<JSONObject> ns,String id,String key,Object value){node(ns,id).put(key,value==null?JSONObject.NULL:value);}
    private static void remove(List<JSONObject> ns,String id){JSONObject n=node(ns,id);ns.remove(n);}
    private static void bounds(List<JSONObject> ns,String id,int l,int t,int r,int b){put(ns,id,"bounds",new JSONArray(Arrays.asList(l,t,r,b)));}
    private static NativeXiaomiProductPage.Page inspect(NativeAppEvidence.Frame f){
        return NativeXiaomiProductPage.inspect(NativeAppGoal.parse(OWNER,NativeAppGoal.XIAOMI_PACKAGE),f);
    }
    private static void quote(NativeAppEvidence.Frame f,String amount,String secondary){
        NativeXiaomiProductPage.Page p=inspect(f);
        if(!candidate){
            need("search_results_unverified".equals(p.phase)&&p.quote==null,"baseline rejects unobserved direct-child layout");
            need(p.missing.equals(Collections.singletonList("actual_clickable_product_card_required")),"baseline exact distance-two refusal");
            return;
        }
        need("search_results_quote".equals(p.phase)&&p.quote!=null,"candidate identifies only a search-card displayed quote");
        need("search_card".equals(p.quote.kind)&&TITLE.equals(p.quote.modelRaw),"exact model and listing-only kind");
        need(amount.equals(p.quote.amountDecimal)&&"CNY".equals(p.quote.currency),"actual displayed current amount");
        need(secondary.equals(p.quote.comparisonAmountDecimal)&&"secondary_display_amount".equals(p.quote.comparisonKind),"secondary amount is not crossed-out or discounted semantics");
        need(p.clickIds.equals(Collections.singleton("n9"))&&p.purposes.equals(Collections.singletonMap("n9","open_exact_product")),"only actual card candidate");
        need(p.frame==f&&p.quote.frame==f,"exact current Frame retained by quote and page");
        Map<String,Object> q=p.quote.evidence(),e=p.evidence();
        need(Boolean.FALSE.equals(e.get("dispatch_authority"))&&Boolean.FALSE.equals(e.get("task_completion_authority"))
                &&Boolean.FALSE.equals(e.get("installed_identity_verified_here"))&&Boolean.FALSE.equals(e.get("query_dispatched"))
                &&Boolean.FALSE.equals(e.get("order_submitted")),"provider never grants authority or completion");
        need(Boolean.FALSE.equals(q.get("task_complete"))&&Boolean.FALSE.equals(q.get("order_submitted"))
                &&Boolean.FALSE.equals(q.get("final_checkout_price_verified"))&&Boolean.FALSE.equals(q.get("selected_sku_verified"))
                &&Boolean.FALSE.equals(q.get("lowest_price_verified")),"quote scope never claims checkout/detail/SKU/lowest price");
        JSONObject sources=new JSONObject(q).getJSONArray("sources").getJSONObject(0);
        need(sources.getString("node_id").equals("n25")&&sources.getString("node_ref_signature").equals(f.byId.get("n25").signature),"title original NodeRef retained");
        JSONObject proof=new JSONObject(q).getJSONObject("same_product_membership");
        need(proof.getString("native_same_parent_path").equals("0/1/8")&&proof.getBoolean("all_price_nodes_within_card")
                &&!proof.getBoolean("comparison_strikethrough_semantics_observed"),"same card proof and explicit secondary limitation");
        JSONArray facts=new JSONObject(q).getJSONArray("sources");
        String[] sourceIds={"n25","n33","n34","n35"};
        need(facts.length()==sourceIds.length,"four separate raw source nodes");
        for(int i=0;i<sourceIds.length;i++){
            JSONObject fact=facts.getJSONObject(i);NativeAppEvidence.Node expected=f.byId.get(sourceIds[i]);
            need(fact.getString("node_id").equals(expected.id)&&fact.getString("native_tree_path").equals(expected.path)
                    &&fact.getString("node_ref_signature").equals(expected.signature)&&fact.getString("raw").equals(expected.text),
                    "unmodified actual source fact "+sourceIds[i]);
        }
        JSONObject action=new JSONObject(e).getJSONObject("current_action_source_facts").getJSONObject("n9");
        need(action.getString("node_ref_signature").equals(f.byId.get("n9").signature)
                &&action.getString("native_tree_path").equals("0/1/8"),"fresh source fact for original card, no redispatch");
        need(NativeXiaomiProductPage.inspectPreferredNavigation(NativeAppGoal.parse(OWNER,NativeAppGoal.XIAOMI_PACKAGE),f).quote.fingerprint.equals(p.quote.fingerprint),"navigation preference cannot change result meaning");
    }
    private static void negative(Fixture f,String name,Mutation mutation){
        run(name,"labelled_counterfactual_parser_DTO",()->{
            NativeXiaomiProductPage.Page p=inspect(f.mutate(mutation));
            need(p.quote==null,"malformed or ambiguous card must not become a quote");
            need(!"search_results_quote".equals(p.phase)&&!"product_detail_quote".equals(p.phase),"no accepted quote phase");
            need(Boolean.FALSE.equals(p.evidence().get("dispatch_authority"))&&Boolean.FALSE.equals(p.evidence().get("order_submitted")),"no action/order authority");
        });
    }
    private static void bindingNegative(Fixture f,String name,String key,Object value){
        run(name,"labelled_counterfactual_frame_binding",()->{
            JSONObject m=new JSONObject(f.wire.toString());m.put(key,value);
            boolean refused=false;try{NativeXiaomiProductPage.Page p=inspect(f.build(f.nodes,m));refused=p.quote==null;}
            catch(IllegalArgumentException rejected){refused=true;}
            need(refused,"changed capture/frame binding must refuse");
        });
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=3)throw new IllegalArgumentException("fixtures output baseline|candidate required");
        Path dir=Paths.get(args[0]),out=Paths.get(args[1]);candidate="candidate".equals(args[2]);
        if(!candidate&&!"baseline".equals(args[2]))throw new IllegalArgumentException("exact variant");
        final List<Fixture> fixtures=new ArrayList<Fixture>();
        for(int i=0;i<IDS.length;i++)fixtures.add(new Fixture(dir,IDS[i],i+3));
        for(int i=0;i<fixtures.size();i++){
            final Fixture f=fixtures.get(i);
            run("real_complete_AX_"+IDS[i],"exact_three_archived_actual_captures",()->quote(f.actual,"159","199"));
        }
        final Fixture f=fixtures.get(0);
        run("three_capture_source_identity","exact_three_archived_actual_captures",()->{
            Set<String> observations=new LinkedHashSet<String>(),fingerprints=new LinkedHashSet<String>(),semantics=new LinkedHashSet<String>();
            for(Fixture v:fixtures){observations.add(v.actual.observationId);NativeXiaomiProductPage.Page p=inspect(v.actual);
                if(candidate){fingerprints.add(p.quote.fingerprint);semantics.add(p.quote.semanticFingerprint);}}
            need(observations.size()==3,"three actual publication identities, not one copied page");
            if(candidate){need(fingerprints.size()==3,"each quote bound to its original distinct frame");need(semantics.size()==1,"same visible model/prices across three independently published captures");}
        });
        run("amount_values_are_not_hardcoded","labelled_counterfactual_parser_DTO",()->{
            quote(f.mutate(ns->{put(ns,"n34","text","179.50");put(ns,"n35","text","¥249.90");}),"179.5","249.9");
        });
        run("non_price_description_changes_keep_same_closed_layout","labelled_counterfactual_parser_DTO",()->{
            quote(f.mutate(ns->put(ns,"n26","text","满血WiFi6，3000兆无线速率")),"159","199");
        });
        negative(f,"different_model",ns->put(ns,"n25","text","Xiaomi路由器AX6000"));
        negative(f,"duplicate_exact_model",ns->put(ns,"n26","text",TITLE));
        negative(f,"second_router_in_same_card",ns->put(ns,"n26","text","Xiaomi路由器AX6000"));
        negative(f,"amount_leading_zero",ns->put(ns,"n34","text","0159"));
        negative(f,"amount_separator",ns->put(ns,"n34","text","1,59"));
        negative(f,"amount_has_currency_prefix",ns->put(ns,"n34","text","¥159"));
        negative(f,"negative_amount",ns->put(ns,"n34","text","-159"));
        negative(f,"excess_precision",ns->put(ns,"n34","text","159.000"));
        negative(f,"second_numeric_amount",ns->put(ns,"n26","text","999"));
        negative(f,"second_currency",ns->put(ns,"n26","text","¥"));
        negative(f,"second_secondary_amount",ns->put(ns,"n26","text","¥999"));
        negative(f,"missing_secondary_slot",ns->remove(ns,"n35"));
        negative(f,"missing_title",ns->remove(ns,"n25"));
        negative(f,"missing_non_price_slot",ns->remove(ns,"n36"));
        negative(f,"extra_direct_child",ns->{JSONObject n=new JSONObject(node(ns,"n36").toString());n.put("id","n99");n.put("path","0/1/8/12");ns.add(n);});
        negative(f,"extra_nested_child",ns->{JSONObject n=new JSONObject(node(ns,"n36").toString());n.put("id","n99");n.put("path","0/1/8/11/0");ns.add(n);});
        negative(f,"title_in_unobserved_slot",ns->{put(ns,"n25","path","0/1/8/1");put(ns,"n26","path","0/1/8/0");});
        negative(f,"adjacent_prices_in_unobserved_slots",ns->{put(ns,"n32","path","0/1/8/10");put(ns,"n33","path","0/1/8/7");put(ns,"n34","path","0/1/8/8");put(ns,"n35","path","0/1/8/9");});
        negative(f,"currency_and_amount_gap",ns->bounds(ns,"n34",650,1362,723,1423));
        negative(f,"price_rows_disjoint",ns->bounds(ns,"n34",499,1450,572,1500));
        negative(f,"price_above_model",ns->{bounds(ns,"n33",465,1040,499,1080);bounds(ns,"n34",499,1030,572,1100);bounds(ns,"n35",581,1040,645,1080);});
        negative(f,"title_outside_card",ns->bounds(ns,"n25",0,1095,931,1149));
        negative(f,"price_outside_card",ns->bounds(ns,"n34",499,1362,1300,1423));
        negative(f,"card_outside_scroll",ns->bounds(ns,"n9",0,100,1190,1518));
        negative(f,"card_wrong_class",ns->put(ns,"n9","class","android.widget.FrameLayout"));
        negative(f,"card_wrong_parent",ns->put(ns,"n9","parent_class","android.view.ViewGroup"));
        negative(f,"card_not_clickable",ns->put(ns,"n9","clickable",false));
        negative(f,"card_disabled",ns->put(ns,"n9","enabled",false));
        negative(f,"card_password",ns->put(ns,"n9","password",true));
        negative(f,"card_has_raw_text",ns->put(ns,"n9","text","159"));
        negative(f,"card_editable",ns->put(ns,"n9","editable",true));
        negative(f,"card_scrollable",ns->put(ns,"n9","scrollable",true));
        negative(f,"card_selected",ns->put(ns,"n9","selected",true));
        negative(f,"card_scroll_actions",ns->put(ns,"n9","scroll_directions",new JSONArray(Arrays.asList("forward"))));
        negative(f,"interactive_title_overlay",ns->put(ns,"n25","clickable",true));
        negative(f,"title_wrong_class",ns->put(ns,"n25","class","android.widget.EditText"));
        negative(f,"title_wrong_parent",ns->put(ns,"n25","parent_class","android.widget.FrameLayout"));
        negative(f,"title_unobserved_view_id",ns->put(ns,"n25","view_id","foreign:id/title"));
        negative(f,"title_unobserved_description",ns->put(ns,"n25","description","other product"));
        negative(f,"title_selection_unknown",ns->{put(ns,"n25","selected",null);put(ns,"n25","checkable",null);put(ns,"n25","checked",null);});
        negative(f,"interactive_currency_overlay",ns->put(ns,"n33","clickable",true));
        negative(f,"scroll_wrong_class",ns->put(ns,"n0","class","android.view.ViewGroup"));
        negative(f,"scroll_wrong_parent",ns->put(ns,"n0","parent_class","android.widget.ScrollView"));
        negative(f,"missing_scroll_ancestor",ns->remove(ns,"n0"));
        negative(f,"scroll_not_scrollable",ns->put(ns,"n0","scrollable",false));
        negative(f,"unobserved_horizontal_scroll",ns->put(ns,"n0","scroll_directions",new JSONArray(Arrays.asList("left","right"))));
        negative(f,"scroll_clickable",ns->put(ns,"n0","clickable",true));
        negative(f,"card_at_unobserved_path",ns->{for(JSONObject n:ns){String p=n.getString("path");if(p.equals("0/1/8")||p.startsWith("0/1/8/"))n.put("path",p.replace("0/1/8","0/1/18"));}});
        negative(f,"three_level_title_is_not_generic_depth_range",ns->{for(JSONObject n:ns){String p=n.getString("path");if(p.startsWith("0/1/8/"))n.put("path",p.replace("0/1/8/","0/1/8/90/91/"));}});
        negative(f,"foreign_package_overlay",ns->put(ns,"n10","package","foreign.package"));
        negative(f,"cross_card_amount",ns->put(ns,"n34","path","0/1/18/9"));
        negative(f,"currency_without_actual_signature",ns->put(ns,"n33","ref_signature_sha256",null));
        negative(f,"derived_label_cannot_replace_title",ns->{put(ns,"n25","text","");put(ns,"n25","label",TITLE);});
        negative(f,"derived_label_cannot_replace_price",ns->{put(ns,"n34","text","");put(ns,"n34","label","159");});
        bindingNegative(f,"wrong_owner_sha","owner_sha256",NativeAppEvidence.hash("different owner"));
        bindingNegative(f,"wrong_observation_id","observation_id","11111111111111111111111111111111");
        bindingNegative(f,"wrong_window_id","window_id",2569);
        bindingNegative(f,"metadata_unobserved","window_metadata_observed",false);
        bindingNegative(f,"non_application_window","window_type",2);
        bindingNegative(f,"truncated_collection","nodes_truncated",true);
        bindingNegative(f,"incomplete_collection","actual_collection_complete",false);
        bindingNegative(f,"expired_original_profile_capture","captured_elapsed_ms",f.window.expiresElapsedMs);
        boolean pass=true;List<String> names=new ArrayList<String>();
        for(Map<String,Object> row:RESULTS){pass&=Boolean.TRUE.equals(row.get("passed"));names.add((String)row.get("name"));}
        need(new LinkedHashSet<String>(names).size()==names.size(),"independent case names");
        Map<String,Object> result=map();result.put("schema","hepta.xiaomi-direct-card-host-cases.v1");result.put("variant",args[2]);
        result.put("all_pass",pass);result.put("cases",RESULTS.size());result.put("assertions",assertions);
        result.put("case_names",names);result.put("results",RESULTS);
        result.put("raw_capture_adapter_assertions_included",true);
        result.put("actual_recorded_captures",3);result.put("phone_operations",0);
        result.put("android_execution",false);result.put("model_executed",false);result.put("business_completion_verified",false);
        result.put("current_phone_frame_or_action_authority",false);
        result.put("counterfactual_scope","parser DTO mutation only; original sealed AX files stay byte-exact and immutable");
        Files.write(out,(new JSONObject(result).toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println("DIRECT_CARD variant="+args[2]+" cases="+RESULTS.size()+" assertions="+assertions+" pass="+pass);
        if(!pass)System.exit(1);
    }
}
