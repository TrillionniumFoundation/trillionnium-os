package org.trillionnium.hepta.local;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileIdentity;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;

/** Whole production parser/capture class. Public shapes have explicit synthetic
 * identities; the optional private replay reads original receipt and after bytes.
 * No Android, Phone, IPC, dispatch, model or business completion is executed. */
public final class DetailMirrorHostTest {
    private static final String TITLE="Xiaomi路由器AX3000T",VIEW="android.view.ViewGroup",TEXT="android.widget.TextView";
    private static final String PRICE="0/0/2",MIRROR=PRICE+"/0",RICH=MIRROR+"/0",MODEL="0/0/6";
    private static final String OWNER="在小米商城查询AX3000T价格";
    private static final NativeAppGoal GOAL=NativeAppGoal.parse(OWNER,NativeAppGoal.XIAOMI_PACKAGE);
    private static final List<Map<String,Object>> cases=new ArrayList<Map<String,Object>>();
    private static JSONObject publicFixture;
    private static int assertions;
    private interface Work {void run()throws Exception;}
    private interface Change {void run(Fixture f)throws Exception;}
    private static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    private static void one(String name,Work work)throws Exception{
        work.run();Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);row.put("passed",true);cases.add(row);
        System.out.println("PASS "+name);
    }
    private static void denied(Work work)throws Exception{
        boolean rejected=false;try{work.run();}catch(IllegalArgumentException expected){rejected=true;}
        check(rejected,"production constructor/getter must reject");
    }
    private static String hash(String text){return NativeAppEvidence.hash(text);}
    private static String str(Map<String,Object> m,String k){return (String)m.get(k);}
    private static int num(Map<String,Object> m,String k){return ((Number)m.get(k)).intValue();}
    private static long lng(Map<String,Object> m,String k){return ((Number)m.get(k)).longValue();}
    @SuppressWarnings("unchecked") private static Map<String,Object> object(Object value){return (Map<String,Object>)value;}
    @SuppressWarnings("unchecked") private static List<Map<String,Object>> rows(Object value){return (List<Map<String,Object>>)value;}
    private static Map<String,Object> map(Object... pairs){
        Map<String,Object> out=new LinkedHashMap<String,Object>();for(int i=0;i<pairs.length;i+=2)out.put((String)pairs[i],pairs[i+1]);return out;
    }
    private static Map<String,Object> copy(Map<String,Object> value){return object(copyValue(value));}
    private static Object copyValue(Object value){
        if(value instanceof Map){
            Map<String,Object> out=new LinkedHashMap<String,Object>();
            for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet())out.put((String)e.getKey(),copyValue(e.getValue()));
            return out;
        }
        if(value instanceof List){List<Object> out=new ArrayList<Object>();for(Object v:(List<?>)value)out.add(copyValue(v));return out;}
        return value;
    }
    private static JSONObject json(Path path)throws Exception{return new JSONObject(new String(Files.readAllBytes(path),StandardCharsets.UTF_8));}
    private static Map<String,Object> node(List<Map<String,Object>> rows,String path){
        for(Map<String,Object> n:rows)if(path.equals(n.get("path")))return n;throw new AssertionError("missing test node "+path);
    }
    private static Set<String> directions(String fingerprint){
        Set<String> result=new TreeSet<String>();String prefix=ObservedScrollActions.SCHEMA+"|observed";
        if(!fingerprint.equals(prefix)&&!fingerprint.startsWith(prefix+"|"))throw new IllegalArgumentException("unknown test scroll input");
        if(fingerprint.length()>prefix.length())result.addAll(Arrays.asList(fingerprint.substring(prefix.length()+1).split("\\|")));
        return result;
    }
    private static String fullReference(String tree,Map<String,Object> row){
        return hash(ObservedImeEnter.ABSENT.bindFreshness(ObservedScrollActions.observed(directions(str(row,"scroll_actions"))).bindFreshness(tree),false,null));
    }
    private static NativeAppEvidence.Node retainedNode(Map<String,Object> row,String id,String tree){
        List<?> b=(List<?>)row.get("bounds");
        return new NativeAppEvidence.Node(id,str(row,"package"),str(row,"class"),str(row,"view_id"),str(row,"text"),str(row,"description"),
            str(row,"path"),str(row,"parent_class"),tree,ObservedTargetLabels.project(str(row,"label")),
            ((Number)b.get(0)).intValue(),((Number)b.get(1)).intValue(),((Number)b.get(2)).intValue(),((Number)b.get(3)).intValue(),
            Boolean.TRUE.equals(row.get("enabled")),Boolean.TRUE.equals(row.get("password")),Boolean.TRUE.equals(row.get("clickable")),
            Boolean.TRUE.equals(row.get("editable")),Boolean.TRUE.equals(row.get("scrollable")),(Boolean)row.get("selected"),
            (Boolean)row.get("checkable"),(Boolean)row.get("checked"),directions(str(row,"scroll_actions")));
    }
    private static final class Fixture {
        final List<Map<String,Object>> raw;
        final Map<String,String> trees=new LinkedHashMap<String,String>(),ids=new LinkedHashMap<String,String>();
        String ime="hidden";
        Fixture(){
            raw=rows(publicFixture.toMap().get("nodes"));
            for(Object value:publicFixture.getJSONArray("retained").toList()){
                Map<String,Object> n=object(value);trees.put(str(n,"path"),str(n,"app_tree_signature"));ids.put(str(n,"path"),str(n,"id"));
            }
        }
        Map<String,Object> row(String path){return node(raw,path);}
        void text(String path,String text){row(path).put("text",text);row(path).put("label",ObservedTargetLabels.project(text));}
        Map<String,Object> receipt(){
            String h=hash("explicit synthetic identity");
            Map<String,Object> identity=map("task_id","11111111111111111111111111111111","owner_sha256",GOAL.ownerSha256,
                "execution_target_sha256",h,"task_authorization_sha256",h,"actual_selection_sha256",h,"native_goal_sha256",GOAL.contractSha256,
                "package",NativeAppGoal.XIAOMI_PACKAGE,"background_generation","12345678-1234-1234-1234-123456789abc",
                "app_tree_sha256",hash("synthetic tree"),"observation_state_sha256",hash("synthetic state"),
                "display_id",31,"window_id",7,"rotation",0,"width",1224,"height",2992,"left",0,"top",0,"right",1224,"bottom",2992);
            Map<String,Object> binding=new LinkedHashMap<String,Object>(identity);
            binding.put("observation_id","22222222222222222222222222222222");binding.put("captured_elapsed_ms",120L);
            binding.put("profile_window",null);binding.put("profile_action_identity",null);binding.put("original_census_captured_elapsed_ms",100L);
            Map<String,Object> watermark=map("events",0L,"content",0L,"boundary",0L,"unknown",0L);
            Map<String,Object> a=census(identity,100,110,100),b=census(identity,121,130,121);
            return map("schema","hepta.native-ax-capture.v1","kind",ObservationCaptureEvidence.NATIVE_AX,"binding",binding,
                "first",a,"second",b,"request_started_elapsed_ms",90L,"request_deadline_elapsed_ms",200L,"sealed_elapsed_ms",140L,
                "complete_census_endpoint_frozen",true,"complete_census_endpoint_elapsed_ms",135L,"capture_watermark",watermark,
                "second_start_watermark",copy(watermark),"second_completed_watermark",copy(watermark),"visual_model",false,
                "screenshot_present",false,"publication_refreshes_capture_age",false,"grants_action_authority",false,"business_completion_verified",false);
        }
        private Map<String,Object> census(Map<String,Object> identity,long began,long ended,long captured){
            int retained=0;for(Map<String,Object> n:raw)if(n.get("ref_signature_sha256")!=null)retained++;
            return map("complete",true,"truncated",false,"visited",raw.size(),"retained",retained,"pending",0,
                "child_slots_omitted",0,"node_budget_omissions",0,"text_budget_omissions",0,"identity",identity,
                "window",map("synthetic_window",true),"reported_windows",map("synthetic_complete_window_set",true),
                "profile_window",null,"profile_owner",null,"census_captured_elapsed_ms",captured,
                "read_started_elapsed_ms",began,"read_completed_elapsed_ms",ended,"ime_visibility",ime,"nodes",copyValue(raw));
        }
        List<NativeAppEvidence.Node> projected(){
            List<NativeAppEvidence.Node> out=new ArrayList<NativeAppEvidence.Node>();
            for(Map<String,Object> row:raw)if(row.get("ref_signature_sha256")!=null){
                String path=str(row,"path");out.add(retainedNode(row,ids.containsKey(path)?ids.get(path):"n998",trees.get(path)));
            }return out;
        }
        NativeAppEvidence.Frame frame(){Map<String,Object> r=receipt();return frame(r,projected());}
        NativeAppEvidence.Frame frame(Map<String,Object> r,List<NativeAppEvidence.Node> projection){
            byte[] bytes=ObservationCaptureEvidence.nativeAxBytes(r);
            ObservationCaptureEvidence capture=ObservationCaptureEvidence.fromSealedNativeAx(r,bytes,ObservationCaptureEvidence.hash(bytes));
            return build(object(r.get("binding")),capture,projection,null,hash("synthetic source record"),hash("synthetic completion"));
        }
    }
    private static NativeAppEvidence.Frame build(Map<String,Object> b,ObservationCaptureEvidence capture,
            List<NativeAppEvidence.Node> projection,WindowOwnership window,String source,String completion){
        return new NativeAppEvidence.Frame(str(b,"task_id"),str(b,"owner_sha256"),str(b,"execution_target_sha256"),
            str(b,"task_authorization_sha256"),str(b,"actual_selection_sha256"),str(b,"observation_id"),str(b,"package"),
            str(b,"background_generation"),str(b,"app_tree_sha256"),str(b,"observation_state_sha256"),null,source,completion,
            num(b,"display_id"),num(b,"window_id"),num(b,"rotation"),num(b,"width"),num(b,"height"),
            num(b,"left"),num(b,"top"),num(b,"right"),num(b,"bottom"),lng(b,"captured_elapsed_ms"),
            false,true,projection,1,true,window,capture);
    }
    private static NativeAppEvidence.Node afterNode(JSONObject n){
        JSONObject pos=n.getJSONObject("native_tree_position"),selection=n.getJSONObject("native_selection_state");
        check(selection.getBoolean("observed"),"original native selection tuple");
        String text=n.optString("text",""),desc=n.optString("description","");
        String label=!text.trim().isEmpty()?text:!desc.trim().isEmpty()?desc:
            "derived".equals(n.optString("child_text_status"))?n.optString("child_text",""):"";
        JSONArray b=n.getJSONArray("bounds");Set<String> dirs=new TreeSet<String>();
        check(n.getBoolean("scroll_actions_observed"),"original scroll directions observed");
        for(Object v:n.getJSONArray("scroll_directions").toList())dirs.add((String)v);
        return new NativeAppEvidence.Node(n.getString("id"),n.getString("package"),n.getString("class_name"),n.optString("view_id",""),text,desc,
            pos.getString("path"),pos.getString("parent_class"),n.getString("node_app_tree_sha256"),ObservedTargetLabels.project(label),
            b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3),n.optBoolean("enabled",true),n.optBoolean("password",false),
            n.optBoolean("clickable",false),n.optBoolean("editable",false),n.optBoolean("scrollable",false),
            selection.getBoolean("selected"),selection.getBoolean("checkable"),selection.getBoolean("checked"),dirs);
    }
    private static void actualReplayOne(Path task,Path output,boolean accept,int ordinal)throws Exception{
        JSONObject page=json(task.resolve(String.format(Locale.ROOT,"native-app-page-%04d.json",ordinal))),meta=page.getJSONObject("frame");
        String originalFrame="native-app-frame-"+meta.getString("observation_id")+".json";JSONObject after=json(task.resolve(originalFrame));
        JSONObject owner=json(task.resolve("owner.json"));NativeAppGoal actualGoal=NativeAppGoal.parse(owner.getString("instruction"),NativeAppGoal.XIAOMI_PACKAGE);
        JSONObject targetJson=page.getJSONObject("profile_target"),pi=targetJson.getJSONObject("profile");
        ProfileIdentity profile=new ProfileIdentity(pi.getInt("user_id"),pi.getLong("user_serial"),pi.getInt("parent_user_id"),pi.getString("user_type"));
        Map<String,String> apks=new TreeMap<String,String>();for(String k:targetJson.getJSONObject("apk_hashes").keySet())apks.put(k,targetJson.getJSONObject("apk_hashes").getString(k));
        Set<String> signers=new TreeSet<String>();for(Object v:targetJson.getJSONArray("signer_sha256").toList())signers.add((String)v);
        ProfileTarget target=new ProfileTarget(profile,targetJson.getInt("full_uid"),targetJson.getString("package"),targetJson.getString("component"),
            targetJson.getLong("version_code"),apks,signers);
        check(target.sha256.equals(targetJson.getString("target_identity_sha256")),"original target exact");
        JSONObject w=meta.getJSONObject("actual_profile_window");
        WindowOwnership window=new WindowOwnership(target,w.getString("generation"),w.getInt("display_id"),w.getInt("window_id"),
            w.getInt("task_id"),w.getInt("parent_task_id"),w.getString("task_token_id"),w.getString("proof_id"),w.getInt("user_id"),
            w.getLong("user_serial"),w.getInt("full_uid"),w.getLong("observed_elapsed_ms"),w.getLong("expires_elapsed_ms"));
        check(window.sha256.equals(w.getString("proof_sha256")),"original profile proof exact; no renewal");
        Path receiptPath=task.resolve(meta.getJSONObject("capture").getString("receipt_file"));byte[] bytes=Files.readAllBytes(receiptPath);
        Map<String,Object> receipt=json(receiptPath).toMap();String receiptSha=ObservationCaptureEvidence.hash(bytes);
        check(receiptSha.equals(meta.getJSONObject("capture").getString("receipt_sha256")),"original sealed file hash");
        ObservationCaptureEvidence capture=ObservationCaptureEvidence.fromSealedNativeAx(receipt,bytes,receiptSha);
        String afterSha=ObservationCaptureEvidence.hash(Files.readAllBytes(task.resolve(originalFrame)));
        check(afterSha.equals(meta.getString("phone_observation_record_sha256")),"original after file binding");
        check(after.getString("observation_id").equals(meta.getString("observation_id")),"same original after ID");
        List<NativeAppEvidence.Node> projection=new ArrayList<NativeAppEvidence.Node>();
        for(Object value:after.getJSONArray("nodes").toList())projection.add(afterNode(new JSONObject(object(value))));
        NativeAppEvidence.Frame frame=build(object(receipt.get("binding")),capture,projection,window,afterSha,meta.getString("completion_frame_sha256"));
        check(frame.nodes.size()==60&&rows(object(receipt.get("second")).get("nodes")).size()==104,"actual complete104/60 vectors");
        check(Arrays.equals(ObservationCaptureEvidence.canonicalBytes(frame.evidence()),ObservationCaptureEvidence.canonicalBytes(meta.toMap())),"complete original Frame evidence including explicit nulls");
        check(actualGoal.ownerSha256.equals(frame.ownerSha),"exact original immutable owner");
        NativeXiaomiProductPage.Page parsed=NativeXiaomiProductPage.inspect(actualGoal,frame);
        if(accept){
            check(parsed.quote!=null&&"product_detail_quote".equals(parsed.phase)&&"159".equals(parsed.quote.amountDecimal)&&"199".equals(parsed.quote.comparisonAmountDecimal),"actual complete mirror detail quote");
            check("explicit_strikethrough_label".equals(parsed.quote.comparisonKind)&&parsed.clickIds.isEmpty(),"literal strike/no action");
        }else check(parsed.quote==null&&parsed.missing.contains("unique_accessible_price_description_required"),"actual baseline refusal preserved");
        Map<String,Object> result=map("schema","hepta.xiaomi-detail-mirror-private-actual-replay.v1","all_pass",true,
            "task_root",task.toString(),"receipt_sha256",receiptSha,"after_sha256",afterSha,"original_node_count",104,"retained_node_count",60,
            "original_node_ids_and_app_tree_signatures",true,"profile_target_and_window_reconstructed_exactly",true,"source_clock_unchanged",true,
            "parsed",parsed.evidence(),"phone_operations",0,"android_runtime",false,"dispatch_executed",false,"business_completion_verified",false);
        Files.write(output,ObservationCaptureEvidence.canonicalBytes(result));
    }

    private static NativeXiaomiProductPage.Page accepted(Fixture f,String amount,String comparison){
        NativeAppEvidence.Frame frame=f.frame();NativeXiaomiProductPage.Page p=NativeXiaomiProductPage.inspect(GOAL,frame);
        check(p.quote!=null,"closed detail must quote: "+p.phase+" "+p.missing);
        check("product_detail_quote".equals(p.phase)&&"detail_display".equals(p.quote.kind),"actual detail role");
        check(amount.equals(p.quote.amountDecimal)&&comparison.equals(p.quote.comparisonAmountDecimal),"complete description values");
        check(TITLE.equals(p.quote.modelRaw)&&"explicit_strikethrough_label".equals(p.quote.comparisonKind),"exact model and literal strike label");
        check(p.clickIds.isEmpty()&&p.editValues.isEmpty()&&p.purposes.isEmpty(),"no new action capability");
        check(Boolean.FALSE.equals(p.quote.evidence().get("task_complete"))&&Boolean.FALSE.equals(p.quote.evidence().get("order_submitted")),"quote only");
        check(Boolean.FALSE.equals(p.quote.evidence().get("promotions_deducted_from_amount")),"no subsidy arithmetic");
        check(Boolean.FALSE.equals(p.quote.evidence().get("selected_sku_verified"))&&Boolean.FALSE.equals(p.quote.evidence().get("delivery_address_verified")),"offscreen roles not asserted");
        Map<String,Object> membership=object(p.quote.evidence().get("same_product_membership"));
        check("sealed_native_ax_scroll_detail_mirrored_price_v1".equals(membership.get("shape")),"new exact shape proof");
        check(((List<?>)membership.get("complete_price_subtree_paths")).size()==5,"complete closed price subtree");
        check(Boolean.FALSE.equals(membership.get("creates_node_reference"))&&Boolean.FALSE.equals(membership.get("grants_action_authority")),"no new freshness or authority");
        return p;
    }
    private static void description(Fixture f,String path,String text){f.row(path).put("description",text);f.row(path).put("label",text);}
    private static void prices(Fixture f,String amount,String comparison){
        String literal=amount+"元划线价"+comparison+"元";
        description(f,PRICE,literal);description(f,MIRROR,literal);f.text(RICH,"￥"+amount+"0￥"+comparison);
    }
    private static void reject(String name,Change change)throws Exception{
        one(name,()->{Fixture f=new Fixture();change.run(f);
            try{NativeXiaomiProductPage.Page p=NativeXiaomiProductPage.inspect(GOAL,f.frame());
                check(p.quote==null,"counterfactual must not quote: "+name);check(!p.missing.isEmpty(),"explicit refusal");
            }catch(IllegalArgumentException completeInputRejected){check(completeInputRejected.getMessage()!=null,"complete actual input validation");}
        });
    }
    private static void rejectReceipt(String name,ChangeReceipt change)throws Exception{
        one(name,()->{Fixture f=new Fixture();Map<String,Object> r=f.receipt();change.run(r);
            denied(()->f.frame(r,f.projected()));});
    }
    private interface ChangeReceipt{void run(Map<String,Object> receipt)throws Exception;}
    private static void actualReplay(Path task,Path output,boolean accept)throws Exception{
        for(int ordinal=4;ordinal<=5;ordinal++)actualReplayOne(task,output.resolveSibling("ACTUAL-REPLAY-"+ordinal+".json"),accept,ordinal);
    }
    public static void main(String[] args)throws Exception{
        publicFixture=json(Paths.get(args[0]));
        Path out=Paths.get(args[1]);boolean baseline=args.length>2&&"--baseline".equals(args[2]);
        if(baseline){
            one("baseline_rejects_recorded_mirrored_layout",()->{
                NativeXiaomiProductPage.Page p=NativeXiaomiProductPage.inspect(GOAL,new Fixture().frame());
                check(p.quote==null&&"product_detail_unverified".equals(p.phase),"legacy rejects duplicate description");
                check(p.missing.contains("unique_accessible_price_description_required"),"exact actual legacy refusal");
            });
            if(args.length==4)one("baseline_private_actual_refusal",()->actualReplay(Paths.get(args[3]),out.resolve("ACTUAL-REPLAY.json"),false));
        }else{
            one("public_complete_104_node_60_projection_detail",()->{
                Fixture f=new Fixture();accepted(f,"159","199");check(f.raw.size()==104&&f.projected().size()==60,"entire recorded shape");
            });
            one("paired_price_values_are_not_hardcoded",()->{Fixture f=new Fixture();prices(f,"179.5","209");accepted(f,"179.5","209");});
            one("parent_child_two_facts_not_string_deduplication",()->{
                NativeXiaomiProductPage.Page p=accepted(new Fixture(),"159","199");
                List<?> sources=(List<?>)p.quote.evidence().get("sources");
                check(sources.size()==3,"model plus two independent parent/child facts");
                check(!object(sources.get(1)).get("native_tree_path").equals(object(sources.get(2)).get("native_tree_path")),"distinct native paths");
                check(object(sources.get(1)).get("raw").equals(object(sources.get(2)).get("raw")),"only full equal descriptions");
            });
            one("merged_1590_rich_text_is_not_the_price",()->{
                NativeXiaomiProductPage.Page p=accepted(new Fixture(),"159","199");
                Map<String,Object> m=object(p.quote.evidence().get("same_product_membership"));
                check(Boolean.FALSE.equals(m.get("merged_child_text_used_as_amount")),"no rich-text parsing");
                check("￥1590￥199".equals(object(((List<?>)m.get("ignored_merged_child_text")).get(0)).get("raw")),"unmodified observed rich text retained");
            });
            one("visible_conditions_preserved_without_deduction",()->{
                NativeXiaomiProductPage.Page p=accepted(new Fixture(),"159","199");Set<String> values=new LinkedHashSet<String>();
                for(Map<String,Object> fact:p.quote.conditions)values.add((String)fact.get("raw"));
                check(values.equals(new LinkedHashSet<String>(Arrays.asList("预计得15米金","实名后可享补贴","政府补贴至高减10%","实名后可立享补贴，至高可减10%"))),"exact visible conditions");
            });
            one("hidden_address_and_sku_never_supply_quote",()->{
                Fixture f=new Fixture();f.row("0/0/18/1").put("text","ANOTHER_REDACTED_ADDRESS");
                NativeXiaomiProductPage.Page p=accepted(f,"159","199");
                check(!new JSONObject(p.quote.evidence()).toString().contains("ANOTHER_REDACTED_ADDRESS"),"hidden address excluded from quote");
            });
            one("capture_remains_deeply_immutable_and_same_clock",()->{
                Fixture f=new Fixture();NativeAppEvidence.Frame before=f.frame();prices(f,"179","299");
                NativeXiaomiProductPage.Page p=NativeXiaomiProductPage.inspect(GOAL,before);
                check(p.quote!=null&&"159".equals(p.quote.amountDecimal),"original immutable captured rows");
                check(before.capturedElapsedMs==120L&&Boolean.FALSE.equals(before.capture.evidence().get("publication_refreshes_capture_age")),"capture time not renewed");
            });
            reject("different_parent_child_primary",f->description(f,MIRROR,"158元划线价199元"));
            reject("different_parent_child_comparison",f->description(f,MIRROR,"159元划线价299元"));
            reject("equal_prices_at_unrelated_sibling",f->{Map<String,Object> n=f.row(MIRROR);n.put("path","0/0/5/0");n.put("parent_class",VIEW);});
            reject("third_equal_price_description",f->description(f,"0/0/10","159元划线价199元"));
            reject("third_competing_price_description",f->description(f,"0/0/10","158元划线价199元"));
            reject("hidden_equal_price_description",f->{f.row("0/0/18/1").put("description","159元划线价199元");});
            reject("hidden_competing_price_description",f->{f.row("0/0/18/1").put("description","99元划线价199元");});
            reject("visible_competing_currency_text",f->f.text("0/0/10/1","￥99"));
            reject("hidden_competing_currency_text",f->f.row("0/0/18/1").put("text","￥99"));
            reject("visible_alternate_yuan_price",f->f.text("0/0/10/1","到手99元"));
            reject("unrecognized_price_description",f->description(f,"0/0/10","到手99元"));
            reject("extra_exact_model",f->f.text("0/0/10/1",TITLE));
            reject("hidden_other_model",f->f.row("0/0/18/1").put("text","Xiaomi路由器AX3000E"));
            reject("hidden_exact_model_outside_selected_role",f->f.row("0/0/18/1").put("text",TITLE));
            reject("selected_sku_other_model",f->f.row("0/0/16/0").put("text","Xiaomi路由器AX3000E "));
            reject("selected_role_visible_is_not_exception",f->{f.row("0/0/16/0").put("visible",true);});
            reject("title_from_another_product",f->f.text(MODEL,"Xiaomi路由器AX3000E"));
            reject("title_moved_to_other_group",f->{Map<String,Object> n=f.row(MODEL);n.put("path","0/0/5/0");n.put("parent_class",VIEW);});
            reject("title_wrong_parent_class",f->f.row(MODEL).put("parent_class",VIEW));
            reject("title_clickable",f->{f.row(MODEL).put("clickable",true);f.row(MODEL).put("action_click",true);});
            reject("title_above_price",f->f.row(MODEL).put("bounds",Arrays.asList(68,1000,1156,1100)));
            reject("title_outside_product_scroll",f->f.row(MODEL).put("bounds",Arrays.asList(68,1929,1256,2011)));
            reject("price_outside_product_scroll",f->f.row(PRICE).put("bounds",Arrays.asList(-1,1380,1190,1555)));
            reject("mirror_outside_parent",f->f.row(MIRROR).put("bounds",Arrays.asList(0,1418,1190,1517)));
            reject("rich_outside_mirror",f->f.row(RICH).put("bounds",Arrays.asList(0,1418,351,1517)));
            reject("rich_text_conflicting_price",f->f.text(RICH,"￥99"));
            reject("rich_text_changed_renderer",f->f.text(RICH,"￥159￥199"));
            reject("mirror_wrong_class",f->f.row(MIRROR).put("class",TEXT));
            reject("mirror_clickable",f->{f.row(MIRROR).put("clickable",true);f.row(MIRROR).put("action_click",true);});
            reject("mirror_scrollable",f->f.row(MIRROR).put("scrollable",true));
            reject("price_hidden",f->f.row(PRICE).put("visible",false));
            reject("mirror_hidden",f->f.row(MIRROR).put("visible",false));
            reject("unknown_click_capability",f->f.row(MIRROR).put("action_click",null));
            reject("editable_price",f->f.row(MIRROR).put("editable",true));
            reject("focused_price",f->f.row(MIRROR).put("focused",true));
            reject("selected_price",f->f.row(MIRROR).put("selected",true));
            reject("missing_price_leaf",f->f.raw.remove(f.row(RICH)));
            reject("missing_subsidy_child",f->f.raw.remove(f.row(PRICE+"/1/0")));
            reject("extra_price_child_slot",f->f.row(PRICE).put("children",3));
            reject("underreported_mirror_children",f->f.row(MIRROR).put("children",0));
            reject("unknown_child_count",f->f.row(PRICE).put("children",null));
            reject("missing_hidden_selected_heading_before_use",f->f.raw.remove(f.row("0/0/15")));
            reject("root_missing_slot",f->f.raw.remove(f.row("0/9/0")));
            reject("scroll_not_actual_scrollview",f->f.row("0/0").put("class",VIEW));
            reject("scroll_not_scrollable",f->f.row("0/0").put("scrollable",false));
            reject("extra_scroll_direct_child_claim",f->f.row("0/0").put("children",23));
            reject("wrong_root_class",f->f.row("0").put("class",VIEW));
            reject("raw_foreign_package_hidden",f->f.row("0/0/18/1").put("package","other.app"));
            reject("raw_foreign_window_hidden",f->f.row("0/0/18/1").put("window_id",8));
            reject("raw_full_reference_mismatch",f->f.row(MIRROR).put("ref_signature_sha256",hash("different actual full ref")));
            reject("raw_missing_price_reference",f->f.row(MIRROR).put("ref_signature_sha256",null));
            reject("government_subsidy_role_changed",f->f.text("0/0/3","其他商品"));
            reject("intervening_other_product_card",f->description(f,"0/0/5","Xiaomi路由器AX3000E"));
            reject("intervening_gap_has_hidden_child",f->f.row("0/0/5").put("children",1));
            reject("benefits_outside_group",f->f.row("0/0/4").put("bounds",Arrays.asList(68,2300,1156,2400)));
            reject("subsidy_changed_to_plain_price",f->f.text(PRICE+"/1/0","优惠价99元"));
            reject("subsidy_overlaps_rich_text",f->f.row(PRICE+"/1").put("bounds",Arrays.asList(100,1380,1156,1555)));
            reject("different_product_feature_group",f->f.text("0/0/7","另一商品参数"));
            reject("footer_duplicate_title",f->f.text("0/11/0",TITLE));
            reject("footer_wrong_child_count",f->f.row("0/10").put("children",2));
            reject("footer_outside_frame",f->f.row("0/10").put("bounds",Arrays.asList(435,2848,1300,2974)));
            for(final String ime:Arrays.asList("visible","unknown"))reject("ime_"+ime,f->f.ime=ime);
            one("retained_projection_text_mismatch",()->{
                Fixture f=new Fixture();List<NativeAppEvidence.Node> old=f.projected();prices(f,"179","299");
                check(NativeXiaomiProductPage.inspect(GOAL,f.frame(f.receipt(),old)).quote==null,"all retained fields match actual census");
            });
            one("retained_projection_membership_missing",()->{
                Fixture f=new Fixture();List<NativeAppEvidence.Node> nodes=f.projected();nodes.remove(0);
                check(NativeXiaomiProductPage.inspect(GOAL,f.frame(f.receipt(),nodes)).quote==null,"complete retained membership");
            });
            rejectReceipt("first_second_literal_difference",r->node(rows(object(r.get("first")).get("nodes")),MIRROR).put("description","158元划线价199元"));
            rejectReceipt("first_census_incomplete",r->object(r.get("first")).put("complete",false));
            rejectReceipt("second_census_truncated",r->object(r.get("second")).put("truncated",true));
            rejectReceipt("omitted_child_slot_counter",r->object(r.get("second")).put("child_slots_omitted",1));
            rejectReceipt("pending_nodes_counter",r->object(r.get("second")).put("pending",1));
            rejectReceipt("missing_text_budget_counter",r->object(r.get("second")).remove("text_budget_omissions"));
            rejectReceipt("different_complete_window_set",r->object(r.get("second")).put("reported_windows",map("changed",true)));
            rejectReceipt("unknown_boundary_event",r->object(r.get("second_completed_watermark")).put("boundary",1L));
            rejectReceipt("ordinary_receipt_cannot_claim_history",r->r.put("historical_form_planning_only",true));
            one("pixel_frame_without_sealed_census_refused",()->{
                Fixture f=new Fixture();Map<String,Object> b=object(f.receipt().get("binding"));
                NativeAppEvidence.Frame frame=new NativeAppEvidence.Frame(str(b,"task_id"),str(b,"owner_sha256"),str(b,"execution_target_sha256"),str(b,"task_authorization_sha256"),
                    str(b,"actual_selection_sha256"),str(b,"observation_id"),str(b,"package"),str(b,"background_generation"),str(b,"app_tree_sha256"),
                    str(b,"observation_state_sha256"),hash("explicit synthetic pixels"),hash("source"),hash("completion"),31,7,0,1224,2992,0,0,1224,2992,120L,false,true,f.projected(),1,true);
                check(NativeXiaomiProductPage.inspect(GOAL,frame).quote==null,"new template requires sealed complete ordinary AX");
            });
            if(args.length==3)one("private_original_receipt_and_after_exact_replay",()->actualReplay(Paths.get(args[2]),out.resolve("ACTUAL-REPLAY.json"),true));
        }
        Map<String,Object> result=map("schema","hepta.xiaomi-detail-mirror-compiled-cases.v1","all_pass",true,"baseline",baseline,
            "cases",cases.size(),"assertions",assertions,"results",cases,"case_names",caseNames(),"phone_operations",0,
            "android_runtime",false,"dispatch_executed",false,"business_completion_verified",false);
        Files.write(out.resolve("CASES.json"),new JSONObject(result).toString(2).getBytes(StandardCharsets.UTF_8));
    }
    private static List<String> caseNames(){List<String> names=new ArrayList<String>();for(Map<String,Object> row:cases)names.add((String)row.get("name"));return names;}
}
