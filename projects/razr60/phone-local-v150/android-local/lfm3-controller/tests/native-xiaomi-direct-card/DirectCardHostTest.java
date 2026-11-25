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
public final class DirectCardHostTest {
    private static final String TITLE="Xiaomi路由器AX3000T",CARD="0/1/8",QUERY="0/0/0/0/0/0";
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
        void extra(boolean hidden,String text){
            Map<String,Object> n=copy(row(CARD+"/9"));String path=CARD+"/12";n.put("path",path);n.put("text",text);
            n.put("bounds",Arrays.asList(700,1370,790,1420));n.put("visible",!hidden);n.put("label",hidden?null:text);
            if(hidden)n.put("ref_signature_sha256",null);
            else{String tree=hash("synthetic extra tree");trees.put(path,tree);ids.put(path,"n999");n.put("ref_signature_sha256",fullReference(tree,n));}
            raw.add(n);row(CARD).put("children",13);
        }
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
                "read_started_elapsed_ms",began,"read_completed_elapsed_ms",ended,"ime_visibility",ime,"nodes",raw);
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
    private static NativeXiaomiProductPage.Page accepted(Fixture f,String amount,String secondary){
        NativeAppEvidence.Frame frame=f.frame();NativeXiaomiProductPage.Page p=NativeXiaomiProductPage.inspect(GOAL,frame);
        check(p.quote!=null,"actual direct-child card must quote from exact sealed membership; got "+p.phase+" "+p.missing);
        check("search_results_quote".equals(p.phase)&&"search_card".equals(p.quote.kind),"search card role");
        check(amount.equals(p.quote.amountDecimal)&&secondary.equals(p.quote.comparisonAmountDecimal),"same card primary/secondary");
        check("secondary_display_amount".equals(p.quote.comparisonKind),"no unsupported strikethrough semantic");
        check(p.clickIds.size()==1&&CARD.equals(frame.byId.get(p.clickIds.iterator().next()).path),"original same-frame card node only");
        check(Boolean.FALSE.equals(p.quote.evidence().get("task_complete"))&&Boolean.FALSE.equals(p.quote.evidence().get("order_submitted")),"no completion or order");
        check(Boolean.FALSE.equals(p.quote.evidence().get("promotions_deducted_from_amount")),"no discount deduction");
        return p;
    }
    private static void reject(String name,Change change)throws Exception{
        one(name,()->{Fixture f=new Fixture();change.run(f);NativeXiaomiProductPage.Page p=NativeXiaomiProductPage.inspect(GOAL,f.frame());
            check(p.quote==null,"counterfactual must not produce quote: "+name);check(!p.missing.isEmpty(),"explicit refusal");});
    }
    private static void historyFixtures(Path file)throws Exception{
        JSONObject fixture=json(file);Field field=NativeXiaomiSearchInputHostTest.class.getDeclaredField("fixture");field.setAccessible(true);field.set(null,fixture);
        field=NativeXiaomiSearchInputHostTest.class.getDeclaredField("ax");field.setAccessible(true);
        field.set(null,NativeXiaomiSearchInputHostTest.source("a57e1dedb06a4e739823379bd472f953-native-ax.json"));
        field=NativeXiaomiSearchInputHostTest.class.getDeclaredField("installed");field.setAccessible(true);
        field.set(null,fixture.getJSONObject("profile_target_from_original_prompt").getString("apk_set_sha256"));
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
    private static void actualReplay(Path task,Path output)throws Exception{
        JSONObject page=json(task.resolve("native-app-page-0003.json")),meta=page.getJSONObject("frame"),after=json(task.resolve("step-03-after.json"));
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
        String afterSha=ObservationCaptureEvidence.hash(Files.readAllBytes(task.resolve("step-03-after.json")));
        check(afterSha.equals(meta.getString("phone_observation_record_sha256")),"original after file binding");
        check(after.getString("observation_id").equals(meta.getString("observation_id")),"same original after ID");
        List<NativeAppEvidence.Node> projection=new ArrayList<NativeAppEvidence.Node>();
        for(Object value:after.getJSONArray("nodes").toList())projection.add(afterNode(new JSONObject(object(value))));
        NativeAppEvidence.Frame frame=build(object(receipt.get("binding")),capture,projection,window,afterSha,meta.getString("completion_frame_sha256"));
        check(frame.nodes.size()==51&&rows(object(receipt.get("second")).get("nodes")).size()==70,"actual seventy/fifty-one vectors");
        check(Arrays.equals(ObservationCaptureEvidence.canonicalBytes(frame.evidence()),ObservationCaptureEvidence.canonicalBytes(meta.toMap())),"complete original Frame evidence including explicit nulls");
        check(actualGoal.ownerSha256.equals(frame.ownerSha),"exact original immutable owner");
        NativeXiaomiProductPage.Page parsed=NativeXiaomiProductPage.inspect(actualGoal,frame);
        check(parsed.quote!=null&&"159".equals(parsed.quote.amountDecimal)&&"199".equals(parsed.quote.comparisonAmountDecimal),"private original direct card must quote");
        check("secondary_display_amount".equals(parsed.quote.comparisonKind),"actual secondary is not strike/discount evidence");
        check(parsed.clickIds.size()==1&&"0/1/8".equals(frame.byId.get(parsed.clickIds.iterator().next()).path),"actual same-frame card ID");
        Map<String,Object> result=map("schema","hepta.xiaomi-direct-card-private-actual-replay.v1","all_pass",true,
            "task_root",task.toString(),"receipt_sha256",receiptSha,"after_sha256",afterSha,"original_node_count",70,"retained_node_count",51,
            "original_node_ids_and_app_tree_signatures",true,"profile_target_and_window_reconstructed_exactly",true,"source_clock_unchanged",true,
            "parsed",parsed.evidence(),"phone_operations",0,"android_runtime",false,"dispatch_executed",false,"business_completion_verified",false);
        Files.write(output,ObservationCaptureEvidence.canonicalBytes(result));
    }
    public static void main(String[] args)throws Exception{
        if(args.length==3&&"--actual-only".equals(args[0])){actualReplay(Paths.get(args[1]),Paths.get(args[2]).resolve("ACTUAL-REPLAY.json"));return;}
        publicFixture=json(Paths.get(args[0]));historyFixtures(Paths.get(args[1]));
        one("public_actual_70_node_51_projection_shape",()->{Fixture f=new Fixture();accepted(f,"159","199");check(f.raw.size()==70&&f.projected().size()==51,"complete public shape");});
        one("price_not_hardcoded",()->{Fixture f=new Fixture();f.text(CARD+"/9","179.5");f.text(CARD+"/10","¥209");accepted(f,"179.5","209");});
        one("other_card_prices_cannot_supply_target_amount",()->{Fixture f=new Fixture();f.text("0/1/10/3","9999");accepted(f,"159","199");});
        one("displayed_review_count_is_not_a_price",()->{Fixture f=new Fixture();f.text(CARD+"/11","37万+条评价    98%满意");accepted(f,"159","199");});
        one("sealed_census_is_deeply_immutable",()->{
            NativeAppEvidence.Frame f=new Fixture().frame();Map<String,Object> c=f.capture.sealedNativeAxCensus();
            boolean mapNo=false,listNo=false,nodeNo=false;
            try{c.put("retained",0);}catch(UnsupportedOperationException expected){mapNo=true;}
            try{rows(c.get("nodes")).clear();}catch(UnsupportedOperationException expected){listNo=true;}
            try{rows(c.get("nodes")).get(0).put("text","changed");}catch(UnsupportedOperationException expected){nodeNo=true;}
            check(mapNo&&listNo&&nodeNo,"deep readonly original census");
            check(f.capturedElapsedMs==120&&Boolean.FALSE.equals(f.capture.evidence().get("publication_refreshes_capture_age")),"original age/no freshness grant");
        });
        one("sealed_input_mutation_cannot_change_capture",()->{Fixture f=new Fixture();NativeAppEvidence.Frame a=f.frame();f.text(CARD+"/9","999");
            check("159".equals(node(rows(a.capture.sealedNativeAxCensus().get("nodes")),CARD+"/9").get("text")),"original deep freeze");});
        for(final boolean form:new boolean[]{false,true})one(form?"form_history_cannot_supply_ordinary_census":"input_history_cannot_supply_ordinary_census",()->{
            ObservationCaptureEvidence h=NativeXiaomiSearchInputHostTest.sealHistory(NativeXiaomiSearchInputHostTest.history(form),form);
            check(h.planningHistory(),"real validated history control");denied(()->h.sealedNativeAxCensus());
        });
        reject("hidden_unretained_extra_number",f->f.extra(true,"89"));
        reject("extra_visible_amount",f->f.extra(false,"89"));
        reject("extra_hidden_coupon",f->f.extra(true,"券后159"));
        reject("wrong_exact_query",f->f.text(QUERY,"AX3000E"));
        reject("query_suffix_is_not_exact_query",f->f.text(QUERY,"AX3000T路由器"));
        reject("two_visible_query_headers",f->f.text("0/1/10/0","AX3000T"));
        reject("multiple_visible_exact_models",f->f.text("0/1/10/0",TITLE));
        reject("hidden_exact_model_is_ambiguous",f->f.row("0/1/12/0").put("text",TITLE));
        reject("unknown_card_child_count",f->f.row(CARD).put("children",null));
        reject("missing_raw_child_slot",f->f.raw.remove(f.row(CARD+"/9")));
        reject("underreported_child_count",f->f.row(CARD).put("children",11));
        reject("overreported_child_count",f->f.row(CARD).put("children",13));
        reject("wrong_direct_parent_class",f->f.row(CARD+"/9").put("parent_class","android.widget.FrameLayout"));
        reject("wrong_card_class",f->f.row(CARD).put("class","android.widget.FrameLayout"));
        reject("nonclickable_card",f->{f.row(CARD).put("clickable",false);f.row(CARD).put("action_click",false);});
        reject("unknown_card_click_action",f->f.row(CARD).put("action_click",null));
        reject("interactive_price_child",f->{f.row(CARD+"/9").put("clickable",true);f.row(CARD+"/9").put("action_click",true);});
        reject("unknown_price_child_visibility",f->f.row(CARD+"/9").put("visible",null));
        reject("hidden_price_child",f->f.row(CARD+"/9").put("visible",false));
        reject("foreign_hidden_node_package",f->f.row("0/1/12/0").put("package","foreign.app"));
        reject("foreign_hidden_node_window",f->f.row("0/1/12/0").put("window_id",8));
        reject("wrong_card_bounds",f->f.row(CARD).put("bounds",Arrays.asList(34,1020,700,1518)));
        reject("amount_outside_card",f->f.row(CARD+"/9").put("bounds",Arrays.asList(499,1362,1272,1423)));
        reject("currency_not_adjacent_to_amount",f->f.row(CARD+"/8").put("bounds",Arrays.asList(100,1375,134,1416)));
        reject("secondary_not_same_row",f->f.row(CARD+"/10").put("bounds",Arrays.asList(581,1430,645,1467)));
        reject("numeric_review_role_ambiguous",f->f.text(CARD+"/11","159"));
        reject("coupon_amount_not_displayed_primary",f->f.text(CARD+"/9","券后159"));
        reject("starting_amount_not_plain_money",f->f.text(CARD+"/9","159起"));
        reject("extra_precision_not_money",f->f.text(CARD+"/9","159.999"));
        reject("secondary_unknown_role",f->f.text(CARD+"/10","原价199"));
        reject("price_description_not_silently_ignored",f->f.row(CARD+"/9").put("description","券后金额"));
        reject("secondary_style_not_inferred_from_label",f->f.row(CARD+"/10").put("description","划线价"));
        reject("currency_from_another_card_not_borrowed",f->f.text(CARD+"/8",""));
        reject("swapped_currency_number_roles",f->{f.text(CARD+"/8","159");f.text(CARD+"/9","￥");});
        for(final String ime:Arrays.asList("visible","unknown"))reject("ime_"+ime,f->f.ime=ime);
        reject("ime_missing",f->f.ime=null);
        reject("focused_node_is_not_ordinary_result",f->f.row(CARD+"/9").put("focused",true));
        reject("input_hash_is_not_ordinary_result",f->f.row(CARD+"/9").put("input_sha256",hash("input")));
        reject("unknown_ime_action",f->f.row(CARD+"/9").put("ime_enter",ObservedImeEnter.UNKNOWN.fingerprintInput()));
        reject("editable_node_is_not_ordinary_result",f->f.row(CARD+"/9").put("editable",true));
        reject("raw_full_signature_mismatch",f->f.row(CARD+"/9").put("ref_signature_sha256",hash("wrong full ref")));
        one("retained_app_tree_signature_mismatch",()->{Fixture f=new Fixture();f.trees.put(CARD+"/9",hash("wrong app tree"));
            check(NativeXiaomiProductPage.inspect(GOAL,f.frame()).quote==null,"no synthetic equal-hash shortcut");});
        one("retained_text_projection_mismatch",()->{Fixture f=new Fixture();List<NativeAppEvidence.Node> old=f.projected();
            f.text(CARD+"/9","178");check(NativeXiaomiProductPage.inspect(GOAL,f.frame(f.receipt(),old)).quote==null,"raw versus retained text");});
        one("retained_ref_removed",()->{Fixture f=new Fixture();List<NativeAppEvidence.Node> old=f.projected();old.remove(0);
            check(NativeXiaomiProductPage.inspect(GOAL,f.frame(f.receipt(),old)).quote==null,"full retained membership");});
        for(final String field:Arrays.asList("observation_id","task_id","owner_sha256","display_id","window_id","captured_elapsed_ms","profile_window")){
            one("original_capture_frame_binding_"+field,()->{
                Fixture f=new Fixture();Map<String,Object> r=f.receipt();byte[] bytes=ObservationCaptureEvidence.nativeAxBytes(r);
                ObservationCaptureEvidence c=ObservationCaptureEvidence.fromSealedNativeAx(r,bytes,ObservationCaptureEvidence.hash(bytes));
                Map<String,Object> b=copy(object(r.get("binding")));
                if(field.endsWith("_id")&&(field.equals("task_id")||field.equals("observation_id")))b.put(field,"33333333333333333333333333333333");
                else if(field.equals("owner_sha256"))b.put(field,hash("wrong owner"));
                else if(field.equals("profile_window")){
                    // The real Frame supplies null here; a non-null sealed binding is not interchangeable.
                    b.put(field,map("untrusted",true));r.put("binding",b);object(r.get("first")).put("profile_window",b.get(field));
                    bytes=ObservationCaptureEvidence.nativeAxBytes(r);c=ObservationCaptureEvidence.fromSealedNativeAx(r,bytes,ObservationCaptureEvidence.hash(bytes));
                }else b.put(field,((Number)b.get(field)).longValue()+1L);
                final Map<String,Object> bad=b;final ObservationCaptureEvidence actual=c;
                String rejection=null;
                try{build(bad,actual,f.projected(),null,hash("source"),hash("completion"));}
                catch(IllegalArgumentException expected){rejection=expected.getMessage();}
                check(rejection!=null&&rejection.contains("AX receipt binding differs: "+field),"specific original binding refusal "+field);
            });
        }
        if(args.length==4)one("private_original_receipt_and_after_exact_replay",()->actualReplay(Paths.get(args[3]),Paths.get(args[2]).resolve("ACTUAL-REPLAY.json")));
        Map<String,Object> result=map("schema","hepta.xiaomi-direct-card-compiled-cases.v1","all_pass",true,"cases",cases.size(),
            "assertions",assertions,"results",cases,"actual_replay_included",args.length==4,"phone_operations",0,"android_runtime",false,
            "dispatch_executed",false,"business_completion_verified",false);
        Files.write(Paths.get(args[2]).resolve("CASES.json"),new JSONObject(result).toString(2).getBytes(StandardCharsets.UTF_8));
    }
}
