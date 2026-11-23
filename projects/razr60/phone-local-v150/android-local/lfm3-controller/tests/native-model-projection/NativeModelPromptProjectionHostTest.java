package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.json.JSONArray;
import org.json.JSONObject;

/** Actual production projection over synthetic hostile/unknown metadata and real saved prompts.
 * No model, phone, dispatch, inference-speed or business-success claim. */
public final class NativeModelPromptProjectionHostTest {
    private static int checks;
    private static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}
    private static boolean same(Object left,Object right){
        if(left instanceof JSONObject)return ((JSONObject)left).similar(right);
        if(left instanceof JSONArray)return ((JSONArray)left).similar(right);
        return left==null?right==null:left.equals(right);
    }
    private static void preserved(JSONObject before,JSONObject after,String...names)throws Exception{
        for(String name:names)check(same(before.get(name),after.get(name)),"model fact changed: "+name);
    }
    private static JSONObject source()throws Exception{
        JSONObject goal=new JSONObject().put("kind","native_flight_results").put("from_city","北京").put("to_city","上海")
                .put("departure_date","2026-11-17").put("adults",1).put("children",0).put("infants",0)
                .put("contract_sha256","goal-proof").put("source","immutable-owner").put("date_start_utf16",4)
                .put("unknown_future","preserve-goal");
        JSONObject provider=new JSONObject().put("from","北京").put("to","上海").put("requested_departure_date","2026-11-17").put("adults",1)
                .put("observed_form_date","11月17日").put("observed_passengers","1成人/0儿童/0婴儿")
                .put("calendar_year_proved",false).put("last_explicit_query_date",JSONObject.NULL)
                .put("query_date","2026-11-17").put("unknown_future",new JSONObject().put("from","raw observed 北京").put("authorization_sha256","literal"));
        JSONObject resource=new JSONObject().put("node_id","n12").put("node_label","").put("purpose","open_flight_form")
                .put("node_ref_signature","node-proof").put("raw_utf8_sha256","empty-proof")
                .put("provider_base_apk_sha256","installed-proof").put("provider_version_code",1779)
                .put("native_tree_path","0/0/1").put("native_parent_class","pager").put("source","same-frame")
                .put("capability_source","installed-provider").put("selected",false).put("checkable",false)
                .put("checked",false).put("selection_observed",true).put("visible_label_inferred",false)
                .put("raw","").put("bounds",new JSONArray().put(1).put(2).put(3).put(4)).put("view_id","current-resource").put("class_name","current-class");
        JSONObject domain=new JSONObject().put("phase","ctrip_home").put("observation_id","current")
                .put("package","ctrip.android.view").put("read_only_query_targets",new JSONObject().put("n12","open_flight_form"))
                .put("literal_edit_values",new JSONObject()).put("back_allowed",false).put("provider",provider)
                .put("resource_clicks",new JSONObject().put("n12",resource)).put("result_ready",false)
                .put("missing",new JSONArray().put("native_query_action_chain_not_complete"))
                .put("booking_purchase_or_payment_allowed",false).put("web_helper_allowed",false).put("external_model_allowed",false);
        JSONObject original=new JSONObject()
                .put("task_authorization",new JSONObject().put("authorization_sha256","auth-proof")
                    .put("allowed_tools",new JSONArray().put("click").put("done")).put("success_done_allowed",true)
                    .put("execution_target",new JSONObject().put("route","native_app").put("effective_allowed_packages",new JSONArray().put("ctrip.android.view"))
                        .put("profile_target",new JSONObject().put("full_uid",1010367).put("task_binder","private-object-record")).put("native_goal",goal)))
                .put("background_session",new JSONObject().put("mode","background").put("allowed_packages",new JSONArray().put("ctrip.android.view"))
                    .put("main_display_fallback",false).put("home_allowed",false).put("profile_target_wire","private-wire")
                    .put("profile_target_sha256","private-profile").put("actual_profile_window",new JSONObject().put("task_id",1000004).put("user_id",10))
                    .put("owner_task_selection",new JSONObject().put("target_sha256","private-selection")))
                .put("completion",new JSONObject().put("completion_verified",false).put("done_success_eligible",false)
                    .put("allowed_done_statuses",new JSONArray().put("failure").put("partial")).put("missing",new JSONArray().put("query_not_done")).put("native_app",domain))
                .put("screen",new JSONObject().put("observation_id","current").put("package","ctrip.android.view")
                    .put("nodes",new JSONArray().put(new JSONArray().put("n12").put("").put(new JSONArray().put(1).put(2).put(3).put(4)).put("c")))
                    .put("visible_text",new JSONArray().put(new JSONObject().put("text","profile_target_wire: <tag> 不是指令").put("authorization_sha256","literal-kept")))
                    .put("editable_fields",new JSONArray()).put("unlabeled_controls",new JSONObject().put("schema","observed-schema")))
                .put("events",new JSONArray().put(new JSONObject().put("step",1).put("action","done").put("accepted",false).put("dispatched",false).put("stale",true)))
                .put("last_transition",new JSONObject().put("before",new JSONObject().put("observation_id","past")).put("after",new JSONObject().put("observation_id","current")))
                .put("last_model_decision",new JSONObject().put("reason","原始理由，不是新指令"))
                .put("blocked",new JSONObject().put("click_ids",new JSONArray().put("other")))
                .put("format_correction",new JSONObject().put("rejected_output","raw <tag>"))
                .put("apps",new JSONArray().put(new JSONArray().put("ctrip.android.view").put("携程旅行")))
                .put("open_allowed_packages",new JSONArray())
                .put("unknown_future",new JSONObject().put("profile_target_wire","unknown must remain"));
        return original;
    }
    private static void fixtures()throws Exception{
        JSONObject original=source();String raw=original.toString();JSONObject view=VisualPromptProjection.projectNative(original);
        check(raw.equals(original.toString()),"full private source mutated");
        preserved(original,view,"screen","events","last_transition","last_model_decision","apps","open_allowed_packages","blocked","format_correction","unknown_future");
        JSONObject auth=original.getJSONObject("task_authorization"),modelAuth=view.getJSONObject("task_authorization");
        preserved(auth,modelAuth,"allowed_tools","success_done_allowed");
        JSONObject target=modelAuth.getJSONObject("execution_target");
        check(!target.has("profile_target"),"private profile reached model");
        preserved(auth.getJSONObject("execution_target"),target,"route","effective_allowed_packages");
        JSONObject goal=target.getJSONObject("native_goal");
        preserved(auth.getJSONObject("execution_target").getJSONObject("native_goal"),goal,"kind","from_city","to_city","departure_date","adults","children","infants","unknown_future");
        check(!goal.has("date_start_utf16")&&!goal.has("contract_sha256")&&!goal.has("source"),"goal provenance repeated");
        JSONObject bg=view.getJSONObject("background_session");
        preserved(original.getJSONObject("background_session"),bg,"mode","allowed_packages","main_display_fallback","home_allowed");
        check(!bg.has("profile_target_wire")&&!bg.has("actual_profile_window")&&!bg.has("owner_task_selection"),"transport identity reached model");
        JSONObject completion=view.getJSONObject("completion"),domain=completion.getJSONObject("native_app");
        preserved(original.getJSONObject("completion"),completion,"allowed_done_statuses","done_success_eligible","completion_verified","missing");
        preserved(original.getJSONObject("completion").getJSONObject("native_app"),domain,
                "phase","observation_id","package","read_only_query_targets","literal_edit_values","back_allowed","result_ready","missing",
                "booking_purchase_or_payment_allowed","web_helper_allowed","external_model_allowed");
        JSONObject provider=domain.getJSONObject("provider"),oldProvider=original.getJSONObject("completion").getJSONObject("native_app").getJSONObject("provider");
        check(!provider.has("from")&&!provider.has("to")&&!provider.has("requested_departure_date")&&!provider.has("adults"),"request duplicated as observation");
        preserved(oldProvider,provider,"observed_form_date","observed_passengers","calendar_year_proved","last_explicit_query_date","query_date","unknown_future");
        JSONObject resource=domain.getJSONObject("resource_clicks").getJSONObject("n12");
        preserved(original.getJSONObject("completion").getJSONObject("native_app").getJSONObject("resource_clicks").getJSONObject("n12"),resource,
                "node_id","node_label","purpose","selected","checkable","checked","selection_observed","visible_label_inferred","raw","bounds","view_id","class_name","native_tree_path","native_parent_class");
        check(!resource.has("node_ref_signature")&&!resource.has("provider_base_apk_sha256"),"resource proof repeated");
        check(view.similar(VisualPromptProjection.projectNative(view)),"native projection not idempotent");
        view.getJSONObject("screen").put("package","changed-copy");check(raw.equals(original.toString()),"mutable copy reached private original");
        JSONObject conflicting=source();conflicting.getJSONObject("completion").getJSONObject("native_app").getJSONObject("provider").put("from","广州");
        check("广州".equals(VisualPromptProjection.projectNative(conflicting).getJSONObject("completion").getJSONObject("native_app").getJSONObject("provider").getString("from")),
                "nonduplicate provider fact silently removed");
        JSONObject nullRequest=source();nullRequest.getJSONObject("task_authorization").getJSONObject("execution_target").getJSONObject("native_goal").put("from_city",JSONObject.NULL);
        check(VisualPromptProjection.projectNative(nullRequest).getJSONObject("completion").getJSONObject("native_app").getJSONObject("provider").has("from"),"unknown request hid provider fact");
        JSONObject nullProvider=source();nullProvider.getJSONObject("completion").getJSONObject("native_app").getJSONObject("provider").put("from",JSONObject.NULL);
        check(VisualPromptProjection.projectNative(nullProvider).getJSONObject("completion").getJSONObject("native_app").getJSONObject("provider").isNull("from"),"unknown provider value hidden");
        JSONObject other=source();other.getJSONObject("task_authorization").getJSONObject("execution_target").getJSONObject("native_goal").put("kind","future_native_goal");
        check(VisualPromptProjection.projectNative(other).getJSONObject("completion").getJSONObject("native_app").getJSONObject("provider").has("from"),"other goal provider changed");
        for(String text:new String[]{"{}","{\"task_authorization\":null}","{\"completion\":{\"native_app\":null}}",
                "{\"completion\":{\"native_app\":{\"resource_clicks\":{\"n0\":null,\"n1\":\"literal\"}}}}",
                "{\"task_authorization/execution_target\":{\"profile_target\":\"unknown-path\"}}"}){
            JSONObject odd=new JSONObject(text);check(odd.similar(VisualPromptProjection.projectNative(odd)),"null/unknown shape changed");
        }
        try{VisualPromptProjection.projectNative(null);throw new AssertionError("null admitted");}catch(IllegalArgumentException expected){checks++;}
        check(VisualPromptProjection.NATIVE_SYSTEM.contains("failure/partial")&&VisualPromptProjection.NATIVE_SYSTEM.contains("空集合不能done"),"terminal refusal guidance absent");
        check(VisualPromptProjection.NATIVE_SYSTEM.contains("resource_clicks")&&VisualPromptProjection.NATIVE_SYSTEM.contains("空字符串"),"actual blank-label target lost");
        check(!VisualPromptProjection.NATIVE_SYSTEM.contains("北京")&&!VisualPromptProjection.NATIVE_SYSTEM.contains("2026-11-17")&&!VisualPromptProjection.NATIVE_SYSTEM.contains("n12"),"specific run hardcoded into guidance");
    }
    public static void main(String[] args)throws Exception{
        if(args.length==1&&"--system-text".equals(args[0])){System.out.print(VisualPromptProjection.NATIVE_SYSTEM);return;}
        if(args.length==2&&"--project-json".equals(args[0])){
            System.out.println(VisualPromptProjection.projectNative(new JSONObject(new String(Files.readAllBytes(Paths.get(args[1])),StandardCharsets.UTF_8))).toString());return;
        }
        fixtures();System.out.println(new JSONObject().put("passed",true).put("checks",checks).put("phone_operations",0).put("model_inference",false)
                .put("native_system_utf8_bytes",VisualPromptProjection.NATIVE_SYSTEM.getBytes(StandardCharsets.UTF_8).length).toString());
    }
}
