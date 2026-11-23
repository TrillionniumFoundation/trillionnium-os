package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import org.json.JSONArray;
import org.json.JSONObject;

public final class VisualPromptProjectionHostTest {
    private static int checks;
    private static void require(boolean value,String message){
        checks++;if(!value)throw new AssertionError(message);
    }
    private static JSONObject object(String value)throws Exception{return new JSONObject(value);}
    private static boolean same(Object a,Object b){
        if(a instanceof JSONObject)return ((JSONObject)a).similar(b);
        if(a instanceof JSONArray)return ((JSONArray)a).similar(b);
        return a==null?b==null:a.equals(b);
    }
    private static void retained(JSONObject before,JSONObject after,String...keys)throws Exception{
        for(String key:keys)require(same(before.get(key),after.get(key)),"required current fact changed: "+key);
    }
    private static void fixtures()throws Exception{
        JSONObject original=object("{\"task_authorization\":{\"schema\":\"audit\",\"parser\":\"parser\","
                +"\"instruction_sha256\":\"opaque-owner\",\"authorization_sha256\":\"opaque-auth\",\"task_id\":\"opaque-task\","
                +"\"allowed_tools\":[\"click\",\"type\",\"done\"],\"success_done_allowed\":false,"
                +"\"require_find_app_before_open\":true,\"find_query\":\"航班\",\"found_packages\":[],"
                +"\"execution_target\":{\"schema\":\"audit\",\"owner_sha256\":\"opaque-owner\","
                +"\"original_ui_allowed_packages\":[\"other.app\",\"test.app\"],"
                +"\"effective_allowed_packages\":[\"test.app\"],\"route\":\"native_app\","
                +"\"native_goal\":{\"contract_sha256\":\"opaque-contract\",\"owner_start_utf16\":0,"
                +"\"product_model\":\"AX3000T\",\"grants_tool_authority\":false}}},"
                +"\"background_session\":{\"generation\":\"opaque-bg\",\"display_id\":8,"
                +"\"mode\":\"background\",\"allowed_packages\":[\"test.app\"],\"main_display_fallback\":false},"
                +"\"screen\":{\"observation_id\":\"must-copy-current-id\",\"package\":\"test.app\","
                +"\"nodes\":[[\"n9\",\"价格 ¥199.00\",[0,0,50,20],\"\"],[\"n2\",\"查机票\",[0,20,50,40],\"c\"],"
                +"[\"n7\",\"\",[0,40,50,70],\"tf\"]],\"scroll_actions\":{\"n2\":[\"down\"]},"
                +"\"submit_actions\":{},\"editable_fields\":[{\"node_id\":\"n7\",\"text\":\"北京→上海 2026-11-17\"}],"
                +"\"visible_text\":[{\"text\":\"owner_sha256: keep literal 012345\"}],\"tree_truncated\":false},"
                +"\"events\":[{\"step\":1,\"action\":\"type\",\"text\":\"原文 <tag>\",\"dispatched\":true}],"
                +"\"last_transition\":{\"before\":{\"text\":\"旧\"},\"after\":{\"text\":\"新\"}},"
                +"\"last_model_decision\":{\"accepted\":false,\"reason\":\"字段为空\"},"
                +"\"apps\":[[\"test.app\",\"应用\"]],\"open_allowed_packages\":[],"
                +"\"blocked\":{\"click_ids\":[\"n8\"]},\"format_correction\":{\"rejected_output\":\"raw\"},"
                +"\"completion\":{\"owner_sha256\":\"opaque-owner\",\"contract_sha256\":\"opaque-contract\","
                +"\"completion_verified\":false,\"allowed_done_statuses\":[\"failure\"],\"missing\":[\"query_not_executed\"],"
                +"\"native_app\":{\"schema\":\"audit\",\"background_generation\":\"opaque-bg\","
                +"\"observation_id\":\"must-copy-current-id\",\"literal_edit_values\":{\"n7\":\"北京\"},"
                +"\"provider\":{\"schema\":\"audit\",\"price\":\"199.00\",\"flight_number\":\"CA1234\","
                +"\"credentials_or_agreement_actions_available\":false}}},"
                +"\"task_phase\":{\"task_id\":\"opaque-task\",\"expected_body_sha256\":\"opaque-body\","
                +"\"notes_create_expected_text\":\"完整正文\\n第二行\",\"direct_text_replacement_allowed\":false},"
                +"\"fixed_intent_tools\":[{\"source\":\"audit\",\"action\":\"notes.create\",\"package\":\"notes.app\","
                +"\"app_label\":\"笔记\",\"max_utf8_bytes\":4096,\"owner_bound_execution_mode\":\"bounded\"}],"
                +"\"unknown_future\":{\"owner_sha256\":\"must-not-remove-unknown\",\"text\":\"保留\"}}" );
        String before=original.toString();JSONObject view=VisualPromptProjection.project(original);
        require(before.equals(original.toString()),"projection mutated the full private source");
        retained(original,view,"screen","events","last_transition","last_model_decision","apps",
                "open_allowed_packages","blocked","format_correction","unknown_future");
        JSONObject a=original.getJSONObject("task_authorization"),b=view.getJSONObject("task_authorization");
        retained(a,b,"allowed_tools","success_done_allowed","require_find_app_before_open","find_query","found_packages");
        require(!b.has("task_id")&&!b.has("instruction_sha256")&&!b.has("authorization_sha256"),"opaque metadata still in model view");
        retained(a.getJSONObject("execution_target"),b.getJSONObject("execution_target"),"effective_allowed_packages","route");
        require(!b.getJSONObject("execution_target").has("original_ui_allowed_packages"),"inactive broader UI selection reached model");
        retained(original.getJSONObject("completion"),view.getJSONObject("completion"),"completion_verified","allowed_done_statuses","missing");
        retained(original.getJSONObject("completion").getJSONObject("native_app"),view.getJSONObject("completion").getJSONObject("native_app"),
                "observation_id","literal_edit_values");
        retained(original.getJSONObject("completion").getJSONObject("native_app").getJSONObject("provider"),
                view.getJSONObject("completion").getJSONObject("native_app").getJSONObject("provider"),
                "price","flight_number","credentials_or_agreement_actions_available");
        retained(original.getJSONObject("task_phase"),view.getJSONObject("task_phase"),"notes_create_expected_text","direct_text_replacement_allowed");
        retained(original.getJSONArray("fixed_intent_tools").getJSONObject(0),view.getJSONArray("fixed_intent_tools").getJSONObject(0),
                "action","package","app_label","max_utf8_bytes","owner_bound_execution_mode");
        require(view.similar(VisualPromptProjection.project(view)),"projection is not idempotent");
        view.getJSONObject("screen").put("package","mutated-copy");
        require("test.app".equals(original.getJSONObject("screen").getString("package")),"model view shares mutable screen with original");
        require(VisualPromptProjection.project(object("{}" )).length()==0,"missing optional metadata invented data");
        for(String raw:Arrays.asList("{\"task_authorization\":null}","{\"fixed_intent_tools\":[null,\"text\"]}",
                "{\"screen\":{\"task_id\":\"observed-text\",\"source\":\"literal\"}}",
                "{\"task_authorization\":{\"schema parser\":\"unknown-future\",\"\":\"keep-empty-key\"}}",
                "{\"task_authorization/execution_target\":{\"owner_sha256\":\"literal-unknown-field\"}}",
                "{\"fixed_intent_tools\":{\"*\":{\"source\":\"not-an-array-member\"}}}")){
            JSONObject value=object(raw);require(value.similar(VisualPromptProjection.project(value)),"unknown/null-shaped observation changed");
        }
        try{VisualPromptProjection.project(null);throw new AssertionError("null source admitted");}
        catch(IllegalArgumentException expected){checks++;}
    }
    public static void main(String[] args)throws Exception{
        if(args.length==1&&"--system-text".equals(args[0])){
            System.out.print(VisualPromptProjection.SYSTEM);return;
        }
        if(args.length==2&&"--project-json".equals(args[0])){
            byte[] raw=Files.readAllBytes(Paths.get(args[1]));
            System.out.println(VisualPromptProjection.project(new JSONObject(new String(raw,StandardCharsets.UTF_8))).toString());return;
        }
        fixtures();System.out.println(new JSONObject().put("passed",true).put("checks",checks)
                .put("visual_system_utf8_bytes",VisualPromptProjection.SYSTEM.getBytes(StandardCharsets.UTF_8).length)
                .put("phone_contacted",false).put("model_inference_performed",false).toString());
    }
}
