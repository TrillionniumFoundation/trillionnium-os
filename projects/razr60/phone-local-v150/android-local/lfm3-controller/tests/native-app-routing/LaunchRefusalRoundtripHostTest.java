package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/** Exact production explanation with the real JSON dependency and a preserved R6
 * refusal. No Android service, shell command, broker, model or phone operation. */
public final class LaunchRefusalRoundtripHostTest {
    private static final List<String> names=new ArrayList<String>();
    private static int assertions;
    private static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void passed(String name){check(!names.contains(name),"unique case");names.add(name);}
    private static Map<String,Object> explain(JSONObject value,String task,String owner)throws Exception{
        return LocalTaskController.OutcomeExplanation.create(task,owner,"failed",true,false,null,
                Collections.<String,Object>emptyMap(),value);
    }
    private static JSONObject copy(JSONObject value){return new JSONObject(value.toString());}
    public static void main(String[] args)throws Exception{
        byte[] original=Files.readAllBytes(Paths.get(args[0]));
        JSONObject fixture=new JSONObject(new String(original,StandardCharsets.UTF_8));
        String task=fixture.getString("task_id"),owner=fixture.getString("owner_sha256");
        long expiry=fixture.getLong("expires_elapsed_ms");
        check(fixture.get("expires_elapsed_ms") instanceof Integer
                &&fixture.getJSONObject("last_broker_response").get("expires_elapsed_ms") instanceof Integer,
                "real JSON parser narrows this actual elapsed time to Integer");
        // BackgroundSession.baseJournal puts a primitive long, then evidence()
        // parses lastResponse.toString() independently. Reproduce that boundary.
        JSONObject live=copy(fixture).put("expires_elapsed_ms",Long.valueOf(expiry));
        check(live.get("expires_elapsed_ms") instanceof Long
                &&live.getJSONObject("last_broker_response").get("expires_elapsed_ms") instanceof Integer,
                "actual live Long/parsed Integer boundary is retained");
        String unchanged=live.toString();
        Map<String,Object> reason=explain(live,task,owner);
        check("APP_ALREADY_ON_MAIN_DISPLAY".equals(reason.get("code")),
                "equal integral lease expiry must explain the actual R6 pre-launch refusal");
        check(Boolean.FALSE.equals(reason.get("changes_task_status"))
                &&Boolean.FALSE.equals(reason.get("grants_tool_authority"))
                &&Boolean.FALSE.equals(reason.get("business_verified")),"guidance grants no execution or success");
        check(unchanged.equals(live.toString()),"presentation never mutates the actual refusal");
        passed("actual_r6_live_long_parsed_integer_refusal_is_explained");
        check("APP_ALREADY_ON_MAIN_DISPLAY".equals(explain(fixture,task,owner).get("code")),
                "fully parsed equal Integer fields remain valid");
        passed("actual_r6_fully_parsed_integer_refusal_is_explained");
        JSONObject bothLong=copy(fixture).put("expires_elapsed_ms",Long.valueOf(expiry));
        bothLong.getJSONObject("last_broker_response").put("expires_elapsed_ms",Long.valueOf(expiry));
        check("APP_ALREADY_ON_MAIN_DISPLAY".equals(explain(bothLong,task,owner).get("code")),
                "equal Long fields remain valid");
        passed("equal_long_expiry_remains_valid");
        Object[] invalid={Long.valueOf(expiry+1),Double.valueOf(expiry),String.valueOf(expiry),JSONObject.NULL};
        String[] invalidNames={"different_integer","floating_point","numeric_string","null"};
        for(int side=0;side<2;side++)for(int i=0;i<invalid.length;i++){
            JSONObject bad=copy(fixture);
            (side==0?bad:bad.getJSONObject("last_broker_response")).put("expires_elapsed_ms",invalid[i]);
            check(explain(bad,task,owner).isEmpty(),"invalid expiry binding stays hidden");
            passed((side==0?"outer_":"response_")+invalidNames[i]+"_expiry_is_rejected");
        }
        check(explain(live,"11111111111111111111111111111111",owner).isEmpty(),"another task cannot borrow the refusal");
        passed("actual_r6_refusal_cannot_move_to_another_task");
        JSONObject pending=copy(fixture).put("broker_process_exit_observed",false);
        check(explain(pending,task,owner).isEmpty(),"unknown broker exit cannot display resolved conflict guidance");
        passed("actual_r6_unknown_broker_exit_stays_hidden");
        JSONObject dispatched=copy(fixture).put("bootstrap_dispatched",true);
        check(explain(dispatched,task,owner).isEmpty(),"an already dispatched bootstrap is not a pre-launch refusal");
        passed("actual_r6_dispatched_bootstrap_stays_hidden");
        JSONObject report=new JSONObject().put("schema","hepta.launch-refusal-roundtrip-host.v1")
                .put("all_pass",true).put("cases",names.size()).put("assertions",assertions)
                .put("case_names",new JSONArray(names)).put("real_json_dependency",true)
                .put("phone_operations",0).put("android_runtime",false).put("model_inference",false)
                .put("business_verified",false);
        Files.write(Paths.get(args[1]),report.toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println(report.toString());
    }
}
