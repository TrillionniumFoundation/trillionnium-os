import org.trillionnium.hepta.local.ActionDecision;
import org.trillionnium.hepta.local.LastModelDecisionProjection;
import org.trillionnium.hepta.local.MobiMindContract;
import org.trillionnium.hepta.local.ObservedAppLabels;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Real saved request provenance, with negative ownership/outcome and bounded Unicode cases. */
public final class LastModelDecisionProjectionHostTest {
    private static final String TASK="840809ea48af4da2aa9b80fe4f3eba8a";
    private static final String RUN="60ae7b32a9824fd4b3e2d7acdac43b19";
    private static final String OBS="78e104bf4708496f88d2ef3bbadd8035";
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static void rejects(Runnable call,String message){
        boolean rejected=false;try{call.run();}catch(IllegalArgumentException expected){rejected=true;}
        check(rejected,message);
    }
    private static String hash(byte[] bytes)throws Exception{
        StringBuilder out=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(bytes))out.append(String.format(Locale.ROOT,"%02x",b&255));return out.toString();
    }
    private static String quoted(String value){return "\""+value.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n")+"\"";}
    private static ActionDecision decision(String tool,String reason)throws Exception{
        String raw="{\"reason\":"+quoted(reason)+",\"action\":"+quoted(tool)+",\"observation_id\":"+quoted(OBS);
        if("open".equals(tool))raw+=",\"app_label\":\"Editor\"";
        raw+=",\"package\":\"org.example.editor\"";
        if("click".equals(tool))raw+=",\"node_label\":\"Edit\",\"node_id\":\"n1\"";
        else if("wait".equals(tool))raw+=",\"duration_ms\":100";
        else if("find_app".equals(tool))raw+=",\"query\":\"Editor\",\"offset\":0";
        else if("done".equals(tool))raw+=",\"status\":\"partial\",\"summary\":\"fixture only\"";
        return ActionDecision.parse(raw+"}",ObservedAppLabels.ACTION_SCHEMA);
    }
    private static Map<String,Object> row(int step,String action,boolean accepted,boolean dispatched,boolean stale){
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("step",Integer.valueOf(step));out.put("action",action);
        out.put("model_issued",Boolean.TRUE);out.put("accepted",Boolean.valueOf(accepted));out.put("dispatched",Boolean.valueOf(dispatched));out.put("stale",Boolean.valueOf(stale));return out;
    }
    private static List<Map<String,Object>> history(Object value){
        List<Map<String,Object>> rows=new ArrayList<Map<String,Object>>();
        for(Object raw:(List<?>)value){
            Map<String,Object> copy=new LinkedHashMap<String,Object>();
            for(Map.Entry<?,?> entry:((Map<?,?>)raw).entrySet())copy.put((String)entry.getKey(),entry.getValue());
            copy.put("step",Integer.valueOf(((Number)copy.get("step")).intValue()));rows.add(copy);
        }
        return rows;
    }
    private static String repeat(String value,int count){StringBuilder out=new StringBuilder();for(int i=0;i<count;i++)out.append(value);return out.toString();}
    public static void main(String[] args)throws Exception{
        if(args.length!=1)throw new IllegalArgumentException("saved fixture directory required");Path dir=Paths.get(args[0]);
        byte[] raw=Files.readAllBytes(dir.resolve("step-03-model-output.txt")),promptBytes=Files.readAllBytes(dir.resolve("step-04-prompt.txt"));
        check(hash(raw).equals("302c7c73ee8e738a70fe40d27d1144c48f6a1afc8aa142eaea8e39f30b6b57a5"),"real raw output fixture hash");
        check(hash(promptBytes).equals("23397c1ba00ab85ed9bfdaadadc0eb96985ea3813a8939262f63aa02757015dd"),"real next prompt fixture hash");
        String prompt=new String(promptBytes,StandardCharsets.UTF_8);int ownerAt=prompt.indexOf("\nOWNER\n");
        Map<String,Object> frame=MobiMindContract.jsonObject(prompt.substring("UNTRUSTED_DATA\n".length(),ownerAt).getBytes(StandardCharsets.UTF_8));
        List<Map<String,Object>> actualHistory=history(frame.get("events"));
        ActionDecision actual=ActionDecision.parse(new String(raw,StandardCharsets.UTF_8),ObservedAppLabels.ACTION_SCHEMA);
        LastModelDecisionProjection saved=LastModelDecisionProjection.fromOutcome(TASK,3,RUN,OBS,actual,true,true,false);
        Map<String,Object> projected=saved.forPrompt(TASK,actualHistory);
        check(TASK.equals(saved.taskId)&&RUN.equals(saved.modelRunId)&&OBS.equals(saved.sourceObservationId),"task, model run and original observation are immutable source bindings");
        check(Integer.valueOf(3).equals(projected.get("step"))&&"click".equals(projected.get("action")),"actual dispatched step and action retained");
        check(actual.reason.equals(saved.reason)&&!saved.reasonTruncated&&!projected.containsKey("reason"),"original reason remains in immutable evidence but is not re-fed");
        check(!prompt.contains(actual.reason)&&!frame.containsKey("last_model_decision"),"regression fixture reproduces dropped prior intention");
        check(LastModelDecisionProjection.SOURCE.equals(projected.get("source")),"model text explicitly differs from observation evidence");
        check(projected.size()==5&&actual.packageName.equals(projected.get("target_package"))&&Boolean.TRUE.equals(projected.get("dispatched"))
                &&!projected.containsKey("node_id")&&!projected.containsKey("package")&&!projected.containsKey("observation_id")
                &&!projected.containsKey("success")&&!projected.containsKey("allowed_tools"),"projection grants no old executable target or completion/permission state");
        Map<?,?> screen=(Map<?,?>)frame.get("screen");
        check("f1a3aff3cd644c7eabadc9520407a491".equals(screen.get("observation_id")),"real current observation differs from historical model source");
        Map<?,?> first=(Map<?,?>)((List<?>)screen.get("editable_fields")).get(0);
        check("23".equals(first.get("text")),"real current readout remains observed text");
        Map<String,Object> augmented=new LinkedHashMap<String,Object>(frame);augmented.put("last_model_decision",projected);
        augmented.remove("last_model_decision");check(augmented.equals(frame),"all original OWNER/frame observations, permissions and events remain unchanged");
        check(hash(Files.readAllBytes(dir.resolve("step-04-prompt.txt"))).equals(hash(promptBytes)),"fixture not rewritten");

        for(boolean[] flags:new boolean[][]{{false,false,false},{false,true,false},{true,false,false},{true,true,true},{false,false,true}})
            check(LastModelDecisionProjection.fromOutcome(TASK,4,RUN,OBS,actual,flags[0],flags[1],flags[2])==null,"unaccepted, undispatched or stale output is not retained");
        check(LastModelDecisionProjection.fromOutcome(null,0,null,null,null,false,false,false)==null,"no output can be invented before dispatch");
        rejects(()->LastModelDecisionProjection.fromOutcome(TASK,3,RUN,"11111111111111111111111111111111",actual,true,true,false),"foreign observation refused");
        rejects(()->LastModelDecisionProjection.fromOutcome("bad",3,RUN,OBS,actual,true,true,false),"malformed task refused");
        rejects(()->LastModelDecisionProjection.fromOutcome(TASK,3,"bad",OBS,actual,true,true,false),"missing model identity refused");
        rejects(()->LastModelDecisionProjection.fromOutcome(TASK,0,RUN,OBS,actual,true,true,false),"nonexistent step refused");
        rejects(()->LastModelDecisionProjection.fromOutcome(TASK,21,RUN,OBS,actual,true,true,false),"out-of-task step refused");
        rejects(()->saved.forPrompt("11111111111111111111111111111111",actualHistory),"old task intention never enters new task");
        rejects(()->saved.forPrompt(TASK,Collections.<Map<String,Object>>emptyList()),"unrecorded action cannot be promoted");
        rejects(()->saved.forPrompt(TASK,Collections.singletonList(row(3,"open",true,true,false))),"same step with different action refused");
        rejects(()->saved.forPrompt(TASK,Collections.singletonList(row(3,"click",true,false,false))),"matching unexecuted history cannot validate a memory");
        List<Map<String,Object>> afterRead=new ArrayList<Map<String,Object>>(actualHistory);
        afterRead.add(row(4,"find_app",true,false,false));
        check(saved.forPrompt(TASK,afterRead).equals(projected),"read-only discovery cannot replace dispatched model intention");
        afterRead.add(row(5,"click",false,false,true));
        check(saved.forPrompt(TASK,afterRead).equals(projected),"stale unexecuted proposal cannot replace dispatched intention");
        List<Map<String,Object>> newer=new ArrayList<Map<String,Object>>(actualHistory);newer.add(row(4,"click",true,true,false));
        rejects(()->saved.forPrompt(TASK,newer),"only latest actual dispatched step may be presented");
        for(String tool:Arrays.asList("wait","find_app","done")){
            final ActionDecision read=decision(tool,"fixture output");
            rejects(()->LastModelDecisionProjection.fromOutcome(TASK,4,RUN,OBS,read,true,true,false),"non-effect tool cannot fabricate a dispatch");
        }

        ActionDecision generic=decision("open","继续原任务；先打开编辑器。");
        LastModelDecisionProjection other=LastModelDecisionProjection.fromOutcome(TASK,4,RUN,OBS,generic,true,true,false);
        Map<String,Object> genericPrompt=other.forPrompt(TASK,Collections.singletonList(row(4,"open",true,true,false)));
        check(generic.packageName.equals(genericPrompt.get("target_package"))&&!genericPrompt.containsKey("reason"),"ordinary tasks retain dispatched target facts without free-form reason feedback");
        ActionDecision unicode=decision("click",repeat("😀",97));
        LastModelDecisionProjection bounded=LastModelDecisionProjection.fromOutcome(TASK,4,RUN,OBS,unicode,true,true,false);
        Map<String,Object> boundedPrompt=bounded.forPrompt(TASK,Collections.singletonList(row(4,"click",true,true,false)));
        check(bounded.reason.codePointCount(0,bounded.reason.length())==96&&bounded.reason.equals(repeat("😀",96)),"one bounded reason preserves complete Unicode scalars");
        check(bounded.reasonTruncated&&!boundedPrompt.containsKey("reason")&&!boundedPrompt.containsKey("reason_truncated"),"bounded prior text stays out of the next prompt");
        boolean immutable=false;try{projected.put("reason","fabricated");}catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"published projection is immutable");
        System.out.println("PASS LastModelDecisionProjectionHostTest checks="+checks+" saved_real_step3_4=true model_inference=false phone_tested=false");
    }
}
