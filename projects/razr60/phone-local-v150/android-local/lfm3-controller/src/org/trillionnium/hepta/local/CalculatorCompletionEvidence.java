package org.trillionnium.hepta.local;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Frame;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Installed;
import org.trillionnium.hepta.local.NotesCompletionEvidence.Node;

/** Pure current-field arithmetic evidence. This is deliberately not a whole-goal
 * verifier. Model/action causality, final stability and cleanup remain mandatory
 * controller checks and are not inferred from a correct pair of visible numbers. */
public final class CalculatorCompletionEvidence {
    public static final String SCHEMA="hepta.calculator-current-fields.v1";
    public static final String PACKAGE=CalculatorGoalContract.PACKAGE;
    public static final String FORMULA=PACKAGE+":id/formula";
    public static final String RESULT=PACKAGE+":id/formula_or_result";
    private CalculatorCompletionEvidence(){}

    /** Captured once from the authenticated controller task and actual installed
     * application. A caller must also verify the installation has not changed;
     * this pure object cannot query PackageManager or establish a live task lease. */
    public static final class TaskBinding {
        public final String taskId,ownerSha256,contractSha256,generation,apkSetSha256;
        public final int displayId,uid;
        private final Map<String,String> apks;
        public TaskBinding(String task,CalculatorGoalContract goal,Installed installed,int display,String backgroundGeneration){
            if(!id(task)||goal==null||!installedValid(installed)||!displayValid(display,backgroundGeneration))
                throw new IllegalArgumentException("actual immutable calculator task binding required");
            taskId=task;ownerSha256=goal.ownerSha256;contractSha256=goal.contractSha256;
            displayId=display;generation=backgroundGeneration;uid=installed.uid;
            apks=Collections.unmodifiableMap(new TreeMap<String,String>(installed.apkHashes));apkSetSha256=apkSet(apks);
        }
        private boolean matches(String actualTask,CalculatorGoalContract goal,Installed current){
            return taskId.equals(actualTask)&&goal!=null&&ownerSha256.equals(goal.ownerSha256)
                    &&contractSha256.equals(goal.contractSha256)&&installedValid(current)
                    &&uid==current.uid&&apks.equals(current.apkHashes);
        }
    }

    public static final class Match {
        public final boolean currentArithmeticObserved;
        /** Always false here: no UI-only snapshot proves a model performed the task. */
        public final boolean completionVerified=false;
        public final String missing,formulaNodeId,resultNodeId,formulaTextSha256,resultTextSha256;
        private final TaskBinding binding;private final CalculatorGoalContract goal;private final Frame frame;
        private final Node formula,result;
        private Match(String error,TaskBinding binding,CalculatorGoalContract goal,Frame frame,Node formula,Node result){
            missing=error;currentArithmeticObserved=error==null;this.binding=binding;this.goal=goal;this.frame=frame;
            this.formula=formula;this.result=result;formulaNodeId=formula==null?null:formula.id;resultNodeId=result==null?null:result.id;
            formulaTextSha256=formula==null?null:ObservedImeEnter.completeTextHash(formula.text);
            resultTextSha256=result==null?null:ObservedImeEnter.completeTextHash(result.text);
        }
        public Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("schema",SCHEMA);
            out.put("source","complete_current_calculator_fields_not_model_claim");
            out.put("task_id",binding==null?null:binding.taskId);out.put("owner_sha256",goal==null?null:goal.ownerSha256);
            out.put("contract_sha256",goal==null?null:goal.contractSha256);out.put("observation_id",frame==null?null:frame.observationId);
            out.put("package",frame==null?null:frame.packageName);out.put("window_id",frame==null?null:frame.windowId);
            out.put("display_id",frame==null?null:frame.displayId);out.put("background_generation",frame==null?null:frame.backgroundGeneration);
            out.put("target_uid",binding==null?null:binding.uid);out.put("apk_set_sha256",binding==null?null:binding.apkSetSha256);
            out.put("current_arithmetic_observed",currentArithmeticObserved);out.put("missing",missing);
            out.put("formula_node_id",formulaNodeId);out.put("result_node_id",resultNodeId);
            out.put("formula_text_sha256",formulaTextSha256);out.put("result_text_sha256",resultTextSha256);
            out.put("formula_input_text_sha256",formula==null?null:formula.inputTextSha256);
            out.put("result_input_text_sha256",result==null?null:result.inputTextSha256);
            out.put("formula_source_sha256",formula==null?null:formula.observedAppTreeSignature);
            out.put("result_source_sha256",result==null?null:result.observedAppTreeSignature);
            out.put("formula_view_id",formula==null?null:formula.viewId);out.put("result_view_id",result==null?null:result.viewId);
            out.put("expected_integer_sha256",goal==null?null:goal.expectedResultSha256);
            out.put("completion_verified",false);out.put("model_calculation_causality_verified",false);
            out.put("final_observation_stability_verified",false);out.put("terminal_cleanup_verified",false);
            out.put("grants_tool_authority",false);out.put("automatic_dispatch",false);
            return Collections.unmodifiableMap(out);
        }
    }

    public static Match inspect(TaskBinding binding,String actualTask,CalculatorGoalContract goal,Frame frame,Installed currentInstalled){
        if(binding==null||!binding.matches(actualTask,goal,currentInstalled))return absent("task_owner_or_installed_identity_mismatch",binding,goal,frame,null,null);
        String error=frameError(frame,binding);
        if(error!=null)return absent(error,binding,goal,frame,null,null);
        Node formula=null,result=null;int formulas=0,results=0;
        for(Node node:frame.nodes){
            if(FORMULA.equals(node.viewId)){formula=node;formulas++;}
            if(RESULT.equals(node.viewId)){result=node;results++;}
        }
        if(formulas!=1||results!=1)return absent("unique_current_formula_and_result_required",binding,goal,frame,formula,result);
        if(!fieldValid(formula)||!fieldValid(result))return absent("complete_own_text_and_actual_field_source_required",binding,goal,frame,formula,result);
        if(!goal.matchesFormula(formula.text))return absent("current_formula_does_not_match_owner_expression",binding,goal,frame,formula,result);
        // Only the known minus glyph has an explicit display alias. No trimming,
        // grouping removal, substring match or matching against historical rows.
        String integer=result.text.startsWith("−")?"-"+result.text.substring(1):result.text;
        if(!goal.expectedResult.equals(integer))return absent("current_result_does_not_match_exact_owner_arithmetic",binding,goal,frame,formula,result);
        return new Match(null,binding,goal,frame,formula,result);
    }
    private static Match absent(String why,TaskBinding b,CalculatorGoalContract g,Frame f,Node formula,Node result){return new Match(why,b,g,f,formula,result);}
    private static boolean fieldValid(Node n){
        return PACKAGE.equals(n.packageName)&&n.enabled&&!n.password&&n.editable
                &&n.left>=0&&n.top>=0&&n.right>n.left&&n.bottom>n.top
                &&n.text.length()>0&&n.text.length()<=96&&ObservedImeEnter.isSha(n.observedAppTreeSignature)
                &&ObservedImeEnter.isSha(n.inputTextSha256)&&n.inputTextSha256.equals(ObservedImeEnter.completeTextHash(n.text));
    }
    private static String frameError(Frame f,TaskBinding binding){
        if(f==null||!id(f.observationId)||!PACKAGE.equals(f.packageName))return "actual_calculator_observation_required";
        if(!f.metadataObserved||f.windowType!=1||f.windowId<0)return "observed_application_window_required";
        if(!displayValid(f.displayId,f.backgroundGeneration)||f.displayId!=binding.displayId
                ||!Objects.equals(f.backgroundGeneration,binding.generation))return "task_display_or_generation_mismatch";
        if(f.nodesTruncated||f.nodes==null||f.nodes.size()>200)return "complete_bounded_observation_required";
        Set<String> ids=new HashSet<String>();
        for(Node n:f.nodes){
            if(n==null||n.id==null||!n.id.matches("n[0-9]{1,5}")||!ids.add(n.id))return "unique_actual_node_ids_required";
            if(!unicode(n.text)||!unicode(n.label)||!unicode(n.packageName)||!unicode(n.viewId))return "valid_observed_node_strings_required";
        }
        return null;
    }
    private static boolean installedValid(Installed installed){
        if(installed==null||!PACKAGE.equals(installed.packageName)||installed.uid<10000||installed.uid>=90000
                ||installed.apkHashes==null||installed.apkHashes.isEmpty()||installed.apkHashes.size()>128
                ||!ObservedImeEnter.isSha(installed.apkHashes.get("base")))return false;
        for(Map.Entry<String,String> entry:installed.apkHashes.entrySet()){
            String key=entry.getKey();
            if(key==null||key.length()>300||!unicode(key)||(!"base".equals(key)&&(!key.startsWith("split:")||key.length()==6))
                    ||!ObservedImeEnter.isSha(entry.getValue()))return false;
        }
        return true;
    }
    private static String apkSet(Map<String,String> hashes){StringBuilder rows=new StringBuilder();for(Map.Entry<String,String> e:new TreeMap<String,String>(hashes).entrySet())rows.append(e.getKey()).append('\t').append(e.getValue()).append('\n');return ObservedImeEnter.hash(rows.toString());}
    private static boolean displayValid(int display,String generation){return display>=0&&(display==0?generation==null:generation!=null&&generation.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));}
    private static boolean id(String text){return text!=null&&text.matches("[0-9a-f]{32}");}
    private static boolean unicode(String text){return text!=null&&ObservedImeEnter.completeTextHash(text)!=null;}
}
