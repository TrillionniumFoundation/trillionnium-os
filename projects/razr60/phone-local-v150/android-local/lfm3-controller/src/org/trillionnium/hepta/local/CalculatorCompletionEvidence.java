package org.trillionnium.hepta.local;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Bounded, read-only completion proof for one current Moto Calculator product.
 * Android/controller code owns actual dispatch, freshness, package identity and cleanup.
 * This class neither executes a calculation in the app nor grants any tool authority.
 */
public final class CalculatorCompletionEvidence {
    public static final String PACKAGE="com.motorola.cn.calculator";
    public static final String FORMULA=PACKAGE+":id/formula", RESULT=PACKAGE+":id/formula_or_result";
    public static final String SCHEMA="hepta.calculator-completion.v1";
    private static final String INTEGER="(?:0|[1-9][0-9]{0,8})";
    private static final Pattern OWNER=Pattern.compile("\\A打开计算器，在当前主输入区计算 ("+INTEGER+") 乘以 ("+INTEGER+")，确认当前结果框显示计算结果后结束任务。\\z");
    private CalculatorCompletionEvidence(){}

    public static final class Goal {
        public final String expression,expressionSha256,result,resultSha256;
        private Goal(String left,String right){
            expression=left+"×"+right;expressionSha256=sha(expression);
            result=new BigInteger(left).multiply(new BigInteger(right)).toString();resultSha256=sha(result);
        }
        /** Entire immutable OWNER only. Negation, quotations and extra clauses are not supported. */
        public static Goal parse(String owner){Matcher m=OWNER.matcher(owner);return m.matches()?new Goal(m.group(1),m.group(2)):null;}
        boolean expression(String text){return expression.equals(canonical(text));}
        String prefix(int length){return expression.substring(0,length);}
        public Map<String,Object> contract(){
            Map<String,Object> o=map();o.put("schema",SCHEMA);o.put("operation","bounded_nonnegative_integer_multiplication");
            o.put("expression_sha256",expressionSha256);o.put("expected_result_sha256",resultSha256);
            o.put("max_operand_digits",9);o.put("result_source","local_BigInteger_from_immutable_owner");
            o.put("expected_result_in_model_prompt",false);return o;
        }
    }
    public static final class Fields {
        public final boolean complete,matched;
        public final String missing;
        public final NotesCompletionEvidence.Node formula,result;
        private Fields(String why,NotesCompletionEvidence.Node formula,NotesCompletionEvidence.Node result,Goal goal){
            missing=why;complete=why==null;this.formula=formula;this.result=result;
            matched=complete&&goal!=null&&goal.expression(formula.text)&&goal.result.equals(result.text);
        }
        public Map<String,Object> evidence(){
            Map<String,Object> o=map();o.put("matched",matched);o.put("complete",complete);o.put("missing",missing);
            o.put("formula_node_id",formula==null?null:formula.id);o.put("formula_view_id",formula==null?null:formula.viewId);
            o.put("formula_raw_sha256",formula==null?null:sha(formula.text));o.put("result_node_id",result==null?null:result.id);
            o.put("result_view_id",result==null?null:result.viewId);o.put("result_raw_sha256",result==null?null:sha(result.text));
            o.put("source","unique_current_accessibility_formula_and_result");o.put("history_item_accepted",false);return o;
        }
    }
    public static Fields fields(NotesCompletionEvidence.Frame f,Goal goal,NotesCompletionEvidence.Installed installed){
        String error=frameError(f);if(error!=null)return new Fields(error,null,null,goal);
        if(!installedValid(installed))return new Fields("actual_installed_calculator_identity_required",null,null,goal);
        NotesCompletionEvidence.Node formula=null,result=null;int formulas=0,results=0;
        for(NotesCompletionEvidence.Node n:f.nodes){
            if(FORMULA.equals(n.viewId)){formulas++;formula=n;}
            if(RESULT.equals(n.viewId)){results++;result=n;}
        }
        if(formulas!=1||results!=1)return new Fields("unique_current_formula_and_result_required",null,null,goal);
        if(!currentField(formula)||!currentField(result))return new Fields("complete_current_editable_field_text_required",formula,result,goal);
        return new Fields(null,formula,result,goal);
    }

    /** Mutable proof state belongs to exactly one TaskCompletionGate, never to the model. */
    public static final class State {
        private final Goal goal;private final TaskAuthorization authorization;
        private int prefix,window=-1,display=-1,lastStep,epoch;private String generation;
        private boolean entered,produced;
        private final Set<String> runs=new HashSet<String>();
        private final List<Map<String,Object>> proofs=new ArrayList<Map<String,Object>>();
        public State(Goal goal,TaskAuthorization authorization){this.goal=goal;this.authorization=authorization;}
        public void observed(NotesCompletionEvidence.Frame f,NotesCompletionEvidence.Installed installed){
            if(prefix==0&&!entered&&!produced)return;
            Fields v=fields(f,goal,installed);
            if(!v.complete||!sameWindow(f)){reset();return;}
            if(produced){if(!v.matched)reset();return;}
            if(!goal.prefix(prefix).equals(canonical(v.result.text)))reset();
        }
        public void action(int step,String run,ActionDecision action,boolean accepted,boolean dispatched,boolean stale,
                           NotesCompletionEvidence.Frame before,NotesCompletionEvidence.Frame after,NotesCompletionEvidence.Installed installed){
            if(step<=lastStep||!runs.add(run)){reset();return;}lastStep=step;
            if(!accepted||!dispatched||stale)return;
            Fields b=fields(before,goal,installed),a=fields(after,goal,installed);
            if(!authorization.allows(action.action)||!b.complete||!a.complete||!PACKAGE.equals(action.packageName)
                    ||!before.observationId.equals(action.observationId)||before.observationId.equals(after.observationId)
                    ||before.windowId!=after.windowId||before.displayId!=after.displayId
                    ||!Objects.equals(before.backgroundGeneration,after.backgroundGeneration)) {reset();return;}
            NotesCompletionEvidence.Node node=target(before,action);
            if(node==null){reset();return;}
            if("type".equals(action.action)){
                // Only the real primary input may establish entry. A formula edit must
                // never borrow an already-correct number from the separate result field.
                // Type alone is not calculation: retain an exact expression readback and
                // require a later observed equals click to replace it with the result.
                if(!RESULT.equals(node.viewId)||!currentField(node)||!goal.expression(action.text)
                        ||goal.expression(node.text)||b.matched||!goal.expression(a.result.text)) {reset();return;}
                bind(after);prefix=goal.expression.length();entered=true;produced=false;
                record("model_typed_complete_owner_expression",step,run,action,node,before,after,a);
                return;
            }
            if(!"click".equals(action.action)||!keyNode(node)){reset();return;}
            String token=key(node.label);
            if("=".equals(token)){
                if(!entered||!sameWindow(before)||!goal.expression(b.result.text)||b.matched||!a.matched){reset();return;}
                produced=true;record("model_equal_then_current_result",step,run,action,node,before,after,a);return;
            }
            if(token==null||produced||entered){reset();return;}
            String beforeInput=canonical(b.result.text),afterInput=canonical(a.result.text);
            if(prefix==0){
                if(!("".equals(beforeInput)||"0".equals(beforeInput))||b.matched){reset();return;}
                bind(before);
            }else if(!sameWindow(before)||!goal.prefix(prefix).equals(beforeInput)){reset();return;}
            if(prefix>=goal.expression.length()||!token.equals(goal.expression.substring(prefix,prefix+1))
                    ||!goal.prefix(prefix+1).equals(afterInput)||Objects.equals(beforeInput,afterInput)){reset();return;}
            prefix++;entered=prefix==goal.expression.length();
            record("model_key_to_observed_expression_prefix",step,run,action,node,before,after,a);
        }
        public boolean verified(NotesCompletionEvidence.Frame current,NotesCompletionEvidence.Installed installed){
            return entered&&produced&&sameWindow(current)&&fields(current,goal,installed).matched;
        }
        public Map<String,Object> prompt(NotesCompletionEvidence.Frame current,NotesCompletionEvidence.Installed installed){
            Map<String,Object> o=map();o.put("input_expression_observed_after_model_tool",entered);
            o.put("current_result_observed_after_model_calculation",produced);
            o.put("current_formula_and_result_match",fields(current,goal,installed).matched);
            o.put("observed_key_prefix_length",prefix);o.put("grants_tool_authority",false);return o;
        }
        public List<String> missing(NotesCompletionEvidence.Frame current,NotesCompletionEvidence.Installed installed){
            List<String> out=new ArrayList<String>();if(!installedValid(installed))out.add("installed_calculator_identity_unavailable");
            if(!entered)out.add("actual_model_owner_expression_entry_missing");
            if(!produced)out.add("actual_model_calculation_to_current_result_missing");
            if(!fields(current,goal,installed).matched)out.add("current_complete_formula_and_exact_result_missing");return out;
        }
        public Map<String,Object> evidence(NotesCompletionEvidence.Frame current,NotesCompletionEvidence.Installed installed){
            Map<String,Object> o=prompt(current,installed);o.put("schema",SCHEMA);o.put("contract",goal.contract());
            o.put("proofs",new ArrayList<Map<String,Object>>(proofs));o.put("active_proof_epoch",epoch);o.put("current_fields",fields(current,goal,installed).evidence());
            o.put("proof_window_id",window);o.put("proof_display_id",display);o.put("proof_background_generation",generation);
            o.put("calculator_engine_implementation_verified",false);o.put("freshness_owner","actual_controller_and_accessibility_dispatch");
            return o;
        }
        private void bind(NotesCompletionEvidence.Frame f){window=f.windowId;display=f.displayId;generation=f.backgroundGeneration;}
        private boolean sameWindow(NotesCompletionEvidence.Frame f){return f!=null&&window==f.windowId&&display==f.displayId&&Objects.equals(generation,f.backgroundGeneration)&&PACKAGE.equals(f.packageName);}
        private void reset(){epoch++;prefix=0;entered=false;produced=false;window=-1;display=-1;generation=null;}
        private void record(String kind,int step,String run,ActionDecision action,NotesCompletionEvidence.Node node,
                            NotesCompletionEvidence.Frame before,NotesCompletionEvidence.Frame after,Fields value){
            Map<String,Object> p=map();p.put("kind",kind);p.put("step",step);p.put("model_run_id",run);p.put("action",action.action);
            p.put("node_id",node.id);p.put("node_label",node.label);p.put("node_view_id",node.viewId);
            p.put("proof_epoch",epoch);p.put("before_observation_id",before.observationId);p.put("after_observation_id",after.observationId);
            p.put("window_id",after.windowId);p.put("display_id",after.displayId);p.put("background_generation",after.backgroundGeneration);
            p.put("current_fields",value.evidence());p.put("model_issued",true);proofs.add(Collections.unmodifiableMap(p));
        }
    }

    private static NotesCompletionEvidence.Node target(NotesCompletionEvidence.Frame f,ActionDecision a){
        if(a.nodeId==null||a.nodeLabel==null)return null;
        for(NotesCompletionEvidence.Node n:f.nodes)if(a.nodeId.equals(n.id))
            return PACKAGE.equals(n.packageName)&&n.enabled&&!n.password&&bounds(n)
                    &&Objects.equals(a.nodeLabel,ObservedTargetLabels.project(n.label))?n:null;
        return null;
    }
    /** Uses observed key semantics plus every exact prefix transition, never guessed key resource IDs.
     * History/field nodes, derived labels and coordinate clicks cannot contribute a key. */
    private static boolean keyNode(NotesCompletionEvidence.Node n){
        return n.clickable&&!n.editable&&!n.scrollable&&!n.password&&n.enabled&&bounds(n)
                &&n.viewId.startsWith(PACKAGE+":id/")&&!FORMULA.equals(n.viewId)&&!RESULT.equals(n.viewId)
                &&!n.viewId.startsWith(PACKAGE+":id/item_")&&!"derived".equals(n.childText.status)&&!n.childText.truncated
                &&(n.text.isEmpty()||n.text.equals(n.label));
    }
    private static String key(String label){
        if(label==null)return null;if(label.matches("[0-9]"))return label;
        if("×".equals(label)||"*".equals(label)||"乘".equals(label)||"乘以".equals(label))return "×";
        if("=".equals(label)||"等于".equals(label))return "=";return null;
    }
    private static boolean currentField(NotesCompletionEvidence.Node n){
        return n!=null&&PACKAGE.equals(n.packageName)&&n.editable&&n.enabled&&!n.password&&bounds(n)
                &&n.text.length()<=32&&sha(n.text).equals(n.inputTextSha256);
    }
    private static String frameError(NotesCompletionEvidence.Frame f){
        if(f==null||!id(f.observationId)||!PACKAGE.equals(f.packageName))return "actual_calculator_frame_required";
        if(!f.metadataObserved||f.windowType!=1||f.windowId<0||f.displayId<0
                ||(f.displayId==0?f.backgroundGeneration!=null:!uuid(f.backgroundGeneration)))return "actual_calculator_display_window_required";
        if(f.nodesTruncated||f.nodes==null||f.nodes.size()>200)return "complete_bounded_calculator_nodes_required";
        Set<String> ids=new HashSet<String>();
        for(NotesCompletionEvidence.Node n:f.nodes)if(n==null||n.id==null||!n.id.matches("n[0-9]{1,5}")||!ids.add(n.id)
                ||!valid(n.packageName)||!valid(n.text)||!valid(n.label)||!valid(n.viewId))return "valid_unique_calculator_nodes_required";
        return null;
    }
    private static boolean installedValid(NotesCompletionEvidence.Installed i){
        if(i==null||!PACKAGE.equals(i.packageName)||i.uid<10000||i.uid>=90000||i.apkHashes==null||i.apkHashes.isEmpty()
                ||i.apkHashes.size()>128||!isSha(i.apkHashes.get("base")))return false;
        for(Map.Entry<String,String> e:i.apkHashes.entrySet())if(!valid(e.getKey())||e.getKey().length()>300
                ||(!"base".equals(e.getKey())&&(!e.getKey().startsWith("split:")||e.getKey().length()==6))||!isSha(e.getValue()))return false;
        return true;
    }
    private static String canonical(String value){return value==null?null:value.replace('*','×');}
    private static boolean bounds(NotesCompletionEvidence.Node n){return n.left>=0&&n.top>=0&&n.right>n.left&&n.bottom>n.top;}
    private static boolean valid(String value){
        if(value==null||value.indexOf('\0')>=0)return false;
        for(int x=0;x<value.length();x++){char c=value.charAt(x);if(Character.isHighSurrogate(c)){
            if(x+1>=value.length()||!Character.isLowSurrogate(value.charAt(++x)))return false;
        }else if(Character.isLowSurrogate(c))return false;}return true;
    }
    private static boolean id(String v){return v!=null&&v.matches("[0-9a-f]{32}");}
    private static boolean uuid(String v){return v!=null&&v.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");}
    private static boolean isSha(String v){return v!=null&&v.matches("[0-9a-f]{64}");}
    private static String sha(String v){return ObservedImeEnter.hash(v);}
    private static Map<String,Object> map(){return new LinkedHashMap<String,Object>();}
}
