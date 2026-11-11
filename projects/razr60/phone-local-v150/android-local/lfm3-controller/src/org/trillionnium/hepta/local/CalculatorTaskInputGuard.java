package org.trillionnium.hepta.local;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.trillionnium.hepta.background.FixedIntentTarget;

/** Task-local input restrictions for the fully consumed integer Calculator
 * contract. This is not a planner, calculator completion provider or authority. */
public final class CalculatorTaskInputGuard {
    public static final String SCHEMA="hepta.calculator-task-input.v1";
    public interface InstalledVerifier {void verify()throws Exception;}
    public final String taskId;
    public final TaskAuthorization authorization;
    public final CalculatorGoalContract goal;
    private NotesCompletionEvidence.Installed installed;
    private InstalledVerifier verifier;
    private CalculatorCompletionEvidence.TaskBinding binding;
    private Domain current;
    private boolean retired,identityInvalid;

    public CalculatorTaskInputGuard(String task,TaskAuthorization auth){
        require(task!=null&&task.matches("[0-9a-f]{32}")&&auth!=null,"immutable task authorization required");
        taskId=task;authorization=auth;goal=CalculatorGoalContract.parse(auth.immutableOwner(),auth);
    }
    public boolean supported(){return goal!=null;}
    public synchronized void retire(){retired=true;current=null;}
    public synchronized void bindInstalled(NotesCompletionEvidence.Installed value,InstalledVerifier check){
        require(!retired&&supported()&&installed==null&&value!=null&&check!=null
                &&CalculatorGoalContract.PACKAGE.equals(value.packageName),"single actual installed target required");
        installed=value;verifier=check;verifyInstalled();
    }
    private void verifyInstalled(){
        require(!retired&&!identityInvalid&&installed!=null&&verifier!=null,"installed Calculator identity unavailable");
        try{verifier.verify();}
        catch(Exception changed){identityInvalid=true;current=null;throw new IllegalStateException("calculator_task_input: installed identity changed",changed);}
    }
    public synchronized Projection prepare(NotesCompletionEvidence.Frame frame){
        require(!retired&&frame!=null&&frame.observationId!=null&&frame.observationId.matches("[0-9a-f]{32}"),"live observed frame required");
        if(supported()){
            verifyInstalled();
            if(binding==null)binding=new CalculatorCompletionEvidence.TaskBinding(taskId,goal,installed,frame.displayId,frame.backgroundGeneration);
            require(binding.displayId==frame.displayId&&Objects.equals(binding.generation,frame.backgroundGeneration),"observation display/generation changed");
        }
        return new Projection(this,frame);
    }
    public synchronized void publish(Domain domain){require(!retired&&domain!=null&&domain.projection.owner==this,"foreign or retired domain");current=domain;}
    public synchronized void requireCurrent(ActionDecision action){
        require(!retired,"task retired");
        if(current==null){require(!supported(),"supported task has no published input domain");return;}
        if(supported())verifyInstalled();current.requireAction(action);
    }
    private synchronized void requireCurrent(Domain expected,ActionDecision action)throws ActionDecision.InvalidActionException{
        try{require(!retired&&expected!=null&&expected==current,"input domain retired or replaced");requireCurrent(action);}
        catch(IllegalStateException refused){throw new ActionDecision.InvalidActionException(refused.getMessage());}
    }
    private static void require(boolean ok,String why){if(!ok)throw new IllegalStateException("calculator_task_input: "+why);}
    private static Set<String> immutable(Set<String> values){return Collections.unmodifiableSet(new TreeSet<String>(values));}

    public static final class Projection {
        private final CalculatorTaskInputGuard owner;
        public final String observationId,packageName,backgroundGeneration;
        public final int windowId,displayId;
        private final Set<String> buttons;
        private Projection(CalculatorTaskInputGuard owner,NotesCompletionEvidence.Frame frame){
            this.owner=owner;observationId=frame.observationId;packageName=frame.packageName;
            windowId=frame.windowId;displayId=frame.displayId;backgroundGeneration=frame.backgroundGeneration;
            Set<String> observed=new TreeSet<String>();Map<String,Integer> counts=new TreeMap<String,Integer>(),ids=new TreeMap<String,Integer>();
            if(owner.supported()&&CalculatorGoalContract.PACKAGE.equals(frame.packageName)&&frame.metadataObserved
                    &&frame.windowType==1&&frame.windowId>=0&&!frame.nodesTruncated&&frame.nodes.size()<=200){
                for(NotesCompletionEvidence.Node n:frame.nodes){
                    if(n.id!=null)ids.put(n.id,Integer.valueOf(ids.containsKey(n.id)?ids.get(n.id).intValue()+1:1));
                    if(n.viewId!=null&&CalculatorGoalContract.PACKAGE.equals(n.packageName))
                        counts.put(n.viewId,Integer.valueOf(counts.containsKey(n.viewId)?counts.get(n.viewId).intValue()+1:1));
                }
                for(NotesCompletionEvidence.Node n:frame.nodes)if(button(n)&&Integer.valueOf(1).equals(counts.get(n.viewId))
                        &&Integer.valueOf(1).equals(ids.get(n.id)))observed.add(n.id);
            }
            buttons=immutable(observed);
        }
        /** Native button identity plus its actual complete semantic label.
         * Neither a historical readout nor an editable field displaying a digit
         * can masquerade as a digit key. No node ID or action sequence is fixed. */
        private static boolean button(NotesCompletionEvidence.Node n){
            if(n==null||!CalculatorGoalContract.PACKAGE.equals(n.packageName)||!n.enabled||n.password||n.editable||n.scrollable||!n.clickable
                    ||n.id==null||!n.id.matches("n[0-9]{1,5}")||n.observedAppTreeSignature==null||!n.observedAppTreeSignature.matches("[0-9a-f]{64}"))return false;
            int[] b=n.bounds();if(b==null||b.length!=4||b[0]<0||b[1]<0||b[2]<=b[0]||b[3]<=b[1])return false;
            String prefix=CalculatorGoalContract.PACKAGE+":id/";
            if(n.viewId==null||!n.viewId.startsWith(prefix))return false;
            String key=n.viewId.substring(prefix.length()),label=n.label;
            if(key.matches("digit_[0-9]"))return key.substring(6).equals(label);
            if("op_add".equals(key))return "加".equals(label)||"+".equals(label);
            if("op_sub".equals(key))return "减".equals(label)||"−".equals(label)||"-".equals(label);
            if("op_mul".equals(key))return "乘".equals(label)||"×".equals(label);
            if("op_positive_negative".equals(key))return "正负".equals(label)||"+/−".equals(label);
            if("eq".equals(key))return "等于".equals(label)||"=".equals(label);
            if("clr".equals(key))return "清除".equals(label);
            if("del".equals(key))return "删除".equals(label);
            return false;
        }
        public Set<String> clicks(Set<String> supplied){Set<String> out=new TreeSet<String>(supplied);if(owner.supported())out.retainAll(buttons);return out;}
        public Set<String> edits(Set<String> supplied){return owner.supported()?new TreeSet<String>():new TreeSet<String>(supplied);}
        public <T> Map<String,T> submits(Map<String,T> supplied){return owner.supported()?new TreeMap<String,T>():new TreeMap<String,T>(supplied);}
        public Set<String> openPackages(Set<String> supplied){Set<String> out=new TreeSet<String>(supplied);if(owner.supported())out.retainAll(Collections.singleton(CalculatorGoalContract.PACKAGE));return out;}
        public Map<String,FixedIntentTarget> fixedTargets(Map<String,FixedIntentTarget> supplied){
            if(supplied==null)return null;return owner.supported()?new TreeMap<String,FixedIntentTarget>():new TreeMap<String,FixedIntentTarget>(supplied);
        }
        public Domain bind(Set<String> clicks,Set<String> edits,Set<String> submits,Map<String,FixedIntentTarget> fixed,
                           Set<String> packages,Map<String,ObservedScrollActions> scrolls){
            require(clicks(clicks).equals(clicks)&&edits(edits).equals(edits)&&openPackages(packages).equals(packages),"input domain contains removed capability");
            require(!owner.supported()||(submits.isEmpty()&&(fixed==null||fixed.isEmpty())),"input domain contains replacement, submit or fixed tool");
            Map<String,List<String>> directions=new TreeMap<String,List<String>>();
            for(Map.Entry<String,ObservedScrollActions> e:scrolls.entrySet()){
                require(e.getValue()!=null,"observed scroll capability missing");if(e.getValue().hasAny())directions.put(e.getKey(),e.getValue().directions);
            }
            require((clicks.isEmpty()||owner.authorization.allowedTools.contains("click"))&&(edits.isEmpty()||owner.authorization.allowedTools.contains("type"))
                    &&(submits.isEmpty()||owner.authorization.allowedTools.contains("submit"))&&(packages.isEmpty()||owner.authorization.allowedTools.contains("open"))
                    &&(directions.isEmpty()||owner.authorization.allowedTools.contains("scroll"))
                    &&(fixed==null||owner.authorization.allowedTools.containsAll(fixed.keySet())),"input domain exceeds immutable authority");
            return new Domain(this,clicks,packages,directions);
        }
        public Map<String,Object> evidence(Set<String> permittedClicks){
            require(clicks(permittedClicks).equals(permittedClicks),"evidence contains an unavailable button");
            Map<String,Object> o=new LinkedHashMap<String,Object>();o.put("schema",SCHEMA);o.put("task_id",owner.taskId);
            o.put("supported",owner.supported());o.put("observation_id",observationId);o.put("package",packageName);o.put("window_id",windowId);
            o.put("display_id",displayId);o.put("background_generation",backgroundGeneration);
            if(owner.supported()){
                o.put("owner_sha256",owner.goal.ownerSha256);o.put("contract_sha256",owner.goal.contractSha256);
                o.put("target_package",CalculatorGoalContract.PACKAGE);o.put("target_uid",owner.binding.uid);o.put("apk_set_sha256",owner.binding.apkSetSha256);
                o.put("input_method","observed_native_calculator_buttons");o.put("permitted_button_node_ids",immutable(permittedClicks));
                o.put("direct_text_replacement_allowed",false);o.put("submit_allowed",false);
                o.put("next_goal","根据当前观察选择可用计算器按键，每次操作后重新观察；公式与结果框是读数来源，不能作为输入按键。当前数字不证明本任务已经计算完成。");
            }
            o.put("completion_verified",false);o.put("automatic_dispatch",false);o.put("grants_tool_authority",false);return o;
        }
    }
    public static final class Domain {
        public final Projection projection;
        public final Set<String> clickIds,openPackages;
        public final Map<String,List<String>> scrollDirections;
        private Domain(Projection p,Set<String> clicks,Set<String> packages,Map<String,List<String>> scrolls){
            projection=p;clickIds=immutable(clicks);openPackages=immutable(packages);scrollDirections=Collections.unmodifiableMap(new TreeMap<String,List<String>>(scrolls));
        }
        public void requireAction(ActionDecision action){
            require(action!=null&&projection.observationId.equals(action.observationId),"action belongs to another observation");
            if(!projection.owner.supported())return;
            require(!"type".equals(action.action)&&!"submit".equals(action.action)
                    &&!org.trillionnium.hepta.background.FixedIntentTools.isTool(action.action),"direct text/submit/fixed tool is outside Calculator input domain");
            if("click".equals(action.action))require(action.nodeId!=null&&clickIds.contains(action.nodeId),"click is not a current observed native button");
            if("open".equals(action.action))require(openPackages.contains(action.packageName),"open is outside current Calculator domain");
            if("scroll".equals(action.action)){List<String> d=scrollDirections.get(action.nodeId);require(d!=null&&d.contains(action.direction),"scroll direction is not in current observed domain");}
        }
        public void requireCurrent(ActionDecision action)throws ActionDecision.InvalidActionException{projection.owner.requireCurrent(this,action);}
        public Map<String,Object> evidence(){return projection.evidence(clickIds);}
    }
}
