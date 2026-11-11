package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** One task's conservative submit ledger. A wait/window change never re-arms input. */
public final class SubmitAttemptGuard {
    public static final int MAX_ATTEMPTS=20;
    public interface Journal { void write(Attempt attempt) throws Exception; }
    public final String taskId;
    private final Journal journal;
    private final Map<String,Attempt> attempts=new LinkedHashMap<String,Attempt>();
    private final Map<String,Map<String,Object>> results=new LinkedHashMap<String,Map<String,Object>>();
    private boolean retired;
    public SubmitAttemptGuard(String taskId,Journal journal){
        require(taskId!=null&&!taskId.isEmpty()&&journal!=null,"task and durable journal required");
        this.taskId=taskId;this.journal=journal;
    }
    private static void require(boolean value,String message){if(!value)throw new IllegalStateException("ime_submit: "+message);}
    private static String key(String pkg,String textSha){
        require(validPackage(pkg),"package required");
        require(ObservedImeEnter.isSha(textSha),"complete input hash required");return pkg+"|"+textSha;
    }
    public synchronized boolean available(String pkg,String textSha){
        return !retired&&validPackage(pkg)&&ObservedImeEnter.isSha(textSha)&&attempts.size()<MAX_ATTEMPTS&&!attempts.containsKey(key(pkg,textSha));
    }
    private static boolean validPackage(String pkg){return pkg!=null&&pkg.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+");}
    public synchronized void retire(){retired=true;}
    /** Consumption precedes durable recording; recording failure can never dispatch or re-arm. */
    public synchronized Attempt consume(Binding binding)throws Exception{
        require(binding!=null&&taskId.equals(binding.taskId),"different task binding");
        String key=key(binding.packageName,binding.inputTextSha256);
        require(available(binding.packageName,binding.inputTextSha256),"input already attempted or task unavailable");
        Attempt attempt=new Attempt(binding,attempts.size()+1);attempts.put(key,attempt);
        results.put(attempt.id,attempt.result(false,null,"not_dispatched"));
        journal.write(attempt);
        return attempt;
    }
    /** Called immediately before entering the platform call; not after its return. */
    public synchronized void entering(Attempt attempt){
        own(attempt);require(!retired,"retired before call");
        require("not_dispatched".equals(results.get(attempt.id).get("result")),"attempt already entered");
        results.put(attempt.id,attempt.result(true,null,"unknown"));
    }
    public synchronized Map<String,Object> finished(Attempt attempt,Boolean apiAccepted){
        own(attempt);require(Boolean.TRUE.equals(results.get(attempt.id).get("dispatch_attempted")),"call was not entered");
        Map<String,Object> value=attempt.result(true,apiAccepted,apiAccepted==null?"unknown":apiAccepted.booleanValue()?"accepted":"refused");
        results.put(attempt.id,value);return new LinkedHashMap<String,Object>(value);
    }
    public synchronized Map<String,Object> evidence(Attempt attempt){own(attempt);return new LinkedHashMap<String,Object>(results.get(attempt.id));}
    public synchronized List<Map<String,Object>> snapshot(){
        List<Map<String,Object>> rows=new ArrayList<Map<String,Object>>();
        for(Map<String,Object> value:results.values())rows.add(new LinkedHashMap<String,Object>(value));return rows;
    }
    private void own(Attempt attempt){require(attempt!=null&&attempts.get(key(attempt.binding.packageName,attempt.binding.inputTextSha256))==attempt,"foreign attempt");}
    public static final class Binding {
        public final String taskId,modelRunId,observationId,packageName,nodeId,backgroundGeneration,inputTextSha256;
        public final int windowId,displayId;
        public final ObservedImeEnter capability;
        public Binding(String task,String run,String observation,String pkg,String node,int window,int display,String background,String input,ObservedImeEnter capability){
            require(task!=null&&!task.isEmpty()&&run!=null&&!run.isEmpty(),"task/model identity required");
            require(observation!=null&&observation.matches("[0-9a-f]{32}")&&node!=null&&node.matches("n[0-9]{1,5}"),"observed target identity required");
            key(pkg,input);require(window>=0&&display>=0,"observed window/display required");
            require(capability!=null&&capability.queryAllowed(),"observed query action required");
            taskId=task;modelRunId=run;observationId=observation;packageName=pkg;nodeId=node;windowId=window;displayId=display;
            backgroundGeneration=background;inputTextSha256=input;this.capability=capability;
        }
    }
    public static final class Attempt {
        public final Binding binding;
        public final int ordinal;
        public final String id;
        private Attempt(Binding binding,int ordinal){
            this.binding=binding;this.ordinal=ordinal;
            id=ObservedImeEnter.hash(binding.taskId+"|"+ordinal+"|"+key(binding.packageName,binding.inputTextSha256));
        }
        private Map<String,Object> identity(){
            Map<String,Object> value=new LinkedHashMap<String,Object>();value.put("task_id",binding.taskId);
            value.put("model_run_id",binding.modelRunId);value.put("observation_id",binding.observationId);
            value.put("package",binding.packageName);value.put("node_id",binding.nodeId);
            value.put("window_id",binding.windowId);value.put("display_id",binding.displayId);
            value.put("background_generation",binding.backgroundGeneration);value.put("input_text_sha256",binding.inputTextSha256);
            value.put("action_label",binding.capability.label);value.put("action_label_sha256",binding.capability.labelSha256);
            value.put("attempt_id",id);value.put("attempt_ordinal",ordinal);value.put("attempt_consumed",true);
            value.put("automatic_retry_allowed",false);return value;
        }
        public Map<String,Object> journal(){
            Map<String,Object> value=identity();value.put("schema","hepta.ime-submit-attempt.v1");
            value.put("stage","consumed_before_call");return Collections.unmodifiableMap(value);
        }
        private Map<String,Object> result(boolean attempted,Boolean apiAccepted,String result){
            Map<String,Object> value=identity();value.put("schema","hepta.ime-submit-result.v1");
            value.put("dispatch_attempted",attempted);value.put("api_accepted",apiAccepted);value.put("result",result);
            value.put("goal_independently_verified",false);return Collections.unmodifiableMap(value);
        }
    }
}
