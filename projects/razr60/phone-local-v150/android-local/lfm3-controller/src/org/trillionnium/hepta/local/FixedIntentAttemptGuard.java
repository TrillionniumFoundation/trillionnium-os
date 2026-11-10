package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.trillionnium.hepta.background.FixedIntentTarget;
import org.trillionnium.hepta.background.FixedIntentTools;

/** One durable attempt per compiled tool in one owner task; uncertain calls never re-arm. */
public final class FixedIntentAttemptGuard {
    public interface Journal {void write(Attempt value)throws Exception;}
    public final String taskId;
    private final Journal journal;
    private final Map<String,Attempt> attempts=new LinkedHashMap<String,Attempt>();
    private final Map<String,Map<String,Object>> results=new LinkedHashMap<String,Map<String,Object>>();
    private boolean retired;
    public FixedIntentAttemptGuard(String task,Journal journal){
        require(id(task)&&journal!=null,"task and durable journal required");taskId=task;this.journal=journal;
    }
    private static void require(boolean ok,String why){if(!ok)throw new IllegalStateException("fixed_intent: "+why);}
    private static boolean id(String value){return value!=null&&value.matches("[0-9a-f]{32}");}
    public synchronized boolean available(String action){return !retired&&FixedIntentTools.isTool(action)&&!attempts.containsKey(action);}
    public synchronized void retire(){retired=true;}
    public synchronized Attempt consume(Binding binding)throws Exception{
        require(binding!=null&&taskId.equals(binding.taskId)&&available(binding.target.action),"tool already consumed or task retired");
        Attempt result=new Attempt(binding,attempts.size()+1);attempts.put(binding.target.action,result);
        results.put(result.id,result.result(false,null,"not_dispatched"));journal.write(result);return result;
    }
    public synchronized void entering(Attempt value){
        own(value);require(!retired&&"not_dispatched".equals(results.get(value.id).get("result")),"attempt unavailable");
        results.put(value.id,value.result(true,null,"unknown"));
    }
    public synchronized Map<String,Object> finished(Attempt value,Boolean accepted){
        own(value);require(Boolean.TRUE.equals(results.get(value.id).get("dispatch_attempted")),"attempt not entered");
        Map<String,Object> row=value.result(true,accepted,accepted==null?"unknown":accepted.booleanValue()?"launch_accepted":"refused");
        results.put(value.id,row);return new LinkedHashMap<String,Object>(row);
    }
    public synchronized Map<String,Object> evidence(Attempt value){own(value);return new LinkedHashMap<String,Object>(results.get(value.id));}
    public synchronized List<Map<String,Object>> snapshot(){List<Map<String,Object>> rows=new ArrayList<Map<String,Object>>();for(Map<String,Object> r:results.values())rows.add(new LinkedHashMap<String,Object>(r));return rows;}
    private void own(Attempt a){require(a!=null&&attempts.get(a.binding.target.action)==a,"foreign attempt");}
    public static final class Binding {
        public final String taskId,modelRunId,observationId,sourcePackage,backgroundGeneration,payloadSha256;
        public final int sourceWindowId,displayId;public final FixedIntentTarget target;
        public Binding(String task,String run,String observation,String source,int window,int display,String generation,FixedIntentTarget target,String payload){
            require(id(task)&&id(run)&&id(observation)&&target!=null,"native model/task/observation identity required");
            require(source!=null&&!source.isEmpty()&&window>=0&&display>=0,"source window/display required");
            require((display==0&&generation==null)||(display>0&&generation!=null&&org.trillionnium.hepta.background.BrokerProtocol.uuid(generation)),"background display/generation binding required");
            FixedIntentTools.forAction(target.action).validatePayload(payload);
            taskId=task;modelRunId=run;observationId=observation;sourcePackage=source;sourceWindowId=window;
            displayId=display;backgroundGeneration=generation;this.target=target;payloadSha256=ObservedImeEnter.hash(payload);
        }
    }
    public static final class Attempt {
        public final Binding binding;public final int ordinal;public final String id;
        private Attempt(Binding binding,int ordinal){this.binding=binding;this.ordinal=ordinal;
            id=ObservedImeEnter.hash(binding.taskId+"|"+ordinal+"|"+binding.target.action+"|"+binding.payloadSha256);}
        private Map<String,Object> identity(){
            Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("task_id",binding.taskId);row.put("model_run_id",binding.modelRunId);
            row.put("observation_id",binding.observationId);row.put("source_package",binding.sourcePackage);row.put("source_window_id",binding.sourceWindowId);
            row.put("display_id",binding.displayId);row.put("background_generation",binding.backgroundGeneration);
            row.put("target",binding.target.evidence());row.put("action",binding.target.action);row.put("payload_sha256",binding.payloadSha256);
            row.put("attempt_id",id);row.put("attempt_ordinal",ordinal);row.put("attempt_consumed",true);row.put("automatic_retry_allowed",false);return row;
        }
        public Map<String,Object> journal(){Map<String,Object> row=identity();row.put("schema","hepta.fixed-intent-attempt.v1");row.put("stage","consumed_before_call");return row;}
        private Map<String,Object> result(boolean entered,Boolean accepted,String state){
            Map<String,Object> row=identity();row.put("schema","hepta.fixed-intent-result.v1");row.put("dispatch_attempted",entered);row.put("api_accepted",accepted);row.put("result",state);
            row.put("requested_outcome",FixedIntentTools.forAction(binding.target.action).outcome);
            row.put("goal_independently_verified",false);row.put("saved_or_search_results_verified",false);return row;
        }
    }
}
