package org.trillionnium.hepta.local;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** One dispatched model intention. It is neither an observed fact nor an action authority. */
public final class LastModelDecisionProjection {
    public static final String SOURCE="prior_model_output_not_observation";
    public static final int REASON_CODE_POINTS=96;
    public final String taskId,modelRunId,sourceObservationId,action,targetPackage,reason;
    public final int step;
    public final boolean reasonTruncated;

    private LastModelDecisionProjection(String taskId,int step,String run,String observation,ActionDecision decision){
        this.taskId=taskId;this.step=step;modelRunId=run;sourceObservationId=observation;action=decision.action;targetPackage=decision.packageName;
        String raw=decision.reason;int count=raw.codePointCount(0,raw.length());
        reasonTruncated=count>REASON_CODE_POINTS;
        reason=reasonTruncated?raw.substring(0,raw.offsetByCodePoints(0,REASON_CODE_POINTS)):raw;
    }

    /** The caller supplies the parsed decision and its real final dispatch outcome. */
    public static LastModelDecisionProjection fromOutcome(String taskId,int step,String modelRunId,
            String sourceObservationId,ActionDecision decision,boolean accepted,boolean dispatched,boolean stale){
        if(!accepted||!dispatched||stale)return null;
        require(identity(taskId)&&identity(modelRunId)&&identity(sourceObservationId),"prior decision identity missing");
        require(step>=1&&step<=20,"prior decision step outside task bound");
        require(decision!=null&&sourceObservationId.equals(decision.observationId),"prior decision observation mismatch");
        require(!"find_app".equals(decision.action)&&!"wait".equals(decision.action)&&!"done".equals(decision.action),
                "read or terminal decision cannot be a dispatched intention");
        require(decision.reason!=null,"parsed prior reason required");
        return new LastModelDecisionProjection(taskId,step,modelRunId,sourceObservationId,decision);
    }

    /** Keep the last actual dispatched step, including across read-only or rejected proposals. */
    public Map<String,Object> forPrompt(String currentTaskId,List<Map<String,Object>> history){
        require(taskId.equals(currentTaskId),"prior decision belongs to another task");
        require(history!=null&&history.size()<=20,"bounded recorded history required");
        Map<String,Object> last=null;
        for(int i=history.size()-1;i>=0;i--){
            Map<String,Object> row=history.get(i);require(row!=null,"recorded history row missing");
            if(Boolean.TRUE.equals(row.get("model_issued"))&&Boolean.TRUE.equals(row.get("accepted"))
                    &&Boolean.TRUE.equals(row.get("dispatched"))&&Boolean.FALSE.equals(row.get("stale"))){last=row;break;}
        }
        require(last!=null&&Integer.valueOf(step).equals(last.get("step"))&&action.equals(last.get("action")),
                "prior decision does not match the last dispatched history step");
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("source",SOURCE);out.put("step",Integer.valueOf(step));out.put("action",action);
        out.put("target_package",targetPackage);out.put("dispatched",Boolean.TRUE);
        // Prior free-form reasoning stays in the raw/action receipts. Refeeding it
        // anchors repeated text without supplying a new observation or tool fact.
        // The original task/run/observation binding remains in this immutable object and
        // the existing per-step receipts. The historical package is descriptive only;
        // no old node/label pair or action authority is reissued.
        return Collections.unmodifiableMap(out);
    }
    private static boolean identity(String value){return value!=null&&value.matches("[0-9a-f]{32}");}
    private static void require(boolean value,String message){if(!value)throw new IllegalArgumentException(message);}
}
