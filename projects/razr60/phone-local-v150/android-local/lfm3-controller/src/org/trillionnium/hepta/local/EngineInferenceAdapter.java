package org.trillionnium.hepta.local;

import java.io.File;

/** The only connection between the controller and this candidate's local engine. */
public final class EngineInferenceAdapter implements LocalInference {
    private final LocalModelEngine engine;
    private volatile LocalModelEngine.WarmTask task;
    public EngineInferenceAdapter(LocalModelEngine engine){if(engine==null)throw new IllegalArgumentException("engine required");this.engine=engine;}
    @Override public LocalRuntimeConfig configuration(){return engine.configuration();}
    @Override public synchronized void beginTask(String taskId){
        if(task!=null)throw new IllegalStateException("prior task worker still owned");
        task=engine.beginWarmTask(taskId);
    }
    @Override public void cancelTask(){LocalModelEngine.WarmTask value=task;if(value!=null)engine.cancelWarmTask(value);}
    @Override public synchronized TaskCleanup endTask(){
        LocalModelEngine.WarmTask value=task;if(value==null)return TaskCleanup.noWorker();
        TaskCleanup proof=engine.finishWarmTask(value);
        if(proof.cleanupKnown)task=null;
        return proof;
    }
    @Override public Handle generate(String prompt,String system,File image,DecisionGrammar controllerGrammar,int maxTokens,long timeout,final Callback callback){
        if(image!=null)throw new IllegalArgumentException("LFM3 text controller does not receive screenshots");
        if(controllerGrammar==null)throw new IllegalArgumentException("controller requests require their observed action grammar");
        final LocalModelEngine.WarmTask expected=task;
        if(expected==null)throw new IllegalStateException("task model session not reserved");
        final LocalModelEngine.RunHandle handle=engine.startWarmRequest(expected,new LocalModelEngine.Request(prompt,system,image,maxTokens,timeout,controllerGrammar),
                new LocalModelEngine.Listener(){public void onFinished(LocalModelEngine.Result result){
                    if(task==expected&&result.requestCommitted&&result.inferenceCompleted
                            &&expected.generation().equals(result.workerGeneration)&&expected.taskId.equals(result.taskId)){
                        callback.onSuccess(result.rawText,result.runId);
                    }else{
                        boolean cleanup=result.processExitObserved||!result.receipt.optBoolean("process_started",true);
                        callback.onFailure(result.status+": "+result.receipt.optString("error","本地推理未完成"),cleanup);
                    }
                }});
        return new Handle(){public void cancel(){handle.cancel();}};
    }
}
