package org.trillionnium.hepta.localprobe;

import java.io.File;

/** The only connection between the controller and this candidate's local engine. */
public final class EngineInferenceAdapter implements LocalInference {
    private final LocalModelEngine engine;
    public EngineInferenceAdapter(LocalModelEngine engine){if(engine==null)throw new IllegalArgumentException("engine required");this.engine=engine;}
    @Override public Handle generate(String prompt,String system,File image,int maxTokens,long timeout,final Callback callback){
        final LocalModelEngine.RunHandle handle=engine.start(new LocalModelEngine.Request(prompt,system,image,maxTokens,timeout),
                new LocalModelEngine.Listener(){public void onFinished(LocalModelEngine.Result result){
                    if(result.processExitObserved&&result.inferenceCompleted&&result.exitCode!=null&&result.exitCode.intValue()==0){
                        callback.onSuccess(result.rawText,result.runId);
                    }else{
                        boolean cleanup=result.processExitObserved||!result.receipt.optBoolean("process_started",true);
                        callback.onFailure(result.status+": "+result.receipt.optString("error","本地推理未完成"),cleanup);
                    }
                }});
        return new Handle(){public void cancel(){handle.cancel();}};
    }
}
