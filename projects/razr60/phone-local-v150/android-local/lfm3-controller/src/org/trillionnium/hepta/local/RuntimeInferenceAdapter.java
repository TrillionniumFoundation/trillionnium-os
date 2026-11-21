package org.trillionnium.hepta.local;

import android.content.Context;
import java.io.File;

/** One cached controller, one exact runtime/delegate binding per task.
 * Settings can select the next task's modality only after the prior delegate proves cleanup.
 */
public final class RuntimeInferenceAdapter implements LocalInference {
    interface Factory {LocalInference create(LocalRuntimeConfig config);}
    private final LocalModelEngine engine;
    private final Factory factory;
    private volatile Binding binding;
    private static final class Binding {
        final String taskId;
        final LocalModelEngine.RuntimeGeneration runtime;
        final LocalInference delegate;
        boolean ending;
        Binding(String taskId,LocalModelEngine.RuntimeGeneration runtime,LocalInference delegate){
            this.taskId=taskId;this.runtime=runtime;this.delegate=delegate;
        }
    }
    public RuntimeInferenceAdapter(Context context,LocalModelEngine engine){
        this(engine,factory(context,engine));
    }
    private static Factory factory(final Context context,final LocalModelEngine engine){
        if(context==null||engine==null)throw new IllegalArgumentException("context and shared engine required");
        return config->config.profile.visual()?new VlmInferenceAdapter(context,engine):new EngineInferenceAdapter(engine);
    }
    RuntimeInferenceAdapter(LocalModelEngine engine,Factory factory){
        if(engine==null||factory==null)throw new IllegalArgumentException("shared engine and adapter factory required");
        this.engine=engine;this.factory=factory;
    }
    @Override public LocalRuntimeConfig configuration(){
        Binding value=binding;
        return value==null?engine.configuration():value.runtime.configuration();
    }
    @Override public boolean acceptsObservedImage(){return configuration().profile.visual();}
    @Override public boolean modelOutputDispatchAllowed(){return !configuration().visualObservationOnly;}
    @Override public long requestCompletionGraceMillis(){
        Binding value=binding;
        return value==null?(configuration().profile.visual()?VlmPins.COMPLETION_GRACE_MILLIS:17000L):
                value.delegate.requestCompletionGraceMillis();
    }
    @Override public synchronized void beginTask(String taskId){
        TaskCleanup.requireTaskId(taskId);
        if(binding!=null)throw new IllegalStateException("prior task still owns its runtime adapter");
        LocalModelEngine.RuntimeGeneration runtime=engine.runtimeGeneration();
        LocalRuntimeConfig config=runtime.configuration();
        LocalInference delegate=factory.create(config);
        if(delegate==null||delegate.configuration()!=config||delegate.acceptsObservedImage()!=config.profile.visual()
                ||delegate.modelOutputDispatchAllowed()==config.visualObservationOnly
                ||engine.runtimeGeneration()!=runtime)
            throw new IllegalStateException("inference adapter differs from the captured runtime generation");
        Binding value=new Binding(taskId,runtime,delegate);binding=value;
        // Retain the binding even when beginTask throws after taking a model slot.
        delegate.beginTask(taskId);
        if(engine.runtimeGeneration()!=runtime)
            throw new IllegalStateException("runtime generation changed while reserving the task");
    }
    @Override public void cancelTask(){
        Binding value=binding;if(value!=null)value.delegate.cancelTask();
    }
    @Override public TaskCleanup endTask(){
        Binding value=binding;
        return value==null?TaskCleanup.noWorker():endTask(value.taskId);
    }
    @Override public TaskCleanup endTask(String expectedTaskId){
        TaskCleanup.requireTaskId(expectedTaskId);
        final Binding value;
        synchronized(this){
            value=binding;
            if(value==null)return TaskCleanup.noWorker(expectedTaskId);
            if(!value.taskId.equals(expectedTaskId)||value.ending)
                throw new IllegalStateException("runtime adapter cleanup belongs to another or ending task");
            value.ending=true;
        }
        try{
            TaskCleanup proof=TaskCleanup.requireTask(expectedTaskId,value.delegate.endTask(expectedTaskId));
            synchronized(this){
                if(binding!=value)throw new IllegalStateException("task runtime binding changed during cleanup");
                if(proof.cleanupKnown)binding=null;
            }
            return proof;
        }finally{
            synchronized(this){value.ending=false;}
        }
    }
    private synchronized Binding current(){
        Binding value=binding;
        if(value==null||value.ending||engine.runtimeGeneration()!=value.runtime)
            throw new IllegalStateException("no current task owns the captured runtime generation");
        return value;
    }
    @Override public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,
            int maximum,long timeout,Callback callback){
        Binding value=current();
        return value.delegate.generate(prompt,system,image,grammar,maximum,timeout,callback);
    }
    @Override public Handle generateObserved(String prompt,String system,CurrentFrame frame,DecisionGrammar grammar,
            int maximum,long timeout,Callback callback){
        Binding value=current();
        if(frame!=null&&!value.taskId.equals(frame.taskId))
            throw new IllegalArgumentException("current frame belongs to a different task");
        return value.delegate.generateObserved(prompt,system,frame,grammar,maximum,timeout,callback);
    }
}
