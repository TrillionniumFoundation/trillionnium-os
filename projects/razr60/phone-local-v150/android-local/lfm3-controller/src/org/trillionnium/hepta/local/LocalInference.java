package org.trillionnium.hepta.local;

import java.io.File;

/** An in-process, on-device inference boundary. No networking or HTTP contract. */
public interface LocalInference {
    LocalRuntimeConfig configuration();
    /** Reserve one model slot for a task; no model is loaded until its first request. */
    default void beginTask(String taskId) { }
    default void cancelTask() { }
    /** Called on the controller worker before publishing a task terminal. */
    default TaskCleanup endTask() { return TaskCleanup.noWorker(); }
    final class TaskCleanup {
        public final boolean cleanupKnown, processStarted, processExitObserved, receiptValid;
        public final Integer exitCode;
        public final String generation, taskId, receiptSha256;
        public TaskCleanup(boolean cleanupKnown,boolean started,boolean exited,Integer code,
                           String generation,String taskId,boolean receiptValid,String receiptSha256) {
            this.cleanupKnown=cleanupKnown;this.processStarted=started;this.processExitObserved=exited;
            this.exitCode=code;this.generation=generation;this.taskId=taskId;
            this.receiptValid=receiptValid;this.receiptSha256=receiptSha256;
        }
        static TaskCleanup noWorker() { return new TaskCleanup(true,false,false,null,null,null,true,null); }
    }
    interface Handle { void cancel(); }
    interface Callback {
        /** A sealed request may retain its task-owned worker. endTask proves final cleanup. */
        void onSuccess(String rawText, String runId);
        /** CleanupKnown is false when process termination could not be established. */
        void onFailure(String message, boolean cleanupKnown);
    }
    Handle generate(String originalPrompt, String systemPrompt, File currentImage,
                    DecisionGrammar controllerGrammar, int maximumTokens, long timeoutMillis, Callback callback);
}
