package org.trillionnium.hepta.local;

import java.io.File;

/** An in-process, on-device inference boundary. No networking or HTTP contract. */
public interface LocalInference {
    LocalRuntimeConfig configuration();
    /** A visual adapter receives only the controller's immutable current frame. */
    default boolean acceptsObservedImage() { return false; }
    /** An explicit observation probe always ends before action parsing/dispatch. */
    default boolean modelOutputDispatchAllowed() { return true; }
    /** Includes native exit and generation cleanup after the original request deadline. */
    default long requestCompletionGraceMillis() { return 17000L; }
    /** A live, read-only controller/service ownership check; a copied frame cannot supply it. */
    interface Currentness { void requireCurrent() throws Exception; }
    final class CurrentFrame {
        public final File image;
        public final String taskId, ownerSha256, observationId, backgroundGeneration,
                packageName, imageSha256;
        public final int width, height, displayId, windowId, rotation;
        public final long capturedElapsedMillis;
        private final byte[] taskOwnerEvidence;
        private final Currentness currentness;
        public CurrentFrame(File image,String taskId,String ownerSha256,String observationId,
                String backgroundGeneration,String packageName,String imageSha256,
                int width,int height,int displayId,int windowId,int rotation,long capturedElapsedMillis,
                byte[] taskOwnerEvidence) {
            this(image,taskId,ownerSha256,observationId,backgroundGeneration,packageName,imageSha256,
                    width,height,displayId,windowId,rotation,capturedElapsedMillis,taskOwnerEvidence,null);
        }
        public CurrentFrame(File image,String taskId,String ownerSha256,String observationId,
                String backgroundGeneration,String packageName,String imageSha256,
                int width,int height,int displayId,int windowId,int rotation,long capturedElapsedMillis,
                byte[] taskOwnerEvidence,Currentness currentness) {
            if(image==null||taskId==null||!taskId.matches("[0-9a-f]{32}")
                    ||ownerSha256==null||!ownerSha256.matches("[0-9a-f]{64}")
                    ||imageSha256==null||!imageSha256.matches("[0-9a-f]{64}")
                    ||observationId==null||observationId.isEmpty()||observationId.length()>128
                    ||backgroundGeneration==null||backgroundGeneration.isEmpty()||backgroundGeneration.length()>128
                    ||packageName==null||packageName.isEmpty()||packageName.length()>256
                    ||width<=0||height<=0||width>8192||height>8192||(long)width*height>24000000L
                    ||displayId<=0||windowId<0||rotation<0||rotation>3||capturedElapsedMillis<=0
                    ||taskOwnerEvidence==null||taskOwnerEvidence.length==0||taskOwnerEvidence.length>1600)
                throw new IllegalArgumentException("a complete original background frame is required");
            this.image=image;this.taskId=taskId;this.ownerSha256=ownerSha256;
            this.observationId=observationId;this.backgroundGeneration=backgroundGeneration;
            this.packageName=packageName;this.imageSha256=imageSha256;this.width=width;this.height=height;
            this.displayId=displayId;this.windowId=windowId;this.rotation=rotation;
            this.capturedElapsedMillis=capturedElapsedMillis;
            this.taskOwnerEvidence=taskOwnerEvidence.clone();
            this.currentness=currentness;
        }
        public byte[] taskOwnerEvidence(){return taskOwnerEvidence.clone();}
        public void requireCurrent() throws Exception {
            if(currentness==null)throw new IllegalStateException("current frame has no live ownership check");
            currentness.requireCurrent();
        }
    }
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
    default Handle generateObserved(String originalPrompt,String systemPrompt,CurrentFrame frame,
                    DecisionGrammar controllerGrammar,int maximumTokens,long timeoutMillis,Callback callback) {
        if(frame!=null)throw new IllegalArgumentException("this inference adapter does not accept images");
        return generate(originalPrompt,systemPrompt,null,controllerGrammar,maximumTokens,timeoutMillis,callback);
    }
}
