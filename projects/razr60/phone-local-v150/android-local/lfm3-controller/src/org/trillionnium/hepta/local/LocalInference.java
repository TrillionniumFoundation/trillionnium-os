package org.trillionnium.hepta.local;

import java.io.File;

/** An in-process, on-device inference boundary. No networking or HTTP contract. */
public interface LocalInference {
    LocalRuntimeConfig configuration();
    interface Handle { void cancel(); }
    interface Callback {
        /** Called only after the original model process has exited and inference completed. */
        void onSuccess(String rawText, String runId);
        /** CleanupKnown is false when process termination could not be established. */
        void onFailure(String message, boolean cleanupKnown);
    }
    Handle generate(String originalPrompt, String systemPrompt, File currentImage,
                    DecisionGrammar controllerGrammar, int maximumTokens, long timeoutMillis, Callback callback);
}
