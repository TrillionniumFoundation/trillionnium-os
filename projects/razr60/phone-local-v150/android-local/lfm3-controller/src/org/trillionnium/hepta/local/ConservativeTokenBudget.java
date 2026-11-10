package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;

/**
 * Java input admission and a diagnostic sizing score, never native token proof.
 * The pinned LFM3 byte-level BPE upper bound is retained. Other profiles require
 * exact native tokenization of the rendered template; a UTF-8 sizing heuristic
 * cannot establish that their actual token count exceeds the context.
 */
public final class ConservativeTokenBudget {
    public static final String TOKENIZER_REFERENCE_SHA256="7e226e34bface23ccf6e495d157bf77186c1c30a7659880e1a8994db528c3701";
    public static final int GENERATION=LocalRuntimeConfig.GENERATION_TOKENS, RESERVED=256;
    // Two text messages, no tools/images, thinking disabled. The native guard
    // checks the actual template, so an underestimated template cannot act.
    public static final int TEMPLATE_BOUND=512, BOS_EOS_BOUND=2;
    // Same per-message limit as LocalModelEngine.TEXT_LIMIT and native INPUT_LIMIT.
    public static final int INPUT_UTF8_LIMIT=65536;
    public static final String METHOD="pinned_lfm3_utf8_bytes_upper_bound_native_checks_rendered_template";
    public final int systemBytesUpper,promptBytesUpper,promptTokensUpper,totalContextUpper,contextTokens;
    /** Permission to submit to the unchanged native guard, not token authorization. */
    public final boolean admitted,inputBytesWithinLimit,projectionWithinContext;
    public final ModelProfile profile;
    public final boolean provenUpperBound;
    public final String method;
    private ConservativeTokenBudget(String system,String prompt,ModelProfile profile,int contextTokens){
        if(contextTokens!=4096&&contextTokens!=8192)throw new IllegalArgumentException("unsupported context");
        this.contextTokens=contextTokens;
        this.profile=profile;provenUpperBound=!profile.exactTokenizationRequired;
        method=provenUpperBound?METHOD:"utf8_projection_heuristic_native_exact_tokenization_required";
        systemBytesUpper=bytesUpper(system);promptBytesUpper=bytesUpper(prompt);
        int projectedBytes=systemBytesUpper+promptBytesUpper;
        // Retain the old score as an optional-projection target. It cannot
        // finally reject a complete, byte-bounded exact-profile prompt.
        promptTokensUpper=(provenUpperBound?projectedBytes:(projectedBytes+1)/2)+TEMPLATE_BOUND+BOS_EOS_BOUND;
        totalContextUpper=promptTokensUpper+GENERATION+RESERVED;
        projectionWithinContext=totalContextUpper<=contextTokens;
        inputBytesWithinLimit=systemBytesUpper<=INPUT_UTF8_LIMIT&&promptBytesUpper<=INPUT_UTF8_LIMIT;
        admitted=inputBytesWithinLimit&&(!provenUpperBound||projectionWithinContext);
    }
    public static ConservativeTokenBudget estimate(String system,String prompt,int contextTokens){
        if(system==null||prompt==null)throw new IllegalArgumentException("missing prompt");
        return new ConservativeTokenBudget(system,prompt,ModelProfile.LFM3,contextTokens);
    }
    public static ConservativeTokenBudget estimate(String system,String prompt,LocalRuntimeConfig config){
        if(system==null||prompt==null||config==null)throw new IllegalArgumentException("missing prompt/config");
        return new ConservativeTokenBudget(system,prompt,config.profile,config.contextTokens);
    }
    public static int bytesUpper(String value){
        // Standard UTF-8 files feed the native worker; no JNI modified UTF-8.
        for(int i=0;i<value.length();i++){
            char ch=value.charAt(i);
            if(Character.isHighSurrogate(ch)){
                if(++i>=value.length()||!Character.isLowSurrogate(value.charAt(i)))throw new IllegalArgumentException("invalid Unicode");
            }else if(Character.isLowSurrogate(ch))throw new IllegalArgumentException("invalid Unicode");
            else if(ch==0)throw new IllegalArgumentException("NUL is not permitted");
        }
        return value.getBytes(StandardCharsets.UTF_8).length;
    }
}
