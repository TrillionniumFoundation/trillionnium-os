package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;

/**
 * Java sizing projection, not an exact token count or generation authorization.
 * All current profiles, including LFM3, require native admission of the rendered
 * prompt and the same counted input IDs passed directly to the SDK. Legacy byte
 * bound metadata remains distinguishable; it cannot authorize an exact profile.
 */
public final class ConservativeTokenBudget {
    public static final String TOKENIZER_REFERENCE_SHA256="7e226e34bface23ccf6e495d157bf77186c1c30a7659880e1a8994db528c3701";
    public static final int GENERATION=LocalRuntimeConfig.GENERATION_TOKENS, RESERVED=256;
    // Two text messages, no tools/images, thinking disabled. The native guard
    // checks the actual template, so an underestimated template cannot act.
    public static final int TEMPLATE_BOUND=512, BOS_EOS_BOUND=2;
    public static final String METHOD="pinned_lfm3_utf8_bytes_upper_bound_native_checks_rendered_template";
    public final int systemBytesUpper,promptBytesUpper,promptTokensUpper,totalContextUpper,contextTokens;
    public final boolean admitted;
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
        // Exact-token profiles retain a diagnostic sizing projection only.
        // It is never token authorization: native counts the rendered prompt.
        promptTokensUpper=(provenUpperBound?projectedBytes:(projectedBytes+1)/2)+TEMPLATE_BOUND+BOS_EOS_BOUND;
        totalContextUpper=promptTokensUpper+GENERATION+RESERVED;admitted=totalContextUpper<=contextTokens;
    }
    /**
     * Allows only an attempt at native admission, never generation or an action.
     * The UTF-8 projection remains advisory for profiles whose exact rendered
     * input IDs are counted and bounded by the native worker before generation.
     */
    public boolean mayAttemptNative(){
        return admitted||profile.exactTokenizationRequired;
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
