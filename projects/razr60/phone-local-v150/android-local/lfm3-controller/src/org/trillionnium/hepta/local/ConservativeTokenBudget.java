package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;

/**
 * Upper bound for the pinned LFM3 byte-level BPE tokenizer, not an exact count.
 * It has no normalizer or added prefix space. Native code repeats the bound on
 * the actually rendered chat template before generation.
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
    private ConservativeTokenBudget(String system,String prompt,int contextTokens){
        if(contextTokens!=4096&&contextTokens!=8192)throw new IllegalArgumentException("unsupported context");
        this.contextTokens=contextTokens;
        systemBytesUpper=bytesUpper(system);promptBytesUpper=bytesUpper(prompt);
        promptTokensUpper=systemBytesUpper+promptBytesUpper+TEMPLATE_BOUND+BOS_EOS_BOUND;
        totalContextUpper=promptTokensUpper+GENERATION+RESERVED;admitted=totalContextUpper<=contextTokens;
    }
    public static ConservativeTokenBudget estimate(String system,String prompt,int contextTokens){
        if(system==null||prompt==null)throw new IllegalArgumentException("missing prompt");
        return new ConservativeTokenBudget(system,prompt,contextTokens);
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
