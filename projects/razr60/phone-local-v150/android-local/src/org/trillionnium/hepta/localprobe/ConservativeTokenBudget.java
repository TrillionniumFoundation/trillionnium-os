package org.trillionnium.hepta.localprobe;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.Normalizer;

/** Deliberately conservative byte-level BPE bound, never reported as exact tokens. */
public final class ConservativeTokenBudget {
    public static final String TOKENIZER_SHA256="be75606093db2094d7cd20f3c2f385c212750648bd6ea4fb2bf507a6a4c55506";
    public static final int CONTEXT=4096, GENERATION=256, RESERVED=256;
    // Fixed Qwen2VL formatter has 80 literal UTF-8 bytes; 192 leaves extra margin.
    public static final int TEMPLATE_BOUND=192, IMAGE_TOKENS=256, VISION_BOUNDARIES=2, BOS_BOUND=1;
    public static final String METHOD="max_raw_nfc_utf8_bytes_plus_fixed_formatter_and_vision_upper_bound";
    public final int systemBytesUpper,promptBytesUpper,promptTokensUpper,totalContextUpper;
    public final boolean admitted;
    private ConservativeTokenBudget(String system,String prompt){
        systemBytesUpper=bytesUpper(system);promptBytesUpper=bytesUpper(prompt);
        promptTokensUpper=systemBytesUpper+promptBytesUpper+TEMPLATE_BOUND+IMAGE_TOKENS+VISION_BOUNDARIES+BOS_BOUND;
        totalContextUpper=promptTokensUpper+GENERATION+RESERVED;admitted=totalContextUpper<=CONTEXT;
    }
    public static ConservativeTokenBudget estimate(String system,String prompt){
        if(system==null||prompt==null)throw new IllegalArgumentException("missing prompt");
        if(system.contains("<__image__>")||prompt.contains("<__image__>"))throw new IllegalArgumentException("reserved image marker");
        return new ConservativeTokenBudget(system,prompt);
    }
    public static int bytesUpper(String value){
        int raw=value.getBytes(StandardCharsets.UTF_8).length;
        int nfc=Normalizer.normalize(value,Normalizer.Form.NFC).getBytes(StandardCharsets.UTF_8).length;
        return Math.max(raw,nfc);
    }
    /** This bound applies only to the reviewed NFC/byte-level BPE tokenizer. */
    public static void verifyTokenizer(File tokenizer)throws Exception{
        if(!tokenizer.isFile()||tokenizer.length()>16L*1024*1024)throw new IllegalArgumentException("selected tokenizer missing");
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try(FileInputStream input=new FileInputStream(tokenizer)){byte[] buffer=new byte[65536];int length;while((length=input.read(buffer))!=-1)digest.update(buffer,0,length);}
        StringBuilder actual=new StringBuilder();for(byte b:digest.digest())actual.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
        if(!TOKENIZER_SHA256.equals(actual.toString()))throw new IllegalArgumentException("selected tokenizer hash differs; token bound cannot be used");
    }
}
