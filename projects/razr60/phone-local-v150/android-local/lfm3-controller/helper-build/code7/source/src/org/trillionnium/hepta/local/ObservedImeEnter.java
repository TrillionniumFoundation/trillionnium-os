package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

/** Facts from one complete action list. Editability never invents an IME action. */
public final class ObservedImeEnter {
    public static final String SCHEMA="hepta.observed-ime-enter.v1";
    public static final ObservedImeEnter UNKNOWN=new ObservedImeEnter(false,false,null);
    public static final ObservedImeEnter ABSENT=new ObservedImeEnter(true,false,null);
    private static final Set<String> QUERY_LABELS=Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
            "搜索","搜尋","查询","查詢","查找","search","query","find")));
    public final boolean observed,present;
    public final String label,labelSha256;
    private ObservedImeEnter(boolean observed,boolean present,String label){
        this.observed=observed;this.present=present;this.label=label;
        this.labelSha256=label==null?null:hash(label);
    }
    public static ObservedImeEnter present(String label){
        if(label!=null){
            if(label.length()>256)return UNKNOWN;
            for(int i=0;i<label.length();i++){
                char c=label.charAt(i);
                if(c==0)return UNKNOWN;
                if(Character.isHighSurrogate(c)){
                    if(++i>=label.length()||!Character.isLowSurrogate(label.charAt(i)))return UNKNOWN;
                }else if(Character.isLowSurrogate(c))return UNKNOWN;
            }
        }
        return new ObservedImeEnter(true,true,label);
    }
    /** Generic Enter/Go/Done is not proof of query semantics or payment authority. */
    public boolean queryAllowed(){
        return observed&&present&&label!=null&&QUERY_LABELS.contains(
                Normalizer.normalize(label,Normalizer.Form.NFKC).trim().toLowerCase(Locale.ROOT));
    }
    public String reasonCode(){
        return !observed?"ime_action_not_observed":!present?"ime_action_unavailable":
                queryAllowed()?"observed_query_action":"ime_action_semantics_unverified";
    }
    public Map<String,Object> evidence(){
        Map<String,Object> value=new LinkedHashMap<String,Object>();
        value.put("schema",SCHEMA);value.put("observed",observed);value.put("present",present);
        value.put("action_label",label);value.put("action_label_sha256",labelSha256);
        value.put("query_allowed",queryAllowed());value.put("reason_code",reasonCode());return value;
    }
    public Map<String,Object> projection(String textSha256){
        if(!queryAllowed()||!isSha(textSha256))throw new IllegalArgumentException("query capability and full input hash required");
        Map<String,Object> value=new LinkedHashMap<String,Object>();value.put("schema",SCHEMA);
        value.put("action_name","ACTION_IME_ENTER");value.put("action_label",label);
        value.put("action_label_sha256",labelSha256);value.put("input_text_sha256",textSha256);return value;
    }
    public String fingerprintInput(){return SCHEMA+"|"+observed+"|"+present+"|"+(labelSha256==null?"null":labelSha256);}
    public String bindFreshness(String original,boolean focused,String textSha256){
        if(original==null)throw new IllegalArgumentException("node identity required");
        return original+"\nime_enter="+fingerprintInput()+"|focused="+focused+"|full_input="+textSha256;
    }
    public static boolean isSha(String value){return value!=null&&value.matches("[0-9a-f]{64}");}
    /** Unknown or ill-formed UTF-16 cannot acquire a full-input identity through replacement encoding. */
    public static String completeTextHash(String value){
        if(value==null)return null;
        for(int i=0;i<value.length();i++){
            char c=value.charAt(i);
            if(Character.isHighSurrogate(c)){
                if(++i>=value.length()||!Character.isLowSurrogate(value.charAt(i)))return null;
            }else if(Character.isLowSurrogate(c))return null;
        }
        return hash(value);
    }
    public static String hash(String value){
        if(value==null)throw new IllegalArgumentException("hash input required");
        try{StringBuilder out=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)))
            out.append(String.format(Locale.ROOT,"%02x",b&255));return out.toString();}
        catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
}
