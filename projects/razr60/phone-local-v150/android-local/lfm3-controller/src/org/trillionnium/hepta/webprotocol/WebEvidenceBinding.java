package org.trillionnium.hepta.webprotocol;

import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;

/** Shared immutable binding and exact canonical UTF-8 hash; no device effects. */
public final class WebEvidenceBinding {
    private WebEvidenceBinding() { }
    public static final String SCHEMA=WebEvidenceProtocol.BINDING_SCHEMA;
    private static final String[] FIELDS={"task_id","controller_session_nonce","owner","owner_sha256",
            "contract_sha256","authorization","background","controller_identity","helper_identity"};
    public static JSONObject fromAttach(JSONObject attach) throws Exception {
        WebTaskPurpose purpose=WebTaskPurpose.fromAttach(attach);
        JSONObject out=new JSONObject().put("schema",SCHEMA).put("initial_url",purpose.initialUrl)
                .put("goal_kind",purpose.kind).put("site_policy_id",purpose.sitePolicyId)
                .put("site_policy_sha256",purpose.sitePolicySha256);
        for(String key:FIELDS)out.put(key,attach.get(key));
        Object nonce=attach.get("controller_session_nonce");
        if(!(nonce instanceof String))throw new IllegalArgumentException("controller session nonce must be a string");
        out.put("storage_profile_name",WebStorageEvidence.profileFor((String)nonce));
        // The parse is a defensive deep copy. Per-request nonce/deadline are
        // deliberately not part of the stable lease identity.
        JSONObject copied=new JSONObject(canonical(out));WebTaskPurpose.requireBinding(copied);return copied;
    }
    public static String sha256(JSONObject binding) throws Exception {
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(canonical(binding).getBytes(StandardCharsets.UTF_8));
        char[] hex="0123456789abcdef".toCharArray();StringBuilder out=new StringBuilder(64);
        for(byte b:digest)out.append(hex[(b>>>4)&15]).append(hex[b&15]);return out.toString();
    }
    /** Keys sorted by Java UTF-16 String.compareTo, arrays retain exact order. */
    public static String canonical(Object value) throws Exception {
        if(value==null||value==JSONObject.NULL)return "null";
        if(value instanceof String){
            String s=(String)value;StringBuilder out=new StringBuilder("\"");
            for(int i=0;i<s.length();i++){
                char c=s.charAt(i);
                if(Character.isHighSurrogate(c)){
                    if(i+1>=s.length()||!Character.isLowSurrogate(s.charAt(i+1)))throw new IllegalArgumentException("invalid Unicode");
                    out.append(c).append(s.charAt(++i));continue;
                }
                if(Character.isLowSurrogate(c))throw new IllegalArgumentException("invalid Unicode");
                if(c=='\"'||c=='\\')out.append('\\').append(c);
                else if(c<0x20){String h=Integer.toHexString(c);out.append("\\u");for(int n=h.length();n<4;n++)out.append('0');out.append(h);}
                else out.append(c);
            }
            return out.append('\"').toString();
        }
        if(value instanceof Boolean)return value.toString();
        if(value instanceof Integer||value instanceof Long)return value.toString();
        if(value instanceof JSONArray){JSONArray a=(JSONArray)value;StringBuilder out=new StringBuilder("[");
            for(int i=0;i<a.length();i++){if(i>0)out.append(',');out.append(canonical(a.get(i)));}return out.append(']').toString();}
        if(value instanceof JSONObject){JSONObject o=(JSONObject)value;ArrayList<String> keys=new ArrayList<String>();
            Iterator<String> it=o.keys();while(it.hasNext())keys.add(it.next());Collections.sort(keys);StringBuilder out=new StringBuilder("{");
            for(int i=0;i<keys.size();i++){if(i>0)out.append(',');String k=keys.get(i);out.append(canonical(k)).append(':').append(canonical(o.get(k)));}return out.append('}').toString();}
        throw new IllegalArgumentException("noncanonical binding type");
    }
}
