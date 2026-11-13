package org.trillionnium.hepta.webprotocol;

import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/** Exact capture handoff between two authenticated app-private stores.
 * A proof is an acknowledgement by the compiled controller, not a filesystem
 * capability. The helper must still read and verify its unique original file.
 * This class never deletes files, changes a page, or grants ARM/tool authority. */
public final class WebCaptureAcknowledgement {
    private WebCaptureAcknowledgement(){}
    public static final String SCHEMA="hepta.web-controller-capture-transfer.v1";
    public static final String STATUS="capture_acknowledged";
    private static final Set<String> PROOF_KEYS=keys("schema","task_id","controller_session_nonce","binding_sha256",
            "capture_request_nonce","capture_request_sha256","raw_file","raw_bytes","raw_sha256",
            "request_record_sha256","reply_record_sha256","callback_sha256","durable_copy_readback_verified",
            "business_verified","grants_page_authority");

    public static JSONObject proof(JSONObject binding,String captureNonce,String requestRaw,String callbackRaw,
            byte[] raw,byte[] requestRecord,byte[] replyRecord)throws Exception{
        need(raw!=null&&requestRecord!=null&&replyRecord!=null,"complete durable original records required");
        JSONObject out=new JSONObject().put("schema",SCHEMA).put("task_id",text(binding,"task_id"))
                .put("controller_session_nonce",text(binding,"controller_session_nonce"))
                .put("binding_sha256",WebEvidenceBinding.sha256(binding)).put("capture_request_nonce",captureNonce)
                .put("capture_request_sha256",sha(requestRaw.getBytes(StandardCharsets.UTF_8)))
                .put("raw_file","raw-"+captureNonce+".json").put("raw_bytes",raw.length).put("raw_sha256",sha(raw))
                .put("request_record_sha256",sha(requestRecord)).put("reply_record_sha256",sha(replyRecord))
                .put("callback_sha256",sha(callbackRaw.getBytes(StandardCharsets.UTF_8)))
                .put("durable_copy_readback_verified",true).put("business_verified",false).put("grants_page_authority",false);
        requireProof(out,binding,captureNonce);return out;
    }
    public static JSONObject requireRequest(JSONObject request,JSONObject binding)throws Exception{
        exact(request,WebEvidenceProtocol.requestKeys(WebEvidenceProtocol.ACK_CAPTURE));
        need(WebEvidenceProtocol.requestSchema(WebEvidenceProtocol.ACK_CAPTURE).equals(text(request,"schema")),
                "capture acknowledgement schema differs");
        need(WebEvidenceProtocol.hex64(text(request,"request_nonce"))
                &&text(binding,"task_id").equals(text(request,"task_id"))
                &&text(binding,"controller_session_nonce").equals(text(request,"controller_session_nonce")),
                "capture acknowledgement belongs to another task/session");
        String nonce=text(request,"capture_request_nonce");
        need(!nonce.equals(text(request,"request_nonce")),"acknowledgement must have a fresh nonce");
        JSONObject proof=request.getJSONObject("durable_acknowledgement");requireProof(proof,binding,nonce);
        need(WebEvidenceProtocol.hex64(text(request,"durable_acknowledgement_sha256"))
                &&WebDomCanonical.sha256(proof).equals(text(request,"durable_acknowledgement_sha256")),
                "durable acknowledgement content hash differs");
        return proof;
    }
    public static void requireProof(JSONObject proof,JSONObject binding,String captureNonce)throws Exception{
        exact(proof,PROOF_KEYS);
        need(SCHEMA.equals(text(proof,"schema"))&&WebEvidenceProtocol.hex64(captureNonce)
                &&captureNonce.equals(text(proof,"capture_request_nonce"))
                &&WebEvidenceProtocol.hex32(text(binding,"task_id"))
                &&WebEvidenceProtocol.hex64(text(binding,"controller_session_nonce"))
                &&text(binding,"task_id").equals(text(proof,"task_id"))
                &&text(binding,"controller_session_nonce").equals(text(proof,"controller_session_nonce"))
                &&WebEvidenceBinding.sha256(binding).equals(text(proof,"binding_sha256")),
                "durable capture tuple differs");
        need(("raw-"+captureNonce+".json").equals(text(proof,"raw_file")),"durable raw leaf differs");
        long bytes=number(proof,"raw_bytes");need(bytes>0&&bytes<=WebEvidenceProtocol.MAX_EVIDENCE_BYTES,"durable capture length invalid");
        for(String key:Arrays.asList("capture_request_sha256","raw_sha256","request_record_sha256","reply_record_sha256","callback_sha256"))
            need(WebEvidenceProtocol.hex64(text(proof,key)),"durable capture hash invalid: "+key);
        need(Boolean.TRUE.equals(proof.get("durable_copy_readback_verified"))
                &&Boolean.FALSE.equals(proof.get("business_verified"))
                &&Boolean.FALSE.equals(proof.get("grants_page_authority")),"capture acknowledgement cannot grant page/business authority");
    }
    /** record and originalRequest must have been strictly parsed by the
     * app's existing bounded, duplicate-key rejecting JSON reader. */
    public static void requireOriginal(JSONObject request,JSONObject binding,byte[] bytes,
            JSONObject record,JSONObject originalRequest)throws Exception{
        JSONObject proof=requireRequest(request,binding);
        need(bytes!=null&&bytes.length==number(proof,"raw_bytes")&&sha(bytes).equals(text(proof,"raw_sha256")),
                "helper original capture length/hash differs");
        need(WebEvidenceProtocol.RAW_SCHEMA.equals(text(record,"schema"))
                &&"controller_evidence_capture".equals(text(record,"actor"))
                &&Boolean.FALSE.equals(record.get("diagnostic_unbound"))
                &&Boolean.FALSE.equals(record.get("business_verified")),"only formal capture records may transfer");
        String original=text(record,"request_json_utf8"),requestSha=sha(original.getBytes(StandardCharsets.UTF_8));
        need(requestSha.equals(text(record,"request_sha256"))&&requestSha.equals(text(proof,"capture_request_sha256")),
                "original capture request bytes/hash differ");
        exact(originalRequest,WebEvidenceProtocol.requestKeys(WebEvidenceProtocol.CAPTURE));
        need(WebEvidenceProtocol.requestSchema(WebEvidenceProtocol.CAPTURE).equals(text(originalRequest,"schema"))
                &&text(request,"capture_request_nonce").equals(text(originalRequest,"request_nonce"))
                &&text(request,"task_id").equals(text(originalRequest,"task_id"))
                &&text(request,"controller_session_nonce").equals(text(originalRequest,"controller_session_nonce")),
                "original capture request belongs to another nonce/task/session");
        need(WebEvidenceBinding.sha256(binding).equals(text(record,"binding_sha256"))
                &&WebDomCanonical.canonical(binding).equals(WebDomCanonical.canonical(record.getJSONObject("binding")))
                &&WebDomCanonical.canonical(binding.getJSONObject("controller_identity")).equals(WebDomCanonical.canonical(record.getJSONObject("controller_identity")))
                &&WebDomCanonical.canonical(binding.getJSONObject("helper_identity")).equals(WebDomCanonical.canonical(record.getJSONObject("helper_identity"))),
                "original capture binding or installed identities differ");
        need(record.get("capture") instanceof JSONObject,"complete original capture object absent");
    }
    public static String reason(JSONObject request)throws Exception{
        return "capture_transferred:"+text(request,"durable_acknowledgement_sha256");
    }
    private static String text(JSONObject object,String key)throws Exception{
        Object value=object.get(key);need(value instanceof String,"string required: "+key);return (String)value;
    }
    private static long number(JSONObject object,String key)throws Exception{
        Object value=object.get(key);need(value instanceof Integer||value instanceof Long,"integer required: "+key);return ((Number)value).longValue();
    }
    private static void exact(JSONObject object,Set<String> expected)throws Exception{
        TreeSet<String> actual=new TreeSet<String>();java.util.Iterator<String> it=object.keys();while(it.hasNext())actual.add(it.next());
        need(actual.equals(expected),"exact capture acknowledgement keys required");
    }
    public static String sha(byte[] bytes)throws Exception{
        byte[] hash=MessageDigest.getInstance("SHA-256").digest(bytes);StringBuilder out=new StringBuilder(64);
        for(byte b:hash)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();
    }
    private static Set<String> keys(String... values){return Collections.unmodifiableSet(new TreeSet<String>(Arrays.asList(values)));}
    private static void need(boolean condition,String reason){if(!condition)throw new IllegalArgumentException(reason);}
}
