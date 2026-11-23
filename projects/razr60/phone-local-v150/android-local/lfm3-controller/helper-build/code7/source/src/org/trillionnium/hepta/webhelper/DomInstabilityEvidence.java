package org.trillionnium.hepta.webhelper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.json.JSONArray;
import org.json.JSONObject;

/** Raw first mismatch pair, for manual diagnostics only; never a Binder/FD success. */
final class DomInstabilityEvidence {
    static final int MAX_DOM_BYTES=1024*1024,MAX_RECORD_BYTES=2*1024*1024,MAX_CONTEXT_BYTES=65536;
    private DomInstabilityEvidence(){}
    static final class Pair {
        final String before,after,contextRaw;
        Pair(JSONObject context,String before,String after)throws Exception{
            need(context!=null&&before!=null&&after!=null&&!before.equals(after),"different raw DOM pair required");
            need(bytes(before)<=MAX_DOM_BYTES&&bytes(after)<=MAX_DOM_BYTES,"raw mismatch DOM byte bound");
            JSONObject binding=context.getJSONObject("binding");
            need("hepta.web-helper.unbound-diagnostic.v2".equals(binding.getString("schema"))
                    &&binding.has("task_id")&&binding.isNull("task_id")&&integer(binding,"display_id")==0
                    &&"manual_native_open".equals(binding.getString("actor"))&&Boolean.FALSE.equals(binding.get("grants_task_authority")),
                    "manual unbound diagnostic required");
            need(integer(context,"display_id")==0&&integer(context,"attempt_index")>=1
                    &&integer(context,"attempt_index")<=CaptureReadBudget.MAX_ATTEMPTS,"manual attempt context");
            long started=integer(context,"started_elapsed_ms"),ended=integer(context,"mismatch_elapsed_ms"),deadline=integer(context,"deadline_elapsed_ms");
            need(started>=0&&ended>=started&&ended<deadline&&deadline-started<=CaptureReadBudget.MAX_CAPTURE_MS,
                    "original bounded mismatch time");
            String current=context.getString("current_native_url");
            JSONObject a=new JSONObject(before),b=new JSONObject(after);
            for(JSONObject dom:new JSONObject[]{a,b})need("hepta.fixed-top-document-dom.v4".equals(dom.getString("schema"))
                    &&current.equals(dom.getString("href"))&&"complete".equals(dom.getString("ready_state")),"raw current DOM context");
            need(context.getJSONArray("geometry_samples").length()==4,"complete failed read bracket");
            this.contextRaw=context.toString();
            need(bytes(contextRaw)<=MAX_CONTEXT_BYTES,"mismatch context byte bound");
            this.before=before;this.after=after;
        }
        JSONObject[] records(String pairId,String cause,String storageRaw)throws Exception{
            need(pairId!=null&&pairId.matches("[0-9a-f]{64}")&&cause!=null&&cause.length()<=256,
                    "diagnostic pair identity/cause");
            need(storageRaw!=null&&bytes(storageRaw)<=MAX_CONTEXT_BYTES,"storage diagnostic byte bound");
            JSONObject storage=new JSONObject(storageRaw);
            String a=sha(before),b=sha(after);
            JSONObject[] records=new JSONObject[2];
            for(int i=0;i<2;i++){
                JSONObject out=new JSONObject().put("schema","hepta.web-helper.manual-dom-instability.v2")
                        .put("actor","manual_foreground_diagnostic").put("cause",cause)
                        .put("dom_schema","hepta.fixed-top-document-dom.v4")
                        .put("pair_id",pairId).put("phase",i==0?"before_visual_callback":"after_visual_callback")
                        .put("pair_member_count",2).put("first_mismatch_only",true)
                        .put("dom_raw_utf8",i==0?before:after).put("dom_sha256",i==0?a:b)
                        .put("before_dom_sha256",a).put("after_dom_sha256",b)
                        .put("capture_attempt_context",new JSONObject(contextRaw)).put("storage_isolation",storage)
                        .put("task_id",JSONObject.NULL).put("diagnostic_unbound",true)
                        .put("capture_succeeded",false).put("dom_equal_across_visual_callback",false)
                        .put("grants_task_authority",false).put("grants_action_authority",false)
                        .put("formal_fd_evidence",false).put("business_verified",false)
                        .put("pixel_equality_claimed",false).put("all_visible_semantics_verified",false);
                need(bytes(out.toString())<=MAX_RECORD_BYTES,"diagnostic record byte bound");records[i]=out;
            }
            return records;
        }
    }
    private static long integer(JSONObject value,String key)throws Exception{
        Object actual=value.get(key);need(actual instanceof Integer||actual instanceof Long,"integer context required");
        return ((Number)actual).longValue();
    }
    private static int bytes(String raw){return raw.getBytes(StandardCharsets.UTF_8).length;}
    private static String sha(String raw)throws Exception{
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8));
        StringBuilder out=new StringBuilder(64);
        for(byte b:digest)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
        return out.toString();
    }
    private static void need(boolean value,String reason){if(!value)throw new IllegalArgumentException(reason);}
}
