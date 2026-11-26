"""Exact proof-copy inverse for the optional public cleanup diagnostic consumer.
Actual compiler inputs remain the current complete production BackgroundSession.
"""
import hashlib

BEFORE_BYTES=156312
BEFORE_SHA256="8109ceb4acc2d2c8577bc5fc5e8d37ce259117100e42b846a601a371f1641eb1"
AFTER_BYTES=158831
AFTER_SHA256="fcb2494d0638e5600a2b84b63ce6e09d9c2180aebc58e61f17949408c73e25d6"
ADDED_MEMBER='    /** Optional producer diagnostics only. The original cleanup, scope, task and\n     * history fields below remain the authority for consuming a terminal reply. */\n    private static JSONObject profileCleanupFieldView(JSONObject proof,boolean publicCleanup)throws Exception{\n        if(!proof.has("normal_cleanup_phase"))return proof;\n        if(!publicCleanup)throw new IOException("profile normal cleanup diagnostic outside public scope");\n        JSONObject phase=proof.getJSONObject("normal_cleanup_phase");\n        requireProfileFields(phase,"schema","original_task_reads_deadline_elapsed_ms",\n                "bounded_convergence_deadline_elapsed_ms","maximum_census_to_effect_age_ms",\n                "read_convergence_activated","failed","last_sample_started_elapsed_ms",\n                "leaf_effect_entered_elapsed_ms","leaf_effect_returned_elapsed_ms",\n                "root_effect_entered_elapsed_ms","root_effect_returned_elapsed_ms",\n                "display_effect_entered_elapsed_ms","display_effect_returned_elapsed_ms",\n                "business_admission_restored","serialized_evidence_is_authority");\n        if(!"hepta.profile-normal-cleanup-phase.v1".equals(phase.getString("schema"))\n                ||strictLong(phase,"maximum_census_to_effect_age_ms")!=1500\n                ||!(phase.get("read_convergence_activated") instanceof Boolean)\n                ||!(phase.get("failed") instanceof Boolean)\n                ||!Boolean.FALSE.equals(phase.get("business_admission_restored"))\n                ||!Boolean.FALSE.equals(phase.get("serialized_evidence_is_authority")))\n            throw new IOException("profile normal cleanup diagnostic differs");\n        for(String key:new String[]{"original_task_reads_deadline_elapsed_ms","bounded_convergence_deadline_elapsed_ms"})\n            if(strictLong(phase,key)<=0)throw new IOException("profile normal cleanup diagnostic deadline differs");\n        for(String key:new String[]{"last_sample_started_elapsed_ms","leaf_effect_entered_elapsed_ms","leaf_effect_returned_elapsed_ms",\n                "root_effect_entered_elapsed_ms","root_effect_returned_elapsed_ms","display_effect_entered_elapsed_ms","display_effect_returned_elapsed_ms"})\n            if(strictLong(phase,key)<-1)throw new IOException("profile normal cleanup diagnostic clock differs");\n        JSONObject fields=new JSONObject(proof.toString());fields.remove("normal_cleanup_phase");return fields;\n    }\n'
OLD_FIELDS='        JSONObject proof=response.getJSONObject("profile_cleanup");\n        if(publicScope==null)requireProfileFields(proof,"schema","generation","display_id","target_sha256","user_id","user_serial","full_uid",\n                "cleanup_known","live_tasks_absent","recents_tasks_absent","foreign_tasks_present","identity_unknown","owned_tasks");\n        else requireProfileFields(proof,"schema","generation","display_id","target_sha256","user_id","user_serial","full_uid",\n                "cleanup_known","live_tasks_absent","recents_tasks_absent","foreign_tasks_present","identity_unknown","owned_tasks",\n                "public_foreign_recent_history","recents_absence_scope");\n'
NEW_FIELDS='        JSONObject proof=response.getJSONObject("profile_cleanup");\n        JSONObject fields=profileCleanupFieldView(proof,publicScope!=null);\n        if(publicScope==null)requireProfileFields(fields,"schema","generation","display_id","target_sha256","user_id","user_serial","full_uid",\n                "cleanup_known","live_tasks_absent","recents_tasks_absent","foreign_tasks_present","identity_unknown","owned_tasks");\n        else requireProfileFields(fields,"schema","generation","display_id","target_sha256","user_id","user_serial","full_uid",\n                "cleanup_known","live_tasks_absent","recents_tasks_absent","foreign_tasks_present","identity_unknown","owned_tasks",\n                "public_foreign_recent_history","recents_absence_scope");\n'

def session_predecessor(raw):
    if type(raw) is not bytes:
        raise ValueError("exact complete BackgroundSession bytes required")
    digest=hashlib.sha256(raw).hexdigest()
    if len(raw)==BEFORE_BYTES and digest==BEFORE_SHA256:
        return raw
    if len(raw)!=AFTER_BYTES or digest!=AFTER_SHA256:
        raise ValueError("unreviewed BackgroundSession cleanup diagnostic source")
    text=raw.decode("utf-8")
    if text.count(ADDED_MEMBER)!=1 or text.count(NEW_FIELDS)!=1:
        raise ValueError("unique complete cleanup diagnostic inverse required")
    restored=text.replace(ADDED_MEMBER,"",1).replace(NEW_FIELDS,OLD_FIELDS,1).encode("utf-8")
    if len(restored)!=BEFORE_BYTES or hashlib.sha256(restored).hexdigest()!=BEFORE_SHA256:
        raise ValueError("complete original BackgroundSession inverse differs")
    return restored
