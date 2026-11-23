package org.trillionnium.hepta.background;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

/** Independent absence proof for an expired, retired, launched profile lease. No cleanup effects or broker-release claim. */
public final class ProfilePostlaunchRecovery {
    public static final String REQUEST_SCHEMA="hepta.profile-postlaunch-recovery-request.v1";
    public static final String SCHEMA="hepta.profile-postlaunch-recovery.v1";
    public static final String SOURCE="fresh_privileged_postlaunch_absence";
    public static final long LIMIT_MS=12000, TTL_MS=540000, EXPIRY_GRACE_MS=2000;
    public static final int MAX_JOURNAL=16384, MAX_OUTPUT=65536;
    private ProfilePostlaunchRecovery(){}

    public static final class Request {
        public final int ownerUid,oldBoot,requestBoot,displayId;
        public final long created,expires,started,deadline;
        public final String requestId,taskId,generation,ownerSha256,journalSha256,displayName;
        public final ProfileTarget target;
        private final byte[] journal;
        private Request(byte[] bytes,int owner,String id,long begun,int boot)throws Exception{
            need(bytes!=null&&bytes.length>0&&bytes.length<=MAX_JOURNAL,"RECOVERY_JOURNAL_BOUND");
            need(owner>=10000&&owner<90000&&ProfileIdentity.uuid(id)&&begun>=0&&boot>=0,
                    "RECOVERY_REQUEST_IDENTITY");
            JSONObject old=object(bytes);
            need("hepta.background-session.v1".equals(string(old,"schema"))&&number(old,"app_uid")==owner,
                    "RECOVERY_JOURNAL_OWNER");
            // These fields really are durable. bootstrap_dispatched is not required or defaulted.
            long recordedDisplay=number(old,"display_id");
            need(Boolean.TRUE.equals(old.get("profile_launch_attempted"))&&recordedDisplay>0
                    &&recordedDisplay<=Integer.MAX_VALUE,"RECOVERY_NOT_POSTLAUNCH");
            displayId=(int)recordedDisplay;
            need(Boolean.TRUE.equals(old.get("profile_isolation_required"))
                    &&Boolean.TRUE.equals(old.get("owned_task_retirement_required")),"RECOVERY_NOT_PROFILE");
            String state=string(old,"state");
            need("CLEANUP_UNKNOWN".equals(state),"RECOVERY_JOURNAL_STATE");
            if(old.has("bootstrap_dispatched"))need(old.get("bootstrap_dispatched") instanceof Boolean,
                    "RECOVERY_BOOTSTRAP_FLAG_TYPE");
            taskId=string(old,"task_id");generation=string(old,"generation");
            ownerSha256=string(old,"owner_sha256");displayName=string(old,"display_name");
            need(taskId.matches("[0-9a-f]{32}")&&ProfileIdentity.uuid(generation)
                    &&ProfileIdentity.hash(ownerSha256)&&("hepta-bg-"+generation).equals(displayName)
                    &&displayName.equals(string(old,"socket")),"RECOVERY_JOURNAL_BINDING");
            target=ProfileTarget.fromWire(string(old,"profile_target_wire"));
            need(target.sha256.equals(string(old,"profile_target_sha256")),"RECOVERY_TARGET_DIGEST");
            JSONObject selection=old.getJSONObject("selection");
            need(target.wire().equals(string(selection,"profile_target_wire"))
                    &&target.sha256.equals(string(selection,"profile_target_sha256")),"RECOVERY_SELECTION_BINDING");
            created=number(old,"created_elapsed_ms");expires=number(old,"expires_elapsed_ms");
            long recordedBoot=number(old,"boot_count");
            need(created>=0&&expires>created&&expires-created==TTL_MS&&expires<=Long.MAX_VALUE-EXPIRY_GRACE_MS
                    &&recordedBoot>=0&&recordedBoot<=Integer.MAX_VALUE,"RECOVERY_LEASE_CLOCK");
            oldBoot=(int)recordedBoot;ownerUid=owner;requestId=id;started=begun;requestBoot=boot;
            need(begun<=Long.MAX_VALUE-LIMIT_MS,"RECOVERY_CLOCK_OVERFLOW");deadline=begun+LIMIT_MS;
            requireFence(begun,boot);
            journal=bytes.clone();journalSha256=ProfileIdentity.sha(journal);
        }
        public void requireFence(long now,int actualBoot)throws IOException{
            need(actualBoot==requestBoot&&now>=started&&now<deadline,"RECOVERY_REQUEST_EXPIRED_OR_BOOT_CHANGED");
            need(actualBoot!=oldBoot||now>expires+EXPIRY_GRACE_MS,"RECOVERY_LEASE_NOT_EXPIRED");
        }
        public byte[] journalBytes(){return journal.clone();}
        public String wire()throws Exception{
            JSONObject out=new JSONObject().put("schema",REQUEST_SCHEMA).put("owner_uid",ownerUid)
                    .put("request_id",requestId).put("started_elapsed_ms",started).put("boot_count",requestBoot)
                    .put("journal_base64",Base64.getEncoder().encodeToString(journal));
            return Base64.getEncoder().encodeToString(out.toString().getBytes(StandardCharsets.UTF_8));
        }
    }
    public static Request request(byte[] journal,int owner,String id,long now,int boot)throws Exception{
        return new Request(journal,owner,id,now,boot);
    }
    public static Request fromWire(String wire)throws Exception{
        need(wire!=null&&wire.length()>0&&wire.length()<=40000,"RECOVERY_WIRE_BOUND");
        byte[] bytes=Base64.getDecoder().decode(wire);
        need(Base64.getEncoder().encodeToString(bytes).equals(wire),"RECOVERY_WIRE_NONCANONICAL");
        JSONObject in=object(bytes);
        keys(in,"schema","owner_uid","request_id","started_elapsed_ms","boot_count","journal_base64");
        need(REQUEST_SCHEMA.equals(string(in,"schema")),"RECOVERY_REQUEST_SCHEMA");
        String encoded=string(in,"journal_base64");byte[] journal=Base64.getDecoder().decode(encoded);
        need(Base64.getEncoder().encodeToString(journal).equals(encoded),"RECOVERY_JOURNAL_NONCANONICAL");
        long owner=number(in,"owner_uid"),boot=number(in,"boot_count");
        need(owner>=10000&&owner<90000&&boot>=0&&boot<=Integer.MAX_VALUE,"RECOVERY_REQUEST_NUMERIC_IDENTITY");
        return new Request(journal,(int)owner,string(in,"request_id"),number(in,"started_elapsed_ms"),(int)boot);
    }
    /** Validates data only. The app additionally requires its actual owned Process receipt. */
    public static JSONObject validate(JSONObject value,Request request,long now,int boot)throws Exception{
        need(request!=null,"RECOVERY_REQUEST_MISSING");request.requireFence(now,boot);
        keys(value,"schema","source","request_id","owner_uid","task_id","generation","owner_sha256",
                "journal_sha256","profile_target_wire","target_sha256","display_id","display_name",
                "old_boot_count","current_boot_count","lease_expires_elapsed_ms","request_started_elapsed_ms",
                "started_elapsed_ms","finished_elapsed_ms","deadline_elapsed_ms","boot_changed","no_late_create",
                "profile_launch_attempted","identity_rechecked","live","recents","displays",
                "process_before","process_after","cleanup_known","automatic_resume");
        need(SCHEMA.equals(string(value,"schema"))&&SOURCE.equals(string(value,"source"))
                &&request.requestId.equals(string(value,"request_id"))&&number(value,"owner_uid")==request.ownerUid
                &&request.taskId.equals(string(value,"task_id"))&&request.generation.equals(string(value,"generation"))
                &&request.ownerSha256.equals(string(value,"owner_sha256"))
                &&request.journalSha256.equals(string(value,"journal_sha256"))
                &&request.target.wire().equals(string(value,"profile_target_wire"))
                &&request.target.sha256.equals(string(value,"target_sha256")),"RECOVERY_PROOF_BINDING");
        need(number(value,"display_id")==request.displayId&&request.displayName.equals(string(value,"display_name"))
                &&number(value,"old_boot_count")==request.oldBoot&&number(value,"current_boot_count")==boot
                &&number(value,"lease_expires_elapsed_ms")==request.expires
                &&number(value,"request_started_elapsed_ms")==request.started
                &&number(value,"deadline_elapsed_ms")==request.deadline,"RECOVERY_PROOF_LEASE");
        long begin=number(value,"started_elapsed_ms"),end=number(value,"finished_elapsed_ms");
        need(begin>=request.started&&end>=begin&&end<=now&&end<request.deadline,"RECOVERY_PROOF_TIME");
        need(Boolean.valueOf(boot!=request.oldBoot).equals(value.get("boot_changed"))
                &&Boolean.TRUE.equals(value.get("no_late_create"))
                &&Boolean.TRUE.equals(value.get("profile_launch_attempted"))
                &&Boolean.TRUE.equals(value.get("identity_rechecked"))
                &&Boolean.TRUE.equals(value.get("cleanup_known"))
                &&Boolean.FALSE.equals(value.get("automatic_resume")),"RECOVERY_PROOF_FLAGS");
        JSONObject live=value.getJSONObject("live"),recents=value.getJSONObject("recents"),displays=value.getJSONObject("displays");
        keys(live,"complete","root_count","leaf_count","snapshot_sha256","target_user_id","target_task_ids","recorded_display_empty");
        keys(recents,"complete","count","bytes","snapshot_sha256","target_user_id","target_task_ids");
        keys(displays,"complete","count","snapshot_sha256","exact_name_absent","recorded_id_absent");
        need(Boolean.TRUE.equals(live.get("complete"))&&number(live,"root_count")>0
                &&number(live,"root_count")<=ProfileTaskPolicy.MAX_ROOTS&&number(live,"leaf_count")>=0
                &&number(live,"leaf_count")<=ProfileTaskPolicy.MAX_LEAVES
                &&ProfileIdentity.hash(string(live,"snapshot_sha256"))
                &&number(live,"target_user_id")==request.target.profile.userId
                &&live.getJSONArray("target_task_ids").length()==0
                &&Boolean.TRUE.equals(live.get("recorded_display_empty")),"RECOVERY_LIVE_ABSENCE_INCOMPLETE");
        need(Boolean.TRUE.equals(recents.get("complete"))&&number(recents,"count")>=0
                &&number(recents,"count")<=ProfileTaskPolicy.MAX_LEAVES&&number(recents,"bytes")>0
                &&number(recents,"bytes")<=1048576&&ProfileIdentity.hash(string(recents,"snapshot_sha256"))
                &&number(recents,"target_user_id")==request.target.profile.userId
                &&recents.getJSONArray("target_task_ids").length()==0,"RECOVERY_RECENTS_ABSENCE_INCOMPLETE");
        need(Boolean.TRUE.equals(displays.get("complete"))&&number(displays,"count")>0
                &&number(displays,"count")<=256&&ProfileIdentity.hash(string(displays,"snapshot_sha256"))
                &&Boolean.TRUE.equals(displays.get("exact_name_absent"))
                &&Boolean.TRUE.equals(displays.get("recorded_id_absent")),"RECOVERY_DISPLAY_ABSENCE_INCOMPLETE");
        JSONObject first=value.getJSONObject("process_before"),last=value.getJSONObject("process_after");
        processSample(first,begin,end);processSample(last,begin,end);
        need(number(first,"finished_elapsed_ms")<=number(last,"started_elapsed_ms")
                &&number(first,"self_pid")==number(last,"self_pid")
                &&number(first,"self_start_ticks")==number(last,"self_start_ticks"),"RECOVERY_PROCESS_BRACKET");
        return new JSONObject(value.toString());
    }
    private static void processSample(JSONObject row,long begin,long end)throws Exception{
        keys(row,"complete","old_creator_absent","started_elapsed_ms","finished_elapsed_ms","self_pid",
                "self_start_ticks","process_count","inspected_count","inventory_sha256");
        need(Boolean.TRUE.equals(row.get("complete"))&&Boolean.TRUE.equals(row.get("old_creator_absent"))
                &&number(row,"started_elapsed_ms")>=begin&&number(row,"finished_elapsed_ms")>=number(row,"started_elapsed_ms")
                &&number(row,"finished_elapsed_ms")<=end&&number(row,"self_pid")>0&&number(row,"self_start_ticks")>0
                &&number(row,"process_count")>0&&number(row,"process_count")<=65536
                &&number(row,"inspected_count")>0&&number(row,"inspected_count")<=number(row,"process_count")
                &&ProfileIdentity.hash(string(row,"inventory_sha256")),"RECOVERY_PROCESS_ABSENCE_INCOMPLETE");
    }
    public static JSONObject object(byte[] bytes)throws Exception{
        String raw=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        JSONTokener parser=new JSONTokener(raw);Object value=parser.nextValue();
        need(value instanceof JSONObject&&parser.nextClean()==0,"RECOVERY_JSON_FRAMING");
        return (JSONObject)value;
    }
    public static void keys(JSONObject value,String... names)throws Exception{
        Set<String> actual=new HashSet<String>();java.util.Iterator<String> iterator=value.keys();
        while(iterator.hasNext())actual.add(iterator.next());
        need(actual.equals(new HashSet<String>(Arrays.asList(names))),"RECOVERY_FIELDS_DIFFER");
    }
    public static String string(JSONObject value,String name)throws Exception{
        Object raw=value.get(name);need(raw instanceof String,"RECOVERY_STRING_"+name);return (String)raw;
    }
    public static long number(JSONObject value,String name)throws Exception{
        Object raw=value.get(name);need(raw instanceof Integer||raw instanceof Long,"RECOVERY_INTEGER_"+name);
        return ((Number)raw).longValue();
    }
    public static void need(boolean value,String reason)throws IOException{if(!value)throw new IOException(reason);}
}
