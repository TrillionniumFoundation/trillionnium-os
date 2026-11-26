package org.trillionnium.hepta.background;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.local.SessionRecovery;

/** Complete external failure originals are inputs, never repository fixtures.
 * Current PackageManager/stat/clock and archive-root records are authored host
 * values. This executes the real pure Policy and SessionRecovery decision; it
 * does not execute Android startup IO, root census, CAS, input or acknowledgement. */
public final class PublicProfileBusinessRecoveryHostTest {
    private static final JSONArray CASES=new JSONArray();
    private static int assertions;
    private static Fixture ORIGINAL;
    private static final String HASH=repeat('a'),OTHER=repeat('b');
    interface Work {void run()throws Exception;}
    interface Edit {void run(JSONObject value)throws Exception;}
    private static void check(boolean value){assertions++;if(!value)throw new AssertionError("business recovery host assertion");}
    private static void pass(String name,Work work)throws Exception{work.run();CASES.put(name);}
    private static void reject(String name,String code,Work work)throws Exception {
        try{work.run();}catch(Exception e){
            check(code.isEmpty()?e instanceof org.json.JSONException:e.getMessage()!=null&&e.getMessage().contains(code));CASES.put(name);return;
        }
        throw new AssertionError("accepted "+name);
    }
    private static String repeat(char c){char[] out=new char[64];Arrays.fill(out,c);return new String(out);}
    private static JSONObject object(byte[] bytes)throws Exception{return PublicProfileBusinessAbsenceRecovery.object(bytes);}
    private static JSONObject cloneJson(JSONObject value)throws Exception{return object(value.toString().getBytes(StandardCharsets.UTF_8));}
    private static byte[] bytes(JSONObject value){return value.toString().getBytes(StandardCharsets.UTF_8);}
    private static Map<String,Object> map(JSONObject value){return value.toMap();}

    static final class Fixture {
        final JSONObject manifest;
        final TreeMap<String,byte[]> files=new TreeMap<String,byte[]>();
        final String task,taskPrefix,modelPrefix,resultPath,sessionPath;
        Fixture(JSONObject value,Map<String,byte[]> inputs)throws Exception {
            manifest=cloneJson(value);for(Map.Entry<String,byte[]> e:inputs.entrySet())files.put(e.getKey(),e.getValue().clone());
            task=manifest.getString("task_id");taskPrefix="control-tasks/"+task+"/";resultPath=taskPrefix+"result.json";
            modelPrefix="runs/"+json(resultPath).getJSONObject("model_session").getString("worker_generation")+"/";
            sessionPath=modelPrefix+"app-session-receipt.json";
        }
        Fixture copy()throws Exception{return new Fixture(manifest,files);}
        JSONObject json(String path)throws Exception{return object(files.get(path));}
        void put(String path,byte[] raw)throws Exception {
            files.put(path,raw.clone());JSONObject all=manifest.getJSONObject("files");
            JSONObject d=all.has(path)?cloneJson(all.getJSONObject(path)):cloneJson(all.getJSONObject("control-session.json"));
            d.put("bytes",raw.length).put("sha256",ProfileIdentity.sha(raw));
            if(!all.has(path))d.put("inode",900000+files.size());
            all.put(path,d);
            if(path.startsWith(taskPrefix)){
                JSONArray names=new JSONArray();for(String key:files.keySet())if(key.startsWith(taskPrefix))names.put(key.substring(taskPrefix.length()));
                manifest.put("task_membership",names);
            }
        }
        void edit(String path,Edit edit)throws Exception{JSONObject value=json(path);edit.run(value);put(path,bytes(value));}
        void remove(String path)throws Exception {
            files.remove(path);manifest.getJSONObject("files").remove(path);
            if(path.startsWith(taskPrefix)){
                JSONArray names=new JSONArray();for(String key:files.keySet())if(key.startsWith(taskPrefix))names.put(key.substring(taskPrefix.length()));
                manifest.put("task_membership",names);
            }
        }
        void result(JSONObject value)throws Exception{
            put(resultPath,bytes(value));JSONObject d=manifest.getJSONObject("files").getJSONObject(resultPath);
            JSONObject current=json("control-session.json"),ref=current.getJSONObject("task_result_reference");
            ref.put("bytes",d.getLong("bytes")).put("sha256",d.getString("sha256"));
            put("control-session.json",bytes(current));
        }
        void session(JSONObject value)throws Exception{
            put(sessionPath,bytes(value));JSONObject r=json(resultPath);
            r.getJSONObject("model_session").put("app_receipt_sha256",ProfileIdentity.sha(files.get(sessionPath)));result(r);
        }
        PublicProfileBusinessAbsenceRecovery.Request request()throws Exception {
            return PublicProfileBusinessAbsenceRecovery.request(PublicProfileBusinessAbsenceRecovery.manifest(manifest),files);
        }
        String firstAppRequest() {
            for(String p:files.keySet())if(p.startsWith("runs/")&&p.endsWith("/app-receipt.json"))return p;
            throw new AssertionError("actual request absent");
        }
        Fixture archived()throws Exception {
            Fixture f=copy();byte[] original=f.files.get("control-session.json").clone();JSONObject prior=object(original);
            SessionRecovery.Decision decision=SessionRecovery.evaluate(map(prior),manifest.getInt("owner_uid"),false);
            check(!decision.allowNewTask&&decision.priorRecordValid&&!decision.automaticResume&&"blocked".equals(decision.priorStatus));
            String digest=ProfileIdentity.sha(original),archive="session-recovery/control-session.json."+digest+".json";
            f.put(archive,original);f.manifest.put("origin_summary",archive);
            JSONObject recovery=new JSONObject().put("schema","hepta.session-recovery.v1").put("decision","blocked_interrupted")
                    .put("reason",decision.reason).put("previous_status",decision.priorStatus).put("previous_session_sha256",digest)
                    .put("read_error",JSONObject.NULL).put("interruption_latch","control-session.interrupted.json")
                    .put("interruption_latch_observed",true).put("interruption_latch_synced",true)
                    .put("recovery_pending_barrier_observed",false).put("automatic_resume",false).put("native_cleanup_independently_observed",false)
                    .put("preserved_records",new JSONArray().put(new JSONObject().put("original_name","control-session.json")
                        .put("bytes",original.length).put("sha256",digest).put("path","/data/user/0/"+PublicProfileBusinessAbsenceRecovery.CONTROLLER+"/files/"+archive)));
            JSONObject latch=new JSONObject().put("schema","hepta.session-interruption-latch.v1").put("app_uid",manifest.getInt("owner_uid"))
                    .put("blocked",true).put("cleanup_known",false).put("automatic_resume",false).put("recovery_reason",cloneJson(recovery));
            JSONObject current=cloneJson(prior).put("status","interrupted").put("startup_recovery",recovery);
            f.put("control-session.interrupted.json",bytes(latch));f.put("control-session.json",bytes(current));return f;
        }
        void shiftModelClocks(long delta)throws Exception{
            JSONObject app=json(sessionPath),g=app.getJSONObject("worker_generation_cleanup"),nativeCleanup=g.getJSONObject("native_cleanup");
            for(String key:new String[]{"finisher_submitted_monotonic_ns","finisher_deadline_monotonic_ns"})app.put(key,app.getLong(key)+delta);
            for(String key:new String[]{"finisher_submitted_monotonic_ns","finisher_deadline_monotonic_ns","submitted_monotonic_ns","deadline_monotonic_ns"})g.put(key,g.getLong(key)+delta);
            for(String key:new String[]{"started_monotonic_ns","ended_monotonic_ns","deadline_monotonic_ns"})nativeCleanup.put(key,nativeCleanup.getLong(key)+delta);
            put(modelPrefix+"generation-cleanup-"+g.getString("cleanup_nonce")+".json",bytes(nativeCleanup));
            g.put("native_receipt_sha256",ProfileIdentity.sha(bytes(nativeCleanup)));session(app);
        }
    }

    private static JSONObject syntheticSample(PublicProfileBusinessAbsenceRecovery.Request r,long at)throws Exception{
        JSONObject sample=new JSONObject().put("started_elapsed_ms",at).put("finished_elapsed_ms",at+3).put("target_sha256",r.target.sha256)
            .put("process",new JSONObject().put("complete",true).put("old_creator_absent",true).put("model_worker_absent",true)
                .put("started_elapsed_ms",at+1).put("finished_elapsed_ms",at+2).put("self_pid",43210).put("self_start_ticks",123456)
                .put("process_count",512).put("inspected_count",35).put("inventory_sha256",HASH))
            .put("live",new JSONObject().put("complete",true).put("root_count",2).put("leaf_count",0).put("snapshot_sha256",HASH)
                .put("target_user_id",10).put("target_task_ids",new JSONArray()).put("all_task_ids",new JSONArray().put(1).put(2))
                .put("recorded_owned_ids_absent",true).put("recorded_display_empty",true))
            .put("recents",new JSONObject(PublicProfileRecentHistory.absence(syntheticRecents(),r.target).evidence()))
            .put("displays",new JSONObject().put("complete",true).put("count",2).put("snapshot_sha256",HASH).put("exact_name_absent",true).put("recorded_id_absent",true))
            .put("physical",new JSONObject().put("schema",PublicOwnGroupPhysicalFence.BUSINESS_RECOVERY_SCHEMA).put("0",HASH).put("1",HASH));
        if(r.retainedCurrentAbsenceRequired())sample.put("firmware_fingerprint_sha256",ProfileIdentity.sha("host-recovery-fixture"));
        if(r.retainedAfterBusiness)sample.getJSONObject("displays").put("including_disabled",true);return sample;
    }
    private static String syntheticRecents(){
        return "ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)\nmRecentsUid=1000\n"
            +"mRecentsComponent=ComponentInfo{com.example.recents/.Main}\nmFreezeTaskListReordering=false\nmFreezeTaskListReorderingPendingTimeout=false\n"
            +"  Recent tasks:\n"
            +"  * Recent #0: Task{aa #100 type=standard A=10367:com.example.foreground}\n"
            +"    userId=0 effectiveUid=10367 mCallingUid=10367\n    taskId=100 rootTaskId=100\n"
            +"    affinity=10367:com.example.foreground\n    intent={flg=0x10000000 cmp=com.example.foreground/.Main}\n"
            +"    mActivityComponent=com.example.foreground/.Main\n    Activities=[]\n    lastActiveTime=2000 (inactive for 0s)\n    lastDisplayId=0\n"
            +"  Visible recent tasks (most recent first):\n"
            +"  * RecentTaskInfo #0:\n    id=100 userId=0 hasTask=true lastActiveTime=2000\n"
            +"    baseIntent=Intent { flg=0x10000000 cmp=com.example.foreground/.Main }\n"
            +"    isExcluded=false displayId=0\n    lastDisplayId=0\n";
    }
    /** Host-only fake root samples; never a device proof or mutation authority. */
    public static JSONObject syntheticProof(PublicProfileBusinessAbsenceRecovery.Request r)throws Exception{
        JSONObject proof=new JSONObject().put("schema",r.proofSchema()).put("source",r.source()).put("request_id",r.requestId).put("task_id",r.taskId)
            .put("generation",r.generation).put("owner_uid",r.ownerUid).put("owner_sha256",r.ownerSha256).put("journal_sha256",r.journalSha256)
            .put("manifest_sha256",r.manifest.sha256).put("originals_sha256",r.originalsSha256).put("public_scope_wire",r.publicScope.wire())
            .put("public_scope_sha256",r.publicScope.sha256).put("profile_target_wire",r.target.wire()).put("target_sha256",r.target.sha256)
            .put("display_name",r.displayName).put("old_boot_count",r.oldBoot).put("current_boot_count",r.requestBoot).put("lease_expires_elapsed_ms",r.expires)
            .put("request_started_elapsed_ms",r.started).put("started_elapsed_ms",r.started+1).put("finished_elapsed_ms",r.started+30).put("deadline_elapsed_ms",r.deadline)
            .put("current_controller",r.controller()).put("before",syntheticSample(r,r.started+2)).put("after",syntheticSample(r,r.started+20))
            .put("current_absence_verified",true).put("recovery_interval_physical_unchanged",true).put("foreign_dormant_history_preserved",true)
            .put("cleanup_known",true).put("automatic_resume",false).put("broker_release_response",false).put("business_steps",r.steps)
            .put("model_requests",r.modelRequests).put("model_generation",r.modelGeneration).put("historical_model_exit_verified",!r.retainedBeforeFirstModel)
            .put("historical_broker_release_observed",!r.retainedCurrentAbsenceRequired()).put("business_dispatch_absent_in_original_receipts",r.retainedBeforeFirstModel)
            .put("recorded_owned_identity",r.recordedOwnedIdentity()).put("rewrites_business_outcome",false).put("acknowledges_control_session",false);
        if(r.retainedAfterBusiness)proof.put("original_history_refusal",r.originalHistoryRefusal()).put("historical_broker_process",r.historicalBrokerProcess());
        return proof;
    }
    private static void proofReject(String name,String code,Edit edit)throws Exception{
        reject(name,code,()->{PublicProfileBusinessAbsenceRecovery.Request r=ORIGINAL.copy().request();JSONObject p=syntheticProof(r);edit.run(p);
            PublicProfileBusinessAbsenceRecovery.validate(p,r,r.started+31,r.requestBoot);});
    }
    private static byte[] readBlock(DataInputStream in)throws Exception{int n=in.readInt();check(n>=0&&n<=PublicProfileBusinessAbsenceRecovery.MAX_BUNDLE);byte[] b=new byte[n];in.readFully(b);return b;}

    /** Exact external bytes only; this does not construct or grant a recovery receipt. */
    public static Map<String,byte[]> loadExternalOriginals(Path pathsFile)throws Exception{
        JSONObject paths=object(Files.readAllBytes(pathsFile));TreeMap<String,byte[]> inputs=new TreeMap<String,byte[]>();
        for(String p:paths.keySet())inputs.put(p,Files.readAllBytes(Paths.get(paths.getString(p))));return inputs;
    }

    public static void main(String[] args)throws Exception{
        if(args.length!=3)throw new IllegalArgumentException("manifest, exact external path map, fresh result required");
        JSONObject manifest=object(Files.readAllBytes(Paths.get(args[0])));
        Map<String,byte[]> inputs=loadExternalOriginals(Paths.get(args[1]));
        ORIGINAL=new Fixture(manifest,inputs);
        pass("complete_actual_seven_request_result_and_all_original_bytes",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=ORIGINAL.request();
            check(r.steps==7&&r.modelRequests==7&&r.manifest.taskFiles().size()==105&&inputs.size()==132);
            check(r.task("result.json").length==547419&&r.task("result.json").length>131072);
            for(String p:inputs.keySet())check(Arrays.equals(inputs.get(p),r.original(p)));
        });
        pass("bounded_manifest_wire_roundtrip_preserves_all_descriptors_and_bytes",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=ORIGINAL.request();
            PublicProfileBusinessAbsenceRecovery.Manifest m=PublicProfileBusinessAbsenceRecovery.fromWire(r.wire());
            check(m.sha256.equals(r.manifest.sha256)&&r.wire().length()<=PublicProfileBusinessAbsenceRecovery.MAX_WIRE);
            PublicProfileBusinessAbsenceRecovery.Request again=PublicProfileBusinessAbsenceRecovery.request(m,inputs);
            check(again.originalsSha256.equals(r.originalsSha256));
        });
        pass("binary_archive_retains_every_complete_original_with_no_trailing_bytes",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=ORIGINAL.request();
            byte[] archive=r.archiveBytes();DataInputStream in=new DataInputStream(new ByteArrayInputStream(archive));
            check("hepta.public-profile-business-originals.v1".equals(in.readUTF()));
            check(Arrays.equals(readBlock(in),PublicProfileBusinessAbsenceRecovery.canonical(r.manifest.json()).getBytes(StandardCharsets.UTF_8)));
            int count=in.readInt();check(count==inputs.size());TreeSet<String> seen=new TreeSet<String>();
            for(int i=0;i<count;i++){String p=in.readUTF();check(seen.add(p));check(Arrays.equals(readBlock(in),inputs.get(p)));}
            check(in.read()==-1&&seen.equals(inputs.keySet()));
        });
        pass("request_owns_defensive_byte_copies",()->{
            Fixture f=ORIGINAL.copy();PublicProfileBusinessAbsenceRecovery.Request r=f.request();byte[] original=inputs.get(f.resultPath);
            f.files.get(f.resultPath)[0]^=1;byte[] returned=r.task("result.json");returned[0]^=1;
            check(Arrays.equals(original,r.task("result.json")));
        });
        pass("actual_seven_android_double_roundtrips_are_limited_to_rate_fields",()->{
            int count=0,strictDifferent=0;
            for(String p:inputs.keySet())if(p.endsWith("/app-receipt.json")){
                JSONObject app=object(inputs.get(p)),nativeValue=object(inputs.get(p.replace("app-receipt.json","native-result.json")));
                check(PublicProfileBusinessAbsenceRecovery.sameNativeRequestReceipt(nativeValue,app.getJSONObject("native_receipt")));
                if(!PublicProfileBusinessAbsenceRecovery.same(nativeValue,app.getJSONObject("native_receipt")))strictDifferent++;count++;
            }
            check(count==7&&strictDifferent>0);
        });
        pass("one_ulp_rate_change_is_rejected",()->{
            JSONObject n=ORIGINAL.json(ORIGINAL.firstAppRequest().replace("app-receipt.json","native-result.json")),b=cloneJson(n);
            b.getJSONObject("profile").put("decode_tokens_per_second",Math.nextUp(n.getJSONObject("profile").getDouble("decode_tokens_per_second")));
            check(!PublicProfileBusinessAbsenceRecovery.sameNativeRequestReceipt(n,b));
        });
        pass("rate_string_type_is_rejected",()->{
            JSONObject n=ORIGINAL.json(ORIGINAL.firstAppRequest().replace("app-receipt.json","native-result.json")),b=cloneJson(n);
            b.getJSONObject("profile").put("decode_tokens_per_second",n.getJSONObject("profile").get("decode_tokens_per_second").toString());
            check(!PublicProfileBusinessAbsenceRecovery.sameNativeRequestReceipt(n,b));
        });
        reject("missing_rate_is_rejected","decode_tokens_per_second",()->{
            JSONObject n=ORIGINAL.json(ORIGINAL.firstAppRequest().replace("app-receipt.json","native-result.json")),b=cloneJson(n);b.getJSONObject("profile").remove("decode_tokens_per_second");
            PublicProfileBusinessAbsenceRecovery.sameNativeRequestReceipt(n,b);
        });
        pass("other_numeric_fields_keep_decimal_exactness",()->{
            JSONObject n=ORIGINAL.json(ORIGINAL.firstAppRequest().replace("app-receipt.json","native-result.json")),b=cloneJson(n);
            b.put("request_sequence",n.getLong("request_sequence")+1);check(!PublicProfileBusinessAbsenceRecovery.sameNativeRequestReceipt(n,b));
            b=cloneJson(n);b.getJSONObject("profile").put("host_added_unknown_rate",new BigDecimal("1.00000000000000000001"));
            check(!PublicProfileBusinessAbsenceRecovery.sameNativeRequestReceipt(n,b));
            n.getJSONObject("profile").put("host_added_unknown_rate",new BigDecimal("1.00000000000000000002"));
            check(!PublicProfileBusinessAbsenceRecovery.sameNativeRequestReceipt(n,b));
        });
        reject("changed_raw_bytes_fail_original_hash","BUSINESS_INPUT_HASH",()->{
            Fixture f=ORIGINAL.copy();f.files.get(f.resultPath)[1]^=1;f.request();
        });
        reject("missing_full_result_cannot_be_replaced_by_summary","BUSINESS_TASK_MEMBERSHIP",()->{
            Fixture f=ORIGINAL.copy();f.remove(f.resultPath);f.request();
        });
        reject("truncated_rehashed_json_is_not_accepted","",()->{
            Fixture f=ORIGINAL.copy();f.put(f.resultPath,Arrays.copyOf(f.files.get(f.resultPath),131072));f.request();
        });
        reject("wrong_stat_or_link_metadata_rejected","BUSINESS_FILE_METADATA",()->{
            Fixture f=ORIGINAL.copy();f.manifest.getJSONObject("files").getJSONObject(f.resultPath).put("nlink",2);f.request();
        });
        reject("control_summary_over_64k_rejected_without_clipping_result","BUSINESS_SUMMARY_BOUND",()->{
            Fixture f=ORIGINAL.copy();char[] pad=new char[65537];Arrays.fill(pad,'x');
            f.edit("control-session.json",v->v.put("host_extra_padding",new String(pad)));f.request();
        });
        reject("unknown_run_file_cannot_join_model_close_proof","BUSINESS_RUN_INPUT_SET",()->{
            Fixture f=ORIGINAL.copy();f.put("runs/11111111111111111111111111111111/raw-text.txt",new byte[]{1});f.request();
        });
        reject("zero_business_step_cannot_use_positive_step_contract","BUSINESS_TERMINAL",()->{
            Fixture f=ORIGINAL.copy();JSONObject r=f.json(f.resultPath).put("steps",0);f.result(r);f.request();
        });
        reject("historical_model_exit_false_cannot_be_recovered_by_json_claim","BUSINESS_EXPECTED_TRUE_process_exit_observed",()->{
            Fixture f=ORIGINAL.copy();JSONObject session=f.json(f.sessionPath).put("process_exit_observed",false);f.session(session);f.request();
        });
        reject("historical_model_forced_cleanup_rejected","BUSINESS_EXPECTED_TRUE_generation_unforced",()->{
            Fixture f=ORIGINAL.copy();f.session(f.json(f.sessionPath).put("generation_unforced",false));f.request();
        });
        reject("pending_actual_action_worker_rejected","BUSINESS_EXPECTED_FALSE_action_worker_pending_at_terminal",()->{
            Fixture f=ORIGINAL.copy();f.result(f.json(f.resultPath).put("action_worker_pending_at_terminal",true));f.request();
        });
        pass("model_monotonic_offset_is_not_compared_to_elapsed_realtime",()->{
            Fixture f=ORIGINAL.copy();f.shiftModelClocks(4000000000000000L);
            check(f.request().modelRequests==7);
            check(Arrays.equals(ORIGINAL.files.get(ORIGINAL.modelPrefix+"worker-generation.identity"),f.files.get(f.modelPrefix+"worker-generation.identity")));
        });
        reject("internal_finisher_deadline_still_enforced","BUSINESS_FINISHER_CLOCK",()->{
            Fixture f=ORIGINAL.copy();JSONObject a=f.json(f.sessionPath);a.put("finisher_deadline_monotonic_ns",a.getLong("finisher_submitted_monotonic_ns"));f.session(a);f.request();
        });
        reject("generation_clock_order_still_enforced","BUSINESS_GENERATION_MONOTONIC_CLOCK",()->{
            Fixture f=ORIGINAL.copy();JSONObject a=f.json(f.sessionPath),g=a.getJSONObject("worker_generation_cleanup"),n=g.getJSONObject("native_cleanup");
            n.put("ended_monotonic_ns",n.getLong("started_monotonic_ns")-1);f.put(f.modelPrefix+"generation-cleanup-"+g.getString("cleanup_nonce")+".json",bytes(n));
            g.put("native_receipt_sha256",ProfileIdentity.sha(bytes(n)));f.session(a);f.request();
        });
        pass("actual_startup_decision_and_policy_archive_branch_keep_old_bytes",()->{
            Fixture f=ORIGINAL.archived();PublicProfileBusinessAbsenceRecovery.Request r=f.request();
            check(Arrays.equals(ORIGINAL.files.get("control-session.json"),r.original(f.manifest.getString("origin_summary"))));
            check(Arrays.equals(ORIGINAL.files.get(f.resultPath),r.task("result.json")));
            check(!SessionRecovery.evaluate(map(f.json("control-session.json")),f.manifest.getInt("owner_uid"),true).allowNewTask);
        });
        reject("startup_archive_missing_rejected","BUSINESS_CORE_FILES",()->{
            Fixture f=ORIGINAL.archived();f.remove(f.manifest.getString("origin_summary"));f.request();
        });
        reject("startup_archive_content_hash_name_mismatch_rejected","BUSINESS_STARTUP_ARCHIVE",()->{
            Fixture f=ORIGINAL.archived();String p=f.manifest.getString("origin_summary");
            JSONObject v=f.json(p).put("state","host mutation");f.put(p,bytes(v));f.request();
        });
        reject("startup_previous_hash_mismatch_rejected","BUSINESS_STARTUP_CHAIN",()->{
            Fixture f=ORIGINAL.archived();f.edit("control-session.json",v->v.getJSONObject("startup_recovery").put("previous_session_sha256",HASH));f.request();
        });
        reject("startup_latch_origin_mismatch_rejected","BUSINESS_LATCH_ORIGIN",()->{
            Fixture f=ORIGINAL.archived();f.edit("control-session.interrupted.json",v->v.getJSONObject("recovery_reason").put("previous_session_sha256",HASH));f.request();
        });
        reject("startup_archive_without_latch_rejected","BUSINESS_STARTUP_LATCH_MISSING",()->{
            Fixture f=ORIGINAL.archived();f.remove("control-session.interrupted.json");f.request();
        });
        reject("current_identity_cannot_replace_original_task","BUSINESS_CONTROL_IDENTITY",()->{
            Fixture f=ORIGINAL.archived();f.edit("control-session.json",v->v.put("task_id","11111111111111111111111111111111"));f.request();
        });
        reject("original_expiry_plus_grace_is_not_fresh_enough","BUSINESS_BOOT_TTL_OR_DEADLINE",()->{
            Fixture f=ORIGINAL.copy();f.manifest.put("started_elapsed_ms",f.json("background-session.active.json").getLong("expires_elapsed_ms")+2000);f.request();
        });
        reject("wrong_boot_rejected","BUSINESS_BOOT_TTL_OR_DEADLINE",()->{
            Fixture f=ORIGINAL.copy();f.manifest.put("boot_count",f.manifest.getInt("boot_count")+1);f.request();
        });
        reject("twelve_second_current_proof_deadline_is_not_extended","BUSINESS_BOOT_TTL_OR_DEADLINE",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=ORIGINAL.request();r.requireFence(r.deadline,r.requestBoot);
        });
        pass("synthetic_double_current_absence_proof_is_absence_only",()->{
            PublicProfileBusinessAbsenceRecovery.Request r=ORIGINAL.request();JSONObject p=syntheticProof(r);
            JSONObject accepted=PublicProfileBusinessAbsenceRecovery.validate(p,r,r.started+31,r.requestBoot);
            check(!accepted.getBoolean("acknowledges_control_session")&&!accepted.getBoolean("rewrites_business_outcome")
                &&!accepted.getBoolean("business_dispatch_absent_in_original_receipts"));
        });
        proofReject("historical_exit_does_not_replace_current_model_absence","PUBLIC_RECOVERY_PROCESS_SAMPLE",p->p.getJSONObject("after").getJSONObject("process").put("model_worker_absent",false));
        proofReject("changed_physical_display_rejects","BUSINESS_DOUBLE_SAMPLE",p->p.getJSONObject("after").getJSONObject("physical").put("0",OTHER));
        proofReject("reused_owned_task_id_rejects","PUBLIC_POSTLAUNCH_OWNED_ID_REUSED",p->p.getJSONObject("after").getJSONObject("live").getJSONArray("all_task_ids").put(0,ORIGINAL.request().ownedLeafTaskId));
        proofReject("current_controller_mismatch_rejects","BUSINESS_PROOF_BINDING",p->p.getJSONObject("current_controller").put("source_sha256",OTHER));
        proofReject("absence_proof_cannot_acknowledge_or_rewrite_business","BUSINESS_EXPECTED_FALSE_acknowledges_control_session",p->p.put("acknowledges_control_session",true));
        proofReject("absence_proof_cannot_claim_zero_business_dispatch","BUSINESS_HISTORICAL_STATUS",p->p.put("business_dispatch_absent_in_original_receipts",true));
        JSONObject result=new JSONObject().put("status","PASS").put("cases",CASES.length()).put("assertions",assertions).put("case_names",CASES)
            .put("actual_original_count",inputs.size()).put("actual_task_file_count",105).put("actual_steps",7).put("actual_model_requests",7)
            .put("actual_full_result_bytes",inputs.get(ORIGINAL.resultPath).length)
            .put("exact_originals_external_not_repository_fixtures",true).put("current_controller_stat_clock_and_root_samples_synthetic",true)
            .put("startup_policy_archive_branch_executed",true).put("android_startup_io_executed",false).put("root_process_census_executed",false)
            .put("journal_cas_executed",false).put("model_reservation_tested_in_separate_actual_gate",true).put("phone_operations",0);
        Path out=Paths.get(args[2]);if(Files.exists(out))throw new IOException("fresh output required");
        Files.write(out,(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(result.toString());
    }
}
