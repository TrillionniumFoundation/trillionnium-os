package org.trillionnium.hepta.local;

import java.io.*;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.json.*;

/** Archived fake-SDK originals plus focused counterexamples. No Android/SDK/phone success is asserted. */
public final class SdkExceptionFailureHostTest {
    private static int cases,assertions;
    private static final JSONArray names=new JSONArray();
    private static Path fixtures;
    private static Data original;
    private static SdkExceptionFailure.Expected expected;
    private interface Work {void run()throws Exception;}
    private interface Edit {void run(Data d)throws Exception;}
    private interface JsonEdit {void run(JSONObject j)throws Exception;}
    private static void check(boolean ok,String message){assertions++;if(!ok)throw new AssertionError(message);}
    private static void test(String name,Work body)throws Exception{body.run();cases++;names.put(name);}
    private static byte[] bytes(JSONObject j){return j.toString().getBytes(StandardCharsets.UTF_8);}
    private static JSONObject json(byte[] b){return new JSONObject(new String(b,StandardCharsets.UTF_8));}
    private static final class Data {
        byte[] request,session,evidence,formatted,ids,raw;
        boolean rawFilePresent=true,observed=true,force;
        Integer exit=70;
        Data copy(){
            Data d=new Data();d.request=request.clone();d.session=session.clone();d.evidence=evidence.clone();
            d.formatted=formatted.clone();d.ids=ids.clone();d.raw=raw.clone();d.rawFilePresent=rawFilePresent;
            d.observed=observed;d.force=force;d.exit=exit;return d;
        }
    }
    private static SdkExceptionFailure bind(Data d)throws Exception{return bind(expected,d);}
    private static SdkExceptionFailure bind(SdkExceptionFailure.Expected e,Data d)throws Exception{
        return SdkExceptionFailure.bind(e,d.request,d.session,d.evidence,d.formatted,d.ids,d.raw,d.rawFilePresent,d.observed,d.exit,d.force);
    }
    private static void rejected(Data d,String name)throws Exception{
        boolean rejected=false;try{bind(d);}catch(Exception expectedFailure){rejected=true;}
        check(rejected,name+" accepted");
    }
    private static void reject(String name,Edit change)throws Exception{test(name,()->{Data d=original.copy();change.run(d);rejected(d,name);});}
    private static void request(Data d,JsonEdit change)throws Exception{JSONObject j=json(d.request);change.run(j);d.request=bytes(j);}
    private static void session(Data d,JsonEdit change)throws Exception{JSONObject j=json(d.session);change.run(j);d.session=bytes(j);}
    private static void metadata(Data d,JsonEdit change)throws Exception{JSONObject j=json(d.evidence);change.run(j);d.evidence=bytes(j);}
    private static byte[] read(String name)throws Exception{return Files.readAllBytes(fixtures.resolve(name));}
    private static ModelProfile hostProfile()throws Exception{
        // Reflection is confined to this host fixture; production's closed model allowlist is unchanged.
        Constructor<ModelProfile> c=ModelProfile.class.getDeclaredConstructor(String.class,String.class,String.class,String.class,String.class,
                long.class,String.class,String.class,boolean.class,long.class);c.setAccessible(true);
        return c.newInstance("host-test-only","host fake model","host fixture","","fixture.gguf",27L,
                "fe572f0ca91e4deace47c4613dc977b02b9d9eff8cac891e2a4e0d3d34324cf8","host-test",true,0L);
    }
    private static SdkExceptionFailure.Expected expected(LocalRuntimeConfig config,long pid)throws Exception{
        JSONObject r=json(original.request);String run=r.getString("raw_text_file");
        run=run.substring(0,run.lastIndexOf('/'));
        return new SdkExceptionFailure.Expected(config,"11111111111111111111111111111111","22222222222222222222222222222222",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",pid,2,1,32,r.getString("model_path"),run,
                read("prompt.txt"),read("system.txt"),read("grammar.gbnf"));
    }
    private static void actualWait(String python,int code,boolean shouldBind)throws Exception{
        Process p=new ProcessBuilder(python,"-B","-c","import os; print(os.getpid(), flush=True); raise SystemExit("+code+")").start();
        long pid;try(BufferedReader input=new BufferedReader(new InputStreamReader(p.getInputStream(),StandardCharsets.UTF_8))){
            pid=Long.parseLong(input.readLine());
        }
        check(p.waitFor(5,TimeUnit.SECONDS)&&p.exitValue()==code,"real host child did not exit as requested");
        OwnedWorkerCancellation owner=new OwnedWorkerCancellation(expected.generation,expected.taskId);
        owner.attach(p,expected.generation,expected.taskId);
        OwnedWorkerCancellation.Exit stopped=owner.awaitCancellation();
        check(stopped.observed&&stopped.code!=null&&stopped.code.intValue()==code&&!stopped.forceSent,"actual owned wait differs");
        Data d=original.copy();request(d,j->j.put("pid",pid));session(d,j->j.put("pid",pid));
        d.observed=stopped.observed;d.exit=stopped.code;d.force=stopped.forceSent;
        SdkExceptionFailure proof=null;try{proof=bind(expected(expected.config,pid),d);}catch(Exception rejected){if(shouldBind)throw rejected;}
        check((proof!=null)==shouldBind,"real wait classification differs");
    }
    public static void main(String[] args)throws Exception{
        fixtures=Paths.get(args[0]);Path output=Paths.get(args[1]);String python=args[2];
        original=new Data();original.request=read("native-request.json");original.session=read("native-session.json");
        original.evidence=read("prompt-evidence.json");original.formatted=read("formatted-prompt.txt");
        original.ids=read("formatted-input-ids.le32");original.raw=read("raw-text.txt");
        expected=expected(new LocalRuntimeConfig(hostProfile(),"npu",4096,4),1326034);
        final SdkExceptionFailure verified=bind(original);
        test("actual_host_sdk_exception_originals_empty_published_raw_file",()->{
            JSONObject audit=verified.audit();
            check(original.raw.length==0&&!json(original.request).getBoolean("raw_text_present"),"actual raw semantics changed");
            check(audit.getBoolean("sdk_cleanup_bound")&&audit.getInt("parent_wait_exit_code")==70,"dedicated proof missing");
            check(!audit.getBoolean("inference_completed")&&!audit.getBoolean("request_committed")&&!audit.getBoolean("action_authorized"),"failure upgraded to success");
            check(verified.sequence==2&&verified.accepted==1&&verified.pid==1326034,"original sequence binding missing");
        });
        test("actual_host_callback_prefix_hash_is_preserved_in_failure_audit",()->{
            Data d=new Data();d.request=read("prefix-native-request.json");d.session=read("prefix-native-session.json");
            d.evidence=read("prefix-prompt-evidence.json");d.formatted=read("prefix-formatted-prompt.txt");
            d.ids=read("prefix-formatted-input-ids.le32");d.raw=read("prefix-raw-text.txt");
            JSONObject nativeRequest=json(d.request);String run=nativeRequest.getString("raw_text_file");
            run=run.substring(0,run.lastIndexOf('/'));
            SdkExceptionFailure.Expected e=new SdkExceptionFailure.Expected(expected.config,expected.generation,expected.taskId,expected.requestId,
                    nativeRequest.getLong("pid"),2,1,32,nativeRequest.getString("model_path"),run,
                    read("prefix-prompt.txt"),read("prefix-system.txt"),read("prefix-grammar.gbnf"));
            SdkExceptionFailure proof=bind(e,d);
            RunHandleFixture.RunHandle h=RunHandleFixture.handle(e.requestId,null);RunHandleFixture.internalCleanup(h);
            JSONObject audit=RunHandleFixture.classify(h,proof);
            check(d.raw.length>0&&nativeRequest.getBoolean("raw_text_truncated")&&"callback_prefix".equals(nativeRequest.getString("raw_text_source")),"original callback prefix missing");
            check(audit.getString("raw_text_sha256_read").equals(nativeRequest.getString("raw_text_sha256"))
                    &&!audit.getString("raw_text_sha256_read").equals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),"actual failure prefix hash replaced with empty output");
            check("native_failed".equals(audit.getString("status"))&&!audit.getBoolean("inference_completed"),"failure prefix promoted");
        });
        reject("wrong_request_task",d->request(d,j->j.put("task_id","33333333333333333333333333333333")));
        reject("wrong_session_task",d->session(d,j->j.put("task_id","33333333333333333333333333333333")));
        reject("wrong_request_generation",d->request(d,j->j.put("worker_generation","33333333333333333333333333333333")));
        reject("wrong_session_generation",d->session(d,j->j.put("worker_generation","33333333333333333333333333333333")));
        reject("wrong_request_id",d->request(d,j->j.put("request_id","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")));
        reject("wrong_request_sequence",d->request(d,j->j.put("request_sequence",1)));
        reject("wrong_request_pid",d->request(d,j->j.put("pid",1326035)));
        reject("wrong_session_pid",d->session(d,j->j.put("pid",1326035)));
        test("missing_or_partial_original_receipts",()->{
            for(int i=0;i<4;i++){Data d=original.copy();if(i==0)d.request=null;if(i==1)d.session=null;if(i==2)d.evidence=null;if(i==3)d.request="{".getBytes(StandardCharsets.UTF_8);rejected(d,"missing receipt "+i);}
        });
        test("request70_requires_actual_wait70_without_force",()->{
            for(Integer code:new Integer[]{0,143,137,134,null}){Data d=original.copy();d.exit=code;rejected(d,"wait "+code);}
            Data d=original.copy();d.observed=false;rejected(d,"unobserved");d=original.copy();d.force=true;rejected(d,"force");
        });
        test("destroy_and_deinit_both_observed_zero",()->{
            for(String key:new String[]{"sdk_destroy_rc","sdk_deinit_rc"}){Data d=original.copy();session(d,j->j.put(key,1));rejected(d,key);}
            for(String key:new String[]{"sdk_destroy_attempted","sdk_deinit_attempted"}){Data d=original.copy();session(d,j->j.put(key,false));rejected(d,key);}
        });
        reject("missing_cleanup_field",d->session(d,j->j.remove("sdk_destroy_rc")));
        reject("ordinary_return70_without_cpp_exception",d->request(d,j->j.put("error","sdk_generate_failed")));
        reject("request70_wrong_worker_outcome",d->request(d,j->j.put("worker_outcome","failed")));
        reject("exception_not_caught",d->request(d,j->j.getJSONObject("sdk_exception_boundary").put("caught",false)));
        reject("request_session_exception_differ",d->session(d,j->j.getJSONObject("sdk_exception_boundary").put("message_ascii","different")));
        reject("wrong_sdk_generate_rc",d->request(d,j->j.getJSONObject("sdk_rc").put("generate",0)));
        reject("wrong_sdk_source",d->request(d,j->j.put("sdk_source_commit","0000000000000000000000000000000000000000")));
        test("wrong_model_and_runtime_configuration",()->{
            String[] keys={"model_profile","model_architecture","model_sha256_verified","model_path","compute_requested","device_resolved","mode","runtime"};
            for(String key:keys){Data d=original.copy();request(d,j->j.put(key,"wrong"));rejected(d,key);}
            String[] numbers={"model_bytes_verified","n_ctx_create","max_tokens","n_gpu_layers_create","power_mode_create"};
            for(String key:numbers){Data d=original.copy();request(d,j->j.put(key,0));rejected(d,key);}
            Data d=original.copy();request(d,j->j.getJSONObject("sampler_requested").put("temperature",1));rejected(d,"sampler");
        });
        test("wrong_original_prompt_system_grammar_hash",()->{
            for(String key:new String[]{"prompt","system","grammar"}){Data d=original.copy();request(d,j->j.getJSONObject("input_sha256").put(key,String.join("",Collections.nCopies(64,"0"))));rejected(d,key);}
        });
        reject("prompt_metadata_original_input_mismatch",d->metadata(d,j->j.getJSONObject("source_input_sha256").put("prompt",String.join("",Collections.nCopies(64,"0")))));
        reject("private_formatted_bytes_changed",d->d.formatted[0]^=1);
        reject("private_input_id_bytes_changed",d->d.ids[0]^=1);
        reject("missing_private_input_ids",d->d.ids=null);
        reject("private_input_id_count_wrong",d->metadata(d,j->j.put("input_ids_count",49)));
        reject("native_input_id_hash_wrong",d->request(d,j->j.getJSONObject("prompt_budget").put("input_ids_sha256",String.join("",Collections.nCopies(64,"0")))));
        reject("private_evidence_wrong_request",d->metadata(d,j->j.put("request_id","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")));
        reject("private_evidence_wrong_path",d->request(d,j->j.getJSONObject("prompt_evidence").put("metadata_file","/different/prompt-evidence.json")));
        reject("missing_raw_file_is_not_raw_text_present_false",d->d.rawFilePresent=false);
        reject("raw_file_hash_mismatch",d->d.raw=new byte[]{65});
        reject("invalid_numeric_type_is_not_coerced",d->request(d,j->j.put("request_sequence","2")));
        test("wrong_current_session_accounting",()->{
            for(String key:new String[]{"requests_received","requests_completed","model_reset_count","last_request_status","last_request_return_status","control_done_attempts","control_done_delivered"}){
                Data d=original.copy();session(d,j->j.put(key,99));rejected(d,key);
            }
        });
        reject("close_or_signal_is_not_sdk_failure70",d->session(d,j->j.put("close_requested",true).put("signal_observed",15)));
        reject("failed_control_delivery_is_unverified",d->session(d,j->j.put("control_channel_write_failed",true).put("control_channel_last_errno",32)));
        test("bound_audit_cannot_be_reused_for_other_current_owner",()->{
            check(verified.matches(expected.config,expected.generation,expected.taskId,expected.pid,2,1,original.request,original.session,true,70,false),"same final owner rejected");
            check(!verified.matches(expected.config,"33333333333333333333333333333333",expected.taskId,expected.pid,2,1,original.request,original.session,true,70,false),"new generation reused");
            check(!verified.matches(expected.config,expected.generation,"33333333333333333333333333333333",expected.pid,2,1,original.request,original.session,true,70,false),"new task reused");
            check(!verified.matches(expected.config,expected.generation,expected.taskId,expected.pid+1,2,1,original.request,original.session,true,70,false),"new pid reused");
            check(!verified.matches(expected.config,expected.generation,expected.taskId,expected.pid,3,1,original.request,original.session,true,70,false),"new sequence reused");
            check(!verified.matches(expected.config,expected.generation,expected.taskId,expected.pid,2,2,original.request,original.session,true,70,false),"accepted counter changed");
            check(!verified.matches(expected.config,expected.generation,expected.taskId,expected.pid,2,1,original.request,original.session,true,143,false),"wait143 reused");
            check(!verified.matches(expected.config,expected.generation,expected.taskId,expected.pid,2,1,original.request,original.session,true,70,true),"force reused");
            check(!verified.matches(new LocalRuntimeConfig(expected.config.profile,"gpu",4096,4),expected.generation,expected.taskId,expected.pid,2,1,original.request,original.session,true,70,false),"new configuration reused");
            check(!verified.matches(expected.config,expected.generation,expected.taskId,expected.pid,2,1,new byte[]{1},original.session,true,70,false),"request changed after binding");
            check(!verified.matches(expected.config,expected.generation,expected.taskId,expected.pid,2,1,original.request,new byte[]{1},true,70,false),"session changed after binding");
        });
        test("actual_parent_wait70_with_explicit_derived_pid_carrier",()->actualWait(python,70,true));
        test("actual_parent_wait143_does_not_authorize_request70",()->actualWait(python,143,false));
        test("internal_cleanup_retains_native_failed_classification",()->{
            RunHandleFixture.RunHandle owner=RunHandleFixture.handle(expected.generation,null);
            RunHandleFixture.RunHandle h=RunHandleFixture.handle(expected.requestId,owner);
            RunHandleFixture.internalCleanup(owner);
            JSONObject value=RunHandleFixture.classify(h,verified);
            check(h.isCancellationRequested()&&!RunHandleFixture.caller(h),"internal retirement became caller cancellation");
            check("native_failed".equals(value.getString("status"))&&!value.getBoolean("inference_completed"),"SDK failure masked/upgraded");
        });
        test("caller_handle_cancel_is_recorded_on_owner",()->{
            RunHandleFixture.RunHandle owner=RunHandleFixture.handle(expected.generation,null);
            RunHandleFixture.RunHandle h=RunHandleFixture.handle(expected.requestId,owner);h.cancel();
            JSONObject value=RunHandleFixture.classify(h,verified);
            check(RunHandleFixture.caller(owner)&&RunHandleFixture.caller(h),"caller flag lost on propagation");
            check(value.getBoolean("caller_cancellation_requested")&&"cancelled".equals(value.getString("status")),"caller fact lost");
            check(!value.getBoolean("inference_completed"),"caller cancel upgraded");
        });
        test("queued_caller_cancellation_records_fact_without_inventing_user_stop",()->{
            RunHandleFixture.RunHandle owner=RunHandleFixture.handle(expected.generation,null);
            RunHandleFixture.RunHandle h=RunHandleFixture.handle(expected.requestId,owner);RunHandleFixture.requestOnly(h);
            JSONObject value=RunHandleFixture.classify(h,verified);
            check(h.isCancellationRequested()&&RunHandleFixture.caller(owner)&&value.getBoolean("caller_cancellation_requested"),"queued fact missing");
            check(!value.has("user_stop")&&!value.has("user_stop_requested"),"caller fact mislabeled user Stop");
        });
        test("unbound_other_failure_preserves_original_cancelled_audit",()->{
            RunHandleFixture.RunHandle h=RunHandleFixture.handle(expected.requestId,null);RunHandleFixture.internalCleanup(h);
            JSONObject value=RunHandleFixture.classify(h,null);
            check("cancelled".equals(value.getString("status"))&&!value.getBoolean("sdk_exception_failure_binding_valid"),"unbound failure reclassified");
        });
        JSONObject result=new JSONObject().put("schema","hepta.sdk-exception-failure-audit-host.v1").put("all_pass",true)
                .put("cases",cases).put("assertions",assertions).put("case_names",names)
                .put("original_fake_sdk_receipts_replayed",true).put("real_host_parent_wait_70_and_143",true)
                .put("actual_run_handle_and_classification_blocks_executed",true).put("android_private_file_io_executed",false)
                .put("real_proprietary_sdk_executed",false).put("phone_operations",0).put("business_verified",false);
        Files.write(output,(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println(result.toString());
    }
}
