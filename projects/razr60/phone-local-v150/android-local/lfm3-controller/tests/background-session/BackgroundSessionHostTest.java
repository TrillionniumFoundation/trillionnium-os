package org.trillionnium.hepta.local;
import android.content.Context;
import android.net.LocalSocket;
import android.os.SystemClock;
import android.provider.Settings;
import android.view.Display;
import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
/** Actual client/lease methods; root transport, display and time are explicit host IO surrogates. */
public final class BackgroundSessionHostTest {
    interface Case { void run() throws Exception; }
    static final List<JSONObject> rows=new ArrayList<JSONObject>();
    static final String PKG="com.example.notes",OTHER="com.example.shop",TASK="11111111111111111111111111111111";
    static int passed;
    static void check(boolean condition,String message){if(!condition)throw new AssertionError(message);}
    static void rejects(Case call)throws Exception{try{call.run();}catch(Exception expected){return;}throw new AssertionError("expected refusal");}
    static void test(String name,Case run)throws Exception{
        LocalSocket.reset();SystemClock.now=1000000;Settings.Global.boot=10;android.system.Os.failUnlink=false;
        JSONObject row=new JSONObject().put("case",name);
        try{run.run();passed++;row.put("status","pass");}
        catch(Throwable failure){row.put("status","fail").put("error",failure.toString());failure.printStackTrace(System.err);}
        rows.add(row);
    }
    static Object invoke(Object instance,String name,Class<?>[] types,Object...args)throws Exception{
        Method method=BackgroundSession.class.getDeclaredMethod(name,types);method.setAccessible(true);
        try{return method.invoke(instance,args);}catch(InvocationTargetException wrapped){Throwable cause=wrapped.getCause();if(cause instanceof Exception)throw (Exception)cause;throw new AssertionError(cause);}
    }
    static void field(Object instance,String name,Object value)throws Exception{Field f=BackgroundSession.class.getDeclaredField(name);f.setAccessible(true);f.set(instance,value);}
    static JSONObject request(String generation,String op)throws Exception{return new JSONObject().put("version",1).put("request_id",UUID.randomUUID().toString()).put("generation",generation).put("deadline_elapsed_ms",SystemClock.now+3000).put("op",op);}
    static JSONObject decode(byte[] frame)throws Exception{DataInputStream input=new DataInputStream(new ByteArrayInputStream(frame));int length=input.readInt();byte[] payload=new byte[length];input.readFully(payload);return new JSONObject(new String(payload,StandardCharsets.UTF_8));}
    static byte[] frame(byte[] payload)throws Exception{ByteArrayOutputStream out=new ByteArrayOutputStream();DataOutputStream data=new DataOutputStream(out);data.writeInt(payload.length);data.write(payload);return out.toByteArray();}
    static JSONObject policy(String generation,int id)throws Exception{
        Map<String,Integer> constants=new LinkedHashMap<String,Integer>();
        constants.put("FLAG_TRUSTED",128);constants.put("FLAG_OWN_FOCUS",2048);constants.put("FLAG_STEAL_TOP_FOCUS_DISABLED",4096);
        constants.put("FLAG_SECURE",2);constants.put("FLAG_ALWAYS_UNLOCKED",512);
        org.trillionnium.hepta.background.BrokerProtocol.DisplayPolicy policy=
            org.trillionnium.hepta.background.BrokerProtocol.DisplayPolicy.checked(6272,constants,2,2);
        return new JSONObject(policy.numericEvidence()).put("schema",org.trillionnium.hepta.background.BrokerProtocol.DisplayPolicy.SCHEMA)
            .put("source","broker_framework_readback").put("generation",generation).put("display_id",id)
            .put("display_name","hepta-bg-"+generation).put("observed_started_elapsed_ms",SystemClock.now)
            .put("observed_ended_elapsed_ms",SystemClock.now);
    }
    static byte[] response(byte[] request,String state,int id,boolean ok,boolean dispatched)throws Exception{
        JSONObject req=decode(request);String generation=req.getString("generation");
        JSONObject value=new JSONObject().put("version",1).put("request_id",req.getString("request_id"))
            .put("generation",generation).put("ok",ok).put("state",state).put("display_id",id)
            .put("flags",6272).put("width",720).put("height",1280).put("density",240).put("dispatched",dispatched)
            .put("display_name","hepta-bg-"+generation).put("expires_elapsed_ms",SystemClock.now+540000)
            .put("operation",req.getString("op"));
        if("ACTIVE".equals(state))value.put("display_policy_readback",policy(generation,id));
        return frame(value.toString().getBytes(StandardCharsets.UTF_8));
    }
    static final String ATTEMPT="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static JSONObject fixedResponse(byte[] request,org.trillionnium.hepta.background.FixedIntentTarget target)throws Exception{
        JSONObject req=decode(request);JSONObject value=decode(response(request,"ACTIVE",7,true,true));
        JSONObject proof=new JSONObject().put("schema","hepta.background-fixed-intent.v1").put("request_id",req.getString("request_id"))
                .put("generation",req.getString("generation")).put("display_id",7).put("action",target.action)
                .put("attempt_id",req.getString("attempt_id")).put("payload_sha256",org.trillionnium.hepta.background.FixedIntentTarget.payloadSha256(req.getString("payload")))
                .put("target",new JSONObject(target.evidence())).put("ordinary_caller_uid",android.os.Process.myUid()).put("attempt_consumed",true)
                .put("resolved_type",org.trillionnium.hepta.background.FixedIntentTools.forAction(target.action).mimeType==null?JSONObject.NULL:org.trillionnium.hepta.background.FixedIntentTools.forAction(target.action).mimeType);
        return value.put("fixed_intent",proof);
    }
    static JSONObject exchange(JSONObject request)throws Exception{return (JSONObject)invoke(null,"exchange",new Class<?>[]{String.class,String.class,JSONObject.class,int.class},"hepta-bg-"+request.getString("generation"),request.getString("generation"),request,3500);}
    static final class Env implements AutoCloseable {
        final Path directory;final Context context;final BackgroundSession session;
        Env()throws Exception{this(null);}
        Env(String extra)throws Exception{directory=Files.createTempDirectory("hepta-background-client-");context=new Context(directory.toFile());Set<String> allowed=new TreeSet<String>(Arrays.asList(PKG,OTHER));if(extra!=null)allowed.add(extra);session=new BackgroundSession(context,TASK,"写备忘录",new BackgroundSession.Selection(PKG,allowed),new QualificationScopeConfig.FilesRoot(context));}
        void active()throws Exception{context.displays.displays.put(7,new Display(7,session.displayName));
            JSONObject receipt=decode(response(frame(request(session.generation,"state").toString().getBytes(StandardCharsets.UTF_8)),"ACTIVE",7,true,false));
            invoke(session,"accept",new Class<?>[]{JSONObject.class,boolean.class},receipt,true);
        }
        void journal()throws Exception{JSONObject value=(JSONObject)invoke(session,"baseJournal",new Class<?>[]{});MobiMindPrivateFiles.writeNew(directory.resolve(BackgroundSession.JOURNAL).toFile(),value.toString().getBytes(StandardCharsets.UTF_8));field(session,"spawnAttempted",true);}
        boolean journalPresent(){return Files.exists(directory.resolve(BackgroundSession.JOURNAL));}
        public void close()throws IOException{android.system.Os.failUnlink=false;try(java.util.stream.Stream<Path> stream=Files.walk(directory)){Path[] paths=stream.sorted(Comparator.reverseOrder()).toArray(Path[]::new);for(Path p:paths)Files.deleteIfExists(p);}}
    }
    static Process exitedProcess(final InputStream input){return new Process(){
        public InputStream getInputStream(){return input;}
        public InputStream getErrorStream(){return new ByteArrayInputStream(new byte[0]);}
        public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
        public int waitFor(){return 70;}public int exitValue(){return 70;}public void destroy(){}
    };}
    static Object output(Process process,Env e)throws Exception{
        Class<?> type=Class.forName("org.trillionnium.hepta.local.BackgroundSession$BrokerOutput");
        Constructor<?> constructor=type.getDeclaredConstructor(Process.class,File.class,String.class,String.class,String.class);
        constructor.setAccessible(true);return constructor.newInstance(process,e.directory.toFile(),TASK,e.session.generation,"fixture-only-no-process-launch");
    }
    static JSONObject outputEvidence(Object output)throws Exception{Method m=output.getClass().getDeclaredMethod("evidence");m.setAccessible(true);return (JSONObject)m.invoke(output);}
    public static void main(String[] args)throws Exception{
        test("selection_empty_refused",()->rejects(()->new BackgroundSession.Selection(PKG,Collections.<String>emptySet())));
        test("selection_initial_must_belong",()->rejects(()->new BackgroundSession.Selection(OTHER,Collections.singleton(PKG))));
        for(String forbidden:new String[]{"org.trillionnium.hepta.local","com.android.systemui","com.android.shell","bad;command","android"})test("selection_forbidden_"+forbidden,()->rejects(()->new BackgroundSession.Selection(forbidden,Collections.singleton(forbidden))));
        test("selection_six_limit",()->{Set<String> values=new TreeSet<String>();for(int i=0;i<7;i++)values.add("com.example.p"+i);rejects(()->new BackgroundSession.Selection("com.example.p0",values));});
        test("selection_copies_owner_scope",()->{Set<String> values=new TreeSet<String>(Collections.singleton(PKG));BackgroundSession.Selection s=new BackgroundSession.Selection(PKG,values);values.add(OTHER);check(s.allowedPackages.size()==1,"owner scope mutated");rejects(()->s.allowedPackages.add(OTHER));});
        test("initial_cannot_observe_display_zero",()->{try(Env e=new Env()){rejects(e.session::requireActive);check(LocalSocket.connections==0,"no transport expected");}});
        test("active_requires_same_display_name",()->{try(Env e=new Env()){e.active();e.session.requireActive();e.context.displays.displays.put(7,new Display(7,"another-generation"));rejects(e.session::requireActive);}});
        test("missing_display_no_default_fallback",()->{try(Env e=new Env()){e.active();e.context.displays.displays.clear();e.context.displays.displays.put(0,new Display(0,e.session.displayName));rejects(e.session::requireActive);}});
        test("display_zero_id_refused",()->{try(Env e=new Env()){e.active();field(e.session,"displayId",0);rejects(e.session::requireActive);}});
        test("locked_and_unknown_lock_state_refused",()->{try(Env e=new Env()){e.active();e.context.keyguard.locked=true;rejects(e.session::requireActive);e.context.keyguard=null;rejects(e.session::requireActive);}});
        test("expired_and_retired_refused",()->{try(Env e=new Env()){e.active();SystemClock.now=e.session.expiresElapsed;rejects(e.session::requireActive);SystemClock.now=1000000;field(e.session,"retired",true);rejects(e.session::requireActive);}});
        test("ordinary_app_flags_independently_match_broker_readback",()->{try(Env e=new Env()){
            e.active();e.session.requireActive();JSONObject proof=e.session.evidence().getJSONObject("app_display_readback");
            check(proof.getInt("flags")==6272&&proof.getInt("display_id")==7&&proof.getInt("app_uid")==android.os.Process.myUid(),"ordinary public readback missing");
            check(e.session.generation.equals(proof.getString("generation"))&&e.session.displayName.equals(proof.getString("display_name"))&&proof.getBoolean("valid"),"readback display generation lost");
            check(proof.getString("broker_request_id").equals(e.session.evidence().getJSONObject("last_broker_response").getString("request_id")),"readback not bound to authenticated request");
        }});
        for(int changed:new int[]{128,6272|2,6272|512,6272|4})test("ordinary_flags_change_refused_"+changed,()->{try(Env e=new Env()){
            e.active();e.context.displays.displays.get(7).flags=changed;rejects(e.session::requireActive);
            JSONObject mismatch=e.session.evidence().getJSONObject("app_display_readback");
            check(mismatch.getInt("flags")==changed&&!mismatch.getBoolean("flags_match_broker"),"actual failed readback was lost or old success retained");
        }});
        for(String changed:new String[]{"generation","display_name","display_id","required_mask","forbidden_mask","ime_actual","flags_source","observed_ended_elapsed_ms"})test("broker_policy_identity_or_value_refused_"+changed,()->{try(Env e=new Env()){
            e.active();JSONObject receipt=e.session.evidence().getJSONObject("last_broker_response");JSONObject policy=receipt.getJSONObject("display_policy_readback");
            if("display_id".equals(changed))policy.put(changed,8);
            else if("required_mask".equals(changed)||"forbidden_mask".equals(changed))policy.put(changed,0);
            else if("ime_actual".equals(changed))policy.put(changed,0);
            else if("observed_ended_elapsed_ms".equals(changed))policy.put(changed,SystemClock.now+1);
            else policy.put(changed,"wrong");
            receipt.put("display_policy_readback",policy);field(e.session,"lastResponse",receipt);rejects(e.session::requireActive);
        }});
        test("broker_policy_missing_refused",()->{try(Env e=new Env()){
            e.active();JSONObject receipt=e.session.evidence().getJSONObject("last_broker_response");receipt.put("display_policy_readback",JSONObject.NULL);field(e.session,"lastResponse",receipt);rejects(e.session::requireActive);
        }});
        test("broker_policy_coerced_numeric_string_refused",()->{try(Env e=new Env()){
            e.active();JSONObject receipt=e.session.evidence().getJSONObject("last_broker_response");JSONObject policy=receipt.getJSONObject("display_policy_readback");policy.put("flags","6272");receipt.put("display_policy_readback",policy);field(e.session,"lastResponse",receipt);rejects(e.session::requireActive);
        }});
        test("permission_preparation_blocks_client_before_lease_or_broker",()->{try(Env e=new Env()){
            LocalProbeApplication.permissionBusy=true;try{rejects(()->e.session.start(()->false));check(!e.journalPresent()&&LocalSocket.connections==0,"permission preparation cannot create lease or broker");}
            finally{LocalProbeApplication.permissionBusy=false;}
        }});
        test("start_cannot_block_main_thread",()->{try(Env e=new Env()){rejects(()->e.session.start(()->false));check(!e.journalPresent()&&LocalSocket.connections==0,"no process or transport before thread check");}});
        test("android_timeout_requires_created_socket",()->{try(LocalSocket socket=new LocalSocket()){
            try{socket.setSoTimeout(3500);throw new AssertionError("uncreated socket accepted timeout");}
            catch(IOException expected){check("socket not created".equals(expected.getMessage()),"wrong Android lifecycle failure");}
        }});
        test("exchange_connects_then_configures_and_authenticates_before_bytes",()->{
            LocalSocket.responder=req->response(req,"ACTIVE",7,true,false);
            exchange(request(UUID.randomUUID().toString(),"state"));
            check(LocalSocket.events.equals(Arrays.asList("connect","timeout","peer","output","input","close")),"socket lifecycle or UID-before-bytes ordering changed");
        });
        test("absent_socket_is_typed_before_timeout_or_request",()->{
            LocalSocket.missing=true;
            try{exchange(request(UUID.randomUUID().toString(),"state"));throw new AssertionError("absent endpoint accepted");}
            catch(IOException expected){check("ConnectionUnavailable".equals(expected.getClass().getSimpleName()),"absent endpoint lost retry/reconcile type");}
            check(LocalSocket.events.equals(Arrays.asList("connect","close"))&&LocalSocket.sent.length==0,"absent endpoint configured or sent bytes");
        });
        test("client_authenticates_server_before_request",()->{LocalSocket.peerUid=10002;rejects(()->exchange(request(UUID.randomUUID().toString(),"state")));check(LocalSocket.sent.length==0,"untrusted server got request");});
        for(int uid:new int[]{0,2000})test("accepted_server_uid_"+uid,()->{LocalSocket.peerUid=uid;LocalSocket.responder=req->response(req,"ACTIVE",7,true,false);JSONObject result=exchange(request(UUID.randomUUID().toString(),"state"));check(result.getInt("display_id")==7&&LocalSocket.timeout==3500,"bound transport response");});
        for(String changed:new String[]{"request_id","generation","version","state"})test("response_identity_"+changed,()->{LocalSocket.responder=req->{JSONObject value=decode(response(req,"ACTIVE",7,true,false));value.put(changed,"version".equals(changed)?Integer.valueOf(2):"mismatch");return frame(value.toString().getBytes(StandardCharsets.UTF_8));};rejects(()->exchange(request(UUID.randomUUID().toString(),"state")));});
        for(int length:new int[]{-1,0,65537})test("response_length_"+length,()->{LocalSocket.responder=req->{ByteArrayOutputStream out=new ByteArrayOutputStream();new DataOutputStream(out).writeInt(length);return out.toByteArray();};rejects(()->exchange(request(UUID.randomUUID().toString(),"state")));});
        test("truncated_response_refused",()->{LocalSocket.responder=req->new byte[]{0,0,0,8,123};rejects(()->exchange(request(UUID.randomUUID().toString(),"state")));});
        test("invalid_utf8_refused",()->{LocalSocket.responder=req->frame(new byte[]{(byte)0xc3,0x28});rejects(()->exchange(request(UUID.randomUUID().toString(),"state")));});
        test("transport_timeout_not_retried",()->{LocalSocket.responder=req->{throw new java.net.SocketTimeoutException("fixture");};rejects(()->exchange(request(UUID.randomUUID().toString(),"state")));check(LocalSocket.connections==1,"unknown request replayed");});
        for(String action:new String[]{"notes.create","web.search"})test("fixed_client_exact_payload_binding_"+action,()->{
            org.trillionnium.hepta.background.FixedIntentTools.Profile profile=org.trillionnium.hepta.background.FixedIntentTools.forAction(action);
            org.trillionnium.hepta.background.FixedIntentTarget target=new org.trillionnium.hepta.background.FixedIntentTarget(action,"actual-installed-label",10382,null);
            try(Env e=new Env(profile.packageName)){e.active();LocalSocket.responder=req->frame(fixedResponse(req,target).toString().getBytes(StandardCharsets.UTF_8));
                e.session.fixedIntent(target,"原文\n中文🙂",ATTEMPT,()->false);JSONObject sent=decode(LocalSocket.sent);
                check(sent.length()==9&&sent.getString("op").equals(action)&&sent.getString("package").equals(target.packageName)
                    &&sent.getString("payload").equals("原文\n中文🙂")&&sent.getInt("target_uid")==10382&&sent.getString("attempt_id").equals(ATTEMPT),"fixed wire must preserve actual model payload/identity without arbitrary fields");
                check(LocalSocket.connections==1,"single bounded transport");
            }
        });
        for(String changed:new String[]{"action","attempt_id","payload_sha256","display_id","generation","ordinary_caller_uid","target_uid","component","app_label","required_permission","exported","activity_enabled","application_enabled","declared_intent_filter_matched","ordinary_caller_permission_checked","resolved_type"})test("fixed_client_changed_proof_refused_"+changed,()->{
            org.trillionnium.hepta.background.FixedIntentTarget target=new org.trillionnium.hepta.background.FixedIntentTarget("notes.create","label",10382,null);
            try(Env e=new Env(target.packageName)){e.active();LocalSocket.responder=req->{JSONObject value=fixedResponse(req,target),proof=value.getJSONObject("fixed_intent");
                if("target_uid".equals(changed))proof.getJSONObject("target").put(changed,10383);
                else if("component".equals(changed))proof.getJSONObject("target").put(changed,"com.example.foreign/.Activity");
                else if(java.util.Arrays.asList("app_label","required_permission").contains(changed))proof.getJSONObject("target").put(changed,"wrong");
                else if(java.util.Arrays.asList("exported","activity_enabled","application_enabled","declared_intent_filter_matched","ordinary_caller_permission_checked").contains(changed))proof.getJSONObject("target").put(changed,false);
                else proof.put(changed,"display_id".equals(changed)||"ordinary_caller_uid".equals(changed)?Integer.valueOf(12345):"wrong");
                return frame(value.toString().getBytes(StandardCharsets.UTF_8));};
                rejects(()->e.session.fixedIntent(target,"正文",ATTEMPT,()->false));check(LocalSocket.connections==1,"mismatched receipt not retried");
            }
        });
        test("fixed_client_outside_scope_or_cancel_zero_request",()->{org.trillionnium.hepta.background.FixedIntentTarget target=new org.trillionnium.hepta.background.FixedIntentTarget("notes.create","label",10382,null);
            try(Env e=new Env()){e.active();rejects(()->e.session.fixedIntent(target,"正文",ATTEMPT,()->false));check(LocalSocket.connections==0,"outside selected package scope");}
            try(Env e=new Env(target.packageName)){e.active();rejects(()->e.session.fixedIntent(target,"正文",ATTEMPT,()->true));check(LocalSocket.connections==0,"cancelled before transport");}
        });
        test("fixed_client_timeout_is_not_retried",()->{org.trillionnium.hepta.background.FixedIntentTarget target=new org.trillionnium.hepta.background.FixedIntentTarget("notes.create","label",10382,null);
            try(Env e=new Env(target.packageName)){e.active();LocalSocket.responder=req->{throw new java.net.SocketTimeoutException("uncertain fixed intent reply");};
                rejects(()->e.session.fixedIntent(target,"正文",ATTEMPT,()->false));check(LocalSocket.connections==1,"unknown fixed intent request replayed");}
        });
        test("background_home_foreign_and_cancel_zero_requests",()->{try(Env e=new Env()){e.active();rejects(()->e.session.action("home",PKG,()->false));rejects(()->e.session.action("launch","com.example.foreign",()->false));rejects(()->e.session.action("back",PKG,()->true));check(LocalSocket.connections==0,"forbidden command sent");}});
        test("back_binds_observed_package",()->{try(Env e=new Env()){e.active();LocalSocket.responder=req->response(req,"ACTIVE",7,true,true);e.session.action("back",PKG,()->false);JSONObject sent=decode(LocalSocket.sent);check(PKG.equals(sent.getString("package"))&&"back".equals(sent.getString("op")),"BACK lost expected package");}});
        test("response_cannot_rebind_display",()->{try(Env e=new Env()){e.active();LocalSocket.responder=req->response(req,"ACTIVE",0,true,true);rejects(()->e.session.action("back",PKG,()->false));check(e.session.displayId()==7,"default display rebound");}});
        test("close_requires_response_and_display_absence",()->{try(Env e=new Env()){e.active();e.journal();LocalSocket.responder=req->response(req,"RELEASED",7,true,false);BackgroundSession.Cleanup result=e.session.close();check(!result.known&&e.journalPresent()&&!e.session.released(),"live display cleanup reported known");}});
        test("close_release_removes_own_journal",()->{try(Env e=new Env()){e.active();e.journal();LocalSocket.responder=req->{e.context.displays.displays.clear();return response(req,"RELEASED",7,true,false);};BackgroundSession.Cleanup result=e.session.close();check(result.known&&!e.journalPresent()&&e.session.released(),"release proof lost");}});
        test("close_timeout_retains_barrier",()->{try(Env e=new Env()){e.active();e.journal();LocalSocket.responder=req->{throw new java.net.SocketTimeoutException("fixture");};check(!e.session.close().known&&e.journalPresent()&&!e.session.released(),"timeout weakened cleanup");}});
        test("journal_delete_failure_never_known",()->{try(Env e=new Env()){e.active();e.journal();LocalSocket.responder=req->{e.context.displays.displays.clear();return response(req,"RELEASED",7,true,false);};android.system.Os.failUnlink=true;check(!e.session.close().known&&e.journalPresent()&&!e.session.released(),"delete failure released lease");}});
        test("already_released_failed_launch_reuses_proof",()->{try(Env e=new Env()){e.active();e.journal();e.context.displays.displays.clear();JSONObject receipt=decode(response(frame(request(e.session.generation,"launch").put("package",PKG).toString().getBytes(StandardCharsets.UTF_8)),"RELEASED",7,false,true));invoke(e.session,"accept",new Class<?>[]{JSONObject.class,boolean.class},receipt,false);check(e.session.close().known&&!e.journalPresent()&&LocalSocket.connections==0,"closed broker unnecessarily contacted");}});
        test("reconcile_live_orphan_not_cleared",()->{try(Env e=new Env()){e.active();e.journal();LocalSocket.missing=true;check(!BackgroundSession.reconcile(e.context).known&&e.journalPresent(),"orphan cleared before expiry");}});
        test("reconcile_expired_absent_display_known",()->{try(Env e=new Env()){e.active();e.journal();LocalSocket.missing=true;e.context.displays.displays.clear();SystemClock.now=e.session.expiresElapsed+2001;check(BackgroundSession.reconcile(e.context).known&&!e.journalPresent(),"expired absent session unresolved");}});
        test("reconcile_expired_named_display_still_blocks",()->{try(Env e=new Env()){e.journal();e.context.displays.displays.put(8,new Display(8,e.session.displayName));LocalSocket.missing=true;SystemClock.now=e.session.expiresElapsed+2001;check(!BackgroundSession.reconcile(e.context).known&&e.journalPresent(),"unknown ID bypassed generation display");}});
        test("reconcile_confirmed_reboot_absent_known",()->{try(Env e=new Env()){e.journal();LocalSocket.missing=true;Settings.Global.boot=11;SystemClock.now=100;check(BackgroundSession.reconcile(e.context).known&&!e.journalPresent(),"boot-changed absence not reconciled");}});
        test("bad_journal_expiry_refused",()->{try(Env e=new Env()){JSONObject value=(JSONObject)invoke(e.session,"baseJournal",new Class<?>[]{});value.put("expires_elapsed_ms",1);MobiMindPrivateFiles.writeNew(e.directory.resolve(BackgroundSession.JOURNAL).toFile(),value.toString().getBytes(StandardCharsets.UTF_8));rejects(()->BackgroundSession.reconcile(e.context));check(e.journalPresent(),"invalid journal discarded");}});
        test("broker_output_is_bounded_and_bound_to_owned_process",()->{try(Env e=new Env()){
            byte[] raw=new byte[65536+123];Arrays.fill(raw,(byte)'x');Process process=exitedProcess(new ByteArrayInputStream(raw));
            Object capture=output(process,e);((Runnable)capture).run();JSONObject receipt=outputEvidence(capture);
            byte[] kept=MobiMindPrivateFiles.read(e.directory.resolve(receipt.getString("output_file")).toFile(),65536,true).bytes;
            check(receipt.getBoolean("persisted")&&receipt.getBoolean("eof_seen")&&receipt.getBoolean("overflow"),"output completeness/overflow lost");
            check(receipt.getLong("observed_bytes")==raw.length&&kept.length==65536,"cap must not stop draining");
            check(receipt.getString("stored_sha256").equals(HeptaAccessibilityService.sha(kept)),"stored hash mismatch");
            check(TASK.equals(receipt.getString("task_id"))&&e.session.generation.equals(receipt.getString("generation"))&&receipt.getInt("process_reference")==System.identityHashCode(process),"output lost owned task/process binding");
            check(!receipt.getBoolean("model_input")&&!receipt.getBoolean("release_evidence"),"diagnostics became model or lease evidence");
            JSONObject saved=new JSONObject(new String(MobiMindPrivateFiles.read(e.directory.resolve(receipt.getString("receipt_file")).toFile(),16384,true).bytes,StandardCharsets.UTF_8));
            check(saved.toString().equals(receipt.toString()),"receipt differs from persisted snapshot");
        }});
        test("broker_read_failure_and_exit_never_release_lease",()->{try(Env e=new Env()){
            e.journal();Process process=exitedProcess(new InputStream(){public int read()throws IOException{throw new IOException("synthetic stream failure");}});
            Object capture=output(process,e);((Runnable)capture).run();JSONObject log=outputEvidence(capture);
            check(log.getBoolean("read_failed")&&!log.getBoolean("eof_seen")&&log.getBoolean("persisted"),"incomplete stream masqueraded as EOF");
            field(e.session,"brokerProcess",process);field(e.session,"brokerOutput",capture);LocalSocket.missing=true;
            BackgroundSession.Cleanup cleanup=e.session.close();
            check(!cleanup.known&&e.journalPresent()&&cleanup.evidence.getBoolean("broker_process_exit_observed")&&cleanup.evidence.getInt("broker_process_exit_code")==70,"exited broker output erased release barrier");
        }});
        test("unstarted_close_is_known_without_broker",()->{try(Env e=new Env()){check(e.session.close().known&&e.session.released()&&LocalSocket.connections==0,"unstarted close tried broker");}});
        for(boolean stop:new boolean[]{false,true})test("cleanup_unknown_with_late_scope_refusal_stop_"+stop,()->{
            final int[] closes={0},cancels={0};
            LocalInference model=new LocalInference(){
                public void cancelTask(){cancels[0]++;}
                public LocalInference.TaskCleanup endTask(){closes[0]++;return LocalInference.TaskCleanup.noWorker();}
            };
            ControllerFinalizationFixture controller=new ControllerFinalizationFixture(model);
            controller.setScopeCheck(()->{throw new IllegalStateException("scope changed during model teardown");});
            if(stop)controller.stop();
            ControllerFinalizationFixture.Outcome result=controller.finish("blocked","background display release unknown",false,false,true);
            check("blocked".equals(result.status)&&!result.cleanupKnown&&result.blocked&&!result.modelSuccess,
                    "late scope refusal or Stop erased unresolved cleanup status");
            check("scope changed during model teardown".equals(result.summary),"terminal reason was discarded");
            check(closes[0]==1&&cancels[0]==(stop?1:0),"finalization repeated model cleanup or cancellation");
        });
        Path output=Paths.get(args[0]);Files.createDirectories(output);JSONObject result=new JSONObject().put("schema","hepta.background-client-host-cases.v1").put("passed",passed).put("failed",rows.size()-passed).put("cases",new JSONArray(rows)).put("android_runtime",false).put("root_process_started",false).put("phone_actions",false);
        Files.write(output.resolve("RESULT.json"),result.toString(2).getBytes(StandardCharsets.UTF_8));System.out.println("background client host cases: "+passed+"/"+rows.size());if(passed!=rows.size())throw new AssertionError("client cases failed");
    }
}
