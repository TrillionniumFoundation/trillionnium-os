package org.trillionnium.hepta.local;

import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.background.*;

/** Actual immutable 50af history; Android PM, clock and future absence are fixtures. */
public final class NotesCancelledAbsenceHostTest {
    private static int cases, assertions;
    private static final JSONArray names=new JSONArray(), rejections=new JSONArray();
    private static Inputs captured;
    private static Path scratch;
    private static final JSONObject measurements=new JSONObject();
    private static final JSONObject bridge=new JSONObject();
    interface Work {void run() throws Exception;}
    interface Change {void run(Inputs input) throws Exception;}
    private static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void test(String name,Work work)throws Exception{work.run();cases++;names.put(name);}
    private static byte[] raw(JSONObject value){return value.toString().getBytes(StandardCharsets.UTF_8);}
    private static JSONObject json(byte[] raw)throws Exception{return PublicPersonalNotesAbsenceRecovery.object(raw);}
    private static String sha(byte[] value){return HeptaAccessibilityService.sha(value);}
    private static void refuse(String name,Work work)throws Exception{try{work.run();throw new AssertionError("accepted: "+name);}
        catch(Exception expected){assertions++;rejections.put(new JSONObject().put("case",name).put("type",expected.getClass().getSimpleName()).put("reason",String.valueOf(expected.getMessage())));}}
    private static String key(String kind,int i){return String.format(Locale.ROOT,"cancelled_%s_%02d",kind,i);}
    private static final class Inputs {
        final Map<String,byte[]> input=new LinkedHashMap<String,byte[]>(), tasks=new TreeMap<String,byte[]>();
        byte[] control;JSONObject controller;int uid,boot;long now;boolean startup;
        Inputs copy()throws Exception{Inputs r=new Inputs();for(Map.Entry<String,byte[]> e:input.entrySet())r.input.put(e.getKey(),e.getValue().clone());
            for(Map.Entry<String,byte[]> e:tasks.entrySet())r.tasks.put(e.getKey(),e.getValue().clone());
            r.control=control.clone();r.controller=json(raw(controller));r.uid=uid;r.boot=boot;r.now=now;r.startup=startup;return r;}
        JSONObject object(String role)throws Exception{return json(input.get(role));}
        void set(String role,JSONObject value)throws Exception{input.put(role,raw(value));String file=fileFor(role);if(file!=null)tasks.put(file,input.get(role));}
        String fileFor(String role)throws Exception{
            if(role.startsWith("cancelled_action_"))return PublicPersonalNotesAbsenceRecovery.cancelledStepName(Integer.parseInt(role.substring(17)),"action");
            if(role.startsWith("cancelled_model_"))return PublicPersonalNotesAbsenceRecovery.cancelledStepName(Integer.parseInt(role.substring(16)),"model-0");
            for(String[] p:new String[][]{{"owner","owner.json"},{"bootstrap","background-bootstrap.json"},{"cleanup","background-cleanup.json"},{"result","result.json"},
                    {"broker_receipt","background-broker-"+object("journal").getString("generation")+".json"},{"broker_output","background-broker-"+object("journal").getString("generation")+".bin"}})
                if(p[0].equals(role))return p[1];return null;
        }
        int count()throws Exception{return object("result").getInt("steps")-1;}
        JSONObject history()throws Exception{JSONArray files=new JSONArray(),requests=new JSONArray();
            for(Map.Entry<String,byte[]> e:tasks.entrySet())files.put(new JSONArray().put(e.getKey()).put(e.getValue().length).put(sha(e.getValue())));
            for(int i=1;i<=count();i++){byte[] b=input.get(key("request",i));requests.put(new JSONArray().put(object(key("model",i)).getString("run_id")).put(b.length).put(sha(b)));}
            return new JSONObject().put("schema","hepta.personal-notes-cancelled-history.v1").put("completed_actions",count()).put("startup_archive",startup)
                    .put("task_files",files).put("request_receipts",requests);}
        Map<String,byte[]> pack()throws Exception{return PublicPersonalNotesAbsenceRecovery.packCancelledInputs(input,history());}
        PublicPersonalNotesAbsenceRecovery.Request request()throws Exception{return PublicPersonalNotesAbsenceRecovery.request(pack(),control,controller,uid,
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",now,boot);}
        void startup()throws Exception{
            byte[] origin=control.clone();String digest=sha(origin),relative="session-recovery/control-session.json."+digest+".json";
            JSONObject recovery=new JSONObject().put("schema","hepta.session-recovery.v1").put("decision","blocked_interrupted")
                    .put("previous_status","blocked").put("previous_session_sha256",digest).put("read_error",JSONObject.NULL)
                    .put("interruption_latch","control-session.interrupted.json").put("recovery_pending_barrier_observed",false)
                    .put("automatic_resume",false).put("native_cleanup_independently_observed",false);
            JSONObject latch=new JSONObject().put("schema","hepta.session-interruption-latch.v1").put("app_uid",uid)
                    .put("blocked",true).put("cleanup_known",false).put("automatic_resume",false).put("recovery_reason",json(raw(recovery)));
            recovery.put("interruption_latch_observed",true).put("interruption_latch_synced",true).put("preserved_records",
                    new JSONArray().put(new JSONObject().put("original_name","control-session.json").put("bytes",origin.length).put("sha256",digest)
                            .put("path","/data/user/0/org.trillionnium.hepta.local/files/"+relative)));
            JSONObject current=json(control).put("status","interrupted").put("startup_recovery",recovery);
            current.remove("steps");current.remove("completion_evidence");current.put("task_authorization",JSONObject.NULL).put("background_request",JSONObject.NULL);
            input.put("origin_control",origin);input.put("interruption_latch",raw(latch));control=raw(current);startup=true;
        }
        void eof()throws Exception{set("broker_receipt",object("broker_receipt").put("eof_seen",true));}
        void brokerBytes(byte[] value)throws Exception{
            input.put("broker_output",value);tasks.put(fileFor("broker_output"),value);
            JSONObject broker=object("broker_receipt").put("stored_bytes",value.length).put("observed_bytes",value.length).put("stored_sha256",sha(value));set("broker_receipt",broker);
            JSONObject cleanup=object("cleanup").put("broker_output",broker);set("cleanup",cleanup);
            JSONObject background=json(raw(cleanup));background.remove("cleanup_known");background.remove("cleanup_error");
            set("result",object("result").put("background_cleanup",cleanup).put("background_session",background));
        }
    }
    private static byte[] readRef(JSONObject ref)throws Exception{Path p=Paths.get(ref.getString("path"));byte[] raw=Files.readAllBytes(p);
        check(raw.length==ref.getLong("bytes")&&sha(raw).equals(ref.getString("sha256")),"captured bytes changed: "+p);return raw;}
    private static Inputs load(Path map)throws Exception{JSONObject value=json(Files.readAllBytes(map));Inputs r=new Inputs();
        JSONObject inputs=value.getJSONObject("inputs"),task=value.getJSONObject("task_files");
        for(String k:inputs.keySet()){byte[] b=readRef(inputs.getJSONObject(k));if("current_control".equals(k))r.control=b;else r.input.put(k,b);}
        for(String k:task.keySet())r.tasks.put(k,readRef(task.getJSONObject(k)));
        JSONObject journal=r.object("journal");r.uid=journal.getInt("app_uid");r.boot=journal.getInt("boot_count");r.now=journal.getLong("expires_elapsed_ms")+3000;
        r.controller=new PersonalNotesAbsenceHostTest.Fixture().controller.put("uid",r.uid);
        return r;
    }
    private static void measure(String name,Inputs input,PublicPersonalNotesAbsenceRecovery.Request request)throws Exception{
        int bytes=0;JSONObject rows=new JSONObject();for(Map.Entry<String,byte[]> e:input.pack().entrySet()){bytes+=e.getValue().length;rows.put(e.getKey(),e.getValue().length);}
        String wire=request.wire();String cmd="CLASSPATH='"+input.controller.getString("source_path")+"' /system/bin/app_process / org.trillionnium.hepta.background.PublicPersonalNotesAbsenceMain --request '"+wire+"'";
        measurements.put(name,new JSONObject().put("complete_original_values_bytes",bytes).put("bundle_limit",262144).put("base64_gzip_wire_chars",wire.length())
                .put("wire_limit",65536).put("whole_command_utf8_bytes",cmd.getBytes(StandardCharsets.UTF_8).length).put("command_limit",60000).put("rows",rows));
        check(bytes<=262144&&wire.length()<=65536&&cmd.getBytes(StandardCharsets.UTF_8).length<60000,"original bounds retained");
    }
    private static void reject(String name,Change change)throws Exception{test(name,()->{Inputs x=captured.copy();change.run(x);refuse(name,x::request);});}
    private static void field(JSONObject object,String path,Object value)throws Exception{String[] parts=path.split("/");JSONObject p=object;
        for(int i=0;i<parts.length-1;i++)p=p.getJSONObject(parts[i]);p.put(parts[parts.length-1],value);}
    private static void rejectField(String name,String role,String path,Object value)throws Exception{reject(name,x->{JSONObject o=x.object(role);field(o,path,value);x.set(role,o);});}
    private static void reset(Inputs x){
        android.os.Process.uid=x.uid;android.provider.Settings.Global.boot=x.boot;android.os.SystemClock.now=x.now;android.os.Looper.worker=true;
        android.net.LocalSocket.reset();android.net.LocalSocket.missing=true;FakePersonalNotesRecoveryProcess.reset();
        android.system.Os.failUnlink=false;android.system.Os.failFsyncPath=null;android.system.Os.corruptPublicArchiveOnSync=false;android.system.Os.afterPublicCommitSync=null;
        RecoveryControllerIdentity.changed=false;RecoveryControllerIdentity.recorded=x.controller;
        System.setProperty("hepta.notes.fixture.apk",x.controller.optString("source_path"));
    }
    private static final class Env implements AutoCloseable {
        final Inputs x;final Path root,task,journal;final android.content.Context context;
        Env(boolean startup,boolean eof)throws Exception{
            x=captured.copy();root=Files.createTempDirectory(scratch,"client-").toRealPath();context=new android.content.Context(root.toFile());
            String worker=x.object("result").getJSONObject("model_session").getString("worker_generation");
            JSONObject session=x.object("model_session_receipt"),g=session.getJSONObject("worker_generation_cleanup");
            // Explicit host IO relocation only; the immutable original session and
            // its raw request semantics were independently verified above.
            g.put("identity_file",root.resolve("runs").resolve(worker).resolve("worker-generation.identity").toString())
                    .put("native_receipt_file",root.resolve("runs").resolve(worker).resolve("generation-cleanup-"+g.getString("cleanup_nonce")+".json").toString());
            x.input.put("model_session_receipt",raw(session));JSONObject result=x.object("result");result.getJSONObject("model_session").put("app_receipt_sha256",sha(x.input.get("model_session_receipt")));x.set("result",result);
            if(eof)x.eof();if(startup)x.startup();reset(x);
            MobiMindPrivateFiles.directory(root.resolve("control-tasks").toFile(),true);MobiMindPrivateFiles.directory(root.resolve("runs").toFile(),true);
            MobiMindPrivateFiles.directory(root.resolve("session-recovery").toFile(),true);
            task=root.resolve("control-tasks").resolve(x.object("journal").getString("task_id"));MobiMindPrivateFiles.directory(task.toFile(),true);
            journal=root.resolve(BackgroundSession.JOURNAL);write(journal,x.input.get("journal"));write(root.resolve("control-session.json"),x.control);
            for(Map.Entry<String,byte[]> e:x.tasks.entrySet())write(task.resolve(e.getKey()),e.getValue());
            for(int i=1;i<=x.count();i++){Path run=root.resolve("runs").resolve(x.object(key("model",i)).getString("run_id"));MobiMindPrivateFiles.directory(run.toFile(),true);write(run.resolve("app-receipt.json"),x.input.get(key("request",i)));}
            Path gen=root.resolve("runs").resolve(worker);MobiMindPrivateFiles.directory(gen.toFile(),true);
            for(String[] p:new String[][]{{"model_session_receipt","app-session-receipt.json"},{"native_session_receipt","native-session-result.json"},{"generation_identity","worker-generation.identity"},
                    {"generation_cleanup_receipt","generation-cleanup-"+g.getString("cleanup_nonce")+".json"}})write(gen.resolve(p[1]),x.input.get(p[0]));
            if(startup){write(root.resolve("session-recovery/control-session.json."+sha(x.input.get("origin_control"))+".json"),x.input.get("origin_control"));write(root.resolve("control-session.interrupted.json"),x.input.get("interruption_latch"));}
        }
        void originals()throws Exception{check(task.toFile().list().length==x.tasks.size(),"entire original directory membership unchanged");
            for(Map.Entry<String,byte[]> e:x.tasks.entrySet())check(Arrays.equals(e.getValue(),Files.readAllBytes(task.resolve(e.getKey()))),"entire original task bytes: "+e.getKey());}
        BackgroundSession.Cleanup run()throws Exception{return BackgroundSession.reconcile(context,()->{});}
        public void close()throws IOException{android.system.Os.failUnlink=false;android.system.Os.failFsyncPath=null;android.system.Os.afterPublicCommitSync=null;
            RecoveryControllerIdentity.changed=false;RecoveryControllerIdentity.recorded=null;System.clearProperty("hepta.notes.fixture.apk");
            try(java.util.stream.Stream<Path> stream=Files.walk(root)){for(Path p:stream.sorted(Comparator.reverseOrder()).toArray(Path[]::new))Files.deleteIfExists(p);}}
    }
    private static void write(Path path,byte[] value)throws Exception{MobiMindPrivateFiles.writeNew(path.toFile(),value);}
    private static void clientPositive(String name,boolean startup,boolean eof)throws Exception{test(name,()->{try(Env e=new Env(startup,eof)){
        BackgroundSession.Cleanup c=e.run();check(c.known&&c.personalNotesRecovery!=null&&!Files.exists(e.journal),"actual exact lease CAS");
        check(!c.evidence.getBoolean("broker_released")&&!c.evidence.getBoolean("historical_broker_release_observed"),"old failed release remains false");
        Path path=Paths.get(c.evidence.getString("personal_notes_receipt_path"));check(path.startsWith(e.root.resolve("session-recovery"))&&!path.startsWith(e.task),"separate new recovery archive");
        JSONObject receipt=json(Files.readAllBytes(path)),archives=receipt.getJSONObject("original_archives");
        check(receipt.getInt("historical_model_exit_code")==143&&!receipt.getBoolean("historical_model_receipt_valid")&&!receipt.getBoolean("historical_business_success"),"143 retained as cancellation");
        for(String k:archives.keySet()){byte[] expected="current_control".equals(k)?e.x.control:e.x.input.get(k);JSONObject ref=archives.getJSONObject(k);byte[] saved=Files.readAllBytes(path.getParent().resolve(ref.getString("file")));
            check(expected!=null&&Arrays.equals(expected,saved)&&saved.length==ref.getInt("bytes")&&sha(saved).equals(ref.getString("sha256")),"full original byte archive "+k);}
        JSONObject history=receipt.getJSONObject("cancelled_history");check(Arrays.equals(c.personalNotesRecovery.request.original("cancelled_history"),Files.readAllBytes(path.getParent().resolve(history.getString("file")))),"complete manifest durable");
        c.personalNotesRecovery.requirePersisted();e.originals();check(FakePersonalNotesRecoveryProcess.calls==1&&android.net.LocalSocket.connections==0,"one readonly synthetic checker, no broker input");
        check(BackgroundSession.reconcile(e.context,()->{}).known&&FakePersonalNotesRecoveryProcess.calls==1,"no retry on retired exact lease");
        bridge.put(name,new JSONObject().put("original_archives",archives.length()).put("all_task_files_byte_unchanged",e.x.tasks.size()).put("current_absence_samples_synthetic",true)
                .put("actual_client_and_CAS",true).put("owned_helper_process_port",true).put("actual_android_UI_ACK_executed",false)
                .put("filesystem_relocation_only","two absolute generation paths and their app-session SHA projection"));
    }});}
    private static void clientNegative(String fault)throws Exception{test("actual_client_"+fault+"_retains_lease",()->{try(Env e=new Env(true,true)){
        if("request_semantics".equals(fault)){
            String run=e.x.object(key("model",1)).getString("run_id");Path file=e.root.resolve("runs").resolve(run).resolve("app-receipt.json");
            JSONObject changed=json(Files.readAllBytes(file)).put("worker_generation","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");Files.write(file,raw(changed));
        }else if("whole_manifest_during_census".equals(fault)){
            final Path file=e.task.resolve("step-10-before.json");
            FakePersonalNotesRecoveryProcess.afterReply=()->{try{Files.write(file,new byte[]{42});}catch(IOException error){throw new IllegalStateException(error);}};
        }else if("durable_receipt_then_journal_ABA".equals(fault)){
            android.system.Os.afterPublicCommitSync=()->{try{Path replacement=e.root.resolve("replacement-lease.json");write(replacement,e.x.input.get("journal"));Files.move(replacement,e.journal,StandardCopyOption.REPLACE_EXISTING);}catch(Exception error){throw new IllegalStateException(error);}};
        }else throw new AssertionError("unknown fixture fault");
        refuse(fault,e::run);check(Files.exists(e.journal),"failed check cannot retire lease");
        check(FakePersonalNotesRecoveryProcess.calls==("request_semantics".equals(fault)?0:1),"no checker before original semantic validation / one current checker");
        check(android.net.LocalSocket.connections==0,"no broker input or replay");
        check(Arrays.equals(captured.input.get("cleanup"),Files.readAllBytes(e.task.resolve("background-cleanup.json"))),"old cleanup failure bytes preserved");
        if(!"whole_manifest_during_census".equals(fault))e.originals();
    }});}
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("actual map and empty scratch required");scratch=Paths.get(args[1]);Files.createDirectory(scratch);captured=load(Paths.get(args[0]));
        test("actual_50af_complete_pack_and_wire",()->{PublicPersonalNotesAbsenceRecovery.Request r=captured.request();measure("direct",captured,r);
            check(r.cancelledAfterActions&&!r.postModelDrained&&!r.releasedBeforeModel,"distinct cancellation kind");
            check(PublicPersonalNotesAbsenceRecovery.fromWire(r.wire()).wire().equals(r.wire()),"full exact roundtrip");
            for(Map.Entry<String,byte[]> e:captured.input.entrySet())r.requireOriginalBytes(e.getKey(),e.getValue());
            for(Map.Entry<String,byte[]> e:captured.tasks.entrySet())r.requireTaskWitness(e.getKey(),e.getValue());
            PublicPersonalNotesRecoveryClient.requireDrainedGeneration(r);
        });
        test("actual_history_authored_startup_archive_and_wire",()->{Inputs x=captured.copy();x.startup();PublicPersonalNotesAbsenceRecovery.Request r=x.request();measure("startup_archive",x,r);
            check(r.cancelledAfterActions&&PublicPersonalNotesAbsenceRecovery.fromWire(r.wire()).wire().equals(r.wire()),"startup exact wire");});
        test("actual_history_authored_EOF_only_successor",()->{Inputs x=captured.copy();x.eof();PublicPersonalNotesAbsenceRecovery.Request r=x.request();measure("eof_successor",x,r);
            check(!r.recordedOwnedIdentity().getBoolean("historical_business_success")&&!r.recordedOwnedIdentity().getBoolean("historical_background_cleanup_known"),"EOF never success");});
        reject("terminal_third_line_refused",x->x.brokerBytes((new String(x.input.get("broker_output"),StandardCharsets.UTF_8)+"{}\n").getBytes(StandardCharsets.UTF_8)));
        reject("terminal_incomplete_final_line_refused",x->x.brokerBytes(Arrays.copyOf(x.input.get("broker_output"),x.input.get("broker_output").length-1)));
        reject("terminal_other_shared_field_change_refused",x->{String[] lines=new String(x.input.get("broker_output"),StandardCharsets.UTF_8).split("\n");JSONObject last=json(lines[1].getBytes(StandardCharsets.UTF_8));last.put("display_id",569);x.brokerBytes((lines[0]+"\n"+last.toString()+"\n").getBytes(StandardCharsets.UTF_8));});
        rejectField("action_worker_not_drained_refused","cancelled_action_01","action_execution/worker_drained",false);
        rejectField("action_owner_changed_refused","cancelled_action_01","action_execution/authorization_sha256",sha(new byte[]{1}));
        rejectField("regular_exit_zero_not_cancelled","model_session_receipt","exit_code",0);
        rejectField("cancel143_business_receipt_cannot_be_true","result","model_session/receipt_valid",true);
        reject("startup_origin_missing_refused",x->{x.startup();x.input.remove("origin_control");});
        reject("startup_latch_wrong_origin_refused",x->{x.startup();JSONObject l=x.object("interruption_latch");l.getJSONObject("recovery_reason").put("previous_session_sha256",sha(new byte[]{1}));x.input.put("interruption_latch",raw(l));});
        reject("broker_successor_extra_change_refused",x->{x.eof();x.set("broker_receipt",x.object("broker_receipt").put("read_failed",true));});
        reject("task_manifest_extra_action_refused",x->x.tasks.put("step-10-action.json",new byte[]{1}));
        reject("task_manifest_missing_final_observation_refused",x->x.tasks.remove("step-10-before.json"));
        test("request_semantics_rechecked_even_with_rebound_manifest",()->{Inputs x=captured.copy();JSONObject req=x.object(key("request",1));req.put("worker_generation","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");x.input.put(key("request",1),raw(req));
            PublicPersonalNotesAbsenceRecovery.Request r=x.request();refuse("actual_raw_request_wrong_generation",()->r.requireOriginalBytes(key("request",1),x.input.get(key("request",1))));});
        test("fresh_two_samples_required_and_old_success_stays_false",()->{PublicPersonalNotesAbsenceRecovery.Request r=captured.request();JSONObject p=PersonalNotesAbsenceHostTest.proof(r);
            check(PublicPersonalNotesAbsenceRecovery.validate(p,r,r.started+21,r.requestBoot).getBoolean("cleanup_known"),"synthetic current absence can validate");
            p.getJSONObject("after").getJSONObject("physical").put("0",sha(new byte[]{1}));refuse("physical_changed",()->PublicPersonalNotesAbsenceRecovery.validate(p,r,r.started+21,r.requestBoot));});
        clientPositive("actual_client_direct_raw_archive_and_exact_CAS",false,false);
        clientPositive("actual_client_startup_EOF_archive_and_exact_CAS",true,true);
        for(String fault:new String[]{"request_semantics","whole_manifest_during_census","durable_receipt_then_journal_ABA"})clientNegative(fault);
        System.out.println(new JSONObject().put("schema","hepta.notes-cancelled-absence-host.v1").put("all_pass",true).put("cases",cases).put("assertions",assertions)
                .put("case_names",names).put("rejections",rejections).put("measurements",measurements).put("client_bridge",bridge).put("phone_operations",0)
                .put("current_absence_claimed",false).put("business_success_claimed",false).put("historical_inputs_actual",true).put("framework_and_clock_fixtures_synthetic",true));
    }
}
