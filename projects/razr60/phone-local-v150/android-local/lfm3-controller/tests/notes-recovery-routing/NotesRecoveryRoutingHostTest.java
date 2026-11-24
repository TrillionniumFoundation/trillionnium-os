package org.trillionnium.hepta.local;

import android.content.Context;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/** Actual recorded startup origin; framework queues, PM and checker IO stay explicit host ports. */
public final class NotesRecoveryRoutingHostTest {
    private static int cases,assertions;
    private static final JSONArray names=new JSONArray();
    private static JSONObject current;
    private static Path scratch;
    private static Class<?> helper,environment;
    private static final JSONObject observations=new JSONObject();
    interface Work {void run()throws Exception;}
    private static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void test(String name,Work work)throws Exception{work.run();cases++;names.put(name);}
    private static JSONObject json(byte[] raw){return new JSONObject(new String(raw,StandardCharsets.UTF_8));}
    private static byte[] bytes(JSONObject value){return value.toString().getBytes(StandardCharsets.UTF_8);}
    private static Field field(Class<?> type,String name)throws Exception{Field f=type.getDeclaredField(name);f.setAccessible(true);return f;}
    private static Object get(Object object,String name)throws Exception{return field(object.getClass(),name).get(object);}
    private static void set(Object object,String name,Object value)throws Exception{field(object.getClass(),name).set(object,value);}
    private static Object invoke(Object target,String name,Class<?>[] types,Object... args)throws Exception{
        Method method=target.getClass().getDeclaredMethod(name,types);method.setAccessible(true);
        try{return method.invoke(target,args);}catch(InvocationTargetException error){
            Throwable cause=error.getCause();if(cause instanceof Exception)throw (Exception)cause;
            if(cause instanceof Error)throw (Error)cause;throw error;
        }
    }
    private static byte[] readRef(JSONObject ref)throws Exception{
        Path path=Paths.get(ref.getString("path"));byte[] raw=Files.readAllBytes(path);
        check(raw.length==ref.getLong("bytes")&&HeptaAccessibilityService.sha(raw).equals(ref.getString("sha256")),"actual ref changed");return raw;
    }
    private static void delete(Path path)throws IOException{
        try(java.util.stream.Stream<Path> stream=Files.walk(path)){
            for(Path p:stream.sorted(Comparator.reverseOrder()).toArray(Path[]::new))Files.deleteIfExists(p);
        }
    }
    private static final class Env implements java.io.Closeable {
        final Object original,input;
        final Path root,task,journal;
        final Context context;
        final RecoveryOwnerButtonBridge ui;
        final HeptaAccessibilityService service;
        final byte[] actualControl,actualLatch,actualOrigin;
        @SuppressWarnings("unchecked")
        Env()throws Exception{
            Constructor<?> constructor=environment.getDeclaredConstructor(boolean.class,boolean.class);constructor.setAccessible(true);
            original=constructor.newInstance(false,false);input=get(original,"x");
            root=(Path)get(original,"root");task=(Path)get(original,"task");journal=(Path)get(original,"journal");context=(Context)get(original,"context");
            Map<String,byte[]> originals=(Map<String,byte[]>)get(input,"input"),tasks=(Map<String,byte[]>)get(input,"tasks");
            JSONObject notes=current.getJSONObject("notes");actualControl=readRef(notes.getJSONObject("current_control"));
            actualLatch=readRef(notes.getJSONObject("interruption_latch"));actualOrigin=readRef(notes.getJSONObject("origin_control"));
            check(Arrays.equals((byte[])get(input,"control"),actualOrigin),"exact old control remains the real archived origin");
            set(input,"control",actualControl);set(input,"startup",true);
            originals.put("origin_control",actualOrigin);originals.put("interruption_latch",actualLatch);
            byte[] broker=readRef(notes.getJSONObject("broker_receipt"));originals.put("broker_receipt",broker);
            String brokerName="background-broker-8139e9c2-d2d2-439a-8a8f-c6331b4ec537.json";tasks.put(brokerName,broker);
            Files.write(task.resolve(brokerName),broker);Files.write(root.resolve("control-session.json"),actualControl);
            MobiMindPrivateFiles.writeNew(root.resolve("control-session.interrupted.json").toFile(),actualLatch);
            MobiMindPrivateFiles.writeNew(root.resolve("session-recovery/control-session.json."+HeptaAccessibilityService.sha(actualOrigin)+".json").toFile(),actualOrigin);
            service=new HeptaAccessibilityService();HeptaAccessibilityService.live=service;
            ui=new RecoveryOwnerButtonBridge(context);android.os.Looper.worker=false;
            LocalProbeApplication.permissionBusy=false;
        }
        void route()throws Exception{ui.reconcileBackgroundFromOwnerButton();}
        void worker(){ui.recoveryWorker.drain();}
        void main(){ui.main.drain();}
        void unchanged()throws Exception{
            invoke(original,"originals",new Class<?>[0]);
            check(Arrays.equals(actualControl,Files.readAllBytes(root.resolve("control-session.json"))),"current interrupted controller not rewritten");
            check(Arrays.equals(actualLatch,Files.readAllBytes(root.resolve("control-session.interrupted.json"))),"interruption latch not acknowledged");
            check(Arrays.equals(actualOrigin,Files.readAllBytes(root.resolve("session-recovery/control-session.json."+HeptaAccessibilityService.sha(actualOrigin)+".json"))),"old archived controller byte unchanged");
        }
        public void close()throws IOException{
            HeptaAccessibilityService.live=null;LocalProbeApplication.permissionBusy=false;
            try{((AutoCloseable)original).close();}catch(IOException error){throw error;}catch(Exception error){throw new IOException(error);}
        }
    }
    private static void failedBeforeChecker(Env e,String reason)throws Exception{
        e.route();check(e.ui.businessCalls==0,"not a profile route");e.worker();e.main();
        check(Files.exists(e.journal)&&FakePersonalNotesRecoveryProcess.calls==0,"rejected original cannot retire lease or launch checker");
        check(e.ui.state.contains(reason)&&e.ui.blocked&&!e.ui.recovering,"ordinary failure remains blocked");
        check(e.service.webAccepted==0&&android.net.LocalSocket.connections==0,"no accepted receipt or old broker command");
    }
    private static JSONObject actualReceipt(Env e)throws Exception{
        try(java.util.stream.Stream<Path> paths=Files.walk(e.root.resolve("session-recovery"))){
            Path[] candidates=paths.filter(p->p.getFileName().toString().matches("background-personal-notes-absence-[0-9a-f-]{36}\\.json")).toArray(Path[]::new);
            check(candidates.length==1,"one actual client durable receipt");return json(Files.readAllBytes(candidates[0]));
        }
    }
    private static void profile(String label)throws Exception{
        JSONObject mapping=json(readRef(current.getJSONObject("profile_original_maps").getJSONObject(label)));
        Path root=Files.createTempDirectory(scratch,"profile-").toRealPath();
        try{
            JSONObject control=null;
            for(String name:new String[]{"background-session.active.json","control-session.json"}){
                byte[] raw=Files.readAllBytes(Paths.get(mapping.getString(name)));MobiMindPrivateFiles.writeNew(root.resolve(name).toFile(),raw);
                if(name.equals("control-session.json"))control=json(raw);
            }
            if(control!=null&&"interrupted".equals(control.optString("status"))){
                String digest=control.getJSONObject("startup_recovery").getString("previous_session_sha256"),relative="session-recovery/control-session.json."+digest+".json";
                Files.createDirectory(root.resolve("session-recovery"));MobiMindPrivateFiles.writeNew(root.resolve(relative).toFile(),Files.readAllBytes(Paths.get(mapping.getString(relative))));
            }
            Context context=new Context(root.toFile());check(LegacyRoutingProbe.hasBusinessOrigin(context)&&PublicProfileBusinessRecoveryClient.hasBusinessOrigin(context),"valid profile "+label+" keeps its original branch");
        }finally{delete(root);}
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=3)throw new IllegalArgumentException("old actual map, new actual map, and new scratch required");
        scratch=Paths.get(args[2]);Files.createDirectory(scratch);current=json(Files.readAllBytes(Paths.get(args[1])));
        check("hepta.notes-recovery-routing-actual-inputs.v1".equals(current.getString("schema")),"current actual map kind");
        helper=Class.forName("org.trillionnium.hepta.local.NotesCancelledAbsenceHostTest");
        Method load=helper.getDeclaredMethod("load",Path.class);load.setAccessible(true);Object captured=load.invoke(null,Paths.get(args[0]));
        field(helper,"captured").set(null,captured);field(helper,"scratch").set(null,scratch);
        environment=Class.forName("org.trillionnium.hepta.local.NotesCancelledAbsenceHostTest$Env");
        test("real_current_startup_archive_reproduces_old_route_and_selects_personal",()->{try(Env e=new Env()){
            check("interrupted".equals(json(e.actualControl).getString("status"))&&json(e.actualOrigin).getInt("steps")==10,"actual outer and original ten-step history");
            check(LegacyRoutingProbe.hasBusinessOrigin(e.context),"old actual classifier reproduces wrong profile selection");
            check(!PublicProfileBusinessRecoveryClient.hasBusinessOrigin(e.context),"personal origin does not enter profile business recovery");
            check(FakePersonalNotesRecoveryProcess.calls==0&&Files.exists(e.journal),"classification grants no cleanup");e.unchanged();
        }});
        test("actual_owner_button_personal_client_exact_CAS_and_service_acceptance",()->{try(Env e=new Env()){
            e.route();check(e.ui.businessCalls==0&&e.ui.recoveryWorker.size()==1&&FakePersonalNotesRecoveryProcess.calls==0,"real entry queues only ordinary recovery");
            e.worker();check(!Files.exists(e.journal)&&FakePersonalNotesRecoveryProcess.calls==1&&e.ui.main.size()==1,"real personal client and exact lease CAS precede callback");
            JSONObject receipt=actualReceipt(e);check(receipt.getJSONObject("original_archives").length()==41,"actual startup retains all41 semantic originals");
            check(receipt.getInt("historical_model_exit_code")==143&&!receipt.getBoolean("historical_model_receipt_valid")&&!receipt.getBoolean("historical_business_success"),"cancelled disposition is not upgraded");
            e.main();check(e.ui.state.startsWith("后台空间已确认释放")&&e.service.webAccepted==1&&!e.ui.recovering&&e.ui.blocked,"actual typed Service acceptance returns without ACK");
            check(android.net.LocalSocket.connections==0,"personal current absence makes no old broker RPC");e.unchanged();
            observations.put("actual_startup_path",new JSONObject().put("raw_originals",41).put("task_files",76).put("history_exit",143).put("history_success",false)
                    .put("owner_button_and_service_methods_verbatim",true).put("actual_client_CAS",true).put("current_checker_PM_clock_and_queues_synthetic",true).put("actual_android_UI_ACK",false));
        }});
        for(String kind:new String[]{"action","observation","cancellation"})test("service_"+kind+"_work_refuses_before_checker",()->{try(Env e=new Env()){
            if(kind.equals("action"))e.service.actionPending=true;else if(kind.equals("observation"))e.service.readPending=true;else e.service.cancelPending=true;
            failedBeforeChecker(e,"原控制器观察、动作或取消工作尚未排空");e.unchanged();
        }});
        test("missing_profile_wire_with_leftover_profile_metadata_is_rejected",()->{try(Env e=new Env()){
            JSONObject journal=json(Files.readAllBytes(e.journal)).put("profile_target_sha256",HeptaAccessibilityService.sha(new byte[]{1}));Files.write(e.journal,bytes(journal));
            failedBeforeChecker(e,"profile journal is incomplete");
        }});
        test("nonprofile_is_not_enough_for_Notes_when_selection_contains_another_package",()->{try(Env e=new Env()){
            JSONObject journal=json(Files.readAllBytes(e.journal));journal.getJSONObject("selection").getJSONArray("allowed_packages").put("com.xiaomi.shop");Files.write(e.journal,bytes(journal));
            failedBeforeChecker(e,"NOTES_JOURNAL_TASK_BINDING_INVALID");
        }});
        test("nonprofile_is_not_enough_for_Notes_when_scope_owner_differs",()->{try(Env e=new Env()){
            JSONObject journal=json(Files.readAllBytes(e.journal)).put("owner_sha256",HeptaAccessibilityService.sha(new byte[]{2}));Files.write(e.journal,bytes(journal));
            failedBeforeChecker(e,"PUBLIC_SCOPE_JOURNAL_BINDING_INVALID");
        }});
        test("missing_actual_startup_archive_still_refuses_before_checker",()->{try(Env e=new Env()){
            Files.delete(e.root.resolve("session-recovery/control-session.json."+HeptaAccessibilityService.sha(e.actualOrigin)+".json"));
            e.route();e.worker();e.main();check(Files.exists(e.journal)&&FakePersonalNotesRecoveryProcess.calls==0&&e.service.webAccepted==0&&e.ui.blocked,"missing original cannot manufacture recovery");
        }});
        test("busy_service_before_acceptance_preserves_blocked_and_no_ACK",()->{try(Env e=new Env()){
            e.route();e.worker();check(!Files.exists(e.journal),"actual CAS already committed before independent service acceptance");
            e.service.capturePending=true;e.main();check(e.ui.state.startsWith("后台释放凭据未匹配原会话")&&e.ui.blocked&&e.service.webAccepted==0,"new busy observation refuses receipt acceptance");e.unchanged();
        }});
        test("valid_profile_text_keeps_business_route",()->profile("text"));
        test("valid_profile_visual_keeps_business_route",()->profile("visual"));
        System.out.println(new JSONObject().put("schema","hepta.notes-recovery-routing-host.v1").put("all_pass",true).put("cases",cases).put("assertions",assertions)
                .put("case_names",names).put("observations",observations).put("phone_operations",0).put("android_runtime_tested",false).put("real_current_absence_claimed",false));
    }
}
