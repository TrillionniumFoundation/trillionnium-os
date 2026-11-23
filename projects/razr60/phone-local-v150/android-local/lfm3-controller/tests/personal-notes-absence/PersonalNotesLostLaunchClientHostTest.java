package org.trillionnium.hepta.local;
import android.content.Context;
import android.net.LocalSocket;
import android.os.SystemClock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONObject;
import org.trillionnium.hepta.background.RecoveryControllerIdentity;

/** Complete ordinary client and journal CAS with archived input; only OS, package and checker IO are test ports. */
public final class PersonalNotesLostLaunchClientHostTest {
    private static int assertions;
    private static void need(boolean ok,String message){assertions++;if(!ok)throw new AssertionError(message);}
    private static JSONObject object(Path path)throws Exception{return new JSONObject(new String(Files.readAllBytes(path),StandardCharsets.UTF_8));}
    private static void run(JSONObject fixture,String fault)throws Exception{
        JSONObject paths=fixture.getJSONObject("records"),controller=fixture.getJSONObject("controller");
        JSONObject old=object(Paths.get(paths.getJSONObject("journal").getString("path")));String gen=old.getString("generation");
        Path dir=Files.createTempDirectory("notes-recorded-recovery").toRealPath();
        try{
            android.os.Process.uid=old.getInt("app_uid");System.setProperty("hepta.notes.fixture.apk",controller.getString("source_path"));
            RecoveryControllerIdentity.recorded=controller;android.provider.Settings.Global.boot=old.getInt("boot_count");
            SystemClock.now=old.getLong("expires_elapsed_ms")+3000;android.os.Looper.worker=true;LocalSocket.reset();LocalSocket.missing=true;
            FakePersonalNotesRecoveryProcess.reset();Context context=new Context(dir.toFile());
            Path journal=dir.resolve(BackgroundSession.JOURNAL),control=dir.resolve("control-session.json");
            MobiMindPrivateFiles.directory(dir.resolve("control-tasks").toFile(),true);Path task=dir.resolve("control-tasks").resolve(old.getString("task_id"));
            MobiMindPrivateFiles.directory(task.toFile(),true);
            Map<String,Path> files=new LinkedHashMap<String,Path>();Map<String,byte[]> bytes=new LinkedHashMap<String,byte[]>();
            for(String key:paths.keySet()){
                JSONObject row=paths.getJSONObject(key);Path p=Paths.get(row.getString("path"));byte[] raw=Files.readAllBytes(p);
                need(raw.length==row.getInt("bytes")&&HeptaAccessibilityService.sha(raw).equals(row.getString("sha256")),"source receipt "+key);
                Path target="journal".equals(key)?journal:"current_control".equals(key)?control:task.resolve(p.getFileName());
                files.put(key,target);bytes.put(key,raw);MobiMindPrivateFiles.writeNew(target.toFile(),raw);
            }
            boolean interrupted=fault.startsWith("startup");
            if(interrupted){
                byte[] original=bytes.get("current_control");String sha=HeptaAccessibilityService.sha(original),relative="session-recovery/control-session.json."+sha+".json";
                Path archive=dir.resolve(relative),latch=dir.resolve("control-session.interrupted.json");
                MobiMindPrivateFiles.directory(archive.getParent().toFile(),true);
                MobiMindPrivateFiles.writeNew(archive.toFile(),original);
                JSONObject recovery=new JSONObject().put("schema","hepta.session-recovery.v1").put("decision","blocked_interrupted")
                        .put("previous_status","blocked").put("previous_session_sha256",sha).put("read_error",JSONObject.NULL)
                        .put("interruption_latch","control-session.interrupted.json").put("recovery_pending_barrier_observed",false)
                        .put("automatic_resume",false).put("native_cleanup_independently_observed",false);
                JSONObject barrier=new JSONObject().put("schema","hepta.session-interruption-latch.v1").put("app_uid",old.getInt("app_uid"))
                        .put("blocked",true).put("cleanup_known",false).put("automatic_resume",false).put("recovery_reason",new JSONObject(recovery.toString()));
                if("startup_bad_latch".equals(fault))barrier.getJSONObject("recovery_reason").put("previous_session_sha256",HeptaAccessibilityService.sha(new byte[]{1}));
                byte[] latchRaw=barrier.toString().getBytes(StandardCharsets.UTF_8);MobiMindPrivateFiles.writeNew(latch.toFile(),latchRaw);
                recovery.put("interruption_latch_observed",true).put("interruption_latch_synced",true).put("preserved_records",
                        new org.json.JSONArray().put(new JSONObject().put("original_name","control-session.json").put("bytes",original.length).put("sha256",sha)
                        .put("path","/data/user/0/org.trillionnium.hepta.local/files/"+relative)));
                JSONObject current=object(control).put("status","interrupted").put("startup_recovery",recovery);
                current.remove("steps");current.remove("completion_evidence");current.put("task_authorization",JSONObject.NULL).put("background_request",JSONObject.NULL);
                byte[] currentRaw=current.toString().getBytes(StandardCharsets.UTF_8);Files.write(control,currentRaw);bytes.put("current_control",currentRaw);
                bytes.put("origin_control",original);files.put("origin_control",archive);bytes.put("interruption_latch",latchRaw);files.put("interruption_latch",latch);
                if("startup_archive_during".equals(fault))FakePersonalNotesRecoveryProcess.afterReply=()->{try{Files.write(archive,new byte[]{42});}catch(Exception e){throw new IllegalStateException(e);}};
            }
            boolean expectSuccess=fault.isEmpty()||"startup".equals(fault);
            if("extra_before".equals(fault))MobiMindPrivateFiles.writeNew(task.resolve("unseen-terminal.json").toFile(),new byte[]{42});
            if("extra_during".equals(fault))FakePersonalNotesRecoveryProcess.afterReply=()->{
                try{MobiMindPrivateFiles.writeNew(task.resolve("step-01-action.json").toFile(),new byte[]{42});}
                catch(Exception e){throw new IllegalStateException(e);}};
            if("apk_during".equals(fault))FakePersonalNotesRecoveryProcess.afterReply=()->RecoveryControllerIdentity.changed=true;
            if("checker_exit".equals(fault))FakePersonalNotesRecoveryProcess.exit=70;
            BackgroundSession.Cleanup cleanup=null;
            try{cleanup=BackgroundSession.reconcile(context,()->{});}catch(Exception refused){if(expectSuccess)throw refused;}
            if(expectSuccess){
                need(cleanup!=null&&cleanup.known&&cleanup.personalNotesRecovery!=null&&!Files.exists(journal),"one actual journal retired");
                need(FakePersonalNotesRecoveryProcess.calls==1&&LocalSocket.connections==0,"independent checker only");
                JSONObject ev=cleanup.evidence;need(ev.getBoolean("historical_broker_release_observed")&&!ev.getBoolean("broker_released"),"original terminal separated from live release response");
                JSONObject commit=object(Paths.get(ev.getString("personal_notes_receipt_path"))),arch=commit.getJSONObject("original_archives");
                need(arch.length()==(interrupted?13:11)&&commit.getBoolean("control_cas_before_lease_unlink"),"nine task artifacts plus journal and current blocked control archived");
                for(String key:bytes.keySet()){JSONObject row=arch.getJSONObject(key);
                    need(java.util.Arrays.equals(bytes.get(key),Files.readAllBytes(task.resolve(row.getString("file")))),"durable archive "+key);}
                need(BackgroundSession.reconcile(context,()->{}).known&&FakePersonalNotesRecoveryProcess.calls==1,"receipt consumed once");
            }else need(cleanup==null&&Files.exists(journal)&&FakePersonalNotesRecoveryProcess.calls==("extra_before".equals(fault)||"startup_bad_latch".equals(fault)?0:1),"refusal preserves lease");
            for(String key:bytes.keySet())if((!"journal".equals(key)||Files.exists(journal))&&!("startup_archive_during".equals(fault)&&"origin_control".equals(key)))
                need(java.util.Arrays.equals(bytes.get(key),Files.readAllBytes(files.get(key))),"original bytes retained "+key);
        }finally{
            RecoveryControllerIdentity.changed=false;RecoveryControllerIdentity.recorded=null;android.os.Process.uid=12345;System.clearProperty("hepta.notes.fixture.apk");
            try(java.util.stream.Stream<Path> stream=Files.walk(dir)){for(Path path:stream.sorted(Comparator.reverseOrder()).toArray(Path[]::new))Files.deleteIfExists(path);}
        }
    }
    public static void main(String[] args)throws Exception{
        JSONObject data=object(Paths.get(args[0]));String[] faults={"","startup","startup_bad_latch","startup_archive_during","extra_before","extra_during","apk_during","checker_exit"};
        for(String fault:faults)run(data,fault);
        System.out.println(new JSONObject().put("all_pass",true).put("cases",faults.length).put("assertions",assertions).put("phone_operations",0)
                .put("original_task","8a2c11d79af547c8a800aeeda47d5220").put("actual_client_archive_and_cas",true));
    }
}
