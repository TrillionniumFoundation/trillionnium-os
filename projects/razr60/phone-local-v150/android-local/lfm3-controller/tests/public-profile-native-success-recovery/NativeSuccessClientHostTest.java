package org.trillionnium.hepta.local;

import android.os.SystemClock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.PublicProfileBusinessAbsenceRecovery;
import org.trillionnium.hepta.background.PublicProfileBusinessRecoveryHostTest;
import org.trillionnium.hepta.background.ProfileIdentity;

/** The real Client Inputs/Prepared boundary and existing explicit Android IO ports.
 * No collect/afterEffect/socket/commit is invoked. No opaque Receipt is made.
 * First case failure ends this process; each constructed Env is really closed. */
public final class NativeSuccessClientHostTest {
    private interface Work {void run(PublicProfileBusinessClientHostTest.Env e)throws Exception;}
    private static final JSONArray CASES=new JSONArray();
    private static int assertions;
    private static void need(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void test(String name,Work work)throws Exception{
        PublicProfileBusinessClientHostTest.test(name,()->{
            try(PublicProfileBusinessClientHostTest.Env e=new PublicProfileBusinessClientHostTest.Env()){work.run(e);
                need(FakeBusinessRecoveryProcess.calls==0&&e.commits()==0&&Files.exists(e.journal),"no checker, cleanup effect or journal CAS");}
        });
        CASES.put(new JSONObject().put("name",name).put("passed",true));
    }
    private static PublicProfileBusinessRecoveryClient.PreparedRetainedCleanup prepare(PublicProfileBusinessClientHostTest.Env e)throws Exception{
        return PublicProfileBusinessRecoveryClient.prepareRetainedCleanup(e.context,MobiMindPrivateFiles.read(e.journal.toFile(),16384,true),e.check());
    }
    private static void refused(PublicProfileBusinessClientHostTest.Work work)throws Exception{
        try{work.run();}catch(Exception expected){need(expected.getMessage()!=null&&!expected.getMessage().isEmpty(),"explicit refusal");return;}
        throw new AssertionError("changed original/current boundary accepted");
    }
    private static Path nativePath(PublicProfileBusinessClientHostTest.Env e,String leaf)throws Exception{
        for(String p:PublicProfileBusinessClientHostTest.originals.keySet())if(p.startsWith("runs/")&&p.endsWith("/"+leaf))return e.dir.resolve(p);
        throw new AssertionError("actual native leaf missing");
    }
    private static Path generation(PublicProfileBusinessClientHostTest.Env e)throws Exception{
        JSONObject result=new JSONObject(new String(Files.readAllBytes(e.result),StandardCharsets.UTF_8));
        return e.dir.resolve("runs").resolve(result.getJSONObject("model_session").getString("worker_generation"));
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("exact original path map, new report");
        JSONObject report=new JSONObject().put("schema","hepta.native-success-recovery-client-cases.v1").put("all_pass",false);
        Throwable failure=null;
        try{
            PublicProfileBusinessClientHostTest.originals=PublicProfileBusinessRecoveryHostTest.loadExternalOriginals(Paths.get(args[0]));
            test("actual_complete_client_read_and_unchanged_pre_effect_check",e->{
                PublicProfileBusinessRecoveryClient.PreparedRetainedCleanup p=prepare(e);
                need(p.request.verifiedNativeSuccessBeforeCleanup&&p.request.manifest.paths().size()==131,"real Request on complete Client Inputs");
                need(p.request.steps==5&&p.request.modelRequests==5&&p.request.retainedAfterBusiness,"historical classification");
                p.beforeEffect();need(p.archiveBytes().length>0,"actual complete archive");
                for(Map.Entry<String,byte[]> row:PublicProfileBusinessClientHostTest.originals.entrySet())
                    need(Arrays.equals(row.getValue(),Files.readAllBytes(e.dir.resolve(row.getKey()))),"actual bytes preserved");
                e.unchanged();
            });
            test("extra_generation_member_before_prepare_refused",e->{
                MobiMindPrivateFiles.writeNew(generation(e).resolve("unexpected.txt").toFile(),new byte[]{1});refused(()->prepare(e));
            });
            test("extra_request_member_before_prepare_refused",e->{
                MobiMindPrivateFiles.writeNew(nativePath(e,"grammar.gbnf").resolveSibling("unexpected.txt").toFile(),new byte[]{1});refused(()->prepare(e));
            });
            test("missing_request_member_before_prepare_refused",e->{
                Files.delete(nativePath(e,"grammar.gbnf"));refused(()->prepare(e));
            });
            test("same_bytes_native_inode_replacement_after_prepare_refused",e->{
                PublicProfileBusinessRecoveryClient.PreparedRetainedCleanup p=prepare(e);
                PublicProfileBusinessClientHostTest.replaceSameBytes(nativePath(e,"grammar.gbnf"));refused(p::beforeEffect);
            });
            test("generation_directory_identity_replacement_after_prepare_refused",e->{
                PublicProfileBusinessRecoveryClient.PreparedRetainedCleanup p=prepare(e);
                Path original=generation(e),saved=original.resolveSibling(original.getFileName()+".saved");Files.move(original,saved);
                MobiMindPrivateFiles.directory(original.toFile(),false);
                try(java.util.stream.Stream<Path> rows=Files.list(saved)){
                    for(Path f:rows.toArray(Path[]::new))MobiMindPrivateFiles.writeNew(original.resolve(f.getFileName()).toFile(),Files.readAllBytes(f));
                }
                refused(p::beforeEffect);
            });
            test("extra_task_member_after_prepare_refused",e->{
                PublicProfileBusinessRecoveryClient.PreparedRetainedCleanup p=prepare(e);
                MobiMindPrivateFiles.writeNew(e.task.resolve("unexpected.json").toFile(),new byte[]{123,125});refused(p::beforeEffect);
            });
            test("permission_preparation_after_prepare_refused",e->{
                PublicProfileBusinessRecoveryClient.PreparedRetainedCleanup p=prepare(e);LocalProbeApplication.permissionBusy=true;
                try{refused(p::beforeEffect);}finally{LocalProbeApplication.permissionBusy=false;}
            });
            test("retired_reservation_after_prepare_refused",e->{
                PublicProfileBusinessRecoveryClient.PreparedRetainedCleanup p=prepare(e);FakeBusinessRecoveryProcess.cancelled=true;refused(p::beforeEffect);
            });
            test("original_request_deadline_after_prepare_refused",e->{
                PublicProfileBusinessRecoveryClient.PreparedRetainedCleanup p=prepare(e);SystemClock.now=p.request.deadline;refused(p::beforeEffect);
            });
            report.put("all_pass",true);
        }catch(Throwable ex){failure=ex;report.put("failure_class",ex.getClass().getName()).put("failure",String.valueOf(ex));}
        report.put("cases",CASES.length()).put("assertions",assertions).put("case_results",CASES)
            .put("existing_env_assertions",PublicProfileBusinessClientHostTest.assertions)
            .put("actual_inputs_and_private_file_checks",true).put("android_stat_uid_clock_pm_synthetic",true)
            .put("actual_after_effect_executed",false).put("actual_absence_collected",false).put("journal_cas_executed",false)
            .put("maintenance_protocol_executed",false).put("phone_operations",0).put("action_dispatches",0).put("business_verified",false);
        Files.write(Paths.get(args[1]),report.toString(2).getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println(report.toString());
        if(failure instanceof Exception)throw (Exception)failure;if(failure instanceof Error)throw (Error)failure;
    }
}
