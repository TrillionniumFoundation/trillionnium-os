package org.trillionnium.hepta.local;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

/** Explicit host substitute for native generation entry and its cleanup helper. */
final class OwnedGenerationScope {
    static volatile boolean nextKnown=true,nextForce=false;
    static volatile CountDownLatch entered,proceed;
    static int cleanupCalls;
    static final class Cleanup {
        final boolean known,forceKnown,forceUsed;
        final JSONObject evidence;
        Cleanup(boolean known,boolean forceKnown,boolean forceUsed,JSONObject evidence){
            this.known=known;this.forceKnown=forceKnown;this.forceUsed=forceUsed;this.evidence=evidence;
        }
        boolean unforced(){return known&&forceKnown&&!forceUsed;}
    }
    final WorkerGenerationProof.Expected expected;
    final long workerPid,workerStart;
    private final File directory;
    private final boolean known,force;
    OwnedGenerationScope(File files,File runner,String generation,String task,String token)throws Exception{
        directory=new File(new File(files,"runs"),generation);
        long pid=android.os.Process.myPid();
        long start=WorkerGenerationProof.procStart(Files.readAllBytes(new File("/proc/"+pid+"/stat").toPath()),pid);
        String boot=new String(Files.readAllBytes(new File("/proc/sys/kernel/random/boot_id").toPath()),StandardCharsets.US_ASCII).trim();
        expected=new WorkerGenerationProof.Expected(task,generation,token,boot,android.os.Process.myUid(),pid,start);
        workerPid=pid+100000;workerStart=start+1;known=nextKnown;force=nextForce;
        String raw="hepta.worker-generation.v1\ntask_id="+task+"\nworker_generation="+generation
                +"\nscope_token="+token+"\napp_uid="+expected.uid+"\napp_pid="+pid
                +"\napp_start_ticks="+start+"\nleader_pid="+workerPid+"\nleader_start_ticks="+workerStart
                +"\npgid="+workerPid+"\nboot_id="+boot+"\n";
        MobiMindPrivateFiles.writeNew(new File(directory,"worker-generation.identity"),raw.getBytes(StandardCharsets.US_ASCII));
    }
    void initialEnvironment(Map<String,String> env){
        String[] values={"v1",expected.task,expected.generation,expected.token,Long.toString(expected.appStart),expected.boot};
        for(int i=0;i<values.length;i++)env.put(WorkerGenerationProof.ENVIRONMENT[i],values[i]);
    }
    Cleanup finish(boolean exited,long submitted,long deadline){
        try{
            if(!exited)throw new AssertionError("fixture cleanup before held process exit");
            cleanupCalls++;
            CountDownLatch notify=entered,wait=proceed;if(notify!=null)notify.countDown();
            if(wait!=null&&!wait.await(5,TimeUnit.SECONDS))throw new AssertionError("fixture cleanup release not supplied");
            WorkerGenerationProof.cleanupDeadline(System.nanoTime(),submitted,deadline);
            byte[] identity=MobiMindPrivateFiles.read(new File(directory,"worker-generation.identity"),2047,true).bytes;
            WorkerGenerationProof.identity(identity,expected);
            File receipt=new File(directory,"host-fixture-cleanup.json");
            byte[] contents="{\"host_fixture_only\":true,\"kernel_generation_absence_proven\":false}\n".getBytes(StandardCharsets.UTF_8);
            MobiMindPrivateFiles.writeNew(receipt,contents);
            JSONObject evidence=new JSONObject().put("schema","hepta.worker-generation.app-cleanup.v1")
                    .put("task_id",expected.task).put("worker_generation",expected.generation).put("scope_token",expected.token)
                    .put("direct_process_exit_observed",true).put("cleanup_known",known)
                    .put("generation_unforced",known&&!force).put("native_receipt_file",receipt.getPath())
                    .put("native_receipt_sha256",MobiMindContract.sha(contents)).put("host_fixture_only",true);
            return new Cleanup(known,true,force,evidence);
        }catch(Exception failure){throw new IllegalStateException("host generation fixture failed",failure);}
    }
    static void reset(){nextKnown=true;nextForce=false;entered=null;proceed=null;cleanupCalls=0;}
}
