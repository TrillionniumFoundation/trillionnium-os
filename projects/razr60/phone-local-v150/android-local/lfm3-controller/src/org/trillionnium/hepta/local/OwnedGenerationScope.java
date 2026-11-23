package org.trillionnium.hepta.local;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

/** App-UID generation cleanup, run only by the engine's serial worker.
 * A held Java Process exit is a prerequisite, never the generation-absence proof.
 */
final class OwnedGenerationScope {
    static final class Cleanup {
        final boolean known,forceKnown,forceUsed;
        final JSONObject evidence;
        Cleanup(boolean known,boolean forceKnown,boolean forceUsed,JSONObject evidence){
            this.known=known;this.forceKnown=forceKnown;this.forceUsed=forceUsed;this.evidence=evidence;
        }
        boolean unforced(){return known&&forceKnown&&!forceUsed;}
    }
    private final WorkerGenerationProof.Expected expected;
    private final File files,directory,runner,nativeDirectory,identityFile;
    private volatile Process cleanupProcess;
    private Cleanup sealed;
    private boolean attempted;
    OwnedGenerationScope(File files,File runner,String generation,String task,String token)throws Exception{
        this.files=files.getCanonicalFile();this.runner=runner.getCanonicalFile();
        nativeDirectory=this.runner.getParentFile();
        directory=new File(new File(this.files,"runs"),generation);
        identityFile=new File(directory,"worker-generation.identity");
        WorkerGenerationProof.need(directory.equals(directory.getCanonicalFile()),"generation directory is not direct");
        MobiMindPrivateFiles.directory(this.files,false);
        MobiMindPrivateFiles.directory(new File(this.files,"runs"),false);
        MobiMindPrivateFiles.directory(directory,false);
        WorkerGenerationProof.need(!identityFile.exists(),"early generation identity already exists");
        long pid=android.os.Process.myPid();
        long start=WorkerGenerationProof.procStart(readProc(new File("/proc/"+pid+"/stat"),8192),pid);
        byte[] bootBytes=readProc(new File("/proc/sys/kernel/random/boot_id"),80);
        String boot=new String(bootBytes,StandardCharsets.US_ASCII);
        WorkerGenerationProof.need(boot.endsWith("\n")&&boot.length()==37,"boot identity unavailable");
        expected=new WorkerGenerationProof.Expected(task,generation,token,boot.substring(0,36),
                android.os.Process.myUid(),pid,start);
    }
    void initialEnvironment(Map<String,String> env){
        String[] values={"v1",expected.task,expected.generation,expected.token,
                Long.toString(expected.appStart),expected.boot};
        for(int i=0;i<values.length;i++)env.put(WorkerGenerationProof.ENVIRONMENT[i],values[i]);
    }
    synchronized Cleanup finish(boolean directExitObserved,long finisherSubmitted,long finisherDeadline){
        if(sealed!=null)return sealed;
        JSONObject audit=new JSONObject(),nativeAudit=null;
        boolean known=false,forceKnown=false,forceUsed=false,helperExited=false,helperForced=false;
        Integer helperExit=null;String error=null,nonce=null,identityHash=null;
        long submitted=0,deadline=0;WorkerGenerationProof.Identity identity=null;
        try{
            WorkerGenerationProof.need(!attempted,"cleanup invocation already attempted");attempted=true;
            WorkerGenerationProof.need(directExitObserved,"direct process exit is not yet observed");
            verifyApp();
            byte[] identityBytes=MobiMindPrivateFiles.read(identityFile,WorkerGenerationProof.IDENTITY_LIMIT,true).bytes;
            identity=WorkerGenerationProof.identity(identityBytes,expected);identityHash=identity.sha256;
            nonce=UUID.randomUUID().toString().replace("-","");
            File stdout=new File(directory,"generation-cleanup-"+nonce+".stdout");
            File stderr=new File(directory,"generation-cleanup-"+nonce+".stderr");
            File receipt=new File(directory,"generation-cleanup-"+nonce+".json");
            WorkerGenerationProof.need(!receipt.exists(),"cleanup receipt collision");
            MobiMindPrivateFiles.writeNew(stdout,new byte[0]);MobiMindPrivateFiles.writeNew(stderr,new byte[0]);
            submitted=System.nanoTime();deadline=WorkerGenerationProof.cleanupDeadline(submitted,finisherSubmitted,finisherDeadline);
            List<String> command=new ArrayList<>(Arrays.asList(runner.getPath(),
                    "--hepta-owned-generation-cleanup-v1",files.getPath(),expected.generation,expected.task,
                    expected.token,Long.toString(expected.appPid),Long.toString(expected.appStart),expected.boot,
                    identity.sha256,nonce,Long.toString(deadline)));
            ProcessBuilder builder=new ProcessBuilder(command).directory(directory).redirectOutput(stdout).redirectError(stderr);
            Map<String,String> env=builder.environment();
            // This fresh child belongs to the app, never the worker's inherited scope.
            for(String name:WorkerGenerationProof.ENVIRONMENT)env.remove(name);
            env.put("LD_LIBRARY_PATH",nativeDirectory.getPath()+":/vendor/lib64");
            env.put("HEPTA_LOCAL_NATIVE_LIB_DIR",nativeDirectory.getPath());
            env.remove("GENIEX_QAIRT_LIB");
            verifyApp();
            WorkerGenerationProof.need(deadline-System.nanoTime()>=WorkerGenerationProof.MINIMUM_BUDGET_NANOS,
                    "insufficient original cleanup budget before launch");
            cleanupProcess=builder.start();
            long wait=Math.max(0,deadline+500000000L-System.nanoTime());
            helperExited=cleanupProcess.waitFor(wait,TimeUnit.NANOSECONDS);
            if(!helperExited){
                // This is only the exact helper Process we just spawned. No PID,
                // group, SDK worker or descendant is targeted by this fallback.
                helperForced=true;cleanupProcess.destroyForcibly();
                helperExited=cleanupProcess.waitFor(500,TimeUnit.MILLISECONDS);
            }
            if(helperExited)helperExit=cleanupProcess.exitValue();
            verifyApp();
            byte[] same=MobiMindPrivateFiles.read(identityFile,WorkerGenerationProof.IDENTITY_LIMIT,true).bytes;
            WorkerGenerationProof.need(identity.sha256.equals(WorkerGenerationProof.sha256(same)),"generation identity changed");
            if(receipt.isFile()){
                byte[] bytes=MobiMindPrivateFiles.read(receipt,WorkerGenerationProof.RECEIPT_LIMIT,true).bytes;
                nativeAudit=new JSONObject(new String(bytes,StandardCharsets.UTF_8));
                try{
                    int attempts=WorkerGenerationProof.boundForceAttempts(identity,nonce,nativeAudit);
                    forceKnown=true;forceUsed=attempts>0;
                }catch(IOException invalidAudit){put(audit,"signal_audit_error",invalidAudit.getMessage());}
                put(audit,"native_receipt_sha256",WorkerGenerationProof.sha256(bytes));
                put(audit,"native_receipt_file",receipt.getPath());
            }
            WorkerGenerationProof.bindCleanup(identity,nonce,submitted,deadline,finisherSubmitted,finisherDeadline,nativeAudit,
                    helperExited,helperExit,helperForced);
            known=true;
        }catch(Exception failure){
            if(failure instanceof InterruptedException)Thread.currentThread().interrupt();
            error=failure.getClass().getSimpleName()+": "+String.valueOf(failure.getMessage());
        }
        put(audit,"schema","hepta.worker-generation.app-cleanup.v1");
        put(audit,"task_id",expected.task);put(audit,"worker_generation",expected.generation);
        put(audit,"scope_token",expected.token);put(audit,"app_uid",expected.uid);put(audit,"app_pid",expected.appPid);
        put(audit,"app_start_ticks",expected.appStart);put(audit,"boot_id",expected.boot);
        put(audit,"identity_file",identityFile.getPath());put(audit,"identity_sha256",identityHash);
        put(audit,"direct_process_exit_observed",directExitObserved);
        put(audit,"finisher_submitted_monotonic_ns",finisherSubmitted);
        put(audit,"finisher_deadline_monotonic_ns",finisherDeadline);
        put(audit,"helper_finalization_reserve_ns",WorkerGenerationProof.FINALIZATION_RESERVE_NANOS);
        put(audit,"cleanup_nonce",nonce);put(audit,"submitted_monotonic_ns",submitted);
        put(audit,"deadline_monotonic_ns",deadline);put(audit,"helper_started",cleanupProcess!=null);
        put(audit,"helper_exit_observed",helperExited);put(audit,"helper_exit_code",helperExit);
        put(audit,"helper_force_destroy_sent",helperForced);
        put(audit,"helper_currently_alive",cleanupProcess!=null&&cleanupProcess.isAlive());
        put(audit,"native_cleanup",nativeAudit);
        put(audit,"cleanup_known",known);put(audit,"descendant_force_known",forceKnown);
        put(audit,"descendant_force_used",forceKnown?Boolean.valueOf(forceUsed):JSONObject.NULL);
        put(audit,"generation_unforced",known&&forceKnown&&!forceUsed);
        put(audit,"scope","pinned_sdk_inheriting_process_group_and_generation_markers");
        put(audit,"escaped_sessions_proven_absent",false);put(audit,"automatic_retry",false);put(audit,"error",error);
        sealed=new Cleanup(known,forceKnown,forceUsed,audit);return sealed;
    }
    private void verifyApp()throws Exception{
        WorkerGenerationProof.need(android.os.Process.myUid()==expected.uid&&android.os.Process.myPid()==expected.appPid,
                "cleanup app identity differs");
        long start=WorkerGenerationProof.procStart(readProc(new File("/proc/"+expected.appPid+"/stat"),8192),expected.appPid);
        String boot=new String(readProc(new File("/proc/sys/kernel/random/boot_id"),80),StandardCharsets.US_ASCII);
        WorkerGenerationProof.need(start==expected.appStart&&(expected.boot+"\n").equals(boot),"cleanup app lifetime differs");
        WorkerGenerationProof.need(files.equals(files.getCanonicalFile())&&directory.equals(directory.getCanonicalFile())
                &&runner.equals(runner.getCanonicalFile())&&runner.isFile()&&runner.canExecute(),"cleanup path differs");
    }
    private static byte[] readProc(File file,int bound)throws IOException{
        try(FileInputStream in=new FileInputStream(file);ByteArrayOutputStream out=new ByteArrayOutputStream()){
            byte[] chunk=new byte[1024];for(int n;(n=in.read(chunk))!=-1;){
                if(out.size()+n>bound)throw new IOException("bounded process evidence exceeded");
                out.write(chunk,0,n);
            }
            return out.toByteArray();
        }
    }
    private static void put(JSONObject value,String key,Object field){
        try{value.put(key,field==null?JSONObject.NULL:field);}catch(Exception impossible){throw new IllegalStateException(impossible);}
    }
}
