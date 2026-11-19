package org.trillionnium.hepta.local;

import android.app.Activity;
import android.content.Context;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import android.view.Display;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ControllerDisplayHandoff;
import org.trillionnium.hepta.background.RecoveryControllerIdentity;

/** The owner button captures public facts only. The privileged reader supplies
 * independent complete census evidence; getDisplay() is never absence proof. */
final class ControllerDisplayHandoffClient {
    private ControllerDisplayHandoffClient(){}
    interface Check {void check()throws Exception;}
    static final class ReaderExitUnknown extends IOException {
        private static final long serialVersionUID=1L;
        ReaderExitUnknown(){super("后台准备尚未结束，任务未启动");}
    }
    static ControllerDisplayHandoff.Locator capture(Activity activity,String owner)throws Exception{
        if(Looper.myLooper()!=Looper.getMainLooper()||activity==null||activity.getClass()!=MainActivity.class)
            throw new IOException("HANDOFF_OWNER_BUTTON_THREAD");
        Display display=activity.getDisplay();if(display==null||!display.isValid())throw new IOException("HANDOFF_OWNER_DISPLAY_UNKNOWN");
        if(display.getDisplayId()==0||display.getDisplayId()==1)return null;
        if(activity.isFinishing()||activity.isDestroyed()||!activity.hasWindowFocus()||activity.getWindow()==null
                ||!activity.getWindow().getDecorView().isShown()||activity.getComponentName()==null
                ||!ControllerDisplayHandoff.COMPONENT.equals(activity.getComponentName().flattenToString())
                ||activity.getApplicationInfo().uid!=android.os.Process.myUid())throw new IOException("HANDOFF_OWNER_BUTTON_NOT_VISIBLE");
        return ControllerDisplayHandoff.fromOwnerButton(android.os.Process.myUid(),android.os.Process.myPid(),selfTicks(),
                activity.getTaskId(),display.getDisplayId(),display.getName(),display.getFlags(),SystemClock.elapsedRealtime(),
                ControllerDisplayHandoff.sha(owner.getBytes(StandardCharsets.UTF_8)));
    }
    static void await(Context context,File evidence,String taskId,String owner,ControllerDisplayHandoff.Locator locator,
            long taskDeadline,Check check)throws Exception{
        if(locator==null)throw new IOException("HANDOFF_LOCATOR_MISSING");check.check();
        if(locator.pid!=android.os.Process.myPid()||locator.uid!=android.os.Process.myUid()||locator.startTicks!=selfTicks()
                ||!locator.ownerSha.equals(ControllerDisplayHandoff.sha(owner.getBytes(StandardCharsets.UTF_8))))throw new IOException("HANDOFF_LOCAL_OWNER_CHANGED");
        QualificationScopeConfig.FilesRoot root=new QualificationScopeConfig.FilesRoot(context);root.unchanged(context);
        File expected=new File(new File(root.path,"control-tasks"),taskId);
        if(!expected.equals(evidence)||!evidence.isDirectory()||!evidence.equals(evidence.getCanonicalFile()))throw new IOException("HANDOFF_TASK_DIRECTORY");
        JSONObject installation=RecoveryControllerIdentity.read(context,locator.uid,taskDeadline);
        ControllerDisplayHandoff.Request request=ControllerDisplayHandoff.request(locator,taskId,UUID.randomUUID().toString().replace("-",""),
                SystemClock.elapsedRealtime(),taskDeadline,boot(context),installation);
        File apk=new File(context.getApplicationInfo().sourceDir).getCanonicalFile();
        if(!apk.getPath().equals(installation.getString("source_path")))throw new IOException("HANDOFF_EXECUTING_INSTALLATION");
        MobiMindPrivateFiles.writeNew(new File(evidence,"controller-display-handoff-request.json"),request.json().toString().getBytes(StandardCharsets.UTF_8));
        String command="CLASSPATH="+quote(apk.getPath())+" /system/bin/app_process / org.trillionnium.hepta.background.ControllerDisplayHandoffMain --request "+quote(request.wire());
        check.check();request.fence(SystemClock.elapsedRealtime(),boot(context));
        final Process process=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();
        final Capture capture=new Capture(process.getInputStream());Thread reader=new Thread(capture,"HeptaControllerHandoffRead");reader.setDaemon(true);reader.start();
        JSONObject before=null,complete=null;boolean exited=false;Exception failure=null;
        try{
            process.getOutputStream().close();
            while(before==null){
                check.check();request.fence(SystemClock.elapsedRealtime(),boot(context));String line=capture.line(0);
                if(line!=null){before=ControllerDisplayHandoff.validateBefore(new JSONObject(line),request,SystemClock.elapsedRealtime(),boot(context));break;}
                if(capture.failedOrEof())throw new IOException("HANDOFF_BEFORE_INCOMPLETE");Thread.sleep(20);
            }
            check.check();root.unchanged(context);
            // No PENDING file exists until a real root complete-before census has
            // passed. It is an explicit wait/release handshake, never idle.
            JSONObject pending=new JSONObject().put("schema","hepta.controller-display-handoff.pending.v1")
                    .put("status","CALLER_VERIFIED_WAITING_EXACT_OUTER_RELEASE").put("request",request.json()).put("before",before)
                    .put("pending_published_elapsed_ms",SystemClock.elapsedRealtime())
                    .put("background_create_entered",false).put("model_entered",false).put("effect_dispatched",false)
                    .put("ordinary_idle",false).put("business_success",false);
            request.fence(SystemClock.elapsedRealtime(),boot(context));
            byte[] pendingRaw=pending.toString().getBytes(StandardCharsets.UTF_8);
            File pendingFile=new File(evidence,"controller-display-handoff-pending.json");
            MobiMindPrivateFiles.writeNew(pendingFile,pendingRaw);
            MobiMindPrivateFiles.Read pendingOriginal=MobiMindPrivateFiles.read(pendingFile,ControllerDisplayHandoff.MAX_OUTPUT,true);
            if(!java.util.Arrays.equals(pendingRaw,pendingOriginal.bytes))throw new IOException("HANDOFF_PENDING_WRITE_CHANGED");
            MobiMindPrivateFiles.syncDirectory(evidence);
            long left=request.deadline-SystemClock.elapsedRealtime();
            if(left<=0||!process.waitFor(left,TimeUnit.MILLISECONDS))throw new ReaderExitUnknown();exited=true;
            left=request.deadline-SystemClock.elapsedRealtime();if(left>0)reader.join(left);
            if(process.exitValue()!=0||reader.isAlive()||!capture.complete(2))throw new IOException("HANDOFF_READER_EXIT_OR_OUTPUT");
            complete=ControllerDisplayHandoff.validateComplete(new JSONObject(capture.line(1)),before,request,SystemClock.elapsedRealtime(),boot(context));
            if(!ControllerDisplayHandoff.same(installation,RecoveryControllerIdentity.read(context,locator.uid,request.deadline)))throw new IOException("HANDOFF_INSTALLATION_CHANGED");
            check.check();request.fence(SystemClock.elapsedRealtime(),boot(context));root.unchanged(context);
            pendingOriginal.unchangedPath();
            if(!java.util.Arrays.equals(pendingRaw,MobiMindPrivateFiles.read(pendingFile,ControllerDisplayHandoff.MAX_OUTPUT,true).bytes))
                throw new IOException("HANDOFF_PENDING_CHANGED");
            JSONObject result=new JSONObject().put("schema","hepta.controller-display-handoff.receipt.v1").put("request",request.json())
                    .put("before",before).put("complete",complete).put("pending_sha256",ControllerDisplayHandoff.sha(pendingRaw))
                    .put("controller_generation",locator.generation).put("reader_exit_observed",true).put("reader_exit_code",0)
                    .put("output_eof",true).put("output_sha256",ControllerDisplayHandoff.sha(capture.raw()))
                    .put("background_create_entered",false).put("business_success",false);
            MobiMindPrivateFiles.writeNew(new File(evidence,"controller-display-handoff-receipt.json"),result.toString().getBytes(StandardCharsets.UTF_8));
            MobiMindPrivateFiles.syncDirectory(evidence);check.check();request.fence(SystemClock.elapsedRealtime(),boot(context));
        }catch(Exception error){failure=error;}
        if(failure!=null){
            if(!exited){try{process.exitValue();exited=true;}catch(IllegalThreadStateException stillAlive){}}
            try{
                MobiMindPrivateFiles.writeNew(new File(evidence,"controller-display-handoff-failure.json"),new JSONObject()
                        .put("schema","hepta.controller-display-handoff.failure-record.v1").put("request",request.json())
                        .put("before",before==null?JSONObject.NULL:before).put("complete",complete==null?JSONObject.NULL:complete)
                        .put("reader_exit_observed",exited).put("reader_exit_code",exited?process.exitValue():JSONObject.NULL)
                        .put("reader_output_complete",!reader.isAlive()&&capture.eof).put("error_class",failure.getClass().getName())
                        .put("error",String.valueOf(failure.getMessage())).put("background_create_entered",false)
                        .put("current_absence_verified",false).put("business_success",false).toString().getBytes(StandardCharsets.UTF_8));
            }catch(Exception archiveFailure){failure.addSuppressed(archiveFailure);}
            // No numeric-PID kill, Process.destroy or cleanup claim. The root
            // reader has its own absolute deadline; uncertain exit blocks reuse.
            if(!exited){ReaderExitUnknown unknown=new ReaderExitUnknown();unknown.addSuppressed(failure);throw unknown;}throw failure;
        }
    }
    private static int boot(Context context)throws Exception{return Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT,-1);}
    private static String quote(String value){return "'"+value.replace("'","'\\''")+"'";}
    private static long selfTicks()throws Exception{
        ByteArrayOutputStream out=new ByteArrayOutputStream();try(FileInputStream in=new FileInputStream("/proc/self/stat")){
            byte[] buffer=new byte[1024];int n;while((n=in.read(buffer))!=-1){if(out.size()+n>8192)throw new IOException("HANDOFF_SELF_STAT_BOUND");out.write(buffer,0,n);}}
        String text=new String(out.toByteArray(),StandardCharsets.US_ASCII);int end=text.lastIndexOf(')');
        if(!text.startsWith(android.os.Process.myPid()+" (")||end<0)throw new IOException("HANDOFF_SELF_STAT");
        String[] fields=text.substring(end+2).trim().split(" +");if(fields.length<20)throw new IOException("HANDOFF_SELF_STAT");
        long ticks=Long.parseLong(fields[19]);if(ticks<=0)throw new IOException("HANDOFF_SELF_TICKS");return ticks;
    }
    private static final class Capture implements Runnable {
        private final InputStream input;private final ByteArrayOutputStream bytes=new ByteArrayOutputStream();private final List<String> lines=new ArrayList<String>();
        volatile boolean eof;private Throwable failure;
        Capture(InputStream input){this.input=input;}
        public void run(){try(InputStream in=input){ByteArrayOutputStream line=new ByteArrayOutputStream();int value;
            while((value=in.read())!=-1){synchronized(this){if(bytes.size()>=ControllerDisplayHandoff.MAX_OUTPUT)throw new IOException("HANDOFF_OUTPUT_BOUND");bytes.write(value);}
                if(value=='\n'){String text=new String(line.toByteArray(),StandardCharsets.UTF_8);line.reset();synchronized(this){if(lines.size()>=2||text.isEmpty())throw new IOException("HANDOFF_OUTPUT_LINES");lines.add(text);}}
                else line.write(value);
            }
            if(line.size()!=0)throw new IOException("HANDOFF_OUTPUT_PARTIAL_LINE");eof=true;
        }catch(Throwable error){synchronized(this){failure=error;}}}
        synchronized String line(int index)throws Exception{if(failure!=null)throw new IOException("HANDOFF_OUTPUT_FAILURE",failure);return lines.size()>index?lines.get(index):null;}
        synchronized boolean failedOrEof(){return failure!=null||eof;}
        synchronized boolean complete(int count){return eof&&failure==null&&lines.size()==count;}
        synchronized byte[] raw(){return bytes.toByteArray();}
    }
}
