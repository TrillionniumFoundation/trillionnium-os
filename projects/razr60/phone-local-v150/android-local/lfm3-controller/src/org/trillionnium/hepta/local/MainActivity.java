package org.trillionnium.hepta.local;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.graphics.Typeface;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.*;
import android.util.AtomicFile;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** Visible owner task UI, application-owned session, and explicit local model diagnostics. */
public final class MainActivity extends Activity implements LocalTaskSession.Listener {
    private LocalModelEngine engine;
    private LocalTaskSession tasks;
    private MobiMindModelEngine visualDiagnostic;
    private UiVenusModelEngine uiVenusDiagnostic;
    private EditText taskInput, probePrompt;
    private TextView modelInfo, taskState, taskLog, taskResult, probeOutput;
    private TextView visualProbeOutput;
    private TextView uiVenusProbeOutput;
    private LinearLayout diagnostics;
    private Button startTask, stopTask, runText;
    private String lastShownProbeId;
    private String lastShownVisualProbeId;
    private String lastShownUiVenusProbeId;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LocalProbeApplication app=(LocalProbeApplication)getApplication();
        engine=app.modelEngine();tasks=app.taskSession();visualDiagnostic=app.mobiMindDiagnostic();
        uiVenusDiagnostic=app.uiVenusDiagnostic();
        ScrollView outer=new ScrollView(this);outer.setFillViewport(true);
        LinearLayout page=new LinearLayout(this);page.setOrientation(LinearLayout.VERTICAL);
        int pad=dp(16);page.setPadding(pad,pad,pad,pad);outer.addView(page);
        TextView title=text("Hepta",25);page.addView(title);
        page.addView(text("用手机本地模型理解指令并操作应用",15));
        modelInfo=text("",12);modelInfo.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);page.addView(modelInfo);
        taskInput=new EditText(this);taskInput.setHint("你想让手机完成什么？");
        taskInput.setText("打开计算器，计算 37 加 58，然后结束任务。");taskInput.setMinLines(3);page.addView(taskInput);
        LinearLayout actions=new LinearLayout(this);page.addView(actions);
        startTask=button("开始任务");actions.addView(startTask);
        stopTask=button("停止");actions.addView(stopTask);
        Button accessibility=button("启用无障碍");actions.addView(accessibility);
        startTask.setOnClickListener(v -> beginTask(taskInput.getText().toString(),"user_button",null));
        stopTask.setOnClickListener(v -> {tasks.stop();engine.cancelActive();refresh();});
        accessibility.setOnClickListener(v -> startActivity(new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)));
        taskState=text("",15);taskState.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);page.addView(taskState);
        ScrollView progress=new ScrollView(this);
        progress.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS);
        page.addView(progress,new LinearLayout.LayoutParams(-1,dp(150)));
        taskLog=text("",12);taskLog.setTypeface(Typeface.MONOSPACE);taskLog.setTextIsSelectable(true);progress.addView(taskLog);
        taskResult=text("",13);taskResult.setTextIsSelectable(true);taskResult.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);page.addView(taskResult);
        Button showDiagnostics=button("本地模型诊断");page.addView(showDiagnostics);
        diagnostics=new LinearLayout(this);diagnostics.setOrientation(LinearLayout.VERTICAL);diagnostics.setVisibility(View.GONE);page.addView(diagnostics);
        showDiagnostics.setOnClickListener(v -> diagnostics.setVisibility(diagnostics.getVisibility()==View.VISIBLE?View.GONE:View.VISIBLE));
        diagnostics.addView(text("本地文字推理；控制任务读取无障碍节点。截图仅保留在手机内用于复核操作。",12));
        probePrompt=new EditText(this);probePrompt.setText("只输出 42。");probePrompt.setMinLines(2);diagnostics.addView(probePrompt);
        LinearLayout probes=new LinearLayout(this);diagnostics.addView(probes);
        runText=button("文本推理");probes.addView(runText);
        runText.setOnClickListener(v -> runProbe(false,128));
        probeOutput=text("",11);probeOutput.setTypeface(Typeface.MONOSPACE);probeOutput.setTextIsSelectable(true);
        probeOutput.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);diagnostics.addView(probeOutput);
        diagnostics.addView(text("私有截图诊断只生成本地视觉模型输出，不会操作手机。",12));
        visualProbeOutput=text("",11);visualProbeOutput.setTypeface(Typeface.MONOSPACE);visualProbeOutput.setTextIsSelectable(true);
        visualProbeOutput.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);diagnostics.addView(visualProbeOutput);
        diagnostics.addView(text("UI-Venus 私有图像诊断；只显示模型原始输出，不执行动作。",12));
        uiVenusProbeOutput=text("尚未收到已准备的私有诊断请求。",11);uiVenusProbeOutput.setTypeface(Typeface.MONOSPACE);uiVenusProbeOutput.setTextIsSelectable(true);
        uiVenusProbeOutput.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);diagnostics.addView(uiVenusProbeOutput);
        setContentView(outer);tasks.bind(this);refresh();handleIntent(getIntent());
    }
    private int dp(int value){return Math.round(value*getResources().getDisplayMetrics().density);}
    private TextView text(String value,int size){TextView view=new TextView(this);view.setText(value);view.setTextSize(size);view.setPadding(0,dp(5),0,dp(5));return view;}
    private Button button(String label){Button view=new Button(this);view.setText(label);return view;}

    @Override protected void onNewIntent(Intent intent){super.onNewIntent(intent);setIntent(intent);handleIntent(intent);}
    private void handleIntent(Intent intent){
        if(intent==null)return;
        if(intent.getBooleanExtra("auto_ui_venus_probe",false)){
            final String nonce=intent.getStringExtra("ui_venus_nonce");
            boolean conflict=intent.getBooleanExtra("auto_mobi_probe",false)||intent.getBooleanExtra("auto_task",false)||intent.getBooleanExtra("auto_run",false);
            // Consume all launch selectors before verification: Activity recreation cannot replay this trigger.
            for(String key:new String[]{"auto_ui_venus_probe","ui_venus_nonce","auto_mobi_probe","mobi_nonce","auto_task","test_nonce","auto_run"})intent.removeExtra(key);
            diagnostics.setVisibility(View.VISIBLE);runUiVenusProbe(nonce,conflict);return;
        }
        if(intent.getBooleanExtra("auto_mobi_probe",false)){
            final String nonce=intent.getStringExtra("mobi_nonce");
            // A recreated Activity cannot replay this one-use launch extra.
            intent.removeExtra("auto_mobi_probe");intent.removeExtra("mobi_nonce");
            boolean conflict=intent.getBooleanExtra("auto_task",false)||intent.getBooleanExtra("auto_run",false);
            intent.removeExtra("auto_task");intent.removeExtra("auto_run");intent.removeExtra("test_nonce");
            diagnostics.setVisibility(View.VISIBLE);
            runVisualProbe(nonce,conflict);
            return;
        }
        String suppliedTask=intent.getStringExtra("task");
        if(suppliedTask!=null&&!tasks.isRunning())taskInput.setText(suppliedTask);
        if(intent.getBooleanExtra("auto_task",false)){
            final String nonce=intent.getStringExtra("test_nonce");
            intent.removeExtra("auto_task");intent.removeExtra("test_nonce");
            boolean consumed=false;
            try{
                if(tasks.isRunning()||tasks.isBlocked()||engine.isBusy())throw new IllegalStateException("已有本地请求或退出状态待确认");
                if(HeptaAccessibilityService.connected()==null)throw new IllegalStateException("请先正常启用 Hepta 本地操作无障碍服务");
                PrivateDebugTask request=PrivateDebugTask.consume(this,nonce);
                consumed=true;
                taskInput.setText(request.instruction);
                boolean accepted=beginTask(request.instruction,"private_debug_nonce",request.nonceSha256);
                recordDebugTrigger(request.nonceSha256,accepted,consumed,accepted?null:"前台任务未启动");
            }catch(Exception error){
                taskState.setText("未启动测试任务："+HeptaAccessibilityService.message(error));
                recordDebugTrigger(nonce==null?null:HeptaAccessibilityService.sha(nonce.getBytes(StandardCharsets.UTF_8)),false,consumed,HeptaAccessibilityService.message(error));
            }
            return;
        }
        String supplied=intent.getStringExtra("prompt");if(supplied!=null)probePrompt.setText(supplied);
        if(intent.getBooleanExtra("auto_run",false)){
            boolean image="image".equals(intent.getStringExtra("mode"));int max=intent.getIntExtra("max_tokens",image?256:128);
            intent.removeExtra("auto_run");diagnostics.setVisibility(View.VISIBLE);
            probePrompt.post(() -> runProbe(image,max));
        }
    }
    private boolean beginTask(String owner,String source,String nonceSha){
        try{
            if(tasks.isRunning()||tasks.isBlocked()||engine.isBusy())throw new IllegalStateException("已有本地请求正在运行或退出状态待确认");
            if(!engine.modelFile().isFile())throw new IllegalStateException("所选本地模型尚未导入");
            engine.configuration();
            if(!tasks.schedule(owner,source,nonceSha,500))throw new IllegalStateException("本地任务未能取得唯一会话");
            InputMethodManager input=(InputMethodManager)getSystemService(INPUT_METHOD_SERVICE);
            if(input!=null)input.hideSoftInputFromWindow(taskInput.getWindowToken(),0);
            if(!moveTaskToBack(true)){tasks.stop();taskState.setText("无法切换到手机前台画面，任务未开始");return false;}
            return true;
        }catch(Exception error){taskState.setText("无法开始："+HeptaAccessibilityService.message(error));return false;}
    }

    private void runProbe(boolean image,int maxTokens){
        if(engine.isBusy()||tasks.isRunning()||tasks.isBlocked()){probeOutput.setText("已有任务正在运行或退出待确认，请先停止并等待。");return;}
        String system=getIntent().getStringExtra("system_prompt");
        if(system==null)system="你是在手机本地运行的助手。请直接、简洁地回答用户指令。";
        long timeout=getIntent().getLongExtra("timeout_ms",120000L);
        if(image){probeOutput.setText("当前本地模型只接收文字；图片不会发送给模型。");return;}
        probeOutput.setText("正在启动手机本地推理……");
        try{
            engine.start(new LocalModelEngine.Request(probePrompt.getText().toString(),system,
                null,maxTokens,timeout),
                result -> runOnUiThread(() -> {renderProbe(result);refresh();}));
            refresh();
        }catch(Exception error){probeOutput.setText("无法启动："+error);refresh();}
    }
    private void renderProbe(LocalModelEngine.Result result){
        lastShownProbeId=result.runId;String receipt;
        try{receipt=result.receipt.toString(2);}catch(Exception error){receipt=result.receipt.toString();}
        String raw=result.rawText.length()>16000?result.rawText.substring(0,16000)+"\n（此处显示前 16000 字符，完整输出保存在凭据目录）":result.rawText;
        probeOutput.setText("状态："+result.status+"\n真实进程退出："+result.processExitObserved+" / "+result.exitCode
            +"\n推理完整完成："+result.inferenceCompleted+"\n\n"+raw+"\n\n凭据："+result.runDirectory+"\n"+receipt);
    }
    private void runVisualProbe(String nonce,boolean conflict){
        boolean consumed=false;String requestId=null;
        try{
            if(conflict)throw new IllegalStateException("视觉诊断不能与其它启动请求合并");
            if(tasks.isRunning()||tasks.isBlocked()||engine.isBusy()||visualDiagnostic.isBlocked())
                throw new IllegalStateException("已有本地请求或退出状态待确认");
            PrivateMobiProbe request=PrivateMobiProbe.consume(this,nonce);consumed=true;requestId=request.id;
            visualProbeOutput.setText("正在执行私有截图的手机本地 GPU 推理；输出不会用于操作手机……");
            visualDiagnostic.start(request,tasks,result -> {renderVisualProbe(result);refresh();});
            recordVisualTrigger(nonce,requestId,true,consumed,null);
            refresh();
        }catch(Exception error){
            visualProbeOutput.setText("未启动视觉诊断："+HeptaAccessibilityService.message(error));
            recordVisualTrigger(nonce,requestId,false,consumed,HeptaAccessibilityService.message(error));
            refresh();
        }
    }
    private void renderVisualProbe(MobiMindModelEngine.Result result){
        lastShownVisualProbeId=result.runId;String receipt;
        try{receipt=result.receipt.toString(2);}catch(Exception error){receipt=result.receipt.toString();}
        String raw=result.rawText.length()>16000?result.rawText.substring(0,16000)+"\n（完整原始输出保存在凭据目录）":result.rawText;
        visualProbeOutput.setText("仅模型推理，未执行手机操作\n状态："+result.status
            +"\n真实进程退出："+result.processExitObserved+" / "+result.exitCode
            +"\n推理完整完成："+result.inferenceCompleted+"\n退出与回执已确认："+result.cleanupKnown
            +"\n\n"+raw+"\n\n凭据："+result.runDirectory+"\n"+receipt);
    }
    private void runUiVenusProbe(String nonce,boolean conflict){
        boolean consumed=false;String requestId=null;
        try{
            if(conflict)throw new IllegalStateException("UI-Venus诊断不能与其它启动请求合并");
            if(tasks.isRunning()||tasks.isBlocked()||engine.isBusy()||visualDiagnostic.isBlocked()||uiVenusDiagnostic.isBlocked())
                throw new IllegalStateException("已有本地请求或退出状态待确认");
            PrivateUiVenusProbe request=PrivateUiVenusProbe.consume(this,nonce);consumed=true;requestId=request.id;
            uiVenusProbeOutput.setText("正在执行手机本地图像推理；原始输出不会用于操作手机……");
            uiVenusDiagnostic.start(request,tasks,result -> {renderUiVenusProbe(result);refresh();});
            recordUiVenusTrigger(nonce,requestId,true,consumed,null);refresh();
        }catch(Exception error){
            uiVenusProbeOutput.setText("未启动UI-Venus诊断："+HeptaAccessibilityService.message(error));
            recordUiVenusTrigger(nonce,requestId,false,consumed,HeptaAccessibilityService.message(error));refresh();
        }
    }
    private void renderUiVenusProbe(UiVenusModelEngine.Result result){
        lastShownUiVenusProbeId=result.runId;String receipt;
        try{receipt=result.receipt.toString(2);}catch(Exception error){receipt=result.receipt.toString();}
        String raw=result.rawText.length()>16000?result.rawText.substring(0,16000)+"\n（完整原始输出保存在凭据目录）":result.rawText;
        uiVenusProbeOutput.setText("仅模型推理，未执行手机操作\n状态："+result.status
            +"\n真实进程退出："+result.processExitObserved+" / "+result.exitCode
            +"\n推理完整完成："+result.inferenceCompleted+"\n退出与回执已确认："+result.cleanupKnown
            +"\n\n"+raw+"\n\n凭据："+result.runDirectory+"\n"+receipt);
    }
    @Override public void onSessionChanged(){refresh();}
    private void refresh(){
        if(modelInfo==null)return;
        boolean available=HeptaAccessibilityService.connected()!=null;
        String device,modelName="本地模型";
        try { device="npu".equals(engine.configuration().compute)?"Hexagon NPU":"Adreno GPU";modelName=engine.configuration().profile.displayName; }
        catch(Exception error) { device="运行参数待修正"; }
        modelInfo.setText(modelName+" · "+device+" · 无外部模型\n"
            +(engine.modelFile().isFile()?"本地模型已导入":"本地模型待导入")
            +" · "+(available?"无障碍已启用":"无障碍未启用")+" · 可用 RAM "+String.format(Locale.US,"%.2f GiB",engine.availableMemoryBytes()/1073741824.0));
        taskState.setText(tasks.state());taskLog.setText(tasks.log());
        boolean busy=tasks.isRunning()||engine.isBusy();
        startTask.setEnabled(!busy&&!tasks.isBlocked());stopTask.setEnabled(busy);
        runText.setEnabled(!busy&&!tasks.isBlocked());
        LocalTaskController.TaskResult result=tasks.lastResult();
        if(result!=null)taskResult.setText("任务："+result.taskId+"\n"+result.summary+"\n步骤："+result.steps
            +"\n退出状态已确认："+result.cleanupKnown+"\n记录："+result.evidenceDirectory);
        else if(tasks.taskId()!=null)taskResult.setText("任务："+tasks.taskId());
        else taskResult.setText("");
        LocalModelEngine.Result probe=engine.lastResult();
        if(probe!=null&&!engine.isBusy()&&!probe.runId.equals(lastShownProbeId))renderProbe(probe);
        MobiMindModelEngine.Result visual=visualDiagnostic.lastResult();
        if(visual!=null&&!visual.runId.equals(lastShownVisualProbeId))renderVisualProbe(visual);
        if(visualDiagnostic.isBlocked()){
            startTask.setEnabled(false);runText.setEnabled(false);
            if(visual==null)visualProbeOutput.setText(visualDiagnostic.recoveryMessage());
        }
        UiVenusModelEngine.Result venus=uiVenusDiagnostic.lastResult();
        if(venus!=null&&!venus.runId.equals(lastShownUiVenusProbeId))renderUiVenusProbe(venus);
        if(uiVenusDiagnostic.isBlocked()){
            startTask.setEnabled(false);runText.setEnabled(false);
            if(venus==null)uiVenusProbeOutput.setText(uiVenusDiagnostic.recoveryMessage());
        }
    }
    private void recordUiVenusTrigger(String nonce,String requestId,boolean accepted,boolean consumed,String error){
        AtomicFile file=new AtomicFile(new File(getFilesDir(),"ui-venus-probe-trigger-result.json"));FileOutputStream out=null;
        try{
            JSONObject value=new JSONObject().put("schema","hepta.private-ui-venus-trigger.v1").put("accepted",accepted)
                .put("request_id",requestId==null?JSONObject.NULL:requestId)
                .put("nonce_sha256",nonce==null?JSONObject.NULL:MobiMindContract.sha(nonce.getBytes(StandardCharsets.UTF_8)))
                .put("error",error==null?JSONObject.NULL:error).put("app_uid",android.os.Process.myUid())
                .put("app_pid",android.os.Process.myPid()).put("at_wall_ms",System.currentTimeMillis())
                .put("private_request_consumed",consumed?Boolean.TRUE:JSONObject.NULL)
                .put("consume_completed",consumed).put("actions_executed",false).put("automatic_resume",false);
            out=file.startWrite();out.write(value.toString(2).getBytes(StandardCharsets.UTF_8));out.getFD().sync();file.finishWrite(out);out=null;
            android.system.Os.chmod(file.getBaseFile().getPath(),0600);
        }catch(Exception ignored){if(out!=null)file.failWrite(out);}
    }
    private void recordVisualTrigger(String nonce,String requestId,boolean accepted,boolean consumed,String error){
        AtomicFile file=new AtomicFile(new File(getFilesDir(),"mobi-probe-trigger-result.json"));FileOutputStream out=null;
        try{
            JSONObject value=new JSONObject().put("schema","hepta.private-mobimind-trigger.v1").put("accepted",accepted)
                .put("request_id",requestId==null?JSONObject.NULL:requestId)
                .put("nonce_sha256",nonce==null?JSONObject.NULL:MobiMindContract.sha(nonce.getBytes(StandardCharsets.UTF_8)))
                .put("error",error==null?JSONObject.NULL:error).put("app_uid",android.os.Process.myUid())
                .put("app_pid",android.os.Process.myPid()).put("at_wall_ms",System.currentTimeMillis())
                .put("private_request_consumed",consumed?Boolean.TRUE:JSONObject.NULL)
                .put("consume_completed",consumed).put("actions_executed",false).put("automatic_resume",false);
            out=file.startWrite();out.write(value.toString(2).getBytes(StandardCharsets.UTF_8));out.getFD().sync();file.finishWrite(out);out=null;
            android.system.Os.chmod(file.getBaseFile().getPath(),0600);
        }catch(Exception ignored){if(out!=null)file.failWrite(out);}
    }
    private void recordDebugTrigger(String nonceSha,boolean accepted,boolean consumed,String error){
        AtomicFile file=new AtomicFile(new File(getFilesDir(),"debug-trigger-result.json"));FileOutputStream out=null;
        try{
            JSONObject value=new JSONObject().put("schema","hepta.private-debug-trigger.v1").put("accepted",accepted)
                .put("nonce_sha256",nonceSha==null?JSONObject.NULL:nonceSha).put("error",error==null?JSONObject.NULL:error)
                .put("app_uid",android.os.Process.myUid()).put("at_wall_ms",System.currentTimeMillis())
                .put("private_request_consumed",consumed).put("automatic_resume",false);
            out=file.startWrite();out.write(value.toString(2).getBytes(StandardCharsets.UTF_8));file.finishWrite(out);out=null;
            android.system.Os.chmod(file.getBaseFile().getPath(),0600);
        }catch(Exception ignored){if(out!=null)file.failWrite(out);}
    }
    @Override protected void onStart(){super.onStart();if(tasks!=null)tasks.bind(this);}
    @Override protected void onResume(){super.onResume();if(tasks!=null)refresh();}
    @Override protected void onStop(){if(tasks!=null)tasks.unbind(this);super.onStop();}
}
