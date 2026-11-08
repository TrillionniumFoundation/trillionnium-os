package org.trillionnium.hepta.gpuprobe;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.graphics.Typeface;
import android.system.Os;
import android.widget.*;
import org.json.JSONObject;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.UUID;

/** Diagnostic-only inference. No Accessibility service, actions, network, or shell command API. */
public final class MainActivity extends Activity {
    private LocalModelEngine engine;
    private EditText prompt;
    private Spinner profile;
    private CheckBox official;
    private TextView status,output,model;
    private Button textRun,imageRun,stop;
    private String lastShown;

    @Override public void onCreate(Bundle state){
        super.onCreate(state);engine=((GpuProbeApplication)getApplication()).engine();
        ScrollView scroll=new ScrollView(this);LinearLayout page=new LinearLayout(this);page.setOrientation(LinearLayout.VERTICAL);
        int pad=dp(16);page.setPadding(pad,pad,pad,pad);scroll.addView(page);
        page.addView(label("Hepta GPU 验证",25));
        page.addView(label("GUI-Owl 1.5 · 2B · 手机本地推理诊断\n此应用不执行手机操作。",15));
        model=label("",12);page.addView(model);
        profile=new Spinner(this);ArrayAdapter<RuntimeProfile> adapter=new ArrayAdapter<>(this,android.R.layout.simple_spinner_item,RuntimeProfile.values());
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);profile.setAdapter(adapter);page.addView(profile);
        official=new CheckBox(this);official.setText("使用官方 GUI-Owl 手机操作提示词");page.addView(official);
        prompt=new EditText(this);prompt.setMinLines(3);prompt.setText("只输出 42。");page.addView(prompt);
        page.addView(label("图片固定读取应用私有 files/probe-image.png；保留原图，按比例缩小后进行精确 token 计数。",12));
        LinearLayout buttons=new LinearLayout(this);page.addView(buttons);
        textRun=button("GPU 文本");imageRun=button("GPU 图片");stop=button("停止");buttons.addView(textRun);buttons.addView(imageRun);buttons.addView(stop);
        textRun.setOnClickListener(v->run(false,128,180000,null,false));
        imageRun.setOnClickListener(v->run(true,256,240000,null,false));
        stop.setOnClickListener(v->{engine.cancelActive();status.setText("已请求停止本应用的推理进程，等待退出确认。");refresh();});
        status=label("尚未运行",15);page.addView(status);output=label("",11);output.setTypeface(Typeface.MONOSPACE);output.setTextIsSelectable(true);page.addView(output);
        setContentView(scroll);refresh();handle(getIntent());
    }
    @Override protected void onNewIntent(Intent intent){super.onNewIntent(intent);setIntent(intent);handle(intent);}
    @Override protected void onResume(){super.onResume();if(engine!=null)refresh();}
    private void handle(Intent intent){
        if(intent==null)return;
        try{
            String id=intent.getStringExtra("profile");
            if(id!=null){RuntimeProfile selected=RuntimeProfile.fromId(id);profile.setSelection(selected.ordinal());}
            String text=intent.getStringExtra("prompt");if(text!=null)prompt.setText(text);
            String systemMode=intent.getStringExtra("system_mode");
            if(systemMode!=null){if(!systemMode.equals("official")&&!systemMode.equals("simple"))throw new IOException("system_mode must be official or simple");official.setChecked(systemMode.equals("official"));}
            if(intent.getBooleanExtra("auto_run",false)){
                intent.removeExtra("auto_run");
                String mode=intent.getStringExtra("mode");if(!"text".equals(mode)&&!"image".equals(mode))throw new IOException("mode must be text or image");
                boolean image="image".equals(mode);int tokens=intent.getIntExtra("max_tokens",image?256:128);
                long timeout=intent.getLongExtra("timeout_ms",image?240000:180000);
                String caseId=intent.getStringExtra("case_id");if(caseId==null)throw new IOException("auto_run requires a unique case_id");
                run(image,tokens,timeout,caseId,intent.getBooleanExtra("prompt_file",false));
            }
        }catch(Exception e){status.setText("未启动："+e.toString());}
    }
    private void run(boolean image,int maxTokens,long timeout,String suppliedCase,boolean fromFile){
        if(engine.isBusy()){status.setText("已有推理或进程退出待确认，请先停止并等待。");return;}
        String caseId=suppliedCase==null?"ui-"+UUID.randomUUID().toString():suppliedCase;
        File trigger=null;boolean ownedTrigger=false;LocalModelEngine.RunHandle handle=null;
        try{
            if(!caseId.matches("[A-Za-z0-9][A-Za-z0-9_-]{0,95}"))throw new IOException("case_id format invalid");
            File triggers=new File(getFilesDir(),"triggers");if(!triggers.isDirectory()&&!triggers.mkdirs())throw new IOException("cannot create trigger directory");Os.chmod(triggers.getPath(),0700);
            trigger=new File(triggers,caseId+".json");if(!trigger.createNewFile())throw new IOException("case already exists; automatic replay is forbidden");ownedTrigger=true;Os.chmod(trigger.getPath(),0600);
            String input=fromFile?read(new FileInputStream(new File(getFilesDir(),"probe-prompt.txt")),65536):prompt.getText().toString();
            String system=official.isChecked()?read(getAssets().open("guiowl-system.txt"),8192):"你是在手机本地运行的助手。请直接、简洁地回答用户指令。";
            RuntimeProfile selected=(RuntimeProfile)profile.getSelectedItem();
            JSONObject record=new JSONObject();record.put("schema","hepta.gpu-probe.trigger.v1");record.put("case_id",caseId);
            record.put("package_name",getPackageName());record.put("app_uid",android.os.Process.myUid());record.put("started_wall_ms",System.currentTimeMillis());
            record.put("prompt_sha256",sha(input));record.put("system_sha256",sha(system));record.put("runtime_profile",selected.id);
            record.put("mode",image?"vlm":"llm");record.put("phone_actions_supported",false);record.put("automatic_retry",false);
            handle=engine.start(new LocalModelEngine.Request(input,system,image?new File(getFilesDir(),"probe-image.png"):null,maxTokens,timeout,selected),
                result->runOnUiThread(()->{render(result);refresh();}));
            record.put("run_id",handle.runId);record.put("request_status","started");
            write(trigger,record.toString(2));
            status.setText("正在本地推理 · "+caseId+"\n运行编号："+handle.runId);
            output.setText("");lastShown=null;refresh();
        }catch(Exception e){
            if(handle!=null)handle.cancel();
            if(ownedTrigger&&trigger!=null&&trigger.isFile()&&trigger.length()==0){try{JSONObject fail=new JSONObject();fail.put("case_id",caseId);fail.put("request_status","failed_before_binding");fail.put("error",e.toString());write(trigger,fail.toString(2));}catch(Exception ignored){}}
            status.setText("未完成启动："+e.toString());refresh();
        }
    }
    private void render(LocalModelEngine.Result result){
        lastShown=result.runId;status.setText("推理状态："+result.status+" · 退出已确认："+result.processExitObserved+" / "+result.exitCode+"\n完整推理及预算校验："+result.inferenceCompleted);
        String visible=result.rawText.length()>16000?result.rawText.substring(0,16000)+"\n（界面显示前 16000 字符；文件保留完整输出）":result.rawText;
        output.setText(visible+"\n\n凭据："+result.runDirectory+"\n"+result.receipt.toString());
    }
    private void refresh(){
        boolean busy=engine.isBusy();textRun.setEnabled(!busy);imageRun.setEnabled(!busy);profile.setEnabled(!busy);official.setEnabled(!busy);stop.setEnabled(busy);
        RuntimeProfile p=(RuntimeProfile)profile.getSelectedItem();File dir=engine.modelDirectory(p);
        model.setText("普通 Android 应用权限 · 无网络权限 · 上下文 8192\n"+(new File(dir,"model.gguf").isFile()&&new File(dir,"mmproj.gguf").isFile()?"本地 GGUF 与视觉投影已导入":"等待导入本地 GGUF 与视觉投影")+" · 可用 RAM "+String.format(Locale.US,"%.2f GiB",engine.availableMemoryBytes()/1073741824.0));
        LocalModelEngine.Result result=engine.lastResult();if(!busy&&result!=null&&!result.runId.equals(lastShown))render(result);
    }
    private int dp(int n){return Math.round(n*getResources().getDisplayMetrics().density);}
    private TextView label(String s,int size){TextView v=new TextView(this);v.setText(s);v.setTextSize(size);v.setPadding(0,dp(5),0,dp(5));return v;}
    private Button button(String s){Button b=new Button(this);b.setText(s);return b;}
    private static String read(InputStream input,int limit)throws IOException{try(InputStream in=input;ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[] b=new byte[8192];int n;while((n=in.read(b))!=-1){if(out.size()+n>limit)throw new IOException("input exceeds bound");out.write(b,0,n);}return new String(out.toByteArray(),StandardCharsets.UTF_8);}}
    private static void write(File file,String text)throws Exception{try(FileOutputStream out=new FileOutputStream(file,false)){out.write(text.getBytes(StandardCharsets.UTF_8));out.getFD().sync();}Os.chmod(file.getPath(),0600);}
    private static String sha(String text)throws Exception{StringBuilder out=new StringBuilder(64);for(byte b:MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)))out.append(String.format(Locale.US,"%02x",b&255));return out.toString();}
}
