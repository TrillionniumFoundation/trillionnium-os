package org.trillionnium.hepta.internprobe;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Typeface;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.File;
import java.util.Locale;

/** Text/image inference diagnostics only. No phone observation or control API is present. */
public final class MainActivity extends Activity {
    private LocalModelEngine engine;
    private EditText prompt;
    private TextView information,output;
    private Button textProbe,imageProbe,stop;
    private String shownRunId;

    @Override public void onCreate(Bundle state){
        super.onCreate(state);engine=((ProbeApplication)getApplication()).modelEngine();
        ScrollView outer=new ScrollView(this);
        LinearLayout page=new LinearLayout(this);page.setOrientation(LinearLayout.VERTICAL);
        int pad=dp(16);page.setPadding(pad,pad,pad,pad);outer.addView(page);
        page.addView(label("Hepta Intern NPU 验证",23));
        page.addView(label("Intern3.5-VL-2B · QAIRT / Hexagon NPU\n仅本地推理诊断，不执行手机操作",15));
        information=label("",12);page.addView(information);
        prompt=new EditText(this);prompt.setText("只输出 42。");prompt.setMinLines(3);page.addView(prompt);
        LinearLayout buttons=new LinearLayout(this);page.addView(buttons);
        textProbe=button("文本推理");imageProbe=button("图像推理");stop=button("停止推理");
        buttons.addView(textProbe);buttons.addView(imageProbe);buttons.addView(stop);
        textProbe.setOnClickListener(v->runProbe(false,128));
        imageProbe.setOnClickListener(v->runProbe(true,256));
        stop.setOnClickListener(v->{engine.cancelActive();output.setText("正在请求本次推理退出，实际退出状态以回执为准。");refresh();});
        page.addView(label("图像诊断固定读取本应用私有 files/probe-image.png。模型文件与 tokenizer 的实际身份、上下文完整性仍需独立验证。",12));
        output=label("尚未运行本机 Intern 模型验证。",12);output.setTypeface(Typeface.MONOSPACE);output.setTextIsSelectable(true);page.addView(output);
        setContentView(outer);refresh();
        // A recreated Activity may display the existing engine, but does not replay auto_run.
        if(state==null)handleIntent(getIntent());
    }
    @Override protected void onNewIntent(Intent intent){super.onNewIntent(intent);setIntent(intent);handleIntent(intent);}
    @Override protected void onResume(){super.onResume();if(engine!=null&&information!=null)refresh();}
    private void handleIntent(Intent intent){
        if(intent==null)return;
        String supplied=intent.getStringExtra("prompt");if(supplied!=null)prompt.setText(supplied);
        if(intent.getBooleanExtra("auto_run",false)){
            boolean image="image".equals(intent.getStringExtra("mode"));
            int max=intent.getIntExtra("max_tokens",image?256:128);
            intent.removeExtra("auto_run");
            prompt.post(()->runProbe(image,max));
        }
    }
    private void runProbe(boolean image,int max){
        if(engine.isBusy()){output.setText("已有本地推理运行中或退出待确认；未发起新的推理。");return;}
        String system=getIntent().getStringExtra("system_prompt");
        if(system==null)system="你是在手机本地运行的助手。请直接、简洁地回答用户指令。";
        long timeout=getIntent().getLongExtra("timeout_ms",120000L);
        output.setText("正在运行独立 Intern 本地 NPU 诊断……");
        try{
            engine.start(new LocalModelEngine.Request(prompt.getText().toString(),system,
                    image?new File(getFilesDir(),"probe-image.png"):null,max,timeout),
                    result->runOnUiThread(()->{if(!isFinishing()&&!isDestroyed()){render(result);refresh();}}));
            refresh();
        }catch(Exception error){output.setText("诊断未启动："+error);refresh();}
    }
    private void refresh(){
        File config=new File(engine.modelDirectory(),"genie_config.json");
        information.setText("包名："+getPackageName()+"\nUID："+android.os.Process.myUid()
                +"\n私有模型目录："+engine.modelDirectory()+"\n已安装运行库："+getApplicationInfo().nativeLibraryDir
                +"\n可用 RAM："+String.format(Locale.US,"%.2f GiB",engine.availableMemoryBytes()/1073741824.0)
                +"\n配置文件："+(config.isFile()?"存在；模型身份尚需验证":"未导入")
                +"\n目标编译配置：4096 上下文 / 448×448 图像 / 256 视觉 token（实际包待核对）");
        boolean busy=engine.isBusy();textProbe.setEnabled(!busy);imageProbe.setEnabled(!busy);stop.setEnabled(busy);
        LocalModelEngine.Result result=engine.lastResult();
        if(result!=null&&!busy&&!result.runId.equals(shownRunId))render(result);
    }
    private void render(LocalModelEngine.Result result){
        shownRunId=result.runId;String receipt;
        try{receipt=result.receipt.toString(2);}catch(Exception error){receipt=result.receipt.toString();}
        String raw=result.rawText.length()>16000?result.rawText.substring(0,16000)+"\n（界面仅显示前16000字符；完整输出已单独保存）":result.rawText;
        output.setText("状态："+result.status+"\n真实进程退出："+result.processExitObserved+" / "+result.exitCode
                +"\n推理完整完成："+result.inferenceCompleted+"\n本结果不代表输入未截断或手机任务完成。\n\n"+raw
                +"\n\n凭据目录："+result.runDirectory+"\n"+receipt);
    }
    private int dp(int n){return Math.round(n*getResources().getDisplayMetrics().density);}
    private TextView label(String value,int size){TextView view=new TextView(this);view.setText(value);view.setTextSize(size);view.setPadding(0,dp(5),0,dp(5));return view;}
    private Button button(String value){Button button=new Button(this);button.setText(value);return button;}
}
