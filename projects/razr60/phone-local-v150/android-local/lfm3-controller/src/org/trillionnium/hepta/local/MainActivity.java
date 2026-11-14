package org.trillionnium.hepta.local;

import android.app.Activity;
import android.app.AlertDialog;
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
public final class MainActivity extends Activity implements LocalTaskSession.Listener,BackgroundPermissionSession.Listener {
    private LocalModelEngine engine;
    private LocalTaskSession tasks;
    private MobiMindModelEngine visualDiagnostic;
    private UiVenusModelEngine uiVenusDiagnostic;
    private BackgroundPermissionSession backgroundPermission;
    private Button prepareBackgroundPermission,openRootManager;
    private TextView backgroundPermissionState;
    private TextView backgroundSummary,modelDiagnostics,taskDiagnostics;
    private EditText taskInput, probePrompt;
    private TextView modelInfo, taskState, taskLog, taskResult, probeOutput;
    private TextView taskAuthorizationInfo;
    private boolean accessibilityUiStarted;
    private boolean cachedModelFilePresent;
    private final Runnable accessibilityConnectionChanged=new Runnable(){
        @Override public void run(){
            if(accessibilityUiStarted&&!isFinishing()&&!isDestroyed())refresh();
        }
    };
    private CheckBox backgroundMode;
    private Button pickBackgroundApps,cleanupBackground;
    private Spinner initialBackgroundApp;
    private TextView backgroundChoiceState,backgroundInitialLabel;
    private BackgroundUiPreferences.Selection rememberedBackgroundSelection;
    private String backgroundModePreferenceError,backgroundSelectionPreferenceError;
    private boolean backgroundInitialChoicePending;
    private final java.util.Map<String,String> backgroundAppLabels=new java.util.TreeMap<String,String>();
    private final java.util.Set<String> backgroundPackages=new java.util.TreeSet<String>();
    private final java.util.List<String> backgroundInitialPackages=new java.util.ArrayList<String>();
    private TextView visualProbeOutput;
    private TextView uiVenusProbeOutput;
    private LinearLayout diagnostics;
    private Button startTask, stopTask, runText, acknowledgeInterruption;
    private String lastShownProbeId;
    private QualificationScope.Launch scopeLaunch=QualificationScope.Launch.normal();
    private String scopeLaunchError;
    private static final String SCOPE_INTENT_CONSUMED="hepta_scope_prefill_consumed";
    private String lastShownVisualProbeId;
    private String lastShownUiVenusProbeId;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LocalProbeApplication app=(LocalProbeApplication)getApplication();
        engine=app.modelEngine();tasks=app.taskSession();visualDiagnostic=app.mobiMindDiagnostic();
        backgroundPermission=app.backgroundPermissionPreparation();
        uiVenusDiagnostic=app.uiVenusDiagnostic();
        ScrollView outer=new ScrollView(this);outer.setFillViewport(true);
        LinearLayout page=new LinearLayout(this);page.setOrientation(LinearLayout.VERTICAL);
        int pad=dp(16);page.setPadding(pad,pad,pad,pad);outer.addView(page);
        TextView title=text("Hepta",25);page.addView(title);
        page.addView(text("用手机本地模型理解指令并操作应用",15));
        modelInfo=text("",12);modelInfo.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);page.addView(modelInfo);
        taskInput=new EditText(this);taskInput.setHint("你想让手机完成什么？");
        taskInput.setText("记一下，明天下午3点看牙，带上检查资料。");taskInput.setMinLines(3);page.addView(taskInput);
        taskAuthorizationInfo=text("",12);
        taskInput.addTextChangedListener(new android.text.TextWatcher(){
            public void beforeTextChanged(CharSequence s,int start,int count,int after){}
            public void onTextChanged(CharSequence s,int start,int before,int count){previewTaskAuthorization();}
            public void afterTextChanged(android.text.Editable value){}
        });
        previewTaskAuthorization();
        backgroundMode=new CheckBox(this);backgroundMode.setText("在后台空间操作");page.addView(backgroundMode);
        backgroundPermissionState=text("",12);
        backgroundSummary=text("",12);page.addView(backgroundSummary);
        Button showBackgroundPermission=button("后台权限与高级设置（展开）");
        final LinearLayout backgroundPermissionDetails=new LinearLayout(this);
        backgroundPermissionDetails.setOrientation(LinearLayout.VERTICAL);
        backgroundPermissionDetails.setVisibility(View.GONE);backgroundPermissionDetails.addView(backgroundPermissionState);
        showBackgroundPermission.setOnClickListener(v -> {
            boolean expanded=backgroundPermissionDetails.getVisibility()!=View.VISIBLE;
            backgroundPermissionDetails.setVisibility(expanded?View.VISIBLE:View.GONE);
            showBackgroundPermission.setText(expanded?"后台权限与高级设置（收起）":"后台权限与高级设置（展开）");
        });
        backgroundPermissionDetails.addView(text("后台操作需要本机 root 权限。Magisk 31.1 及以上不再弹出授权请求：请在管理器的「超级用户」页点「+」，添加并允许 Hepta（org.trillionnium.hepta.local，UID "+android.os.Process.myUid()+"），然后返回核验。其它版本请按管理器界面操作。",12));
        openRootManager=button("打开 Magisk 管理器");backgroundPermissionDetails.addView(openRootManager);
        openRootManager.setOnClickListener(v -> openRootManagerFromOwnerButton());
        prepareBackgroundPermission=button("核验后台执行权限");backgroundPermissionDetails.addView(prepareBackgroundPermission);
        prepareBackgroundPermission.setOnClickListener(v -> {
            if(!hasWindowFocus()||isFinishing()||isDestroyed())return;
            try{app.prepareBackgroundPermissionFromOwnerButton();refresh();}
            catch(Exception error){refresh();backgroundPermissionState.setText("权限准备未开始："+HeptaAccessibilityService.message(error));}
        });
        backgroundPermissionDetails.addView(text("先选择可操作的应用范围，再选择本次任务的起始应用。任务会使用你明确选择的应用，不会自动改用网页查询工具。开始时会先打开该应用。后台任务需要本机 root 授权；应用兼容性可能影响隔离，遇到越界或锁屏会停止。",12));
        pickBackgroundApps=button("选择后台应用范围");page.addView(pickBackgroundApps);
        pickBackgroundApps.setOnClickListener(v -> chooseBackgroundApps());
        backgroundChoiceState=text("",12);page.addView(backgroundChoiceState);
        initialBackgroundApp=new Spinner(this){
            @Override public boolean performClick(){backgroundInitialChoicePending=true;return super.performClick();}
        };
        initialBackgroundApp.setOnKeyListener((view,key,event) -> {
            if(event.getAction()==android.view.KeyEvent.ACTION_DOWN
                    &&(key==android.view.KeyEvent.KEYCODE_DPAD_CENTER||key==android.view.KeyEvent.KEYCODE_ENTER
                    ||key==android.view.KeyEvent.KEYCODE_SPACE||key==android.view.KeyEvent.KEYCODE_DPAD_UP
                    ||key==android.view.KeyEvent.KEYCODE_DPAD_DOWN))backgroundInitialChoicePending=true;
            return false;
        });
        backgroundInitialLabel=text("本次任务的起始应用",12);page.addView(backgroundInitialLabel);page.addView(initialBackgroundApp);
        reloadBackgroundApps();updateBackgroundSelection(null);
        cleanupBackground=button("清理上一次后台空间");
        cleanupBackground.setOnClickListener(v -> {try{tasks.reconcileBackgroundFromOwnerButton();}catch(Exception error){taskState.setText("清理未开始："+HeptaAccessibilityService.message(error));}refresh();});
        LinearLayout actions=new LinearLayout(this);page.addView(actions);
        startTask=button("开始任务");actions.addView(startTask);
        stopTask=button("停止");actions.addView(stopTask);
        Button accessibility=button("启用无障碍");actions.addView(accessibility);
        page.addView(cleanupBackground);
        startTask.setOnClickListener(v -> beginTask(taskInput.getText().toString(),"user_button",null));
        stopTask.setOnClickListener(v -> {
            // Controlled tasks cancel their captured task/handle. A diagnostic cancels one captured engine run.
            boolean controlled=tasks.isRunning();tasks.stop();if(!controlled)engine.cancelActive();
            // Explicitly ends this UI prefill only; the running task retains its immutable scope.
            scopeLaunch=QualificationScope.Launch.normal();scopeLaunchError=null;refresh(false);});
        accessibility.setOnClickListener(v -> startActivity(new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)));
        acknowledgeInterruption=button("确认中断并开始新会话");page.addView(acknowledgeInterruption);
        acknowledgeInterruption.setOnClickListener(v -> new AlertDialog.Builder(this)
            .setTitle("保留旧任务，建立新会话")
            .setMessage("旧任务不会恢复。它仍记为中断，原进程退出与清理状态仍未知。应用会先保存原记录并核验当前可见的本应用进程；通过后只建立空闲会话，不会自动开始任务。其它诊断仍未确认退出时不能解除阻塞。")
            .setNegativeButton("暂不确认",null)
            .setPositiveButton("确认并核验",(dialog,which) -> {
                try{tasks.acknowledgeInterruptionFromOwnerButton();}
                catch(Exception error){taskState.setText("无法确认中断："+HeptaAccessibilityService.message(error));}
            }).show());
        taskState=text("",15);taskState.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);page.addView(taskState);
        ScrollView progress=new ScrollView(this);
        progress.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS);
        progress.setLayoutParams(new LinearLayout.LayoutParams(-1,dp(150)));
        taskLog=text("",12);taskLog.setTypeface(Typeface.MONOSPACE);taskLog.setTextIsSelectable(true);progress.addView(taskLog);
        taskResult=text("",13);taskResult.setTextIsSelectable(true);taskResult.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);page.addView(taskResult);
        Button showDiagnostics=button("高级诊断");page.addView(showDiagnostics);
        diagnostics=new LinearLayout(this);diagnostics.setOrientation(LinearLayout.VERTICAL);diagnostics.setVisibility(View.GONE);page.addView(diagnostics);
        showDiagnostics.setOnClickListener(v -> diagnostics.setVisibility(diagnostics.getVisibility()==View.VISIBLE?View.GONE:View.VISIBLE));
        modelDiagnostics=text("",12);diagnostics.addView(modelDiagnostics);
        diagnostics.addView(showBackgroundPermission);diagnostics.addView(backgroundPermissionDetails);
        diagnostics.addView(text("本次指令的权限与工具范围",12));diagnostics.addView(taskAuthorizationInfo);
        diagnostics.addView(text("任务记录",12));diagnostics.addView(progress);
        taskDiagnostics=text("",12);taskDiagnostics.setTextIsSelectable(true);diagnostics.addView(taskDiagnostics);
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
        setContentView(outer);tasks.bind(this);refresh();
        restoreBackgroundPreferences();
        if(state==null)handleIntent(getIntent());else{restoreScopeUi(state);restoreBackgroundUi(state);}
        installBackgroundPreferenceListeners();refresh();
    }
    private int dp(int value){return Math.round(value*getResources().getDisplayMetrics().density);}
    private TextView text(String value,int size){TextView view=new TextView(this);view.setText(value);view.setTextSize(size);view.setPadding(0,dp(5),0,dp(5));return view;}
    private Button button(String label){Button view=new Button(this);view.setText(label);return view;}
    /** Normal owner navigation only; no grant, su request, task or permission-state update. */
    private void openRootManagerFromOwnerButton(){
        if(!hasWindowFocus()||isFinishing()||isDestroyed())return;
        if(!rootManagerNavigationIdle()){
            backgroundPermissionState.setText("请先结束当前任务、诊断或权限核验，再打开管理器。");return;
        }
        try{
            Intent launch=getPackageManager().getLaunchIntentForPackage("com.topjohnwu.magisk");
            if(launch==null){backgroundPermissionState.setText("未找到默认包名的 Magisk 管理器。若管理器已隐藏或改名，请从桌面手动打开；授权 Hepta 后返回核验。");return;}
            startActivity(launch);
        }catch(android.content.ActivityNotFoundException|SecurityException error){
            backgroundPermissionState.setText("无法打开 Magisk 管理器，请从桌面手动打开并授权 Hepta，然后返回核验。");
        }
    }
    private boolean rootManagerNavigationIdle(){
        return !tasks.isRunning()&&!tasks.isBlocked()&&!tasks.isRecovering()&&!tasks.hasBackgroundLease()
                &&!engine.isBusy()&&!backgroundPermission.blocksOtherWork()
                &&!visualDiagnostic.isBusy()&&!visualDiagnostic.isBlocked()
                &&!uiVenusDiagnostic.isBusy()&&!uiVenusDiagnostic.isBlocked();
    }
    private void previewTaskAuthorization(){
        if(taskAuthorizationInfo==null)return;
        try{
            String owner=taskInput.getText().toString();TaskAuthorization preview=TaskAuthorization.parse(owner);
            if(backgroundMode!=null&&backgroundMode.isChecked()){
                BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(owner,selectedBackgroundPackage(),backgroundPackages);
                preview=preview.forExecutionSelection(new BackgroundSession.Selection(target));
            }
            taskAuthorizationInfo.setText(preview.summary());
        }
        catch(Exception error){taskAuthorizationInfo.setText("本次限制无法识别，任务不会启动："+HeptaAccessibilityService.message(error));}
        refreshBackgroundTaskTarget();
    }

    @Override protected void onSaveInstanceState(Bundle state){
        super.onSaveInstanceState(state);
        state.putBoolean("scope_ui_saved",true);state.putString("scope_ui_task",taskInput.getText().toString());
        state.putString("scope_ui_expected",scopeLaunch.expectedSha256);state.putString("scope_ui_owner",scopeLaunch.ownerSha256);
        state.putBoolean("scope_ui_consumed",scopeLaunch.consumed);state.putString("scope_ui_error",scopeLaunchError);
        state.putBoolean("background_mode",backgroundMode.isChecked());
        state.putStringArrayList("background_packages",new java.util.ArrayList<String>(backgroundPackages));
        state.putString("background_initial",selectedBackgroundPackage());
    }
    private void restoreScopeUi(Bundle state){
        try{
            QualificationScope.require(state.getBoolean("scope_ui_saved",false),"saved UI binding missing");
            String owner=state.getString("scope_ui_task");QualificationScope.require(owner!=null,"saved task missing");taskInput.setText(owner);
            String expected=state.getString("scope_ui_expected"),ownerSha=state.getString("scope_ui_owner");boolean consumed=state.getBoolean("scope_ui_consumed",false);
            if(expected==null){QualificationScope.require(ownerSha==null&&!consumed,"saved unscoped binding inconsistent");scopeLaunch=QualificationScope.Launch.normal();}
            else scopeLaunch=QualificationScope.Launch.restore(expected,ownerSha,consumed);
            scopeLaunchError=state.getString("scope_ui_error");
        }catch(Exception error){scopeLaunchError=HeptaAccessibilityService.message(error);}
    }
    /** Consume the restriction once. Reused Intents cannot replay or clear a pending claim. */
    private void acceptScopePrefill(Intent intent,String task,String expected,boolean hasExpected,boolean autoTask){
        if(intent.getBooleanExtra(SCOPE_INTENT_CONSUMED,false)||tasks.isRunning())return;
        boolean normalEntry=Intent.ACTION_MAIN.equals(intent.getAction())&&intent.hasCategory(Intent.CATEGORY_LAUNCHER);
        if(task==null&&!hasExpected&&!normalEntry&&!autoTask)return;
        scopeLaunch=QualificationScope.Launch.normal();scopeLaunchError=null;
        if(hasExpected||autoTask)backgroundMode.setChecked(false);
        if(task!=null)taskInput.setText(task);
        try{
            QualificationScope.require(!hasExpected||expected!=null,"null expected scope extra");
            if(!autoTask)scopeLaunch=QualificationScope.Launch.prefill(task,expected);
            else QualificationScope.expected(expected); // The consumed private request supplies the exact OWNER below.
        }catch(Exception error){scopeLaunchError=HeptaAccessibilityService.message(error);}
    }

    @Override protected void onNewIntent(Intent intent){super.onNewIntent(intent);setIntent(intent);handleIntent(intent);}
    private void handleIntent(Intent intent){
        if(intent==null)return;
        final String suppliedTask=intent.getStringExtra("task");
        final boolean hasExpectedScope=intent.hasExtra(QualificationScope.EXPECTED_EXTRA);
        final String expectedScope=intent.getStringExtra(QualificationScope.EXPECTED_EXTRA);
        boolean scopeIntentReused=intent.getBooleanExtra(SCOPE_INTENT_CONSUMED,false);
        acceptScopePrefill(intent,suppliedTask,expectedScope,hasExpectedScope,intent.getBooleanExtra("auto_task",false));
        intent.removeExtra("task");intent.removeExtra(QualificationScope.EXPECTED_EXTRA);
        intent.putExtra(SCOPE_INTENT_CONSUMED,true);
        if(scopeIntentReused)return;
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
        if(intent.getBooleanExtra("auto_task",false)){
            final String nonce=intent.getStringExtra("test_nonce");
            intent.removeExtra("auto_task");intent.removeExtra("test_nonce");
            boolean consumed=false;
            try{
                if(tasks.isRunning()||tasks.isBlocked()||engine.isBusy())throw new IllegalStateException("已有本地请求或退出状态待确认");
                if(HeptaAccessibilityService.connected()==null)throw new IllegalStateException("请先正常启用 Hepta 本地操作无障碍服务");
                PrivateDebugTask request=PrivateDebugTask.consume(this,nonce);
                consumed=true;
                if(scopeLaunchError!=null)throw new IllegalStateException(scopeLaunchError);
                if(hasExpectedScope&&suppliedTask!=null)QualificationScope.require(suppliedTask.equals(request.instruction),"private OWNER differs from scoped prefill");
                scopeLaunch=QualificationScope.Launch.prefill(request.instruction,expectedScope);
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
            if(scopeLaunchError!=null)throw new IllegalStateException(scopeLaunchError);
            final TaskAuthorization originalAuthorization=TaskAuthorization.parse(owner);
            final TaskAuthorization authorization;
            final String expectedScope=scopeLaunch.claim(owner);
            final BackgroundSession.Selection selection;
            if(backgroundMode.isChecked()){
                if(!"user_button".equals(source))throw new IllegalStateException("后台应用范围只能由当前可见的开始按钮确认");
                QualificationScopeConfig.FilesRoot root=new QualificationScopeConfig.FilesRoot(this);
                if(expectedScope!=null||MobiMindPrivateFiles.exists(new File(root.path,QualificationScope.FILE_NAME)))
                    throw new IllegalStateException("当前 qualification scope 已启用，后台任务不可启动；原范围保持不变");
                requireCurrentBackgroundChoice();
                BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(owner,selectedBackgroundPackage(),backgroundPackages);
                selection=new BackgroundSession.Selection(target);
                authorization=originalAuthorization.forExecutionSelection(selection);
                selection.requireTaskTarget(owner,authorization);
                if(authorization.requireFindAppBeforeOpen||!authorization.allowedTools.contains("open"))
                    throw new IllegalStateException("当前指令的方法限制不允许预先打开后台起始应用，请使用前台模式");
            }else{selection=null;authorization=originalAuthorization;}
            if(!tasks.schedule(owner,source,nonceSha,expectedScope,authorization,selection,500))throw new IllegalStateException("本地任务未能取得唯一会话");
            scopeLaunch=scopeLaunch.accepted();
            InputMethodManager input=(InputMethodManager)getSystemService(INPUT_METHOD_SERVICE);
            if(input!=null)input.hideSoftInputFromWindow(taskInput.getWindowToken(),0);
            if(selection==null&&!moveTaskToBack(true)){tasks.stop();taskState.setText("无法切换到手机前台画面，任务未开始");return false;}
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
    private void reloadBackgroundApps(){
        backgroundAppLabels.clear();
        String home=null;
        android.content.pm.ResolveInfo homeInfo=getPackageManager().resolveActivity(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME),android.content.pm.PackageManager.MATCH_DEFAULT_ONLY);
        if(homeInfo!=null&&homeInfo.activityInfo!=null)home=homeInfo.activityInfo.packageName;
        for(android.content.pm.ResolveInfo info:getPackageManager().queryIntentActivities(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER),0)){
            if(info.activityInfo==null||!info.activityInfo.enabled||!info.activityInfo.exported)continue;
            String pkg=info.activityInfo.packageName;
            if(pkg.equals(getPackageName())||pkg.equals(home)||"android".equals(pkg)||"com.android.systemui".equals(pkg))continue;
            backgroundAppLabels.put(pkg,String.valueOf(info.loadLabel(getPackageManager())));
        }
    }
    private void chooseBackgroundApps(){
        reloadBackgroundApps();final java.util.List<String> packages=new java.util.ArrayList<String>(backgroundAppLabels.keySet());
        final java.util.Set<String> chosen=new java.util.TreeSet<String>(backgroundPackages);chosen.retainAll(packages);
        String[] labels=new String[packages.size()];boolean[] checked=new boolean[packages.size()];
        for(int i=0;i<packages.size();i++){String pkg=packages.get(i);labels[i]=backgroundAppLabels.get(pkg)+" · "+pkg;checked[i]=chosen.contains(pkg);}
        final String initial=selectedBackgroundPackage();
        new AlertDialog.Builder(this).setTitle("本次后台可操作应用（最多 6 个）")
                .setMultiChoiceItems(labels,checked,(dialog,which,enabled) -> {if(enabled)chosen.add(packages.get(which));else chosen.remove(packages.get(which));})
                .setNegativeButton("取消",null).setPositiveButton("使用所选应用",(dialog,which) -> {
                    if(chosen.isEmpty()||chosen.size()>6){taskState.setText("请选择 1 至 6 个后台应用");return;}
                    backgroundPackages.clear();backgroundPackages.addAll(chosen);updateBackgroundSelection(initial);
                    rememberExplicitBackgroundChoice();refresh();
                }).show();
    }
    private String selectedBackgroundPackage(){int index=initialBackgroundApp==null?-1:initialBackgroundApp.getSelectedItemPosition();
        return index>=0&&index<backgroundInitialPackages.size()?backgroundInitialPackages.get(index):null;}
    private void updateBackgroundSelection(String initial){
        backgroundInitialChoicePending=false;
        backgroundInitialPackages.clear();backgroundInitialPackages.addAll(backgroundPackages);
        java.util.List<String> labels=new java.util.ArrayList<String>();
        for(String pkg:backgroundInitialPackages)labels.add(backgroundAppLabels.getOrDefault(pkg,pkg)+" · "+pkg);
        if(labels.isEmpty())labels.add("请先选择后台应用");
        ArrayAdapter<String> adapter=new ArrayAdapter<String>(this,android.R.layout.simple_spinner_item,labels);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);initialBackgroundApp.setAdapter(adapter);
        int selected=backgroundInitialPackages.indexOf(initial);if(selected>=0)initialBackgroundApp.setSelection(selected);
        pickBackgroundApps.setText(backgroundPackages.isEmpty()?"选择后台应用范围":"后台范围："+backgroundPackages.size()+" 个应用（更改）");
    }
    private void restoreBackgroundUi(Bundle state){
        backgroundMode.setChecked(state.getBoolean("background_mode",false));
        try{
            java.util.ArrayList<String> saved=state.getStringArrayList("background_packages");
            if(saved!=null&&saved.size()>6)throw new IllegalStateException("saved range too large");
            backgroundPackages.clear();
            if(saved!=null)for(String pkg:saved){
                if(pkg==null||!pkg.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+")||!backgroundPackages.add(pkg))
                    throw new IllegalStateException("saved range malformed");
            }
            updateBackgroundSelection(state.getString("background_initial"));recheckBackgroundChoice();
        }catch(Exception error){backgroundSelectionPreferenceError="无法恢复当前应用范围，请重新选择。";}
    }
    /** Restore only owner UI choices. Nothing here creates or resumes a task. */
    private void restoreBackgroundPreferences(){
        try{backgroundMode.setChecked(BackgroundUiPreferences.mode(this));backgroundModePreferenceError=null;}
        catch(Exception error){backgroundMode.setChecked(true);backgroundModePreferenceError="无法读取上次的后台模式，请重新选择。";}
        try{
            rememberedBackgroundSelection=BackgroundUiPreferences.load(this);
            backgroundPackages.clear();
            if(rememberedBackgroundSelection!=null)backgroundPackages.addAll(rememberedBackgroundSelection.packages.keySet());
            updateBackgroundSelection(rememberedBackgroundSelection==null?null:rememberedBackgroundSelection.initial);
            recheckBackgroundChoice();
        }catch(Exception error){
            rememberedBackgroundSelection=null; backgroundSelectionPreferenceError="无法恢复上次的应用范围，请重新选择。";
        }
    }
    private void installBackgroundPreferenceListeners(){
        backgroundMode.setOnClickListener(view -> {
            try{BackgroundUiPreferences.saveMode(this,backgroundMode.isChecked());backgroundModePreferenceError=null;}
            catch(Exception error){backgroundModePreferenceError="后台模式未能保存，请重新选择。";}
            recheckBackgroundChoice();refresh();
        });
        initialBackgroundApp.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener(){
            public void onItemSelected(AdapterView<?> parent,View view,int position,long id){
                if(!backgroundInitialChoicePending)return;
                backgroundInitialChoicePending=false;
                try{
                    if(rememberedBackgroundSelection==null)throw new IllegalStateException("range not confirmed");
                    BackgroundUiPreferences.Selection next=rememberedBackgroundSelection.withInitial(selectedBackgroundPackage());
                    reloadBackgroundApps();
                    BackgroundUiPreferences.requireCurrent(MainActivity.this,next,backgroundPackages,selectedBackgroundPackage(),backgroundAppLabels.keySet());
                    BackgroundUiPreferences.save(MainActivity.this,next);rememberedBackgroundSelection=next;backgroundSelectionPreferenceError=null;
                }catch(Exception error){backgroundSelectionPreferenceError="应用范围需要重新确认，请重新选择。";}
                refresh();
            }
            public void onNothingSelected(AdapterView<?> parent){backgroundInitialChoicePending=false;}
        });
    }
    private void rememberExplicitBackgroundChoice(){
        try{
            reloadBackgroundApps();
            BackgroundUiPreferences.Selection next=BackgroundUiPreferences.capture(this,backgroundPackages,selectedBackgroundPackage(),backgroundAppLabels.keySet());
            BackgroundUiPreferences.save(this,next);rememberedBackgroundSelection=next;backgroundSelectionPreferenceError=null;
        }catch(Exception error){backgroundSelectionPreferenceError="应用范围未能保存或安装信息已变，请重新选择。";}
    }
    private void requireCurrentBackgroundChoice()throws Exception{
        reloadBackgroundApps();
        if(backgroundModePreferenceError!=null)throw new IllegalStateException(backgroundModePreferenceError);
        BackgroundUiPreferences.requireCurrent(this,rememberedBackgroundSelection,backgroundPackages,selectedBackgroundPackage(),backgroundAppLabels.keySet());
        backgroundSelectionPreferenceError=null;
    }
    private void recheckBackgroundChoice(){
        if(backgroundPackages.isEmpty()){
            backgroundSelectionPreferenceError=backgroundMode.isChecked()?"请选择后台可操作的应用。":null;return;
        }
        try{
            reloadBackgroundApps();
            BackgroundUiPreferences.requireCurrent(this,rememberedBackgroundSelection,backgroundPackages,selectedBackgroundPackage(),backgroundAppLabels.keySet());
            backgroundSelectionPreferenceError=null;
        }catch(Exception error){backgroundSelectionPreferenceError="已选应用的安装信息发生变化或不可用，请重新选择范围。";}
    }
    private String backgroundChoiceError(){
        return backgroundModePreferenceError!=null?backgroundModePreferenceError:backgroundSelectionPreferenceError;
    }
    private void refreshBackgroundTaskTarget(){
        if(backgroundChoiceState==null||initialBackgroundApp==null||backgroundInitialLabel==null||backgroundMode==null)return;
        String error=backgroundChoiceError();String summary="";
        if(backgroundMode.isChecked()){
            try{
                BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(taskInput.getText().toString(),selectedBackgroundPackage(),backgroundPackages);
                summary="本次使用："+backgroundAppLabels.getOrDefault(target.packageName,target.packageName)
                        +(target.webHelper()?"（官网查询工具）":"（所选应用）")+"。已保存的应用范围保持不变。";
            }catch(Exception unavailable){summary=HeptaAccessibilityService.message(unavailable);}
        }
        backgroundChoiceState.setText(error==null?summary:error);
        backgroundInitialLabel.setVisibility(backgroundMode.isChecked()?View.VISIBLE:View.GONE);
        initialBackgroundApp.setVisibility(backgroundMode.isChecked()?View.VISIBLE:View.GONE);
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
    @Override public void onSessionChanged(){refresh(false);}
    @Override public void onPermissionPreparationChanged(){refresh();}
    private void refresh(){refresh(true);}
    private void refresh(boolean inspectModelFile){
        if(modelInfo==null)return;
        boolean available=HeptaAccessibilityService.connected()!=null;
        String device,modelName="本地模型",modelState;
        boolean configurationReady=false;
        try {
            LocalRuntimeConfig configuration=engine.configuration();
            device="npu".equals(configuration.compute)?"Hexagon NPU":"Adreno GPU";modelName=configuration.profile.displayName;
            if(inspectModelFile)cachedModelFilePresent=engine.modelFile().isFile();
            modelState=cachedModelFilePresent?"本地模型已导入":"本地模型待导入";
            configurationReady=true;
        }catch(Exception error) {
            device="运行参数待修正";modelState="本地配置错误："+HeptaAccessibilityService.message(error);
        }
        modelInfo.setText(modelState+" · "+(available?"无障碍已启用":"请启用无障碍"));
        modelDiagnostics.setText(modelName+" · "+device+" · 无外部模型");
        taskState.setText(tasks.state());taskLog.setText(tasks.log());
        boolean busy=tasks.isRunning()||engine.isBusy();
        backgroundPermissionState.setText(backgroundPermission.state());
        backgroundSummary.setText(tasks.isRunning()&&backgroundMode.isChecked()?"正在后台执行":
                tasks.hasBackgroundLease()?"上次后台空间待清理":
                backgroundMode.isChecked()?"将在所选应用范围内后台操作":"将在当前屏幕操作");
        openRootManager.setEnabled(rootManagerNavigationIdle());
        prepareBackgroundPermission.setEnabled(!busy&&!tasks.isBlocked()&&!tasks.isRecovering()&&!tasks.hasBackgroundLease()
                &&!visualDiagnostic.isBusy()&&!visualDiagnostic.isBlocked()&&!uiVenusDiagnostic.isBusy()&&!uiVenusDiagnostic.isBlocked());
        backgroundMode.setEnabled(!busy&&!tasks.isRecovering());pickBackgroundApps.setEnabled(!busy&&!tasks.isRecovering());initialBackgroundApp.setEnabled(!busy&&!tasks.isRecovering());
        cleanupBackground.setVisibility(tasks.hasBackgroundLease()?View.VISIBLE:View.GONE);
        cleanupBackground.setEnabled(!tasks.isRunning()&&!tasks.isRecovering()&&!backgroundPermission.blocksOtherWork());
        boolean recoveryAvailable=tasks.canAcknowledgeInterruption();
        acknowledgeInterruption.setVisibility(tasks.isBlocked()||tasks.isRecovering()||recoveryAvailable?View.VISIBLE:View.GONE);
        acknowledgeInterruption.setEnabled(recoveryAvailable);
        String backgroundError=backgroundChoiceError();
        previewTaskAuthorization();
        pickBackgroundApps.setText(backgroundError==null
                ?(backgroundPackages.isEmpty()?"选择后台应用范围":"后台范围："+backgroundPackages.size()+" 个应用（更改）")
                :"后台应用范围（需重新确认）");
        startTask.setEnabled(available&&configurationReady&&!busy&&!tasks.isBlocked()&&(!backgroundMode.isChecked()||backgroundError==null));stopTask.setEnabled(busy);
        runText.setEnabled(configurationReady&&!busy&&!tasks.isBlocked());
        LocalTaskController.TaskResult result=tasks.lastResult();
        if(result!=null){
            taskResult.setText(result.summary);
            taskDiagnostics.setText("任务："+result.taskId+"\n步骤："+result.steps
                    +"\n退出状态已确认："+result.cleanupKnown+"\n记录："+result.evidenceDirectory);
        }else{
            taskResult.setText("");taskDiagnostics.setText(tasks.taskId()==null?"":"任务："+tasks.taskId());
        }
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
    @Override protected void onStart(){super.onStart();if(tasks!=null)tasks.bind(this);if(backgroundPermission!=null)backgroundPermission.bind(this);
        accessibilityUiStarted=true;HeptaAccessibilityService.addConnectionListener(accessibilityConnectionChanged);
    }
    @Override protected void onResume(){super.onResume();if(tasks!=null){recheckBackgroundChoice();refresh();}}
    @Override protected void onStop(){accessibilityUiStarted=false;HeptaAccessibilityService.removeConnectionListener(accessibilityConnectionChanged);
        if(tasks!=null)tasks.unbind(this);if(backgroundPermission!=null)backgroundPermission.unbind(this);super.onStop();
    }
}
