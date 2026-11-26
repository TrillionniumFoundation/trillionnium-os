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
public final class MainActivity extends Activity implements LocalTaskSession.Listener,BackgroundPermissionSession.Listener,LocalModelSettings.Listener,LocalModelImport.Listener {
    private LocalModelEngine engine;
    private LocalModelSettings modelSettings;
    private LocalModelImport modelImport;
    private Button importLocalModel,cancelModelImport;
    private TextView localModelImportState;
    private String pendingImportAsset;
    private static final int MODEL_FILE_REQUEST=8461;
    private Button chooseLocalModel,restoreLocalModel;
    private TextView localModelSettingsState;
    private LocalTaskSession tasks;
    private MobiMindModelEngine visualDiagnostic;
    private UiVenusModelEngine uiVenusDiagnostic;
    private BackgroundPermissionSession backgroundPermission;
    private Button prepareBackgroundPermission,openRootManager;
    private TextView backgroundPermissionState;
    private LinearLayout profilePermissionCard;
    private TextView profilePermissionMessage;
    private Button denyProfilePermission;
    private HeptaAccessibilityService profilePermissionService;
    private ProfilePermissionUiSession.Presentation shownProfilePermission;
    private final ProfilePermissionUiSession.Listener profilePermissionChanged=new ProfilePermissionUiSession.Listener(){
        public void onPermissionUiChanged(){if(accessibilityUiStarted&&!isFinishing()&&!isDestroyed())refreshProfilePermission();}
    };
    private TextView backgroundSummary,modelDiagnostics,taskDiagnostics;
    private EditText taskInput, probePrompt;
    private TextView modelIdentity, modelInfo, taskState, taskLog, taskResult, probeOutput;
    private TextView taskAuthorizationInfo;
    private boolean accessibilityUiStarted;
    private boolean ownerCleanupFeedbackPending;
    private LinearLayout recoveryCard;
    private TextView recoveryTitle,recoveryMessage;
    private String recoveryUiFeedback;
    private boolean cachedModelFilePresent;
    private final Runnable accessibilityConnectionChanged=new Runnable(){
        @Override public void run(){
            if(accessibilityUiStarted&&!isFinishing()&&!isDestroyed())refresh();
        }
    };
    private CheckBox backgroundMode,independentProfileDisplay,independentPersonalDisplay;
    private String backgroundDisplayPreferenceError;
    private Button pickBackgroundApps,pickProfileTarget,cleanupBackground;
    private boolean profileCatalogueLoading;
    private Spinner initialBackgroundApp;
    private TextView backgroundChoiceState,backgroundInitialLabel;
    private BackgroundUiPreferences.Selection rememberedBackgroundSelection;
    private String backgroundModePreferenceError,backgroundSelectionPreferenceError;
    private boolean backgroundInitialChoicePending;
    private CheckBox automaticTargetMode;
    private Button pickAutomaticTargets,pickAutomaticInstance;
    private BackgroundAutoTargetPreferences.Snapshot automaticTargets;
    private BackgroundAutoTargetResolver.Resolution automaticResolution;
    private String automaticTargetsError,automaticInstanceChoice,automaticStartFeedback;
    private long automaticUiEpoch;
    private AutomaticStart automaticStartPending,automaticReadyStart;
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
        backgroundPermission=app.backgroundPermissionPreparation();modelSettings=app.modelSettings();
        uiVenusDiagnostic=app.uiVenusDiagnostic();modelImport=app.modelImport();
        pendingImportAsset=state==null?null:state.getString("pending_model_import_asset");
        ScrollView outer=new ScrollView(this);outer.setFillViewport(true);
        LinearLayout page=new LinearLayout(this);page.setOrientation(LinearLayout.VERTICAL);
        int pad=dp(16);page.setPadding(pad,pad,pad,pad);outer.addView(page);
        TextView title=text("Hepta",25);page.addView(title);
        page.addView(text("用手机本地模型理解指令并操作应用",15));
        recoveryCard=new LinearLayout(this);recoveryCard.setOrientation(LinearLayout.VERTICAL);
        recoveryCard.setPadding(dp(12),dp(10),dp(12),dp(10));recoveryCard.setBackgroundColor(0xfffff3df);
        recoveryTitle=text("",17);recoveryMessage=text("",13);
        recoveryCard.addView(recoveryTitle);recoveryCard.addView(recoveryMessage);
        recoveryCard.setVisibility(View.GONE);page.addView(recoveryCard);
        modelIdentity=text("",12);page.addView(modelIdentity);
        modelInfo=text("",12);page.addView(modelInfo);
        LinearLayout modelImportButtons=new LinearLayout(this);page.addView(modelImportButtons);
        importLocalModel=button("导入模型文件");modelImportButtons.addView(importLocalModel);
        chooseLocalModel=button("选择本地模型");modelImportButtons.addView(chooseLocalModel);
        cancelModelImport=button("取消导入");modelImportButtons.addView(cancelModelImport);
        chooseLocalModel.setOnClickListener(v -> chooseLocalModelFromOwnerButton());
        importLocalModel.setOnClickListener(v -> chooseModelFileFromOwnerButton());
        cancelModelImport.setOnClickListener(v -> modelImport.cancel());
        localModelImportState=text("",12);page.addView(localModelImportState);
        taskInput=new EditText(this);taskInput.setHint("你想让手机完成什么？");
        taskInput.setText("记一下，明天下午3点看牙，带上检查资料。");taskInput.setMinLines(3);page.addView(taskInput);
        taskAuthorizationInfo=text("",12);
        taskInput.addTextChangedListener(new android.text.TextWatcher(){
            public void beforeTextChanged(CharSequence s,int start,int count,int after){}
            public void onTextChanged(CharSequence s,int start,int before,int count){automaticInputChanged();previewTaskAuthorization();}
            public void afterTextChanged(android.text.Editable value){}
        });
        previewTaskAuthorization();
        backgroundMode=new CheckBox(this);backgroundMode.setText("在后台空间操作");page.addView(backgroundMode);
        automaticTargetMode=new CheckBox(this);automaticTargetMode.setText("根据任务自动选择已保存的目标与模型");page.addView(automaticTargetMode);
        pickAutomaticTargets=button("管理自动目标与首选模型");page.addView(pickAutomaticTargets);
        pickAutomaticInstance=button("选择本次应用实例");page.addView(pickAutomaticInstance);pickAutomaticInstance.setVisibility(View.GONE);
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
        pickProfileTarget=button("选择隔离资料中的应用");page.addView(pickProfileTarget);
        pickProfileTarget.setOnClickListener(v -> chooseProfileTarget());
        independentProfileDisplay=new CheckBox(this);
        independentProfileDisplay.setText("独立后台显示（无锁屏密码设备的隔离资料应用）");
        page.addView(independentProfileDisplay);
        independentPersonalDisplay=new CheckBox(this);
        independentPersonalDisplay.setText("个人空间独立后台显示（备忘录、小米商城）");
        page.addView(independentPersonalDisplay);
        page.addView(text("需要所选应用没有正在使用或保留的任务。若发现既有任务会停止，不会关闭或搬动它。",12));
        page.addView(text("仅用于设备和所选资料都未设置锁屏密码的情形。每次开始都会核验实际条件；条件不满足时任务停止。",12));
        page.addView(text("资料隔离支持携程、小米商城，需要已配置的专属工作资料；一次执行一个资料应用。个人空间已有任务会保留。",12));
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
        cleanupBackground.setOnClickListener(v -> {
            recoveryUiFeedback=null;ownerCleanupFeedbackPending=true;
            try{tasks.reconcileBackgroundFromOwnerButton();}
            catch(Exception error){
                ownerCleanupFeedbackPending=false;recoveryUiFeedback="清理未开始："+HeptaAccessibilityService.message(error);refresh();
                taskState.setText(recoveryUiFeedback);revealTaskState();return;
            }
            refresh();revealTaskState();
        });
        LinearLayout actions=new LinearLayout(this);page.addView(actions);
        startTask=button("开始任务");actions.addView(startTask);
        stopTask=button("停止");actions.addView(stopTask);
        Button accessibility=button("启用无障碍");actions.addView(accessibility);
        recoveryCard.addView(cleanupBackground);
        startTask.setOnClickListener(v -> beginTask(taskInput.getText().toString(),"user_button",null));
        stopTask.setOnClickListener(v -> {
            if(cancelAutomaticStart())return;
            // Controlled tasks cancel their captured task/handle. A diagnostic cancels one captured engine run.
            boolean controlled=tasks.isRunning();tasks.stop();if(!controlled)engine.cancelActive();
            // Explicitly ends this UI prefill only; the running task retains its immutable scope.
            scopeLaunch=QualificationScope.Launch.normal();scopeLaunchError=null;refresh(false);});
        accessibility.setOnClickListener(v -> startActivity(new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)));
        acknowledgeInterruption=button("确认中断并开始新会话");recoveryCard.addView(acknowledgeInterruption);
        acknowledgeInterruption.setOnClickListener(v -> new AlertDialog.Builder(this)
            .setTitle("保留旧任务，建立新会话")
            .setMessage("旧任务不会恢复。它仍记为中断，原进程退出与清理状态仍未知。应用会先保存原记录并核验当前可见的本应用进程；通过后只建立空闲会话，不会自动开始任务。其它诊断仍未确认退出时不能解除阻塞。")
            .setNegativeButton("暂不确认",null)
            .setPositiveButton("确认并核验",(dialog,which) -> {
                recoveryUiFeedback=null;
                try{tasks.acknowledgeInterruptionFromOwnerButton();}
                catch(Exception error){recoveryUiFeedback="无法确认中断："+HeptaAccessibilityService.message(error);
                    refresh();taskState.setText(recoveryUiFeedback);revealTaskState();}
            }).show());
        taskState=text("",15);taskState.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);page.addView(taskState);
        profilePermissionCard=new LinearLayout(this);profilePermissionCard.setOrientation(LinearLayout.VERTICAL);
        profilePermissionCard.setVisibility(View.GONE);page.addView(profilePermissionCard);
        profilePermissionMessage=text("",13);profilePermissionMessage.setTextIsSelectable(true);profilePermissionCard.addView(profilePermissionMessage);
        denyProfilePermission=button("拒绝此权限");profilePermissionCard.addView(denyProfilePermission);
        denyProfilePermission.setOnClickListener(v -> {
            android.graphics.Rect visibleButton=new android.graphics.Rect();
            if(!accessibilityUiStarted||!hasWindowFocus()||isFinishing()||isDestroyed()
                    ||!denyProfilePermission.isShown()||!denyProfilePermission.isEnabled()
                    ||!denyProfilePermission.getGlobalVisibleRect(visibleButton)||visibleButton.isEmpty()
                    ||!profilePermissionMessage.isShown())return;
            HeptaAccessibilityService current=HeptaAccessibilityService.connected();
            ProfilePermissionUiSession.Presentation captured=shownProfilePermission;
            if(current!=null&&current==profilePermissionService&&captured!=null&&tasks.isRunning()
                    &&captured.taskId.equals(tasks.taskId())){
                current.permissionUi().ownerVisibility(this,captured,true);
                current.permissionUi().denyFromOwnerButton(captured,this);
            }
            refreshProfilePermission();
        });
        ScrollView progress=new ScrollView(this);
        progress.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS);
        progress.setLayoutParams(new LinearLayout.LayoutParams(-1,dp(150)));
        taskLog=text("",12);taskLog.setTypeface(Typeface.MONOSPACE);taskLog.setTextIsSelectable(true);progress.addView(taskLog);
        taskResult=text("",13);taskResult.setTextIsSelectable(true);taskResult.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);page.addView(taskResult);
        Button showDiagnostics=button("高级诊断");page.addView(showDiagnostics);
        diagnostics=new LinearLayout(this);diagnostics.setOrientation(LinearLayout.VERTICAL);diagnostics.setVisibility(View.GONE);page.addView(diagnostics);
        showDiagnostics.setOnClickListener(v -> diagnostics.setVisibility(diagnostics.getVisibility()==View.VISIBLE?View.GONE:View.VISIBLE));
        modelDiagnostics=text("",12);diagnostics.addView(modelDiagnostics);
        LinearLayout modelSettingsButtons=new LinearLayout(this);diagnostics.addView(modelSettingsButtons);
        restoreLocalModel=new Button(this);restoreLocalModel.setText("恢复上次配置");modelSettingsButtons.addView(restoreLocalModel);
        chooseLocalModel.setOnClickListener(v -> chooseLocalModelFromOwnerButton());
        restoreLocalModel.setOnClickListener(v -> restoreLocalModelFromOwnerButton());
        localModelSettingsState=text("",12);diagnostics.addView(localModelSettingsState);
        diagnostics.addView(showBackgroundPermission);diagnostics.addView(backgroundPermissionDetails);
        diagnostics.addView(text("本次指令的权限与工具范围",12));diagnostics.addView(taskAuthorizationInfo);
        diagnostics.addView(text("任务记录",12));diagnostics.addView(progress);
        taskDiagnostics=text("",12);taskDiagnostics.setTextIsSelectable(true);diagnostics.addView(taskDiagnostics);
        diagnostics.addView(text("本地任务读取当前应用的无障碍节点；视觉模型还会读取同一轮截图。截图与推理记录保存在手机内。",12));
        probePrompt=new EditText(this);probePrompt.setText("只输出 42。");probePrompt.setMinLines(2);diagnostics.addView(probePrompt);
        LinearLayout probes=new LinearLayout(this);diagnostics.addView(probes);
        runText=button("文本推理");probes.addView(runText);
        runText.setOnClickListener(v -> runProbe(false,128,true));
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
        restoreAutomaticTargets();installAutomaticTargetListeners();installBackgroundPreferenceListeners();refresh();
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
            if(backgroundMode!=null&&backgroundMode.isChecked()&&!automaticMode()){
                BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(owner,selectedBackgroundPackage(),backgroundPackages,selectedProfileTarget());
                preview=preview.forExecutionSelection(new BackgroundSession.Selection(target,selectedIndependentProfileDisplay(),selectedIndependentPersonalDisplay()));
            }
            taskAuthorizationInfo.setText(preview.summary());
        }
        catch(Exception error){taskAuthorizationInfo.setText("本次限制无法识别，任务不会启动："+HeptaAccessibilityService.message(error));}
        refreshBackgroundTaskTarget();
    }

    @Override protected void onSaveInstanceState(Bundle state){
        super.onSaveInstanceState(state);
        state.putString("pending_model_import_asset",pendingImportAsset);
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
        // Legacy automated requests have no verified background selection. They
        // cannot replace the owner's pending task, scope claim, or display choice.
        if(autoTask||intent.getBooleanExtra(SCOPE_INTENT_CONSUMED,false)||tasks.isRunning())return;
        boolean normalEntry=Intent.ACTION_MAIN.equals(intent.getAction())&&intent.hasCategory(Intent.CATEGORY_LAUNCHER);
        if(task==null&&!hasExpected&&!normalEntry&&!autoTask)return;
        scopeLaunch=QualificationScope.Launch.normal();scopeLaunchError=null;
        if(task!=null)taskInput.setText(task);
        try{
            QualificationScope.require(!hasExpected||expected!=null,"null expected scope extra");
            scopeLaunch=QualificationScope.Launch.prefill(task,expected);
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
            intent.removeExtra("auto_task");intent.removeExtra("test_nonce");intent.removeExtra("auto_run");
            // A private nonce proves neither a selected virtual display nor an
            // owner-confirmed background app range. Refuse before consuming it.
            String error="自动测试需要已确认的后台应用范围。请启用「在后台空间操作」、选择目标应用后点击「开始任务」；旧自动入口不会执行手机操作。";
            taskState.setText("未启动测试任务："+error);
            recordDebugTrigger(nonce==null?null:HeptaAccessibilityService.sha(nonce.getBytes(StandardCharsets.UTF_8)),false,false,error);
            return;
        }
        String supplied=intent.getStringExtra("prompt");if(supplied!=null)probePrompt.setText(supplied);
        if(intent.getBooleanExtra("auto_run",false)){
            boolean image="image".equals(intent.getStringExtra("mode"));int max=intent.getIntExtra("max_tokens",image?256:128);
            intent.removeExtra("auto_run");diagnostics.setVisibility(View.VISIBLE);
            probePrompt.post(() -> runProbe(image,max));
        }
    }
    private void chooseModelFileFromOwnerButton(){
        LocalProbeApplication app=(LocalProbeApplication)getApplication();
        if(!hasWindowFocus()||isFinishing()||isDestroyed()||pendingImportAsset!=null
                ||profileCatalogueLoading||!app.canImportLocalModel()){
            localModelImportState.setText("请先等待任务结束，并清理上次后台空间。");return;
        }
        final java.util.List<LocalModelImportAsset> assets=LocalModelImportAsset.all();
        String[] labels=new String[assets.size()];
        for(int i=0;i<labels.length;i++)labels[i]=assets.get(i).label;
        new AlertDialog.Builder(this).setTitle("选择要导入的模型文件").setItems(labels,(dialog,which)->{
            if(which<0||which>=assets.size()||!app.canImportLocalModel()||pendingImportAsset!=null)return;
            LocalModelImportAsset asset=assets.get(which);pendingImportAsset=asset.pin.id;
            Intent picker=new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                    .setType("*/*").putExtra(Intent.EXTRA_LOCAL_ONLY,true)
                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            try{startActivityForResult(picker,MODEL_FILE_REQUEST);localModelImportState.setText("请选择手机中的 "+asset.pin.filename);}
            catch(RuntimeException unavailable){pendingImportAsset=null;localModelImportState.setText("无法打开手机文件选择器，请稍后重试。");}
        }).setNegativeButton("取消",null).show();
    }
    @Override protected void onActivityResult(int requestCode,int resultCode,Intent data){
        super.onActivityResult(requestCode,resultCode,data);
        if(requestCode!=MODEL_FILE_REQUEST)return;
        String asset=pendingImportAsset;pendingImportAsset=null;
        if(resultCode!=RESULT_OK){localModelImportState.setText("未选择文件，已有模型保持不变。");return;}
        try{
            if(asset==null||data==null||data.getData()==null
                    ||(data.getFlags()&Intent.FLAG_GRANT_READ_URI_PERMISSION)==0)
                throw new IllegalArgumentException("没有取得所选文件的只读权限，请重新选择");
            if(profileCatalogueLoading||!((LocalProbeApplication)getApplication()).canImportLocalModel())
                throw new IllegalStateException("任务或后台空间尚未空闲，请结束后重新选择文件");
            modelImport.start(asset,data.getData());refresh();
        }catch(Exception failure){localModelImportState.setText("导入未开始："+HeptaAccessibilityService.message(failure));}
    }
    @Override public void onLocalModelImportChanged(){refresh();}
    private void chooseLocalModelFromOwnerButton(){
        invalidateAutomaticStart();
        LocalProbeApplication app=(LocalProbeApplication)getApplication();
        if(profileCatalogueLoading||!app.canChangeLocalModelSettings(false)){
            localModelSettingsState.setText("请先等待任务、后台空间和模型队列完全空闲。");return;
        }
        final String[] labels={
            "LFM3-1.7B · Hexagon NPU（基线）\nQAD Q4_0 · 可用内存门槛 3 GiB",
            "LFM3-1.7B · Adreno GPU\nQAD Q4_0 · 可用内存门槛 3 GiB",
            "LFM2.5-8B-A1B · Hexagon NPU（实验）\nQ4_0 · 可用内存门槛 7 GiB",
            "LFM2.5-8B-A1B · Adreno GPU（实验）\nQ4_0 · 可用内存门槛 7 GiB",
            "GUI-Owl 4B · 语言 NPU + 图像 GPU（实验）\nQ4_0 + F16 视觉投影 · 可用内存门槛 6 GiB",
            "LFM3-VL 2B · 语言 NPU + 图像 GPU（仅观察）\nQAD Q4_0 + F16 视觉投影 · 可用内存门槛 4 GiB",
            "Qwen3.5 4B · Hexagon NPU（实验）\nQ4_0 · 可用内存门槛 5 GiB",
            "Qwen3.5 4B · Adreno GPU（实验）\nQ4_0 · 可用内存门槛 5 GiB"};
        final ModelProfile[] profiles={ModelProfile.LFM3,ModelProfile.LFM3,ModelProfile.LFM25_8B_A1B,ModelProfile.LFM25_8B_A1B,
                ModelProfile.GUI_OWL_4B,ModelProfile.LFM3_VL_2B,ModelProfile.QWEN35_4B,ModelProfile.QWEN35_4B};
        final String[] computes={"npu","gpu","npu","gpu","npu","npu","npu","gpu"};
        int current=0;
        try{LocalRuntimeConfig config=engine.configuration();
            for(int i=0;i<profiles.length;i++)if(config.profile==profiles[i]&&config.compute.equals(computes[i])){current=i;break;}}
        catch(Exception unavailable){/* The actual apply still rejects an unreadable prior configuration. */}
        final int[] selected={current};
        new AlertDialog.Builder(this).setTitle("选择本地模型 · 8192 上下文 / 4 线程")
                .setSingleChoiceItems(labels,current,(dialog,which)->selected[0]=which)
                .setNegativeButton("取消",null).setPositiveButton("保存",(dialog,which)->{
                    int choice=selected[0];
                    try{
                        if(choice<0||choice>=labels.length||profileCatalogueLoading||!app.canChangeLocalModelSettings(false))
                            throw new IllegalStateException("设置范围或当前空闲状态已变化");
                        modelSettings.start(profiles[choice].id,computes[choice],false);refresh();
                    }catch(Exception error){localModelSettingsState.setText("未更改配置："+HeptaAccessibilityService.message(error));}
                }).show();
    }
    private void restoreLocalModelFromOwnerButton(){
        invalidateAutomaticStart();
        LocalProbeApplication app=(LocalProbeApplication)getApplication();
        if(profileCatalogueLoading||!app.canChangeLocalModelSettings(true)){
            localModelSettingsState.setText("当前没有可恢复的配置，或任务和模型队列尚未空闲。");return;
        }
        new AlertDialog.Builder(this).setTitle("恢复上一次模型配置")
                .setMessage("核验空闲后恢复上次保存前的本地模型设置。本次不会启动推理或操作应用。")
                .setNegativeButton("取消",null).setPositiveButton("恢复",(dialog,which)->{
                    try{
                        if(profileCatalogueLoading||!app.canChangeLocalModelSettings(true))
                            throw new IllegalStateException("当前空闲状态已变化");
                        modelSettings.start(null,null,true);refresh();
                    }catch(Exception error){localModelSettingsState.setText("未开始恢复："+HeptaAccessibilityService.message(error));}
                }).show();
    }
    @Override public void onLocalModelSettingsChanged(){
        AutomaticStart pending=automaticStartPending;
        if(pending!=null&&pending.settingsStarted&&!modelSettings.isBusy())finishAutomaticPreparation(pending);
        refresh();
    }

    /** Only the actual physical-screen MainActivity's ordinary Start callback
     * creates a locator. A VD owner keeps the existing strict initialization path. */
    private org.trillionnium.hepta.background.PublicPermissionControllerUi.Locator controllerUiFromOwnerButton(String owner){
        android.app.Activity activity=this;
        if(activity==null||android.os.Looper.myLooper()!=android.os.Looper.getMainLooper())
            throw new IllegalArgumentException("CONTROLLER_UI_MAIN_THREAD_REQUIRED");
        android.view.Display actual=activity.getDisplay();
        if(actual==null||!actual.isValid())throw new IllegalArgumentException("CONTROLLER_UI_DISPLAY_UNAVAILABLE");
        if(actual.getDisplayId()>1)return null;
        if(activity.getClass()!=MainActivity.class||activity.isFinishing()||activity.isDestroyed()||!activity.hasWindowFocus()
                ||activity.getWindow()==null||!activity.getWindow().getDecorView().isShown()
                ||activity.getComponentName()==null
                ||!org.trillionnium.hepta.background.PublicPermissionControllerUi.COMPONENT.equals(activity.getComponentName().flattenToString())
                ||activity.getApplicationInfo().uid!=android.os.Process.myUid())
            throw new IllegalArgumentException("CONTROLLER_UI_OWNER_BUTTON_NOT_VISIBLE");
        return org.trillionnium.hepta.background.PublicPermissionControllerUi.fromMainActivityButton(
                android.os.Process.myUid(),android.os.Process.myPid(),activity.getTaskId(),actual.getDisplayId(),
                android.os.SystemClock.elapsedRealtime(),HeptaAccessibilityService.sha(owner.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }
    private boolean beginTask(String owner,String source,String nonceSha){
        try{
            if(tasks.isRunning()||tasks.isBlocked()||engine.isBusy())throw new IllegalStateException("已有本地请求正在运行或退出状态待确认");
            if(automaticMode()){
                if(!backgroundMode.isChecked())throw new IllegalStateException("自动目标需要启用后台空间操作");
                if(automaticReadyStart==null)return prepareAutomaticStart(owner,source,nonceSha);
            }
            if(!engine.modelFile().isFile())throw new IllegalStateException("所选本地模型尚未导入");
            LocalRuntimeConfig selectedModel=engine.configuration();
            if(selectedModel.profile.visual()){
                if(!new File(engine.modelDirectory(),VlmResultContract.named(selectedModel.profile.id).projectorFilename).isFile())
                    throw new IllegalStateException("本地视觉投影文件尚未导入");
                if(!backgroundMode.isChecked())throw new IllegalStateException("当前本地视觉模型需要启用后台操作并选择起始应用");
            }
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
                if(automaticMode())selection=automaticStartSelection(owner);
                else{
                requireCurrentBackgroundChoice();
                BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(owner,selectedBackgroundPackage(),backgroundPackages,selectedProfileTarget());
                boolean independentProfile=selectedIndependentProfileDisplay();
                selection=new BackgroundSession.Selection(target,independentProfile,selectedIndependentPersonalDisplay(),
                        independentProfile&&target.profileTarget!=null&&org.trillionnium.hepta.background.ProfileTarget.CTRIP.equals(target.profileTarget.packageName)
                                ?controllerUiFromOwnerButton(owner):null);
                }
                authorization=originalAuthorization.forExecutionSelection(selection);
                selection.requireTaskTarget(owner,authorization);
                if(authorization.requireFindAppBeforeOpen||!authorization.allowedTools.contains("open"))
                    throw new IllegalStateException("当前指令不允许打开所选后台起始应用，后台任务未启动");
            }else{selection=null;authorization=originalAuthorization;}
            if(automaticMode())requireAutomaticSchedule(owner);
            if(!tasks.schedule(owner,source,nonceSha,expectedScope,authorization,selection,500))throw new IllegalStateException("本地任务未能取得唯一会话");
            scopeLaunch=scopeLaunch.accepted();
            InputMethodManager input=(InputMethodManager)getSystemService(INPUT_METHOD_SERVICE);
            if(input!=null)input.hideSoftInputFromWindow(taskInput.getWindowToken(),0);
            if(selection==null&&!moveTaskToBack(true)){tasks.stop();taskState.setText("无法切换到手机前台画面，任务未开始");return false;}
            return true;
        }catch(Exception error){
            if(automaticMode()){invalidateAutomaticStart();automaticStartFeedback="无法开始："+HeptaAccessibilityService.message(error);}
            taskState.setText("无法开始："+HeptaAccessibilityService.message(error));return false;
        }
    }

    private void runProbe(boolean image,int maxTokens){
        runProbe(image,maxTokens,false);
    }
    private void runProbe(boolean image,int maxTokens,boolean ordinaryText){
        if(engine.isBusy()||tasks.isRunning()||tasks.isBlocked()){probeOutput.setText("已有任务正在运行或退出待确认，请先停止并等待。");return;}
        String system=getIntent().getStringExtra("system_prompt");
        if(system==null)system="你是在手机本地运行的助手。请直接、简洁地回答用户指令。";
        long timeout=getIntent().getLongExtra("timeout_ms",120000L);
        if(image){probeOutput.setText("当前本地模型只接收文字；图片不会发送给模型。");return;}
        probeOutput.setText("正在启动手机本地推理……");
        try{
            // Only the ordinary button derives its budget from the current saved profile.
            if(ordinaryText)maxTokens=engine.configuration().profile==ModelProfile.LFM25_8B_A1B?256:128;
            engine.start(new LocalModelEngine.Request(probePrompt.getText().toString(),system,
                null,maxTokens,timeout),
                result -> runOnUiThread(() -> {renderProbe(result);refresh();}));
            refresh();
        }catch(Exception error){probeOutput.setText("无法启动："+error);refresh();}
    }
    private boolean selectedIndependentProfileDisplay(){
        if(backgroundDisplayPreferenceError!=null)throw new IllegalStateException(backgroundDisplayPreferenceError);
        boolean selected=independentProfileDisplay!=null&&independentProfileDisplay.isChecked();
        if(selected!=BackgroundUiPreferences.independentProfileDisplay(this))
            throw new IllegalStateException("后台显示方式已变化，请重新选择后开始");
        if(selected&&selectedProfileTarget()==null)
            throw new IllegalStateException("请明确选择已核验的隔离资料应用；个人空间应用不会被自动迁移");
        return selected;
    }
    private void restoreIndependentProfileDisplay(){
        try{
            boolean profile=BackgroundUiPreferences.independentProfileDisplay(this),personal=BackgroundUiPreferences.independentPersonalDisplay(this);
            if(profile&&personal)throw new IllegalStateException("后台显示方式冲突");
            independentProfileDisplay.setChecked(profile);independentPersonalDisplay.setChecked(personal);backgroundDisplayPreferenceError=null;
        }catch(Exception error){independentProfileDisplay.setChecked(false);independentPersonalDisplay.setChecked(false);
            backgroundDisplayPreferenceError="无法读取后台显示方式，请重新选择。";}
    }
    private boolean personalIndependentTarget(){
        String selected=selectedBackgroundPackage();
        return selectedProfileTarget()==null&&("com.motorola.stylus".equals(selected)||"com.xiaomi.shop".equals(selected));
    }
    private boolean selectedIndependentPersonalDisplay(){
        if(backgroundDisplayPreferenceError!=null)throw new IllegalStateException(backgroundDisplayPreferenceError);
        boolean selected=independentPersonalDisplay!=null&&independentPersonalDisplay.isChecked();
        if(selected!=BackgroundUiPreferences.independentPersonalDisplay(this))throw new IllegalStateException("个人空间后台显示方式已变化，请重新选择");
        if(selected&&(independentProfileDisplay.isChecked()||!personalIndependentTarget()))
            throw new IllegalStateException("个人空间独立显示需要明确选择备忘录或小米商城；不会改变资料或迁移任务");
        return selected;
    }
    private org.trillionnium.hepta.background.ProfileTarget selectedProfileTarget(){
        return rememberedBackgroundSelection==null?null:rememberedBackgroundSelection.profileTarget;
    }
    private void chooseProfileTarget(){
        if(profileCatalogueLoading||!hasWindowFocus()||isFinishing()||isDestroyed()
                ||tasks.isRunning()||engine.isBusy()||tasks.isBlocked()||tasks.isRecovering()
                ||tasks.hasBackgroundLease()||backgroundPermission.blocksOtherWork())return;
        profileCatalogueLoading=true;taskState.setText("正在读取隔离资料中的携程和小米商城……");refresh();
        new Thread(() -> {
            java.util.List<org.trillionnium.hepta.background.ProfileTarget> found=null;String error=null;
            try{found=ProfileCatalogueClient.load(getApplicationContext());}catch(Exception failure){error=HeptaAccessibilityService.message(failure);}
            final java.util.List<org.trillionnium.hepta.background.ProfileTarget> targets=found;final String failure=error;
            runOnUiThread(() -> {
                profileCatalogueLoading=false;
                if(isFinishing()||isDestroyed())return;
                refresh();
                if(failure!=null){taskState.setText("无法读取隔离资料："+failure);return;}
                if(targets==null||targets.isEmpty()){taskState.setText("未找到可用工作资料中的携程或小米商城。请完成专属资料配置、解锁资料并在资料中安装目标应用，然后重新读取。");return;}
                if(!hasWindowFocus()||tasks.isRunning()||engine.isBusy()||tasks.isBlocked()||tasks.isRecovering()||tasks.hasBackgroundLease())return;
                String[] labels=new String[targets.size()];
                for(int i=0;i<labels.length;i++)labels[i]=targets.get(i).appLabel()+" · 工作资料 "+targets.get(i).profile.userId;
                new AlertDialog.Builder(this).setTitle("明确选择本次隔离实例").setItems(labels,(dialog,index) -> {
                    if(tasks.isRunning()||engine.isBusy()||tasks.isBlocked()||tasks.isRecovering()||tasks.hasBackgroundLease())return;
                    try{
                        BackgroundUiPreferences.Selection choice=BackgroundUiPreferences.captureProfile(targets.get(index));
                        BackgroundUiPreferences.save(MainActivity.this,choice);BackgroundUiPreferences.saveMode(MainActivity.this,true);
                        rememberedBackgroundSelection=choice;backgroundPackages.clear();backgroundPackages.add(choice.initial);
                        restoreIndependentProfileDisplay();
                        backgroundMode.setChecked(true);backgroundModePreferenceError=null;backgroundSelectionPreferenceError=null;
                        reloadBackgroundApps();updateBackgroundSelection(choice.initial);refresh();
                    }catch(Exception invalid){taskState.setText("隔离实例未保存："+HeptaAccessibilityService.message(invalid));}
                }).setNegativeButton("取消",null).show();
            });
        },"hepta-profile-catalogue").start();
    }
    private void reloadBackgroundApps(){reloadBackgroundApps(true);}
    private void reloadBackgroundApps(boolean includeSelectedProfile){
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
        org.trillionnium.hepta.background.ProfileTarget profile=selectedProfileTarget();
        if(includeSelectedProfile&&profile!=null)backgroundAppLabels.put(profile.packageName,profile.appLabel()+" · 工作资料 "+profile.profile.userId);
    }
    private void chooseBackgroundApps(){
        reloadBackgroundApps(false);final java.util.List<String> packages=new java.util.ArrayList<String>(backgroundAppLabels.keySet());
        final java.util.Set<String> chosen=new java.util.TreeSet<String>(backgroundPackages);chosen.retainAll(packages);
        String[] labels=new String[packages.size()];boolean[] checked=new boolean[packages.size()];
        for(int i=0;i<packages.size();i++){String pkg=packages.get(i);labels[i]=backgroundAppLabels.get(pkg)+" · "+pkg;checked[i]=chosen.contains(pkg);}
        final String initial=selectedBackgroundPackage();
        new AlertDialog.Builder(this).setTitle("个人空间后台应用（最多 6 个）")
                .setMultiChoiceItems(labels,checked,(dialog,which,enabled) -> {if(enabled)chosen.add(packages.get(which));else chosen.remove(packages.get(which));})
                .setNegativeButton("取消",null).setPositiveButton("使用所选应用",(dialog,which) -> {
                    if(chosen.isEmpty()||chosen.size()>6){taskState.setText("请选择 1 至 6 个后台应用");return;}
                    rememberedBackgroundSelection=null; backgroundPackages.clear();backgroundPackages.addAll(chosen);updateBackgroundSelection(initial);
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
        backgroundMode.setChecked(state.getBoolean("background_mode",true));
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
        restoreIndependentProfileDisplay();
        try{backgroundMode.setChecked(BackgroundUiPreferences.mode(this));backgroundModePreferenceError=null;}
        catch(Exception error){backgroundMode.setChecked(true);backgroundModePreferenceError="无法读取上次的后台模式，请重新选择。";}
        try{
            rememberedBackgroundSelection=BackgroundUiPreferences.load(this);
            backgroundPackages.clear();
            if(rememberedBackgroundSelection!=null)backgroundPackages.addAll(rememberedBackgroundSelection.packages.keySet());
            reloadBackgroundApps();
            updateBackgroundSelection(rememberedBackgroundSelection==null?null:rememberedBackgroundSelection.initial);
            recheckBackgroundChoice();
        }catch(Exception error){
            rememberedBackgroundSelection=null; backgroundSelectionPreferenceError="无法恢复上次的应用范围，请重新选择。";
        }
    }
    private void installBackgroundPreferenceListeners(){
        independentProfileDisplay.setOnClickListener(view -> {
            if(!hasWindowFocus()||!independentProfileDisplay.isShown()||isFinishing()||isDestroyed()
                    ||tasks.isRunning()||engine.isBusy()||tasks.isBlocked()||tasks.isRecovering()
                    ||tasks.hasBackgroundLease()||backgroundPermission.blocksOtherWork()){
                restoreIndependentProfileDisplay();refresh();return;
            }
            try{
                boolean selected=independentProfileDisplay.isChecked();
                if(selected&&selectedProfileTarget()==null)throw new IllegalStateException("请先选择隔离资料中的应用");
                BackgroundUiPreferences.saveIndependentProfileDisplay(this,selected);restoreIndependentProfileDisplay();
            }catch(Exception error){backgroundDisplayPreferenceError="后台显示方式未保存："+HeptaAccessibilityService.message(error);}
            refresh();
        });
        independentPersonalDisplay.setOnClickListener(view -> {
            if(!hasWindowFocus()||!independentPersonalDisplay.isShown()||isFinishing()||isDestroyed()
                    ||tasks.isRunning()||engine.isBusy()||tasks.isBlocked()||tasks.isRecovering()
                    ||tasks.hasBackgroundLease()||backgroundPermission.blocksOtherWork()){
                restoreIndependentProfileDisplay();refresh();return;
            }
            try{
                boolean selected=independentPersonalDisplay.isChecked();
                if(selected&&!personalIndependentTarget())throw new IllegalStateException("请明确选择个人空间的备忘录或小米商城");
                BackgroundUiPreferences.saveIndependentPersonalDisplay(this,selected);restoreIndependentProfileDisplay();
            }catch(Exception error){backgroundDisplayPreferenceError="个人空间后台显示方式未保存："+HeptaAccessibilityService.message(error);}
            refresh();
        });
        backgroundMode.setOnClickListener(view -> {
            automaticInputChanged();
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
                    restoreIndependentProfileDisplay();
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
            restoreIndependentProfileDisplay();
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
        if(automaticMode())return automaticChoiceError();
        if(backgroundModePreferenceError!=null)return backgroundModePreferenceError;
        if(backgroundSelectionPreferenceError!=null)return backgroundSelectionPreferenceError;
        if(backgroundDisplayPreferenceError!=null)return backgroundDisplayPreferenceError;
        if(backgroundMode.isChecked()&&independentProfileDisplay.isChecked()&&selectedProfileTarget()==null)
            return "独立后台显示需要明确选择隔离资料中的应用；个人空间选择保持不变。";
        if(backgroundMode.isChecked()&&independentPersonalDisplay.isChecked()
                &&(independentProfileDisplay.isChecked()||!personalIndependentTarget()))
            return "个人空间独立显示需要选择备忘录或小米商城，不能同时选择隔离资料模式。";
        return null;
    }
    private void refreshBackgroundTaskTarget(){
        if(backgroundChoiceState==null||initialBackgroundApp==null||backgroundInitialLabel==null||backgroundMode==null)return;
        if(automaticMode()){refreshAutomaticTargetPreview();return;}
        String error=backgroundChoiceError();String summary="";
        if(backgroundMode.isChecked()){
            try{
                BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(taskInput.getText().toString(),selectedBackgroundPackage(),backgroundPackages,selectedProfileTarget());
                summary="本次使用："+backgroundAppLabels.getOrDefault(target.packageName,target.packageName)
                        +(target.webHelper()?"（官网查询工具）":"（所选应用）")+"。已保存的应用范围保持不变。";
            }catch(Exception unavailable){summary=HeptaAccessibilityService.message(unavailable);}
        }
        backgroundChoiceState.setText(error==null?summary:error);
        backgroundInitialLabel.setVisibility(backgroundMode.isChecked()?View.VISIBLE:View.GONE);
        initialBackgroundApp.setVisibility(backgroundMode.isChecked()?View.VISIBLE:View.GONE);
    }

    /** One visible Start, never restored across an Activity lifecycle. Model
     * settings use their original owner/slot/transaction; no task exists yet. */
    private static final class AutomaticStart {
        final MainActivity activity;
        final BackgroundAutoTargetResolver.Resolution resolution;
        final BackgroundAutoTargetPreferences.Entry entry;
        final String owner,source,originalNonce,nonce;
        final long uiEpoch;
        final LocalModelEngine.RuntimeGeneration previousRuntime;
        boolean settingsStarted,cancelled,consumed,entered,scheduleAttempted;
        LocalModelEngine.RuntimeGeneration readyRuntime;
        BackgroundAutoTargetResolver.StartSelection confirmed;
        private AutomaticStart(MainActivity activity,BackgroundAutoTargetResolver.Resolution resolution,
                BackgroundAutoTargetPreferences.Entry entry,String source,String originalNonce,long uiEpoch,
                LocalModelEngine.RuntimeGeneration previousRuntime){
            this.activity=activity;this.resolution=resolution;this.entry=entry;owner=resolution.owner;
            this.source=source;this.originalNonce=originalNonce;this.uiEpoch=uiEpoch;this.previousRuntime=previousRuntime;
            nonce=java.util.UUID.randomUUID().toString().replace("-","");
        }
    }
    private boolean automaticMode(){
        return automaticTargetMode!=null&&automaticTargetMode.isChecked();
    }
    private void invalidateAutomaticStart(){
        if(automaticStartPending!=null)automaticStartPending.cancelled=true;
        if(automaticReadyStart!=null)automaticReadyStart.cancelled=true;
        automaticStartPending=null;automaticReadyStart=null;automaticUiEpoch++;
    }
    private void automaticInputChanged(){
        invalidateAutomaticStart();automaticResolution=null;automaticInstanceChoice=null;automaticStartFeedback=null;
    }
    private boolean automaticWorkIdle(){
        return !isFinishing()&&!isDestroyed()&&!profileCatalogueLoading
                &&!tasks.isRunning()&&!tasks.isBlocked()&&!tasks.isRecovering()&&!tasks.hasBackgroundLease()
                &&!engine.isBusy()&&!modelSettings.isBusy()&&!modelImport.isBusy()&&!backgroundPermission.blocksOtherWork();
    }
    private boolean automaticUiIdle(){return hasWindowFocus()&&automaticWorkIdle();}
    private void restoreAutomaticTargets(){
        try{automaticTargets=BackgroundAutoTargetPreferences.load(this);automaticTargetsError=null;automaticTargetMode.setChecked(automaticTargets.automatic);}
        catch(Exception error){automaticTargets=null;automaticTargetsError="自动目标偏好无法读取，请重新明确选择。";automaticTargetMode.setChecked(true);}
        automaticInputChanged();
    }
    private void installAutomaticTargetListeners(){
        automaticTargetMode.setOnClickListener(view->{
            if(!automaticUiIdle()||!automaticTargetMode.isShown()){
                automaticTargetMode.setChecked(automaticTargets==null||automaticTargets.automatic);refresh();return;
            }
            try{
                BackgroundAutoTargetPreferences.Snapshot base=automaticTargets==null?BackgroundAutoTargetPreferences.empty():automaticTargets;
                BackgroundAutoTargetPreferences.Snapshot next=base.withAutomatic(automaticTargetMode.isChecked());
                BackgroundAutoTargetPreferences.save(this,next);automaticTargets=next;automaticTargetsError=null;automaticInputChanged();
            }catch(Exception error){automaticTargetMode.setChecked(automaticTargets==null||automaticTargets.automatic);automaticStartFeedback="自动选择未保存："+HeptaAccessibilityService.message(error);taskState.setText(automaticStartFeedback);}
            refresh();
        });
        pickAutomaticTargets.setOnClickListener(view->chooseAutomaticTargets());
        pickAutomaticInstance.setOnClickListener(view->chooseAutomaticInstance());
    }
    private void chooseAutomaticTargets(){
        if(!automaticUiIdle())return;
        automaticInputChanged();final long epoch=automaticUiEpoch;
        profileCatalogueLoading=true;taskState.setText("正在读取可明确保存的应用实例和首选模型……");refresh();
        final android.content.Context context=getApplicationContext();
        new Thread(()->{
            final java.util.List<BackgroundAutoTargetPreferences.Entry> candidates=new java.util.ArrayList<BackgroundAutoTargetPreferences.Entry>();
            String error=null;
            try{
                if(context.getPackageManager().getLaunchIntentForPackage(BackgroundAutoTargetPreferences.NOTES)!=null){
                    BackgroundAutoTargetPreferences.Entry item=BackgroundAutoTargetPreferences.captureNotes(context);
                    candidates.add(item);candidates.add(item.withModel(ModelProfile.QWEN35_4B));
                    candidates.add(item.withModel(ModelProfile.LFM25_8B_A1B));
                }
                for(org.trillionnium.hepta.background.ProfileTarget target:ProfileCatalogueClient.load(context)){
                    BackgroundAutoTargetPreferences.Entry item=BackgroundAutoTargetPreferences.captureProfile(target);
                    candidates.add(item);
                    if(org.trillionnium.hepta.background.ProfileTarget.CTRIP.equals(target.packageName))
                        candidates.add(item.withModel(ModelProfile.LFM3));
                    else if(org.trillionnium.hepta.background.ProfileTarget.XIAOMI.equals(target.packageName)){
                        candidates.add(item.withModel(ModelProfile.QWEN35_4B));
                        candidates.add(item.withModel(ModelProfile.LFM25_8B_A1B));
                    }
                }
            }catch(Exception failure){error=HeptaAccessibilityService.message(failure);}
            final String failure=error;
            runOnUiThread(()->{
                profileCatalogueLoading=false;
                if(epoch!=automaticUiEpoch||!automaticUiIdle()){refresh();return;}
                if(failure!=null){taskState.setText("无法读取自动目标："+failure);refresh();return;}
                if(candidates.isEmpty()){taskState.setText("未找到可用的个人备忘录或工作资料携程、小米商城。");refresh();return;}
                final BackgroundAutoTargetPreferences.Snapshot previous=automaticTargets==null?BackgroundAutoTargetPreferences.empty():automaticTargets;
                final java.util.Set<String> chosen=new java.util.HashSet<String>();
                String[] labels=new String[candidates.size()];boolean[] checked=new boolean[candidates.size()];
                for(int i=0;i<candidates.size();i++){
                    BackgroundAutoTargetPreferences.Entry item=candidates.get(i),saved=previous.entry(item.instanceKey);
                    checked[i]=saved!=null&&saved.identitySha256.equals(item.identitySha256);if(checked[i])chosen.add(item.identitySha256);
                    labels[i]=item.label()+"\n"+item.modelLabel()+" · "+(item.independentProfile()?"工作资料独立后台显示":"个人空间独立后台显示");
                }
                new AlertDialog.Builder(this).setTitle("自动目标与模型（最多 6 个应用实例，每个选一项）")
                        .setMultiChoiceItems(labels,checked,(dialog,index,enabled)->{
                            BackgroundAutoTargetPreferences.Entry item=candidates.get(index);
                            checked[index]=enabled;
                            if(!enabled){chosen.remove(item.identitySha256);return;}
                            chosen.add(item.identitySha256);
                            // Model alternatives share one installed instance and one scheduling slot.
                            for(int other=0;other<candidates.size();other++){
                                BackgroundAutoTargetPreferences.Entry sibling=candidates.get(other);
                                if(other!=index&&sibling.instanceKey.equals(item.instanceKey)&&chosen.remove(sibling.identitySha256)){
                                    // The dialog adapter consults its initial array again when binding a row.
                                    checked[other]=false;
                                    ((AlertDialog)dialog).getListView().setItemChecked(other,false);
                                }
                            }
                        }).setNegativeButton("取消",null).setPositiveButton("保存所选目标与模型",(dialog,which)->{
                            try{
                                if(epoch!=automaticUiEpoch||!automaticWorkIdle())throw new IllegalStateException("界面或空闲状态已变化");
                                if(automaticTargets!=null)BackgroundAutoTargetPreferences.requireSame(this,previous);
                                java.util.List<BackgroundAutoTargetPreferences.Entry> selected=new java.util.ArrayList<BackgroundAutoTargetPreferences.Entry>();
                                for(BackgroundAutoTargetPreferences.Entry item:candidates)if(chosen.contains(item.identitySha256))selected.add(item);
                                BackgroundAutoTargetPreferences.Snapshot next=new BackgroundAutoTargetPreferences.Snapshot(previous.automatic,selected);
                                BackgroundAutoTargetPreferences.save(this,next);automaticTargets=next;automaticTargetsError=null;
                                automaticTargetMode.setChecked(next.automatic);automaticInputChanged();
                            }catch(Exception invalid){taskState.setText("自动目标未保存："+HeptaAccessibilityService.message(invalid));}
                            refresh();
                        }).show();refresh();
            });
        },"hepta-auto-target-catalogue").start();
    }
    private BackgroundAutoTargetResolver.Resolution currentAutomaticResolution(){
        if(automaticTargetsError!=null)throw new IllegalStateException(automaticTargetsError);
        if(!automaticMode()||automaticTargets==null||!automaticTargets.automatic)throw new IllegalStateException("请明确启用自动目标模式");
        String owner=taskInput.getText().toString();
        if(automaticResolution==null||!automaticResolution.same(owner,automaticTargets)){
            automaticResolution=BackgroundAutoTargetResolver.resolve(owner,automaticTargets,TaskAuthorization.parse(owner));automaticInstanceChoice=null;
        }
        return automaticResolution;
    }
    private void chooseAutomaticInstance(){
        if(!automaticUiIdle())return;
        try{
            final BackgroundAutoTargetResolver.Resolution resolution=currentAutomaticResolution();
            if(resolution.matches.size()<2)return;
            String[] labels=new String[resolution.matches.size()];
            for(int i=0;i<labels.length;i++){BackgroundAutoTargetPreferences.Entry item=resolution.matches.get(i);labels[i]=item.label()+"\n"+item.modelLabel();}
            new AlertDialog.Builder(this).setTitle("明确选择本次任务的应用实例").setItems(labels,(dialog,index)->{
                if(!automaticWorkIdle()||automaticResolution!=resolution||!resolution.same(taskInput.getText().toString(),automaticTargets))return;
                invalidateAutomaticStart();automaticInstanceChoice=resolution.matches.get(index).instanceKey;refresh();
            }).setNegativeButton("取消",null).show();
        }catch(Exception error){taskState.setText(HeptaAccessibilityService.message(error));}
    }
    private String automaticChoiceError(){
        if(automaticTargetsError!=null)return automaticTargetsError;
        if(!automaticMode())return null;
        if(backgroundModePreferenceError!=null)return backgroundModePreferenceError;
        if(!backgroundMode.isChecked())return "自动目标需要启用后台空间操作。";
        try{currentAutomaticResolution().choose(automaticInstanceChoice);return null;}
        catch(Exception error){return HeptaAccessibilityService.message(error);}
    }
    private void refreshAutomaticTargetPreview(){
        String message;int matches=0;
        try{
            BackgroundAutoTargetResolver.Resolution resolution=currentAutomaticResolution();matches=resolution.matches.size();
            BackgroundAutoTargetPreferences.Entry item=resolution.choose(automaticInstanceChoice);
            message="本次使用："+item.label()+"；首选 "+item.modelLabel()+"。手动起始应用保持不变。";
        }catch(Exception error){message=HeptaAccessibilityService.message(error);}
        if(pickAutomaticInstance!=null)pickAutomaticInstance.setVisibility(matches>1?View.VISIBLE:View.GONE);
        backgroundChoiceState.setText(message+(automaticStartFeedback==null?"":"\n"+automaticStartFeedback));backgroundInitialLabel.setVisibility(View.GONE);initialBackgroundApp.setVisibility(View.GONE);
    }
    private void requireAutomaticOwner(AutomaticStart pending)throws Exception{
        if(android.os.Looper.myLooper()!=android.os.Looper.getMainLooper()||pending==null||pending.activity!=this||pending.cancelled||pending.uiEpoch!=automaticUiEpoch
                ||!"user_button".equals(pending.source)||!hasWindowFocus()||!accessibilityUiStarted||isFinishing()||isDestroyed()
                ||getWindow()==null||!getWindow().getDecorView().isShown()||startTask==null||!startTask.isShown()
                ||!backgroundMode.isChecked()||!automaticMode()||automaticResolution!=pending.resolution
                ||!pending.owner.equals(taskInput.getText().toString())||!pending.resolution.same(pending.owner,automaticTargets)
                ||pending.resolution.choose(automaticInstanceChoice)!=pending.entry)
            throw new IllegalStateException("本次自动开始已因界面、任务或目标变化而失效");
        if(backgroundModePreferenceError!=null||!BackgroundUiPreferences.mode(this))
            throw new IllegalStateException("后台操作模式未保存或已变化");
        BackgroundAutoTargetPreferences.requireSame(this,pending.resolution.snapshot);pending.entry.requireCurrent(this);
    }
    private boolean prepareAutomaticStart(String owner,String source,String nonceSha)throws Exception{
        if(android.os.Looper.myLooper()!=android.os.Looper.getMainLooper()||!"user_button".equals(source)||!automaticUiIdle()||!accessibilityUiStarted||!startTask.isShown()||!startTask.isEnabled()
                ||!owner.equals(taskInput.getText().toString())||automaticStartPending!=null||automaticReadyStart!=null)
            throw new IllegalStateException("自动目标只能由当前可见且空闲的开始按钮确认");
        if(scopeLaunchError!=null)throw new IllegalStateException(scopeLaunchError);
        QualificationScopeConfig.FilesRoot root=new QualificationScopeConfig.FilesRoot(this);
        if(scopeLaunch.expectedSha256!=null||MobiMindPrivateFiles.exists(new File(root.path,QualificationScope.FILE_NAME)))
            throw new IllegalStateException("当前 qualification scope 已启用，自动目标不可开始");
        TaskAuthorization original=TaskAuthorization.parse(owner);
        if(original.requireFindAppBeforeOpen||!original.allowedTools.contains("open"))
            throw new IllegalStateException("当前指令不允许打开应用，模型设置与任务均未开始");
        BackgroundAutoTargetResolver.Resolution resolution=currentAutomaticResolution();
        BackgroundAutoTargetPreferences.Entry entry=resolution.choose(automaticInstanceChoice);
        BackgroundAutoTargetPreferences.requireSame(this,resolution.snapshot);entry.requireCurrent(this);
        LocalModelEngine.RuntimeGeneration previous=engine.runtimeGeneration();
        if(previous==null||previous!=engine.runtimeGeneration()||previous.configuration()!=engine.configuration())throw new IllegalStateException("实际模型代已变化");
        final AutomaticStart pending=new AutomaticStart(this,resolution,entry,source,nonceSha,automaticUiEpoch,previous);
        automaticStartPending=pending;requireAutomaticOwner(pending);
        if(entry.matches(previous.configuration()))return finishAutomaticPreparation(pending);
        LocalProbeApplication app=(LocalProbeApplication)getApplication();
        if(!app.canChangeLocalModelSettings(false)){invalidateAutomaticStart();throw new IllegalStateException("请先完成模型设置或清理，再开始任务");}
        pending.settingsStarted=true;automaticStartFeedback="正在准备 "+entry.label()+" 的首选模型 "+entry.modelLabel()+"，完成后开始本次任务……";taskState.setText(automaticStartFeedback);
        try{modelSettings.start(entry.modelProfile,entry.compute,false);refresh();return true;}
        catch(Exception error){invalidateAutomaticStart();throw error;}
    }
    private boolean finishAutomaticPreparation(AutomaticStart pending){
        if(pending==null||automaticStartPending!=pending||pending.cancelled||pending.consumed||modelSettings.isBusy())return false;
        try{
            requireAutomaticOwner(pending);
            LocalProbeApplication app=(LocalProbeApplication)getApplication();
            if(!app.canChangeLocalModelSettings(false)||engine.settingsBlocked())throw new IllegalStateException("模型准备未完成或退出状态尚未确认");
            LocalModelEngine.RuntimeGeneration actual=engine.runtimeGeneration();
            if(actual==null||actual.source==null||actual!=engine.runtimeGeneration()||!pending.entry.matches(actual.configuration())
                    ||(!pending.settingsStarted&&actual!=pending.previousRuntime)
                    ||(pending.settingsStarted&&actual==pending.previousRuntime))throw new IllegalStateException("首选模型没有形成已核验的实际配置代");
            actual.source.unchanged();requireAutomaticOwner(pending);
            if(actual!=engine.runtimeGeneration())throw new IllegalStateException("模型代在开始前发生变化");
            pending.readyRuntime=actual;pending.confirmed=pending.resolution.confirm(pending.entry,pending.nonce,actual.id,actual.source.sha());
            pending.consumed=true;automaticStartPending=null;automaticReadyStart=pending;automaticStartFeedback=null;
            try{return beginTask(pending.owner,pending.source,pending.originalNonce);}
            finally{automaticReadyStart=null;refresh();}
        }catch(Exception error){
            String settingsFailure=pending.settingsStarted?modelSettings.failure():null;
            String rejected=HeptaAccessibilityService.message(error);
            invalidateAutomaticStart();automaticStartFeedback="自动任务未开始："+(settingsFailure==null?rejected:settingsFailure+"（"+rejected+"）");
            taskState.setText(automaticStartFeedback);refresh();return false;
        }
    }
    private BackgroundSession.Selection automaticStartSelection(String owner)throws Exception{
        AutomaticStart pending=automaticReadyStart;
        if(pending==null||!pending.consumed||pending.entered||pending.confirmed==null||!pending.owner.equals(owner))
            throw new IllegalStateException("自动目标没有同一次已核验的开始来源");
        pending.entered=true;requireAutomaticOwner(pending);
        if(pending.readyRuntime!=engine.runtimeGeneration()||!pending.entry.matches(engine.configuration())||engine.settingsBlocked()||modelSettings.isBusy())
            throw new IllegalStateException("首选模型在开始前已变化");
        pending.readyRuntime.source.unchanged();
        BackgroundTaskTarget target=BackgroundTaskTarget.resolveAutomaticSelection(owner,pending.confirmed);
        boolean profile=pending.entry.independentProfile();
        return new BackgroundSession.Selection(target,profile,pending.entry.independentPersonal(),
                profile&&org.trillionnium.hepta.background.ProfileTarget.CTRIP.equals(target.packageName)?controllerUiFromOwnerButton(owner):null);
    }
    private void requireAutomaticSchedule(String owner)throws Exception{
        AutomaticStart pending=automaticReadyStart;
        if(pending==null||!pending.entered||pending.scheduleAttempted||!pending.owner.equals(owner))throw new IllegalStateException("自动开始不能重复提交");
        requireAutomaticOwner(pending);
        if(pending.readyRuntime!=engine.runtimeGeneration()||!pending.entry.matches(engine.configuration())||engine.settingsBlocked()||modelSettings.isBusy())throw new IllegalStateException("实际模型代已变化");
        pending.readyRuntime.source.unchanged();pending.scheduleAttempted=true;
    }
    private boolean cancelAutomaticStart(){
        if(automaticStartPending==null)return false;
        invalidateAutomaticStart();automaticStartFeedback="已取消任务开始。正在进行的模型设置会正常收尾，不会自动启动任务。";taskState.setText(automaticStartFeedback);refresh();return true;
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
    @Override public void onSessionChanged(){
        recoveryUiFeedback=null;refresh(false);
        if(ownerCleanupFeedbackPending&&!tasks.isRecovering()){
            ownerCleanupFeedbackPending=false;revealTaskState();
        }
    }
    /** Reveal this Activity's next recovery action, without changing any task or display. */
    private void revealTaskState(){
        final View target=recoveryCard!=null&&recoveryCard.getVisibility()==View.VISIBLE?recoveryCard:taskState;
        target.post(() -> {
            if(accessibilityUiStarted&&hasWindowFocus()&&!isFinishing()&&!isDestroyed())
                target.requestRectangleOnScreen(new android.graphics.Rect(0,0,target.getWidth(),
                        Math.max(1,Math.min(target.getHeight(),dp(300)))),false);
        });
    }
    @Override public void onPermissionPreparationChanged(){refresh();}
    private void refresh(){refresh(true);}
    /** Display-only reattachment; never launches an Activity, grants a permission,
     * restores an old input attempt or broadens the selected business App range. */
    private void refreshProfilePermission(){
        if(profilePermissionCard==null)return;
        HeptaAccessibilityService connected=HeptaAccessibilityService.connected();
        if(profilePermissionService!=connected){
            if(profilePermissionService!=null){
                profilePermissionService.permissionUi().ownerVisibility(this,null,false);
                profilePermissionService.permissionUi().unbind(profilePermissionChanged);
            }
            profilePermissionService=connected;
            if(profilePermissionService!=null&&accessibilityUiStarted)profilePermissionService.permissionUi().bind(profilePermissionChanged);
        }
        ProfilePermissionUiSession.Presentation value=profilePermissionService==null?null:profilePermissionService.permissionUi().current();
        shownProfilePermission=value;
        if(value==null){
            profilePermissionCard.setVisibility(View.GONE);denyProfilePermission.setEnabled(false);
            if(profilePermissionService!=null)profilePermissionService.permissionUi().ownerVisibility(this,null,false);
            return;
        }
        StringBuilder text=new StringBuilder(value.state);
        if(!value.message.isEmpty())text.append("\n\n系统请求原文：\n").append(value.message);
        if(!value.visibleOptions.isEmpty()){
            text.append("\n\n系统当前显示的选项：");
            for(String label:value.visibleOptions)text.append("\n• ").append(label);
            text.append("\n此处仅可选择拒绝；允许类选项仅作展示。");
        }
        profilePermissionMessage.setText(text.toString());profilePermissionCard.setVisibility(View.VISIBLE);
        denyProfilePermission.setEnabled(value.denyAvailable&&tasks.isRunning()&&value.taskId.equals(tasks.taskId()));
        profilePermissionService.permissionUi().ownerVisibility(this,value,accessibilityUiStarted&&hasWindowFocus()
                &&!isFinishing()&&!isDestroyed()&&profilePermissionCard.isShown()&&profilePermissionMessage.isShown()
                &&tasks.isRunning()&&value.taskId.equals(tasks.taskId()));
    }
    private void refresh(boolean inspectModelFile){
        if(modelInfo==null)return;
        refreshProfilePermission();
        boolean available=HeptaAccessibilityService.connected()!=null;
        String device,modelName="本地模型",modelState;
        boolean configurationReady=false,visualProfile=false,visualObserve=false;
        try {
            LocalRuntimeConfig configuration=engine.configuration();
            visualProfile=configuration.profile.visual();visualObserve=configuration.visualObservationOnly;
            device="npu".equals(configuration.compute)?"Hexagon NPU":"Adreno GPU";modelName=configuration.profile.displayName;
            if(visualProfile)device="Hexagon NPU + Adreno GPU视觉";
            if(inspectModelFile)cachedModelFilePresent=engine.modelFile().isFile()
                    &&(!visualProfile||new File(engine.modelDirectory(),VlmResultContract.named(configuration.profile.id).projectorFilename).isFile());
            modelState=cachedModelFilePresent?"本地模型已导入":"本地模型待导入";
            if(visualProfile)modelState+=visualObserve?" · 仅观察，不执行工具":" · 本地视觉工具模式";
            configurationReady=true;
        }catch(Exception error) {
            device="运行参数待修正";modelState="本地配置错误："+HeptaAccessibilityService.message(error);
        }
        modelIdentity.setText("当前模型："+modelName+" · "+device);
        modelInfo.setText(modelState+" · "+(available?"无障碍已启用":"请启用无障碍"));
        modelDiagnostics.setText(modelName+" · "+device+" · 无外部模型");
        LocalProbeApplication modelApp=(LocalProbeApplication)getApplication();
        importLocalModel.setEnabled(pendingImportAsset==null&&!profileCatalogueLoading&&modelApp.canImportLocalModel());
        cancelModelImport.setVisibility(modelImport.isBusy()?View.VISIBLE:View.GONE);
        cancelModelImport.setEnabled(modelImport.isBusy());localModelImportState.setText(modelImport.state());
        chooseLocalModel.setEnabled(!profileCatalogueLoading&&modelApp.canChangeLocalModelSettings(false));
        restoreLocalModel.setEnabled(!profileCatalogueLoading&&modelApp.canChangeLocalModelSettings(true));
        localModelSettingsState.setText(modelSettings.state()+"\n设置只使用本机文件；不自动回退 CPU。内存门槛不是实测峰值，8B 仍需同条件验证。");
        taskState.setText(TaskDisplayText.forStatus(tasks.state()));taskLog.setText(tasks.log());
        boolean busy=tasks.isRunning()||engine.isBusy()||profileCatalogueLoading||automaticStartPending!=null;
        backgroundPermissionState.setText(backgroundPermission.state());
        boolean recoveryAvailable=tasks.canAcknowledgeInterruption();
        BackgroundRecoveryPresentation recovery=BackgroundRecoveryPresentation.from(tasks.isRunning(),tasks.isRecovering(),
                tasks.hasBackgroundLease(),tasks.isBlocked(),recoveryAvailable,
                recoveryAvailable?null:tasks.interruptionRecoveryUnavailableReason());
        recoveryCard.setVisibility(recovery.visible?View.VISIBLE:View.GONE);
        recoveryTitle.setText(recovery.title);recoveryMessage.setText(recoveryUiFeedback==null?recovery.message:recoveryUiFeedback);
        backgroundSummary.setText(recovery.visible?recovery.title:tasks.isRunning()&&backgroundMode.isChecked()?"正在后台执行":
                tasks.hasBackgroundLease()?"上次后台空间待清理":
                backgroundMode.isChecked()?(independentProfileDisplay.isChecked()?"将在所选隔离资料应用的独立后台显示中操作":
                        independentPersonalDisplay.isChecked()?"将在所选个人空间应用的新建独立后台显示中操作":"将在所选起始应用的后台空间操作")
                        :"前台模式会操作主屏幕；点击「开始任务」表示同意本次主屏操作");
        if(automaticMode()&&backgroundMode.isChecked()&&!tasks.isRunning()&&!tasks.hasBackgroundLease()&&!recovery.visible)
            backgroundSummary.setText("按本次完整任务选择已保存的应用实例和首选模型；每次只执行一个目标。");
        boolean autoControls=!busy&&!tasks.isBlocked()&&!tasks.isRecovering()&&!tasks.hasBackgroundLease()&&!backgroundPermission.blocksOtherWork()&&!modelSettings.isBusy()&&!modelImport.isBusy();
        if(automaticTargetMode!=null)automaticTargetMode.setEnabled(autoControls);
        if(pickAutomaticTargets!=null){pickAutomaticTargets.setEnabled(autoControls);pickAutomaticTargets.setText("管理自动目标与首选模型（"+(automaticTargets==null?0:automaticTargets.targets.size())+" 个）");}
        if(pickAutomaticInstance!=null){pickAutomaticInstance.setVisibility(automaticMode()&&automaticResolution!=null&&automaticResolution.matches.size()>1?View.VISIBLE:View.GONE);pickAutomaticInstance.setEnabled(autoControls);}
        openRootManager.setEnabled(rootManagerNavigationIdle());
        prepareBackgroundPermission.setEnabled(!busy&&!tasks.isBlocked()&&!tasks.isRecovering()&&!tasks.hasBackgroundLease()
                &&!visualDiagnostic.isBusy()&&!visualDiagnostic.isBlocked()&&!uiVenusDiagnostic.isBusy()&&!uiVenusDiagnostic.isBlocked());
        backgroundMode.setEnabled(!busy&&!tasks.isRecovering());pickBackgroundApps.setEnabled(!busy&&!tasks.isRecovering());initialBackgroundApp.setEnabled(!busy&&!tasks.isRecovering());
        pickProfileTarget.setEnabled(!busy&&!tasks.isBlocked()&&!tasks.isRecovering()&&!tasks.hasBackgroundLease()&&!backgroundPermission.blocksOtherWork());
        independentProfileDisplay.setEnabled(backgroundMode.isChecked()&&!busy&&!tasks.isBlocked()&&!tasks.isRecovering()
                &&!tasks.hasBackgroundLease()&&!backgroundPermission.blocksOtherWork()
                &&(selectedProfileTarget()!=null||independentProfileDisplay.isChecked()||backgroundDisplayPreferenceError!=null));
        independentPersonalDisplay.setEnabled(backgroundMode.isChecked()&&!busy&&!tasks.isBlocked()&&!tasks.isRecovering()
                &&!tasks.hasBackgroundLease()&&!backgroundPermission.blocksOtherWork()
                &&(personalIndependentTarget()||independentPersonalDisplay.isChecked()||backgroundDisplayPreferenceError!=null));
        if(automaticMode()){pickBackgroundApps.setEnabled(false);pickProfileTarget.setEnabled(false);initialBackgroundApp.setEnabled(false);independentProfileDisplay.setEnabled(false);independentPersonalDisplay.setEnabled(false);}
        cleanupBackground.setVisibility(tasks.hasBackgroundLease()?View.VISIBLE:View.GONE);
        cleanupBackground.setEnabled(!modelSettings.isBusy()&&!tasks.isRunning()&&!tasks.isRecovering()&&!backgroundPermission.blocksOtherWork());
        acknowledgeInterruption.setVisibility(tasks.isBlocked()||tasks.isRecovering()||recoveryAvailable?View.VISIBLE:View.GONE);
        acknowledgeInterruption.setEnabled(recoveryAvailable);
        String backgroundError=backgroundChoiceError();
        previewTaskAuthorization();
        pickBackgroundApps.setText(backgroundError==null
                ?(backgroundPackages.isEmpty()?"选择后台应用范围":"后台范围："+backgroundPackages.size()+" 个应用（更改）")
                :"后台应用范围（需重新确认）");
        startTask.setEnabled(available&&configurationReady&&!busy&&!tasks.isBlocked()&&(!backgroundMode.isChecked()||backgroundError==null)
                &&(!automaticMode()||(backgroundMode.isChecked()&&backgroundError==null)));
        stopTask.setEnabled(automaticStartPending!=null||(busy&&!modelSettings.isBusy()&&!modelImport.isBusy()));
        runText.setEnabled(configurationReady&&!visualProfile&&!busy&&!tasks.isBlocked());
        LocalTaskController.TaskResult result=tasks.lastResult();
        if(result!=null){
            if(!busy&&!tasks.isBlocked()&&!tasks.isRecovering())taskState.setText(TaskDisplayText.forStatus(result.displaySummary));
            taskResult.setText(TaskDisplayText.forStatus(result.displaySummary));
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
    @Override protected void onStart(){super.onStart();if(tasks!=null)tasks.bind(this);if(backgroundPermission!=null)backgroundPermission.bind(this);if(modelSettings!=null)modelSettings.bind(this);if(modelImport!=null)modelImport.bind(this);
        accessibilityUiStarted=true;HeptaAccessibilityService.addConnectionListener(accessibilityConnectionChanged);
        if(profilePermissionService!=null)profilePermissionService.permissionUi().bind(profilePermissionChanged);
        refreshProfilePermission();
    }
    @Override protected void onResume(){super.onResume();if(tasks!=null){recheckBackgroundChoice();refresh();}}
    @Override public void onWindowFocusChanged(boolean focused){
        super.onWindowFocusChanged(focused);
        if(!focused&&automaticStartPending!=null){invalidateAutomaticStart();automaticStartFeedback="已离开当前任务界面，自动开始已取消。";}
        if(!focused&&profilePermissionService!=null)profilePermissionService.permissionUi().ownerVisibility(this,null,false);
        if(focused&&accessibilityUiStarted)refreshProfilePermission();
    }
    @Override protected void onStop(){automaticInputChanged();accessibilityUiStarted=false;HeptaAccessibilityService.removeConnectionListener(accessibilityConnectionChanged);
        if(profilePermissionService!=null){
            profilePermissionService.permissionUi().ownerVisibility(this,null,false);
            profilePermissionService.permissionUi().unbind(profilePermissionChanged);
        }
        if(tasks!=null)tasks.unbind(this);if(backgroundPermission!=null)backgroundPermission.unbind(this);if(modelSettings!=null)modelSettings.unbind(this);if(modelImport!=null)modelImport.unbind(this);super.onStop();
    }
}

