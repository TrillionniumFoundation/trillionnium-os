package org.trillionnium.hepta.webhelper;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.os.SystemClock;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.GeolocationPermissions;
import android.webkit.JsPromptResult;
import android.webkit.JsResult;
import android.webkit.PermissionRequest;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebStorageEvidence;
import android.view.accessibility.AccessibilityNodeInfo;
import java.security.SecureRandom;
import java.util.UUID;

/** Fixed official page UI. Launch itself creates only a local placeholder. */
public final class PageActivity extends Activity {
    private EvidenceSession session;
    private WebView web,popupInterceptor;
    private ObservedLinkPermit armedLink,lastObservedLink;
    private JSONObject armedCaptureSource;
    private String expectedControlledMainUrl,allowedShoppingUrl;
    private boolean auxiliaryStopSucceeded=true,auxiliaryDestroySucceeded=true;
    private OfficialPageCapture capture;
    private ProfileIsolation isolation;
    private PageSitePolicy sitePolicy;
    private final String plannedInstance=UUID.randomUUID().toString();
    private int savedWindow=-1;
    private boolean preparing;
    // These latches are set before the respective operation and never reset after failure.
    private boolean resourceCreationDispatched,profileAssignmentDispatched;
    private int loadDispatchCount,captureDispatchCount,ownedDisplayId=-1;
    private final org.json.JSONArray destructionFailures=new org.json.JSONArray();
    interface Loaded { void complete(boolean ok,String reason); }
    private LinearLayout content,manualActions;
    private TextView address,status;
    private long created;
    private boolean diagnostic,loaded,destroyed,bound;
    private JSONObject destroyedFacts;
    private String savedInstance;
    private long savedEpoch;
    private final Runnable diagnosticAfterTouch=()->{if(session!=null&&diagnostic&&!destroyed)session.diagnostic(PageActivity.this,"ordinary_touch_followed_by_read_only_capture");};

    @Override public void onCreate(Bundle state){
        super.onCreate(state);created=SystemClock.elapsedRealtime();
        try{
            Intent intent=getIntent();Jsons.need(intent!=null&&Intent.ACTION_MAIN.equals(intent.getAction())&&intent.getData()==null
                    &&(intent.getExtras()==null||intent.getExtras().isEmpty()),"launcher only; page parameters refused");
            session=EvidenceSession.get(this);Jsons.need(session.register(this),"another or unknown helper page already exists");
            content=new LinearLayout(this);content.setOrientation(LinearLayout.VERTICAL);content.setBackgroundColor(Color.WHITE);
            address=new TextView(this);address.setText("官方网页 · 尚未加载");address.setTextSize(14);address.setPadding(16,12,16,12);content.addView(address);
            status=new TextView(this);status.setText("等待 Hepta 的当前任务授权。页面数据不会直接授予任务成功。");status.setTextSize(12);status.setPadding(16,4,16,8);content.addView(status);
            manualActions=new LinearLayout(this);manualActions.setOrientation(LinearLayout.HORIZONTAL);
            Button open=new Button(this);open.setText("南航官网（观察）");open.setOnClickListener(v->openDiagnostic(false));
            Button mi=new Button(this);mi.setText("小米官网（观察）");mi.setOnClickListener(v->openDiagnostic(true));
            Button record=new Button(this);record.setText("记录当前页面（只读）");record.setOnClickListener(v->{if(session.canDiagnose(this)&&diagnostic)session.diagnostic(this,"manual_record_button");});
            manualActions.addView(open,new LinearLayout.LayoutParams(0,ViewGroup.LayoutParams.WRAP_CONTENT,1));
            manualActions.addView(mi,new LinearLayout.LayoutParams(0,ViewGroup.LayoutParams.WRAP_CONTENT,1));
            manualActions.addView(record,new LinearLayout.LayoutParams(0,ViewGroup.LayoutParams.WRAP_CONTENT,1));
            content.addView(manualActions);manualActions.setVisibility(actualDisplayId()==0?View.VISIBLE:View.GONE);
            getWindow().setDecorFitsSystemWindows(false);
            content.setOnApplyWindowInsetsListener((view,insets)->{
                android.graphics.Insets bars=insets.getInsets(android.view.WindowInsets.Type.systemBars()
                        |android.view.WindowInsets.Type.displayCutout());
                view.setPadding(bars.left,bars.top,bars.right,bars.bottom);
                android.view.WindowInsetsController controller=getWindow().getInsetsController();
                if(controller!=null)controller.setSystemBarsAppearance(
                        android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                                |android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS,
                        android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                                |android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS);
                return insets;
            });
            setContentView(content); // No WebView/profile/network page exists before attach or an explicit diagnostic tap.
            content.requestApplyInsets(); // Actual system bars/cutout; a display without SystemUI contributes zero.

        }catch(Exception failure){showFatal(failure.getMessage());}
    }
    private void createIsolatedWeb(String profileName,PageSitePolicy selectedPolicy)throws Exception{
        Jsons.need(web==null&&capture==null&&isolation==null&&sitePolicy==null&&!destroyed&&selectedPolicy!=null,"WebView/policy creation is single use");
        sitePolicy=selectedPolicy;allowedShoppingUrl=sitePolicy.initialUrl;
            ProfileIsolation.requireAvailable(profileName); // Read-only feature/name preflight before any WebView construction.
            resourceCreationDispatched=true;
            web=new WebView(this);
            profileAssignmentDispatched=true;
            isolation=ProfileIsolation.create(web,profileName); // First interaction with this new WebView.
            web.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
            WebSettings settings=web.getSettings();settings.setJavaScriptEnabled(true);settings.setDomStorageEnabled(true);
            // Honor the site's mobile viewport, including its overview zoom. No hard-coded initial scale.
            settings.setUseWideViewPort(true);settings.setLoadWithOverviewMode(true);
            settings.setAllowFileAccess(false);settings.setAllowContentAccess(false);settings.setAllowFileAccessFromFileURLs(false);
            settings.setAllowUniversalAccessFromFileURLs(false);settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
            settings.setGeolocationEnabled(false);settings.setJavaScriptCanOpenWindowsAutomatically(false);settings.setSupportMultipleWindows(true);
            settings.setMediaPlaybackRequiresUserGesture(true);settings.setSaveFormData(false);settings.setSafeBrowsingEnabled(true);
            web.setWebChromeClient(new WebChromeClient(){
                @Override public boolean onCreateWindow(WebView view,boolean dialog,boolean userGesture,android.os.Message result){
                    return createObservedLinkInterceptor(view,dialog,userGesture,result);
                }
                @Override public void onPermissionRequest(PermissionRequest request){request.deny();showProblem("网页设备权限未授予");}
                @Override public void onGeolocationPermissionsShowPrompt(String origin,GeolocationPermissions.Callback callback){callback.invoke(origin,false,false);showProblem("网页定位权限未授予");}
                @Override public boolean onJsAlert(WebView view,String url,String message,JsResult result){result.cancel();showProblem("网页对话框未确认");return true;}
                @Override public boolean onJsConfirm(WebView view,String url,String message,JsResult result){result.cancel();showProblem("网页确认未执行");return true;}
                @Override public boolean onJsPrompt(WebView view,String url,String message,String defaultValue,JsPromptResult result){result.cancel();showProblem("网页输入对话框未执行");return true;}
                @Override public boolean onShowFileChooser(WebView view,ValueCallback<android.net.Uri[]> callback,FileChooserParams params){callback.onReceiveValue(null);return true;}
            });
            web.setDownloadListener((url,userAgent,contentDisposition,mimetype,contentLength)->showProblem("网页下载未执行"));
            capture=new OfficialPageCapture(web,new OfficialPageCapture.LeaseGuard(){
                public void requireActive()throws Exception{session.requirePage(PageActivity.this);}
                public int expectedDisplayId(){return actualDisplayId();}
                public JSONObject binding()throws Exception{return session.pageBinding(PageActivity.this);}
            },plannedInstance,sitePolicy);
            capture.setNavigationGate(new OfficialPageCapture.NavigationGate(){
                public boolean allowMainFrameRequest(String url,String method){
                    // No popup/same-frame URL supplied by page code can select a route.
                    // The sole approved detail load is the actual intercepted armed href.
                    if(!sitePolicy.shopping())return true;
                    return sitePolicy.initial(url)||expectedControlledMainUrl!=null&&expectedControlledMainUrl.equals(url)&&"GET".equals(method);
                }
                public boolean allowMainFrameStarted(String url){
                    if(!sitePolicy.shopping())return true;
                    if(sitePolicy.initial(url)){allowedShoppingUrl=url;return true;}
                    if(expectedControlledMainUrl!=null&&expectedControlledMainUrl.equals(url)){
                        expectedControlledMainUrl=null;allowedShoppingUrl=url;return true;
                    }
                    return false;
                }
                public boolean allowHistoryOrCommitUrl(String url){
                    return !sitePolicy.shopping()||url!=null&&url.equals(allowedShoppingUrl);
                }
            });
            capture.setListener(event->{
                if("page_started".equals(event)||"history_changed".equals(event)||"invalidated".equals(event))
                    invalidateObservedLink("native_"+event);
                if(web!=null){String url=web.getUrl();address.setText(url==null?"官方网页 · 尚未加载":url);}
                if(diagnostic&&"page_finished".equals(event)&&web!=null)web.postDelayed(()->{if(diagnostic&&!destroyed)session.diagnostic(PageActivity.this,"page_finished_read_only_capture");},300);
            });
            web.setOnTouchListener((v,event)->{if(diagnostic&&event.getActionMasked()==MotionEvent.ACTION_UP){web.removeCallbacks(diagnosticAfterTouch);web.postDelayed(diagnosticAfterTouch,400);}return false;});
            content.addView(web,new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,0,1));
    }
    private void openDiagnostic(boolean shopping){
        try{
            Jsons.need(!loaded&&!preparing&&!destroyed&&!bound&&session.canDiagnose(this)&&actualDisplayId()==0,"fresh manual foreground diagnostic only");
            diagnostic=true;preparing=true;
            byte[] random=new byte[32];new SecureRandom().nextBytes(random);
            createIsolatedWeb(WebStorageEvidence.profileFor(ProcessIdentity.hex(random)),
                    shopping?PageSitePolicy.diagnosticShopping():PageSitePolicy.diagnosticFlight());
            status.setText("人工网页观察；正在等待独立存储清理回调。");
            isolation.clearBeforeFirstLoad(SystemClock.elapsedRealtime()+ProfileIsolation.CLEAR_BUDGET_MS,(ok,facts,reason)->{
                try{
                    Jsons.need(ok&&!destroyed&&!bound&&session.canDiagnose(this)&&actualDisplayId()==0,"diagnostic storage gate unavailable");
                    isolation.firstLoadDispatch(sitePolicy.initialUrl);preparing=false;loaded=true;
                    status.setText("人工网页观察；没有绑定任务，不代表查询完成。");
                    loadDispatchCount++;
                    web.loadUrl(sitePolicy.initialUrl);
                }catch(Exception failure){preparing=false;showProblem(reason+": "+failure.getMessage());session.diagnosticFailed(PageActivity.this);}
            });
        }catch(Exception failure){preparing=false;showProblem(failure.getMessage());if(session!=null)session.diagnosticFailed(this);}
    }
    boolean canAttach(TaskBinding binding)throws Exception{
        return !diagnostic&&!loaded&&!preparing&&!destroyed&&!bound&&web==null&&capture==null&&created>=binding.created
                &&actualDisplayId()==binding.displayId&&content!=null&&content.isAttachedToWindow()&&content.isShown()&&actualWindowId()>=0;
    }
    void attachAndLoad(final TaskBinding binding,final long deadline,final Loaded reply)throws Exception{
        Jsons.need(reply!=null&&canAttach(binding),"fresh bound placeholder required");
        final int expectedWindow=actualWindowId();Jsons.need(expectedWindow>=0,"current placeholder window required");
        ownedDisplayId=actualDisplayId();bound=true;preparing=true;manualActions.setVisibility(View.GONE);
        binding.requireActive(this);
        createIsolatedWeb(binding.evidence.getString("storage_profile_name"),PageSitePolicy.forTask(binding));
        status.setText("已绑定只读查询；等待当前租约的独立存储清理回调。");
        isolation.clearBeforeFirstLoad(deadline,(ok,facts,reason)->{
            try{
                Jsons.need(ok&&!destroyed&&bound&&preparing,"bound storage clear did not complete");
                binding.requireActive(this);
                requireBinding(binding,plannedInstance,expectedWindow);
                Jsons.need(SystemClock.elapsedRealtime()<=deadline,"attach RPC expired before page load");
                isolation.firstLoadDispatch(sitePolicy.initialUrl);preparing=false;loaded=true;
                status.setText("已绑定 Hepta 公开信息查询；结果仍需字段与来源核验。");
                loadDispatchCount++;
                web.loadUrl(sitePolicy.initialUrl); // This lease has exactly one compiled site/entry after the actual clear callback.
                reply.complete(true,"profile_isolated_and_fixed_page_load_dispatched");
            }catch(Exception failure){preparing=false;reply.complete(false,reason+": "+failure.getMessage());}
        });
    }
    void requireBinding(TaskBinding binding,String instance,int window)throws Exception{
        Jsons.need(!destroyed&&bound&&web!=null&&capture!=null&&isolation!=null&&actualDisplayId()==binding.displayId
                &&capture.instance().equals(instance)&&actualWindowId()==window&&web.isAttachedToWindow()&&web.isShown()
                &&isolation.profileName().equals(binding.evidence.getString("storage_profile_name"))
                &&sitePolicy!=null&&sitePolicy.kind.equals(binding.purpose.kind)&&sitePolicy.id.equals(binding.purpose.sitePolicyId)
                &&sitePolicy.sha.equals(binding.purpose.sitePolicySha256)&&sitePolicy.initialUrl.equals(binding.purpose.initialUrl),
                "bound page/window/profile/site identity changed");
        isolation.requireCurrentProfile();
    }
    void capture(String nonce,long deadline,OfficialPageCapture.Callback callback){
        if(capture==null||destroyed){callback.failed("owned WebView absent");return;}
        invalidateObservedLink("new_capture_started");
        captureDispatchCount++;capture.capture(nonce,deadline,new OfficialPageCapture.Callback(){
            public void captured(JSONObject actual){
                try{actual.put("observed_link_navigation",lastObservedLink==null?JSONObject.NULL:lastObservedLink.evidence());callback.captured(actual);}
                catch(Exception failure){callback.failed(failure.getMessage());}
            }
            public void failed(String reason){callback.failed(reason);}
            public void unstable(DomInstabilityEvidence.Pair pair)throws Exception{callback.unstable(pair);}
        });
    }
    void requireArmSource(JSONObject source)throws Exception{
        Jsons.need(!destroyed&&bound&&!diagnostic&&capture!=null&&web!=null&&isolation!=null
                &&sitePolicy!=null&&sitePolicy.shopping()&&popupInterceptor==null,"current formal shopping view required");
        session.requirePage(this);isolation.requireCurrentProfile();capture.requireArmSource(source);
    }
    void installObservedLinkArm(JSONObject actualArm,JSONObject source)throws Exception{
        requireArmSource(source);Jsons.need(armedLink==null,"observed-link permit already armed");
        ObservedLinkPermit permit=new ObservedLinkPermit(actualArm);
        permit.requireCurrent(SystemClock.elapsedRealtime(),capture.instance(),capture.navigationEpoch(),
                actualWindowId(),actualDisplayId(),web.getUrl(),
                org.trillionnium.hepta.webprotocol.WebEvidenceBinding.sha256(session.pageBinding(this)),isolation.profileName());
        armedCaptureSource=new JSONObject(source.toString());armedLink=permit;lastObservedLink=permit;
        boolean scheduled=web.postDelayed(()->{if(armedLink==permit)invalidateObservedLink("arm_deadline_elapsed");},
                Math.max(1,permit.deadline-SystemClock.elapsedRealtime()));
        if(!scheduled){invalidateObservedLink("arm_deadline_could_not_be_scheduled");throw new IllegalStateException("arm timer unavailable");}
    }
    void invalidateObservedLink(String reason){
        ObservedLinkPermit old=armedLink;armedLink=null;armedCaptureSource=null;
        if(old!=null)try{old.cancel(reason,SystemClock.elapsedRealtime());}catch(Exception failure){destructionFailures.put("arm_cancel:"+failure.getClass().getName());}
        destroyPopupInterceptor();
    }
    private void requirePopupSource(ObservedLinkPermit permit)throws Exception{
        Jsons.need(armedLink==permit&&!destroyed&&bound&&!diagnostic&&capture!=null&&web!=null&&isolation!=null,
                "original armed formal view absent");
        session.requirePage(this);isolation.requireCurrentProfile();
        Jsons.need(armedCaptureSource!=null,"original arm capture absent");capture.requireArmSource(armedCaptureSource);
        permit.requireCurrent(SystemClock.elapsedRealtime(),capture.instance(),capture.navigationEpoch(),
                actualWindowId(),actualDisplayId(),web.getUrl(),
                org.trillionnium.hepta.webprotocol.WebEvidenceBinding.sha256(session.pageBinding(this)),isolation.profileName());
    }
    private boolean createObservedLinkInterceptor(WebView caller,boolean dialog,boolean gesture,android.os.Message result){
        ObservedLinkPermit permit=armedLink;boolean handedOff=false;
        try{
            Jsons.need(caller==web&&permit!=null&&popupInterceptor==null&&result!=null
                    &&result.obj instanceof WebView.WebViewTransport,"an actual armed popup callback is required");
            requirePopupSource(permit);permit.beginPopup(SystemClock.elapsedRealtime(),dialog,gesture);
            // This view only receives the platform's requested URL. Every resource
            // load is blocked; no webpage, script, new visible window or app opens in it.
            WebView child=new WebView(this);popupInterceptor=child;
            JSONObject profile=isolation.assignAuxiliaryProfile(child); // First interaction with the new WebView.
            WebSettings config=child.getSettings();
            config.setBlockNetworkLoads(true);config.setBlockNetworkImage(true);config.setJavaScriptEnabled(false);
            config.setDomStorageEnabled(false);config.setAllowFileAccess(false);config.setAllowContentAccess(false);
            config.setAllowFileAccessFromFileURLs(false);config.setAllowUniversalAccessFromFileURLs(false);
            config.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);config.setGeolocationEnabled(false);
            config.setJavaScriptCanOpenWindowsAutomatically(false);config.setSupportMultipleWindows(true);
            config.setMediaPlaybackRequiresUserGesture(true);config.setSaveFormData(false);
            child.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
            child.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS);
            child.setVisibility(View.GONE);
            child.setWebChromeClient(new WebChromeClient(){
                @Override public boolean onCreateWindow(WebView view,boolean d,boolean g,android.os.Message message){return false;}
                @Override public void onPermissionRequest(PermissionRequest request){request.deny();}
                @Override public void onGeolocationPermissionsShowPrompt(String origin,GeolocationPermissions.Callback callback){callback.invoke(origin,false,false);}
                @Override public boolean onJsAlert(WebView view,String url,String message,JsResult value){value.cancel();return true;}
                @Override public boolean onJsConfirm(WebView view,String url,String message,JsResult value){value.cancel();return true;}
                @Override public boolean onJsPrompt(WebView view,String url,String message,String initial,JsPromptResult value){value.cancel();return true;}
                @Override public boolean onShowFileChooser(WebView view,ValueCallback<android.net.Uri[]> callback,FileChooserParams params){callback.onReceiveValue(null);return true;}
            });
            child.setWebViewClient(new android.webkit.WebViewClient(){
                @Override public boolean shouldOverrideUrlLoading(WebView view,android.webkit.WebResourceRequest request){
                    if(view!=popupInterceptor||!request.isForMainFrame())return true;
                    interceptObservedPopupUrl(permit,view,request.getUrl().toString(),request.getMethod(),request.isForMainFrame());return true;
                }
                @Override public boolean shouldOverrideUrlLoading(WebView view,String url){return true;} // No inferred method.
                @Override public android.webkit.WebResourceResponse shouldInterceptRequest(WebView view,android.webkit.WebResourceRequest request){
                    return new android.webkit.WebResourceResponse("text/plain","UTF-8",new java.io.ByteArrayInputStream(new byte[0]));
                }
                @Override public void onReceivedSslError(WebView view,android.webkit.SslErrorHandler handler,android.net.http.SslError error){handler.cancel();}
            });
            child.setDownloadListener((url,userAgent,disposition,mime,length)->{});
            content.addView(child,new LinearLayout.LayoutParams(0,0));
            profile.put("network_loads_blocked",config.getBlockNetworkLoads())
                    .put("javascript_enabled",config.getJavaScriptEnabled()).put("visible_in_layout",false);
            Jsons.need(config.getBlockNetworkLoads()&&!config.getJavaScriptEnabled(),"URL interception networking/script gate differs");
            permit.auxiliaryCreated(profile);
            requirePopupSource(permit);
            ((WebView.WebViewTransport)result.obj).setWebView(child);
            handedOff=true;result.sendToTarget();return true;
        }catch(Exception failure){
            invalidateObservedLink("popup_rejected:"+failure.getClass().getSimpleName());showProblem("商品链接导航未完成："+failure.getMessage());
            // Never return false after a possibly submitted platform transport message.
            return handedOff;
        }
    }
    private void interceptObservedPopupUrl(ObservedLinkPermit permit,WebView child,String actualUrl,String method,boolean mainFrame){
        try{
            Jsons.need(child==popupInterceptor,"stale popup URL callback");requirePopupSource(permit);
            permit.acceptUrl(SystemClock.elapsedRealtime(),actualUrl,method,mainFrame);
            destroyPopupInterceptor();
            Jsons.need(popupInterceptor==null&&isolation.liveAuxiliaryViews()==0&&auxiliaryDestroySucceeded,
                    "URL interception view could not be retired");
            requirePopupSource(permit);permit.beginMainLoad(SystemClock.elapsedRealtime());
            // Actual platform-requested URL has already matched the fresh immutable
            // anchor. No controller/model URL is used here.
            expectedControlledMainUrl=actualUrl;armedLink=null;armedCaptureSource=null;
            web.loadUrl(actualUrl);permit.mainLoadReturned(SystemClock.elapsedRealtime());
        }catch(Exception failure){
            expectedControlledMainUrl=null;invalidateObservedLink("popup_url_rejected:"+failure.getClass().getSimpleName());
            try{permit.cancel("popup_url_rejected",SystemClock.elapsedRealtime());}catch(Exception ignored){}
            showProblem("商品链接导航未完成："+failure.getMessage());
        }
    }
    private void destroyPopupInterceptor(){
        WebView child=popupInterceptor;if(child==null)return;
        try{child.stopLoading();}catch(Exception failure){auxiliaryStopSucceeded=false;destructionFailures.put("aux_stop:"+failure.getClass().getName());}
        try{if(child.getParent() instanceof ViewGroup)((ViewGroup)child.getParent()).removeView(child);}
        catch(Exception failure){destructionFailures.put("aux_remove:"+failure.getClass().getName());}
        try{
            child.destroy();popupInterceptor=null;
            if(isolation!=null&&isolation.liveAuxiliaryViews()>0)isolation.auxiliaryDestroyed();
            if(lastObservedLink!=null)lastObservedLink.auxiliaryDestroyed(SystemClock.elapsedRealtime());
        }catch(Exception failure){auxiliaryDestroySucceeded=false;destructionFailures.put("aux_destroy:"+failure.getClass().getName());}
    }
    int actualDisplayId(){return getDisplay()==null?-1:getDisplay().getDisplayId();}
    int actualWindowId(){
        if(capture!=null&&!destroyed)return capture.windowId();
        if(destroyed)return savedWindow;
        if(content==null)return -1;AccessibilityNodeInfo node=content.createAccessibilityNodeInfo();
        if(node==null)return -1;try{return node.getWindowId();}finally{node.recycle();}
    }
    String webviewInstance(){return plannedInstance;}
    long navigationEpoch(){return capture==null?savedEpoch:capture.navigationEpoch();}
    boolean diagnosticActive(){return diagnostic&&loaded&&!destroyed;}
    JSONObject pagePolicy()throws Exception{Jsons.need(sitePolicy!=null,"no selected page policy");return sitePolicy.evidence();}
    String pagePolicyId(){return sitePolicy==null?null:sitePolicy.id;}
    String pagePolicyHash(){return sitePolicy==null?null:sitePolicy.sha;}
    String pageKind(){return sitePolicy==null?null:sitePolicy.kind;}
    String pageInitialUrl(){return sitePolicy==null?null:sitePolicy.initialUrl;}
    boolean boundPage(){return bound;}
    JSONObject destroyForLease()throws Exception{
        if(destroyedFacts!=null)return currentCleanup();
        savedWindow=actualWindowId();
        invalidateObservedLink("page_retired");expectedControlledMainUrl=null;
        boolean capturesRetired=false,stopped=false,killed=false;
        if(capture!=null){
            savedInstance=capture.instance();savedEpoch=capture.navigationEpoch();
            try{capture.retire();capturesRetired=true;}catch(Exception failure){destructionFailures.put("capture_retire:"+failure.getClass().getName());}
        }
        if(web!=null){
            web.removeCallbacks(diagnosticAfterTouch);
            try{web.stopLoading();stopped=true;}catch(Exception failure){destructionFailures.put("stop_loading:"+failure.getClass().getName());}
            try{if(web.getParent() instanceof ViewGroup)((ViewGroup)web.getParent()).removeView(web);}
            catch(Exception failure){destructionFailures.put("remove_view:"+failure.getClass().getName());}
            try{web.destroy();killed=true;web=null;}catch(Exception failure){destructionFailures.put("destroy_view:"+failure.getClass().getName());}
        }
        destroyed=true;diagnostic=false;preparing=false;
        if(web==null)capture=null;
        destroyedFacts=new JSONObject().put("captures_retired",capturesRetired).put("stop_loading_called",stopped&&auxiliaryStopSucceeded)
                .put("webview_destroyed",killed&&auxiliaryDestroySucceeded&&popupInterceptor==null)
                .put("active_view_absent",web==null&&popupInterceptor==null&&(isolation==null||isolation.liveAuxiliaryViews()==0)).put("storage_clear_completed",false);
        if(bound&&!isFinishing())finishAndRemoveTask(); // This Activity's own isolated helper task only.
        return currentCleanup();
    }
    JSONObject currentCleanup()throws Exception{
        if(destroyedFacts==null)return null;
        JSONObject out=new JSONObject(destroyedFacts.toString());
        out.put("storage_clear_completed",isolation!=null&&isolation.cleanupCompleted());return out;
    }
    void clearStorageAfterRetirement(long deadline,ProfileIsolation.Result reply)throws Exception{
        clearStorageAfterRetirement(deadline,null,reply);
    }
    void clearStorageAfterRetirement(long deadline,String freshCloseNonce,ProfileIsolation.Result reply)throws Exception{
        Jsons.need(destroyed&&web==null&&popupInterceptor==null&&(isolation==null||isolation.liveAuxiliaryViews()==0),"storage retirement requires every actual owned view absent");
        if(isolation==null){reply.complete(false,new JSONObject(),"no recorded profile clear proof");return;}
        isolation.clearAfterRetirement(deadline,freshCloseNonce,reply);
    }
    boolean neverStartedResources(){
        return destroyed&&!resourceCreationDispatched&&!profileAssignmentDispatched&&loadDispatchCount==0
                &&captureDispatchCount==0&&web==null&&popupInterceptor==null&&capture==null&&isolation==null&&!preparing;
    }
    JSONObject unstartedResourceFence()throws Exception{
        Jsons.need(neverStartedResources()&&bound&&savedWindow>=0&&ownedDisplayId>0,"owned resources were started or placeholder identity is unknown");
        return new JSONObject().put("schema",WebEvidenceProtocol.UNSTARTED_FENCE_SCHEMA)
                .put("observed_elapsed_ms",SystemClock.elapsedRealtime()).put("activity_created_elapsed_ms",created)
                .put("planned_webview_instance",plannedInstance).put("placeholder_window_id",savedWindow)
                .put("owned_display_id",ownedDisplayId).put("bound_page",bound).put("retired",destroyed)
                .put("resource_creation_dispatched",resourceCreationDispatched).put("profile_assignment_dispatched",profileAssignmentDispatched)
                .put("load_dispatch_count",loadDispatchCount).put("capture_dispatch_count",captureDispatchCount)
                .put("webview_present",web!=null).put("capture_present",capture!=null).put("profile_present",isolation!=null)
                .put("preparing",preparing).put("live_webview_count",liveWebViewCount()).put("pending_capture_count",pendingCaptureCount());
    }
    Object storageEvidence()throws Exception{return isolation==null?JSONObject.NULL:isolation.evidence();}
    JSONObject destructionEvidence()throws Exception{return new JSONObject().put("errors",new org.json.JSONArray(destructionFailures.toString()));}
    int liveWebViewCount(){return (web==null?0:1)+(popupInterceptor==null?0:1);}
    int pendingCaptureCount(){return capture==null?0:capture.pendingCaptureCount();}
    void showRecord(String name,String sha){if(status!=null&&!destroyed)status.setText("只读原件："+name+"\nSHA-256 "+sha+"\n未判定查询成功。");}
    void showProblem(String text){if(status!=null&&!destroyed)status.setText(text==null?"页面证据尚不可用":text);}
    private void showFatal(String text){TextView error=new TextView(this);error.setPadding(24,48,24,24);error.setText("网页 helper 未启动："+text);setContentView(error);}
    @Override public void onNewIntent(Intent intent){super.onNewIntent(intent);showProblem("新的页面参数未接受；当前任务不自动重开。");}
    @Override public void onBackPressed(){if(web!=null&&!destroyed&&web.canGoBack())web.goBack();else super.onBackPressed();}
    @Override protected void onDestroy(){
        if(!destroyed){try{destroyForLease();}catch(Exception ignored){}}
        if(session!=null)session.pageDestroyed(this);
        super.onDestroy();
    }
}
