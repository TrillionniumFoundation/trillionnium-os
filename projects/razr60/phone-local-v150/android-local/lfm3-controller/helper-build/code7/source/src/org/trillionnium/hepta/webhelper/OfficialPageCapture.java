package org.trillionnium.hepta.webhelper;

import android.graphics.Bitmap;
import android.net.http.SslError;
import android.os.Looper;
import android.os.Process;
import android.os.SystemClock;
import android.view.Display;
import android.view.accessibility.AccessibilityNodeInfo;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONTokener;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;

/**
 * Owned-WebView capture core. EvidenceSession supplies authenticated LeaseGuard
 * or a distinct manual display-0 diagnostic binding. No page-facing native bridge.
 *
 * This class observes an OWNED WebView. It cannot inspect com.zui.browser's
 * internal WebView. It never navigates, clicks, types, submits, or proves a fare.
 */
public final class OfficialPageCapture {
    private static final String ASSET = "readonly_dom.js";
    private static final String ASSET_SHA = "05bb7c1e4e1929b961c42af1e5c0e01918bf6ff64f153132ca11c7d85873e705";
    private static final int MAX_DOM_BYTES = 1024 * 1024;
    private static final long CAPTURE_MS = 3000;
    public interface LeaseGuard {
        /** Re-read actual authenticated lease/task/owner/display; throw on changes. */
        void requireActive() throws Exception;
        int expectedDisplayId();
        /** Immutable binding from the signature IPC session, never a page message. */
        JSONObject binding() throws Exception;
    }
    public interface Callback {
        void captured(JSONObject actualEvidence);
        void failed(String reason);
        /** Manual diagnostics only; the authenticated IPC callback leaves this unused. */
        default void unstable(DomInstabilityEvidence.Pair firstMismatch)throws Exception { }
    }
    public interface Listener { void nativeStateChanged(String event); }
    interface NavigationGate {
        boolean allowMainFrameRequest(String url,String method);
        boolean allowMainFrameStarted(String url);
        boolean allowHistoryOrCommitUrl(String url);
    }
    private NavigationGate navigationGate;
    void setNavigationGate(NavigationGate gate){requireUi();navigationGate=gate;}
    void requireArmSource(JSONObject source)throws Exception{
        requireCurrent();
        if(inFlight!=null||SystemClock.elapsedRealtime()-source.getLong("ended_elapsed_ms")>org.trillionnium.hepta.webprotocol.WebObservedNavigation.SOURCE_MAX_AGE_MS
                ||SystemClock.elapsedRealtime()<source.getLong("ended_elapsed_ms")||!instance.equals(source.getString("webview_instance"))||epoch!=source.getLong("navigation_epoch")
                ||windowId()!=source.getInt("actual_window_id")||!view.getUrl().equals(source.getString("current_native_url"))
                ||!org.trillionnium.hepta.webprotocol.WebEvidenceBinding.canonical(lease.binding()).equals(
                        org.trillionnium.hepta.webprotocol.WebEvidenceBinding.canonical(source.getJSONObject("binding"))))
            throw new IllegalStateException("ARM source identity changed");
        JSONArray samples=source.getJSONObject("capture_geometry").getJSONArray("samples");
        if(samples.length()!=4||!sameGeometry(samples.getJSONObject(3).getJSONObject("native"),nativeGeometry()))
            throw new IllegalStateException("ARM source native geometry changed");
    }
    private final WebView view;
    private final LeaseGuard lease;
    private final PageSitePolicy sitePolicy;
    private final String script;
    private final String instance;
    private long epoch;
    private String committedUrl;
    private long commitElapsed;
    private String invalidReason = "no_main_frame_commit";
    private Ticket inFlight;
    private boolean retired;
    private Listener listener;
    private long scaleChangeSequence,scaleChangedElapsed;
    private Float lastScaleOld,lastScaleNew;

    OfficialPageCapture(WebView ownedView,LeaseGuard authenticatedLease,String recordedInstance,PageSitePolicy selectedPolicy)throws Exception{
        if (ownedView == null || authenticatedLease == null || selectedPolicy==null) throw new IllegalArgumentException("owned view/lease/single-site policy required");
        if(!org.trillionnium.hepta.webprotocol.WebEvidenceProtocol.uuid(recordedInstance))throw new IllegalArgumentException("recorded WebView instance invalid");
        requireUi(); view = ownedView; lease = authenticatedLease;instance=recordedInstance;sitePolicy=selectedPolicy;
        script = readFixedAsset();
        // The owning Activity must retain this one client. No page-facing native
        // interface or model-supplied JavaScript is registered.
        view.setWebViewClient(new WebViewClient() {
            @Override public void onPageStarted(WebView v, String url, Bitmap favicon) {
                epoch++; committedUrl = null; commitElapsed = 0;
                invalidReason = sitePolicy.origin(url) == null ? "unapproved_main_frame_navigation" : "main_frame_loading";
                if(navigationGate!=null&&!navigationGate.allowMainFrameStarted(url)){
                    invalidReason="main_frame_navigation_without_observed_link_permit";v.stopLoading();
                }
                abortPending("navigation_changed_during_capture");
                changed("page_started");
            }
            @Override public void onPageCommitVisible(WebView v, String url) {
                if (v != view || retired || sitePolicy.origin(url) == null || !url.equals(view.getUrl())
                        ||navigationGate!=null&&!navigationGate.allowHistoryOrCommitUrl(url)) {
                    invalidReason = "main_frame_commit_url_mismatch"; return;
                }
                committedUrl = url; commitElapsed = SystemClock.elapsedRealtime(); invalidReason = null;
                changed("main_frame_committed");
            }
            @Override public void doUpdateVisitedHistory(WebView v, String url, boolean reload) {
                // Includes observed history changes; current getUrl and fixed DOM
                // href are independently rechecked even when a callback is absent.
                epoch++; abortPending("observed_history_changed_during_capture");
                if (navigationGate!=null&&!navigationGate.allowHistoryOrCommitUrl(url)) {
                    committedUrl=null;invalidReason="history_without_observed_link_permit";
                }
                if (committedUrl != null && !sitePolicy.sameOrigin(committedUrl, url)) {
                    committedUrl = null; invalidReason = "history_left_committed_origin";
                }
                changed("history_changed");
            }
            @Override public void onPageFinished(WebView v,String url){changed("page_finished");}
            @Override public void onScaleChanged(WebView v,float oldScale,float newScale){
                requireUi();
                if(v!=view||retired)return;
                scaleChangeSequence++;scaleChangedElapsed=SystemClock.elapsedRealtime();
                lastScaleOld=oldScale;lastScaleNew=newScale;
                abortPending("native_scale_changed_during_capture");
            }
            @Override public void onReceivedError(WebView v, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame()) invalidate("main_frame_load_error");
            }
            @Override public void onReceivedSslError(WebView v, SslErrorHandler handler, SslError error) {
                handler.cancel(); invalidate("ssl_error_cancelled");
            }
            @Override public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest request) {
                if (request.isForMainFrame() && (sitePolicy.origin(request.getUrl().toString()) == null
                        ||navigationGate!=null&&!navigationGate.allowMainFrameRequest(request.getUrl().toString(),request.getMethod()))) {
                    invalidate("unapproved_main_frame_navigation"); return true;
                }
                return false;
            }
        });
    }

    private static final class ReadAttempt {
        final CaptureReadBudget.Attempt token;
        final JSONArray geometrySamples=new JSONArray();
        String firstDom;
        ReadAttempt(CaptureReadBudget.Attempt token){this.token=token;}
    }
    private static final class Ticket {
        final String challenge,nativeUrl,bindingJson;
        final long epoch,started,deadline;
        final int windowId;
        final int[] nativeBounds;
        final JSONObject initialGeometry;
        final Callback callback;
        final CaptureReadBudget budget;
        ReadAttempt attempt;
        boolean mismatchReported;
        Ticket(String challenge,String url,String binding,long epoch,long now,long callerDeadline,int windowId,int[] nativeBounds,JSONObject geometry,Callback callback){
            this.challenge=challenge;nativeUrl=url;bindingJson=binding;this.epoch=epoch;
            budget=new CaptureReadBudget(now,callerDeadline);started=budget.started;deadline=budget.deadline;
            this.windowId=windowId;this.nativeBounds=nativeBounds;initialGeometry=geometry;this.callback=callback;
        }
    }

    public void capture(String actualCallerChallenge,long callerDeadline, Callback callback) {
        requireUi();
        try {
            if (callback == null || actualCallerChallenge == null || !actualCallerChallenge.matches("[0-9a-f]{64}"))
                throw new IllegalArgumentException("caller challenge/callback required");
            if (inFlight != null) throw new IllegalStateException("capture already in progress");
            requireCurrent();
            if(callerDeadline<=SystemClock.elapsedRealtime())throw new IllegalArgumentException("capture deadline expired");
            Ticket ticket = new Ticket(actualCallerChallenge, view.getUrl(), lease.binding().toString(),
                    epoch, SystemClock.elapsedRealtime(),callerDeadline,windowId(),nativeBounds(),nativeGeometry(),callback);
            inFlight=ticket;
            view.postDelayed(() -> { if (inFlight==ticket) abortPending("capture_deadline_exceeded"); }, Math.max(1,ticket.deadline-SystemClock.elapsedRealtime()));
            beginAttempt(ticket);
        } catch (Exception failure) {
            if (callback != null) callback.failed(failure.getMessage());
        }
    }

    private boolean ownsAttempt(Ticket ticket,ReadAttempt attempt){
        return inFlight==ticket&&ticket.attempt==attempt&&ticket.budget.owns(attempt.token);
    }
    private void beginAttempt(Ticket ticket){
        if(inFlight!=ticket)return;
        try{
            requireTicketContext(ticket);
            ReadAttempt attempt=new ReadAttempt(ticket.budget.begin(SystemClock.elapsedRealtime()));
            ticket.attempt=attempt;read(ticket,attempt,false);
        }catch(Exception failure){if(inFlight==ticket)abortPending(failure.getMessage());}
    }
    private void read(final Ticket ticket,final ReadAttempt attempt,final boolean second) {
        if(!ownsAttempt(ticket,attempt))return;
        try {
            requireTicket(ticket,attempt);
            recordGeometry(ticket,attempt,second?"before_js2":"before_js1");
            view.evaluateJavascript(script, encoded -> {
                if(!ownsAttempt(ticket,attempt))return;
                try {
                    requireTicket(ticket,attempt);
                    recordGeometry(ticket,attempt,second?"after_js2":"after_js1");
                    Object decoded = new JSONTokener(encoded).nextValue();
                    if (!(decoded instanceof String)) throw new IllegalStateException("DOM observer did not return a JSON string");
                    String raw=(String)decoded;
                    if (raw.getBytes(StandardCharsets.UTF_8).length>MAX_DOM_BYTES) throw new IllegalStateException("DOM byte budget exceeded");
                    JSONObject dom=new JSONObject(raw);
                    if (!org.trillionnium.hepta.webprotocol.WebDomStability.DOM_SCHEMA.equals(dom.getString("schema"))
                            || !ticket.nativeUrl.equals(dom.getString("href"))
                            || !sitePolicy.origin(ticket.nativeUrl).equals(dom.getString("origin"))
                            || !"complete".equals(dom.getString("ready_state")))
                        throw new IllegalStateException("native URL/current DOM binding incomplete");
                    if (!second) {
                        attempt.firstDom=raw;
                        view.postVisualStateCallback(attempt.token.visualRequestId, new WebView.VisualStateCallback() {
                            @Override public void onComplete(long actualId) {
                                if(!ownsAttempt(ticket,attempt))return;
                                if(actualId!=attempt.token.visualRequestId){abortPending("visual callback id differs");return;}
                                read(ticket,attempt,true);
                            }
                        });
                        return;
                    }
                    requireTicket(ticket,attempt);
                    if(attempt.geometrySamples.length()!=4)throw new IllegalStateException("four native geometry samples required");
                    org.trillionnium.hepta.webprotocol.WebDomStability.Result stability;
                    try{
                        stability=org.trillionnium.hepta.webprotocol.WebDomStability.evaluate(attempt.firstDom,raw,sitePolicy.id);
                    }catch(Exception different){
                        if(!raw.equals(attempt.firstDom)){domMismatch(ticket,attempt,raw);return;}
                        throw different;
                    }
                    JSONObject stabilityProof=stability.evidence();
                    String stabilitySha=org.trillionnium.hepta.webprotocol.WebDomCanonical.sha256(stabilityProof);
                    JSONObject result=new JSONObject().put("schema","hepta.owned-webview-origin-dom.v2")
                            .put("challenge",ticket.challenge).put("binding",new JSONObject(ticket.bindingJson))
                            .put("helper_package",view.getContext().getPackageName())
                            .put("helper_uid",Process.myUid()).put("helper_pid",Process.myPid())
                            .put("display_id",view.getDisplay().getDisplayId()).put("webview_instance",instance)
                            .put("actual_window_id",ticket.windowId)
                            .put("webview_bounds_screen_pixels",new JSONArray(ticket.nativeBounds))
                            .put("capture_geometry",new JSONObject().put("schema","hepta.webview-geometry-bracket.v2")
                                    .put("samples",attempt.geometrySamples).put("native_samples_equal",true)
                                    .put("dom_equal_across_visual_callback",stability.rawEqual).put("ui_thread_bracket",true)
                                    .put("dom_comparison_scope",stability.comparisonScope).put("dom_stability_sha256",stabilitySha)
                                    .put("get_scale_is_deprecated_racy_observation",true)
                                    .put("css_to_screen_mapping_verified",false))
                            .put("navigation_epoch",ticket.epoch).put("committed_main_frame_url",committedUrl)
                            .put("commit_elapsed_ms",commitElapsed).put("current_native_url",ticket.nativeUrl)
                            .put("native_url_source","android.webkit.WebView.getUrl")
                            .put("commit_source","android.webkit.WebViewClient.onPageCommitVisible")
                            .put("visual_request_id",attempt.token.visualRequestId).put("dom_raw_utf8",raw)
                            .put("before_dom_raw_utf8",attempt.firstDom).put("before_dom_sha256",stability.beforeRawSha256)
                            .put("dom_stability",stabilityProof).put("dom_stability_sha256",stabilitySha)
                            .put("raw_dom_equal",stability.rawEqual).put("comparison_scope",stability.comparisonScope)
                            .put("dom_sha256",sha(raw.getBytes(StandardCharsets.UTF_8)))
                            .put("observer_script_sha256",ASSET_SHA).put("started_elapsed_ms",ticket.started)
                            .put("ended_elapsed_ms",SystemClock.elapsedRealtime())
                            .put("business_verified",false).put("pixel_equality_claimed",false)
                            .put("all_visible_semantics_verified",false).put("truncated",dom.getBoolean("truncated"));
                    requireTicket(ticket,attempt);
                    ticket.budget.complete(attempt.token,SystemClock.elapsedRealtime());
                    ticket.attempt=null;inFlight=null;
                    ticket.callback.captured(result);
                } catch (Exception failure) { if(ownsAttempt(ticket,attempt))abortPending(failure.getMessage()); }
            });
        } catch (Exception failure) { if(ownsAttempt(ticket,attempt))abortPending(failure.getMessage()); }
    }

    private void domMismatch(Ticket ticket,ReadAttempt attempt,String after)throws Exception{
        requireTicket(ticket,attempt);
        if(!ticket.mismatchReported){
            ticket.mismatchReported=true;
            JSONObject binding=new JSONObject(ticket.bindingJson);
            if("hepta.web-helper.unbound-diagnostic.v2".equals(binding.optString("schema"))){
                JSONObject context=new JSONObject().put("binding",binding).put("challenge",ticket.challenge)
                        .put("helper_package",view.getContext().getPackageName()).put("helper_uid",Process.myUid()).put("helper_pid",Process.myPid())
                        .put("display_id",view.getDisplay().getDisplayId()).put("actual_window_id",ticket.windowId)
                        .put("webview_instance",instance).put("navigation_epoch",ticket.epoch)
                        .put("current_native_url",ticket.nativeUrl).put("committed_main_frame_url",committedUrl)
                        .put("started_elapsed_ms",ticket.started).put("deadline_elapsed_ms",ticket.deadline)
                        .put("mismatch_elapsed_ms",SystemClock.elapsedRealtime()).put("attempt_index",attempt.token.index)
                        .put("visual_request_id",attempt.token.visualRequestId).put("geometry_samples",attempt.geometrySamples);
                ticket.callback.unstable(new DomInstabilityEvidence.Pair(context,attempt.firstDom,after));
            }
        }
        requireTicket(ticket,attempt);
        boolean again=ticket.budget.retryAfterDomMismatch(attempt.token,SystemClock.elapsedRealtime());
        ticket.attempt=null;
        if(!again){abortPending("DOM changed across visual callback");return;}
        try{
            long delay=ticket.budget.nextDelay(SystemClock.elapsedRealtime());
            if(!view.postDelayed(()->beginAttempt(ticket),delay))abortPending("capture retry could not be scheduled");
        }catch(Exception failure){if(inFlight==ticket&&ticket.attempt==null)abortPending(failure.getMessage());}
    }

    private void requireCurrent() throws Exception {
        requireUi(); lease.requireActive();
        Display actual=view.getDisplay();
        if (retired || invalidReason!=null || committedUrl==null || commitElapsed<=0
                || actual==null || actual.getDisplayId()!=lease.expectedDisplayId()
                || !view.isAttachedToWindow() || !view.isShown()
                || windowId()<0
                || !sitePolicy.sameOrigin(committedUrl,view.getUrl()))
            throw new IllegalStateException(invalidReason==null?"owned page/display unavailable":invalidReason);
    }
    private void requireTicket(Ticket ticket,ReadAttempt attempt)throws Exception{
        if(!ownsAttempt(ticket,attempt))throw new IllegalStateException("capture attempt is stale");
        ticket.budget.requireActive(attempt.token,SystemClock.elapsedRealtime());
        requireTicketContext(ticket);
    }
    private void requireTicketContext(Ticket ticket) throws Exception {
        requireCurrent();
        if (inFlight!=ticket || epoch!=ticket.epoch || SystemClock.elapsedRealtime()>=ticket.deadline
                || windowId()!=ticket.windowId || !java.util.Arrays.equals(nativeBounds(),ticket.nativeBounds)
                || !sameGeometry(ticket.initialGeometry,nativeGeometry())
                || !ticket.nativeUrl.equals(view.getUrl()) || !ticket.bindingJson.equals(lease.binding().toString()))
            throw new IllegalStateException("capture task/lease/navigation changed");
    }
    private void invalidate(String reason) {
        epoch++; committedUrl=null; invalidReason=reason; abortPending(reason);
        changed("invalidated");
    }
    private void abortPending(String reason) {
        Ticket old=inFlight; inFlight=null;
        if(old!=null){old.budget.cancel();old.attempt=null;old.callback.failed(reason==null?"capture failed":reason);}
    }
    public void retire() {
        requireUi(); retired=true; invalidate("helper_session_retired");
    }
    public int pendingCaptureCount(){requireUi();return inFlight==null?0:1;}
    public void setListener(Listener listener){requireUi();this.listener=listener;}
    public String instance(){requireUi();return instance;}
    public long navigationEpoch(){requireUi();return epoch;}
    public int windowId(){
        requireUi();AccessibilityNodeInfo node=view.createAccessibilityNodeInfo();
        if(node==null)return -1;try{return node.getWindowId();}finally{node.recycle();}
    }
    @SuppressWarnings("deprecation")
    private JSONObject nativeGeometry()throws Exception{
        requireUi();
        float scale=view.getScale();
        if(!Float.isFinite(scale)||scale<=0)throw new IllegalStateException("native scale unavailable");
        Display display=view.getDisplay();
        if(display==null)throw new IllegalStateException("native geometry display absent");
        android.graphics.Rect visible=new android.graphics.Rect();
        boolean hasVisible=view.getGlobalVisibleRect(visible);
        return new JSONObject().put("sampled_elapsed_ms",SystemClock.elapsedRealtime())
                .put("display_id",display.getDisplayId()).put("actual_window_id",windowId())
                .put("bounds_screen_pixels",new JSONArray(nativeBounds()))
                .put("global_visible_rect_pixels",hasVisible?new JSONArray(new int[]{visible.left,visible.top,visible.right,visible.bottom}):JSONObject.NULL)
                .put("global_visible_rect_source","View.getGlobalVisibleRect; root-view coordinates")
                .put("scroll_pixels",new JSONArray(new int[]{view.getScrollX(),view.getScrollY()}))
                .put("padding_pixels",new JSONArray(new int[]{view.getPaddingLeft(),view.getPaddingTop(),view.getPaddingRight(),view.getPaddingBottom()}))
                .put("view_transform",new JSONArray(new double[]{view.getScaleX(),view.getScaleY(),view.getRotation(),view.getTranslationX(),view.getTranslationY()}))
                .put("webview_get_scale",(double)scale)
                .put("scale_change_sequence",scaleChangeSequence).put("scale_changed_elapsed_ms",scaleChangedElapsed)
                .put("scale_callback_old",lastScaleOld==null?JSONObject.NULL:(double)lastScaleOld)
                .put("scale_callback_new",lastScaleNew==null?JSONObject.NULL:(double)lastScaleNew)
                .put("use_wide_viewport",view.getSettings().getUseWideViewPort())
                .put("load_with_overview_mode",view.getSettings().getLoadWithOverviewMode());
    }
    private static boolean sameGeometry(JSONObject a,JSONObject b)throws Exception{
        String[] integers={"display_id","actual_window_id","scale_change_sequence","scale_changed_elapsed_ms"};
        for(String key:integers)if(a.getLong(key)!=b.getLong(key))return false;
        String[] values={"bounds_screen_pixels","global_visible_rect_pixels","global_visible_rect_source",
                "scroll_pixels","padding_pixels","view_transform","webview_get_scale","scale_callback_old",
                "scale_callback_new","use_wide_viewport","load_with_overview_mode"};
        for(String key:values)if(!a.get(key).toString().equals(b.get(key).toString()))return false;
        return true;
    }
    private void recordGeometry(Ticket ticket,ReadAttempt attempt,String phase)throws Exception{
        JSONObject current=nativeGeometry();
        if(!sameGeometry(ticket.initialGeometry,current))throw new IllegalStateException("native geometry changed during capture");
        attempt.geometrySamples.put(new JSONObject().put("phase",phase).put("native",current));
    }
    private int[] nativeBounds(){int[] xy=new int[2];view.getLocationOnScreen(xy);return new int[]{xy[0],xy[1],xy[0]+view.getWidth(),xy[1]+view.getHeight()};}
    private void changed(String event){if(listener!=null)listener.nativeStateChanged(event);}
    private String readFixedAsset() throws Exception {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        try(InputStream stream=view.getContext().getAssets().open(ASSET)) {
            byte[] buffer=new byte[4096]; int n;
            while((n=stream.read(buffer))!=-1) {
                if(bytes.size()+n>32768) throw new IllegalStateException("fixed observer asset too large");
                bytes.write(buffer,0,n);
            }
        }
        byte[] raw=bytes.toByteArray();
        if(!ASSET_SHA.equals(sha(raw))) throw new IllegalStateException("fixed DOM observer source differs");
        return new String(raw,StandardCharsets.UTF_8);
    }
    private static String sha(byte[] raw) throws Exception {
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(raw);
        StringBuilder out=new StringBuilder(64);
        for(byte b:digest) out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
        return out.toString();
    }
    private static void requireUi() {
        if(Looper.myLooper()!=Looper.getMainLooper()) throw new IllegalStateException("WebView UI thread required");
    }
}
