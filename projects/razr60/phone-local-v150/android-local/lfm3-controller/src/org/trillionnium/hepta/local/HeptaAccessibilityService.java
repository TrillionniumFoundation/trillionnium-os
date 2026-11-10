package org.trillionnium.hepta.local;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.AccessibilityServiceInfo;
import android.accessibilityservice.GestureDescription;
import android.app.KeyguardManager;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.graphics.Bitmap;
import android.graphics.Path;
import android.graphics.Rect;
import android.hardware.HardwareBuffer;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.Display;
import android.view.WindowManager;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Standard Android accessibility service. All effects pass an observed-target gate. */
public final class HeptaAccessibilityService extends AccessibilityService {
    public interface ObservationCallback { void onObservation(PhoneObservation value); void onError(String error); }
    public interface Cancellation { boolean isCancelled(); }
    public interface ActionCallback { void onResult(ActionOutcome result); }
    public static final class ActionOutcome {
        public final boolean accepted, dispatched, stale;
        public final String detail;
        public final AppCatalogueRanker.Page appCatalogue;
        ActionOutcome(boolean accepted,boolean dispatched,boolean stale,String detail) {
            this(accepted,dispatched,stale,detail,null);
        }
        ActionOutcome(boolean accepted,boolean dispatched,boolean stale,String detail,AppCatalogueRanker.Page appCatalogue) {
            this.accepted=accepted;this.dispatched=dispatched;this.stale=stale;this.detail=detail;
            this.appCatalogue=appCatalogue;
        }
    }
    private static volatile HeptaAccessibilityService live;
    public static HeptaAccessibilityService connected() { return live; }
    private final Handler main=new Handler(Looper.getMainLooper());
    private String lease;
    private Runnable stopListener;
    private LocalTaskController ownedController;
    private long lastScreenshotAt;
    private boolean capturePending;
    private long captureSerial;
    private ObservationRequest activeObservation;
    private PhoneObservation current;
    private Graph currentGraph;
    private Bitmap currentBitmap;
    private static final long MAX_OBSERVATION_AGE_MS=90000;
    private static final int MAX_NODES=64, MAX_VISITED=320;
    private final Map<String,String> launchable=new java.util.concurrent.ConcurrentHashMap<String,String>();
    private AppCatalogueRanker appDiscovery;

    @Override protected void onServiceConnected() {
        AccessibilityServiceInfo info=getServiceInfo();
        info.eventTypes=AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED|AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED
                |AccessibilityEvent.TYPE_WINDOWS_CHANGED
                |AccessibilityEvent.TYPE_VIEW_SCROLLED|AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED|AccessibilityEvent.TYPE_VIEW_FOCUSED;
        info.feedbackType=AccessibilityServiceInfo.FEEDBACK_GENERIC;
        info.flags|=AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS|AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS;
        info.notificationTimeout=80;setServiceInfo(info);refreshApps();live=this;
    }
    @Override public void onAccessibilityEvent(AccessibilityEvent event) { /* Read again at every decision and effect. */ }
    @Override public void onInterrupt() { requestStop(); }
    @Override public void onDestroy() {
        LocalTaskController controller; synchronized(this){controller=ownedController;}
        if(controller!=null)controller.close();
        requestStop();
        if(activeObservation!=null)failObservation(activeObservation,"无障碍服务已断开");
        if(live==this)live=null;clearSnapshot();super.onDestroy();
    }
    /** Service-owned session survives Activity recreation. The controller stays injectable. */
    public synchronized LocalTaskController taskController(LocalInference inference){
        if(ownedController==null)ownedController=new LocalTaskController(this,inference);
        return ownedController;
    }
    public synchronized LocalTaskController taskController(LocalModelEngine engine){
        return taskController(new EngineInferenceAdapter(engine));
    }
    /** Administrative retirement only; no action, inference, capture or old task is restarted. */
    synchronized boolean recoveryControllerIdle(LocalTaskController expected){
        if(Looper.myLooper()!=Looper.getMainLooper())throw new IllegalStateException("recovery service check must run on main thread");
        return live==this&&ownedController==expected&&(expected==null||!expected.isRunning())
                &&activeObservation==null&&!capturePending
                &&(lease==null||(expected!=null&&lease.equals(expected.currentTaskId())));
    }
    synchronized void retireControllerAfterAcknowledgement(LocalTaskController expected,
            RecoveryJournalTransaction.Proof proof){
        if(proof==null||!recoveryControllerIdle(expected))throw new IllegalStateException("controller is not idle for acknowledgement");
        if(expected!=null){expected.setListener(null);expected.close();}
        ownedController=null;lease=null;stopListener=null;appDiscovery=null;clearSnapshot();
    }
    private void requestStop() { Runnable value; synchronized(this){value=stopListener;} if(value!=null)value.run(); }
    public synchronized boolean acquireTask(String taskId,Runnable onStop) {
        if(lease!=null || live!=this)return false;lease=taskId;stopListener=onStop;appDiscovery=null;return true;
    }
    public synchronized void releaseTask(String taskId) { if(taskId.equals(lease)){lease=null;stopListener=null;appDiscovery=null;} }
    private synchronized boolean owns(String taskId) { return taskId.equals(lease) && live==this; }
    private boolean locked() { KeyguardManager value=(KeyguardManager)getSystemService(KEYGUARD_SERVICE);return value!=null&&value.isKeyguardLocked(); }
    private int rotation() { return ((WindowManager)getSystemService(WINDOW_SERVICE)).getDefaultDisplay().getRotation(); }

    private void refreshApps() {
        launchable.clear();Intent query=new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        for(ResolveInfo info:getPackageManager().queryIntentActivities(query,0)) {
            if(info.activityInfo!=null && info.activityInfo.exported && info.activityInfo.enabled)
                launchable.put(info.activityInfo.packageName,String.valueOf(info.loadLabel(getPackageManager())));
        }
    }
    /** Snapshot only installed launcher entries; model searches cannot add entries. */
    public AppCatalogueRanker.Page appCatalogue(String taskId,String instruction) {
        if(!owns(taskId))throw new IllegalStateException("任务已停止");
        refreshApps();AppCatalogueRanker snapshot=new AppCatalogueRanker(new HashMap<String,String>(launchable),instruction);
        synchronized(this){
            if(!owns(taskId))throw new IllegalStateException("任务已停止");
            appDiscovery=snapshot;
        }
        return snapshot.search("",0);
    }

    /** Each observation owns its samples/capture and the caller's original deadline. */
    private static final class ObservationRequest {
        final String taskId;final File directory;final ObservationCallback callback;final Cancellation cancel;
        final ObservationStabilityGate gate;
        Graph captured;long token;int intervalRetries;boolean finished,shotPending;
        ObservationRequest(String taskId,File directory,ObservationCallback callback,Cancellation cancel,long deadline){
            this.taskId=taskId;this.directory=directory;this.callback=callback;this.cancel=cancel;
            this.gate=new ObservationStabilityGate(SystemClock.elapsedRealtime(),deadline);
        }
    }
    public void observe(final String taskId,final File evidenceDirectory,final Cancellation cancel,
                        final long deadline,final ObservationCallback callback) {
        final ObservationRequest request=new ObservationRequest(taskId,evidenceDirectory,callback,cancel,deadline);
        main.post(new Runnable(){public void run(){
            if(activeObservation!=null){
                ObservationRequest old=activeObservation;
                if(!owns(old.taskId)||old.cancel.isCancelled())failObservation(old,"任务已经停止");
                else {callback.onError("已有屏幕观察尚未结束");return;}
            }
            if(capturePending){callback.onError("已有截图尚未结束");return;}
            activeObservation=request;sampleObservation(request);
        }});
    }
    private boolean observationActive(ObservationRequest request){
        if(request.finished||activeObservation!=request)return false;
        if(!request.gate.requestAlive(SystemClock.elapsedRealtime(),owns(request.taskId)&&!request.cancel.isCancelled())){
            failObservation(request,"任务停止或本次观察已超时");return false;
        }
        if(locked()){failObservation(request,"手机已锁定，请正常解锁后重新发起任务");return false;}
        return true;
    }
    private static ObservationStabilityGate.FrameKey frameKey(Graph graph){
        return new ObservationStabilityGate.FrameKey(graph.packageName,graph.windowId,graph.rotation,
                graph.bounds.left,graph.bounds.top,graph.bounds.right,graph.bounds.bottom,graph.digest,graph.truncated);
    }
    private static boolean sameObservedFrame(Graph a,Graph b){
        return a.sameWindowAndTree(b)&&a.truncated==b.truncated;
    }
    private void sampleObservation(final ObservationRequest request){
        if(!observationActive(request))return;
        Graph graph=null;
        try{
            try{graph=readGraph();}catch(NoActiveWindow busy){/* Only this explicit missing root is transient. */}
            long now=SystemClock.elapsedRealtime();
            ObservationStabilityGate.Result result=request.gate.sample(now,graph==null?null:frameKey(graph),true);
            if(result==ObservationStabilityGate.Result.EXPIRED||result==ObservationStabilityGate.Result.CANCELLED){
                failObservation(request,"窗口仍在变化或没有活动窗口，未取得稳定观察");return;
            }
            long screenshotDelay=Math.max(0,400-(now-lastScreenshotAt));
            if(result==ObservationStabilityGate.Result.READY&&screenshotDelay==0){
                request.captured=graph;graph=null;captureObservation(request);return;
            }
            long delay=request.gate.nextSampleDelay(now);
            if(result==ObservationStabilityGate.Result.READY)delay=Math.min(delay,screenshotDelay);
            main.postDelayed(new Runnable(){public void run(){sampleObservation(request);}},delay);
        }catch(Exception error){failObservation(request,"无法读取当前活动窗口："+message(error));}
        finally{if(graph!=null)graph.close();}
    }
    private void failObservation(ObservationRequest request,String error){
        if(request.finished)return;
        request.finished=true;request.gate.retire();
        if(request.shotPending&&captureSerial==request.token){capturePending=false;captureSerial++;}
        request.shotPending=false;
        if(request.captured!=null){request.captured.close();request.captured=null;}
        if(activeObservation==request)activeObservation=null;
        request.callback.onError(error);
    }
    private void retryObservation(final ObservationRequest request,long delay){
        if(request.captured!=null){request.captured.close();request.captured=null;}
        request.gate.resetEvidence();
        if(!observationActive(request))return;
        // This never renews the fixed settling deadline or the original caller deadline.
        main.postDelayed(new Runnable(){public void run(){sampleObservation(request);}},
                Math.min(delay,request.gate.nextSampleDelay(SystemClock.elapsedRealtime())));
    }
    private void watchCapture(final ObservationRequest request,final long captureDeadline){
        if(request.finished||activeObservation!=request||!request.shotPending)return;
        if(!observationActive(request))return;
        if(SystemClock.elapsedRealtime()>=captureDeadline){failObservation(request,"系统截图回调超时");return;}
        main.postDelayed(new Runnable(){public void run(){watchCapture(request,captureDeadline);}},100);
    }
    private void captureObservation(final ObservationRequest request){
        if(!observationActive(request))return;
        if(capturePending){failObservation(request,"已有截图尚未结束");return;}
        capturePending=true;request.shotPending=true;lastScreenshotAt=SystemClock.elapsedRealtime();
        final long token=++captureSerial;request.token=token;
        watchCapture(request,lastScreenshotAt+5000);
        try{takeScreenshot(Display.DEFAULT_DISPLAY,getMainExecutor(),new TakeScreenshotCallback(){
            @Override public void onFailure(int code){
                if(request.finished||activeObservation!=request||captureSerial!=token)return;
                capturePending=false;captureSerial++;request.shotPending=false;
                if(!observationActive(request))return;
                if(code==ERROR_TAKE_SCREENSHOT_INTERVAL_TIME_SHORT&&request.intervalRetries++<1)
                    retryObservation(request,500);
                else failObservation(request,"系统截图失败，错误码 "+code+"；不会绕过受保护画面");
            }
            @Override public void onSuccess(ScreenshotResult result){
                if(request.finished||activeObservation!=request||captureSerial!=token){result.getHardwareBuffer().close();return;}
                capturePending=false;captureSerial++;request.shotPending=false;
                Bitmap bitmap=null;Graph after=null;
                try{
                    bitmap=copyScreenshot(result);
                    if(!observationActive(request))return;
                    try{after=readGraph();}catch(NoActiveWindow busy){retryObservation(request,200);return;}
                    if(!sameObservedFrame(request.captured,after)){retryObservation(request,200);return;}
                    after.close();after=null;
                    if(bitmap.getWidth()<1||bitmap.getHeight()<1||(long)bitmap.getWidth()*bitmap.getHeight()>16000000L)
                        throw new IllegalStateException("屏幕尺寸超出观察范围");
                    if(!request.directory.isDirectory())throw new IllegalStateException("任务证据目录不存在");
                    String id=UUID.randomUUID().toString().replace("-","");File path=new File(request.directory,id+".png");
                    if(!path.createNewFile())throw new IllegalStateException("观察标识重复");
                    try(FileOutputStream stream=new FileOutputStream(path)){
                        if(!bitmap.compress(Bitmap.CompressFormat.PNG,100,stream))throw new IllegalStateException("截图编码失败");
                        stream.getFD().sync();
                    }
                    path.setReadable(false,false);path.setReadable(true,true);path.setWritable(false,false);path.setWritable(true,true);
                    String digest=fileSha256(path);
                    // Encoding/fsync/hash can take time. Recheck the full observed graph before publication.
                    if(!observationActive(request))return;
                    try{after=readGraph();}catch(NoActiveWindow busy){retryObservation(request,200);return;}
                    if(!sameObservedFrame(request.captured,after)){retryObservation(request,200);return;}
                    after.close();after=null;
                    if(!observationActive(request))return;
                    Graph graph=request.captured;
                    PhoneObservation observation=new PhoneObservation(id,graph.packageName,SystemClock.elapsedRealtime(),
                            bitmap.getWidth(),bitmap.getHeight(),graph.rotation,graph.windowId,graph.bounds,path,digest,graph.digest,graph.state,graph.windowMetadata,graph.truncated,graph.rows);
                    clearSnapshot();current=observation;currentGraph=graph;currentBitmap=bitmap;
                    request.captured=null;bitmap=null; // Ownership transfers only here. Late callbacks cannot close this snapshot.
                    request.finished=true;request.gate.retire();activeObservation=null;
                    request.callback.onObservation(observation);
                }catch(Exception error){failObservation(request,"观察失败："+message(error));}
                finally{if(after!=null)after.close();if(bitmap!=null)bitmap.recycle();}
            }
        });}catch(Exception error){failObservation(request,"系统截图不可用："+message(error));}
    }
    private static Bitmap copyScreenshot(ScreenshotResult result) {
        HardwareBuffer buffer=result.getHardwareBuffer();Bitmap wrapped=null;
        try{
            wrapped=Bitmap.wrapHardwareBuffer(buffer,result.getColorSpace());
            if(wrapped==null)throw new IllegalStateException("无法读取系统截图缓冲区");
            Bitmap copy=wrapped.copy(Bitmap.Config.ARGB_8888,false);
            if(copy==null)throw new IllegalStateException("无法复制系统截图");return copy;
        }finally{if(wrapped!=null)wrapped.recycle();buffer.close();}
    }
    private void clearSnapshot(){if(currentGraph!=null)currentGraph.close();if(currentBitmap!=null)currentBitmap.recycle();current=null;currentGraph=null;currentBitmap=null;}

    public void perform(final String taskId,final PhoneObservation expected,final ActionDecision decision,
                        final ObservedTargetLabels targets,final Cancellation cancel,final ActionCallback callback){
        main.post(new Runnable(){public void run(){performOnMain(taskId,expected,decision,targets,cancel,callback);}});
    }
    private String validate(String taskId,PhoneObservation expected,ActionDecision action,ObservedTargetLabels targets,Cancellation cancel){
        if(cancel.isCancelled()||!owns(taskId))return "任务已停止";
        if(locked())return "手机已锁定";
        if(expected!=current||currentGraph==null||!expected.id.equals(action.observationId))return "stale:观察标识已失效";
        // Use the controller's immutable, exact prompt projection. Never resolve a
        // label to an ID or reconstruct a different ordering from the live tree.
        if(targets==null||!expected.id.equals(targets.observationId)||!expected.packageName.equals(targets.packageName))
            return "目标标签投影不属于本次观察";
        if(action.nodeId!=null&&!targets.matches(action.observationId,action.packageName,action.nodeId,action.nodeLabel))
            return "节点文字与标识不是本次观察提供的原始配对";
        long age=SystemClock.elapsedRealtime()-expected.capturedElapsedMillis;
        if(age<0||age>MAX_OBSERVATION_AGE_MS)return "stale:观察已过期";
        if(!"open".equals(action.action)&&!expected.packageName.equals(action.packageName))return "stale:动作应用与观察不一致";
        Graph now=null;
        try{
            now=readGraph();
            if(!currentGraph.sameWindow(now))return "stale:目标窗口已变化";
            if(ActionPolicy.requiresStableTree(action)&&!currentGraph.digest.equals(now.digest))
                return "stale:目标窗口内容已变化";
        }
        catch(Exception e){return "stale:无法复核当前窗口";}finally{if(now!=null)now.close();}
        return null;
    }
    private void performOnMain(final String taskId,final PhoneObservation expected,final ActionDecision action,
                               final ObservedTargetLabels targets,final Cancellation cancel,final ActionCallback callback){
        String invalid=validate(taskId,expected,action,targets,cancel);
        if(invalid!=null){callback.onResult(new ActionOutcome(false,false,invalid.startsWith("stale:"),invalid));return;}
        try{
            if("wait".equals(action.action)){
                main.postDelayed(new Runnable(){public void run(){callback.onResult(new ActionOutcome(!cancel.isCancelled(),false,false,cancel.isCancelled()?"等待已停止":"等待结束"));}},action.durationMs);return;
            }
            if("done".equals(action.action)){callback.onResult(new ActionOutcome(true,false,false,"模型请求结束；仍需最终观察"));return;}
            if(ActionPolicy.isReadOnlyDiscovery(action)){
                final AppCatalogueRanker snapshot;synchronized(this){snapshot=appDiscovery;}
                if(snapshot==null)throw new IllegalStateException("本次任务的本机应用目录不可用");
                AppCatalogueRanker.Page page=snapshot.search(action.query,action.offset);
                if(cancel.isCancelled()||!owns(taskId)){callback.onResult(new ActionOutcome(false,false,false,"任务已停止"));return;}
                // Pure lookup: no Intent, accessibility action, gesture, shell,
                // network or app launch is dispatched by this tool.
                callback.onResult(new ActionOutcome(true,false,false,"已只读查询本机应用目录",page));return;
            }
            if("open".equals(action.action)){
                refreshApps();if(!launchable.containsKey(action.packageName))throw new IllegalArgumentException("目标不是已列出的可启动应用");
                Intent launch=getPackageManager().getLaunchIntentForPackage(action.packageName);
                if(launch==null)throw new IllegalArgumentException("找不到应用启动入口");
                launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TOP);
                if(cancel.isCancelled()){callback.onResult(new ActionOutcome(false,false,false,"任务已停止"));return;}
                startActivity(launch);finishAfter(700,true,"已请求打开应用，下一步将重新观察",callback);return;
            }
            if("back".equals(action.action)||"home".equals(action.action)){
                if(cancel.isCancelled()){callback.onResult(new ActionOutcome(false,false,false,"任务已停止"));return;}
                boolean accepted=performGlobalAction("back".equals(action.action)?GLOBAL_ACTION_BACK:GLOBAL_ACTION_HOME);
                finishAfter(350,accepted,accepted?"系统导航已接受":"系统导航未接受",callback);return;
            }
            if("click".equals(action.action)&&action.nodeId==null){coordinateClick(taskId,expected,action,targets,cancel,callback);return;}
            NodeRef reference=currentGraph.refs.get(action.nodeId);
            if(reference==null)throw new IllegalArgumentException("节点不属于这次观察");
            AccessibilityNodeInfo node=reference.node;
            boolean refreshed=node.refresh();
            ObservedChildText.Result freshChildText=refreshed?observedChildText(node):ObservedChildText.notApplicable();
            if(!refreshed||!reference.signature.equals(nodeSignature(node,freshChildText))||!node.isVisibleToUser()||!node.isEnabled()){
                callback.onResult(new ActionOutcome(false,false,true,"stale:目标节点已变化"));return;
            }
            if(node.isPassword())throw new IllegalArgumentException("不自动输入或操作密码节点");
            if(!expected.packageName.equals(string(node.getPackageName()))||node.getWindowId()!=expected.windowId)
                throw new IllegalArgumentException("目标节点窗口不一致");
            if(cancel.isCancelled()){callback.onResult(new ActionOutcome(false,false,false,"任务已停止"));return;}
            boolean accepted;
            if("click".equals(action.action)){
                if(!hasAction(node,AccessibilityNodeInfo.ACTION_CLICK))throw new IllegalArgumentException("这个节点没有点击动作");
                // Only actual editability grants the input-focus exemption. A nonzero
                // raw inputType alone can also occur on a noneditable custom TextView.
                PersistentActionPolicy.Decision policy=PersistentActionPolicy.evaluate(string(node.getText()),
                        string(node.getContentDescription()),freshChildText.text,node.isEditable());
                if(!policy.allowed){
                    callback.onResult(new ActionOutcome(false,false,false,policy.reasonCode+": "+policy.detail));return;
                }
                accepted=node.performAction(AccessibilityNodeInfo.ACTION_CLICK);
                finishAfter(350,accepted,accepted?"节点点击已接受":"节点点击未接受",callback);
            }else if("type".equals(action.action)){
                if(!node.isEditable()||!hasAction(node,AccessibilityNodeInfo.ACTION_SET_TEXT))throw new IllegalArgumentException("目标不是可写文本节点");
                Bundle args=new Bundle();args.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,action.text);
                accepted=node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT,args);
                if(!accepted){callback.onResult(new ActionOutcome(false,false,false,"文本写入未被接受"));return;}
                main.postDelayed(new Runnable(){public void run(){
                    boolean verified=reference.node.refresh()&&action.text.equals(string(reference.node.getText()));
                    callback.onResult(new ActionOutcome(verified,true,false,verified?"文本已按原文回读验证":"文本操作已发送，但原文回读未通过；不重试"));
                }},300);
            }else if("scroll".equals(action.action)){
                int operation=scrollAction(action.direction);
                if(!hasAction(node,operation))throw new IllegalArgumentException("这个节点未提供所选滚动方向");
                accepted=node.performAction(operation);finishAfter(450,accepted,accepted?"滚动已接受":"滚动未接受",callback);
            }else throw new IllegalArgumentException("不支持的动作");
        }catch(Exception e){callback.onResult(new ActionOutcome(false,false,false,message(e)));}
    }
    private void finishAfter(long delay,final boolean accepted,final String detail,final ActionCallback callback){
        main.postDelayed(new Runnable(){public void run(){callback.onResult(new ActionOutcome(accepted,accepted,false,detail));}},delay);
    }
    private void coordinateClick(final String taskId,final PhoneObservation expected,final ActionDecision action,
                                 final ObservedTargetLabels targets,final Cancellation cancel,final ActionCallback callback){
        if(capturePending){callback.onResult(new ActionOutcome(false,false,true,"stale:截图正在更新"));return;}
        final int x=Math.min(expected.width-1,(int)Math.round(action.x*(expected.width-1)/1000.0));
        final int y=Math.min(expected.height-1,(int)Math.round(action.y*(expected.height-1)/1000.0));
        if(!expected.windowBounds.contains(x,y)){callback.onResult(new ActionOutcome(false,false,false,"坐标不在已观察应用窗口内"));return;}
        capturePending=true;lastScreenshotAt=SystemClock.elapsedRealtime();final long token=++captureSerial;
        main.postDelayed(new Runnable(){public void run(){
            if(capturePending&&captureSerial==token){capturePending=false;captureSerial++;callback.onResult(new ActionOutcome(false,false,true,"stale:点击前截图回调超时"));}
        }},5000);
        try { takeScreenshot(Display.DEFAULT_DISPLAY,getMainExecutor(),new TakeScreenshotCallback(){
            @Override public void onFailure(int code){
                if(captureSerial!=token)return;capturePending=false;captureSerial++;
                callback.onResult(new ActionOutcome(false,false,true,"stale:点击前截图校验失败，代码 "+code));}
            @Override public void onSuccess(ScreenshotResult result){
                if(captureSerial!=token){result.getHardwareBuffer().close();return;}
                capturePending=false;captureSerial++;Bitmap fresh=null;
                try{
                    fresh=copyScreenshot(result);String invalid=validate(taskId,expected,action,targets,cancel);
                    if(invalid!=null){callback.onResult(new ActionOutcome(false,false,invalid.startsWith("stale:"),invalid));return;}
                    if(fresh.getWidth()!=expected.width||fresh.getHeight()!=expected.height||!samePatch(currentBitmap,fresh,x,y)){
                        callback.onResult(new ActionOutcome(false,false,true,"stale:点击目标像素已变化"));return;
                    }
                    if(cancel.isCancelled()){callback.onResult(new ActionOutcome(false,false,false,"任务已停止"));return;}
                    Path path=new Path();path.moveTo(x,y);
                    GestureDescription gesture=new GestureDescription.Builder().addStroke(new GestureDescription.StrokeDescription(path,0,80)).build();
                    boolean queued=dispatchGesture(gesture,new GestureResultCallback(){
                        @Override public void onCompleted(GestureDescription value){finishAfter(300,true,"坐标点击完成，下一步将重新观察",callback);}
                        @Override public void onCancelled(GestureDescription value){callback.onResult(new ActionOutcome(false,true,false,"手势中断，可能已有部分效果；不重试"));}
                    },main);
                    if(!queued)callback.onResult(new ActionOutcome(false,false,false,"系统未接受坐标手势"));
                }catch(Exception e){callback.onResult(new ActionOutcome(false,false,false,message(e)));}
                finally{if(fresh!=null)fresh.recycle();}
            }
        }); } catch(Exception error){
            if(captureSerial==token){capturePending=false;captureSerial++;callback.onResult(new ActionOutcome(false,false,false,"点击前截图不可用："+message(error)));}
        }
    }
    private static boolean samePatch(Bitmap a,Bitmap b,int x,int y){
        if(a==null)return false;int left=Math.max(0,x-24),top=Math.max(0,y-24),right=Math.min(a.getWidth(),x+25),bottom=Math.min(a.getHeight(),y+25);
        int width=right-left,height=bottom-top;int[] first=new int[width*height],second=new int[width*height];
        a.getPixels(first,0,width,left,top,width,height);b.getPixels(second,0,width,left,top,width,height);
        return java.util.Arrays.equals(first,second);
    }
    private static boolean hasAction(AccessibilityNodeInfo node,int id){for(AccessibilityNodeInfo.AccessibilityAction a:node.getActionList())if(a.getId()==id)return true;return false;}
    private static int scrollAction(String direction){
        if("forward".equals(direction))return AccessibilityNodeInfo.ACTION_SCROLL_FORWARD;
        if("backward".equals(direction))return AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD;
        if("up".equals(direction))return AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_UP.getId();
        if("down".equals(direction))return AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_DOWN.getId();
        if("left".equals(direction))return AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_LEFT.getId();
        if("right".equals(direction))return AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_RIGHT.getId();
        throw new IllegalArgumentException("未知滚动方向");
    }
    private static final class NodeRef {
        final AccessibilityNodeInfo node;final String signature,appTreeSignature;
        NodeRef(AccessibilityNodeInfo node,ObservedChildText.Result childText,ObservedScrollActions scrollActions){
            this.node=AccessibilityNodeInfo.obtain(node);
            this.appTreeSignature=childText.bind(baseNodeSignature(node));
            this.signature=scrollActions.bindFreshness(appTreeSignature);
        }
    }
    private static final class Graph {
        String packageName,digest;int windowId,rotation;Rect bounds;boolean truncated;
        ObservationState state;
        ObservedWindowMetadata windowMetadata;
        final List<PhoneObservation.Node> rows=new ArrayList<PhoneObservation.Node>();
        final Map<String,NodeRef> refs=new HashMap<String,NodeRef>();
        boolean sameWindow(Graph other){return windowId==other.windowId&&rotation==other.rotation&&packageName.equals(other.packageName)&&bounds.equals(other.bounds);}
        boolean sameWindowAndTree(Graph other){return sameWindow(other)&&digest.equals(other.digest);}
        void close(){for(NodeRef n:refs.values())n.node.recycle();refs.clear();}
    }
    /** Inspect window metadata only. Never traverse an IME root or collect its text. */
    private ImeVisibility readImeVisibility(int targetWindowId){
        List<AccessibilityWindowInfo> windows=null;
        try{
            AccessibilityServiceInfo info=getServiceInfo();
            if(info==null||(info.flags&AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS)==0
                    ||(info.getCapabilities()&AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT)==0)
                return ImeVisibility.UNKNOWN;
            windows=getWindows();
            if(windows==null||windows.isEmpty())return ImeVisibility.UNKNOWN;
            boolean complete=true,targetPresent=false,imePresent=false;
            for(AccessibilityWindowInfo window:windows){
                if(window==null){complete=false;continue;}
                if(window.getDisplayId()!=Display.DEFAULT_DISPLAY)continue;
                if(window.getId()==targetWindowId)targetPresent=true;
                if(window.getType()==AccessibilityWindowInfo.TYPE_INPUT_METHOD){
                    Rect bounds=new Rect();window.getBoundsInScreen(bounds);
                    if(bounds.isEmpty())complete=false;else imePresent=true;
                }
            }
            return ImeVisibility.observed(complete,targetPresent,imePresent);
        }catch(RuntimeException unavailable){return ImeVisibility.UNKNOWN;}
        finally{if(windows!=null)for(AccessibilityWindowInfo window:windows)if(window!=null){
            try{window.recycle();}catch(RuntimeException ignored){/* No visibility conclusion from cleanup. */}
        }}
    }
    /** Read only the selected root's window metadata; never traverse another/IME window. */
    private ObservedWindowMetadata readWindowMetadata(AccessibilityNodeInfo root,Rect rootBounds,int windowId){
        int[] bounds=new int[]{rootBounds.left,rootBounds.top,rootBounds.right,rootBounds.bottom};
        String rootClass=null;
        AccessibilityWindowInfo window=null;
        try{
            CharSequence actualClass=root.getClassName();rootClass=actualClass==null?null:actualClass.toString();
            window=root.getWindow();
            if(window==null||window.getId()!=windowId||window.getDisplayId()!=Display.DEFAULT_DISPLAY)
                return ObservedWindowMetadata.unknown(bounds,rootClass);
            Rect actualBounds=new Rect();window.getBoundsInScreen(actualBounds);
            int type=window.getType();
            // An input-method window is never a source of title/input text here.
            CharSequence actualTitle=type==AccessibilityWindowInfo.TYPE_INPUT_METHOD?null:window.getTitle();
            return ObservedWindowMetadata.observed(bounds,rootClass,type,window.getDisplayId(),
                    new int[]{actualBounds.left,actualBounds.top,actualBounds.right,actualBounds.bottom},
                    actualTitle==null?null:actualTitle.toString());
        }catch(RuntimeException unavailable){return ObservedWindowMetadata.unknown(bounds,rootClass);}
        finally{if(window!=null)try{window.recycle();}catch(RuntimeException ignored){/* Cleanup supplies no metadata. */}}
    }
    private static final class NoActiveWindow extends IllegalStateException {
        private static final long serialVersionUID=1L;
        NoActiveWindow(){super("没有活动窗口");}
    }
    private Graph readGraph(){
        AccessibilityNodeInfo root=getRootInActiveWindow();if(root==null)throw new NoActiveWindow();
        Graph graph=new Graph();graph.packageName=string(root.getPackageName());graph.windowId=root.getWindowId();graph.rotation=rotation();graph.bounds=new Rect();root.getBoundsInScreen(graph.bounds);
        if(graph.packageName.isEmpty()||graph.bounds.isEmpty()){root.recycle();throw new IllegalStateException("活动窗口身份不可用");}
        graph.windowMetadata=readWindowMetadata(root,graph.bounds,graph.windowId);
        ArrayDeque<AccessibilityNodeInfo> queue=new ArrayDeque<AccessibilityNodeInfo>();queue.add(root);
        StringBuilder signatures=new StringBuilder(),focusStates=new StringBuilder(),scrollStates=new StringBuilder();int visited=0,characters=0;
        try{
            while(!queue.isEmpty()&&visited<MAX_VISITED){
                AccessibilityNodeInfo node=queue.removeFirst();visited++;
                try{
                    Rect bounds=new Rect();node.getBoundsInScreen(bounds);boolean visible=node.isVisibleToUser()&&!bounds.isEmpty();
                    String text=node.isPassword()?"":limited(string(node.getText()),96);
                    String description=node.isPassword()?"":limited(string(node.getContentDescription()),96);
                    ObservedScrollActions scrollActions=readScrollActions(node);
                    boolean useful=visible&&(node.isClickable()||node.isEditable()||node.isScrollable()||!text.isEmpty()||!description.isEmpty());
                    if(useful){
                        ObservedChildText.Result childText=graph.rows.size()<MAX_NODES?observedChildText(node):ObservedChildText.notApplicable();
                        if(graph.rows.size()<MAX_NODES&&characters+text.length()+description.length()+childText.text.length()<2400){
                            String id="n"+graph.rows.size();NodeRef reference=new NodeRef(node,childText,scrollActions);graph.refs.put(id,reference);signatures.append(reference.appTreeSignature).append('\n');
                            scrollStates.append(id).append('=').append(scrollActions.fingerprintInput()).append('\n');
                            boolean focused=node.isFocused();focusStates.append(id).append('=').append(focused).append('\n');
                            graph.rows.add(new PhoneObservation.Node(id,string(node.getPackageName()),string(node.getClassName()),limited(string(node.getViewIdResourceName()),96),text,description,bounds,node.isClickable(),node.isEditable(),node.isScrollable(),node.isEnabled(),focused,node.isPassword(),childText,scrollActions));
                            characters+=text.length()+description.length()+childText.text.length();
                        }else graph.truncated=true;
                    }
                    int children=Math.min(node.getChildCount(),MAX_VISITED-visited-queue.size());
                    if(children<node.getChildCount())graph.truncated=true;
                    for(int index=0;index<children;index++){AccessibilityNodeInfo child=node.getChild(index);if(child!=null)queue.add(child);}
                }finally{node.recycle();}
            }
            if(!queue.isEmpty())graph.truncated=true;
            String appTree=sha((graph.packageName+"|"+graph.windowId+"|"+graph.rotation+"|"+graph.bounds+"|"+signatures).getBytes(StandardCharsets.UTF_8));
            graph.state=new ObservationState(appTree,readImeVisibility(graph.windowId));
            // Focus is newly model-visible evidence, not an expansion of the old progress predicate.
            graph.digest=sha(graph.windowMetadata.bindFreshness(graph.state.fingerprintInput()+"\nnode_focus="+focusStates+"\nnode_scroll_actions="+scrollStates)
                    .getBytes(StandardCharsets.UTF_8));return graph;
        }catch(RuntimeException e){graph.close();throw e;}
        finally{while(!queue.isEmpty())queue.removeFirst().recycle();}
    }
    private static String nodeSignature(AccessibilityNodeInfo node,ObservedChildText.Result childText){
        // Capture and target refresh both supply the same bounded subtree observation.
        return readScrollActions(node).bindFreshness(childText.bind(baseNodeSignature(node)));
    }
    /** No aliasing of logical forward/backward to content directions. */
    private static ObservedScrollActions readScrollActions(AccessibilityNodeInfo node){
        try{
            List<AccessibilityNodeInfo.AccessibilityAction> actions=node.getActionList();
            if(actions==null||actions.size()>128)return ObservedScrollActions.UNKNOWN;
            List<String> directions=new ArrayList<String>();
            for(AccessibilityNodeInfo.AccessibilityAction action:actions){
                if(action==null)return ObservedScrollActions.UNKNOWN;
                int id=action.getId();
                if(id==AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_FORWARD.getId())directions.add("forward");
                else if(id==AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_BACKWARD.getId())directions.add("backward");
                else if(id==AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_UP.getId())directions.add("up");
                else if(id==AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_DOWN.getId())directions.add("down");
                else if(id==AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_LEFT.getId())directions.add("left");
                else if(id==AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_RIGHT.getId())directions.add("right");
            }
            return ObservedScrollActions.observed(directions);
        }catch(RuntimeException unavailable){return ObservedScrollActions.UNKNOWN;}
    }
    private static ObservedChildText.Result observedChildText(final AccessibilityNodeInfo root){
        final Rect rootBounds=new Rect();root.getBoundsInScreen(rootBounds);
        final String ownerPackage=string(root.getPackageName());final int ownerWindow=root.getWindowId();
        return ObservedChildText.collect(root,new ObservedChildText.Reader<AccessibilityNodeInfo>(){
            public ObservedChildText.Metadata metadata(AccessibilityNodeInfo node){
                Rect bounds=new Rect();node.getBoundsInScreen(bounds);
                boolean inputLike=node.isEditable()||node.getInputType()!=0;
                boolean clickAction=hasAction(node,AccessibilityNodeInfo.ACTION_CLICK);
                boolean interactive=node.isClickable()||node.isLongClickable()||inputLike||node.isScrollable()||node.isCheckable()
                        ||clickAction||hasAction(node,AccessibilityNodeInfo.ACTION_LONG_CLICK)
                        ||hasAction(node,AccessibilityNodeInfo.ACTION_SET_TEXT)
                        ||hasAction(node,AccessibilityNodeInfo.ACTION_SCROLL_FORWARD)||hasAction(node,AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD)
                        ||hasAction(node,AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_UP.getId())
                        ||hasAction(node,AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_DOWN.getId())
                        ||hasAction(node,AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_LEFT.getId())
                        ||hasAction(node,AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_RIGHT.getId());
                return new ObservedChildText.Metadata(node.isVisibleToUser()&&!bounds.isEmpty(),
                        ownerWindow==node.getWindowId()&&ownerPackage.equals(string(node.getPackageName()))&&Rect.intersects(rootBounds,bounds),
                        node.isClickable(),clickAction,inputLike,node.isPassword(),interactive);
            }
            // collect() checks metadata boundaries before calling either text accessor.
            public String text(AccessibilityNodeInfo node){return string(node.getText());}
            public String description(AccessibilityNodeInfo node){return string(node.getContentDescription());}
            public String identity(AccessibilityNodeInfo node){return baseNodeSignature(node);}
            public int childCount(AccessibilityNodeInfo node){return node.getChildCount();}
            public AccessibilityNodeInfo child(AccessibilityNodeInfo node,int index){return node.getChild(index);}
            public void release(AccessibilityNodeInfo node){node.recycle();}
        });
    }
    private static String baseNodeSignature(AccessibilityNodeInfo node){
        Rect bounds=new Rect();node.getBoundsInScreen(bounds);
        String value=string(node.getPackageName())+"\u0001"+node.getWindowId()+"\u0001"+string(node.getClassName())+"\u0001"+string(node.getViewIdResourceName())+"\u0001"+bounds+"\u0001"+
                (node.isPassword()?"<password>":string(node.getText())+"\u0001"+string(node.getContentDescription()))+"\u0001"+node.isEnabled()+"|"+node.isClickable()+"|"+node.isEditable()+"|"+node.isScrollable();
        return sha(value.getBytes(StandardCharsets.UTF_8));
    }
    static String sha(byte[] raw){try{MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] bytes=digest.digest(raw);StringBuilder value=new StringBuilder();for(byte b:bytes)value.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return value.toString();}catch(Exception e){throw new IllegalStateException(e);}}
    private static String fileSha256(File file)throws Exception{MessageDigest digest=MessageDigest.getInstance("SHA-256");try(java.io.FileInputStream stream=new java.io.FileInputStream(file)){byte[] buffer=new byte[65536];int size;while((size=stream.read(buffer))!=-1)digest.update(buffer,0,size);}StringBuilder value=new StringBuilder();for(byte b:digest.digest())value.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return value.toString();}
    private static String string(CharSequence value){return value==null?"":value.toString();}
    static String limited(String text,int max){if(text.length()<=max)return text;int end=max;if(end>0&&Character.isHighSurrogate(text.charAt(end-1)))end--;return text.substring(0,end)+"…";}
    static String message(Throwable e){String value=e.getMessage();return value==null?e.getClass().getSimpleName():limited(value,300);}
}
