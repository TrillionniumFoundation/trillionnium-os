package org.trillionnium.hepta.localprobe;

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
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
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
        ActionOutcome(boolean accepted,boolean dispatched,boolean stale,String detail) {
            this.accepted=accepted;this.dispatched=dispatched;this.stale=stale;this.detail=detail;
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
    private PhoneObservation current;
    private Graph currentGraph;
    private Bitmap currentBitmap;
    private static final long MAX_OBSERVATION_AGE_MS=90000;
    private static final int MAX_NODES=64, MAX_VISITED=320;
    private final Map<String,String> launchable=new java.util.concurrent.ConcurrentHashMap<String,String>();

    @Override protected void onServiceConnected() {
        AccessibilityServiceInfo info=getServiceInfo();
        info.eventTypes=AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED|AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED
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
        requestStop();if(live==this)live=null;clearSnapshot();super.onDestroy();
    }
    /** Service-owned session survives Activity recreation. The controller stays injectable. */
    public synchronized LocalTaskController taskController(LocalInference inference){
        if(ownedController==null)ownedController=new LocalTaskController(this,inference);
        return ownedController;
    }
    public synchronized LocalTaskController taskController(LocalModelEngine engine){
        return taskController(new EngineInferenceAdapter(engine));
    }
    private void requestStop() { Runnable value; synchronized(this){value=stopListener;} if(value!=null)value.run(); }
    public synchronized boolean acquireTask(String taskId,Runnable onStop) {
        if(lease!=null || live!=this)return false;lease=taskId;stopListener=onStop;return true;
    }
    public synchronized void releaseTask(String taskId) { if(taskId.equals(lease)){lease=null;stopListener=null;} }
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
    /** Only installed launcher applications may be opened; labels are data. */
    public String appCatalogue(String instruction) {
        refreshApps();List<String> packages=new ArrayList<String>(launchable.keySet());Collections.sort(packages);
        final String original=instruction.toLowerCase(java.util.Locale.ROOT);
        Collections.sort(packages,new Comparator<String>() { public int compare(String a,String b) {
            boolean aa=original.contains(launchable.get(a).toLowerCase(java.util.Locale.ROOT));
            boolean bb=original.contains(launchable.get(b).toLowerCase(java.util.Locale.ROOT));return aa==bb?a.compareTo(b):(aa?-1:1);
        }});
        try {
            JSONArray rows=new JSONArray();int characters=0;
            for(String pkg:packages) { String label=limited(launchable.get(pkg),48);
                if(rows.length()>=40 || characters+pkg.length()+label.length()>2000)break;
                rows.put(new JSONObject().put("package",pkg).put("label",label));characters+=pkg.length()+label.length();
            }
            return new JSONObject().put("apps",rows).put("catalogue_truncated",rows.length()<packages.size()).toString();
        }catch(Exception e){throw new IllegalStateException(e);}
    }

    public void observe(final String taskId,final File evidenceDirectory,final ObservationCallback callback) {
        main.post(new Runnable(){public void run(){observeOnMain(taskId,evidenceDirectory,callback,0);}});
    }
    private void observeOnMain(final String taskId,final File directory,final ObservationCallback callback,final int retry) {
        if(!owns(taskId)){callback.onError("任务已经停止或无障碍服务已断开");return;}
        if(locked()){callback.onError("手机已锁定，请正常解锁后重新发起任务");return;}
        if(capturePending){callback.onError("已有屏幕观察尚未结束");return;}
        long delay=Math.max(0,400-(SystemClock.elapsedRealtime()-lastScreenshotAt));
        if(delay>0){main.postDelayed(new Runnable(){public void run(){observeOnMain(taskId,directory,callback,retry);}},delay);return;}
        final Graph graph;
        try{graph=readGraph();}catch(Exception e){callback.onError("无法读取当前活动窗口："+message(e));return;}
        capturePending=true;lastScreenshotAt=SystemClock.elapsedRealtime();final long token=++captureSerial;
        main.postDelayed(new Runnable(){public void run(){
            if(capturePending&&captureSerial==token){capturePending=false;captureSerial++;graph.close();callback.onError("系统截图回调超时");}
        }},5000);
        try { takeScreenshot(Display.DEFAULT_DISPLAY,getMainExecutor(),new TakeScreenshotCallback(){
            @Override public void onFailure(int code){
                if(captureSerial!=token){graph.close();return;}
                capturePending=false;captureSerial++;graph.close();
                if(code==ERROR_TAKE_SCREENSHOT_INTERVAL_TIME_SHORT && retry<1){
                    main.postDelayed(new Runnable(){public void run(){observeOnMain(taskId,directory,callback,retry+1);}},500);
                }else callback.onError("系统截图失败，错误码 "+code+"；不会绕过受保护画面");
            }
            @Override public void onSuccess(ScreenshotResult result){
                if(captureSerial!=token){result.getHardwareBuffer().close();graph.close();return;}
                capturePending=false;captureSerial++;Bitmap bitmap=null;Graph after=null;
                try{
                    bitmap=copyScreenshot(result);
                    if(!owns(taskId)||locked())throw new IllegalStateException("观察过程中任务停止或手机锁定");
                    after=readGraph();
                    if(!graph.sameWindowAndTree(after)){
                        graph.close();after.close();bitmap.recycle();
                        if(retry<2){main.postDelayed(new Runnable(){public void run(){observeOnMain(taskId,directory,callback,retry+1);}},300);}
                        else callback.onError("窗口仍在变化，尚未取得稳定观察");
                        return;
                    }
                    after.close();after=null;
                    if(bitmap.getWidth()<1||bitmap.getHeight()<1||(long)bitmap.getWidth()*bitmap.getHeight()>16000000L)
                        throw new IllegalStateException("屏幕尺寸超出观察范围");
                    if(!directory.isDirectory())throw new IllegalStateException("任务证据目录不存在");
                    String id=UUID.randomUUID().toString().replace("-","");File path=new File(directory,id+".png");
                    if(!path.createNewFile())throw new IllegalStateException("观察标识重复");
                    try(FileOutputStream stream=new FileOutputStream(path)){
                        if(!bitmap.compress(Bitmap.CompressFormat.PNG,100,stream))throw new IllegalStateException("截图编码失败");
                        stream.getFD().sync();
                    }
                    path.setReadable(false,false);path.setReadable(true,true);path.setWritable(false,false);path.setWritable(true,true);
                    String digest=fileSha256(path);
                    PhoneObservation observation=new PhoneObservation(id,graph.packageName,SystemClock.elapsedRealtime(),
                            bitmap.getWidth(),bitmap.getHeight(),graph.rotation,graph.windowId,graph.bounds,path,digest,graph.digest,graph.truncated,graph.rows);
                    clearSnapshot();current=observation;currentGraph=graph;currentBitmap=bitmap;bitmap=null;
                    callback.onObservation(observation);
                }catch(Exception e){graph.close();if(after!=null)after.close();if(bitmap!=null)bitmap.recycle();callback.onError("观察失败："+message(e));}
            }
        }); } catch(Exception error){
            if(captureSerial==token){capturePending=false;captureSerial++;graph.close();callback.onError("系统截图不可用："+message(error));}
        }
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
                        final Cancellation cancel,final ActionCallback callback){
        main.post(new Runnable(){public void run(){performOnMain(taskId,expected,decision,cancel,callback);}});
    }
    private String validate(String taskId,PhoneObservation expected,ActionDecision action,Cancellation cancel){
        if(cancel.isCancelled()||!owns(taskId))return "任务已停止";
        if(locked())return "手机已锁定";
        if(expected!=current||currentGraph==null||!expected.id.equals(action.observationId))return "stale:观察标识已失效";
        long age=SystemClock.elapsedRealtime()-expected.capturedElapsedMillis;
        if(age<0||age>MAX_OBSERVATION_AGE_MS)return "stale:观察已过期";
        if(!"open".equals(action.action)&&!expected.packageName.equals(action.packageName))return "stale:动作应用与观察不一致";
        Graph now=null;
        try{
            now=readGraph();
            // An explicit app launch does not target source-window text. Clock
            // updates must not invalidate it; window identity/geometry still do.
            boolean same="open".equals(action.action)?currentGraph.sameWindow(now):currentGraph.sameWindowAndTree(now);
            if(!same)return "stale:目标窗口或内容已变化";
        }
        catch(Exception e){return "stale:无法复核当前窗口";}finally{if(now!=null)now.close();}
        return null;
    }
    private void performOnMain(final String taskId,final PhoneObservation expected,final ActionDecision action,
                               final Cancellation cancel,final ActionCallback callback){
        String invalid=validate(taskId,expected,action,cancel);
        if(invalid!=null){callback.onResult(new ActionOutcome(false,false,invalid.startsWith("stale:"),invalid));return;}
        try{
            if("wait".equals(action.action)){
                main.postDelayed(new Runnable(){public void run(){callback.onResult(new ActionOutcome(!cancel.isCancelled(),false,false,cancel.isCancelled()?"等待已停止":"等待结束"));}},action.durationMs);return;
            }
            if("done".equals(action.action)){callback.onResult(new ActionOutcome(true,false,false,"模型请求结束；仍需最终观察"));return;}
            if("open".equals(action.action)){
                if(expected.packageName.equals(action.packageName))throw new IllegalArgumentException("应用已在前台；未执行重复打开，请根据当前画面判断下一步");
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
            if("click".equals(action.action)&&action.nodeId==null){coordinateClick(taskId,expected,action,cancel,callback);return;}
            NodeRef reference=currentGraph.refs.get(action.nodeId);
            if(reference==null)throw new IllegalArgumentException("节点不属于这次观察");
            AccessibilityNodeInfo node=reference.node;
            if(!node.refresh()||!reference.signature.equals(nodeSignature(node))||!node.isVisibleToUser()||!node.isEnabled()){
                callback.onResult(new ActionOutcome(false,false,true,"stale:目标节点已变化"));return;
            }
            if(node.isPassword())throw new IllegalArgumentException("不自动输入或操作密码节点");
            if(!expected.packageName.equals(string(node.getPackageName()))||node.getWindowId()!=expected.windowId)
                throw new IllegalArgumentException("目标节点窗口不一致");
            if(cancel.isCancelled()){callback.onResult(new ActionOutcome(false,false,false,"任务已停止"));return;}
            boolean accepted;
            if("click".equals(action.action)){
                if(!hasAction(node,AccessibilityNodeInfo.ACTION_CLICK))throw new IllegalArgumentException("这个节点没有点击动作");
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
                                 final Cancellation cancel,final ActionCallback callback){
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
                    fresh=copyScreenshot(result);String invalid=validate(taskId,expected,action,cancel);
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
        final AccessibilityNodeInfo node;final String signature;
        NodeRef(AccessibilityNodeInfo node){this.node=AccessibilityNodeInfo.obtain(node);this.signature=nodeSignature(node);}
    }
    private static final class TraversalNode {
        final AccessibilityNodeInfo node;final String labelOwner;
        TraversalNode(AccessibilityNodeInfo node,String labelOwner){this.node=node;this.labelOwner=labelOwner;}
    }
    private static final class Graph {
        String packageName,digest;int windowId,rotation;Rect bounds;boolean truncated;
        final List<PhoneObservation.Node> rows=new ArrayList<PhoneObservation.Node>();
        final Map<String,NodeRef> refs=new HashMap<String,NodeRef>();
        final Map<String,StringBuilder> childLabels=new HashMap<String,StringBuilder>();
        boolean sameWindow(Graph other){return windowId==other.windowId&&rotation==other.rotation&&packageName.equals(other.packageName)&&bounds.equals(other.bounds);}
        boolean sameWindowAndTree(Graph other){return sameWindow(other)&&digest.equals(other.digest);}
        void close(){for(NodeRef n:refs.values())n.node.recycle();refs.clear();}
    }
    private Graph readGraph(){
        AccessibilityNodeInfo root=getRootInActiveWindow();if(root==null)throw new IllegalStateException("没有活动窗口");
        Graph graph=new Graph();graph.packageName=string(root.getPackageName());graph.windowId=root.getWindowId();graph.rotation=rotation();graph.bounds=new Rect();root.getBoundsInScreen(graph.bounds);
        if(graph.packageName.isEmpty()||graph.bounds.isEmpty()){root.recycle();throw new IllegalStateException("活动窗口身份不可用");}
        ArrayDeque<TraversalNode> queue=new ArrayDeque<TraversalNode>();queue.add(new TraversalNode(root,null));StringBuilder signatures=new StringBuilder();int visited=0,characters=0;
        try{
            while(!queue.isEmpty()&&visited<MAX_VISITED){
                TraversalNode entry=queue.removeFirst();AccessibilityNodeInfo node=entry.node;visited++;
                try{
                    Rect bounds=new Rect();node.getBoundsInScreen(bounds);boolean visible=node.isVisibleToUser()&&!bounds.isEmpty();
                    String text=node.isPassword()?"":limited(string(node.getText()),96);
                    String description=node.isPassword()?"":limited(string(node.getContentDescription()),96);
                    boolean useful=visible&&(node.isClickable()||node.isEditable()||node.isScrollable()||!text.isEmpty()||!description.isEmpty());
                    boolean interactive=node.isClickable()||node.isEditable()||node.isScrollable();
                    // Text is folded only through actual ancestors, never by
                    // rectangle overlap. Nested actionable targets form a boundary.
                    if(visible&&!node.isPassword()&&!interactive&&entry.labelOwner!=null)
                        appendChildLabel(graph,entry.labelOwner,text.isEmpty()?description:text);
                    String childOwner=interactive?null:entry.labelOwner;
                    if(useful){
                        if(graph.rows.size()<MAX_NODES&&characters+text.length()+description.length()<2400){
                            String id="n"+graph.rows.size();NodeRef reference=new NodeRef(node);graph.refs.put(id,reference);signatures.append(reference.signature).append('\n');
                            graph.rows.add(new PhoneObservation.Node(id,string(node.getPackageName()),string(node.getClassName()),limited(string(node.getViewIdResourceName()),96),text,description,bounds,node.isClickable(),node.isEditable(),node.isScrollable(),node.isEnabled(),node.isFocused(),node.isPassword()));
                            if(node.isClickable()&&!node.isEditable()&&!node.isPassword()&&text.isEmpty()&&description.isEmpty())childOwner=id;
                            characters+=text.length()+description.length();
                        }else graph.truncated=true;
                    }
                    int children=Math.min(node.getChildCount(),MAX_VISITED-visited-queue.size());
                    if(children<node.getChildCount())graph.truncated=true;
                    for(int index=0;index<children;index++){AccessibilityNodeInfo child=node.getChild(index);if(child!=null)queue.add(new TraversalNode(child,childOwner));}
                }finally{node.recycle();}
            }
            if(!queue.isEmpty())graph.truncated=true;
            for(int i=0;i<graph.rows.size();i++){
                PhoneObservation.Node row=graph.rows.get(i);StringBuilder folded=graph.childLabels.get(row.id);
                if(folded!=null&&folded.length()>0){
                    String label=folded.toString();graph.rows.set(i,row.withChildText(label));
                    // Child labels take part in strict non-open freshness, so
                    // a recycled blank row cannot silently acquire new meaning.
                    signatures.append(row.id).append("|child_text|").append(label).append('\n');
                }
            }
            graph.digest=sha((graph.packageName+"|"+graph.windowId+"|"+graph.rotation+"|"+graph.bounds+"|"+signatures).getBytes(StandardCharsets.UTF_8));return graph;
        }catch(RuntimeException e){graph.close();throw e;}
        finally{while(!queue.isEmpty())queue.removeFirst().node.recycle();}
    }
    private static void appendChildLabel(Graph graph,String owner,String label){
        if(label.isEmpty())return;
        StringBuilder value=graph.childLabels.get(owner);
        if(value==null){value=new StringBuilder();graph.childLabels.put(owner,value);}
        if(value.indexOf(label)>=0)return;
        int space=96-value.length()-(value.length()==0?0:3);if(space<=0)return;
        if(value.length()>0)value.append(" / ");value.append(limited(label,space));
    }
    private static String nodeSignature(AccessibilityNodeInfo node){
        Rect bounds=new Rect();node.getBoundsInScreen(bounds);
        String value=string(node.getPackageName())+"\u0001"+node.getWindowId()+"\u0001"+string(node.getClassName())+"\u0001"+string(node.getViewIdResourceName())+"\u0001"+bounds+"\u0001"+
                (node.isPassword()?"<password>":string(node.getText())+"\u0001"+string(node.getContentDescription()))+"\u0001"+node.isEnabled()+"|"+node.isClickable()+"|"+node.isEditable()+"|"+node.isScrollable()+"|"+node.isCheckable()+"|"+node.isChecked()+"|"+node.isSelected();
        return sha(value.getBytes(StandardCharsets.UTF_8));
    }
    static String sha(byte[] raw){try{MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] bytes=digest.digest(raw);StringBuilder value=new StringBuilder();for(byte b:bytes)value.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return value.toString();}catch(Exception e){throw new IllegalStateException(e);}}
    private static String fileSha256(File file)throws Exception{MessageDigest digest=MessageDigest.getInstance("SHA-256");try(java.io.FileInputStream stream=new java.io.FileInputStream(file)){byte[] buffer=new byte[65536];int size;while((size=stream.read(buffer))!=-1)digest.update(buffer,0,size);}StringBuilder value=new StringBuilder();for(byte b:digest.digest())value.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return value.toString();}
    private static String string(CharSequence value){return value==null?"":value.toString();}
    static String limited(String text,int max){if(text.length()<=max)return text;int end=max;if(end>0&&Character.isHighSurrogate(text.charAt(end-1)))end--;return text.substring(0,end)+"…";}
    static String message(Throwable e){String value=e.getMessage();return value==null?e.getClass().getSimpleName():limited(value,300);}
}
