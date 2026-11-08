package org.trillionnium.hepta.stopobserver;

import android.app.Activity;
import android.app.Instrumentation;
import android.app.UiAutomation;
import android.graphics.Bitmap;
import android.graphics.Rect;
import android.os.Bundle;
import android.os.SystemClock;
import android.provider.Settings;
import android.view.accessibility.AccessibilityNodeInfo;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

/** Isolated test observer. The only UI effect available is one exact Hepta Stop click. */
public final class StopObserverInstrumentation extends Instrumentation {
    private static final String TARGET="org.trillionnium.hepta.localprobe";
    private static final String BUTTON_CLASS="android.widget.Button";
    private static final int MAX_NODES=512;
    private static final long MAX_SCAN_MS=2000, MAX_TARGET_AGE_MS=500;
    private Bundle arguments;
    private boolean actionAttempted,actionReturned,actionAccepted;

    @Override public void onCreate(Bundle args){
        super.onCreate(args);arguments=args==null?new Bundle():new Bundle(args);start();
    }
    @Override public void onStart(){
        JSONObject receipt=new JSONObject();File directory=null;Bitmap screenshot=null;
        Snapshot first=null,second=null;String enabledBefore=null;boolean completed=false;
        try{
            String mode=arguments.getString("mode"),runId=arguments.getString("run_id");
            if(!"observe".equals(mode)&&!"click_stop".equals(mode))throw new IllegalArgumentException("mode must be observe or click_stop");
            if(runId==null||!runId.matches("[0-9a-f]{32}"))throw new IllegalArgumentException("run_id must be 32 lowercase hex characters");
            File root=new File(getTargetContext().getFilesDir(),"observations");
            if(!root.isDirectory()&&!root.mkdir())throw new IllegalStateException("cannot create observations directory");
            directory=new File(root,runId);
            if(!directory.mkdir())throw new IllegalStateException("run_id already used; no replay performed");
            put(receipt,"schema","hepta.stop-observer.v1");put(receipt,"run_id",runId);put(receipt,"mode",mode);
            put(receipt,"observer_package",getTargetContext().getPackageName());put(receipt,"target_package",TARGET);
            put(receipt,"observer_uid",android.os.Process.myUid());put(receipt,"observer_pid",android.os.Process.myPid());
            put(receipt,"sdk",android.os.Build.VERSION.SDK_INT);put(receipt,"started_wall_ms",System.currentTimeMillis());
            put(receipt,"started_elapsed_ms",SystemClock.elapsedRealtime());
            put(receipt,"ui_automation_flags",UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES);
            put(receipt,"default_ui_automation_used",false);put(receipt,"automatic_retry",false);
            enabledBefore=enabledServices();put(receipt,"enabled_services_before",enabledBefore);

            // This is the only acquisition. No no-argument helper, flag 0,
            // UiDevice, shell identity, settings mutation or app launch exists.
            UiAutomation automation=getUiAutomation(UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES);
            if(automation==null)throw new IllegalStateException("UiAutomation connection failed; no flag fallback");
            first=scan(automation);
            put(receipt,"first",first.metadata());
            long screenshotAt=SystemClock.elapsedRealtime();screenshot=automation.takeScreenshot();
            if(screenshot==null)throw new IllegalStateException("screenshot unavailable; no protected-content fallback");
            put(receipt,"screenshot_requested_elapsed_ms",screenshotAt);
            put(receipt,"screenshot_returned_elapsed_ms",SystemClock.elapsedRealtime());
            put(receipt,"screenshot_width",screenshot.getWidth());put(receipt,"screenshot_height",screenshot.getHeight());
            second=scan(automation);put(receipt,"second",second.metadata());
            boolean sameWindow=first.sameWindow(second),sameTree=first.treeSha.equals(second.treeSha);
            put(receipt,"window_stable_across_screenshot",sameWindow);
            put(receipt,"tree_stable_across_screenshot",sameTree);
            put(receipt,"snapshot_is_atomic",false);
            put(receipt,"stop_eligible",second.eligible());

            if("click_stop".equals(mode)){
                if(!sameWindow||!sameTree)throw new IllegalStateException("screen changed across observation; no click");
                if(!second.eligible())throw new IllegalStateException("need exact Hepta foreground and one visible enabled clickable Stop Button in a complete tree");
                AccessibilityNodeInfo button=second.stops.get(0);
                String before=signature(button);Rect targetBounds=new Rect();button.getBoundsInScreen(targetBounds);
                JSONObject intent=new JSONObject().put("action","ACTION_CLICK").put("target_package",TARGET)
                        .put("window_id",second.windowId).put("text","停止").put("class",BUTTON_CLASS)
                        .put("bounds",bounds(targetBounds)).put("candidate_count",second.stops.size())
                        .put("only_one_attempt",true).put("prepared_elapsed_ms",SystemClock.elapsedRealtime());
                writeNew(directory,"click-intent.json",intent.toString(2).getBytes(StandardCharsets.UTF_8));

                // Refresh after evidence I/O, then re-check the active window.
                if(!button.refresh()||!isStop(button)||!before.equals(signature(button)))
                    throw new IllegalStateException("Stop target changed before action; no click");
                long targetFreshAt=SystemClock.elapsedRealtime();
                AccessibilityNodeInfo active=automation.getRootInActiveWindow();
                try{
                    if(active==null||!active.refresh()||!second.sameWindow(active))
                        throw new IllegalStateException("active window changed before action; no click");
                }finally{if(active!=null)active.recycle();}
                if(SystemClock.elapsedRealtime()-targetFreshAt>MAX_TARGET_AGE_MS)
                    throw new IllegalStateException("fresh target check exceeded time bound; no click");
                put(receipt,"target_fresh_elapsed_ms",targetFreshAt);
                put(receipt,"action_attempt_elapsed_ms",SystemClock.elapsedRealtime());
                actionAttempted=true;
                actionAccepted=button.performAction(AccessibilityNodeInfo.ACTION_CLICK);
                actionReturned=true;
                put(receipt,"status",actionAccepted?"stop_click_accepted":"stop_click_not_accepted");
            }else put(receipt,"status",second.eligible()?"observed_stop_target":"observed_no_eligible_stop_target");
            completed=true;
        }catch(Throwable error){put(receipt,"status",actionAttempted?"error_after_action_attempt":"observation_rejected");put(receipt,"error",error.getClass().getSimpleName()+": "+String.valueOf(error.getMessage()));}
        finally{
            put(receipt,"action_attempted",actionAttempted);put(receipt,"action_call_returned",actionReturned);put(receipt,"action_accepted",actionAccepted);
            put(receipt,"finished_elapsed_ms",SystemClock.elapsedRealtime());put(receipt,"finished_wall_ms",System.currentTimeMillis());
            String enabledAfter=enabledServices();put(receipt,"enabled_services_after",enabledAfter);
            put(receipt,"enabled_services_setting_unchanged",enabledBefore!=null&&enabledBefore.equals(enabledAfter));
            put(receipt,"setting_equality_proves_service_connection_unchanged",false);
            put(receipt,"model_exit_verified",false);put(receipt,"late_phone_effects_verified",false);
            if(directory!=null){
                try{
                    if(first!=null)writeNew(directory,"ui-before.json",first.json().toString(2).getBytes(StandardCharsets.UTF_8));
                    if(second!=null)writeNew(directory,"ui-fresh.json",second.json().toString(2).getBytes(StandardCharsets.UTF_8));
                    if(screenshot!=null){
                        File image=new File(directory,"screen.png");
                        if(!image.createNewFile())throw new IllegalStateException("screenshot file already exists");
                        try(FileOutputStream out=new FileOutputStream(image)){if(!screenshot.compress(Bitmap.CompressFormat.PNG,100,out))throw new IllegalStateException("PNG encoding failed");out.getFD().sync();}
                        put(receipt,"screenshot_sha256",fileSha(image));
                    }
                    writeNew(directory,"receipt.json",receipt.toString(2).getBytes(StandardCharsets.UTF_8));
                }catch(Throwable evidenceError){completed=false;put(receipt,"evidence_error",String.valueOf(evidenceError));}
            }
            if(first!=null)first.close();if(second!=null)second.close();if(screenshot!=null)screenshot.recycle();
            Bundle result=new Bundle();result.putString("receipt",receipt.toString());
            result.putString("evidence_directory",directory==null?"":directory.getPath());
            // Ending this instrumentation affects only the separate observer package.
            finish(completed?Activity.RESULT_OK:Activity.RESULT_CANCELED,result);
        }
    }
    private String enabledServices(){
        try{return Settings.Secure.getString(getTargetContext().getContentResolver(),Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);}
        catch(Throwable ignored){return null;}
    }
    private static final class Snapshot {
        String packageName,treeSha;int windowId;Rect windowBounds;long started,finished;boolean truncated;
        final JSONArray nodes=new JSONArray();final List<AccessibilityNodeInfo> stops=new ArrayList<AccessibilityNodeInfo>();
        boolean eligible(){return TARGET.equals(packageName)&&!truncated&&finished-started<=MAX_SCAN_MS&&stops.size()==1;}
        boolean sameWindow(Snapshot other){return windowId==other.windowId&&packageName.equals(other.packageName)&&windowBounds.equals(other.windowBounds);}
        boolean sameWindow(AccessibilityNodeInfo root){Rect r=new Rect();root.getBoundsInScreen(r);return windowId==root.getWindowId()&&packageName.equals(text(root.getPackageName()))&&windowBounds.equals(r);}
        JSONObject metadata()throws Exception{return new JSONObject().put("package",packageName).put("window_id",windowId).put("bounds",bounds(windowBounds))
                .put("tree_sha256",treeSha).put("nodes",nodes.length()).put("truncated",truncated).put("stop_candidates",stops.size())
                .put("scan_started_elapsed_ms",started).put("scan_finished_elapsed_ms",finished);}
        JSONObject json()throws Exception{return metadata().put("node_content_is_untrusted",true).put("nodes",nodes);}
        void close(){for(AccessibilityNodeInfo node:stops)node.recycle();stops.clear();}
    }
    private static Snapshot scan(UiAutomation automation)throws Exception{
        Snapshot result=new Snapshot();result.started=SystemClock.elapsedRealtime();
        ArrayDeque<AccessibilityNodeInfo> queue=new ArrayDeque<AccessibilityNodeInfo>();
        AccessibilityNodeInfo root=automation.getRootInActiveWindow();
        if(root==null)throw new IllegalStateException("no active root");
        try{
            if(!root.refresh())throw new IllegalStateException("active root refresh failed");
            result.packageName=text(root.getPackageName());result.windowId=root.getWindowId();result.windowBounds=new Rect();root.getBoundsInScreen(result.windowBounds);
            if(result.packageName.isEmpty()||result.windowBounds.isEmpty())throw new IllegalStateException("active window identity unavailable");
            queue.add(root);root=null;
            while(!queue.isEmpty()&&result.nodes.length()<MAX_NODES){
                AccessibilityNodeInfo node=queue.removeFirst();
                try{
                    if(!node.refresh())throw new IllegalStateException("node changed during fresh tree read");
                    Rect r=new Rect();node.getBoundsInScreen(r);
                    JSONObject row=new JSONObject().put("package",text(node.getPackageName())).put("window_id",node.getWindowId())
                            .put("class",text(node.getClassName())).put("text",node.isPassword()?"<password>":limited(text(node.getText()),512))
                            .put("description",node.isPassword()?"<password>":limited(text(node.getContentDescription()),512)).put("view_id",text(node.getViewIdResourceName()))
                            .put("bounds",bounds(r)).put("visible",node.isVisibleToUser()).put("enabled",node.isEnabled()).put("clickable",node.isClickable())
                            .put("checked",node.isChecked()).put("selected",node.isSelected());
                    result.nodes.put(row);
                    if(isStop(node)&&node.getWindowId()==result.windowId&&result.windowBounds.contains(r))result.stops.add(AccessibilityNodeInfo.obtain(node));
                    int count=node.getChildCount(),room=MAX_NODES-result.nodes.length()-queue.size();
                    if(count>room){result.truncated=true;count=Math.max(0,room);}
                    for(int i=0;i<count;i++){AccessibilityNodeInfo child=node.getChild(i);if(child!=null)queue.addLast(child);else result.truncated=true;}
                }finally{node.recycle();}
                if(SystemClock.elapsedRealtime()-result.started>MAX_SCAN_MS){result.truncated=true;break;}
            }
            if(!queue.isEmpty())result.truncated=true;
            result.treeSha=sha(result.nodes.toString().getBytes(StandardCharsets.UTF_8));result.finished=SystemClock.elapsedRealtime();return result;
        }catch(Throwable error){result.close();throw error;}
        finally{if(root!=null)root.recycle();while(!queue.isEmpty())queue.removeFirst().recycle();}
    }
    private static boolean isStop(AccessibilityNodeInfo node){
        Rect r=new Rect();node.getBoundsInScreen(r);
        if(!TARGET.equals(text(node.getPackageName()))||!BUTTON_CLASS.equals(text(node.getClassName()))||!"停止".equals(text(node.getText()))
                ||!node.isVisibleToUser()||!node.isEnabled()||!node.isClickable()||node.isPassword()||r.isEmpty())return false;
        for(AccessibilityNodeInfo.AccessibilityAction action:node.getActionList())if(action.getId()==AccessibilityNodeInfo.ACTION_CLICK)return true;
        return false;
    }
    private static String signature(AccessibilityNodeInfo node){Rect r=new Rect();node.getBoundsInScreen(r);return text(node.getPackageName())+"|"+node.getWindowId()+"|"+text(node.getClassName())+"|"+text(node.getText())+"|"+r+"|"+node.isVisibleToUser()+"|"+node.isEnabled()+"|"+node.isClickable();}
    private static JSONArray bounds(Rect r){return new JSONArray().put(r.left).put(r.top).put(r.right).put(r.bottom);}
    private static String text(CharSequence value){return value==null?"":value.toString();}
    private static String limited(String value,int max){if(value.length()<=max)return value;int end=max;if(Character.isHighSurrogate(value.charAt(end-1)))end--;return value.substring(0,end)+"…";}
    private static void put(JSONObject value,String key,Object item){try{value.put(key,item==null?JSONObject.NULL:item);}catch(Exception ignored){}}
    private static void writeNew(File directory,String name,byte[] data)throws Exception{File file=new File(directory,name);if(!file.createNewFile())throw new IllegalStateException("evidence file already exists: "+name);try(FileOutputStream out=new FileOutputStream(file)){out.write(data);out.getFD().sync();}}
    private static String sha(byte[] bytes)throws Exception{MessageDigest digest=MessageDigest.getInstance("SHA-256");return hex(digest.digest(bytes));}
    private static String fileSha(File file)throws Exception{MessageDigest digest=MessageDigest.getInstance("SHA-256");try(FileInputStream in=new FileInputStream(file)){byte[] data=new byte[32768];int n;while((n=in.read(data))!=-1)digest.update(data,0,n);}return hex(digest.digest());}
    private static String hex(byte[] bytes){StringBuilder out=new StringBuilder();for(byte b:bytes)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();}
}
