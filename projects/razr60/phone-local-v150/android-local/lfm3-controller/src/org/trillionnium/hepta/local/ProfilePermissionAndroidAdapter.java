package org.trillionnium.hepta.local;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.graphics.Rect;
import android.os.Looper;
import android.os.SystemClock;
import android.util.SparseArray;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;
import org.trillionnium.hepta.background.PermissionWindowObservation;
import org.trillionnium.hepta.background.ProfilePermissionTransient;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Dedicated PermissionController reader. No ordinary PhoneObservation or model
 * input is constructed here; the selected business package set stays unchanged.
 * Every retained handle comes from the owned display's actual accessibility tree.
 */
final class ProfilePermissionAndroidAdapter implements AutoCloseable {
    interface Guard { void check()throws Exception; void authority()throws Exception; }
    private final HeptaAccessibilityService service;
    private final BackgroundSession background;
    private final HeptaAccessibilityService.Cancellation cancellation;
    private final long deadline;
    private final Guard guard;
    private final List<AccessibilityNodeInfo> retained=new ArrayList<AccessibilityNodeInfo>();
    private boolean closed;

    ProfilePermissionAndroidAdapter(HeptaAccessibilityService service,BackgroundSession background,
            HeptaAccessibilityService.Cancellation cancellation,long deadline,Guard guard){
        if(service==null||background==null||background.profileTarget()==null||cancellation==null||guard==null)
            throw new IllegalArgumentException("owned profile permission adapter inputs required");
        this.service=service;this.background=background;this.cancellation=cancellation;this.deadline=deadline;this.guard=guard;
    }
    private static void need(boolean ok,String message){if(!ok)throw new IllegalStateException(message);}
    private void check()throws Exception{
        need(Looper.myLooper()!=Looper.getMainLooper(),"permission Binder reads must stay off main");
        need(!closed&&!cancellation.isCancelled()&&SystemClock.elapsedRealtime()<deadline,"permission read retired or expired");
        guard.check();background.requirePermissionPreparationActive();
    }
    private static String string(CharSequence value){return value==null?"":value.toString();}
    private AccessibilityNodeInfo retain(AccessibilityNodeInfo value){
        need(value!=null,"permission accessibility child missing; no partial tree accepted");
        retained.add(value);return value;
    }
    private List<AccessibilityWindowInfo> selectedWindows()throws Exception{
        check();AccessibilityServiceInfo info=service.getServiceInfo();check();
        need(info!=null&&(info.flags&AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS)!=0
                &&(info.flags&AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS)!=0
                &&(info.getCapabilities()&AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT)!=0,
                "permission accessibility capabilities incomplete");
        SparseArray<List<AccessibilityWindowInfo>> all=service.getWindowsOnAllDisplays();
        List<AccessibilityWindowInfo> result=new ArrayList<AccessibilityWindowInfo>();boolean returned=false;
        try{
            check();need(all!=null,"complete permission display window census unavailable");
            List<AccessibilityWindowInfo> selected=all.get(background.displayId());
            need(selected!=null&&!selected.isEmpty()&&selected.size()<=16,"permission window census empty or over bound");
            for(AccessibilityWindowInfo window:selected){
                need(window!=null,"permission window census contains null");
                result.add(AccessibilityWindowInfo.obtain(window));
            }
            returned=true;return result;
        }finally{
            if(all!=null)for(int i=0;i<all.size();i++){
                List<AccessibilityWindowInfo> windows=all.valueAt(i);
                if(windows!=null)for(AccessibilityWindowInfo window:windows)if(window!=null)window.recycle();
            }
            if(!returned)for(AccessibilityWindowInfo window:result)window.recycle();
        }
    }
    private void requireSameWindowCensus(List<ProfilePermissionInitialization.Window> expected)throws Exception{
        List<AccessibilityWindowInfo> current=selectedWindows();
        try{
            need(current.size()==expected.size(),"permission interactive-window census changed during node read");
            Set<Integer> seen=new HashSet<Integer>();
            for(AccessibilityWindowInfo window:current){
                check();ProfilePermissionInitialization.Window match=null;
                for(ProfilePermissionInitialization.Window before:expected)if(before.id==window.getId()){match=before;break;}
                need(match!=null&&seen.add(window.getId())&&match.display==window.getDisplayId()
                        &&match.type==window.getType()&&match.layer==window.getLayer()
                        &&match.active==window.isActive()&&match.focused==window.isFocused()
                        &&match.task==HeptaAccessibilityService.actualProfileAccessibilityTaskId(window),
                        "permission window focus, layer, display or owned task changed during node read");
                AccessibilityNodeInfo root=retain(window.getRoot());check();
                need(root.refresh(),"permission final census root became stale");check();
                need(!root.isPassword()&&root.getWindowId()==match.id&&match.packageName.equals(string(root.getPackageName())),
                        "permission final census package/window identity changed");
            }
        }finally{for(AccessibilityWindowInfo window:current)window.recycle();}
    }
    ProfilePermissionInitialization.Snapshot observe()throws Exception{
        check();guard.authority();check();long started=SystemClock.elapsedRealtime();
        List<AccessibilityWindowInfo> windows=selectedWindows();
        try{
            AccessibilityWindowInfo pc=null;AccessibilityNodeInfo pcRoot=null;
            int task=-1;Set<Integer> ids=new HashSet<Integer>();
            List<ProfilePermissionInitialization.Window> census=new ArrayList<ProfilePermissionInitialization.Window>();
            for(AccessibilityWindowInfo window:windows){
                check();need(window.getDisplayId()==background.displayId()&&background.displayId()>1
                        &&window.getType()==AccessibilityWindowInfo.TYPE_APPLICATION&&ids.add(window.getId()),
                        "permission window type/display/identity differs");
                int actualTask=HeptaAccessibilityService.actualProfileAccessibilityTaskId(window);
                AccessibilityNodeInfo root=retain(window.getRoot());check();
                need(root.refresh(),"permission window root no longer live");check();
                need(root.getWindowId()==window.getId()&&!root.isPassword(),"permission root/window identity differs");
                String pkg=string(root.getPackageName());
                need(ProfilePermissionTransient.PACKAGE.equals(pkg)||background.profileTarget().packageName.equals(pkg),
                        "foreign package on permission preparation display");
                census.add(new ProfilePermissionInitialization.Window(window.getId(),window.getDisplayId(),actualTask,
                        window.getType(),window.getLayer(),pkg,window.isActive(),window.isFocused()));
                if(ProfilePermissionTransient.PACKAGE.equals(pkg)){
                    need(pc==null&&window.isFocused()&&root.isVisibleToUser(),"permission window absent, ambiguous or unfocused");
                    pc=window;pcRoot=root;task=actualTask;
                }
            }
            need(pc!=null&&pcRoot!=null,"owned PermissionController root unavailable");
            PermissionWindowObservation before=background.verifyPermissionWindow(pc.getId(),task,cancellation,deadline);
            check();background.requirePermissionWindow(before,SystemClock.elapsedRealtime());
            // The public window fields and exact Android36 parcel task ID must
            // agree with the authenticated broker's same owned root/leaf proof.
            need(before.displayId==background.displayId()&&before.windowId==pc.getId()&&before.taskId==task,
                    "PermissionController window not in broker-owned profile task");
            for(ProfilePermissionInitialization.Window window:census)
                need(window.task==task,"permission display includes another task");
            List<ProfilePermissionInitialization.Node> nodes=new ArrayList<ProfilePermissionInitialization.Node>();
            List<AccessibilityNodeInfo> queue=new ArrayList<AccessibilityNodeInfo>();queue.add(pcRoot);
            Set<AccessibilityNodeInfo> seen=new HashSet<AccessibilityNodeInfo>();
            for(int index=0;index<queue.size();index++){
                check();need(index<128&&queue.size()<=128,"permission tree exceeds complete node bound");
                AccessibilityNodeInfo node=queue.get(index);
                need(seen.add(node)&&node.refresh(),"permission tree contains stale/duplicate node");check();
                need(!node.isPassword()&&node.getWindowId()==pc.getId()
                        &&ProfilePermissionTransient.PACKAGE.equals(string(node.getPackageName())),
                        "permission node belongs to another identity or protected input");
                Rect bounds=new Rect();node.getBoundsInScreen(bounds);
                List<AccessibilityNodeInfo.AccessibilityAction> actions=node.getActionList();
                boolean click=actions!=null&&actions.contains(AccessibilityNodeInfo.AccessibilityAction.ACTION_CLICK);
                nodes.add(new ProfilePermissionInitialization.Node(node,string(node.getPackageName()),node.getWindowId(),
                        node.getViewIdResourceName(),string(node.getClassName()),string(node.getText()),string(node.getContentDescription()),
                        bounds.flattenToString(),node.isVisibleToUser(),node.isEnabled(),node.isClickable(),click,node.isCheckable(),node.isChecked()));
                int children=node.getChildCount();need(children>=0&&children<=128-queue.size(),"permission child census exceeds bound");
                for(int child=0;child<children;child++){check();queue.add(retain(node.getChild(child)));check();}
                need(children==node.getChildCount(),"permission child census changed during read");
            }
            check();PermissionWindowObservation after=background.verifyPermissionWindow(pc.getId(),task,cancellation,deadline);
            check();background.requirePermissionWindow(after,SystemClock.elapsedRealtime());
            need(before.sameRequest(after)&&before.physicalIdentities.equals(after.physicalIdentities),
                    "permission or physical display identity changed while reading nodes");
            requireSameWindowCensus(census);check();
            return new ProfilePermissionInitialization.Snapshot(after,started,SystemClock.elapsedRealtime(),true,
                    nodes,census,after.physicalIdentities);
        }finally{for(AccessibilityWindowInfo window:windows)window.recycle();}
    }
    boolean clickOrdinaryDeny(ProfilePermissionInitialization.Dispatch dispatch)throws Exception{
        check();ProfilePermissionInitialization.Snapshot immediatelyBefore=observe();check();
        ProfilePermissionInitialization.Node allowed=null;
        for(ProfilePermissionInitialization.Node node:immediatelyBefore.nodes)
            if(node.visible&&ProfilePermissionInitialization.DENY.equals(node.resourceId)){
                need(allowed==null,"ordinary permission deny role is ambiguous");allowed=node;
            }
        need(allowed!=null&&allowed.handle instanceof AccessibilityNodeInfo
                &&ProfilePermissionInitialization.DENY.equals(allowed.resourceId)
                &&retained.contains((AccessibilityNodeInfo)allowed.handle),"permission dispatch did not return a retained ordinary-deny node");
        AccessibilityNodeInfo live=(AccessibilityNodeInfo)allowed.handle;
        check();need(live.refresh(),"permission deny node changed after final complete snapshot");check();
        Rect bounds=new Rect();live.getBoundsInScreen(bounds);
        need(live.getWindowId()==allowed.windowId&&ProfilePermissionTransient.PACKAGE.equals(string(live.getPackageName()))
                &&ProfilePermissionInitialization.DENY.equals(live.getViewIdResourceName())
                &&allowed.className.equals(string(live.getClassName()))
                &&allowed.label.equals(string(live.getText()))&&allowed.contentDescription.equals(string(live.getContentDescription()))
                &&allowed.bounds.equals(bounds.flattenToString())&&live.isVisibleToUser()&&live.isEnabled()&&live.isClickable()
                &&allowed.checkable==live.isCheckable()&&allowed.checked==live.isChecked()
                &&!live.isPassword()&&live.getActionList()!=null
                &&live.getActionList().contains(AccessibilityNodeInfo.AccessibilityAction.ACTION_CLICK),
                "ordinary permission deny target changed before ACTION_CLICK");
        guard.authority();background.requirePermissionWindow(immediatelyBefore.identity,SystemClock.elapsedRealtime());check();
        background.requirePolicyBeforeEffect(cancellation,deadline);
        // The final dispatch gate runs after all potentially blocking platform
        // reads above. It rechecks live owner-choice provenance and cancellation.
        need(dispatch.enter(immediatelyBefore)==allowed,"permission dispatch changed the verified deny node");
        guard.check();
        // The only effect in this class. No root, shell, coordinate, parent-node,
        // global-back, alternative button, grant, or retry path exists.
        return live.performAction(AccessibilityNodeInfo.ACTION_CLICK);
    }
    @Override public void close(){
        if(closed)return;closed=true;
        for(AccessibilityNodeInfo node:retained)node.recycle();retained.clear();
    }
}
