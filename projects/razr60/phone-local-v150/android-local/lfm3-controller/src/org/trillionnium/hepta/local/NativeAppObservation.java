package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;

/** Android-side copying of one actual retained observation. No field is read
 * from model output, uiautomator fixtures, a previous task or a screenshot. */
final class NativeAppObservation {
    private NativeAppObservation() {}
    static String selectionSha(BackgroundSession.Selection selection)throws Exception{
        NativeAppEvidence.need(selection!=null,"actual native Selection missing");return NativeAppEvidence.fingerprint(value(selection.json()));
    }
    static NativeAppEvidence.Frame copy(String task,TaskAuthorization.Gate authorization,BackgroundSession background,
            PhoneObservation observed,NotesCompletionEvidence.Frame completion,String originalRecordSha)throws Exception{
        NativeAppEvidence.need(background!=null&&observed!=null&&completion!=null&&task.equals(background.taskId)
                &&authorization!=null&&task.equals(authorization.taskId),"actual native background/task observation required");
        BackgroundSession.Selection selected=background.selection;authorization.authorization.requireCompletionSelection(selected);
        BackgroundTaskTarget target=selected.taskTarget;
        NativeAppEvidence.need(target!=null&&target.nativeGoal!=null&&!target.webHelper()&&target.explicitSelection
                &&background.ownerSha256.equals(target.ownerSha256)&&target.packageName.equals(observed.packageName)
                &&background.generation.equals(observed.backgroundGeneration)&&background.displayId()==completion.displayId
                &&observed.backgroundAllowedPackages.size()==1&&observed.backgroundAllowedPackages.contains(target.packageName)
                &&target.packageName.equals(observed.backgroundBootstrapPackage),"same native lease/package/selection required");
        String expected=selectionSha(selected),actual=NativeAppEvidence.fingerprint(value(observed.backgroundSelectionEvidence()));
        NativeAppEvidence.need(expected.equals(actual),"actual observed native Selection projection differs");
        List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();
        for(PhoneObservation.Node n:observed.nodes){
            String label=n.label();if(n.text.trim().isEmpty()&&n.description.trim().isEmpty()
                    &&!"derived".equals(n.childText.status))label="";
            label=ObservedTargetLabels.project(label);
            nodes.add(new NativeAppEvidence.Node(n.id,n.packageName,n.className,n.viewId,n.text,n.description,
                    n.nativeTreePath,n.nativeParentClass,n.observedAppTreeSignature,label,
                    n.bounds.left,n.bounds.top,n.bounds.right,n.bounds.bottom,n.enabled,n.password,n.clickable,n.editable,n.scrollable,
                    n.selected,n.checkable,n.checked,new TreeSet<String>(n.scrollActions.directions)));
        }
        PhoneObservation.CollectionStats stats=observed.collectionStats;
        boolean complete=stats!=null&&!stats.truncated()&&stats.retained==nodes.size()&&stats.pending==0
                &&stats.childSlotsOmitted==0&&stats.nodeBudgetOmissions==0&&stats.textBudgetOmissions==0;
        return new NativeAppEvidence.Frame(task,target.ownerSha256,target.targetSha256,authorization.authorization.sha256,actual,
                observed.id,observed.packageName,observed.backgroundGeneration,observed.state.appTreeSha256,observed.treeSha256,
                observed.screenshotSha256,originalRecordSha,TaskCompletionGate.webFrameSha(completion),completion.displayId,
                observed.windowId,observed.rotation,observed.width,observed.height,observed.windowBounds.left,observed.windowBounds.top,
                observed.windowBounds.right,observed.windowBounds.bottom,observed.capturedElapsedMillis,observed.nodesTruncated,complete,nodes,
                completion.windowType,completion.metadataObserved);
    }
    private static Object value(Object v)throws Exception{
        if(v==null||v==JSONObject.NULL)return null;
        if(v instanceof JSONObject){Map<String,Object> out=NativeAppEvidence.map();JSONObject o=(JSONObject)v;
            for(java.util.Iterator<String> keys=o.keys();keys.hasNext();){String key=keys.next();out.put(key,value(o.get(key)));}return out;}
        if(v instanceof JSONArray){List<Object> out=new ArrayList<Object>();JSONArray a=(JSONArray)v;for(int i=0;i<a.length();i++)out.add(value(a.get(i)));return out;}
        if(v instanceof String||v instanceof Boolean||v instanceof Integer||v instanceof Long)return v;
        throw new IllegalArgumentException("native Selection has an unsupported actual field");
    }
}
