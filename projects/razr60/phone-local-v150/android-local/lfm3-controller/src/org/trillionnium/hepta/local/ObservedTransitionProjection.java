package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Two observed text/window snapshots; no field matching, action authority or inferred progress. */
public final class ObservedTransitionProjection {
    public static final String SCHEMA="hepta.observed-transition.v1";
    private ObservedTransitionProjection() {}

    public static final class Field {
        private final String packageName,nodeId,viewId,text;
        private Field(String packageName,String nodeId,String viewId,String text){
            this.packageName=packageName;this.nodeId=nodeId;this.viewId=viewId;this.text=text;
        }
    }

    /** Only the current app's observed, non-password editable text. Empty text is a value. */
    public static Field field(String observedPackage,String nodePackage,String nodeId,String viewId,String text,
            boolean editable,boolean password){
        if(observedPackage==null||observedPackage.isEmpty())throw new IllegalArgumentException("observed package required");
        if(password||!editable||!observedPackage.equals(nodePackage))return null;
        if(nodeId==null||!nodeId.matches("n[0-9]{1,5}")||viewId==null||text==null)
            throw new IllegalArgumentException("complete observed editable text required");
        return new Field(observedPackage,nodeId,viewId,text);
    }

    public static final class Snapshot {
        private final String observationId,packageName;
        private final Map<String,Object> fields;
        private Snapshot(String observationId,String packageName,Map<String,Object> fields){
            this.observationId=observationId;this.packageName=packageName;this.fields=fields;
        }
    }

    /** Node IDs belong to this snapshot only; equal view IDs are not joined or interpreted. */
    public static Snapshot snapshot(String observationId,String packageName,boolean nodesTruncated,
            String windowTitle,boolean windowTitleTruncated,Boolean imeVisible,List<Field> observed){
        if(observationId==null||!observationId.matches("[0-9a-f]{32}")||packageName==null||packageName.isEmpty()||observed==null)
            throw new IllegalArgumentException("complete observation identity required");
        if(windowTitle==null&&windowTitleTruncated)throw new IllegalArgumentException("unknown title cannot be a truncated title");
        List<Map<String,Object>> values=new ArrayList<Map<String,Object>>();Set<String> ids=new HashSet<String>();
        for(Field field:observed){
            if(field==null||!packageName.equals(field.packageName)||!ids.add(field.nodeId))
                throw new IllegalArgumentException("editable fields must belong to this observation without duplicate IDs");
            Map<String,Object> value=new LinkedHashMap<String,Object>();
            value.put("node_id",field.nodeId);value.put("view_id",field.viewId);value.put("text",field.text);
            values.add(Collections.unmodifiableMap(value));
        }
        Map<String,Object> value=new LinkedHashMap<String,Object>();
        value.put("observation_id",observationId);value.put("package",packageName);
        value.put("nodes_truncated",Boolean.valueOf(nodesTruncated));
        Map<String,Object> window=new LinkedHashMap<String,Object>();
        window.put("title",windowTitle);window.put("title_truncated",Boolean.valueOf(windowTitleTruncated));
        value.put("window",Collections.unmodifiableMap(window));value.put("ime_visible",imeVisible);
        value.put("editable_fields",Collections.unmodifiableList(values));
        return new Snapshot(observationId,packageName,Collections.unmodifiableMap(value));
    }

    public static final class Transition {
        private final Snapshot after;
        private final Map<String,Object> fields;
        private Transition(Snapshot after,Map<String,Object> fields){this.after=after;this.fields=fields;}

        /** A refreshed observation must not silently reuse a previous snapshot as current. */
        public Map<String,Object> forCurrent(String observationId,String packageName){
            if(!after.observationId.equals(observationId)||!after.packageName.equals(packageName))
                throw new IllegalArgumentException("transition after-observation differs from current screen");
            return fields;
        }
    }

    /** Execution, rejection and unknown flags remain in the complete history row for this step. */
    public static Transition between(int step,Snapshot before,Snapshot after){
        if(step<1||before==null||after==null)throw new IllegalArgumentException("recorded step and two observations required");
        Map<String,Object> value=new LinkedHashMap<String,Object>();
        value.put("schema",SCHEMA);value.put("step",Integer.valueOf(step));
        value.put("before",before.fields);value.put("after",after.fields);
        return new Transition(after,Collections.unmodifiableMap(value));
    }
}
