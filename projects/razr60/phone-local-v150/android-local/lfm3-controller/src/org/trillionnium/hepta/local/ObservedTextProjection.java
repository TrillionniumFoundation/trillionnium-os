package org.trillionnium.hepta.local;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Factual text metadata from one observed node; never a field/result classifier or action grant. */
public final class ObservedTextProjection {
    public static final String SCHEMA="hepta.observed-text-projection.v1";
    public static final String CONTROL_HINT_SCHEMA="hepta.observed-unlabeled-controls.v1";
    public static final String CONTROL_HINT_SOURCE="observed_node_properties_not_labels_or_authority";
    public static final int MAX_CONTROL_HINTS=16,CONTROL_PROPERTY_UTF16_LIMIT=96;
    private ObservedTextProjection() {}

    /** Only caller-selected current action targets with an empty observed label.
     * Resource/class names are untrusted facts, never translated to a UI name or purpose.
     */
    public static Map<String,Object> unlabeledControlHint(String nodeId,String label,String viewId,String className,boolean actionable){
        if(nodeId==null||label==null||viewId==null||className==null)throw new IllegalArgumentException("complete observed control facts required");
        if(!actionable||!label.isEmpty()||(viewId.isEmpty()&&className.isEmpty()))return null;
        Map<String,Object> value=new LinkedHashMap<String,Object>();value.put("node_id",nodeId);
        if(!viewId.isEmpty()){
            value.put("view_id",boundedProperty(viewId));
            if(viewId.length()>CONTROL_PROPERTY_UTF16_LIMIT)value.put("view_id_truncated",true);
        }
        if(!className.isEmpty()){
            value.put("class_name",boundedProperty(className));
            if(className.length()>CONTROL_PROPERTY_UTF16_LIMIT)value.put("class_name_truncated",true);
        }
        return Collections.unmodifiableMap(value);
    }
    private static String boundedProperty(String value){
        if(value.length()<=CONTROL_PROPERTY_UTF16_LIMIT)return value;
        int end=CONTROL_PROPERTY_UTF16_LIMIT;
        if(Character.isHighSurrogate(value.charAt(end-1)))end--;
        return value.substring(0,end)+"…";
    }

    /** Empty editable text is evidence too. Descriptions never replace the observed text value. */
    public static Map<String,Object> project(String nodeId,String text,String description,String viewId,
            int[] bounds,boolean clickable,boolean editable,boolean scrollable,boolean password,
            boolean focused,boolean enabled) {
        if(password)return null;
        if(nodeId==null||text==null||description==null||viewId==null||bounds==null||bounds.length!=4)
            throw new IllegalArgumentException("complete observed text metadata required");
        if(!editable&&(clickable||scrollable||(text.isEmpty()&&description.isEmpty())))return null;
        Map<String,Object> value=new LinkedHashMap<String,Object>();
        value.put("node_id",nodeId);
        value.put("role",editable?"editable_text":"noninteractive_text");
        value.put("text",text);
        if(!description.isEmpty())value.put("description",description);
        value.put("view_id",viewId);
        value.put("bounds",Collections.unmodifiableList(Arrays.asList(bounds[0],bounds[1],bounds[2],bounds[3])));
        if(editable){value.put("focused",Boolean.valueOf(focused));value.put("enabled",Boolean.valueOf(enabled));}
        return Collections.unmodifiableMap(value);
    }

    /** Recomputed after each budget reduction; an omitted node cannot leak through metadata. */
    public static java.util.List<Map<String,Object>> select(java.util.List<Map<String,Object>> observed,
            java.util.Set<String> finalNodeIds,String role,int maximum) {
        if(observed==null||finalNodeIds==null||maximum<0
                ||!("editable_text".equals(role)||"noninteractive_text".equals(role)))
            throw new IllegalArgumentException("valid text projection selection required");
        java.util.List<Map<String,Object>> selected=new java.util.ArrayList<Map<String,Object>>();
        for(Map<String,Object> row:observed) {
            if(selected.size()>=maximum)break;
            if(row==null||!(row.get("node_id") instanceof String))
                throw new IllegalArgumentException("observed text node identity required");
            if(role.equals(row.get("role"))&&finalNodeIds.contains(row.get("node_id")))selected.add(row);
        }
        return Collections.unmodifiableList(selected);
    }
}
