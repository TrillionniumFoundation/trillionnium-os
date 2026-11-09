package org.trillionnium.hepta.local;

import java.util.LinkedHashMap;
import java.util.Map;

/** A compact view of one existing controller history row; never infers success. */
public final class RecentActionProjection {
    private RecentActionProjection() {}

    public static Map<String,Object> project(Map<String,Object> entry) {
        if (entry == null) throw new IllegalArgumentException("History row required");
        Map<String,Object> result = new LinkedHashMap<String,Object>();
        copy(entry,result,"step");
        copy(entry,result,"action");
        copy(entry,result,"action_rejected");
        // Preserve the existing field's value and meaning, including its use as
        // the observation package for non-open actions. Do not relabel it here.
        copy(entry,result,"target_package");
        copy(entry,result,"before_package");
        Object action = entry.get("action");
        if ("click".equals(action) || "type".equals(action) || "scroll".equals(action)) {
            copy(entry,result,"node_label");
        }
        if ("type".equals(action) && entry.containsKey("type_text")) {
            Object value = entry.get("type_text");
            if (value instanceof String) {
                String text = (String)value;
                result.put("type_text",limited(text,80));
                result.put("type_text_truncated",Boolean.valueOf(text.length()>80));
            } else {
                // Preserve explicit unknown/null, without inventing a complete
                // text flag. JSONObject.NULL is deliberately kept as an object.
                result.put("type_text",value);
            }
        }
        copy(entry,result,"dispatched");
        copy(entry,result,"package_after");
        // Every real after-observation can establish these, including read-only
        // discovery and waits. False, null and absence remain distinct.
        copy(entry,result,"window_changed");
        copy(entry,result,"ime_visible_before");
        copy(entry,result,"ime_visible_after");
        if ("open".equals(action)) copy(entry,result,"exact_package_match");
        if ("find_app".equals(action)) {
            copy(entry,result,"query");
            copy(entry,result,"offset");
            copy(entry,result,"read_only");
        }
        if (entry.containsKey("detail")) {
            Object detail=entry.get("detail");
            result.put("detail",detail instanceof String?limited((String)detail,48):detail);
        }
        return result;
    }

    /** Only confirmed dispatched rows, in caller order; no inferred progress or completion. */
    public static Map<String,Object> dispatched(Map<String,Object> entry) {
        if(entry==null)throw new IllegalArgumentException("History row required");
        if(!Boolean.TRUE.equals(entry.get("dispatched")))return null;
        Map<String,Object> result=new LinkedHashMap<String,Object>();
        copy(entry,result,"step");copy(entry,result,"action");copy(entry,result,"target_package");
        copy(entry,result,"before_package");
        // Rename only an actually observed after-package; never infer it from the action or target.
        if(entry.containsKey("package_after"))result.put("after_package",entry.get("package_after"));
        Object action=entry.get("action");
        if("click".equals(action)||"type".equals(action)||"scroll".equals(action))copy(entry,result,"node_label");
        if("scroll".equals(action))copy(entry,result,"direction");
        if("type".equals(action)&&entry.containsKey("type_text")){
            Object value=entry.get("type_text");
            if(value instanceof String){
                String text=(String)value;
                result.put("type_text",limited(text,80));
                result.put("type_text_truncated",Boolean.valueOf(text.length()>80));
            }else result.put("type_text",value);
        }
        return result;
    }


    public static final String SEQUENCE_SCHEMA="hepta.dispatched-sequence.v2";
    public static final java.util.List<String> SEQUENCE_COLUMNS=java.util.Collections.unmodifiableList(
            java.util.Arrays.asList("step","action","target_package","before_package","after_package","details"));

    /** A lossless package dictionary for the bounded suffix of actual dispatched rows. */
    public static final class CompactSequence {
        public final java.util.List<Object> packages;
        public final java.util.List<java.util.List<Object>> rows;
        public final int observed,omitted;
        private CompactSequence(java.util.List<Object> packages,java.util.List<java.util.List<Object>> rows,int observed) {
            this.packages=java.util.Collections.unmodifiableList(new java.util.ArrayList<Object>(packages));
            this.rows=java.util.Collections.unmodifiableList(new java.util.ArrayList<java.util.List<Object>>(rows));
            this.observed=observed;this.omitted=observed-rows.size();
        }
    }

    /**
     * Package indices are references to actual values, never inferred destinations.
     * Missing base columns are null with their indices in details.absent_columns;
     * explicit null package values remain dictionary values and are not absence.
     */
    public static CompactSequence compactDispatched(java.util.List<Map<String,Object>> history,int maximumRows) {
        if(history==null||maximumRows<0)throw new IllegalArgumentException("History and nonnegative limit required");
        java.util.List<Map<String,Object>> effects=new java.util.ArrayList<Map<String,Object>>();
        for(Map<String,Object> entry:history){
            Map<String,Object> effect=dispatched(entry);
            if(effect!=null)effects.add(effect);
        }
        java.util.List<Object> packages=new java.util.ArrayList<Object>();
        java.util.List<java.util.List<Object>> rows=new java.util.ArrayList<java.util.List<Object>>();
        for(int i=Math.max(0,effects.size()-maximumRows);i<effects.size();i++){
            Map<String,Object> effect=effects.get(i);
            java.util.List<Object> row=new java.util.ArrayList<Object>();
            java.util.List<Integer> absent=new java.util.ArrayList<Integer>();
            for(int column=0;column<5;column++){
                String key=SEQUENCE_COLUMNS.get(column);
                if(!effect.containsKey(key)){
                    row.add(null);absent.add(Integer.valueOf(column));
                }else{
                    Object value=effect.get(key);
                    if(column>=2){
                        int index=packages.indexOf(value);
                        if(index<0){index=packages.size();packages.add(value);}
                        row.add(Integer.valueOf(index));
                    }else row.add(value);
                }
            }
            Map<String,Object> details=new LinkedHashMap<String,Object>();
            for(String key:new String[]{"node_label","direction","type_text","type_text_truncated"})copy(effect,details,key);
            if(!absent.isEmpty())details.put("absent_columns",java.util.Collections.unmodifiableList(absent));
            row.add(java.util.Collections.unmodifiableMap(details));
            rows.add(java.util.Collections.unmodifiableList(row));
        }
        return new CompactSequence(packages,rows,effects.size());
    }

    private static void copy(Map<String,Object> from,Map<String,Object> to,String key) {
        if (from.containsKey(key)) to.put(key,from.get(key));
    }

    private static String limited(String text,int maximum) {
        if (text.length()<=maximum) return text;
        int end=maximum;
        if (end>0 && Character.isHighSurrogate(text.charAt(end-1))) end--;
        return text.substring(0,end)+"…";
    }
}
