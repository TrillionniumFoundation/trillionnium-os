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
