package org.trillionnium.hepta.local;

import java.util.LinkedHashMap;
import java.util.Map;

/** A compact view of one existing controller history row; never infers success. */
public final class RecentActionProjection {
    private RecentActionProjection() {}

    public static final String READABLE_SCHEMA="hepta.readable-action-history.v1";
    private static final String[] READABLE_FIELD_ORDER={
            "step","action","app_label","node_label","node_id","type_text","direction","query","offset","duration_ms",
            "before_package","target_package","package_after","model_issued","accepted","dispatched","stale",
            "window_changed","ime_visible_before","ime_visible_after","exact_package_match","read_only",
            "find_returned","find_matches","find_catalogue_sha256","observation_after","action_rejected","detail"};
    private static final String[] READABLE_BOOLEAN_FIELDS={
            "model_issued","accepted","dispatched","stale","window_changed","ime_visible_before",
            "ime_visible_after","exact_package_match","read_only"};

    /** Complete observed facts, in execution order, without dictionary references or text truncation. */
    public static final class ReadableEvents {
        public final java.util.List<Map<String,Object>> rows;
        public final int observed;
        private ReadableEvents(java.util.List<Map<String,Object>> rows){
            this.rows=java.util.Collections.unmodifiableList(new java.util.ArrayList<Map<String,Object>>(rows));
            observed=rows.size();
        }
    }

    public static ReadableEvents readableEvents(java.util.List<Map<String,Object>> history){
        if(history==null||history.size()>20)throw new IllegalArgumentException("Bounded complete history required");
        java.util.List<Map<String,Object>> rows=new java.util.ArrayList<Map<String,Object>>();
        int previous=0;
        for(Map<String,Object> entry:history){
            if(entry==null||!(entry.get("step") instanceof Integer))throw new IllegalArgumentException("Observed integer step required");
            int step=((Integer)entry.get("step")).intValue();
            if(step<=previous)throw new IllegalArgumentException("History order must be strictly increasing");
            previous=step;
            for(String key:READABLE_BOOLEAN_FIELDS){
                Object value=entry.get(key);
                if(value!=null&&!(value instanceof Boolean))throw new IllegalArgumentException("History status must be boolean or explicit null");
            }
            // The controller records scalar facts. Reject a new unsupported shape instead of
            // silently summarizing it or manufacturing values for absent receipt fields.
            for(Map.Entry<String,Object> field:entry.entrySet()){
                Object value=field.getValue();
                if(field.getKey()==null||!(value==null||value instanceof String||value instanceof Boolean
                        ||value instanceof Integer||value instanceof Long))
                    throw new IllegalArgumentException("History fact must be a named scalar");
            }
            Map<String,Object> row=new LinkedHashMap<String,Object>();
            for(String key:READABLE_FIELD_ORDER)copy(entry,row,key);
            // Preserve any additional recorded scalar facts, rather than silently losing a
            // future controller field. Their stable order keeps prompt/evidence reproducible.
            for(String key:new java.util.TreeSet<String>(entry.keySet()))if(!row.containsKey(key))copy(entry,row,key);
            rows.add(java.util.Collections.unmodifiableMap(row));
        }
        return new ReadableEvents(rows);
    }

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
        if("submit".equals(action))submitFacts(entry,result);
        if ("open".equals(action)) copy(entry,result,"app_label");
        if ("click".equals(action) || "type".equals(action) || "scroll".equals(action) || "submit".equals(action)) {
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
        if("submit".equals(action))submitFacts(entry,result);
        if("open".equals(action))copy(entry,result,"app_label");
        if("click".equals(action)||"type".equals(action)||"scroll".equals(action)||"submit".equals(action))copy(entry,result,"node_label");
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
            for(String key:new String[]{"app_label","node_label","direction","type_text","type_text_truncated","submit_input_sha256","submit_action_label","submit_attempt_id","submit_result","submit_attempt_consumed"})copy(effect,details,key);
            if(!absent.isEmpty())details.put("absent_columns",java.util.Collections.unmodifiableList(absent));
            row.add(java.util.Collections.unmodifiableMap(details));
            rows.add(java.util.Collections.unmodifiableList(row));
        }
        return new CompactSequence(packages,rows,effects.size());
    }


    public static final String EVENT_SCHEMA="hepta.model-events.v1";
    public static final java.util.List<String> EVENT_COLUMNS=java.util.Collections.unmodifiableList(
            java.util.Arrays.asList("step","action","target","from","to","state","arg"));
    public static final java.util.List<String> EVENT_STATE_COLUMNS=java.util.Collections.unmodifiableList(
            java.util.Arrays.asList("model_issued","accepted","dispatched","stale","changed"));
    private static final String[] EVENT_STATE_KEYS={"model_issued","accepted","dispatched","stale","window_changed"};

    /** Complete ordered trace; optional arguments never erase a recorded step. */
    public static final class CompactEvents {
        public final java.util.List<Object> actions,packages;
        public final java.util.List<java.util.List<Object>> states,rows;
        public final java.util.List<Map<String,Object>> arguments;
        public final java.util.List<Integer> detailOmittedSteps;
        public final int observed,detailLevel;
        private CompactEvents(java.util.List<Object> actions,java.util.List<Object> packages,
                java.util.List<java.util.List<Object>> states,java.util.List<java.util.List<Object>> rows,
                java.util.List<Map<String,Object>> arguments,java.util.List<Integer> omitted,int level,int observed){
            this.actions=java.util.Collections.unmodifiableList(new java.util.ArrayList<Object>(actions));
            this.packages=java.util.Collections.unmodifiableList(new java.util.ArrayList<Object>(packages));
            this.states=java.util.Collections.unmodifiableList(new java.util.ArrayList<java.util.List<Object>>(states));
            this.rows=java.util.Collections.unmodifiableList(new java.util.ArrayList<java.util.List<Object>>(rows));
            this.arguments=java.util.Collections.unmodifiableList(new java.util.ArrayList<Map<String,Object>>(arguments));
            detailOmittedSteps=java.util.Collections.unmodifiableList(new java.util.ArrayList<Integer>(omitted));
            detailLevel=level;this.observed=observed;
        }
        public Map<String,Object> jsonFields(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();
            out.put("schema",EVENT_SCHEMA);out.put("columns",EVENT_COLUMNS);
            out.put("actions",actions);out.put("packages",packages);
            out.put("state_columns",EVENT_STATE_COLUMNS);out.put("states",states);
            out.put("args",arguments);out.put("rows",rows);
            out.put("observed",Integer.valueOf(observed));out.put("omitted",Integer.valueOf(0));
            out.put("detail_level",Integer.valueOf(detailLevel));out.put("detail_omitted_steps",detailOmittedSteps);
            return java.util.Collections.unmodifiableMap(out);
        }
    }

    /**
     * All at most twenty controller history rows are retained in original order.
     * Dictionary index -1 is absence; null inside a dictionary is explicit unknown.
     * Detail levels 2/1/0 reduce optional parameters only. Scroll direction remains.
     */
    public static CompactEvents compactEvents(java.util.List<Map<String,Object>> history,int detailLevel){
        if(history==null||history.size()>20||detailLevel<0||detailLevel>2)
            throw new IllegalArgumentException("Bounded history and detail level required");
        java.util.List<Object> actions=new java.util.ArrayList<Object>(),packages=new java.util.ArrayList<Object>();
        java.util.List<java.util.List<Object>> states=new java.util.ArrayList<java.util.List<Object>>(),rows=new java.util.ArrayList<java.util.List<Object>>();
        java.util.List<Map<String,Object>> arguments=new java.util.ArrayList<Map<String,Object>>();
        java.util.List<Integer> omitted=new java.util.ArrayList<Integer>();
        int previous=0;
        for(Map<String,Object> entry:history){
            if(entry==null||!(entry.get("step") instanceof Integer))throw new IllegalArgumentException("Observed integer step required");
            int step=((Integer)entry.get("step")).intValue();
            if(step<=previous)throw new IllegalArgumentException("History order must be strictly increasing");
            previous=step;
            java.util.List<Object> status=new java.util.ArrayList<Object>();
            for(String key:EVENT_STATE_KEYS){
                if(!entry.containsKey(key)){status.add("absent");continue;}
                Object value=entry.get(key);
                if(value!=null&&!(value instanceof Boolean))throw new IllegalArgumentException("History status must be boolean or explicit null");
                status.add(value);
            }
            java.util.List<Object> immutableStatus=java.util.Collections.unmodifiableList(status);
            int state=states.indexOf(immutableStatus);
            if(state<0){state=states.size();states.add(immutableStatus);}
            Map<String,Object> full=eventArguments(entry,2),argument=eventArguments(entry,detailLevel);
            if(!full.equals(argument))omitted.add(Integer.valueOf(step));
            int arg=-1;
            if(!argument.isEmpty()){
                arg=arguments.indexOf(argument);
                if(arg<0){arg=arguments.size();arguments.add(java.util.Collections.unmodifiableMap(argument));}
            }
            java.util.List<Object> row=new java.util.ArrayList<Object>();
            row.add(Integer.valueOf(step));row.add(Integer.valueOf(dictionaryIndex(entry,"action",actions)));
            row.add(Integer.valueOf(dictionaryIndex(entry,"target_package",packages)));
            row.add(Integer.valueOf(dictionaryIndex(entry,"before_package",packages)));
            row.add(Integer.valueOf(dictionaryIndex(entry,"package_after",packages)));
            row.add(Integer.valueOf(state));row.add(Integer.valueOf(arg));
            rows.add(java.util.Collections.unmodifiableList(row));
        }
        return new CompactEvents(actions,packages,states,rows,arguments,omitted,detailLevel,history.size());
    }

    private static int dictionaryIndex(Map<String,Object> entry,String key,java.util.List<Object> dictionary){
        if(!entry.containsKey(key))return -1;
        Object value=entry.get(key);int index=dictionary.indexOf(value);
        if(index<0){index=dictionary.size();dictionary.add(value);}return index;
    }

    private static void submitFacts(Map<String,Object> entry,Map<String,Object> result){
        for(String key:new String[]{"node_label","node_id","submit_input_sha256","submit_action_label","submit_attempt_id","submit_result","submit_attempt_consumed"})
            copy(entry,result,key);
    }

    private static Map<String,Object> eventArguments(Map<String,Object> entry,int level){
        Map<String,Object> result=new LinkedHashMap<String,Object>();
        Object action=entry.get("action");
        if("submit".equals(action))submitFacts(entry,result);
        if("open".equals(action))copy(entry,result,"app_label");
        if("scroll".equals(action))copy(entry,result,"direction");
        if(level>=1&&("click".equals(action)||"type".equals(action)||"scroll".equals(action)))copy(entry,result,"node_label");
        if(level==2&&"type".equals(action)&&entry.containsKey("type_text")){
            Object value=entry.get("type_text");
            if(value instanceof String){
                String text=(String)value;result.put("text",limited(text,80));result.put("text_truncated",Boolean.valueOf(text.length()>80));
            }else result.put("text",value);
        }
        if("find_app".equals(action)){
            if(level>=1)copy(entry,result,"query");
            copy(entry,result,"offset");
            if(entry.containsKey("find_returned"))result.put("returned",entry.get("find_returned"));
            if(level==2){
                if(entry.containsKey("find_matches"))result.put("matches",entry.get("find_matches"));
                if(entry.containsKey("find_catalogue_sha256"))result.put("catalogue_sha256",entry.get("find_catalogue_sha256"));
            }
        }
        return result;
    }

    /** A current result page receives model provenance only after exact identity matching. */
    public static Map<String,Object> discoveryProvenance(java.util.List<Map<String,Object>> history,
            String query,int offset,String catalogueSha){
        if(history==null||query==null||catalogueSha==null)throw new IllegalArgumentException("Catalogue provenance required");
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        for(int i=history.size()-1;i>=0;i--){
            Map<String,Object> e=history.get(i);
            if(!"find_app".equals(e.get("action"))||!Boolean.TRUE.equals(e.get("model_issued"))
                    ||!Boolean.TRUE.equals(e.get("accepted"))||!Boolean.FALSE.equals(e.get("dispatched"))
                    ||!Boolean.FALSE.equals(e.get("stale"))||!Boolean.TRUE.equals(e.get("read_only")))continue;
            boolean match=query.equals(e.get("query"))&&Integer.valueOf(offset).equals(e.get("offset"))
                    &&catalogueSha.equals(e.get("find_catalogue_sha256"))&&e.get("find_returned") instanceof Integer;
            if(!match){out.put("source","unbound");out.put("model_issued",null);return java.util.Collections.unmodifiableMap(out);}
            out.put("source","model_find_app");out.put("model_issued",Boolean.TRUE);copy(e,out,"step");
            out.put("returned",e.get("find_returned"));out.put("catalogue_sha256",catalogueSha);
            return java.util.Collections.unmodifiableMap(out);
        }
        out.put("source","initial_catalogue");out.put("model_issued",Boolean.FALSE);
        return java.util.Collections.unmodifiableMap(out);
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
