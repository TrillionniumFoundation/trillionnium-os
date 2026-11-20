package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Lossless scalar table for this task's complete recorded history.
 * Empty cells mean absent fields; Java null remains an explicitly observed null.
 * No row is discarded, summarized, coalesced, or treated as proof of success.
 */
public final class CompactTaskHistory {
    public static final String SCHEMA="hepta.compact-task-history.v1";
    private CompactTaskHistory() {}

    public static Map<String,Object> encode(List<Map<String,Object>> history) {
        if(history==null||history.size()>20)throw new IllegalArgumentException("bounded task history required");
        List<String> columns=new ArrayList<String>();
        Map<String,Integer> counts=new LinkedHashMap<String,Integer>();
        for(Map<String,Object> row:history){
            if(row==null)throw new IllegalArgumentException("history row required");
            for(Map.Entry<String,Object> field:row.entrySet()){
                String key=field.getKey();
                if(key==null||key.isEmpty())throw new IllegalArgumentException("history field name required");
                if(!columns.contains(key))columns.add(key);
                Object value=field.getValue();requireScalar(value);
                if(value instanceof String){String text=(String)value;Integer count=counts.get(text);counts.put(text,count==null?1:count+1);}
            }
        }
        List<String> refs=new ArrayList<String>();
        for(Map.Entry<String,Integer> count:counts.entrySet())
            if(count.getValue().intValue()>1&&count.getKey().getBytes(StandardCharsets.UTF_8).length>=16)refs.add(count.getKey());
        List<List<Object>> rows=new ArrayList<List<Object>>();
        for(Map<String,Object> row:history){
            int end=columns.size();while(end>0&&!row.containsKey(columns.get(end-1)))end--;
            List<Object> cells=new ArrayList<Object>();
            for(int i=0;i<end;i++){
                String key=columns.get(i);
                if(!row.containsKey(key)){cells.add(Collections.emptyList());continue;}
                Object value=row.get(key);int ref=value instanceof String?refs.indexOf(value):-1;
                cells.add(ref<0?value:Collections.singletonList(Integer.valueOf(ref)));
            }
            rows.add(Collections.unmodifiableList(cells));
        }
        Map<String,Object> result=new LinkedHashMap<String,Object>();
        result.put("columns",Collections.unmodifiableList(columns));result.put("refs",Collections.unmodifiableList(refs));
        result.put("rows",Collections.unmodifiableList(rows));return Collections.unmodifiableMap(result);
    }

    /** Decode the exact in-memory encoding for representation contracts. */
    public static List<Map<String,Object>> decode(Map<String,Object> encoded) {
        if(encoded==null||encoded.size()!=3||!encoded.containsKey("columns")||!encoded.containsKey("refs")||!encoded.containsKey("rows"))
            throw new IllegalArgumentException("exact history table required");
        List<?> columns=list(encoded.get("columns")),refs=list(encoded.get("refs")),rows=list(encoded.get("rows"));
        if(rows.size()>20)throw new IllegalArgumentException("bounded task history required");
        List<String> seen=new ArrayList<String>();
        for(Object key:columns){if(!(key instanceof String)||((String)key).isEmpty()||seen.contains(key))throw new IllegalArgumentException("unique column names required");seen.add((String)key);}
        for(Object ref:refs)if(!(ref instanceof String))throw new IllegalArgumentException("string reference required");
        List<Map<String,Object>> result=new ArrayList<Map<String,Object>>();
        for(Object raw:rows){
            List<?> cells=list(raw);if(cells.size()>columns.size())throw new IllegalArgumentException("excess history cells");
            Map<String,Object> row=new LinkedHashMap<String,Object>();
            for(int i=0;i<cells.size();i++){
                Object value=cells.get(i);
                if(value instanceof List<?>){
                    List<?> marker=(List<?>)value;if(marker.isEmpty())continue;
                    if(marker.size()!=1||!(marker.get(0) instanceof Integer))throw new IllegalArgumentException("exact reference index required");
                    int index=((Integer)marker.get(0)).intValue();if(index<0||index>=refs.size())throw new IllegalArgumentException("reference index outside table");
                    value=refs.get(index);
                }else requireScalar(value);
                row.put((String)columns.get(i),value);
            }
            result.add(Collections.unmodifiableMap(row));
        }
        return Collections.unmodifiableList(result);
    }
    private static List<?> list(Object value){if(!(value instanceof List<?>))throw new IllegalArgumentException("history list required");return (List<?>)value;}
    private static void requireScalar(Object value){
        if(value==null||value instanceof String||value instanceof Boolean||value instanceof Byte||value instanceof Short||value instanceof Integer||value instanceof Long)return;
        if(value instanceof Double&&Double.isFinite(((Double)value).doubleValue()))return;
        if(value instanceof Float&&Float.isFinite(((Float)value).floatValue()))return;
        throw new IllegalArgumentException("history field is not a finite scalar");
    }
}
