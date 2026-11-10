package org.json;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
/** Write-only JSON IO fixture. Admission/projection decisions are production code. */
public final class JSONObject {
    public static final Object NULL=new Object();
    private final Map<String,Object> fields=new LinkedHashMap<String,Object>();
    public JSONObject(){}
    public JSONObject(Map<?,?> values){for(Map.Entry<?,?> item:values.entrySet())fields.put(String.valueOf(item.getKey()),item.getValue()==null?NULL:item.getValue());}
    public JSONObject put(String key,Object value)throws JSONException{
        if(key==null)throw new JSONException("null key");
        if(value==null)fields.remove(key);else fields.put(key,value);return this;
    }
    public Object get(String key)throws JSONException{if(!fields.containsKey(key))throw new JSONException("missing "+key);return fields.get(key);}
    public JSONObject getJSONObject(String key)throws JSONException{
        Object value=get(key);if(value instanceof JSONObject)return (JSONObject)value;
        if(value instanceof Map<?,?>)return new JSONObject((Map<?,?>)value);throw new JSONException("not object");
    }
    public boolean has(String key){return fields.containsKey(key);}
    public boolean isNull(String key){return !has(key)||fields.get(key)==NULL||fields.get(key)==null;}
    public int length(){return fields.size();}
    public Iterator<String> keys(){return fields.keySet().iterator();}
    @Override public String toString(){return encode(fields);}
    static String encode(Object value){
        if(value==null||value==NULL)return "null";
        if(value instanceof String)return quote((String)value);
        if(value instanceof Boolean||value instanceof Number)return value.toString();
        if(value instanceof JSONObject||value instanceof JSONArray)return value.toString();
        if(value instanceof Map<?,?>){
            StringBuilder result=new StringBuilder("{");boolean comma=false;
            for(Map.Entry<?,?> item:((Map<?,?>)value).entrySet()){
                if(comma)result.append(',');comma=true;
                result.append(quote(String.valueOf(item.getKey()))).append(':').append(encode(item.getValue()));
            }
            return result.append('}').toString();
        }
        if(value instanceof Collection<?>)return new JSONArray((Collection<?>)value).toString();
        if(value.getClass().isArray())return new JSONArray(value).toString();
        throw new IllegalArgumentException("unsupported JSON fixture type "+value.getClass());
    }
    private static String quote(String value){
        StringBuilder result=new StringBuilder("\"");
        for(int i=0;i<value.length();i++){
            char c=value.charAt(i);
            switch(c){
                case '"':result.append("\\\"");break;
                case '\\':result.append("\\\\");break;
                case '\b':result.append("\\b");break;
                case '\f':result.append("\\f");break;
                case '\n':result.append("\\n");break;
                case '\r':result.append("\\r");break;
                case '\t':result.append("\\t");break;
                default:
                    if(c<32)result.append(String.format(java.util.Locale.ROOT,"\\u%04x",Integer.valueOf(c)));
                    else result.append(c);
            }
        }
        return result.append('"').toString();
    }
}
