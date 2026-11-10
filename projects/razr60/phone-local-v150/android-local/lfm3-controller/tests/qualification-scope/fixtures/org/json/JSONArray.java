package org.json;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
/** Write-only JSON IO fixture; no model/phone result parser is replaced. */
public final class JSONArray {
    private final List<Object> values=new ArrayList<Object>();
    public JSONArray(){}
    public JSONArray(Collection<?> items){values.addAll(items);}
    public JSONArray(Object items){for(int i=0;i<Array.getLength(items);i++)values.add(Array.get(items,i));}
    public JSONArray put(Object value){values.add(value==null?JSONObject.NULL:value);return this;}
    public int length(){return values.size();}
    public Object get(int i){return values.get(i);}
    public JSONObject getJSONObject(int index)throws JSONException{
        Object value=values.get(index);if(value instanceof JSONObject)return (JSONObject)value;
        if(value instanceof java.util.Map<?,?>)return new JSONObject((java.util.Map<?,?>)value);
        throw new JSONException("not object");
    }
    @Override public String toString(){
        StringBuilder result=new StringBuilder("[");boolean comma=false;
        for(Object value:values){if(comma)result.append(',');comma=true;result.append(JSONObject.encode(value));}
        return result.append(']').toString();
    }
}
