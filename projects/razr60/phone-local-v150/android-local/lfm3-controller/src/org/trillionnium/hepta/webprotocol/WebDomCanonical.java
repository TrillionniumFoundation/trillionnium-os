package org.trillionnium.hepta.webprotocol;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Bounded data canonicalizer for observed DOM geometry only.
 * It does not change the integer-only request/TaskBinding canonical grammar.
 * Numbers use the finite IEEE-754 value produced by the fixed browser observer.
 */
public final class WebDomCanonical {
    private static final int MAX_DEPTH=64,MAX_VALUES=180000,MAX_OUTPUT=4*1024*1024;
    private WebDomCanonical(){}
    public static String canonical(Object value)throws Exception{
        StringBuilder out=new StringBuilder();write(value,out,new int[]{0},0);
        need(out.length()<=MAX_OUTPUT,"bounded completed DOM canonical output");return out.toString();
    }
    public static boolean same(Object left,Object right)throws Exception{
        // Validate the complete left value and then the complete right value, exactly as canonical().
        // These invocation-local immutable tokens never cache task evidence or grant authority.
        ComparisonSnapshot a=comparison(left),b=comparison(right);return a.tokens.equals(b.tokens);
    }
    /** Validate every original value with the same full canonical bounds first.
     * Only then serialize the retained fields. The returned object is detached;
     * omitted nodes still undergo all type, depth, Unicode and output-budget checks. */
    public static JSONObject without(JSONObject value,String... omitted)throws Exception{
        ComparisonSnapshot checked=comparison(value);
        if(value==null)return new JSONObject("null"); // Preserve the original invalid-object rejection.
        java.util.Set<String> excluded=new java.util.HashSet<String>(java.util.Arrays.asList(omitted));
        ProjectionReader reader=new ProjectionReader(checked.tokens);reader.expect(ComparisonTag.OBJECT_START);
        StringBuilder out=new StringBuilder("{");boolean first=true;
        while(reader.peek()!=ComparisonTag.OBJECT_END){
            String key=(String)reader.take();
            if(excluded.contains(key)){reader.value(null);continue;}
            if(!first)out.append(',');first=false;quoted(key,out);out.append(':');reader.value(out);
        }
        reader.expect(ComparisonTag.OBJECT_END);need(reader.at==checked.tokens.size(),"complete checked object projection");
        return new JSONObject(out.append('}').toString());
    }
    public static String sha256(Object value)throws Exception{return sha256Utf8(canonical(value));}
    public static String sha256Utf8(String raw)throws Exception{
        if(raw==null)throw new IllegalArgumentException("raw string required");
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8));
        char[] hex="0123456789abcdef".toCharArray();StringBuilder out=new StringBuilder(64);
        for(byte b:digest)out.append(hex[(b>>>4)&15]).append(hex[b&15]);return out.toString();
    }
    private enum ComparisonTag { NULL, NUMBER, ARRAY_START, ARRAY_END, OBJECT_START, OBJECT_END }
    private static final class ComparisonSnapshot {
        final List<Object> tokens;
        ComparisonSnapshot(List<Object> tokens){this.tokens=Collections.unmodifiableList(tokens);}
    }
    /** Reads only immutable tokens; the original JSONObject and Number values
     * are never read a second time, even for fields retained by the projection. */
    private static final class ProjectionReader {
        final List<Object> tokens;int at;
        ProjectionReader(List<Object> tokens){this.tokens=tokens;}
        Object peek(){return tokens.get(at);}
        Object take(){return tokens.get(at++);}
        void expect(ComparisonTag tag){need(take()==tag,"checked projection token");}
        void value(StringBuilder out){
            Object token=take();
            if(token==ComparisonTag.NULL){if(out!=null)out.append("null");return;}
            if(token==ComparisonTag.NUMBER){String number=(String)take();if(out!=null)out.append(number);return;}
            if(token instanceof Boolean){if(out!=null)out.append(token);return;}
            if(token instanceof String){if(out!=null)quoted((String)token,out);return;}
            if(token==ComparisonTag.ARRAY_START){
                if(out!=null)out.append('[');boolean first=true;
                while(peek()!=ComparisonTag.ARRAY_END){if(out!=null&&!first)out.append(',');first=false;value(out);}
                expect(ComparisonTag.ARRAY_END);if(out!=null)out.append(']');return;
            }
            if(token==ComparisonTag.OBJECT_START){
                if(out!=null)out.append('{');boolean first=true;
                while(peek()!=ComparisonTag.OBJECT_END){
                    String key=(String)take();if(out!=null){if(!first)out.append(',');quoted(key,out);out.append(':');}
                    first=false;value(out);
                }
                expect(ComparisonTag.OBJECT_END);if(out!=null)out.append('}');return;
            }
            throw new IllegalArgumentException("invalid checked projection token");
        }
    }
    private static final class ComparisonBuilder {
        final List<Object> tokens=new ArrayList<Object>();int count;long outputUnits;
        void quotedUnits(String value){
            need(value.length()<=1024*1024,"bounded DOM string");outputUnits++;
            for(int i=0;i<value.length();i++){
                char c=value.charAt(i);
                if(Character.isHighSurrogate(c)){
                    need(i+1<value.length()&&Character.isLowSurrogate(value.charAt(i+1)),"valid DOM Unicode");
                    outputUnits+=2;i++;continue;
                }
                need(!Character.isLowSurrogate(c),"valid DOM Unicode");
                outputUnits+=c=='"'||c=='\\'?2:c<0x20?6:1;
            }
            outputUnits++;
        }
        void value(Object value,int depth)throws Exception{
            need(depth<=MAX_DEPTH&&++count<=MAX_VALUES&&outputUnits<=MAX_OUTPUT,"bounded DOM canonical value");
            if(value==null||value==JSONObject.NULL){outputUnits+=4;tokens.add(ComparisonTag.NULL);return;}
            if(value instanceof Boolean){outputUnits+=value.toString().length();tokens.add(value);return;}
            if(value instanceof String){quotedUnits((String)value);tokens.add(value);return;}
            if(value instanceof Number){
                double number=((Number)value).doubleValue();
                need(Double.isFinite(number)&&Math.abs(number)<=9007199254740991d,"finite safe observed DOM number");
                String normalized=number==0d?"0":new BigDecimal(Double.toString(number)).stripTrailingZeros().toPlainString();
                outputUnits+=normalized.length();tokens.add(ComparisonTag.NUMBER);tokens.add(normalized);return;
            }
            if(value instanceof JSONArray){
                JSONArray array=(JSONArray)value;need(array.length()<=180000,"bounded DOM array");
                outputUnits++;tokens.add(ComparisonTag.ARRAY_START);
                for(int i=0;i<array.length();i++){if(i>0)outputUnits++;value(array.get(i),depth+1);}
                outputUnits++;tokens.add(ComparisonTag.ARRAY_END);return;
            }
            if(value instanceof JSONObject){
                JSONObject object=(JSONObject)value;List<String> keys=new ArrayList<String>();
                Iterator<String> iterator=object.keys();while(iterator.hasNext()){keys.add(iterator.next());need(keys.size()<=4096,"bounded DOM object");}
                Collections.sort(keys);outputUnits++;tokens.add(ComparisonTag.OBJECT_START);
                for(int i=0;i<keys.size();i++){
                    if(i>0)outputUnits++;String key=keys.get(i);quotedUnits(key);tokens.add(key);outputUnits++;
                    value(object.get(key),depth+1);
                }
                outputUnits++;tokens.add(ComparisonTag.OBJECT_END);return;
            }
            throw new IllegalArgumentException("unsupported observed DOM data type");
        }
    }
    private static ComparisonSnapshot comparison(Object value)throws Exception{
        ComparisonBuilder builder=new ComparisonBuilder();builder.value(value,0);
        need(builder.outputUnits<=MAX_OUTPUT,"bounded completed DOM canonical output");
        return new ComparisonSnapshot(builder.tokens);
    }
    private static void write(Object value,StringBuilder out,int[] count,int depth)throws Exception{
        need(depth<=MAX_DEPTH&&++count[0]<=MAX_VALUES&&out.length()<=MAX_OUTPUT,"bounded DOM canonical value");
        if(value==null||value==JSONObject.NULL){out.append("null");return;}
        if(value instanceof Boolean){out.append(value.toString());return;}
        if(value instanceof String){quoted((String)value,out);return;}
        if(value instanceof Number){
            double number=((Number)value).doubleValue();
            need(Double.isFinite(number)&&Math.abs(number)<=9007199254740991d,"finite safe observed DOM number");
            if(number==0d){out.append('0');return;}
            // Double.toString is shared by Android/host Java and normalizes host
            // org.json BigDecimal versus Android org.json Double representation.
            out.append(new BigDecimal(Double.toString(number)).stripTrailingZeros().toPlainString());return;
        }
        if(value instanceof JSONArray){
            JSONArray array=(JSONArray)value;need(array.length()<=180000,"bounded DOM array");
            out.append('[');for(int i=0;i<array.length();i++){if(i>0)out.append(',');write(array.get(i),out,count,depth+1);}out.append(']');return;
        }
        if(value instanceof JSONObject){
            JSONObject object=(JSONObject)value;List<String> keys=new ArrayList<String>();
            Iterator<String> iterator=object.keys();while(iterator.hasNext()){keys.add(iterator.next());need(keys.size()<=4096,"bounded DOM object");}
            Collections.sort(keys);out.append('{');
            for(int i=0;i<keys.size();i++){if(i>0)out.append(',');String key=keys.get(i);quoted(key,out);out.append(':');write(object.get(key),out,count,depth+1);}
            out.append('}');return;
        }
        throw new IllegalArgumentException("unsupported observed DOM data type");
    }
    private static void quoted(String value,StringBuilder out){
        need(value.length()<=1024*1024,"bounded DOM string");out.append('"');
        for(int i=0;i<value.length();i++){
            char c=value.charAt(i);
            if(Character.isHighSurrogate(c)){
                need(i+1<value.length()&&Character.isLowSurrogate(value.charAt(i+1)),"valid DOM Unicode");
                out.append(c).append(value.charAt(++i));continue;
            }
            need(!Character.isLowSurrogate(c),"valid DOM Unicode");
            if(c=='"'||c=='\\')out.append('\\').append(c);
            else if(c<0x20){String h=Integer.toHexString(c);out.append("\\u");for(int n=h.length();n<4;n++)out.append('0');out.append(h);}
            else out.append(c);
        }out.append('"');
    }
    private static void need(boolean value,String message){if(!value)throw new IllegalArgumentException(message);}
}
