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
    public static boolean same(Object left,Object right)throws Exception{return canonical(left).equals(canonical(right));}
    public static String sha256(Object value)throws Exception{return sha256Utf8(canonical(value));}
    public static String sha256Utf8(String raw)throws Exception{
        if(raw==null)throw new IllegalArgumentException("raw string required");
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8));
        char[] hex="0123456789abcdef".toCharArray();StringBuilder out=new StringBuilder(64);
        for(byte b:digest)out.append(hex[(b>>>4)&15]).append(hex[b&15]);return out.toString();
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
