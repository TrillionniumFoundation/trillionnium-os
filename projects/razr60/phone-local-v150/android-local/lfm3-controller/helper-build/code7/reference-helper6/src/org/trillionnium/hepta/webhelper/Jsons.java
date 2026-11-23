package org.trillionnium.hepta.webhelper;

import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

/** Strict bounded request JSON: rejects duplicate keys, invalid Unicode and floats. */
final class Jsons {
    private Jsons() { }
    static void need(boolean value,String reason){if(!value)throw new IllegalArgumentException(reason);}
    static JSONObject parse(String raw,int max)throws Exception{
        need(raw!=null&&raw.getBytes(StandardCharsets.UTF_8).length<=max,"JSON byte budget");
        return parseBounded(raw,16384,256);
    }
    /** Private, hash-bound evidence has a separate budget; incoming request limits stay unchanged. */
    static JSONObject parseEvidence(String raw,int max)throws Exception{
        need(max>0&&max<=org.trillionnium.hepta.webprotocol.WebEvidenceProtocol.MAX_EVIDENCE_BYTES,"evidence byte budget shape");
        need(raw!=null&&raw.getBytes(StandardCharsets.UTF_8).length<=max,"evidence JSON byte budget");
        return parseBounded(raw,Math.min(max,65536),1024);
    }
    private static JSONObject parseBounded(String raw,int stringBudget,int memberBudget)throws Exception{
        Parser p=new Parser(raw,stringBudget,memberBudget);Object v=p.value(0);p.ws();need(p.at==raw.length()&&v instanceof JSONObject,"one JSON object required");return (JSONObject)v;
    }
    static void keys(JSONObject o,Set<String> expected)throws Exception{
        Set<String> actual=new TreeSet<String>();Iterator<String> it=o.keys();while(it.hasNext())actual.add(it.next());
        need(actual.equals(expected),"exact JSON keys required");
    }
    static String text(JSONObject o,String key)throws Exception{Object v=o.get(key);need(v instanceof String,"string required: "+key);return (String)v;}
    static long number(JSONObject o,String key)throws Exception{Object v=o.get(key);need(v instanceof Integer||v instanceof Long,"integer required: "+key);return ((Number)v).longValue();}
    static int integer(JSONObject o,String key)throws Exception{long n=number(o,key);need(n>=Integer.MIN_VALUE&&n<=Integer.MAX_VALUE,"integer range: "+key);return (int)n;}
    static String sha(byte[] raw)throws Exception{byte[] v=MessageDigest.getInstance("SHA-256").digest(raw);StringBuilder s=new StringBuilder(64);for(byte b:v)s.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return s.toString();}
    static String sha(String value)throws Exception{return sha(value.getBytes(StandardCharsets.UTF_8));}
    static void unicode(String value){for(int i=0;i<value.length();i++){char c=value.charAt(i);need(c!=0,"NUL text refused");if(Character.isHighSurrogate(c))need(++i<value.length()&&Character.isLowSurrogate(value.charAt(i)),"unpaired surrogate");else need(!Character.isLowSurrogate(c),"unpaired surrogate");}}
    private static final class Parser {
        final String raw;final int stringBudget,memberBudget;int at;
        Parser(String raw,int stringBudget,int memberBudget){this.raw=raw;this.stringBudget=stringBudget;this.memberBudget=memberBudget;}
        void ws(){while(at<raw.length()&&" \t\r\n".indexOf(raw.charAt(at))>=0)at++;}
        char take(){need(at<raw.length(),"unexpected JSON end");return raw.charAt(at++);}
        Object value(int depth)throws Exception{
            need(depth<=16,"JSON depth budget");ws();char c=take();
            if(c=='{'){
                JSONObject out=new JSONObject();Set<String> seen=new HashSet<String>();ws();if(at<raw.length()&&raw.charAt(at)=='}'){at++;return out;}
                for(int n=0;;n++){
                    need(n<memberBudget,"object member budget");ws();need(take()=='\"',"quoted object key required");String key=string();need(seen.add(key),"duplicate JSON key");ws();need(take()==':',"object colon required");out.put(key,value(depth+1));ws();char end=take();if(end=='}')return out;need(end==',',"object comma required");
                }
            }
            if(c=='['){JSONArray out=new JSONArray();ws();if(at<raw.length()&&raw.charAt(at)==']'){at++;return out;}for(int n=0;;n++){need(n<memberBudget,"array member budget");out.put(value(depth+1));ws();char end=take();if(end==']')return out;need(end==',',"array comma required");}}
            if(c=='\"')return string();
            if(c=='t'){literal("rue");return Boolean.TRUE;}if(c=='f'){literal("alse");return Boolean.FALSE;}if(c=='n'){literal("ull");return JSONObject.NULL;}
            int start=at-1;need(c=='-'||(c>='0'&&c<='9'),"JSON value invalid");while(at<raw.length()&&raw.charAt(at)>='0'&&raw.charAt(at)<='9')at++;
            String number=raw.substring(start,at);need(number.matches("-?(?:0|[1-9][0-9]*)"),"JSON integer required");return Long.valueOf(number);
        }
        void literal(String suffix){need(raw.startsWith(suffix,at),"JSON literal invalid");at+=suffix.length();}
        String string(){StringBuilder out=new StringBuilder();for(;;){char c=take();if(c=='\"')break;need(c>=0x20,"unescaped string control");if(c=='\\'){char e=take();switch(e){case '\"':case '\\':case '/':out.append(e);break;case 'b':out.append('\b');break;case 'f':out.append('\f');break;case 'n':out.append('\n');break;case 'r':out.append('\r');break;case 't':out.append('\t');break;case 'u':need(at+4<=raw.length(),"short Unicode escape");String h=raw.substring(at,at+4);need(h.matches("[0-9a-fA-F]{4}"),"invalid Unicode escape");out.append((char)Integer.parseInt(h,16));at+=4;break;default:throw new IllegalArgumentException("unknown string escape");}}else out.append(c);need(out.length()<=stringBudget,"string budget");}String s=out.toString();unicode(s);return s;}
    }
}
