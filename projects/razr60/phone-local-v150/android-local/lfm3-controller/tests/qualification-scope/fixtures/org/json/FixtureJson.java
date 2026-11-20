package org.json;
import java.util.*;
/** Small IO-only JSON parser, never used by QualificationScope.Config or ActionDecision. */
final class FixtureJson {
 final String s;int p;FixtureJson(String s){this.s=s;}static Object read(String s)throws JSONException{FixtureJson r=new FixtureJson(s);Object v=r.value();r.ws();if(r.p!=s.length())throw new JSONException("trailing");return v;}
 void ws(){while(p<s.length()&&" \t\r\n".indexOf(s.charAt(p))>=0)p++;}
 Object value()throws JSONException{ws();if(p>=s.length())throw new JSONException("eof");char c=s.charAt(p);
  if(c=='"')return string();if(c=='{'){p++;Map<String,Object> m=new LinkedHashMap<String,Object>();ws();if(take('}'))return m;while(true){ws();String k=string();ws();need(':');m.put(k,value());ws();if(take('}'))return m;need(',');}}
  if(c=='['){p++;List<Object> a=new ArrayList<Object>();ws();if(take(']'))return a;while(true){a.add(value());ws();if(take(']'))return a;need(',');}}
  if(s.startsWith("true",p)){p+=4;return Boolean.TRUE;}if(s.startsWith("false",p)){p+=5;return Boolean.FALSE;}if(s.startsWith("null",p)){p+=4;return null;}
  int start=p;while(p<s.length()&&"-+0123456789.eE".indexOf(s.charAt(p))>=0)p++;if(start==p)throw new JSONException("token");String n=s.substring(start,p);try{return n.indexOf('.')>=0||n.indexOf('e')>=0||n.indexOf('E')>=0?Double.valueOf(n):(Object)Long.valueOf(n);}catch(NumberFormatException e){throw new JSONException("number");}}
 String string()throws JSONException{need('"');StringBuilder b=new StringBuilder();while(p<s.length()){char c=s.charAt(p++);if(c=='"')return b.toString();if(c=='\\'){if(p>=s.length())throw new JSONException("escape");char e=s.charAt(p++);switch(e){case '"':c='"';break;case '\\':c='\\';break;case '/':c='/';break;case 'n':c='\n';break;case 'r':c='\r';break;case 't':c='\t';break;case 'b':c='\b';break;case 'f':c='\f';break;case 'u':if(p+4>s.length())throw new JSONException("unicode");try{c=(char)Integer.parseInt(s.substring(p,p+4),16);}catch(NumberFormatException x){throw new JSONException("unicode");}p+=4;break;default:throw new JSONException("escape");}}b.append(c);}throw new JSONException("string");}
 boolean take(char c){if(p<s.length()&&s.charAt(p)==c){p++;return true;}return false;}void need(char c)throws JSONException{if(!take(c))throw new JSONException("expected "+c);}
}
