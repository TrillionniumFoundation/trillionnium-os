package org.trillionnium.hepta.webprotocol;
import org.json.*;import java.util.*;
/** Complete canonical-parse-then-remove remains the unchanged oracle. */
public final class ProjectionParityHostTest {
 static int cases,assertions;
 static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
 static String outcome(JSONObject value,String[] omitted,boolean prior){
  try{JSONObject result;
   if(prior){result=new JSONObject(WebDomCanonical.canonical(value));for(String key:omitted)result.remove(key);}
   else result=WebDomCanonical.without(value,omitted);
   return "value:"+WebDomCanonical.canonical(result);
  }catch(Exception e){return "error:"+e.getClass().getName()+":"+e.getMessage();}
 }
 static void parity(String name,JSONObject value,String...omitted){
  String a=outcome(value,omitted,true),b=outcome(value,omitted,false);check(a.equals(b),name+" differs");cases++;
 }
 static final class OnceNumber extends Number {
  private static final long serialVersionUID=1L;int calls;
  public int intValue(){return 1;}public long longValue(){return 1;}public float floatValue(){return 1;}
  public double doubleValue(){if(++calls!=1)throw new IllegalStateException("original number reread");return 1;}
 }
 static final class BadNumber extends Number {
  private static final long serialVersionUID=1L;
  public int intValue(){return 0;}public long longValue(){return 0;}public float floatValue(){return Float.NaN;}
  public double doubleValue(){return Double.NaN;}
 }
 public static void main(String[] args)throws Exception{
  parity("empty",new JSONObject(),"nodes");parity("null-object",null,"nodes");
  parity("nested",new JSONObject().put("nodes",new JSONArray().put("removed"))
    .put("keep",new JSONObject().put("number",-0.0).put("s","quoted\\\"中文😀")),"nodes","absent","nodes");
  Random random=new Random(184172L);
  for(int i=0;i<600;i++){
   JSONObject object=new JSONObject().put("nodes",CanonicalComparisonParity.random(random,5))
     .put("keep",CanonicalComparisonParity.random(random,5)).put("other",CanonicalComparisonParity.random(random,5));
   parity("seeded",object,"nodes",i%2==0?"other":"absent");parity("none",object);
  }
  for(Object bad:new Object[]{"\uD800","\uDC00",new Object(),new BadNumber(),CanonicalComparisonParity.repeated('x',1048577)})
   parity("bad-omitted-field",new JSONObject().put("nodes",bad).put("keep",1),"nodes");
  Object depth=1;for(int i=0;i<65;i++)depth=new JSONArray().put(depth);
  parity("deep-omitted-field",new JSONObject().put("nodes",depth),"nodes");
  parity("output-overflow-omitted-field",new JSONObject().put("nodes",CanonicalComparisonParity.repeated('\u0001',699051)),"nodes");
  JSONObject object=new JSONObject();for(int i=0;i<4097;i++)object.put("k"+i,i);parity("object-limit",object,"k0");
  JSONArray values=new JSONArray();for(int i=0;i<180001;i++)values.put(0);parity("array-limit-omitted",new JSONObject().put("nodes",values),"nodes");
  JSONObject source=new JSONObject().put("keep",new JSONObject().put("array",new JSONArray().put(1))).put("nodes","private");
  String original=WebDomCanonical.canonical(source);JSONObject detached=WebDomCanonical.without(source,"nodes");
  detached.getJSONObject("keep").getJSONArray("array").put(0,2);check(original.equals(WebDomCanonical.canonical(source)),"projected mutation leaked to source");cases++;
  OnceNumber once=new OnceNumber();JSONObject input=new JSONObject().put("keep",once).put("nodes","discard");
  check(WebDomCanonical.without(input,"nodes").getInt("keep")==1&&once.calls==1,"retained source Number read more than once");cases++;
  OnceNumber omitted=new OnceNumber();WebDomCanonical.without(new JSONObject().put("nodes",omitted),"nodes");
  check(omitted.calls==1,"omitted Number was not fully validated");cases++;
  System.out.println(new JSONObject().put("schema","hepta.canonical-projection-parity.v1").put("all_pass",true)
    .put("cases",cases).put("assertions",assertions).put("original_all_field_validation_preserved",true)
    .put("returned_projection_detached",true).put("phone_actions",0));
 }
}

