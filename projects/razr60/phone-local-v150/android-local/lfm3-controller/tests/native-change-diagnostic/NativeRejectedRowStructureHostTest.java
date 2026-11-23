package org.trillionnium.hepta.local;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebDomCanonical;
/** Synthetic failure metadata; no actual native rows or authority. */
public final class NativeRejectedRowStructureHostTest {
 static int checks,cases;
 static void ck(boolean b,String s){checks++;if(!b)throw new AssertionError(s);}
 static JSONObject row(String p,int c,int[] r){
  return new JSONObject().put("path",p).put("parent_class","android.view.View").put("package","org.trillionnium.hepta.webhelper")
   .put("window_id",9).put("class","android.view.View").put("view_id","PRIVATE-ID").put("text","PRIVATE-TEXT")
   .put("description","PRIVATE-DESC").put("bounds",new JSONArray(r)).put("visible",true).put("enabled",true)
   .put("clickable",false).put("editable",false).put("password",false).put("scrollable",false).put("focused",false)
   .put("children",c).put("scroll_actions","[]").put("ime_enter","PRIVATE-IME").put("input_sha256",JSONObject.NULL);
 }
 static JSONArray base(){return new JSONArray()
  .put(row("0",3,new int[]{0,0,200,200}).put("class","android.webkit.WebView").put("scrollable",true))
  .put(row("0/0",0,new int[]{5,5,10,10})).put(row("0/1",0,new int[]{100,100,150,150}).put("clickable",true))
  .put(row("0/2",0,new int[]{4,4,12,12}).put("clickable",true).put("visible",false).put("enabled",false));}
 static JSONArray cp(JSONArray a){return new JSONArray(a.toString());}
 static JSONObject at(JSONArray a,String p){for(int i=0;i<a.length();i++)if(p.equals(a.getJSONObject(i).get("path")))return a.getJSONObject(i);throw new IllegalArgumentException();}
 static WebNativeObservationChanged fail(JSONArray a,JSONArray b,String p)throws Exception{
  JSONObject d=new JSONObject().put("schema","hepta.native-row-change-diagnostic.v1").put("available",true).put("native_path",p)
   .put("changed_fields",new JSONArray().put("bounds")).put("before_canonical_sha256",WebDomCanonical.sha256(at(a,p)))
   .put("after_canonical_sha256",WebDomCanonical.sha256(at(b,p))).put("contains_page_text",false).put("grants_action_capability",false);
  return new WebNativeObservationChanged("original rejection: ",p,WebDomCanonical.canonical(d));
 }
 static JSONObject get(WebNativeObservationChanged f,JSONArray a,JSONArray b,String t){return new JSONObject(WebNativeObservationChanged.structureAfterFailure(f,a,b,t));}
 public static void main(String[] args)throws Exception{

  JSONArray a=base(),b=cp(a);at(b,"0/0").put("bounds",new JSONArray(new int[]{5,5,11,10}));
  String aa=WebDomCanonical.canonical(a),bb=WebDomCanonical.canonical(b);WebNativeObservationChanged f=fail(a,b,"0/0");
  String message=f.getMessage(),old=f.diagnostic;JSONObject d=get(f,a,b,"0/1"),r=d.getJSONObject("path_and_rectangle_relationship");
  ck(d.getBoolean("available"),"missing metadata");
  ck(d.getJSONObject("failed_row_before").getJSONArray("bounds").toString().equals("[5,5,10,10]")
   &&d.getJSONObject("failed_row_after").getJSONArray("bounds").toString().equals("[5,5,11,10]"),"wrong rectangles");
  ck(d.getJSONObject("failed_row_before").getInt("children")==0&&!r.getBoolean("after_positive_area_intersection")
   &&!r.getBoolean("failure_is_selected_card_ancestor"),"wrong structural relation");
  ck(d.getString("before_canonical_sha256").equals(WebDomCanonical.sha256(at(a,"0/0")))
   &&d.getString("after_canonical_sha256").equals(WebDomCanonical.sha256(at(b,"0/0"))),"row hash mismatch");
  ck(!d.getBoolean("benign_change_verified")&&!d.getBoolean("intersections_prove_occlusion")
   &&!d.getBoolean("grants_action_capability")&&!d.getBoolean("target_dom_native_bridge_verified"),"authority claim");
  ck(d.toString().getBytes("UTF-8").length<=32768,"output cap");cases++;
  JSONObject c=d.getJSONObject("before_overlapping_observed_controls");
  ck(c.getInt("count")==2&&c.getBoolean("samples_complete"),"invisible disabled control filtered");
  JSONObject hidden=c.getJSONArray("samples").getJSONObject(1).getJSONObject("structure");
  ck(!hidden.getBoolean("visible")&&!hidden.getBoolean("enabled"),"control flags lost");
  JSONArray p=base();at(p,"0").put("children",14);
  for(int i=3;i<14;i++)p.put(row("0/"+i,0,new int[]{5,5,10,10}).put("editable",true));
  JSONArray q=cp(p);at(q,"0/0").put("bounds",new JSONArray(new int[]{5,5,11,10}));
  c=get(fail(p,q,"0/0"),p,q,"0/1").getJSONObject("before_overlapping_observed_controls");
  ck(c.getInt("count")==13&&c.getJSONArray("samples").length()==8&&!c.getBoolean("samples_complete")&&c.getInt("omitted_count")==5,"sample falsely complete");cases++;
  p=base();q=cp(p);at(q,"0").put("bounds",new JSONArray(new int[]{0,0,201,200}));
  ck(get(fail(p,q,"0"),p,q,"0/1").getJSONObject("path_and_rectangle_relationship").getBoolean("failure_is_selected_card_ancestor"),"ancestor");
  at(p,"0/1").put("children",1);p.put(row("0/1/0",0,new int[]{110,110,115,115}));q=cp(p);
  at(q,"0/1/0").put("bounds",new JSONArray(new int[]{110,110,116,115}));
  ck(get(fail(p,q,"0/1/0"),p,q,"0/1").getJSONObject("path_and_rectangle_relationship").getBoolean("failure_is_selected_card_descendant"),"descendant");cases++;

  p=base();String secret="PRIVATE-SECRET",clazz="PRIVATE-CLASS",digest=new String(new char[64]).replace('\0','f');
  at(p,"0/0").put("class",clazz).put("text",secret).put("description",secret).put("view_id",secret).put("ime_enter",secret).put("input_sha256",digest);
  q=cp(p);at(q,"0/0").put("bounds",new JSONArray(new int[]{5,5,11,10}));JSONObject priv=get(fail(p,q,"0/0"),p,q,"0/1");String raw=priv.toString();
  ck(priv.getBoolean("available")&&!raw.contains("PRIVATE-")&&!raw.contains(digest),"opaque content leaked");
  ck(priv.getJSONObject("failed_row_before").getString("class").equals("other")
   &&priv.getJSONObject("failed_row_before").getString("class_sha256").equals(WebDomCanonical.sha256Utf8(clazz)),"unknown class raw");cases++;
  q=cp(b);at(q,"0/0").put("text","different-snapshot");
  ck(!get(f,a,q,"0/1").getBoolean("available"),"hash mismatch accepted");
  ck(!get(f,a,b,"0/9").getBoolean("available"),"missing target accepted");
  ck(!get(new WebNativeObservationChanged("x","0/2",f.diagnostic),a,b,"0/1").getBoolean("available"),"wrong path");
  ck(!get(new WebNativeObservationChanged("x","0/0","bad-json"),a,b,"0/1").getBoolean("available"),"bad original metadata");cases++;
  JSONArray many=cp(a);while(many.length()<=1024)many.put(row("0/"+many.length(),0,new int[]{0,0,1,1}));
  ck(!get(f,many,b,"0/1").getBoolean("available"),"row cap");
  String deep="0";for(int i=0;i<17;i++)deep+="/0";ck(!get(f,a,b,deep).getBoolean("available"),"depth cap");
  p=new JSONArray().put(row("0",2,new int[]{0,0,200,200}));String l="0",right="0";
  for(int i=0;i<14;i++){l+="/0";right+=i==0?"/1":"/0";p.put(row(l,i==13?0:1,new int[]{5,5,10,10}));p.put(row(right,i==13?0:1,new int[]{100,100,150,150}));}
  q=cp(p);at(q,l).put("bounds",new JSONArray(new int[]{5,5,11,10}));
  ck(!get(fail(p,q,l),p,q,right).getBoolean("available"),"ancestor cap");
  q=cp(b);at(q,"0/2").put("clickable","true");ck(!get(f,a,q,"0/1").getBoolean("available"),"untyped flag");
  q=cp(b);at(q,"0/2").put("bounds",new JSONArray(new int[]{0,0,40000,2}));ck(!get(f,a,q,"0/1").getBoolean("available"),"rect range");
  q=cp(b);at(q,"0/2").put("unexpected_private_field","secret");ck(!get(f,a,q,"0/1").getBoolean("available"),"unknown row field");cases++;

  final long[] clock={1};WebObservationTiming timing=new WebObservationTiming("synthetic",10,()->clock[0]);
  WebObservationTiming.Span span=WebObservationTiming.begin(timing,WebObservationTiming.Phase.NATIVE_DOM_BRACKET,10);
  clock[0]=5;WebObservationTiming.failed(span,f);JSONObject prior=timing.snapshot().getJSONArray("spans").getJSONObject(0);
  clock[0]=50;WebObservationTiming.failureStructure(span,f,a,b,"0/1");
  JSONObject event=timing.snapshot().getJSONArray("spans").getJSONObject(0);
  ck(event.getJSONObject("native_change_structure").getBoolean("available"),"not attached");
  event.remove("native_change_structure");event.put("deadline_exceeded_at_snapshot",prior.get("deadline_exceeded_at_snapshot"));
  ck(WebDomCanonical.same(prior,event),"original failure time/outcome/error changed");
  WebObservationTiming.failureStructure(span,f,a,q,"0/1");
  ck(timing.snapshot().getJSONArray("spans").getJSONObject(0).getJSONObject("native_change_structure").getBoolean("available"),"attachment overwritten");
  ck(f.getMessage().equals(message)&&f.diagnostic.equals(old),"exception mutated");cases++;
  WebObservationTiming clean=new WebObservationTiming("synthetic",100,()->clock[0]);
  WebObservationTiming.Span success=WebObservationTiming.begin(clean,WebObservationTiming.Phase.NATIVE_DOM_BRACKET,100);
  WebObservationTiming.complete(success);WebObservationTiming.failureStructure(success,f,a,b,"0/1");
  ck(!clean.snapshot().getJSONArray("spans").getJSONObject(0).has("native_change_structure"),"success path changed");
  WebObservationTiming.Span other=WebObservationTiming.begin(clean,WebObservationTiming.Phase.NATIVE_READ,100);
  WebObservationTiming.failed(other,f);WebObservationTiming.failureStructure(other,f,a,b,"0/1");
  ck(!clean.snapshot().getJSONArray("spans").getJSONObject(1).has("native_change_structure"),"wrong phase");
  ck(aa.equals(WebDomCanonical.canonical(a))&&bb.equals(WebDomCanonical.canonical(b)),"input mutation");
  d.getJSONObject("failed_row_before").getJSONArray("bounds").put(0,999);
  ck(get(f,a,b,"0/1").getJSONObject("failed_row_before").getJSONArray("bounds").getInt(0)==5,"alias");cases++;
  System.out.println(new JSONObject().put("schema","hepta.native-rejected-row-structure-host.v1").put("all_pass",true)
   .put("cases",cases).put("assertions",checks).put("phone_actions",0).put("synthetic_metadata_only",true)
   .put("native_authority_tested_here",false).put("actual_rejected_native_rows_replayed",false));
 }
}
