package org.trillionnium.hepta.local;
import java.lang.reflect.*;import org.json.*;import org.trillionnium.hepta.webprotocol.*;
/** Synthetic constructor-boundary ownership tests, not formal capture or native authority.
 * Retained gates and separate exact-original replay exercise the real verify entry point. */
public final class ReceiptReuseHostTest {
 static int assertions,cases;static Method reuse;
 static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
 static JSONObject dom()throws Exception{
  JSONObject node=new JSONObject().put("path","0").put("parent_path",JSONObject.NULL);
  for(String k:new String[]{"tag","id","name","role","aria_label","aria_hidden","aria_modal","aria_selected","aria_checked","aria_pressed","text","item_type","item_prop"})node.put(k,"");
  node.put("tag","body");
  for(String k:new String[]{"visible_in_viewport","disabled","hidden_attr","inert_attr","item_scope","iframe_contents_read"})node.put(k,false);
  for(String k:new String[]{"href_raw","href_resolved","link_target","value","aria_disabled"})node.put(k,JSONObject.NULL);
  node.put("rect_css_pixels",new JSONArray(new int[]{0,0,1,1}));
  return new JSONObject().put("schema",WebDomStability.DOM_SCHEMA).put("ready_state","complete")
    .put("truncated",false).put("truncation_reasons",new JSONArray()).put("visited",1).put("nodes",new JSONArray().put(node));
 }
 static WebEvidenceReceipt fixture(String task)throws Exception{
  String d=dom().toString();WebDomStability.Result stability=WebDomStability.evaluate(d,d,"csair_public_flight_v1");
  JSONObject binding=new JSONObject().put("task_id",task).put("nested",new JSONObject().put("display_id",17));
  JSONObject capture=new JSONObject().put("binding",binding).put("current_native_url","https://m.csair.com/")
    .put("dom_sha256",WebEvidenceJson.sha(d)).put("before_dom_sha256",WebEvidenceJson.sha(d))
    .put("dom_raw_utf8",d).put("before_dom_raw_utf8",d).put("started_elapsed_ms",1).put("ended_elapsed_ms",2)
    .put("navigation_epoch",1).put("capture_geometry",new JSONObject().put("bounds",new JSONArray(new int[]{0,0,100,100})))
    .put("dom_stability",stability.evidence()).put("dom_stability_sha256",WebDomCanonical.sha256(stability.evidence()));
  String raw=new JSONObject().put("synthetic_constructor_fixture",true).put("capture",capture).toString();
  JSONObject callback=new JSONObject().put("status","captured").put("binding_sha256",WebEvidenceBinding.sha256(binding))
    .put("webview_instance","00000000-0000-0000-0000-000000000001").put("navigation_epoch",1)
    .put("actual_display_id",17).put("actual_window_id",19).put("raw_sha256",WebEvidenceJson.sha(raw));
  Constructor<WebEvidenceReceipt> factory=WebEvidenceReceipt.class.getDeclaredConstructor(JSONObject.class,String.class,String.class,String.class,
    boolean.class,boolean.class,WebDomStability.Result.class,JSONObject.class);factory.setAccessible(true);
  return factory.newInstance(callback,raw,capture.toString(),d,false,false,stability,null);
 }
 static Object invoke(WebEvidenceReceipt receipt,JSONObject candidate)throws Exception{return reuse.invoke(receipt,candidate);}
 static void rejected(WebEvidenceReceipt receipt,JSONObject changed,String name)throws Exception{
  boolean refused=false;try{invoke(receipt,changed);}catch(InvocationTargetException e){refused=e.getCause() instanceof IllegalArgumentException;}
  check(refused,name+" reused a changed capture");cases++;
 }
 public static void main(String[] args)throws Exception{
  reuse=WebEvidenceReceipt.class.getDeclaredMethod("verifiedStability",JSONObject.class);reuse.setAccessible(true);
  WebEvidenceReceipt receipt=fixture("00000000000000000000000000000001"),other=fixture("00000000000000000000000000000002");
  JSONObject copy=receipt.capture();String original=WebDomCanonical.canonical(copy);
  check(invoke(receipt,copy)==receipt.stability(),"exact own proof was not reused");cases++;
  for(String key:new String[]{"dom_raw_utf8","before_dom_raw_utf8","dom_sha256","before_dom_sha256","current_native_url"}){
   JSONObject changed=receipt.capture();changed.put(key,changed.getString(key)+"x");rejected(receipt,changed,key);}
  for(String key:new String[]{"started_elapsed_ms","ended_elapsed_ms","navigation_epoch"}){
   JSONObject changed=receipt.capture();changed.put(key,changed.getLong(key)+1);rejected(receipt,changed,key);}
  JSONObject changed=receipt.capture();changed.getJSONObject("binding").put("task_id","foreign");rejected(receipt,changed,"task");
  changed=receipt.capture();changed.getJSONObject("binding").getJSONObject("nested").put("display_id",18);rejected(receipt,changed,"nested display");
  changed=receipt.capture();changed.getJSONObject("capture_geometry").getJSONArray("bounds").put(3,101);rejected(receipt,changed,"nested bounds");
  changed=receipt.capture();changed.getJSONObject("dom_stability").put("business_verified",true);rejected(receipt,changed,"proof fields");
  changed=receipt.capture();changed.remove("dom_sha256");rejected(receipt,changed,"removed field");
  changed=receipt.capture();changed.put("unknown",true);rejected(receipt,changed,"extra field");
  changed=receipt.capture();changed.put("navigation_epoch",1d);rejected(receipt,changed,"integer-to-decimal type change");
  rejected(receipt,other.capture(),"another receipt binding");rejected(receipt,null,"null");
  copy.getJSONObject("binding").getJSONObject("nested").put("display_id",999);
  copy.getJSONObject("capture_geometry").getJSONArray("bounds").put(0,999);
  check(original.equals(WebDomCanonical.canonical(receipt.capture())),"returned-copy mutation escaped");
  check(receipt.beforeDomRaw().equals(receipt.capture().getString("before_dom_raw_utf8")),"immutable before raw changed");cases++;
  JSONObject proof=receipt.stability().evidence();proof.put("grants_action_authority",true);
  check(Boolean.FALSE.equals(receipt.stability().evidence().get("grants_action_authority")),"proof result alias escaped");cases++;
  check(invoke(receipt,receipt.capture())==receipt.stability(),"private proof changed after caller mutations");cases++;
  System.out.println(new JSONObject().put("schema","hepta.receipt-reuse-ownership.v1").put("all_pass",true)
    .put("cases",cases).put("assertions",assertions).put("synthetic_private_constructor_boundary",true)
    .put("formal_receipt_verification_covered_here",false).put("native_freshness_covered_here",false).put("phone_actions",0));
 }
}

