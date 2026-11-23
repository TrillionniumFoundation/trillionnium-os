package org.trillionnium.hepta.local;
import java.nio.file.*;import java.lang.reflect.*;import org.json.*;
public final class ShoppingFooterActualReplay {
 static JSONObject read(String path)throws Exception{return new JSONObject(Files.readString(Paths.get(path))).getJSONObject("capture");}
 static JSONObject attempt(JSONObject a,JSONObject b)throws Exception{
  Class<?> c=Class.forName("org.trillionnium.hepta.local.WebShoppingObservationStability$CaptureUse");
  Object selected=null;for(Object v:c.getEnumConstants())if(v.toString().equals("READONLY_OBSERVATION"))selected=v;
  Method m=WebShoppingObservationStability.class.getDeclaredMethod("captureDom",JSONObject.class,JSONObject.class,WebEvidenceReceipt.class,WebEvidenceReceipt.class,c);m.setAccessible(true);
  try{return (JSONObject)m.invoke(null,a,b,null,null,selected);}catch(InvocationTargetException e){throw (Exception)e.getCause();}
 }
 public static void main(String[] args)throws Exception{
  JSONObject headA=read(args[0]),headB=read(args[1]),a=read(args[2]),b=read(args[3]);
  String originalError=null;try{attempt(a,b);}catch(Exception rejected){originalError=rejected.getMessage();}
  if(originalError==null||!originalError.contains("price-only"))throw new AssertionError("original legacy purpose must remain rejected");
  JSONObject originalA=a,originalB=b;a=new JSONObject(a.toString());b=new JSONObject(b.toString());
  String syntheticOwner="查一下小米官网AX3000T的价格";
  ShoppingFooterObservationHost.rebind(a,syntheticOwner);ShoppingFooterObservationHost.rebind(b,syntheticOwner);
  if(!a.getString("before_dom_raw_utf8").equals(originalA.getString("before_dom_raw_utf8"))
   ||!a.getString("dom_raw_utf8").equals(originalA.getString("dom_raw_utf8"))
   ||!b.getString("before_dom_raw_utf8").equals(originalB.getString("before_dom_raw_utf8"))
   ||!b.getString("dom_raw_utf8").equals(originalB.getString("dom_raw_utf8")))throw new AssertionError("actual DOM bytes modified");
  long t=System.nanoTime();JSONObject accepted=attempt(a,b);long elapsed=System.nanoTime()-t;
  boolean strict=WebShoppingObservationStability.supportsCaptures(a,b);if(strict)throw new AssertionError("strict completion entry widened");
  String error=null;try{attempt(headA,headB);}catch(Exception rejected){error=rejected.getMessage();}
  if(error==null||!error.contains("membership"))throw new AssertionError("HEAD membership mutation not rejected: "+error);
  JSONObject scope=accepted.getJSONObject("dom_scope"),footer=scope.getJSONObject("observed_footer_visibility");
  int count=0;JSONArray diffs=scope.getJSONArray("outside_changes");
  for(int i=0;i<diffs.length();i++)if("observed_footer_IMG_visibility_exchange".equals(diffs.getJSONObject(i).get("scope")))count++;
  if(count!=2||footer.getBoolean("grants_action_authority")||footer.getBoolean("business_verified"))throw new AssertionError("wrong scope");
  System.out.println(new JSONObject().put("schema","hepta.footer-actual-dom-replay.v1").put("all_pass",true)
   .put("actual_original_task_accepted",false).put("actual_original_scope_error",originalError)
   .put("synthetic_price_purpose_only",true).put("synthetic_owner",syntheticOwner)
   .put("all_four_actual_DOM_raw_strings_unchanged",true).put("original_capture_blobs_modified",false)
   .put("readonly_dom_scope_accepted_with_synthetic_purpose",true).put("strict_pre_done_dom_entry_accepted",strict)
   .put("earlier_HEAD_pair_error",error).put("observed_footer_change_count",count).put("all_explicit_change_count",diffs.length())
   .put("elapsed_same_process_nanoseconds",elapsed).put("timing_is_not_phone_performance",true)
   .put("footer_proof",footer).put("own_capture_proofs_revalidated",true).put("four_raw_dom_hashes",new JSONArray()
    .put(a.get("before_dom_sha256")).put(a.get("dom_sha256")).put(b.get("before_dom_sha256")).put(b.get("dom_sha256")))
   .put("native_snapshot_or_IPC_verified",false).put("business_verified",false).put("phone_actions",0).toString(2));
 }
}