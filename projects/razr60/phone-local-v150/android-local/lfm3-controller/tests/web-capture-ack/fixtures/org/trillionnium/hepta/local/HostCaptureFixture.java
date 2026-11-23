package org.trillionnium.hepta.local;
import org.json.*;import java.lang.reflect.Method;import org.trillionnium.hepta.webprotocol.*;
/** Explicit synthetic browser fixture assembled from retained factory methods; no actual UI evidence. */
public final class HostCaptureFixture {
 public static final String INSTANCE="12345678-1234-1234-1234-123456789012",ANCHOR="0/0/0/0/0";
 static JSONObject invoke(String type,String method)throws Exception{Method m=Class.forName(type).getDeclaredMethod(method);m.setAccessible(true);return (JSONObject)m.invoke(null);}
 public static JSONObject binding()throws Exception{
  JSONObject b=invoke("org.trillionnium.hepta.webhelper.WebScopedNavigationHostTest","binding");
  b.getJSONObject("helper_identity").put("version_code",WebEvidenceProtocol.HELPER_VERSION_CODE).put("uid",10484);
  b.getJSONObject("controller_identity").put("version_code",63).put("uid",10481);
  b.getJSONObject("background").put("display_id",7).put("created_elapsed_ms",500L).put("expires_elapsed_ms",100000L);
  return b;
 }
 public static JSONObject storage(JSONObject b)throws Exception{
  JSONObject s=invoke("org.trillionnium.hepta.local.WebFlightEvidenceHostTest","storage");
  s.put("profile_name",b.getString("storage_profile_name")).put("first_url",b.getString("initial_url"));return s;
 }
 public static JSONObject capture(JSONObject binding,String nonce,long epoch,String url,JSONObject navigation)throws Exception{
  long start=android.os.SystemClock.now,end=start+10;
  JSONObject raw=invoke("org.trillionnium.hepta.local.WebFlightEvidenceHostTest","captured"),c=raw.getJSONObject("capture");
  JSONObject dom=invoke("org.trillionnium.hepta.webhelper.WebScopedNavigationHostTest","dom");dom.put("href",url);
  // Explicit current-observer viewport shape for this synthetic browser. The old scoped fixture intentionally omitted it.
  dom.put("geometry_semantics_verified",false).put("layout_viewport_css_pixels",new JSONArray(new int[]{1280,900}))
   .put("document_scroll_css_pixels",new JSONArray(new int[]{0,0})).put("document_extent_css_pixels",new JSONArray(new int[]{1280,1800}))
   .put("visual_viewport",new JSONObject().put("width",1280).put("height",900).put("offset_left",0).put("offset_top",0).put("page_left",0).put("page_top",0).put("scale",1));
  String d=dom.toString();WebDomStability.Result stable=WebDomStability.evaluate(d,d,binding.getString("site_policy_id"));String ps=WebDomCanonical.sha256(stable.evidence());
  c.put("binding",new JSONObject(binding.toString())).put("challenge",nonce).put("helper_uid",10484).put("helper_pid",123)
   .put("webview_instance",INSTANCE).put("navigation_epoch",epoch).put("current_native_url",url).put("committed_main_frame_url",url)
   .put("commit_elapsed_ms",start-1).put("started_elapsed_ms",start).put("ended_elapsed_ms",end)
   .put("dom_raw_utf8",d).put("dom_sha256",WebEvidenceJson.sha(d)).put("before_dom_raw_utf8",d).put("before_dom_sha256",WebEvidenceJson.sha(d))
   .put("dom_stability",stable.evidence()).put("dom_stability_sha256",ps).put("raw_dom_equal",true).put("comparison_scope",stable.comparisonScope)
   .put("observed_link_navigation",navigation==null?JSONObject.NULL:navigation);
  JSONObject g=c.getJSONObject("capture_geometry");g.put("dom_comparison_scope",stable.comparisonScope).put("dom_stability_sha256",ps).put("dom_equal_across_visual_callback",true);
  JSONArray samples=g.getJSONArray("samples");for(int i=0;i<samples.length();i++)samples.getJSONObject(i).getJSONObject("native").put("sampled_elapsed_ms",start+i+1).put("scale_changed_elapsed_ms",start-1);
  android.os.SystemClock.now=end+1;return c;
 }
 public static JSONObject envelope(JSONObject binding,JSONObject request)throws Exception{
  JSONObject c=capture(binding,request.getString("request_nonce"),7,binding.getString("initial_url"),null);String rq=request.toString();
  return new JSONObject().put("schema",WebEvidenceProtocol.RAW_SCHEMA).put("request_json_utf8",rq).put("request_sha256",WebEvidenceJson.sha(rq))
   .put("binding",binding).put("binding_sha256",WebEvidenceBinding.sha256(binding)).put("controller_identity",binding.get("controller_identity")).put("helper_identity",binding.get("helper_identity"))
   .put("actual_window_id",19).put("capture",c).put("storage_isolation",storage(binding)).put("actor","controller_evidence_capture").put("diagnostic_unbound",false).put("business_verified",false);
 }
 public static JSONObject callback(int code,JSONObject request,JSONObject binding,String status,byte[] raw)throws Exception{
  return new JSONObject().put("schema",WebEvidenceProtocol.CALLBACK_SCHEMA).put("method",WebEvidenceProtocol.method(code)).put("request_nonce",request.get("request_nonce")).put("task_id",binding.get("task_id")).put("controller_session_nonce",binding.get("controller_session_nonce"))
   .put("status",status).put("reason",code==WebEvidenceProtocol.ACK_CAPTURE?WebCaptureAcknowledgement.reason(request):JSONObject.NULL).put("actual_helper_uid",10484).put("actual_display_id",7).put("actual_window_id",19)
   .put("webview_instance",INSTANCE).put("navigation_epoch",7).put("binding_sha256",WebEvidenceBinding.sha256(binding)).put("raw_length",raw==null?0:raw.length).put("raw_sha256",raw==null?JSONObject.NULL:WebEvidenceJson.sha(raw))
   .put("retired",false).put("cleanup",JSONObject.NULL).put("recovery",JSONObject.NULL);
 }
}