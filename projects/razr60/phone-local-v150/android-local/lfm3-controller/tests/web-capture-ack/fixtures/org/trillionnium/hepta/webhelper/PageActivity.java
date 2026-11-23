package org.trillionnium.hepta.webhelper;
import org.json.*;import org.trillionnium.hepta.webprotocol.*;import org.trillionnium.hepta.local.HostCaptureFixture;
/** Only Android WebView/renderer callbacks are synthetic. No raw evidence path is available to this fixture. */
final class PageActivity {
 final JSONObject binding;final String instance;final int window;long epoch=7;String url;JSONObject arm,source,navigation;ObservedLinkPermit permit;
 PageActivity(JSONObject b,String i,int w)throws Exception{binding=b;instance=i;window=w;url=b.getString("initial_url");}
 String webviewInstance(){return instance;}long navigationEpoch(){return epoch;}
 void requireBinding(TaskBinding b,String i,int w)throws Exception{Jsons.need(b.live&&instance.equals(i)&&window==w&&WebDomCanonical.same(binding,b.evidence),"fixture current page binding");}
 JSONObject storageEvidence()throws Exception{return HostCaptureFixture.storage(binding);}
 void capture(String nonce,long deadline,OfficialPageCapture.Callback callback){try{JSONObject capture=HostCaptureFixture.capture(binding,nonce,epoch,url,navigation);callback.captured(capture);}catch(Exception e){callback.failed(e.toString());}}
 void requireArmSource(JSONObject c)throws Exception{Jsons.need(instance.equals(c.getString("webview_instance"))&&epoch==c.getLong("navigation_epoch")&&window==c.getInt("actual_window_id")&&url.equals(c.getString("current_native_url"))&&WebDomCanonical.same(binding,c.getJSONObject("binding")),"fixture latest source mismatch");}
 void installObservedLinkArm(JSONObject a,JSONObject c)throws Exception{requireArmSource(c);Jsons.need(permit==null,"fixture no pending permit");permit=new ObservedLinkPermit(a);permit.requireCurrent(android.os.SystemClock.now,instance,epoch,window,binding.getJSONObject("background").getInt("display_id"),url,WebEvidenceBinding.sha256(binding),binding.getString("storage_profile_name"));arm=new JSONObject(a.toString());source=new JSONObject(c.toString());}
 void invalidateObservedLink(String s){try{if(permit!=null)permit.cancel(s,android.os.SystemClock.now);}catch(Exception ignored){}permit=null;}
 void fixtureClickAndCommit()throws Exception{
  Jsons.need(permit!=null,"original ARM required");long t=android.os.SystemClock.now;
  permit.requireCurrent(t,instance,epoch,window,binding.getJSONObject("background").getInt("display_id"),url,WebEvidenceBinding.sha256(binding),binding.getString("storage_profile_name"));
  permit.beginPopup(t+1,false,true);permit.auxiliaryCreated(new JSONObject().put("profile_assignment_api","WebViewCompat.setProfile").put("profile_assigned_before_other_interactions",true).put("actual_profile_name",binding.getString("storage_profile_name")).put("profile_assigned_elapsed_ms",t+2).put("reused_same_lease_profile",true).put("network_loads_blocked",true).put("javascript_enabled",false).put("visible_in_layout",false));
  permit.acceptUrl(t+3,permit.url,"GET",true);permit.auxiliaryDestroyed(t+4);permit.beginMainLoad(t+5);permit.mainLoadReturned(t+6);navigation=permit.evidence();url=permit.url;epoch++;android.os.SystemClock.now=t+7;permit=null;
 }
}