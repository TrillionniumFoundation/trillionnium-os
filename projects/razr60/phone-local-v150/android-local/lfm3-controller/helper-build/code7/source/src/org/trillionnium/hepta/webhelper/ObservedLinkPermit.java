package org.trillionnium.hepta.webhelper;

import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebDomCanonical;
import org.trillionnium.hepta.webprotocol.WebObservedNavigation;

/** UI-thread-owned, one-shot state; no Android/URL input effects occur in this class. */
final class ObservedLinkPermit {
    final String immutableArm;
    final String url,instance,bindingSha,profile,sourceUrl;
    final long epoch,deadline,window,display;
    private boolean popupAttempted,urlAttempted,cancelled,loadAttempted;
    private final JSONObject event;
    ObservedLinkPermit(JSONObject actualArm)throws Exception{
        Jsons.need(WebObservedNavigation.ARM_SCHEMA.equals(actualArm.getString("schema")),"typed actual ARM required");
        immutableArm=WebDomCanonical.canonical(actualArm);url=actualArm.getString("observed_href_resolved");
        instance=actualArm.getString("webview_instance");epoch=actualArm.getLong("navigation_epoch");
        window=actualArm.getLong("actual_window_id");display=actualArm.getLong("display_id");
        bindingSha=actualArm.getString("binding_sha256");profile=actualArm.getString("storage_profile_name");
        sourceUrl=actualArm.getString("source_native_url");deadline=actualArm.getLong("expires_elapsed_ms");
        event=new JSONObject().put("schema",WebObservedNavigation.NAV_SCHEMA).put("arm",new JSONObject(immutableArm))
                .put("popup_callback_observed",false).put("popup_url_observed",false)
                .put("popup_initiating_frame_verified",false).put("auxiliary_network_loads_blocked",true)
                .put("auxiliary_view_created",false).put("auxiliary_view_destroyed",false)
                .put("same_profile_assignment",JSONObject.NULL).put("same_lease_main_load_invoked",false)
                .put("same_lease_main_load_returned",false).put("new_visible_window_created",false)
                .put("external_app_launched",false).put("transaction_authority",false).put("business_verified",false)
                .put("cancelled",false).put("cancelled_elapsed_ms",JSONObject.NULL).put("cancellation_reason",JSONObject.NULL)
                .put("popup_callback_elapsed_ms",JSONObject.NULL).put("popup_is_dialog",JSONObject.NULL).put("popup_is_user_gesture",JSONObject.NULL)
                .put("popup_url_observed_elapsed_ms",JSONObject.NULL).put("popup_observed_url",JSONObject.NULL)
                .put("popup_observed_method",JSONObject.NULL).put("popup_observed_main_frame",JSONObject.NULL)
                .put("auxiliary_destroyed_elapsed_ms",JSONObject.NULL).put("main_load_begin_elapsed_ms",JSONObject.NULL)
                .put("main_load_returned_elapsed_ms",JSONObject.NULL);
    }
    void requireCurrent(long now,String actualInstance,long actualEpoch,int actualWindow,int actualDisplay,
                        String actualUrl,String actualBindingSha,String actualProfile)throws Exception{
        Jsons.need(!cancelled&&now>=new JSONObject(immutableArm).getLong("armed_elapsed_ms")&&now<deadline
                &&instance.equals(actualInstance)&&epoch==actualEpoch&&window==actualWindow&&display==actualDisplay
                &&sourceUrl.equals(actualUrl)&&bindingSha.equals(actualBindingSha)&&profile.equals(actualProfile),
                "observed-link permit expired or source lease changed");
    }
    void beginPopup(long now,boolean dialog,boolean gesture)throws Exception{
        boolean first=!popupAttempted;popupAttempted=true;
        Jsons.need(first&&!cancelled&&now<deadline&&!dialog&&gesture,"one actual user-gesture popup required");
        event.put("popup_callback_observed",true).put("popup_callback_elapsed_ms",now)
                .put("popup_is_dialog",dialog).put("popup_is_user_gesture",gesture);
    }
    void auxiliaryCreated(JSONObject facts)throws Exception{
        Jsons.need(popupAttempted&&!cancelled&&!event.getBoolean("auxiliary_view_created"),"single URL interception view");
        Jsons.need(profile.equals(facts.getString("actual_profile_name"))&&facts.getBoolean("network_loads_blocked"),
                "interception view must use the original isolated profile with networking blocked");
        event.put("auxiliary_view_created",true).put("same_profile_assignment",new JSONObject(facts.toString()));
    }
    void acceptUrl(long now,String actualUrl,String method,boolean mainFrame)throws Exception{
        boolean first=!urlAttempted;urlAttempted=true;
        event.put("popup_url_observed",true).put("popup_url_observed_elapsed_ms",now)
                .put("popup_observed_url",actualUrl==null?JSONObject.NULL:actualUrl)
                .put("popup_observed_method",method==null?JSONObject.NULL:method).put("popup_observed_main_frame",mainFrame);
        Jsons.need(first&&popupAttempted&&!cancelled&&now<deadline&&mainFrame&&"GET".equals(method)&&url.equals(actualUrl),
                "popup URL/method differs from the one actually observed and armed");
    }
    void auxiliaryDestroyed(long now)throws Exception{event.put("auxiliary_view_destroyed",true).put("auxiliary_destroyed_elapsed_ms",now);}
    void beginMainLoad(long now)throws Exception{
        boolean first=!loadAttempted;loadAttempted=true;
        Jsons.need(first&&urlAttempted&&!cancelled&&now<deadline&&event.getBoolean("auxiliary_view_destroyed"),
                "same-lease navigation requires one intercepted URL and actual auxiliary destruction");
        event.put("same_lease_main_load_invoked",true).put("main_load_begin_elapsed_ms",now);
    }
    void mainLoadReturned(long now)throws Exception{event.put("same_lease_main_load_returned",true).put("main_load_returned_elapsed_ms",now);}
    void cancel(String reason,long now)throws Exception{
        cancelled=true;event.put("cancelled",true).put("cancelled_elapsed_ms",now)
                .put("cancellation_reason",reason==null?"unknown":reason);
    }
    JSONObject evidence()throws Exception{return new JSONObject(event.toString());}
}
