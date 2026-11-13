package org.trillionnium.hepta.webprotocol;

import org.json.JSONObject;

/**
 * Typed one-shot link arm derived from the helper's last successful fresh capture.
 * A request supplies identities/hashes/path, never a URL or page script.
 * An ARM receipt is not a click, navigation completion, or business result.
 */
public final class WebObservedNavigation {
    public static final String ARM_SCHEMA="hepta.web-helper.observed-link-arm.v1";
    public static final String NAV_SCHEMA="hepta.web-helper.observed-link-navigation.v1";
    public static final String CAPTURE_SCHEMA="hepta.owned-webview-origin-dom.v2";
    public static final long SOURCE_MAX_AGE_MS=2500,ARM_BUDGET_MS=1500;
    private WebObservedNavigation(){}
    public static void requireRequest(JSONObject request)throws Exception{
        java.util.Set<String> keys=new java.util.TreeSet<String>();
        java.util.Iterator<String> it=request.keys();while(it.hasNext())keys.add(it.next());
        need(keys.equals(WebEvidenceProtocol.requestKeys(WebEvidenceProtocol.ARM_OBSERVED_LINK))
                &&WebEvidenceProtocol.requestSchema(WebEvidenceProtocol.ARM_OBSERVED_LINK).equals(text(request,"schema")),
                "exact observed-link request required");
        need(WebEvidenceProtocol.hex32(text(request,"task_id"))
                &&WebEvidenceProtocol.hex64(text(request,"controller_session_nonce"))
                &&WebEvidenceProtocol.hex64(text(request,"request_nonce"))
                &&WebEvidenceProtocol.uuid(text(request,"expected_webview_instance"))
                &&integer(request,"expected_navigation_epoch")>=0
                &&WebEvidenceProtocol.hex64(text(request,"source_capture_challenge"))
                &&WebEvidenceProtocol.hex64(text(request,"source_dom_sha256"))
                &&WebEvidenceProtocol.hex64(text(request,"source_stability_sha256"))
                &&text(request,"anchor_dom_path").matches("0(?:/[0-9]{1,5}){0,32}")
                &&WebEvidenceProtocol.hex32(text(request,"model_run_id")),
                "observed-link request identity/hash/path shape");
        need(integer(request,"deadline_elapsed_ms")>0,"positive observed-link request deadline");
    }
    public static JSONObject arm(JSONObject request,JSONObject binding,JSONObject capture,long now)throws Exception{
        requireRequest(request);WebTaskPurpose purpose=WebTaskPurpose.requireBinding(binding);
        need(purpose.shopping!=null&&WebMiActionRegion.POLICY.equals(purpose.sitePolicyId),
                "only the compiled public shopping purpose can arm a product link");
        need(text(binding,"task_id").equals(text(request,"task_id"))
                &&text(binding,"controller_session_nonce").equals(text(request,"controller_session_nonce"))
                &&WebEvidenceBinding.canonical(binding).equals(WebEvidenceBinding.canonical(capture.getJSONObject("binding"))),
                "last successful capture belongs to another lease");
        need(CAPTURE_SCHEMA.equals(text(capture,"schema"))
                &&Boolean.FALSE.equals(capture.get("business_verified"))
                &&Boolean.FALSE.equals(capture.get("truncated"))
                &&integer(capture,"display_id")>0&&integer(capture,"actual_window_id")>=0
                &&WebEvidenceProtocol.HELPER_PACKAGE.equals(text(capture,"helper_package")),
                "current formal wire-v4 capture required");
        need(text(request,"source_capture_challenge").equals(text(capture,"challenge"))
                &&text(request,"expected_webview_instance").equals(text(capture,"webview_instance"))
                &&integer(request,"expected_navigation_epoch")==integer(capture,"navigation_epoch")
                &&text(request,"source_dom_sha256").equals(text(capture,"dom_sha256")),
                "fresh capture identity changed");
        String before=text(capture,"before_dom_raw_utf8"),after=text(capture,"dom_raw_utf8");
        WebDomStability.Result stability=WebDomStability.verify(before,after,purpose.sitePolicyId,capture.getJSONObject("dom_stability"));
        need(stability.region!=null&&stability.permitsActionTargetPath(text(request,"anchor_dom_path"))
                &&stability.afterRawSha256.equals(text(request,"source_dom_sha256"))
                &&stability.beforeRawSha256.equals(text(capture,"before_dom_sha256"))
                &&WebDomCanonical.sha256(stability.evidence()).equals(text(request,"source_stability_sha256"))
                &&WebDomCanonical.sha256(stability.evidence()).equals(text(capture,"dom_stability_sha256")),
                "only the actual stable region anchor can be armed");
        WebMiActionRegion region=stability.region;
        need("_blank".equals(region.linkTarget),"this observed-link arm handles the actual new-window card link only");
        JSONObject geometry=capture.getJSONObject("capture_geometry");
        need("hepta.webview-geometry-bracket.v2".equals(text(geometry,"schema"))
                &&geometry.getJSONArray("samples").length()==4
                &&Boolean.TRUE.equals(geometry.get("native_samples_equal"))
                &&Boolean.TRUE.equals(geometry.get("ui_thread_bracket"))
                &&stability.comparisonScope.equals(text(geometry,"dom_comparison_scope"))
                &&Boolean.valueOf(stability.rawEqual).equals(geometry.get("dom_equal_across_visual_callback")),
                "complete actual native geometry bracket is required");
        long ended=integer(capture,"ended_elapsed_ms"),started=integer(capture,"started_elapsed_ms");
        JSONObject bg=binding.getJSONObject("background");long expires=integer(bg,"expires_elapsed_ms");
        long requestDeadline=integer(request,"deadline_elapsed_ms");
        need(now>=0&&now<=Long.MAX_VALUE-ARM_BUDGET_MS&&started<=ended&&ended<=now&&now-ended<=SOURCE_MAX_AGE_MS
                &&requestDeadline>now&&requestDeadline-now<=WebEvidenceProtocol.MAX_RPC_FUTURE_MS&&requestDeadline<=expires,
                "fresh capture/arm/lease deadline invalid");
        long deadline=Math.min(Math.min(requestDeadline,expires),Math.min(now+ARM_BUDGET_MS,ended+SOURCE_MAX_AGE_MS));
        return new JSONObject().put("schema",ARM_SCHEMA).put("request_nonce",text(request,"request_nonce"))
                .put("task_id",text(request,"task_id")).put("controller_session_nonce",text(request,"controller_session_nonce"))
                .put("binding_sha256",WebEvidenceBinding.sha256(binding)).put("model_run_id",text(request,"model_run_id"))
                .put("source_capture_challenge",text(request,"source_capture_challenge"))
                .put("source_dom_sha256",stability.afterRawSha256).put("source_before_dom_sha256",stability.beforeRawSha256)
                .put("source_stability_sha256",text(request,"source_stability_sha256"))
                .put("comparison_scope",stability.comparisonScope).put("anchor_dom_path",region.anchorPath)
                .put("region_root_path",region.rootPath).put("region_sha256",region.fullRegionSha256)
                .put("observed_href_raw",region.hrefRaw).put("observed_href_resolved",region.hrefResolved)
                .put("observed_link_target",region.linkTarget).put("site_policy_id",purpose.sitePolicyId)
                .put("source_native_url",text(capture,"current_native_url"))
                .put("webview_instance",text(capture,"webview_instance")).put("navigation_epoch",integer(capture,"navigation_epoch"))
                .put("actual_window_id",integer(capture,"actual_window_id")).put("display_id",integer(capture,"display_id"))
                .put("storage_profile_name",text(binding,"storage_profile_name"))
                .put("source_capture_ended_elapsed_ms",ended).put("armed_elapsed_ms",now).put("expires_elapsed_ms",deadline)
                .put("one_shot",true).put("url_supplied_by_controller_or_model",false)
                .put("native_click_observed",false).put("navigation_dispatched",false)
                .put("new_visible_window_allowed",false).put("external_app_allowed",false)
                .put("transaction_authority",false).put("business_verified",false);
    }
    public static JSONObject verifyArm(JSONObject request,JSONObject binding,JSONObject capture,JSONObject claimed)throws Exception{
        JSONObject expected=arm(request,binding,capture,integer(claimed,"armed_elapsed_ms"));
        need(WebDomCanonical.same(expected,claimed),"observed-link ARM receipt differs from fresh capture");return expected;
    }
    /**
     * Checks the exact bounded record shape, including incomplete/cancelled records.
     * This method never confirms a click, successful navigation, or a business result.
     * Receipt consumers must retain this record and later call verifyNavigation with
     * the private verified ARM and original accepted native ActionOutcome bracket.
     */
    public static void requireNavigationRecordShape(JSONObject nav)throws Exception{
        need(nav!=null&&NAV_SCHEMA.equals(text(nav,"schema")),"typed observed navigation record required");
        exactKeys(nav,new String[]{
                "schema","arm","popup_callback_observed","popup_callback_elapsed_ms","popup_is_dialog","popup_is_user_gesture",
                "popup_url_observed","popup_url_observed_elapsed_ms","popup_observed_url","popup_observed_method","popup_observed_main_frame",
                "popup_initiating_frame_verified","auxiliary_network_loads_blocked","auxiliary_view_created","auxiliary_view_destroyed",
                "same_profile_assignment","auxiliary_destroyed_elapsed_ms","same_lease_main_load_invoked","same_lease_main_load_returned",
                "main_load_begin_elapsed_ms","main_load_returned_elapsed_ms","new_visible_window_created","external_app_launched",
                "transaction_authority","business_verified","cancelled","cancelled_elapsed_ms","cancellation_reason"});
        JSONObject arm=nav.getJSONObject("arm");
        exactKeys(arm,new String[]{"schema","request_nonce","task_id","controller_session_nonce","binding_sha256","model_run_id",
                "source_capture_challenge","source_dom_sha256","source_before_dom_sha256","source_stability_sha256","comparison_scope",
                "anchor_dom_path","region_root_path","region_sha256","observed_href_raw","observed_href_resolved","observed_link_target",
                "site_policy_id","source_native_url","webview_instance","navigation_epoch","actual_window_id","display_id",
                "storage_profile_name","source_capture_ended_elapsed_ms","armed_elapsed_ms","expires_elapsed_ms","one_shot",
                "url_supplied_by_controller_or_model","native_click_observed","navigation_dispatched","new_visible_window_allowed",
                "external_app_allowed","transaction_authority","business_verified"});
        need(ARM_SCHEMA.equals(text(arm,"schema")),"typed nested ARM required");
        for(String key:new String[]{"request_nonce","task_id","controller_session_nonce","binding_sha256","model_run_id",
                "source_capture_challenge","source_dom_sha256","source_before_dom_sha256","source_stability_sha256","comparison_scope",
                "anchor_dom_path","region_root_path","region_sha256","observed_href_raw","observed_href_resolved","observed_link_target",
                "site_policy_id","source_native_url","webview_instance","storage_profile_name"})
            need(text(arm,key).length()<=4096,"bounded nested ARM string: "+key);
        for(String key:new String[]{"navigation_epoch","actual_window_id","display_id","source_capture_ended_elapsed_ms",
                "armed_elapsed_ms","expires_elapsed_ms"})need(integer(arm,key)>=0,"nonnegative nested ARM time/identity: "+key);
        need(Boolean.TRUE.equals(arm.get("one_shot")),"one-shot ARM record required");
        for(String key:new String[]{"url_supplied_by_controller_or_model","native_click_observed","navigation_dispatched",
                "new_visible_window_allowed","external_app_allowed","transaction_authority","business_verified"})
            need(Boolean.FALSE.equals(arm.get(key)),"nested ARM must not grant or claim action: "+key);
        for(String key:new String[]{"popup_callback_observed","popup_url_observed","popup_initiating_frame_verified",
                "auxiliary_network_loads_blocked","auxiliary_view_created","auxiliary_view_destroyed",
                "same_lease_main_load_invoked","same_lease_main_load_returned","new_visible_window_created",
                "external_app_launched","transaction_authority","business_verified","cancelled"})
            need(nav.get(key) instanceof Boolean,"typed navigation flag: "+key);
        for(String key:new String[]{"popup_is_dialog","popup_is_user_gesture","popup_observed_main_frame"})
            need(nav.get(key)==JSONObject.NULL||nav.get(key) instanceof Boolean,"nullable navigation flag: "+key);
        for(String key:new String[]{"popup_callback_elapsed_ms","popup_url_observed_elapsed_ms","auxiliary_destroyed_elapsed_ms",
                "main_load_begin_elapsed_ms","main_load_returned_elapsed_ms","cancelled_elapsed_ms"})
            need(nav.get(key)==JSONObject.NULL||integer(nav,key)>=0,"nullable navigation timestamp: "+key);
        for(String key:new String[]{"popup_observed_url","popup_observed_method","cancellation_reason"})
            need(nav.get(key)==JSONObject.NULL||nav.get(key) instanceof String&&text(nav,key).length()<=4096,
                    "nullable bounded navigation string: "+key);
        for(String key:new String[]{"popup_initiating_frame_verified","new_visible_window_created",
                "external_app_launched","transaction_authority","business_verified"})
            need(Boolean.FALSE.equals(nav.get(key)),"unsupported navigation claim: "+key);
        Object profile=nav.get("same_profile_assignment");
        if(profile!=JSONObject.NULL){
            need(profile instanceof JSONObject,"nullable profile assignment object required");
            JSONObject assigned=(JSONObject)profile;
            exactKeys(assigned,new String[]{"profile_assignment_api","profile_assigned_before_other_interactions","actual_profile_name",
                    "profile_assigned_elapsed_ms","reused_same_lease_profile","network_loads_blocked","javascript_enabled","visible_in_layout"});
            need(text(assigned,"profile_assignment_api").length()<=128&&text(assigned,"actual_profile_name").length()<=128
                    &&integer(assigned,"profile_assigned_elapsed_ms")>=0,"bounded actual profile assignment");
            for(String key:new String[]{"profile_assigned_before_other_interactions","reused_same_lease_profile",
                    "network_loads_blocked","javascript_enabled","visible_in_layout"})
                need(assigned.get(key) instanceof Boolean,"typed profile assignment flag: "+key);
        }
        need(WebDomCanonical.canonical(nav).getBytes(java.nio.charset.StandardCharsets.UTF_8).length<=65536,
                "bounded observed navigation record");
    }
    private static void exactKeys(JSONObject value,String[] expected)throws Exception{
        java.util.Set<String> actual=new java.util.TreeSet<String>();java.util.Iterator<String> it=value.keys();
        while(it.hasNext())actual.add(it.next());
        need(actual.equals(new java.util.TreeSet<String>(java.util.Arrays.asList(expected))),"exact observed record keys");
    }
    /**
     * Replays the helper's observed popup and same-lease load against an actual
     * native dispatch time bracket. The caller still independently requires the
     * original accepted/dispatched/not-stale ActionOutcome and current receipt.
     */
    public static JSONObject verifyNavigation(JSONObject expectedArm,JSONObject nav,JSONObject destination,
                                             long dispatchStarted,long dispatchEnded)throws Exception{
        requireNavigationRecordShape(nav);
        need(nav!=null&&NAV_SCHEMA.equals(text(nav,"schema"))&&ARM_SCHEMA.equals(text(expectedArm,"schema"))
                &&WebDomCanonical.same(expectedArm,nav.getJSONObject("arm")),"same actual ARM/navigation required");
        java.util.Set<String> expectedKeys=new java.util.TreeSet<String>(java.util.Arrays.asList(
                "schema","arm","popup_callback_observed","popup_callback_elapsed_ms","popup_is_dialog","popup_is_user_gesture",
                "popup_url_observed","popup_url_observed_elapsed_ms","popup_observed_url","popup_observed_method","popup_observed_main_frame",
                "popup_initiating_frame_verified","auxiliary_network_loads_blocked","auxiliary_view_created","auxiliary_view_destroyed",
                "same_profile_assignment","auxiliary_destroyed_elapsed_ms","same_lease_main_load_invoked","same_lease_main_load_returned",
                "main_load_begin_elapsed_ms","main_load_returned_elapsed_ms","new_visible_window_created","external_app_launched",
                "transaction_authority","business_verified","cancelled","cancelled_elapsed_ms","cancellation_reason"));
        java.util.Set<String> actualKeys=new java.util.TreeSet<String>();java.util.Iterator<String> keys=nav.keys();
        while(keys.hasNext())actualKeys.add(keys.next());need(actualKeys.equals(expectedKeys),"complete typed observed navigation fields");
        for(String key:new String[]{"popup_callback_observed","popup_is_user_gesture","popup_url_observed","popup_observed_main_frame",
                "auxiliary_network_loads_blocked","auxiliary_view_created","auxiliary_view_destroyed",
                "same_lease_main_load_invoked","same_lease_main_load_returned"})
            need(Boolean.TRUE.equals(nav.get(key)),"actual positive navigation fact required: "+key);
        for(String key:new String[]{"popup_is_dialog","popup_initiating_frame_verified","new_visible_window_created",
                "external_app_launched","transaction_authority","business_verified","cancelled"})
            need(Boolean.FALSE.equals(nav.get(key)),"navigation scope differs: "+key);
        need(nav.get("cancelled_elapsed_ms")==JSONObject.NULL&&nav.get("cancellation_reason")==JSONObject.NULL,
                "cancelled or partially completed navigation cannot be confirmed");
        String href=text(expectedArm,"observed_href_resolved"),profile=text(expectedArm,"storage_profile_name");
        need("_blank".equals(text(expectedArm,"observed_link_target"))&&href.equals(text(nav,"popup_observed_url"))
                &&"GET".equals(text(nav,"popup_observed_method")),"actual popup target/method differs from observed card");
        JSONObject assigned=nav.getJSONObject("same_profile_assignment");
        need(profile.equals(text(assigned,"actual_profile_name"))
                &&"WebViewCompat.setProfile".equals(text(assigned,"profile_assignment_api"))
                &&Boolean.TRUE.equals(assigned.get("profile_assigned_before_other_interactions"))
                &&Boolean.TRUE.equals(assigned.get("reused_same_lease_profile"))
                &&Boolean.TRUE.equals(assigned.get("network_loads_blocked"))
                &&Boolean.FALSE.equals(assigned.get("javascript_enabled"))
                &&Boolean.FALSE.equals(assigned.get("visible_in_layout")),"actual URL interceptor profile/network facts differ");
        long armed=integer(expectedArm,"armed_elapsed_ms"),deadline=integer(expectedArm,"expires_elapsed_ms");
        long popup=integer(nav,"popup_callback_elapsed_ms"),assign=integer(assigned,"profile_assigned_elapsed_ms"),
                requested=integer(nav,"popup_url_observed_elapsed_ms"),destroyed=integer(nav,"auxiliary_destroyed_elapsed_ms"),
                invoked=integer(nav,"main_load_begin_elapsed_ms"),returned=integer(nav,"main_load_returned_elapsed_ms");
        need(armed<=dispatchStarted&&dispatchStarted<=dispatchEnded&&dispatchEnded<=deadline
                &&dispatchStarted<=popup&&popup<=assign&&assign<=requested&&requested<=destroyed&&destroyed<=invoked
                &&invoked<=returned&&returned<deadline,"actual dispatch/popup/profile/destruction/load time chain differs");
        need(CAPTURE_SCHEMA.equals(text(destination,"schema"))&&Boolean.FALSE.equals(destination.get("business_verified"))
                &&Boolean.FALSE.equals(destination.get("truncated"))
                &&text(expectedArm,"binding_sha256").equals(WebEvidenceBinding.sha256(destination.getJSONObject("binding")))
                &&profile.equals(text(destination.getJSONObject("binding"),"storage_profile_name"))
                &&text(expectedArm,"webview_instance").equals(text(destination,"webview_instance"))
                &&integer(expectedArm,"actual_window_id")==integer(destination,"actual_window_id")
                &&integer(expectedArm,"display_id")==integer(destination,"display_id")
                &&integer(destination,"navigation_epoch")>integer(expectedArm,"navigation_epoch")
                &&href.equals(text(destination,"current_native_url"))&&href.equals(text(destination,"committed_main_frame_url"))
                &&returned<=integer(destination,"started_elapsed_ms")
                &&integer(destination,"started_elapsed_ms")<=integer(destination,"ended_elapsed_ms"),
                "actual destination capture does not follow the same-lease observed navigation");
        WebTaskPurpose purpose=WebTaskPurpose.requireBinding(destination.getJSONObject("binding"));
        need(purpose.shopping!=null&&WebSitePolicy.forShopping(purpose.shopping).classify(href)==WebSitePolicy.Route.PUBLIC_DETAIL_CANDIDATE,
                "actual destination is outside the fixed public detail policy");
        WebDomStability.Result stable=WebDomStability.verify(text(destination,"before_dom_raw_utf8"),
                text(destination,"dom_raw_utf8"),purpose.sitePolicyId,destination.getJSONObject("dom_stability"));
        need(stable.rawEqual&&stable.region==null,"current detail capture is whole raw stable and grants no click target");
        return new JSONObject().put("schema","hepta.web-helper.observed-navigation-verdict.v1")
                .put("arm_request_nonce",text(expectedArm,"request_nonce")).put("model_run_id",text(expectedArm,"model_run_id"))
                .put("source_capture_challenge",text(expectedArm,"source_capture_challenge"))
                .put("destination_capture_challenge",text(destination,"challenge")).put("observed_href",href)
                .put("helper_navigation_chain_verified",true).put("native_action_outcome_verified_by_this_method",false)
                .put("same_lease_profile",profile).put("detail_price_verified",false).put("business_verified",false);
    }
    public static long integer(JSONObject o,String key)throws Exception{
        Object v=o.get(key);need(v instanceof Integer||v instanceof Long,"integer "+key+" required");return ((Number)v).longValue();
    }
    public static String text(JSONObject o,String key)throws Exception{Object v=o.get(key);need(v instanceof String,"string "+key+" required");return (String)v;}
    private static void need(boolean value,String reason){if(!value)throw new IllegalArgumentException(reason);}
}
