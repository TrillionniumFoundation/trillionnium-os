package org.trillionnium.hepta.webprotocol;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;

/** Pure, bounded replay of the helper's recorded platform/profile clear callbacks. */
public final class WebStorageEvidence {
    private WebStorageEvidence() { }
    public static final String ISOLATION_SCHEMA="hepta.web-helper.storage-isolation.v1";
    public static final String RETIREMENT_SCHEMA="hepta.web-helper.recovery-storage.v1";
    public static final String LIBRARY="androidx.webkit:webkit:1.13.0";
    public static final int MAX_PROFILES=128;
    public static final long CLEAR_BUDGET_MS=3000;

    public static String profileFor(String controllerSessionNonce){
        need(controllerSessionNonce!=null&&controllerSessionNonce.matches("[0-9a-f]{64}"),"controller session nonce shape");
        return "hepta_v2_"+controllerSessionNonce;
    }

    public static void requireCapture(JSONObject binding,JSONObject facts,long captureStarted,long captureEnded)throws Exception{
        exact(facts,"schema","library","runtime_multi_profile","runtime_delete_browsing_data","profile_name",
                "profile_names_before","profile_was_present_before","profile_assigned_elapsed_ms",
                "webview_provider_package","webview_provider_version","webview_provider_version_code",
                "preload_clear","first_load_dispatch_begin_elapsed_ms","retirement_clear",
                "all_os_sockets_observed_closed","whole_device_storage_erased","business_verified","first_url");
        String profile=profileFor(text(binding,"controller_session_nonce"));
        need(profile.equals(text(binding,"storage_profile_name"))&&profile.equals(text(facts,"profile_name")),"profile is not bound to this lease");
        need(ISOLATION_SCHEMA.equals(text(facts,"schema"))&&LIBRARY.equals(text(facts,"library"))
                &&yes(facts,"runtime_multi_profile")&&yes(facts,"runtime_delete_browsing_data"),"storage API/feature provenance differs");
        need(no(facts,"profile_was_present_before")&&no(facts,"all_os_sockets_observed_closed")
                &&no(facts,"whole_device_storage_erased")&&no(facts,"business_verified"),"storage facts overclaim scope");
        need(!names(facts.getJSONArray("profile_names_before")).contains(profile),"profile was reused");
        need(text(facts,"webview_provider_package").length()>0&&text(facts,"webview_provider_package").length()<=200
                &&text(facts,"webview_provider_version").length()>0&&text(facts,"webview_provider_version").length()<=200
                &&number(facts,"webview_provider_version_code")>0,"provider identity missing");
        JSONObject clear=facts.getJSONObject("preload_clear");
        exact(clear,"started_elapsed_ms","deadline_elapsed_ms","initial_url","callback_elapsed_ms",
                "callback_observed","deadline_met","cookies_present_after","api");
        need("WebStorageCompat.deleteBrowsingData".equals(text(clear,"api"))&&yes(clear,"callback_observed")
                &&yes(clear,"deadline_met")&&no(clear,"cookies_present_after"),"actual clear callback facts incomplete");
        Object url=clear.get("initial_url");
        need(url==JSONObject.NULL||"".equals(url)||"about:blank".equals(url),"network page preceded storage isolation");
        JSONObject bg=binding.getJSONObject("background");
        long created=number(bg,"created_elapsed_ms"),expires=number(bg,"expires_elapsed_ms");
        long assigned=number(facts,"profile_assigned_elapsed_ms"),start=number(clear,"started_elapsed_ms"),
                deadline=number(clear,"deadline_elapsed_ms"),callback=number(clear,"callback_elapsed_ms"),
                load=number(facts,"first_load_dispatch_begin_elapsed_ms");
        need(created>=0&&created<=assigned&&assigned<=start&&start<=callback&&callback<=load
                &&load<=deadline&&deadline-start<=CLEAR_BUDGET_MS&&deadline>start
                &&load<=captureStarted&&captureStarted<=captureEnded&&captureEnded<=expires,
                "profile/clear/load/capture/lease order differs");
        need(WebEvidenceProtocol.INITIAL_URL.equals(text(facts,"first_url"))
                &&facts.get("retirement_clear")==JSONObject.NULL,"capture occurred after retirement or on a different first URL");
    }

    public static void requireRetirement(JSONObject binding,JSONObject facts)throws Exception{
        exact(facts,"schema","profile_name","runtime_multi_profile","runtime_delete_browsing_data","kind",
                "profile_names_before","profile_names_after","started_elapsed_ms","deadline_elapsed_ms",
                "callback_elapsed_ms","ended_elapsed_ms","callback_observed","deadline_met","cookies_present_after",
                "api","other_profiles_deleted","all_os_sockets_observed_closed","business_verified");
        String profile=profileFor(text(binding,"controller_session_nonce"));
        need(profile.equals(text(binding,"storage_profile_name"))&&profile.equals(text(facts,"profile_name"))
                &&RETIREMENT_SCHEMA.equals(text(facts,"schema")),"retirement profile/schema differs");
        need(yes(facts,"runtime_multi_profile")&&yes(facts,"runtime_delete_browsing_data")
                &&no(facts,"other_profiles_deleted")&&no(facts,"all_os_sockets_observed_closed")
                &&no(facts,"business_verified"),"retirement feature/scope differs");
        Set<String> before=names(facts.getJSONArray("profile_names_before"));
        Set<String> after=names(facts.getJSONArray("profile_names_after"));
        long start=number(facts,"started_elapsed_ms"),deadline=number(facts,"deadline_elapsed_ms"),end=number(facts,"ended_elapsed_ms");
        need(start>0&&deadline>start&&deadline-start<=CLEAR_BUDGET_MS&&end>=start&&end<=deadline
                &&yes(facts,"deadline_met"),"retirement storage time bracket invalid");
        String kind=text(facts,"kind");
        if("recorded_profile_absent".equals(kind)){
            need(!before.contains(profile)&&!after.contains(profile)&&no(facts,"callback_observed")
                    &&facts.get("callback_elapsed_ms")==JSONObject.NULL&&facts.get("cookies_present_after")==JSONObject.NULL
                    &&"ProfileStore.getAllProfileNames".equals(text(facts,"api")),"profile absence facts inconsistent");
        }else{
            need("recorded_profile_clear_completed".equals(kind)&&before.contains(profile)&&after.contains(profile)
                    &&yes(facts,"callback_observed")&&no(facts,"cookies_present_after")
                    &&"WebStorageCompat.deleteBrowsingData".equals(text(facts,"api")),"profile clear facts incomplete");
            long callback=number(facts,"callback_elapsed_ms");
            need(start<=callback&&callback<=end,"profile clear callback outside native bracket");
        }
    }

    private static Set<String> names(JSONArray values)throws Exception{
        need(values.length()>0&&values.length()<=MAX_PROFILES,"profile name enumeration unavailable or over budget");
        Set<String> answer=new HashSet<String>();
        for(int i=0;i<values.length();i++){Object value=values.get(i);need(value instanceof String
                &&((String)value).length()<=128&&answer.add((String)value),"invalid/duplicate profile name");}
        return answer;
    }
    private static boolean yes(JSONObject object,String key)throws Exception{return Boolean.TRUE.equals(object.get(key));}
    private static boolean no(JSONObject object,String key)throws Exception{return Boolean.FALSE.equals(object.get(key));}
    private static String text(JSONObject object,String key)throws Exception{Object value=object.get(key);need(value instanceof String,"string required:"+key);return (String)value;}
    private static long number(JSONObject object,String key)throws Exception{Object value=object.get(key);need(value instanceof Integer||value instanceof Long,"integer required:"+key);return ((Number)value).longValue();}
    private static void exact(JSONObject object,String... keys)throws Exception{
        Set<String> expected=new HashSet<String>(Arrays.asList(keys));need(object.length()==expected.size(),"unexpected storage fields");
        java.util.Iterator<String> actual=object.keys();while(actual.hasNext())need(expected.contains(actual.next()),"unknown storage field");
    }
    private static void need(boolean condition,String reason){if(!condition)throw new IllegalArgumentException(reason);}
}
