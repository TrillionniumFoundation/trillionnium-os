package org.trillionnium.hepta.webhelper;

import android.content.pm.PackageInfo;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.webkit.WebView;
import androidx.webkit.Profile;
import androidx.webkit.ProfileStore;
import androidx.webkit.WebStorageCompat;
import androidx.webkit.WebViewCompat;
import androidx.webkit.WebViewFeature;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;

/**
 * A fresh profile per authorized lease or explicit diagnostic page.
 * No legacy/default profile is loaded, reused, deleted, or treated as cleared.
 */
final class ProfileIsolation {
    static final int MAX_PROFILE_NAMES=128;
    static final long CLEAR_BUDGET_MS=3000;
    static final String LIBRARY_VERSION="1.13.0";
    interface Result { void complete(boolean success,JSONObject facts,String reason); }

    private final Handler ui=new Handler(Looper.getMainLooper());
    private final WebView web;
    private final Profile profile;
    private final String name;
    private final JSONObject facts;
    private boolean beforeStarted,beforeCompleted,beforeExpired,loadDispatched,retired;
    private boolean cleanupStarted,cleanupCompleted;
    private int cleanupAttempt,auxiliaryViews;
    private final Set<String> cleanupNonces=new HashSet<String>();
    private Result beforeReply,cleanupReply;
    private long beforeDeadline,cleanupDeadline;

    /** Must be the first interaction with the freshly constructed WebView. */
    static ProfileIsolation create(WebView fresh,String profileName)throws Exception {
        return new ProfileIsolation(fresh,profileName);
    }

    /** No WebView construction, profile assignment or navigation is performed here. */
    static JSONObject requireAvailable(String profileName)throws Exception {
        mainThread();need(profileName!=null&&profileName.matches("hepta_v2_[0-9a-f]{64}"),"invalid fresh profile name");
        boolean multi=WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE);
        boolean clear=WebViewFeature.isFeatureSupported(WebViewFeature.DELETE_BROWSING_DATA);
        need(multi&&clear,"required WebView profile/storage features unavailable");
        ProfileStore store=ProfileStore.getInstance();
        List<String> known=store.getAllProfileNames();
        need(known!=null&&known.size()>0&&known.size()<MAX_PROFILE_NAMES,"profile enumeration unavailable or budget reached");
        Set<String> unique=new HashSet<String>();JSONArray originalNames=new JSONArray();
        for(String entry:known){
            need(entry!=null&&entry.length()<=128&&unique.add(entry),"invalid profile enumeration");
            originalNames.put(entry);
        }
        need(!unique.contains(profileName),"profile already exists; name may not be reused");
        return new JSONObject().put("runtime_multi_profile",multi).put("runtime_delete_browsing_data",clear)
                .put("profile_names_before",originalNames);
    }

    private ProfileIsolation(WebView fresh,String profileName)throws Exception {
        mainThread();
        need(fresh!=null&&profileName!=null&&profileName.matches("hepta_v2_[0-9a-f]{64}"),"invalid fresh profile name");
        JSONObject available=requireAvailable(profileName);
        boolean multi=available.getBoolean("runtime_multi_profile"),clear=available.getBoolean("runtime_delete_browsing_data");
        JSONArray originalNames=available.getJSONArray("profile_names_before");
        web=fresh;name=profileName;
        WebViewCompat.setProfile(web,name);
        profile=WebViewCompat.getProfile(web);
        need(profile!=null&&name.equals(profile.getName()),"profile assignment differs");
        profile.getCookieManager().setAcceptThirdPartyCookies(web,false);
        PackageInfo provider=WebView.getCurrentWebViewPackage();
        need(provider!=null&&provider.packageName!=null&&provider.versionName!=null,"actual WebView provider unavailable");
        facts=new JSONObject().put("schema","hepta.web-helper.storage-isolation.v1")
                .put("library","androidx.webkit:webkit:"+LIBRARY_VERSION)
                .put("runtime_multi_profile",multi).put("runtime_delete_browsing_data",clear)
                .put("profile_name",name).put("profile_names_before",originalNames)
                .put("profile_was_present_before",false).put("profile_assigned_elapsed_ms",SystemClock.elapsedRealtime())
                .put("webview_provider_package",provider.packageName).put("webview_provider_version",provider.versionName)
                .put("webview_provider_version_code",provider.getLongVersionCode())
                .put("preload_clear",JSONObject.NULL).put("first_load_dispatch_begin_elapsed_ms",JSONObject.NULL)
                .put("retirement_clear",JSONObject.NULL).put("all_os_sockets_observed_closed",false)
                .put("whole_device_storage_erased",false).put("business_verified",false);
    }

    void clearBeforeFirstLoad(long deadline,Result reply)throws Exception {
        mainThread();
        need(!retired&&!beforeStarted&&!loadDispatched&&reply!=null,"preload clear is single use");
        need(name.equals(WebViewCompat.getProfile(web).getName()),"profile changed before clear");
        String initial=web.getUrl();
        need(initial==null||initial.length()==0||"about:blank".equals(initial),"page loaded before storage gate");
        long now=SystemClock.elapsedRealtime();
        need(deadline>now,"preload clear deadline expired");
        beforeStarted=true;beforeReply=reply;beforeDeadline=Math.min(deadline,now+CLEAR_BUDGET_MS);
        facts.put("preload_clear",new JSONObject().put("started_elapsed_ms",now).put("deadline_elapsed_ms",beforeDeadline)
                .put("initial_url",initial==null?JSONObject.NULL:initial).put("callback_elapsed_ms",JSONObject.NULL)
                .put("callback_observed",false).put("deadline_met",false).put("cookies_present_after",JSONObject.NULL)
                .put("api","WebStorageCompat.deleteBrowsingData"));
        ui.postDelayed(new Runnable(){public void run(){
            if(!beforeCompleted&&!beforeExpired){
                beforeExpired=true;finishBefore(false,"storage clear callback deadline exceeded");
            }
        }},Math.max(1,beforeDeadline-now));
        try{
            WebStorageCompat.deleteBrowsingData(profile.getWebStorage(),new Runnable(){public void run(){ui.post(new Runnable(){public void run(){
                try{
                    mainThread();
                    JSONObject clear=facts.getJSONObject("preload_clear");
                    long completed=SystemClock.elapsedRealtime();
                    clear.put("callback_elapsed_ms",completed).put("callback_observed",true)
                            .put("deadline_met",completed<=beforeDeadline);
                    boolean cookies=profile.getCookieManager().hasCookies();
                    clear.put("cookies_present_after",cookies);
                    beforeCompleted=true;
                    boolean valid=!retired&&!beforeExpired&&completed<=beforeDeadline&&!cookies
                            &&name.equals(WebViewCompat.getProfile(web).getName())&&!loadDispatched;
                    finishBefore(valid,valid?"storage clear completed":"storage clear callback cannot authorize a late or retired load");
                }catch(Exception error){finishBefore(false,"storage callback invalid:"+error.getClass().getName());}
            }});}});
        }catch(RuntimeException unavailable){
            facts.getJSONObject("preload_clear").put("invoke_error",unavailable.getClass().getName());
            finishBefore(false,"storage clear unavailable");
        }
    }

    /** Called immediately before the one fixed-URL loadUrl invocation. */
    void firstLoadDispatch(String compiledInitialUrl)throws Exception {
        mainThread();
        need(!retired&&beforeStarted&&beforeCompleted&&!beforeExpired&&!loadDispatched
                &&SystemClock.elapsedRealtime()<=beforeDeadline,"storage gate is not current");
        JSONObject clear=facts.getJSONObject("preload_clear");
        need(clear.getBoolean("callback_observed")&&clear.getBoolean("deadline_met")
                &&Boolean.FALSE.equals(clear.get("cookies_present_after")),"storage clear facts incomplete");
        need(name.equals(WebViewCompat.getProfile(web).getName()),"profile changed before URL load");
        need(compiledInitialUrl!=null&&compiledInitialUrl.length()>0&&compiledInitialUrl.length()<=4096,
                "compiled initial page required");
        loadDispatched=true;facts.put("first_load_dispatch_begin_elapsed_ms",SystemClock.elapsedRealtime())
                .put("first_url",compiledInitialUrl);
    }

    /**
     * The page calls this after its actual stopLoading/destroy attempt. It does not turn those
     * separate facts true. Late storage completion is recorded, never a second RPC callback.
     */
    void clearAfterRetirement(long deadline,String freshCloseNonce,Result reply)throws Exception {
        mainThread();need(reply!=null&&auxiliaryViews==0,"cleanup requires every owned auxiliary view destroyed");
        need(freshCloseNonce==null||WebEvidenceProtocol.hex64(freshCloseNonce),"cleanup close nonce shape");
        long now=SystemClock.elapsedRealtime();
        need(deadline>now,"cleanup clear deadline expired");
        if(cleanupStarted){
            retired=true;finishBefore(false,"page retired");
            if(cleanupCompleted){reply.complete(true,evidence(),"storage clear already completed");return;}
            // Only a later authenticated, consumed close nonce may authorize a new cleanup attempt.
            // The old callback can still be observed, but never completes this new attempt.
            need(cleanupReply==null&&freshCloseNonce!=null&&!cleanupNonces.contains(freshCloseNonce),
                    "fresh authenticated close required after an incomplete clear");
            JSONArray history=facts.optJSONArray("retirement_clear_history");
            if(history==null){history=new JSONArray();facts.put("retirement_clear_history",history);}
            need(history.length()<WebEvidenceProtocol.MAX_REQUESTS_PER_SESSION,"retirement evidence history budget");
            history.put(facts.getJSONObject("retirement_clear"));
        }
        if(freshCloseNonce!=null)need(cleanupNonces.add(freshCloseNonce),"cleanup nonce already consumed");
        retired=true;cleanupStarted=true;cleanupCompleted=false;cleanupReply=reply;
        cleanupDeadline=Math.min(deadline,now+CLEAR_BUDGET_MS);
        final int attempt=++cleanupAttempt;
        final long attemptDeadline=cleanupDeadline;
        final JSONObject clear=new JSONObject().put("started_elapsed_ms",now).put("deadline_elapsed_ms",attemptDeadline)
                .put("callback_elapsed_ms",JSONObject.NULL).put("callback_observed",false).put("deadline_met",false)
                .put("cookies_present_after",JSONObject.NULL).put("api","WebStorageCompat.deleteBrowsingData")
                .put("attempt",attempt).put("close_request_nonce",freshCloseNonce==null?JSONObject.NULL:freshCloseNonce)
                .put("actor",freshCloseNonce==null?"automatic_owned_retirement":"authenticated_controller_close");
        facts.put("retirement_clear",clear);
        finishBefore(false,"page retired");
        ui.postDelayed(new Runnable(){public void run(){
            if(attempt==cleanupAttempt&&!cleanupCompleted)finishCleanup(false,"storage cleanup callback deadline exceeded");
        }},Math.max(1,attemptDeadline-now));
        try{
            WebStorageCompat.deleteBrowsingData(profile.getWebStorage(),new Runnable(){public void run(){ui.post(new Runnable(){public void run(){
                try{
                    mainThread();long completed=SystemClock.elapsedRealtime();
                    clear.put("callback_elapsed_ms",completed).put("callback_observed",true)
                            .put("deadline_met",completed<=attemptDeadline);
                    boolean cookies=profile.getCookieManager().hasCookies();
                    clear.put("cookies_present_after",cookies);
                    if(attempt!=cleanupAttempt)return; // Previous callback only updates its own recorded attempt.
                    cleanupCompleted=completed<=attemptDeadline&&!cookies;
                    finishCleanup(cleanupCompleted,cleanupCompleted?"storage cleanup completed":"storage cleanup was late or cookies remain");
                }catch(Exception error){
                    if(attempt==cleanupAttempt)finishCleanup(false,"storage cleanup callback invalid:"+error.getClass().getName());
                }
            }});}});
        }catch(RuntimeException unavailable){
            clear.put("invoke_error",unavailable.getClass().getName());
            if(attempt==cleanupAttempt)finishCleanup(false,"storage cleanup unavailable");
        }
    }

    /** First interaction with a temporary URL-interception view; never a fresh/default profile. */
    JSONObject assignAuxiliaryProfile(WebView fresh)throws Exception{
        mainThread();requireCurrentProfile();
        need(fresh!=null&&beforeCompleted&&loadDispatched&&!retired&&auxiliaryViews==0,"one current isolated URL interceptor");
        // Count before assignment: a failed profile call must still be retired.
        auxiliaryViews++;
        WebViewCompat.setProfile(fresh,name);
        Profile actual=WebViewCompat.getProfile(fresh);
        need(actual!=null&&name.equals(actual.getName()),"auxiliary view profile differs");
        actual.getCookieManager().setAcceptThirdPartyCookies(fresh,false);
        return new JSONObject().put("profile_assignment_api","WebViewCompat.setProfile")
                .put("profile_assigned_before_other_interactions",true).put("actual_profile_name",actual.getName())
                .put("profile_assigned_elapsed_ms",SystemClock.elapsedRealtime()).put("reused_same_lease_profile",true);
    }
    void auxiliaryDestroyed(){mainThread();need(auxiliaryViews==1,"tracked auxiliary destruction required");auxiliaryViews=0;}
    int liveAuxiliaryViews(){mainThread();return auxiliaryViews;}
    void requireCurrentProfile(){mainThread();need(!retired&&name.equals(WebViewCompat.getProfile(web).getName()),"actual WebView profile changed or retired");}
    String profileName(){return name;}
    boolean cleanupCompleted(){mainThread();return retired&&cleanupCompleted;}
    JSONObject evidence()throws Exception{mainThread();return new JSONObject(facts.toString());}
    private void finishBefore(boolean ok,String reason){
        Result reply=beforeReply;beforeReply=null;if(reply!=null)reply.complete(ok,copy(),reason);
    }
    private void finishCleanup(boolean ok,String reason){
        Result reply=cleanupReply;cleanupReply=null;if(reply!=null)reply.complete(ok,copy(),reason);
    }
    private JSONObject copy(){
        try{return new JSONObject(facts.toString());}catch(Exception unavailable){return new JSONObject();}
    }
    private static void mainThread(){need(Looper.myLooper()==Looper.getMainLooper(),"WebView storage requires helper UI thread");}
    private static void need(boolean condition,String reason){if(!condition)throw new IllegalStateException(reason);}
}
