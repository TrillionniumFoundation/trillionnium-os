package org.trillionnium.hepta.webhelper;

import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import androidx.webkit.Profile;
import androidx.webkit.ProfileStore;
import androidx.webkit.WebStorageCompat;
import androidx.webkit.WebViewFeature;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebStorageEvidence;

/** Cleans only the exact recorded retired profile after native process/display proof has passed. */
final class RetiredProfileClear {
    interface Result { void complete(boolean success,JSONObject facts,String reason); }
    private final Handler ui=new Handler(Looper.getMainLooper());
    private Result reply;
    private final JSONObject binding,facts;
    private final long deadline;
    private final String name;
    private final ProfileStore store;
    private Profile profile;

    static void start(JSONObject oldBinding,long requestDeadline,Result reply)throws Exception{
        new RetiredProfileClear(oldBinding,requestDeadline,reply).run();
    }
    private RetiredProfileClear(JSONObject oldBinding,long requestDeadline,Result listener)throws Exception{
        need(Looper.myLooper()==Looper.getMainLooper(),"profile recovery requires UI thread");
        name=WebStorageEvidence.profileFor(oldBinding.getString("controller_session_nonce"));
        need(name.equals(oldBinding.getString("storage_profile_name")),"recorded profile differs from immutable binding");
        need(WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE)
                &&WebViewFeature.isFeatureSupported(WebViewFeature.DELETE_BROWSING_DATA),"retirement storage features unavailable");
        long now=SystemClock.elapsedRealtime();need(requestDeadline>now,"recovery clear deadline expired");
        deadline=Math.min(requestDeadline,now+WebStorageEvidence.CLEAR_BUDGET_MS);
        binding=new JSONObject(oldBinding.toString());reply=listener;
        store=ProfileStore.getInstance();
        facts=new JSONObject().put("schema",WebStorageEvidence.RETIREMENT_SCHEMA).put("profile_name",name)
                .put("runtime_multi_profile",true).put("runtime_delete_browsing_data",true)
                .put("kind","unverified").put("profile_names_before",new JSONArray()).put("profile_names_after",new JSONArray())
                .put("started_elapsed_ms",now).put("deadline_elapsed_ms",deadline).put("callback_elapsed_ms",JSONObject.NULL)
                .put("ended_elapsed_ms",JSONObject.NULL).put("callback_observed",false).put("deadline_met",false)
                .put("cookies_present_after",JSONObject.NULL).put("api",JSONObject.NULL)
                .put("other_profiles_deleted",false).put("all_os_sockets_observed_closed",false).put("business_verified",false);
    }
    private void run()throws Exception{
        JSONArray before=names();facts.put("profile_names_before",before);
        if(!contains(before,name)){
            facts.put("kind","recorded_profile_absent").put("api","ProfileStore.getAllProfileNames")
                    .put("profile_names_after",names());
            finish(true,"recorded profile is absent");
            return;
        }
        profile=store.getProfile(name);
        need(profile!=null&&name.equals(profile.getName()),"recorded profile changed while opening cleanup handle");
        facts.put("api","WebStorageCompat.deleteBrowsingData");
        ui.postDelayed(new Runnable(){public void run(){finish(false,"recovered profile clear timed out");}},
                Math.max(1,deadline-SystemClock.elapsedRealtime()));
        try{
            WebStorageCompat.deleteBrowsingData(profile.getWebStorage(),new Runnable(){public void run(){ui.post(new Runnable(){public void run(){
                if(reply==null)return;
                try{
                    facts.put("callback_observed",true).put("callback_elapsed_ms",SystemClock.elapsedRealtime())
                            .put("cookies_present_after",profile.getCookieManager().hasCookies())
                            .put("profile_names_after",names()).put("kind","recorded_profile_clear_completed");
                    finish(true,"recorded profile clear callback completed");
                }catch(Exception invalid){finish(false,"profile cleanup facts invalid:"+invalid.getClass().getName());}
            }});}});
        }catch(RuntimeException unavailable){finish(false,"profile cleanup API unavailable:"+unavailable.getClass().getName());}
    }
    private void finish(boolean possible,String reason){
        Result listener=reply;reply=null;if(listener==null)return;
        boolean verified=false;
        try{
            long now=SystemClock.elapsedRealtime();facts.put("ended_elapsed_ms",now).put("deadline_met",now<=deadline);
            if(possible){WebStorageEvidence.requireRetirement(binding,facts);verified=true;}
        }catch(Exception rejected){reason="profile retirement proof incomplete:"+rejected.getMessage();}
        listener.complete(verified,copy(),reason);
    }
    private JSONArray names()throws Exception{
        List<String> values=store.getAllProfileNames();
        need(values!=null&&values.size()>0&&values.size()<=WebStorageEvidence.MAX_PROFILES,"profile enumeration unavailable or over budget");
        Set<String> seen=new HashSet<String>();JSONArray result=new JSONArray();
        for(String value:values){need(value!=null&&value.length()<=128&&seen.add(value),"invalid profile enumeration");result.put(value);}
        return result;
    }
    private static boolean contains(JSONArray values,String name)throws Exception{
        for(int i=0;i<values.length();i++)if(name.equals(values.get(i)))return true;return false;
    }
    private JSONObject copy(){try{return new JSONObject(facts.toString());}catch(Exception failed){return new JSONObject();}}
    private static void need(boolean condition,String reason){if(!condition)throw new IllegalStateException(reason);}
}
