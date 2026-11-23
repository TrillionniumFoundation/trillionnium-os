package org.trillionnium.hepta.webhelper;

import android.content.Context;
import android.hardware.display.DisplayManager;
import android.os.SystemClock;
import android.provider.Settings;
import android.view.Display;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebTaskPurpose;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import java.util.TreeSet;

/** Exact supported OWNER and immutable controller/helper/background intersection. */
final class TaskBinding {
    final String taskId,sessionNonce,sha,generation,displayName;
    final int displayId,bootCount;
    final long created,expires;
    final InstalledIdentity controller,helper;
    final WebTaskPurpose purpose;
    final JSONObject evidence;
    private TaskBinding(JSONObject request,InstalledIdentity controller,InstalledIdentity helper,Context context)throws Exception{
        this.controller=controller;this.helper=helper;
        taskId=Jsons.text(request,"task_id");sessionNonce=Jsons.text(request,"controller_session_nonce");
        // Full original TaskAuthorization compiler, including every existing clause, runs inside WebTaskPurpose.
        purpose=WebTaskPurpose.fromAttach(request);
        controller.requireRequest(request.getJSONObject("controller_identity"));helper.requireRequest(request.getJSONObject("helper_identity"));
        JSONObject bg=request.getJSONObject("background");Jsons.keys(bg,WebEvidenceProtocol.BACKGROUND_KEYS);
        generation=Jsons.text(bg,"generation");displayId=Jsons.integer(bg,"display_id");displayName=Jsons.text(bg,"display_name");
        bootCount=Jsons.integer(bg,"boot_count");created=Jsons.number(bg,"created_elapsed_ms");expires=Jsons.number(bg,"expires_elapsed_ms");
        Jsons.need(WebEvidenceProtocol.uuid(generation)&&displayId>0&&displayName.equals("hepta-bg-"+generation),"owned background identity required");
        Jsons.need(created>0&&expires>created&&expires-created<=WebEvidenceProtocol.MAX_LEASE_MS,"background lease duration");
        JSONArray packages=bg.getJSONArray("selected_packages");TreeSet<String> seen=new TreeSet<String>();
        Jsons.need(packages.length()==1,"public-page task requires the selected helper alone");
        for(int i=0;i<packages.length();i++){Object v=packages.get(i);Jsons.need(v instanceof String&&((String)v).matches("[a-zA-Z][a-zA-Z0-9_]*(?:\\.[a-zA-Z][a-zA-Z0-9_]*)+")&&seen.add((String)v),"unique selected package required");}
        Jsons.need(seen.contains(WebEvidenceProtocol.HELPER_PACKAGE),"helper not selected by owner");
        evidence=WebEvidenceBinding.fromAttach(request);sha=WebEvidenceBinding.sha256(evidence);requireActive(context);
    }
    static TaskBinding attach(JSONObject request,InstalledIdentity controller,InstalledIdentity helper,Context context)throws Exception{
        return new TaskBinding(request,controller,helper,context);
    }
    void requireActive(Context context)throws Exception{
        requireIdentity(context);long now=SystemClock.elapsedRealtime();Jsons.need(now>=created&&now<expires,"background lease expired");
        DisplayManager dm=(DisplayManager)context.getSystemService(Context.DISPLAY_SERVICE);Display display=dm.getDisplay(displayId);
        Jsons.need(display!=null&&display.isValid()&&displayName.equals(display.getName()),"owned display changed or absent");
    }
    void requireIdentity(Context context)throws Exception{
        controller.requireUnchanged(context);helper.requireUnchanged(context);
        int actual=Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT,-1);
        Jsons.need(actual>=0&&actual==bootCount,"boot identity unknown or changed");
    }
    static void validateCommon(JSONObject request,int code)throws Exception{
        Jsons.keys(request,WebEvidenceProtocol.requestKeys(code));
        Jsons.need(WebEvidenceProtocol.requestSchema(code).equals(Jsons.text(request,"schema")),"request schema differs");
        Jsons.need(WebEvidenceProtocol.hex32(Jsons.text(request,"task_id"))&&WebEvidenceProtocol.hex64(Jsons.text(request,"controller_session_nonce"))
                &&WebEvidenceProtocol.hex64(Jsons.text(request,"request_nonce")),"request identity shape");
        long now=SystemClock.elapsedRealtime(),deadline=Jsons.number(request,"deadline_elapsed_ms");
        Jsons.need(deadline>now&&deadline-now<=WebEvidenceProtocol.MAX_RPC_FUTURE_MS,"RPC deadline invalid");
        if(code==WebEvidenceProtocol.ARM_OBSERVED_LINK)
            org.trillionnium.hepta.webprotocol.WebObservedNavigation.requireRequest(request);
        if(code==WebEvidenceProtocol.ACK_CAPTURE){
            Jsons.need(WebEvidenceProtocol.hex64(Jsons.text(request,"capture_request_nonce"))
                    &&WebEvidenceProtocol.hex64(Jsons.text(request,"durable_acknowledgement_sha256"))
                    &&request.get("durable_acknowledgement") instanceof JSONObject,"capture transfer request shape invalid");
        }
        if(code==WebEvidenceProtocol.CLOSE){String reason=Jsons.text(request,"reason");Jsons.need(reason.equals("normal")||reason.equals("cancelled")||reason.equals("error"),"close reason invalid");}
        if(code==WebEvidenceProtocol.CAPTURE){Object instance=request.get("expected_webview_instance"),epoch=request.get("expected_navigation_epoch");
            Jsons.need((instance==JSONObject.NULL)==(epoch==JSONObject.NULL),"capture expectation pair required");
            if(instance!=JSONObject.NULL)Jsons.need(instance instanceof String&&WebEvidenceProtocol.uuid((String)instance)
                    &&(epoch instanceof Integer||epoch instanceof Long)&&((Number)epoch).longValue()>=0,"capture expectation invalid");}
    }

}
