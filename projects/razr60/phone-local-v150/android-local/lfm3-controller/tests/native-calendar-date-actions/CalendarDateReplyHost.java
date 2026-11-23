package org.trillionnium.hepta.local;

import android.os.SystemClock;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.BrokerProtocol;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.PublicOwnGroupPolicy;
import org.trillionnium.hepta.background.WindowOwnership;

/**
 * Explicit synthetic root-socket/platform response for the actual HA Attempt ->
 * BackgroundSession consumer gate. It never constructs a private Attempt or
 * Receipt, invokes a broker, observes a ROM, or grants Android authority.
 *
 * Scope/target/window wires use the production value constructors. The prior
 * actual fixture lease readback supplies the unchanged display/physical facts.
 * Callback, namespace, geometry and DOWN/UP acknowledgements below are socket
 * port values, not executions of WindowInfosCapture or dispatchCalendarDate.
 */
public final class CalendarDateReplyHost {
    private CalendarDateReplyHost() {}

    public static byte[] reply(byte[] requestWire, BackgroundSession bg,
            ProfileTarget profile, WindowOwnership window) throws Exception {
        JSONObject q=decode(requestWire);
        BrokerProtocol.Request.parse(q.toString().getBytes(StandardCharsets.UTF_8));
        if(bg==null||profile==null||window==null||!profile.same(bg.profileTarget())
                ||!ProfileTarget.CTRIP.equals(profile.packageName)
                ||!profile.packageName.equals(q.getString("package"))
                ||!"calendar_date".equals(q.getString("op"))||q.getInt("version")!=4)
            throw new IOException("calendar reply fixture requires actual profile lease and calendar request");
        JSONObject lease=bg.evidence();
        PublicOwnGroupPolicy.Scope scope=PublicOwnGroupPolicy.Scope.fromWire(lease.getString("public_own_group_scope_wire"));
        JSONObject previous=lease.getJSONObject("last_broker_response");
        PublicOwnGroupPolicy.Readback prior=PublicOwnGroupPolicy.Readback.fromWire(
                previous.getString("public_own_group_readback_wire"),scope);
        long now=SystemClock.elapsedRealtime(),deadline=q.getLong("deadline_elapsed_ms");
        int display=bg.displayId(),axWindow=q.getInt("window_id"),task=q.getInt("task_id");
        if(display<=1||prior.display.displayId!=display||!bg.generation.equals(q.getString("generation"))
                ||!scope.sha256.equals(q.getString("display_scope_sha256"))
                ||!scope.taskId.equals(q.getString("owner_task_id"))
                ||!profile.sha256.equals(q.getString("target_sha256"))
                ||!profile.sha256.equals(window.targetSha256)||!bg.generation.equals(window.generation)
                ||window.displayId!=display||window.windowId!=axWindow||window.taskId!=task
                ||deadline<=now||deadline>bg.expiresElapsed||deadline-now>4000)
            throw new IOException("calendar reply fixture request/lease binding mismatch");
        PublicOwnGroupPolicy.Readback current=new PublicOwnGroupPolicy.Readback(scope,q.getString("request_id"),
                now,now,prior.privileges,prior.credentials,prior.display,prior.physical);
        // Fresh synthetic root-window values only. Not registered as live BG profile proofs.
        WindowOwnership before=window(profile,window,now,deadline);
        WindowOwnership after=window(profile,window,now,deadline);
        JSONObject geometry=geometry(q,bg,now);
        JSONObject namespace=namespace(profile,axWindow,now);
        JSONObject p=new JSONObject().put("schema","hepta.calendar-date-input-attempt.v1")
                .put("request_id",q.getString("request_id")).put("generation",bg.generation)
                .put("display_id",display).put("entered_elapsed_ms",now)
                .put("original_request_deadline_elapsed_ms",deadline).put("effect_deadline_elapsed_ms",deadline)
                // This is the intended integrated platform PORT response; not a
                // claim that the currently isolated broker handler is connected.
                .put("effect_route_integrated",true).put("attempt_consumed",true)
                .put("down_attempted",true).put("down_returned_true",true)
                .put("up_attempted",true).put("up_returned_true",true)
                .put("cancel_attempted",false).put("second_down_attempted",false)
                .put("date_independently_verified",false).put("business_completion_verified",false)
                .put("phase","input_pair_accepted_date_unverified").put("input_pair_accepted",true)
                .put("profile_target_sha256",profile.sha256).put("display_scope_sha256",scope.sha256)
                .put("target_full_uid",profile.fullUid)
                .put("namespace_before",namespace).put("namespace_after",new JSONObject(namespace.toString()))
                .put("owned_window_before",new JSONObject(before.evidence()))
                .put("owned_window_after",new JSONObject(after.evidence()))
                .put("display_before",geometry).put("display_after",new JSONObject(geometry.toString()))
                // Explicit synthetic platform constant, not a ROM readback.
                .put("no_focus_change_platform_value",536870912).put("injection_mode_platform_value",1)
                .put("requested_device_id",-1).put("dispatcher_device_id_isolation_claimed",false)
                .put("consumed_elapsed_ms",now).put("down_attempted_elapsed_ms",now)
                .put("down_returned_elapsed_ms",now).put("up_attempted_elapsed_ms",now)
                .put("up_returned_elapsed_ms",now).put("finished_elapsed_ms",now)
                .put("down_time_uptime_ms",SystemClock.uptimeMillis())
                .put("up_time_uptime_ms",SystemClock.uptimeMillis())
                .put("isolation",isolation(q,profile,display,now))
                .put("listener_lifecycle",lifecycle(now,deadline));
        for(String key:new String[]{"owner_task_id","goal_sha256","date","observation_id",
                "screen_sha256","permit_sha256","attempt_record_sha256"})p.put(key,q.get(key));
        JSONArray rect=new JSONArray();
        for(String edge:new String[]{"left","top","right","bottom"})rect.put(q.getInt(edge));
        p.put("rectangle",rect).put("logical_point",new JSONArray()
                .put((q.getInt("left")+(double)q.getInt("right"))/2.0)
                .put((q.getInt("top")+(double)q.getInt("bottom"))/2.0));
        JSONObject response=new JSONObject().put("version",q.getInt("version"))
                .put("request_id",q.getString("request_id")).put("generation",bg.generation)
                .put("operation","calendar_date").put("display_scope_sha256",scope.sha256)
                .put("public_scope_admission_retired",false).put("public_scope_closing",false)
                .put("ok",true).put("state","ACTIVE").put("display_id",display)
                .put("display_name",bg.displayName).put("flags",prior.display.flags)
                .put("width",q.getInt("display_width")).put("height",q.getInt("display_height"))
                .put("density",240).put("expires_elapsed_ms",bg.expiresElapsed).put("dispatched",true)
                .put("profile_target_wire",profile.wire()).put("profile_current_identity_verified",true)
                .put("public_own_group_readback_wire",current.wire()).put("calendar_date_input",p);
        return frame(response.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static WindowOwnership window(ProfileTarget target,WindowOwnership prior,long now,long deadline){
        return new WindowOwnership(target,prior.generation,prior.displayId,prior.windowId,prior.taskId,
                prior.parentTaskId,prior.taskTokenId,UUID.randomUUID().toString(),target.profile.userId,
                target.profile.serial,target.fullUid,now,deadline);
    }
    private static JSONObject geometry(JSONObject q,BackgroundSession bg,long now)throws Exception{
        int width=q.getInt("display_width"),height=q.getInt("display_height");
        return new JSONObject().put("metrics_source","android.view.Display.getRealMetrics")
                .put("display_id",bg.displayId()).put("display_name",bg.displayName)
                .put("width",width).put("height",height).put("density",240)
                .put("rotation",q.getInt("display_rotation")).put("pixels",(long)width*height)
                .put("max_pixels",16000000L).put("observed_started_elapsed_ms",now)
                .put("observed_ended_elapsed_ms",now);
    }
    private static JSONObject namespace(ProfileTarget p,int window,long now)throws Exception{
        return new JSONObject().put("schema","hepta.accessibility-window-token-binding.v1")
                .put("namespace_derivation","fresh_UserManager_profile_parent_and_actual_current_parent")
                .put("target_profile_user_id",p.profile.userId).put("target_profile_serial",p.profile.serial)
                .put("actual_parent_user_id",p.profile.parentUserId).put("api_namespace_user_id",p.profile.parentUserId)
                .put("accessibility_window_id",window).put("direct_profile_lookup_token_present",false)
                .put("parent_namespace_lookup_token_present",true).put("null_result_fallback_used",false)
                .put("lookup_source","IAccessibilityManager.getWindowToken")
                .put("required_permission","android.permission.RETRIEVE_WINDOW_CONTENT")
                .put("started_elapsed_ms",now).put("completed_elapsed_ms",now)
                .put("serialized_token_is_authority",false).put("grants_dispatch",false);
    }
    private static JSONObject isolation(JSONObject q,ProfileTarget p,int display,long now)throws Exception{
        int width=q.getInt("display_width"),height=q.getInt("display_height");
        JSONObject constants=new JSONObject().put("DEFAULT",0);
        String[] names={"NO_INPUT_CHANNEL","NOT_VISIBLE","NOT_TOUCHABLE","SPY","CLONE",
                "DUPLICATE_TOUCH_TO_WALLPAPER","IS_WALLPAPER","SLIPPERY"};
        for(int i=0;i<names.length;i++)constants.put(names[i],1<<i);
        return new JSONObject().put("schema","hepta.input-channel-isolation-readonly.v1")
                .put("source","raw_WindowInfosListener_callback_and_actual_accessibility_window_token")
                .put("census_sha256",sha(("explicit-synthetic-platform-census:"+q.getString("request_id")).getBytes(StandardCharsets.UTF_8)))
                .put("callback_ordinal",1).put("callback_received_elapsed_ms",now)
                .put("facts_copy_completed_elapsed_ms",now).put("checked_elapsed_ms",now)
                .put("window_count",1).put("display_count",3).put("region_rectangle_count",1)
                .put("omitted_window_count",0).put("owned_display_window_count",1)
                .put("owned_display_channel_count",1).put("other_display_window_count",0)
                .put("target_profile_user_id",p.profile.userId).put("accessibility_namespace_user_id",p.profile.parentUserId)
                .put("full_uid",p.fullUid).put("package",p.packageName).put("display_id",display)
                .put("accessibility_window_id",q.getInt("window_id")).put("observed_task_id",q.getInt("task_id"))
                .put("display_width",width).put("display_height",height).put("display_rotation",q.getInt("display_rotation"))
                .put("actual_window_token_match_count",1).put("actual_input_token_present",true)
                .put("cross_display_input_or_window_token_aliases",0).put("ambiguous_owned_channel_rows",0)
                .put("raw_frame",new JSONArray().put(0).put(0).put(width).put(height))
                .put("logical_frame",new JSONArray().put(0.0).put(0.0).put((double)width).put((double)height))
                .put("raw_window_transform",new JSONArray().put(1.0).put(0.0).put(0.0)
                        .put(0.0).put(1.0).put(0.0).put(0.0).put(0.0).put(1.0))
                .put("input_config",0).put("input_config_constants",constants)
                .put("global_monitor_isolation_basis","AOSP_fresh_channel_pair_and_single_display_registration")
                .put("global_monitor_tokens_observed",false).put("vendor_dispatcher_qualified",false)
                .put("privileged_post_census_mirror_excluded",false).put("atomic_surface_epoch_compare_and_dispatch",false)
                .put("date_rectangle_verified",false).put("grants_dispatch",false).put("input_attempts",0);
    }
    private static JSONObject lifecycle(long now,long deadline)throws Exception{
        return new JSONObject().put("schema","hepta.window-infos-listener-lifecycle.v1")
                .put("actual_boot_framework_required",true).put("registration_attempted",true).put("registration_returned",true)
                .put("register_started_elapsed_ms",now).put("register_ended_elapsed_ms",now)
                .put("original_deadline_elapsed_ms",deadline).put("register_cache_window_count",0).put("register_cache_display_count",0)
                .put("register_cache_grants_currentness",false).put("callback_arrivals",1).put("callback_finishes",1)
                .put("callbacks_in_flight",0).put("last_callback_finished_elapsed_ms",now)
                .put("superseded_callbacks",0).put("late_callbacks_ignored",0)
                .put("retired",true).put("retired_elapsed_ms",now).put("retains_current_census",false)
                .put("unregister_attempted",true).put("unregister_returned",true).put("unregister_failed",false)
                .put("unregister_started_elapsed_ms",now).put("unregister_ended_elapsed_ms",now)
                .put("local_callbacks_drained",true).put("surfaceflinger_removal_queue_drain_observed",false)
                .put("failure",JSONObject.NULL).put("grants_dispatch",false).put("input_attempts",0);
    }
    private static JSONObject decode(byte[] wire)throws Exception{
        if(wire==null)throw new IOException("missing request");
        DataInputStream in=new DataInputStream(new ByteArrayInputStream(wire));
        int n=in.readInt();if(n<=0||n>65536||n!=wire.length-4)throw new IOException("request frame");
        byte[] payload=new byte[n];in.readFully(payload);if(in.read()!=-1)throw new IOException("request trailer");
        return new JSONObject(new String(payload,StandardCharsets.UTF_8));
    }
    private static byte[] frame(byte[] payload)throws Exception{
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
        out.writeInt(payload.length);out.write(payload);out.flush();return bytes.toByteArray();
    }
    private static String sha(byte[] bytes)throws Exception{
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(bytes);StringBuilder out=new StringBuilder();
        for(byte b:digest){int n=b&255;if(n<16)out.append('0');out.append(Integer.toHexString(n));}return out.toString();
    }
}
