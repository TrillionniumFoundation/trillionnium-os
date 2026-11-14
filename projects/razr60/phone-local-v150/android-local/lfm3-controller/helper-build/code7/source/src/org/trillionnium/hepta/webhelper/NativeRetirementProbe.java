package org.trillionnium.hepta.webhelper;

import android.app.ActivityManager;
import android.app.ApplicationExitInfo;
import android.content.Context;
import android.hardware.display.DisplayManager;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import android.view.Display;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebRecoveryPolicy;

/** Reads Android facts itself; no request parameter can supply a process-exit or absence fact. */
final class NativeRetirementProbe {
    interface OwnedState {
        int liveWebViewCount();
        int pendingCaptureCount();
    }
    private NativeRetirementProbe() { }

    static JSONObject collect(Context context,JSONObject prior,ProcessIdentity current,OwnedState owned) throws Exception {
        if(Looper.myLooper()!=Looper.getMainLooper())throw new IllegalStateException("recovery probe requires serialized helper UI thread");
        JSONArray errors=new JSONArray();
        JSONObject background=prior.getJSONObject("binding").getJSONObject("background");
        int oldId=background.getInt("display_id"),oldBoot=background.getInt("boot_count");
        int oldPid=prior.getInt("helper_pid");
        long begin=SystemClock.elapsedRealtime();
        int bootBefore=boot(context,errors);
        JSONObject process=current.snapshot();
        DisplayManager displays=context.getSystemService(DisplayManager.class);
        Object directBefore=direct(displays,oldId,errors);
        JSONArray before=snapshot(displays,errors);
        JSONArray exits=new JSONArray();String exitStatus="not_required_boot_changed";
        if(bootBefore==oldBoot){
            exitStatus="queried";
            try{
                ActivityManager manager=context.getSystemService(ActivityManager.class);
                if(manager==null)throw new IllegalStateException("ActivityManager unavailable");
                List<ApplicationExitInfo> records=manager.getHistoricalProcessExitReasons(
                        WebEvidenceProtocol.HELPER_PACKAGE,oldPid,WebRecoveryPolicy.MAX_EXIT_RECORDS);
                if(records==null||records.size()>WebRecoveryPolicy.MAX_EXIT_RECORDS)
                    throw new IllegalStateException("exit records unavailable or over budget");
                for(ApplicationExitInfo row:records){
                    if(row==null)throw new IllegalStateException("null exit record");
                    byte[] summary=row.getProcessStateSummary();
                    if(summary!=null&&summary.length>128)throw new IllegalStateException("exit state summary over budget");
                    exits.put(new JSONObject().put("pid",row.getPid()).put("real_uid",row.getRealUid())
                            .put("package_uid",row.getPackageUid()).put("process_name",row.getProcessName())
                            .put("reason",row.getReason()).put("status",row.getStatus()).put("timestamp_ms",row.getTimestamp())
                            .put("state_summary_hex",summary==null?JSONObject.NULL:ProcessIdentity.hex(summary)));
                }
            }catch(Exception unavailable){exitStatus="query_unavailable";errors.put(error("exit_records",unavailable));}
        }else if(bootBefore<oldBoot){exitStatus="boot_unavailable_or_regressed";}
        JSONArray after=snapshot(displays,errors);
        Object directAfter=direct(displays,oldId,errors);
        int bootAfter=boot(context,errors);
        return new JSONObject().put("schema",WebRecoveryPolicy.PROBE_SCHEMA)
                .put("current_boot_count_before",bootBefore).put("current_boot_count_after",bootAfter)
                .put("started_elapsed_ms",begin).put("ended_elapsed_ms",SystemClock.elapsedRealtime())
                .put("current_process",process).put("active_bound_view_count",owned.liveWebViewCount())
                .put("pending_capture_count",owned.pendingCaptureCount())
                .put("displays_before",before).put("displays_after",after)
                .put("direct_old_display_before",directBefore).put("direct_old_display_after",directAfter)
                .put("exit_records",exits).put("exit_records_status",exitStatus).put("errors",errors);
    }

    static JSONObject displayRecord(Display display) throws Exception {
        if(display==null)throw new IllegalStateException("display is absent");
        return new JSONObject().put("display_id",display.getDisplayId()).put("name",display.getName())
                .put("flags",display.getFlags()).put("valid",display.isValid());
    }
    private static int boot(Context context,JSONArray errors) {
        try{return Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT);}
        catch(Exception unavailable){errors.put(error("boot_count",unavailable));return -1;}
    }
    private static Object direct(DisplayManager manager,int id,JSONArray errors) {
        try{
            if(manager==null||id<=0)throw new IllegalStateException("display manager or original display unavailable");
            Display value=manager.getDisplay(id);
            return value==null?JSONObject.NULL:displayRecord(value);
        }catch(Exception unavailable){errors.put(error("direct_old_display",unavailable));return new JSONObject();}
    }
    private static JSONArray snapshot(DisplayManager manager,JSONArray errors) {
        JSONArray answer=new JSONArray();
        try{
            if(manager==null)throw new IllegalStateException("display manager unavailable");
            Display[] values=manager.getDisplays();
            if(values==null||values.length==0||values.length>WebRecoveryPolicy.MAX_DISPLAYS)
                throw new IllegalStateException("display enumeration unavailable or over budget");
            for(Display display:values)answer.put(displayRecord(display));
        }catch(Exception unavailable){errors.put(error("display_snapshot",unavailable));}
        return answer;
    }
    private static String error(String operation,Exception error){return operation+":"+error.getClass().getName();}
}
