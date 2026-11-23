package org.trillionnium.hepta.local;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;

/** Restart inspection only; never resumes a diagnostic or consumes its old nonce. */
public final class MobiMindSessionContract {
    private MobiMindSessionContract() {}
    public static boolean clean(Map<String,Object> value,int uid){
        if(value==null||!"hepta.mobimind.diagnostic-session.v1".equals(value.get("schema"))||uid<10000
                ||integer(value.get("app_uid"))!=uid||integer(value.get("updated_wall_ms"))<=0)return false;
        for(String key:new String[]{"pending","running","actions_executed","external_model_used","automatic_resume"})
            if(!Boolean.FALSE.equals(value.get(key)))return false;
        if(!Boolean.TRUE.equals(value.get("cleanup_known")))return false;
        if(!(value.get("native_binding_valid") instanceof Boolean))return false;
        for(String key:new String[]{"nonce_sha256","owner_sha256"})
            if(!(value.get(key) instanceof String)||!((String)value.get(key)).matches("[0-9a-f]{64}"))return false;
        if(!(value.get("request_id") instanceof String)||!((String)value.get("request_id")).matches("[0-9a-f]{32}"))return false;
        Object status=value.get("status");
        if(!new HashSet<String>(Arrays.asList("completed","preflight_failed","native_failed","cancelled_before_start",
                "cancelled","cancel_race","timed_out","submission_failed")).contains(status))return false;
        boolean started=Boolean.TRUE.equals(value.get("process_started"));
        if(!started&&!Boolean.FALSE.equals(value.get("process_started")))return false;
        if(started){
            long exit=integer(value.get("exit_code"));
            if(!Boolean.TRUE.equals(value.get("process_exit_observed"))||exit<0||exit>255
                    ||new HashSet<String>(Arrays.asList("preflight_failed","cancelled_before_start","submission_failed")).contains(status))return false;
            if("cancelled".equals(status)&&exit==0)return false;
        }else if(!Boolean.FALSE.equals(value.get("process_exit_observed"))||!value.containsKey("exit_code")||value.get("exit_code")!=null
                ||!new HashSet<String>(Arrays.asList("preflight_failed","cancelled_before_start","submission_failed")).contains(status))return false;
        if("completed".equals(status)&&(!started||integer(value.get("exit_code"))!=0||!Boolean.TRUE.equals(value.get("native_binding_valid"))))return false;
        if(!"completed".equals(status)&&!Boolean.FALSE.equals(value.get("native_binding_valid")))return false;
        return true;
    }
    private static long integer(Object value){return value instanceof Long||value instanceof Integer?((Number)value).longValue():Long.MIN_VALUE;}
}
