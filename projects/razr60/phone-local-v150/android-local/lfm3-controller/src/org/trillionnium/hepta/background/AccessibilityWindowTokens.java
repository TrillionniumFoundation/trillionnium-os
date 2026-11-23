package org.trillionnium.hepta.background;

import android.app.ActivityManager;
import android.os.IBinder;
import android.os.SystemClock;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Actual accessibility Binder lookup in the namespace derived from the live managed profile.
 * Android shares managed-profile accessibility state with its parent. The target UID/profile is
 * never changed to that namespace. There is no null-result fallback to an assumed user zero.
 */
final class AccessibilityWindowTokens {
    private AccessibilityWindowTokens() {}
    static final class Read {
        final ProfileIdentity profile;
        final int windowId,namespaceUserId;
        final IBinder token;
        final boolean directProfileTokenPresent;
        final long startedElapsedMs,completedElapsedMs;
        private Read(ProfileIdentity p,int window,IBinder token,boolean direct,long started,long completed){
            profile=p;windowId=window;namespaceUserId=p.parentUserId;this.token=token;
            directProfileTokenPresent=direct;startedElapsedMs=started;completedElapsedMs=completed;
        }
        void requireSame(Read other)throws InputChannelIsolation.Refusal{
            InputChannelIsolation.need(other!=null&&profile.same(other.profile)&&windowId==other.windowId
                    &&namespaceUserId==other.namespaceUserId&&token==other.token
                    &&directProfileTokenPresent==other.directProfileTokenPresent,
                    "INPUT_ACCESSIBILITY_WINDOW_CHANGED");
        }
        Map<String,Object> evidence(){
            Map<String,Object> v=new LinkedHashMap<String,Object>();
            v.put("schema","hepta.accessibility-window-token-binding.v1");
            v.put("namespace_derivation","fresh_UserManager_profile_parent_and_actual_current_parent");
            v.put("target_profile_user_id",profile.userId);v.put("target_profile_serial",profile.serial);
            v.put("actual_parent_user_id",profile.parentUserId);v.put("api_namespace_user_id",namespaceUserId);
            v.put("accessibility_window_id",windowId);v.put("direct_profile_lookup_token_present",directProfileTokenPresent);
            v.put("parent_namespace_lookup_token_present",true);v.put("null_result_fallback_used",false);
            v.put("lookup_source","IAccessibilityManager.getWindowToken");
            v.put("required_permission","android.permission.RETRIEVE_WINDOW_CONTENT");
            v.put("started_elapsed_ms",startedElapsedMs);v.put("completed_elapsed_ms",completedElapsedMs);
            v.put("serialized_token_is_authority",false);v.put("grants_dispatch",false);
            return Collections.unmodifiableMap(v);
        }
    }
    static Read read(ProfilePackages packages,ProfileTarget expected,int windowId,long deadline)throws Exception{
        InputChannelIsolation.need(android.os.Process.myUid()==0&&packages!=null&&expected!=null&&windowId>=0,
                "INPUT_ACCESSIBILITY_LOOKUP_INVALID");
        long started=SystemClock.elapsedRealtime();time(deadline);
        ProfileIdentity before=packages.identity(expected.profile.userId);
        InputChannelIsolation.need(before.same(expected.profile),"INPUT_ACCESSIBILITY_PROFILE_CHANGED");
        requireCurrentParent(before);time(deadline);
        IBinder service=(IBinder)Class.forName("android.os.ServiceManager").getMethod("getService",String.class)
                .invoke(null,"accessibility");
        InputChannelIsolation.need(service!=null&&service.isBinderAlive(),"INPUT_ACCESSIBILITY_SERVICE_UNAVAILABLE");
        Class<?> manager=Class.forName("android.view.accessibility.IAccessibilityManager");
        Object api=Class.forName("android.view.accessibility.IAccessibilityManager$Stub")
                .getMethod("asInterface",IBinder.class).invoke(null,service);
        InputChannelIsolation.need(api!=null,"INPUT_ACCESSIBILITY_SERVICE_UNAVAILABLE");
        Method get=manager.getMethod("getWindowToken",int.class,int.class);
        // The direct profile lookup is retained as a diagnostic. The namespace is selected from
        // the verified parent relation BEFORE either lookup; a null result never selects it.
        int namespace=before.parentUserId;
        InputChannelIsolation.need(namespace>=0&&namespace!=before.userId,"INPUT_ACCESSIBILITY_NAMESPACE_INVALID");
        IBinder direct=token(get.invoke(api,windowId,before.userId));time(deadline);
        IBinder actual=token(get.invoke(api,windowId,namespace));time(deadline);
        InputChannelIsolation.need(actual!=null&&actual.isBinderAlive(),"INPUT_ACCESSIBILITY_WINDOW_TOKEN_NULL");
        InputChannelIsolation.need(direct==null||direct==actual,"INPUT_ACCESSIBILITY_NAMESPACE_AMBIGUOUS");
        ProfileIdentity after=packages.identity(expected.profile.userId);requireCurrentParent(after);time(deadline);
        InputChannelIsolation.need(before.same(after)&&after.same(expected.profile),"INPUT_ACCESSIBILITY_PROFILE_CHANGED");
        IBinder finalDirect=token(get.invoke(api,windowId,after.userId));time(deadline);
        IBinder finalActual=token(get.invoke(api,windowId,namespace));time(deadline);
        InputChannelIsolation.need(finalActual==actual&&finalDirect==direct&&service.isBinderAlive()&&actual.isBinderAlive(),
                "INPUT_ACCESSIBILITY_WINDOW_CHANGED");
        return new Read(after,windowId,actual,direct!=null,started,SystemClock.elapsedRealtime());
    }
    private static IBinder token(Object value)throws InputChannelIsolation.Refusal{
        InputChannelIsolation.need(value==null||value instanceof IBinder,"INPUT_ACCESSIBILITY_TOKEN_RUNTIME_TYPE");
        return (IBinder)value;
    }
    private static void requireCurrentParent(ProfileIdentity profile)throws Exception{
        Object current=ActivityManager.class.getMethod("getCurrentUser").invoke(null);
        InputChannelIsolation.need(current instanceof Integer&&((Integer)current).intValue()==profile.parentUserId,
                "INPUT_ACCESSIBILITY_PARENT_NOT_CURRENT");
    }
    private static void time(long deadline)throws InputChannelIsolation.Refusal{
        InputChannelIsolation.need(deadline>SystemClock.elapsedRealtime(),"INPUT_ACCESSIBILITY_LOOKUP_DEADLINE");
    }
}
