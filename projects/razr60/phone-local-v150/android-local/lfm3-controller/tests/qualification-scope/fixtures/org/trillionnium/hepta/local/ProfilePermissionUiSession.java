package org.trillionnium.hepta.local;

import java.io.File;
import org.json.JSONObject;

/** Empty type boundary for original non-profile tests. No worker, window, input,
 * publication, or permission receipt is created. The independent permission UI
 * gate executes the complete production worker with explicit Android IO fakes. */
final class ProfilePermissionUiSession {
    ProfilePermissionUiSession(HeptaAccessibilityService service) {
        if(service==null)throw new AssertionError("current fixture service required");
    }
    static boolean workPending(){return false;}
    void retire(String taskId,String reason){/* No work can exist in this refusing boundary. */}
    void prepare(String taskId,NativeAppGoal goal,TaskAuthorization.Gate authorization,
            QualificationScopeConfig.Bound scope,BackgroundSession background,File evidence,
            HeptaAccessibilityService.Cancellation cancel,long deadline){
        throw new AssertionError("legacy fixture cannot initialize profile permissions");
    }
    JSONObject evidence(String taskId){return null;} // The never-started production worker likewise has no receipt.
}
