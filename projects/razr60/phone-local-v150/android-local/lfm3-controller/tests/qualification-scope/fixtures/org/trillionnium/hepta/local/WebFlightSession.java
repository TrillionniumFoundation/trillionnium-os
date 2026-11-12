package org.trillionnium.hepta.local;

import android.content.Context;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import org.json.JSONObject;
import org.trillionnium.hepta.local.web.WebFlightGoal;
import org.trillionnium.hepta.local.web.WebShoppingGoal;

/** Explicit empty-Web-journal IO boundary in the legacy Notes/controller harness.
 * A real Web OWNER, selected helper, journal, connection, observation, dispatch or
 * cleanup is unsupported and throws. The real Web classes have their own gate.
 */
final class WebFlightSession {
    interface Observer { PhoneObservation observe() throws Exception; }
    static final class Cleanup {
        final boolean known;
        final JSONObject evidence;
        private Cleanup(){throw unavailable();}
    }
    final String taskId;
    final WebFlightGoal goal=null;
    final TaskAuthorization.Gate authorization;
    WebFlightSession(HeptaAccessibilityService service,String task,String owner,
            TaskAuthorization.Gate auth,BackgroundSession background,
            QualificationScopeConfig.FilesRoot root,File evidence,TaskCompletionGate completion,
            HeptaAccessibilityService.Cancellation cancellation){throw unavailable();}
    private static AssertionError unavailable(){
        return new AssertionError("legacy fixture has no Web helper IO or action implementation");
    }
    static boolean hasUnreleased(Context context){
        if(context==null||Files.exists(new File(context.getFilesDir(),"web-helper.active.json").toPath(),
                LinkOption.NOFOLLOW_LINKS))throw unavailable();
        return false; // Explicit empty fixture journal, never a production cleanup claim.
    }
    static void validateSelection(String owner,BackgroundSession.Selection selection){
        if(WebFlightGoal.parse(owner)!=null||WebShoppingGoal.parse(owner)!=null
                ||selection!=null&&selection.allowedPackages.contains("org.trillionnium.hepta.webhelper"))
            throw unavailable();
    }
    static boolean supported(String owner){
        if(WebFlightGoal.parse(owner)!=null||WebShoppingGoal.parse(owner)!=null)throw unavailable();
        return false;
    }
    void attach(long deadline){throw unavailable();}
    PhoneObservation observe(PhoneObservation initial,Observer observer,long deadline){throw unavailable();}
    void beforeModelAction(ActionDecision action,String run,long deadline){throw unavailable();}
    void requireDispatch(ActionDecision action,String run){throw unavailable();}
    WebFlightNativeStability.Permit flightNativePermitForDispatch(ActionDecision action,PhoneObservation frame){throw unavailable();}
    void acceptFlightNativeCheck(ActionDecision action,PhoneObservation frame,HeptaAccessibilityService.FlightNativeCheck actual){throw unavailable();}
    WebRegionNativeBridge nativeRegionForDispatch(ActionDecision action,String run,PhoneObservation frame){throw unavailable();}
    void acceptNativeRegionCheck(ActionDecision action,String run,HeptaAccessibilityService.NativeRegionCheck actual){throw unavailable();}
    void beforeNativeClickInvocation(ActionDecision action,String run){throw unavailable();}
    void modelActionOutcome(ActionDecision action,String run,HeptaAccessibilityService.ActionOutcome outcome,
                            long dispatchStarted,long dispatchEnded){throw unavailable();}
    boolean released(){throw unavailable();}
    void acceptReconciliation(Cleanup proof){throw unavailable();}
    void serviceRetired(){throw unavailable();}
    Cleanup close(String reason){throw unavailable();}
    static Cleanup reconcile(Context context){throw unavailable();}
}
