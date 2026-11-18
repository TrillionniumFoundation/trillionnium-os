package org.trillionnium.hepta.local;
import android.content.Context;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;
/** Explicit IO boundary fake. Controlled display metadata is not an Android VirtualDisplay test. */
final class BackgroundSession {
    static final class Selection {
        final String initialPackage;final java.util.List<String> allowedPackages;
        Selection(String initial,java.util.Set<String> packages){initialPackage=initial;allowedPackages=new java.util.ArrayList<String>(packages);}
        Selection(String initial,java.util.Set<String> packages,String uiInitial,java.util.Set<String> uiAllowed,String ownerSha,String recognition){
            throw new AssertionError("owner-derived background selection is outside this legacy scope fixture");
        }
        /** Synthetic explicit UI selection only; no owner-intent narrowing is asserted. */
        JSONObject json(){try{return new JSONObject().put("mode","background")
                .put("allowed_packages",new org.json.JSONArray(allowedPackages)).put("bootstrap_package",initialPackage)
                .put("bootstrap_source","owner_selected_initial_app").put("bootstrap_model_issued",false)
                .put("main_display_fallback",false).put("home_allowed",false);
            }catch(Exception failure){throw new IllegalStateException("synthetic explicit Selection encoding failed",failure);}}
    }
    static final class Cleanup {final boolean known;final JSONObject evidence=new JSONObject();final Object prelaunchRecovery=null,postlaunchRecovery=null,publicProfileRecovery=null;Cleanup(boolean value){known=value;}}
    static int controllerDisplay=-1;
    final String taskId,generation,ownerSha256;final Selection selection;final int testDisplay;boolean testClosed;
    BackgroundSession(Context c,String id,String owner,Selection s,QualificationScopeConfig.FilesRoot root){
        if(controllerDisplay<1)throw new UnsupportedOperationException("background requires explicit synthetic fixture admission");
        taskId=id;generation="12345678-1234-1234-1234-123456789abc";ownerSha256=HeptaAccessibilityService.sha(owner.getBytes(java.nio.charset.StandardCharsets.UTF_8));selection=s;testDisplay=controllerDisplay;
    }
    static BackgroundSession experimentalPublicOwnGroup(Context c,String id,String owner,Selection s,QualificationScopeConfig.FilesRoot root){
        throw new AssertionError("legacy scope fixture cannot create an experimental public display lease");
    }
    private BackgroundSession(String id,int display,java.util.Set<String> packages){taskId=id;generation="12345678-1234-1234-1234-123456789abc";ownerSha256=HeptaAccessibilityService.sha(("qualification-scope synthetic OWNER: "+id).getBytes(java.nio.charset.StandardCharsets.UTF_8));selection=new Selection(packages.iterator().next(),packages);testDisplay=display;}
    static BackgroundSession fixture(String id,int display,java.util.Set<String> packages){return new BackgroundSession(id,display,packages);}
    static boolean hasUnreleased(Context c){return false;}
    boolean released(){return testClosed;}
    boolean prelaunchRecoveryEligible(){return false;} // This legacy IO fake cannot establish profile recovery.
    boolean postlaunchRecoveryEligible(){return false;} // No launched-profile absence authority in this IO fake.
    boolean publicProfileRecoveryEligible(){return false;} // No public-profile absence authority in this legacy IO fake.
    boolean allows(String p){return selection.allowedPackages.contains(p);}
    int displayId(){return testDisplay;}
    JSONObject evidence(){try{return new JSONObject().put("task_id",taskId).put("generation",generation).put("display_id",testDisplay);}catch(Exception error){throw new IllegalStateException(error);}}
    void acceptReconciliation(JSONObject p){throw new UnsupportedOperationException();}
    void acceptReconciliation(Cleanup p){throw new UnsupportedOperationException("no owned profile recovery receipt in legacy IO fixture");}
    void verifyRemote(){requireActive();}
    ProfileTarget profileTarget(){
        if(selection.profileTarget!=null)throw new UnsupportedOperationException("legacy IO fixture cannot qualify a managed profile");
        return null;
    }
    WindowOwnership verifyProfileWindow(int window,int task,HeptaAccessibilityService.Cancellation cancel,long deadline){
        throw new UnsupportedOperationException("no broker or actual profile window in legacy IO fixture");
    }
    void requireProfileWindow(WindowOwnership proof,int window,int task,long now){
        throw new UnsupportedOperationException("no live profile proof in legacy IO fixture");
    }
    void requireHistoricalProfileWindow(WindowOwnership proof,int window,int task,long capturedAt){
        throw new UnsupportedOperationException("no actual received profile proof in legacy IO fixture");
    }
    void verifyProfileInstallation(){throw new UnsupportedOperationException("no profile installation qualification in legacy fixture");}
    void requireActive(){if(testClosed)throw new IllegalStateException("fixture display closed");}
    /** This IO fake only represents the legacy scope; it cannot admit new display authority. */
    boolean usesExperimentalPublicOwnGroup(){return false;}
    void requireAdmissionActive(){requireActive();}
    void requirePolicyBeforeEffect(HeptaAccessibilityService.Cancellation cancel,long deadline){
        if(usesExperimentalPublicOwnGroup())throw new AssertionError("legacy fixture cannot qualify experimental effect entry");
        // Actual legacy production branch returns without adding a policy proof.
    }
    interface InitializationHandler {
        void prepare(BackgroundSession session,long deadline,HeptaAccessibilityService.Cancellation cancel)throws Exception;
    }
    void requirePermissionPreparationActive(){throw new AssertionError("legacy fixture has no owned profile permission preparation");}
    void startWithPermissionInitialization(HeptaAccessibilityService.Cancellation cancel,InitializationHandler handler,long deadline){
        throw new AssertionError("legacy fixture cannot launch or prepare a profile permission window");
    }
    void start(HeptaAccessibilityService.Cancellation c){if(controllerDisplay<1||c.isCancelled())throw new UnsupportedOperationException();}
    JSONObject action(String op,String pkg,HeptaAccessibilityService.Cancellation c){throw new UnsupportedOperationException();}
    JSONObject action(String op,String pkg,HeptaAccessibilityService.Cancellation c,long deadline){throw new UnsupportedOperationException();}
    Cleanup close(){testClosed=true;return new Cleanup(true);}
JSONObject fixedIntent(org.trillionnium.hepta.background.FixedIntentTarget target,String payload,String attemptId,HeptaAccessibilityService.Cancellation cancel)throws Exception{throw new IllegalStateException("fixed intent transport not enabled in legacy scope IO fake");}
JSONObject fixedIntent(org.trillionnium.hepta.background.FixedIntentTarget target,String payload,String attemptId,HeptaAccessibilityService.Cancellation cancel,long deadline)throws Exception{throw new IllegalStateException("fixed intent transport not enabled in legacy scope IO fake");}
}
