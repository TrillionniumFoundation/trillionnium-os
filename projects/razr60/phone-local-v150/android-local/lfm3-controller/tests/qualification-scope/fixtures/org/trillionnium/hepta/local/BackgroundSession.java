package org.trillionnium.hepta.local;
import android.content.Context;
import org.json.JSONObject;
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
    static final class Cleanup {final boolean known;final JSONObject evidence=new JSONObject();Cleanup(boolean value){known=value;}}
    static int controllerDisplay=-1;
    final String taskId,generation,ownerSha256;final Selection selection;final int testDisplay;boolean testClosed;
    BackgroundSession(Context c,String id,String owner,Selection s,QualificationScopeConfig.FilesRoot root){
        if(controllerDisplay<1)throw new UnsupportedOperationException("background requires explicit synthetic fixture admission");
        taskId=id;generation="12345678-1234-1234-1234-123456789abc";ownerSha256=HeptaAccessibilityService.sha(owner.getBytes(java.nio.charset.StandardCharsets.UTF_8));selection=s;testDisplay=controllerDisplay;
    }
    private BackgroundSession(String id,int display,java.util.Set<String> packages){taskId=id;generation="12345678-1234-1234-1234-123456789abc";ownerSha256=HeptaAccessibilityService.sha(("qualification-scope synthetic OWNER: "+id).getBytes(java.nio.charset.StandardCharsets.UTF_8));selection=new Selection(packages.iterator().next(),packages);testDisplay=display;}
    static BackgroundSession fixture(String id,int display,java.util.Set<String> packages){return new BackgroundSession(id,display,packages);}
    static boolean hasUnreleased(Context c){return false;}
    boolean released(){return testClosed;}
    boolean allows(String p){return selection.allowedPackages.contains(p);}
    int displayId(){return testDisplay;}
    JSONObject evidence(){try{return new JSONObject().put("task_id",taskId).put("generation",generation).put("display_id",testDisplay);}catch(Exception error){throw new IllegalStateException(error);}}
    void acceptReconciliation(JSONObject p){throw new UnsupportedOperationException();}
    void verifyRemote(){requireActive();}
    void requireActive(){if(testClosed)throw new IllegalStateException("fixture display closed");}
    void start(HeptaAccessibilityService.Cancellation c){if(controllerDisplay<1||c.isCancelled())throw new UnsupportedOperationException();}
    JSONObject action(String op,String pkg,HeptaAccessibilityService.Cancellation c){throw new UnsupportedOperationException();}
    JSONObject action(String op,String pkg,HeptaAccessibilityService.Cancellation c,long deadline){throw new UnsupportedOperationException();}
    Cleanup close(){testClosed=true;return new Cleanup(true);}
JSONObject fixedIntent(org.trillionnium.hepta.background.FixedIntentTarget target,String payload,String attemptId,HeptaAccessibilityService.Cancellation cancel)throws Exception{throw new IllegalStateException("fixed intent transport not enabled in legacy scope IO fake");}
JSONObject fixedIntent(org.trillionnium.hepta.background.FixedIntentTarget target,String payload,String attemptId,HeptaAccessibilityService.Cancellation cancel,long deadline)throws Exception{throw new IllegalStateException("fixed intent transport not enabled in legacy scope IO fake");}
}
