package org.trillionnium.hepta.local;
import android.content.Context;
import org.json.JSONObject;
/** Explicit boundary fake for foreground scope/owner regressions. Never claims background support. */
final class BackgroundSession {
    static final class Selection {
        final String initialPackage;final java.util.List<String> allowedPackages;
        Selection(String initial,java.util.Set<String> packages){initialPackage=initial;allowedPackages=new java.util.ArrayList<String>(packages);}
        JSONObject json(){return new JSONObject();}
    }
    static final class Cleanup {final boolean known=false;final JSONObject evidence=new JSONObject();}
    final String taskId="unused",generation="unused";final Selection selection=null;
    BackgroundSession(Context c,String id,String owner,Selection s,QualificationScopeConfig.FilesRoot root){throw new UnsupportedOperationException("background is outside foreground fixture");}
    static boolean hasUnreleased(Context c){return false;}
    boolean released(){throw new UnsupportedOperationException();}
    boolean allows(String p){throw new UnsupportedOperationException();}
    int displayId(){throw new UnsupportedOperationException();}
    JSONObject evidence(){throw new UnsupportedOperationException();}
    void acceptReconciliation(JSONObject p){throw new UnsupportedOperationException();}
    void verifyRemote(){throw new UnsupportedOperationException();}
    void requireActive(){throw new UnsupportedOperationException();}
    void start(HeptaAccessibilityService.Cancellation c){throw new UnsupportedOperationException();}
    JSONObject action(String op,String pkg,HeptaAccessibilityService.Cancellation c){throw new UnsupportedOperationException();}
    Cleanup close(){throw new UnsupportedOperationException();}
}
