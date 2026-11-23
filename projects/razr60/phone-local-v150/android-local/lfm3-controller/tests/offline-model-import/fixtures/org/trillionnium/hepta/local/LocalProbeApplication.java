package org.trillionnium.hepta.local;
public class LocalProbeApplication extends android.content.Context {
    public static boolean permissionBlocked;
    boolean taskRunning,taskBlocked,backgroundLease,diagnosticBusy;
    final LocalTaskSession tasks=new LocalTaskSession();
    public LocalProbeApplication(java.io.File files){super(files);}
    static boolean permissionPreparationBlocks(android.content.Context context){return permissionBlocked;}
    static void requirePermissionPreparationIdle(android.content.Context context){if(permissionBlocked)throw new IllegalStateException("fixture permission preparation");}
    void requireModelImportIdle(HeptaAccessibilityService expected){
        if(taskRunning||taskBlocked||backgroundLease||diagnosticBusy||permissionBlocked
                ||HeptaAccessibilityService.connected()!=expected)throw new IllegalStateException("fixture observed busy task/background owner");
    }
    LocalTaskSession taskSession(){return tasks;}
    public android.content.ContentResolver getContentResolver(){return new android.content.ContentResolver();}
}

