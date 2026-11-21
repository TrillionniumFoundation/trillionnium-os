package org.trillionnium.hepta.local;
public class LocalProbeApplication extends android.content.Context {
 public static boolean permissionBlocked;public LocalProbeApplication(java.io.File path){super(path);}
 static boolean permissionPreparationBlocks(android.content.Context context){return permissionBlocked;}
 static void requirePermissionPreparationIdle(android.content.Context context){if(permissionBlocked)throw new IllegalStateException("synthetic independent permission barrier");}
}
