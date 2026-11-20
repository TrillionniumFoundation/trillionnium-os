package org.trillionnium.hepta.local;
/** Permission-preparation IO boundary; production controller still calls its real entry guard. */
final class LocalProbeApplication {
 static boolean permissionBusy;
 static void requirePermissionPreparationIdle(android.content.Context context){if(permissionBusy)throw new IllegalStateException("permission preparation active");}
}
