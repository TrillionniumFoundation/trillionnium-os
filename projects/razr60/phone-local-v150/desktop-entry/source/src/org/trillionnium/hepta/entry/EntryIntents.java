package org.trillionnium.hepta.entry;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;

/** Presentation only. Opens the local controller UI; never starts a task. */
final class EntryIntents {
    static final String SHORTCUT_ID = "hepta-workspace";
    static final ComponentName HEPTA = new ComponentName("org.trillionnium.hepta.local",
            "org.trillionnium.hepta.local.MainActivity");

    static boolean isHeptaAvailable(Context context) {
        try {
            ActivityInfo info = context.getPackageManager().getActivityInfo(HEPTA, 0);
            return info.exported && info.enabled && info.applicationInfo.enabled;
        } catch (PackageManager.NameNotFoundException unavailable) {
            return false;
        }
    }

    static Intent entry(Context context) {
        return new Intent(context, OpenHeptaActivity.class)
                .setAction(Intent.ACTION_VIEW)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
    }

    private EntryIntents() {}
}
