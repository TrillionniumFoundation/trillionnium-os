package org.trillionnium.owneropen;

import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Intent;
import android.graphics.drawable.Icon;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;
import android.util.Log;

/** SystemUI entry only. Listening and opening never initialize or dispatch a turn. */
public final class OwnerOpenTileService extends TileService {
    @Override public void onStartListening() {
        super.onStartListening();
        Tile tile = getQsTile();
        if (tile == null) return;
        tile.setLabel(getString(R.string.systemui_entry_label));
        tile.setContentDescription(getString(R.string.systemui_entry_description));
        tile.setIcon(Icon.createWithResource(this, R.drawable.ic_owner_open_entry));
        // This is an entry, not an assertion that execution has been enabled.
        tile.setState(Tile.STATE_INACTIVE);
        tile.updateTile();
    }

    @Override public void onClick() {
        super.onClick();
        if (isLocked()) unlockAndRun(this::openWorkspace);
        else openWorkspace();
    }

    private void openWorkspace() {
        Intent intent = new Intent(Intent.ACTION_MAIN)
                .addCategory(Intent.CATEGORY_LAUNCHER)
                .setComponent(new ComponentName(getPackageName(),
                        "org.trillionnium.owneropen.OwnerOpenShellActivity"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        try {
            PendingIntent entry = PendingIntent.getActivity(this, 0, intent,
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
            startActivityAndCollapse(entry);
        } catch (RuntimeException error) {
            // A failed entry stays failed. No reconnect, send, initialization or retry.
            Log.w("OwnerOpenTile", "Workspace entry unconfirmed: "
                    + error.getClass().getSimpleName());
        }
    }
}
