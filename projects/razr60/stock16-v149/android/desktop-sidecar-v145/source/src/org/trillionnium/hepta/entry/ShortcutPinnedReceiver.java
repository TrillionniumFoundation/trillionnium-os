package org.trillionnium.hepta.entry;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ShortcutInfo;
import android.content.pm.ShortcutManager;
import android.widget.Toast;

public final class ShortcutPinnedReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        if (!"org.trillionnium.hepta.entry.SHORTCUT_PINNED".equals(intent.getAction())) return;
        ShortcutManager manager = context.getSystemService(ShortcutManager.class);
        if (manager == null) return;
        try {
            for (ShortcutInfo shortcut : manager.getPinnedShortcuts()) {
                if (EntryIntents.SHORTCUT_ID.equals(shortcut.getId()) && shortcut.isPinned()) {
                    Toast.makeText(context, R.string.shortcut_pinned, Toast.LENGTH_LONG).show();
                    return;
                }
            }
        } catch (RuntimeException unknown) {
            // A callback alone is not proof that the launcher saved the shortcut.
        }
    }
}
