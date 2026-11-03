package org.trillionnium.owneropen;

import android.app.Activity;
import android.app.ActivityOptions;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Toast;

/** Explicit presentation-only entry for an OEM external-display shortcut.
 * The Activity's actual display is the route authority. No hardcoded display 6,
 * fold-state override, hidden Motorola API, background receiver or request extra.
 */
public final class OwnerOpenCoverEntryActivity extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        try {
            if (getDisplay() == null) throw new IllegalStateException("No attached display");
            int displayId = getDisplay().getDisplayId();
            Intent conversation = new Intent(this, OwnerOpenShellActivity.class);
            conversation.setAction(Intent.ACTION_MAIN);
            conversation.addCategory(Intent.CATEGORY_LAUNCHER);
            conversation.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP
                    | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            ActivityOptions route = ActivityOptions.makeBasic().setLaunchDisplayId(displayId);
            startActivity(conversation, route.toBundle());
        } catch (RuntimeException unavailable) {
            Toast.makeText(this, getResources().getConfiguration().getLocales().get(0)
                    .getLanguage().equals("zh") ? "暂时无法在此屏幕打开 HEPTA" :
                    "HEPTA cannot open on this display", Toast.LENGTH_SHORT).show();
        } finally { finish(); }
    }
}
