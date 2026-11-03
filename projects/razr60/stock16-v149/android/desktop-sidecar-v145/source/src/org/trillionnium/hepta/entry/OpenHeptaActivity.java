package org.trillionnium.hepta.entry;

import android.app.Activity;
import android.app.ActivityOptions;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Toast;

/** Stable launcher/widget destination owned by this sidecar, then explicit HEPTA UI. */
public final class OpenHeptaActivity extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        try {
            if (!EntryIntents.isHeptaAvailable(this) || getDisplay() == null) {
                throw new IllegalStateException("HEPTA or caller display unavailable");
            }
            Intent target = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
                    .setComponent(EntryIntents.HEPTA)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
            ActivityOptions options = ActivityOptions.makeBasic();
            options.setLaunchDisplayId(getDisplay().getDisplayId());
            startActivity(target, options.toBundle());
        } catch (RuntimeException unavailable) {
            Toast.makeText(this, R.string.open_failed, Toast.LENGTH_LONG).show();
        } finally {
            finish();
        }
    }
}
