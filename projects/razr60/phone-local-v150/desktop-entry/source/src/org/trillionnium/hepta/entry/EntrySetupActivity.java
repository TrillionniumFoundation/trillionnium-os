package org.trillionnium.hepta.entry;

import android.app.Activity;
import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.ShortcutInfo;
import android.content.pm.ShortcutManager;
import android.graphics.Color;
import android.graphics.Insets;
import android.graphics.drawable.Icon;
import android.os.Bundle;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import java.util.Collections;

/** Uses only the current launcher's public pin flows; never edits its database. */
public final class EntrySetupActivity extends Activity {
    private TextView stateText;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        ScrollView scroll = new ScrollView(this);
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        int pad = Math.round(24 * getResources().getDisplayMetrics().density);
        body.setPadding(pad, pad, pad, pad);
        body.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() {
            @Override public WindowInsets onApplyWindowInsets(View view, WindowInsets insets) {
                Insets bars = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                view.setPadding(pad + bars.left, pad + bars.top, pad + bars.right, pad + bars.bottom);
                return insets;
            }
        });
        TextView title = new TextView(this);
        title.setText(R.string.app_name);
        title.setTextSize(24);
        title.setTextColor(Color.rgb(25, 65, 70));
        body.addView(title);
        TextView description = new TextView(this);
        description.setText(R.string.description);
        description.setTextSize(16);
        description.setPadding(0, pad / 2, 0, pad);
        body.addView(description);
        stateText = new TextView(this);
        body.addView(stateText);
        addButton(body, R.string.open_hepta, new View.OnClickListener() {
            @Override public void onClick(View view) { open(); }
        });
        addButton(body, R.string.pin_shortcut, new View.OnClickListener() {
            @Override public void onClick(View view) { pinShortcut(); }
        });
        addButton(body, R.string.pin_widget, new View.OnClickListener() {
            @Override public void onClick(View view) { pinWidget(); }
        });
        scroll.addView(body);
        setContentView(scroll);
    }

    @Override protected void onResume() {
        super.onResume();
        if (stateText == null) return;
        stateText.setText(EntryIntents.isHeptaAvailable(this)
                ? R.string.hepta_available : R.string.hepta_unavailable);
    }

    private void addButton(LinearLayout parent, int label, View.OnClickListener action) {
        Button button = new Button(this);
        button.setText(label);
        button.setOnClickListener(action);
        parent.addView(button, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
    }

    private boolean requireHepta() {
        if (EntryIntents.isHeptaAvailable(this)) return true;
        Toast.makeText(this, R.string.hepta_unavailable, Toast.LENGTH_LONG).show();
        return false;
    }

    private void open() {
        if (requireHepta()) startActivity(EntryIntents.entry(this));
    }

    private void pinShortcut() {
        if (!requireHepta()) return;
        ShortcutManager manager = getSystemService(ShortcutManager.class);
        if (manager == null || !manager.isRequestPinShortcutSupported()) {
            Toast.makeText(this, R.string.shortcut_unsupported, Toast.LENGTH_LONG).show();
            return;
        }
        ShortcutInfo info = new ShortcutInfo.Builder(this, EntryIntents.SHORTCUT_ID)
                .setActivity(new ComponentName(this, EntrySetupActivity.class))
                .setShortLabel(getString(R.string.hepta_name))
                .setLongLabel(getString(R.string.open_hepta))
                .setIcon(Icon.createWithResource(this, R.drawable.ic_hepta_entry))
                .setIntent(EntryIntents.entry(this))
                .build();
        try {
            // Publishing our own shortcut changes no Moto HOME defaults or existing cells.
            manager.setDynamicShortcuts(Collections.singletonList(info));
            Intent callback = new Intent(this, ShortcutPinnedReceiver.class)
                    .setAction("org.trillionnium.hepta.entry.SHORTCUT_PINNED");
            PendingIntent receipt = PendingIntent.getBroadcast(this, 10, callback,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            boolean submitted = manager.requestPinShortcut(info, receipt.getIntentSender());
            Toast.makeText(this, submitted ? R.string.confirm_in_launcher : R.string.pin_not_submitted,
                    Toast.LENGTH_LONG).show();
        } catch (RuntimeException unavailable) {
            Toast.makeText(this, R.string.pin_not_submitted, Toast.LENGTH_LONG).show();
        }
    }

    private void pinWidget() {
        if (!requireHepta()) return;
        AppWidgetManager manager = AppWidgetManager.getInstance(this);
        if (!manager.isRequestPinAppWidgetSupported()) {
            Toast.makeText(this, R.string.widget_unsupported, Toast.LENGTH_LONG).show();
            return;
        }
        try {
            boolean submitted = manager.requestPinAppWidget(
                    new ComponentName(this, HeptaEntryWidget.class), null, null);
            Toast.makeText(this, submitted ? R.string.confirm_in_launcher : R.string.pin_not_submitted,
                    Toast.LENGTH_LONG).show();
        } catch (RuntimeException unavailable) {
            Toast.makeText(this, R.string.pin_not_submitted, Toast.LENGTH_LONG).show();
        }
    }
}
