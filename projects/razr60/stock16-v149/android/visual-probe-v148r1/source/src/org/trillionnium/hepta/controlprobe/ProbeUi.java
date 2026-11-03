package org.trillionnium.hepta.controlprobe;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Insets;
import android.view.View;
import android.view.WindowInsets;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

final class ProbeUi {
    static final int INK = Color.rgb(22, 33, 54);
    static final int BACKGROUND = Color.rgb(244, 247, 252);

    static int dp(Activity context, float value) {
        return Math.round(value * context.getResources().getDisplayMetrics().density);
    }

    static LinearLayout column(Activity activity) {
        LinearLayout root = new LinearLayout(activity);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BACKGROUND);
        root.setPadding(dp(activity, 24), dp(activity, 24), dp(activity, 24), dp(activity, 24));
        root.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() {
          @Override public WindowInsets onApplyWindowInsets(View view, WindowInsets insets) {
            Insets bars = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            view.setPadding(dp(activity, 24) + bars.left, dp(activity, 24) + bars.top,
                    dp(activity, 24) + bars.right, dp(activity, 24) + bars.bottom);
            return insets;
          }
        });
        return root;
    }

    static TextView text(Activity activity, String value, int sp) {
        TextView text = new TextView(activity);
        text.setText(value);
        text.setTextSize(sp);
        text.setTextColor(INK);
        text.setPadding(0, dp(activity, 8), 0, dp(activity, 8));
        return text;
    }

    static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(64);
            for (byte b : digest) result.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
            return result.toString();
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private ProbeUi() {}
}
