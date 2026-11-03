package org.trillionnium.hepta.controlprobe;

import android.app.Activity;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Insets;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.os.Bundle;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowInsets;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Locale;

/** Random, one-attempt visual challenge: all instructions and targets are pixels. */
public final class VisualChallengeActivity extends Activity {
    private final SecureRandom random = new SecureRandom();
    private String code;
    private boolean resolved;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        setTitle("HEPTA 图片型界面验证");
        code = String.format(Locale.ROOT, "%08X", random.nextInt());
        setContentView(new ChallengeView());
        // Neither Intent extras nor saved Bundles can choose a target or a seed.
    }

    private void finishAttempt(boolean correct) {
        if (resolved) return;
        resolved = true;
        LinearLayout root = ProbeUi.column(this);
        root.addView(ProbeUi.text(this, correct ? "图片操作成功" : "本轮未命中", 27));
        TextView receipt = ProbeUi.text(this,
                (correct ? "HEPTA_VISUAL_OK " : "HEPTA_VISUAL_MISS ") + code, 20);
        receipt.setId(R.id.visual_receipt);
        root.addView(receipt);
        TextView publicCode = ProbeUi.text(this, "挑战码：" + code, 17);
        publicCode.setId(R.id.visual_challenge_code);
        root.addView(publicCode);
        root.addView(ProbeUi.text(this, "本轮只接受一次目标点击；新一轮需要重新打开验证页。", 16));
        setContentView(root);
        // The success receipt is only created after one actual in-bounds hit.
    }

    private final class ChallengeView extends View {
        private final int[] colors = { Color.rgb(39, 93, 218), Color.rgb(0, 153, 105), Color.rgb(224, 119, 24) };
        private final String[] colorNames = { "蓝色", "绿色", "橙色" };
        private final String[] shapeNames = { "圆形", "三角形", "方形" };
        private final String[] words = { "春", "夏", "秋", "冬", "山", "水", "风", "云", "星" };
        private final ArrayList<Integer> order = new ArrayList<>();
        private final ArrayList<Integer> wordOrder = new ArrayList<>();
        private final RectF[] cards = new RectF[9];
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final float density = getResources().getDisplayMetrics().density;
        private final float[] jitterX = new float[9];
        private final float[] jitterY = new float[9];
        private final int target;
        private Insets bars = Insets.NONE;

        ChallengeView() {
            super(VisualChallengeActivity.this);
            for (int i = 0; i < 9; i++) { order.add(i); wordOrder.add(i); cards[i] = new RectF(); }
            Collections.shuffle(order, random);
            Collections.shuffle(wordOrder, random);
            target = random.nextInt(9);
            for (int i = 0; i < 9; i++) {
                jitterX[i] = (random.nextFloat() - .5f) * .08f;
                jitterY[i] = (random.nextFloat() - .5f) * .08f;
            }
            // A hierarchy dump can expose at most the enclosing surface. It
            // cannot contain this Canvas's painted target text or hit regions.
            setContentDescription(null);
            setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS);
            setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
            setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() {
              @Override public WindowInsets onApplyWindowInsets(View view, WindowInsets insets) {
                bars = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                invalidate();
                return insets;
              }
            });
        }

        private float dp(float value) { return value * density; }

        private void line(Canvas canvas, String text, float y, float sp, int color) {
            paint.setColor(color);
            paint.setStyle(Paint.Style.FILL);
            paint.setTextAlign(Paint.Align.CENTER);
            paint.setTextSize(sp * getResources().getDisplayMetrics().scaledDensity);
            canvas.drawText(text, getWidth() / 2f, y, paint);
        }

        @Override protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            canvas.drawColor(ProbeUi.BACKGROUND);
            float top = bars.top + dp(24);
            int targetCombo = order.get(target);
            String request = colorNames[targetCombo / 3] + " · " + shapeNames[targetCombo % 3] + " · " + words[wordOrder.get(target)];
            line(canvas, "请点击符合要求的图卡", top + dp(26), 23, ProbeUi.INK);
            line(canvas, request, top + dp(64), 24, Color.rgb(30, 77, 158));
            line(canvas, "只点一次；请按当前画面判断", top + dp(94), 15, Color.rgb(86, 98, 117));
            line(canvas, "挑战 " + code, top + dp(120), 13, Color.rgb(100, 111, 128));
            float margin = dp(18), gap = dp(12);
            float gridTop = top + dp(145);
            float usable = getHeight() - bars.bottom - dp(18) - gridTop;
            float width = (getWidth() - margin * 2 - gap * 2) / 3f;
            float height = Math.min(width * 1.32f, (usable - gap * 2) / 3f);
            if (height <= dp(32) || width <= dp(32)) return;
            for (int index = 0; index < 9; index++) {
                float x = margin + (index % 3) * (width + gap) + jitterX[index] * width;
                float y = gridTop + (index / 3) * (height + gap) + jitterY[index] * height;
                RectF card = cards[index];
                card.set(x, y, x + width, y + height);
                paint.setStyle(Paint.Style.FILL);
                paint.setColor(Color.WHITE);
                canvas.drawRoundRect(card, dp(15), dp(15), paint);
                paint.setStyle(Paint.Style.STROKE);
                paint.setStrokeWidth(dp(1));
                paint.setColor(Color.rgb(207, 216, 231));
                canvas.drawRoundRect(card, dp(15), dp(15), paint);
                paint.setStyle(Paint.Style.FILL);
                int combo = order.get(index), shape = combo % 3;
                paint.setColor(colors[combo / 3]);
                float radius = Math.min(width * .25f, height * .24f);
                float cx = card.centerX(), cy = card.top + height * .38f;
                if (shape == 0) canvas.drawCircle(cx, cy, radius, paint);
                else if (shape == 1) {
                    Path path = new Path();
                    path.moveTo(cx, cy - radius);
                    path.lineTo(cx - radius, cy + radius);
                    path.lineTo(cx + radius, cy + radius);
                    path.close(); canvas.drawPath(path, paint);
                } else canvas.drawRoundRect(cx - radius, cy - radius, cx + radius, cy + radius, dp(3), dp(3), paint);
                paint.setTextAlign(Paint.Align.CENTER);
                paint.setColor(ProbeUi.INK);
                paint.setTextSize(Math.min(dp(23), height * .22f));
                canvas.drawText(words[wordOrder.get(index)], cx, card.top + height * .84f, paint);
            }
        }

        @Override public boolean onTouchEvent(MotionEvent event) {
            if (resolved) return true;
            if (event.getActionMasked() == MotionEvent.ACTION_DOWN) return true;
            if (event.getActionMasked() == MotionEvent.ACTION_UP) {
                for (int index = 0; index < cards.length; index++) {
                    if (cards[index].contains(event.getX(), event.getY())) {
                        finishAttempt(index == target);
                        return true;
                    }
                }
                return true;
            }
            return true;
        }
    }
}
