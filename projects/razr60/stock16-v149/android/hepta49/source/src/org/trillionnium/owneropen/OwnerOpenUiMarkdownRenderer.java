package org.trillionnium.owneropen;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.BackgroundColorSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.LeadingMarginSpan;
import android.text.style.LineBackgroundSpan;
import android.text.style.QuoteSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.StyleSpan;
import android.text.style.TypefaceSpan;

/** Native selectable TextView spans. Source content never becomes HTML or a clickable URI. */
public final class OwnerOpenUiMarkdownRenderer {
    private OwnerOpenUiMarkdownRenderer() {}

    public static CharSequence render(String source, int codeBackground, int quoteColor, float density) {
        OwnerOpenUiMarkdown.Document document = OwnerOpenUiMarkdown.parse(source);
        if (document.marks.isEmpty()) return document.text;
        SpannableString text = new SpannableString(document.text);
        for (OwnerOpenUiMarkdown.Mark mark : document.marks) {
            switch (mark.kind) {
                case HEADING:
                    span(text, new StyleSpan(Typeface.BOLD), mark);
                    span(text, new RelativeSizeSpan(mark.level == 1 ? 1.35f : mark.level == 2 ? 1.22f : 1.1f), mark);
                    break;
                case BOLD:
                    span(text, new StyleSpan(Typeface.BOLD), mark);
                    break;
                case INLINE_CODE:
                    span(text, new TypefaceSpan("monospace"), mark);
                    span(text, new BackgroundColorSpan(codeBackground), mark);
                    span(text, new RelativeSizeSpan(.93f), mark);
                    break;
                case CODE_BLOCK:
                    span(text, new TypefaceSpan("monospace"), mark);
                    span(text, new CodeBlockSurface(codeBackground, mark.start, mark.end, density), mark);
                    span(text, new RelativeSizeSpan(.90f), mark);
                    span(text, new LeadingMarginSpan.Standard(Math.round(12 * density)), mark);
                    break;
                case LIST:
                    span(text, new LeadingMarginSpan.Standard(0, Math.round(18 * density)), mark);
                    break;
                case QUOTE:
                    span(text, new QuoteSpan(quoteColor, Math.max(1, Math.round(2 * density)),
                            Math.round(10 * density)), mark);
                    span(text, new ForegroundColorSpan(quoteColor), mark);
                    break;
            }
        }
        return text;
    }

    /** One continuous surface across wrapped lines, with rounded outer corners only. */
    private static final class CodeBlockSurface implements LineBackgroundSpan {
        private final int blockStart;
        private final int blockEnd;
        private final float radius;
        private final Paint background = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Path outline = new Path();
        private final RectF bounds = new RectF();
        private final float[] corners = new float[8];

        CodeBlockSurface(int color, int start, int end, float density) {
            blockStart = start;
            blockEnd = end;
            radius = Math.max(1, 10 * density);
            background.setColor(color);
            background.setStyle(Paint.Style.FILL);
        }

        @Override public void drawBackground(Canvas canvas, Paint textPaint, int left, int right,
                int top, int baseline, int bottom, CharSequence text, int start, int end, int lineNumber) {
            if (right <= left || bottom <= top || start >= blockEnd || end <= blockStart) return;
            boolean first = start <= blockStart;
            boolean last = end >= blockEnd;
            float curve = Math.min(radius, Math.min((right - left) / 2f, (bottom - top) / 2f));
            for (int i = 0; i < 4; i++) corners[i] = first ? curve : 0;
            for (int i = 4; i < 8; i++) corners[i] = last ? curve : 0;
            bounds.set(left, top, right, bottom);
            outline.reset();
            outline.addRoundRect(bounds, corners, Path.Direction.CW);
            // Own Paint: the shared text Paint is left unchanged, including its alpha/style.
            canvas.drawPath(outline, background);
        }
    }

    private static void span(SpannableString text, Object style, OwnerOpenUiMarkdown.Mark mark) {
        text.setSpan(style, mark.start, mark.end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
    }
}
