package org.trillionnium.owneropen;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Small presentation-only Markdown subset; no HTML, links, images or executable content. */
public final class OwnerOpenUiMarkdown {
    private static final int MAX_CHARS = 131_072;
    private static final int MAX_LINES = 4_096;
    private static final int MAX_MARKS = 2_048;

    public enum Kind { HEADING, BOLD, INLINE_CODE, CODE_BLOCK, LIST, QUOTE }

    public static final class Mark {
        public final Kind kind;
        public final int start;
        public final int end;
        public final int level;
        Mark(Kind kind, int start, int end, int level) {
            this.kind = kind; this.start = start; this.end = end; this.level = level;
        }
    }

    public static final class Document {
        public final String text;
        public final List<Mark> marks;
        public final boolean plainFallback;
        Document(String text, List<Mark> marks, boolean plainFallback) {
            this.text = text;
            this.marks = Collections.unmodifiableList(new ArrayList<>(marks));
            this.plainFallback = plainFallback;
        }
    }

    private static final class Limit extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    private static final class Line {
        final int start, end, next;
        Line(int start, int end, int next) { this.start = start; this.end = end; this.next = next; }
    }

    private static final class Fence {
        final char marker;
        final int count;
        Fence(char marker, int count) { this.marker = marker; this.count = count; }
    }

    private final String source;
    private final StringBuilder output;
    private final List<Mark> marks = new ArrayList<>();
    private int budget;

    private OwnerOpenUiMarkdown(String source) {
        this.source = source;
        output = new StringBuilder(source.length());
        budget = Math.max(256, source.length() * 16);
    }

    public static Document parse(String source) {
        if (source == null) source = "";
        if (source.isEmpty() || source.length() > MAX_CHARS)
            return new Document(source, Collections.emptyList(), source.length() > MAX_CHARS);
        try { return new OwnerOpenUiMarkdown(source).parseDocument(); }
        catch (Limit exceeded) {
            // Pathological or excessively fragmented input remains complete, selectable plain text.
            return new Document(source, Collections.emptyList(), true);
        }
    }

    private Document parseDocument() {
        List<Line> lines = new ArrayList<>();
        for (int start = 0; start < source.length();) {
            int newline = source.indexOf('\n', start);
            int next = newline < 0 ? source.length() : newline + 1;
            int end = newline < 0 ? next : newline;
            if (end > start && source.charAt(end - 1) == '\r') end--;
            lines.add(new Line(start, end, next));
            if (lines.size() > MAX_LINES) throw new Limit();
            start = next;
        }
        for (int i = 0; i < lines.size(); i++) {
            Line line = lines.get(i);
            Fence fence = openingFence(line);
            if (fence != null) {
                int closing = i + 1;
                while (closing < lines.size() && !closingFence(lines.get(closing), fence)) {
                    use(lines.get(closing).end - lines.get(closing).start + 1);
                    closing++;
                }
                if (closing == lines.size()) {
                    // In-progress fences stay literal until the closing delimiter arrives.
                    output.append(source, line.start, source.length());
                    break;
                }
                int begin = output.length();
                for (int body = i + 1; body < closing; body++) {
                    Line code = lines.get(body);
                    output.append(source, code.start, code.next);
                }
                add(Kind.CODE_BLOCK, begin, output.length(), 0);
                i = closing;
                continue;
            }
            parseLine(line);
        }
        return new Document(output.toString(), marks, false);
    }

    private int contentStart(Line line) {
        int start = line.start;
        while (start < line.end && start - line.start < 3 && source.charAt(start) == ' ') start++;
        return start;
    }

    private Fence openingFence(Line line) {
        int begin = contentStart(line);
        if (begin == line.end) return null;
        char marker = source.charAt(begin);
        if (marker != '`' && marker != '~') return null;
        int end = begin;
        while (end < line.end && source.charAt(end) == marker) { use(1); end++; }
        if (end - begin < 3 || end - begin > 16) return null;
        // Only a bounded language label is supported; arbitrary info strings remain literal.
        for (int i = end; i < line.end; i++) {
            use(1);
            char ch = source.charAt(i);
            if (!(Character.isLetterOrDigit(ch) || ch == ' ' || ch == '\t' || ch == '_'
                    || ch == '-' || ch == '+' || ch == '#' || ch == '.')) return null;
        }
        return new Fence(marker, end - begin);
    }

    private boolean closingFence(Line line, Fence fence) {
        int begin = contentStart(line), end = begin;
        while (end < line.end && source.charAt(end) == fence.marker) { use(1); end++; }
        if (end - begin < fence.count) return false;
        while (end < line.end) {
            use(1);
            if (source.charAt(end) != ' ' && source.charAt(end) != '\t') return false;
            end++;
        }
        return true;
    }

    private void parseLine(Line line) {
        int start = contentStart(line);
        if (start == line.end) { output.append(source, line.start, line.next); return; }
        int heading = 0;
        while (start + heading < line.end && source.charAt(start + heading) == '#') heading++;
        if (heading > 0 && heading <= 6 && start + heading < line.end
                && isSpace(source.charAt(start + heading))) {
            int body = start + heading;
            while (body < line.end && isSpace(source.charAt(body))) body++;
            if (body == line.end) { output.append(source, line.start, line.next); return; }
            int begin = output.length();
            inline(body, line.end, true);
            add(Kind.HEADING, begin, output.length(), heading);
            output.append(source, line.end, line.next);
            return;
        }
        if (source.charAt(start) == '>' && (start + 1 == line.end || isSpace(source.charAt(start + 1)))) {
            int body = start + 1;
            if (body < line.end && isSpace(source.charAt(body))) body++;
            int begin = output.length();
            inline(body, line.end, true);
            output.append(source, line.end, line.next);
            add(Kind.QUOTE, begin, output.length(), 1);
            return;
        }
        int markerEnd = listMarkerEnd(start, line.end);
        if (markerEnd > start) {
            int begin = output.length();
            char first = source.charAt(start);
            if (first == '-' || first == '+' || first == '*') output.append("• ");
            else output.append(source, start, markerEnd).append(' ');
            int body = markerEnd;
            while (body < line.end && isSpace(source.charAt(body))) body++;
            inline(body, line.end, true);
            output.append(source, line.end, line.next);
            add(Kind.LIST, begin, output.length(), 1);
            return;
        }
        inline(line.start, line.end, true);
        output.append(source, line.end, line.next);
    }

    private int listMarkerEnd(int start, int end) {
        char first = source.charAt(start);
        if ((first == '-' || first == '*' || first == '+') && start + 1 < end
                && isSpace(source.charAt(start + 1))) return start + 1;
        int digit = start;
        while (digit < end && digit - start < 9 && source.charAt(digit) >= '0' && source.charAt(digit) <= '9') digit++;
        if (digit > start && digit + 1 < end && (source.charAt(digit) == '.' || source.charAt(digit) == ')')
                && isSpace(source.charAt(digit + 1))) return digit + 1;
        return start;
    }

    private void inline(int start, int end, boolean allowBold) {
        for (int i = start; i < end;) {
            use(1);
            char ch = source.charAt(i);
            if (ch == '`') {
                int run = i + 1;
                while (run < end && source.charAt(run) == '`') { use(1); run++; }
                int count = run - i;
                int close = count <= 2 ? closeTicks(run, end, count) : -1;
                if (close > run) {
                    int begin = output.length();
                    output.append(source, run, close);
                    add(Kind.INLINE_CODE, begin, output.length(), 0);
                    i = close + count;
                    continue;
                }
                if (close < 0 && count <= 2) {
                    output.append(source, i, end);
                    return;
                }
                output.append(source, i, run);
                i = run;
                continue;
            }
            if (allowBold && (ch == '*' || ch == '_') && i + 2 < end && source.charAt(i + 1) == ch
                    && !Character.isWhitespace(source.charAt(i + 2))
                    && source.charAt(i + 2) != ch && (ch != '_' || i == start || !Character.isLetterOrDigit(source.charAt(i - 1)))) {
                int close = closeBold(i + 2, end, ch);
                if (close > i + 2) {
                    int begin = output.length();
                    inline(i + 2, close, false);
                    add(Kind.BOLD, begin, output.length(), 0);
                    i = close + 2;
                    continue;
                }
            }
            output.append(ch);
            i++;
        }
    }

    private int closeTicks(int start, int end, int count) {
        for (int i = start; i < end;) {
            use(1);
            if (source.charAt(i) != '`') { i++; continue; }
            int run = i + 1;
            while (run < end && source.charAt(run) == '`') { use(1); run++; }
            if (run - i == count) return i;
            i = run;
        }
        return -1;
    }

    private int closeBold(int start, int end, char marker) {
        for (int i = start; i + 1 < end; i++) {
            use(1);
            if (source.charAt(i) == '`') {
                int run = i + 1;
                while (run < end && source.charAt(run) == '`') { use(1); run++; }
                int close = run - i <= 2 ? closeTicks(run, end, run - i) : -1;
                if (close >= run) { i = close + run - i - 1; continue; }
            }
            if (source.charAt(i) == marker && source.charAt(i + 1) == marker
                    && i > start && !Character.isWhitespace(source.charAt(i - 1))
                    && source.charAt(i - 1) != marker
                    && (i + 2 == end || source.charAt(i + 2) != marker)
                    && (marker != '_' || i + 2 == end || !Character.isLetterOrDigit(source.charAt(i + 2)))) return i;
        }
        return -1;
    }

    private static boolean isSpace(char ch) { return ch == ' ' || ch == '\t'; }

    private void add(Kind kind, int start, int end, int level) {
        if (start == end) return;
        if (marks.size() >= MAX_MARKS) throw new Limit();
        marks.add(new Mark(kind, start, end, level));
    }

    private void use(int work) {
        budget -= work;
        if (budget < 0) throw new Limit();
    }
}
