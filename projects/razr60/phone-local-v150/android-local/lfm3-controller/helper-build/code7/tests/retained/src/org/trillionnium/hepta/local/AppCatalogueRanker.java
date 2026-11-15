package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Immutable local launcher snapshot. Searching this data never launches an app. */
public final class AppCatalogueRanker {
    public static final int PAGE_SIZE = 6;
    public static final int MAX_APPS = 4096;
    public static final int MAX_OFFSET = MAX_APPS - 1;
    public static final int MAX_QUERY_CODE_POINTS = 64;
    public static final String SOURCE = "installed_launcher_snapshot";

    public static final class Entry {
        public final String packageName, label;
        private final String normalizedPackage, normalizedLabel;

        private Entry(String packageName, String label) {
            this.packageName = packageName;
            this.label = label;
            normalizedPackage = normalize(packageName);
            normalizedLabel = normalize(label);
        }
    }

    public static final class Page {
        public final String query, catalogueSha256;
        public final int offset, totalApps, matchingApps;
        public final List<Entry> apps;

        private Page(String query, int offset, int totalApps, int matchingApps,
                     String catalogueSha256, List<Entry> apps) {
            this.query = query;
            this.offset = offset;
            this.totalApps = totalApps;
            this.matchingApps = matchingApps;
            this.catalogueSha256 = catalogueSha256;
            this.apps = Collections.unmodifiableList(new ArrayList<Entry>(apps));
        }

        /** Advance past the prefix actually supplied to the model, not omitted rows. */
        public int nextOffset(int shown) {
            if (shown < 0 || shown > apps.size()) throw new IllegalArgumentException("invalid app projection");
            return offset + shown < matchingApps ? offset + shown : -1;
        }
    }

    private final List<Entry> ranked;
    public final String catalogueSha256;

    public AppCatalogueRanker(Map<String, String> installedLauncherApps, String owner) {
        if (installedLauncherApps == null || installedLauncherApps.size() > MAX_APPS || owner == null)
            throw new IllegalArgumentException("invalid installed launcher snapshot");
        final String normalizedOwner = normalize(owner);
        List<Entry> rows = new ArrayList<Entry>();
        for (Map.Entry<String, String> value : installedLauncherApps.entrySet()) {
            String pkg = value.getKey();
            if (pkg == null || pkg.length() > 255 || !pkg.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+"))
                throw new IllegalArgumentException("invalid installed launcher package");
            // The displayed label is untrusted data. Limit only the stored display
            // label; every installed package stays searchable and pageable.
            rows.add(new Entry(pkg, boundedLabel(value.getValue())));
        }
        Collections.sort(rows, new Comparator<Entry>() {
            @Override public int compare(Entry a, Entry b) { return a.packageName.compareTo(b.packageName); }
        });
        catalogueSha256 = fingerprint(rows);
        Collections.sort(rows, new Comparator<Entry>() {
            @Override public int compare(Entry a, Entry b) {
                int priority = Integer.compare(ownerPriority(b, normalizedOwner), ownerPriority(a, normalizedOwner));
                return priority != 0 ? priority : a.packageName.compareTo(b.packageName);
            }
        });
        ranked = Collections.unmodifiableList(rows);
    }

    /** Empty query browses all installed launcher entries; nonempty query is a substring search. */
    public Page search(String query, int offset) {
        validateQuery(query);
        if (offset < 0 || offset > MAX_OFFSET) throw new IllegalArgumentException("app search offset out of range");
        final String term = normalize(query);
        List<Entry> matches = new ArrayList<Entry>();
        for (Entry entry : ranked) {
            if (term.isEmpty() || entry.normalizedPackage.contains(term) || entry.normalizedLabel.contains(term))
                matches.add(entry);
        }
        if (!term.isEmpty()) {
            // Collections.sort is stable: ties retain the owner's ranking and
            // existing package order, independent of PackageManager iteration.
            Collections.sort(matches, new Comparator<Entry>() {
                @Override public int compare(Entry a, Entry b) {
                    return Integer.compare(searchPriority(b, term), searchPriority(a, term));
                }
            });
        }
        int from = Math.min(offset, matches.size()), to = Math.min(from + PAGE_SIZE, matches.size());
        return new Page(query, offset, ranked.size(), matches.size(), catalogueSha256, matches.subList(from, to));
    }

    public static void validateQuery(String query) {
        if (query == null || query.length() > 2 * MAX_QUERY_CODE_POINTS || query.indexOf('\0') >= 0)
            throw new IllegalArgumentException("invalid app search query");
        for (int i = 0; i < query.length(); i++) {
            char c = query.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= query.length() || !Character.isLowSurrogate(query.charAt(++i)))
                    throw new IllegalArgumentException("invalid app search Unicode");
            } else if (Character.isLowSurrogate(c)) throw new IllegalArgumentException("invalid app search Unicode");
        }
        if (query.codePointCount(0, query.length()) > MAX_QUERY_CODE_POINTS)
            throw new IllegalArgumentException("app search query exceeds 64 characters");
    }

    private static int ownerPriority(Entry entry, String owner) {
        if (containsPackage(owner, entry.normalizedPackage)) return 2;
        return !entry.normalizedLabel.isEmpty() && owner.contains(entry.normalizedLabel) ? 1 : 0;
    }

    private static boolean containsPackage(String text, String pkg) {
        int from = 0;
        while (from <= text.length() - pkg.length()) {
            int at = text.indexOf(pkg, from);
            if (at < 0) return false;
            int end = at + pkg.length();
            if ((at == 0 || !packageCharacter(text.charAt(at - 1)))
                    && (end == text.length() || !packageCharacter(text.charAt(end)))) return true;
            from = at + 1;
        }
        return false;
    }

    private static boolean packageCharacter(char value) {
        return value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '_' || value == '.';
    }

    private static int searchPriority(Entry entry, String term) {
        if (entry.normalizedPackage.equals(term)) return 3;
        if (entry.normalizedLabel.equals(term)) return 2;
        return entry.normalizedLabel.startsWith(term) ? 1 : 0;
    }

    private static String normalize(String value) {
        String normalized = Normalizer.normalize(value, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
        StringBuilder result = new StringBuilder();
        boolean space = false;
        for (int i = 0; i < normalized.length();) {
            int cp = normalized.codePointAt(i); i += Character.charCount(cp);
            if (Character.isWhitespace(cp) || Character.isSpaceChar(cp)) { space = result.length() > 0; continue; }
            if (space) result.append(' ');
            result.appendCodePoint(cp); space = false;
        }
        return result.toString();
    }

    private static String boundedLabel(String label) {
        if (label == null) return "";
        StringBuilder safe = new StringBuilder();
        for (int i = 0, count = 0; i < label.length() && count < 256; count++) {
            int cp = label.codePointAt(i); i += Character.charCount(cp);
            // Android labels can be supplied by other apps; malformed text must
            // not introduce invalid UTF-8/NUL into the local model prompt.
            safe.appendCodePoint(cp == 0 || cp >= 0xd800 && cp <= 0xdfff ? 0xfffd : cp);
        }
        return safe.toString();
    }

    private static String fingerprint(List<Entry> entries) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (Entry entry : entries) {
                hashField(digest, entry.packageName); hashField(digest, entry.label);
            }
            StringBuilder out = new StringBuilder(64);
            for (byte value : digest.digest()) out.append(String.format(Locale.ROOT, "%02x", value & 255));
            return out.toString();
        } catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private static void hashField(MessageDigest digest, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        digest.update(new byte[] {(byte)(bytes.length >>> 24), (byte)(bytes.length >>> 16),
                (byte)(bytes.length >>> 8), (byte)bytes.length});
        digest.update(bytes);
    }
}
