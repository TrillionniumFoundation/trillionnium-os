package org.trillionnium.hepta.webhelper;

import java.net.URI;
import java.util.Locale;

/** An origin check only. It never grants a page action or declares a fare valid. */
public final class OfficialOrigin {
    private OfficialOrigin() { }

    /** No wildcard subdomains, credentials, cleartext, nonstandard ports or opaque URLs. */
    public static String origin(String raw) {
        if (raw == null || raw.length() == 0 || raw.length() > 4096) return null;
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (Character.isISOControl(c) || Character.isWhitespace(c) || Character.isSpaceChar(c)) return null;
        }
        try {
            URI uri = new URI(raw);
            if (uri.isOpaque() || !"https".equalsIgnoreCase(uri.getScheme())
                    || uri.getRawUserInfo() != null || (uri.getPort() != -1 && uri.getPort() != 443)) return null;
            String host = uri.getHost();
            if (host == null) return null;
            host = host.toLowerCase(Locale.ROOT);
            if (!"m.csair.com".equals(host) && !"b2c.csair.com".equals(host)) return null;
            return "https://" + host;
        } catch (Exception invalid) {
            return null;
        }
    }

    public static boolean sameOrigin(String a, String b) {
        String origin = origin(a);
        return origin != null && origin.equals(origin(b));
    }
}
