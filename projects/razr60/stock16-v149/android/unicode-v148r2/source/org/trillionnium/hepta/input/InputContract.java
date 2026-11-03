package org.trillionnium.hepta.input;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/** Pure argument/data contract; contains no Android, filesystem or dispatch code. */
public final class InputContract {
    public static final int MAX_TEXT_BYTES = 4096;
    private static final Pattern PACKAGE = Pattern.compile("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+");
    private static final Pattern VIEW_ID = Pattern.compile("[A-Za-z][A-Za-z0-9_.]*:id/[A-Za-z0-9_.$]+");
    private static final Pattern OPERATION = Pattern.compile("[A-Za-z0-9_-]{1,64}");
    public final String operationId;
    public final int display;
    public final String packageName;
    public final String viewId;
    public final String expected;
    public final String replacement;

    private InputContract(String operationId, int display, String packageName,
                          String viewId, String expected, String replacement) {
        this.operationId = operationId; this.display = display;
        this.packageName = packageName; this.viewId = viewId;
        this.expected = expected; this.replacement = replacement;
    }

    public static InputContract parse(String[] argv) {
        if (argv.length != 13 || !argv[0].equals("set-text"))
            throw new IllegalArgumentException("exact set-text arguments required");
        Map<String,String> values = new HashMap<String,String>();
        for (int i = 1; i < argv.length; i += 2) {
            if (values.put(argv[i], argv[i+1]) != null)
                throw new IllegalArgumentException("duplicate argument");
        }
        String[] names = {"--operation-id", "--display", "--package", "--view-id",
                          "--expected-text-b64", "--text-b64"};
        for (String name : names) if (!values.containsKey(name))
            throw new IllegalArgumentException("missing or unknown argument");
        String operation = values.get("--operation-id");
        String pkg = values.get("--package");
        String id = values.get("--view-id");
        if (!OPERATION.matcher(operation).matches() || !PACKAGE.matcher(pkg).matches()
                || !VIEW_ID.matcher(id).matches())
            throw new IllegalArgumentException("invalid target or operation identifier");
        // The checked stock constructor targets DEFAULT_DISPLAY. Do not silently
        // redirect cover-display input through this first version.
        if (!values.get("--display").equals("0"))
            throw new IllegalArgumentException("only explicitly observed display0 is qualified");
        return new InputContract(operation, 0, pkg, id,
                decodeText(values.get("--expected-text-b64")), decodeText(values.get("--text-b64")));
    }

    public static String decodeText(String text) {
        if (text.equals("-")) return "";
        if (text.isEmpty() || text.length() > 4 * ((MAX_TEXT_BYTES + 2) / 3))
            throw new IllegalArgumentException("invalid text envelope size");
        final byte[] bytes;
        try { bytes = Base64.getDecoder().decode(text); }
        catch (IllegalArgumentException bad) { throw new IllegalArgumentException("invalid base64"); }
        if (bytes.length > MAX_TEXT_BYTES || !Base64.getEncoder().encodeToString(bytes).equals(text))
            throw new IllegalArgumentException("noncanonical or oversized base64");
        final String decoded;
        try {
            decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException bad) {
            throw new IllegalArgumentException("invalid UTF8");
        }
        if (decoded.indexOf('\0') >= 0) throw new IllegalArgumentException("NUL is not supported");
        return decoded;
    }

    public static String sha(String text) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(64);
            for (byte b : bytes) result.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
            return result.toString();
        } catch (java.security.NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }

    public static String encodeText(String text) {
        return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));
    }
}
