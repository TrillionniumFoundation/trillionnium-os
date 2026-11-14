package org.trillionnium.hepta.background;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Strict, bounded wire contract. No Android classes, subprocesses, or network clients. */
public final class BrokerProtocol {
    public static final int VERSION = 1;
    public static final int MAX_REQUEST = 16384;
    public static final int MAX_RESPONSE = 65536;
    public static final int MAX_REQUEST_IDS = 128;
    public static final long MAX_REQUEST_MS = 10000;
    public static final long MAX_TTL_MS = 600000;
    private BrokerProtocol() {}

    public static final class Refusal extends Exception {
        private static final long serialVersionUID = 1L;
        public final String code;
        public Refusal(String code) { super(code); this.code = code; }
    }

    /** Exact numeric policy contract shared by the broker and ordinary app readback. */
    public static final class DisplayPolicy {
        public static final String SCHEMA="hepta.background-display-policy.v1";
        public static final Set<String> REQUIRED=Collections.unmodifiableSet(new LinkedHashSet<String>(Arrays.asList(
                "FLAG_TRUSTED","FLAG_OWN_FOCUS","FLAG_STEAL_TOP_FOCUS_DISABLED")));
        public static final Set<String> FORBIDDEN=Collections.unmodifiableSet(new LinkedHashSet<String>(Arrays.asList(
                "FLAG_SECURE","FLAG_ALWAYS_UNLOCKED")));
        public final int flags,requiredMask,forbiddenMask,imeActual,imeHide;
        public final Map<String,Integer> constants;
        private DisplayPolicy(int flags,Map<String,Integer> values,int required,int forbidden,int actualIme,int hide){
            this.flags=flags;constants=Collections.unmodifiableMap(new LinkedHashMap<String,Integer>(values));
            requiredMask=required;forbiddenMask=forbidden;imeActual=actualIme;imeHide=hide;
        }
        public static DisplayPolicy checked(int flags,Map<String,Integer> values,int actualIme,int hide)throws Refusal{
            Set<String> names=new LinkedHashSet<String>(REQUIRED);names.addAll(FORBIDDEN);
            if(values==null||!values.keySet().equals(names))throw new Refusal("DISPLAY_FLAG_CONSTANTS_INVALID");
            int used=0,required=0,forbidden=0;
            for(String name:names){Integer boxed=values.get(name);int value=boxed==null?0:boxed.intValue();
                if(value<=0||(value&(value-1))!=0||(used&value)!=0)throw new Refusal("DISPLAY_FLAG_CONSTANTS_INVALID");
                used|=value;if(REQUIRED.contains(name))required|=value;else forbidden|=value;
            }
            if(flags<0||(flags&required)!=required||(flags&forbidden)!=0)throw new Refusal("DISPLAY_FLAGS_NOT_ACCEPTED");
            if(actualIme<0||hide<0||actualIme!=hide)throw new Refusal("IME_POLICY_NOT_ACCEPTED");
            return new DisplayPolicy(flags,values,required,forbidden,actualIme,hide);
        }
        public Map<String,Object> numericEvidence(){
            Map<String,Object> value=new LinkedHashMap<String,Object>();
            value.put("flag_namespace","android.view.Display");value.put("flags_source","android.view.Display.getFlags");
            value.put("flags",flags);value.put("flag_constants",constants);
            value.put("required_mask",requiredMask);value.put("forbidden_mask",forbiddenMask);
            value.put("ime_source","android.view.IWindowManager.getDisplayImePolicy");value.put("ime_actual",imeActual);
            value.put("ime_hide_constant","android.view.WindowManager.DISPLAY_IME_POLICY_HIDE");value.put("ime_hide_value",imeHide);
            return value;
        }
    }

    public static final class Config {
        public final String socketName;
        public final int ownerUid;
        public final String generation;
        public final Set<String> packages;
        public final long ttlMs;
        public final long expiresElapsedMs;
        private Config(String socket, int owner, String generation, Set<String> packages,
                       long ttl, long expiry) {
            socketName = socket; ownerUid = owner; this.generation = generation;
            this.packages = Collections.unmodifiableSet(new LinkedHashSet<String>(packages));
            ttlMs = ttl; expiresElapsedMs = expiry;
        }
        public static Config parse(String[] args) throws Refusal {
            if (args.length != 12) throw new Refusal("INVALID_ARGUMENTS");
            Map<String,String> a = new HashMap<String,String>();
            Set<String> keys = new LinkedHashSet<String>(Arrays.asList("--socket", "--owner-uid",
                "--generation", "--allowed-packages", "--ttl-ms", "--expires-elapsed-ms"));
            for (int i = 0; i < args.length; i += 2) {
                if (!keys.contains(args[i]) || a.put(args[i], args[i + 1]) != null)
                    throw new Refusal("INVALID_ARGUMENTS");
            }
            String gen = a.get("--generation");
            if (!uuid(gen)) throw new Refusal("INVALID_GENERATION");
            String socket = a.get("--socket");
            if (socket == null || !socket.startsWith("hepta-bg-") || !uuid(socket.substring(9)))
                throw new Refusal("INVALID_SOCKET_NAME");
            long uid = decimal(a.get("--owner-uid"));
            // This initial shell-context integration intentionally supports Android user 0 only.
            if (uid < 10000 || uid >= 90000) throw new Refusal("OWNER_USER_UNSUPPORTED");
            long ttl = decimal(a.get("--ttl-ms"));
            long expiry = decimal(a.get("--expires-elapsed-ms"));
            if (ttl < 1000 || ttl > MAX_TTL_MS || expiry <= 0)
                throw new Refusal("INVALID_EXPIRY");
            String rawPackages = a.get("--allowed-packages");
            if (rawPackages == null || rawPackages.length() > 4096)
                throw new Refusal("INVALID_PACKAGE_SCOPE");
            String[] rows = rawPackages.split(",", -1);
            if (rows.length == 0 || rows.length > 32) throw new Refusal("INVALID_PACKAGE_SCOPE");
            Set<String> packages = new LinkedHashSet<String>();
            for (String row : rows) {
                if (!packageName(row) || !packages.add(row)) throw new Refusal("INVALID_PACKAGE_SCOPE");
            }
            return new Config(socket, (int) uid, gen, packages, ttl, expiry);
        }
    }

    public static final class Request {
        public final byte[] bytes;
        public final String requestId;
        public final String generation;
        public final String operation;
        public final String packageName;
        public final long deadline;
        public final String payload,attemptId;
        public final int targetUid;
        private Request(byte[] bytes, String id, String gen, String op, String pkg, long deadline,String payload,String attemptId,int targetUid) {
            this.payload=payload;this.attemptId=attemptId;this.targetUid=targetUid;
            this.bytes = bytes.clone(); requestId = id; generation = gen; operation = op;
            packageName = pkg; this.deadline = deadline;
        }
        public static Request parse(byte[] input) throws Refusal {
            if (input.length == 0 || input.length > MAX_REQUEST) throw new Refusal("REQUEST_SIZE");
            String text;
            try {
                text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(input)).toString();
            } catch (CharacterCodingException error) { throw new Refusal("INVALID_UTF8"); }
            Map<String,Object> map = new FlatJson(text).parse();
            Set<String> expected = new LinkedHashSet<String>(Arrays.asList("version", "request_id",
                "generation", "deadline_elapsed_ms", "op"));
            String op = string(map, "op");
            boolean fixed=FixedIntentTools.isTool(op);
            if ("launch".equals(op) || "back".equals(op)||fixed) expected.add("package");
            if(fixed)expected.addAll(Arrays.asList("payload","attempt_id","target_uid"));
            if (!map.keySet().equals(expected)) throw new Refusal("REQUEST_FIELDS");
            if (number(map, "version") != VERSION) throw new Refusal("PROTOCOL_VERSION");
            String id = string(map, "request_id"), gen = string(map, "generation");
            if (!uuid(id) || !uuid(gen)) throw new Refusal("INVALID_REQUEST_IDENTITY");
            if (!fixed&&!Arrays.asList("create", "state", "launch", "back", "close").contains(op))
                throw new Refusal("OPERATION_NOT_ALLOWED");
            String pkg = ("launch".equals(op) || "back".equals(op)||fixed) ? string(map, "package") : null;
            if (pkg != null && !packageName(pkg)) throw new Refusal("INVALID_PACKAGE");
            long deadline = number(map, "deadline_elapsed_ms");
            if (deadline <= 0) throw new Refusal("INVALID_DEADLINE");
            String payload=null,attempt=null;int targetUid=-1;
            if(fixed){
                FixedIntentTools.Profile profile=FixedIntentTools.forAction(op);
                if(!profile.packageName.equals(pkg))throw new Refusal("FIXED_TARGET_PACKAGE_MISMATCH");
                payload=string(map,"payload");attempt=string(map,"attempt_id");long uid=number(map,"target_uid");
                if(uid<10000||uid>=90000||!attempt.matches("[0-9a-f]{64}"))throw new Refusal("FIXED_TARGET_IDENTITY_INVALID");
                try{profile.validatePayload(payload);}catch(IllegalArgumentException invalid){throw new Refusal("FIXED_PAYLOAD_INVALID");}
                targetUid=(int)uid;
            }
            return new Request(input, id, gen, op, pkg, deadline,payload,attempt,targetUid);
        }
        public void authenticate(Config config, int peerUid) throws Refusal {
            if (peerUid != config.ownerUid) throw new Refusal("CALLER_UID_MISMATCH");
            if (!generation.equals(config.generation)) throw new Refusal("GENERATION_MISMATCH");
            if (packageName != null && !config.packages.contains(packageName))
                throw new Refusal("PACKAGE_NOT_ALLOWED");
        }
        public void checkDeadline(long now, long sessionExpiry) throws Refusal {
            if (now >= sessionExpiry) throw new Refusal("SESSION_EXPIRED");
            if (now >= deadline) throw new Refusal("REQUEST_EXPIRED");
            if (deadline - now > MAX_REQUEST_MS) throw new Refusal("REQUEST_DEADLINE_TOO_LONG");
        }
    }

    /** Completed receipts are retained for the entire bounded session; no evicted replay can act. */
    public static final class Receipts {
        private final Map<String,byte[][]> records = new LinkedHashMap<String,byte[][]>();
        public synchronized byte[] replay(Request request) throws Refusal {
            byte[][] row = records.get(request.requestId);
            if (row == null) {
                int limit = "close".equals(request.operation) ? MAX_REQUEST_IDS : MAX_REQUEST_IDS - 1;
                if (records.size() >= limit) throw new Refusal("SESSION_REQUEST_LIMIT");
                return null;
            }
            if (!Arrays.equals(row[0], request.bytes)) throw new Refusal("REQUEST_ID_REUSED");
            return row[1].clone();
        }
        public synchronized void remember(Request request, byte[] response) throws Refusal {
            if (response.length == 0 || response.length > MAX_RESPONSE) throw new Refusal("RESPONSE_SIZE");
            if (records.containsKey(request.requestId)) throw new Refusal("REQUEST_ALREADY_RECORDED");
            int limit = "close".equals(request.operation) ? MAX_REQUEST_IDS : MAX_REQUEST_IDS - 1;
            if (records.size() >= limit) throw new Refusal("SESSION_REQUEST_LIMIT");
            records.put(request.requestId, new byte[][] {request.bytes.clone(), response.clone()});
        }
    }

    public static byte[] readFrame(InputStream input) throws IOException, Refusal {
        DataInputStream in = new DataInputStream(input);
        int size = in.readInt();
        if (size <= 0 || size > MAX_REQUEST) throw new Refusal("REQUEST_SIZE");
        byte[] frame = new byte[size]; in.readFully(frame); return frame;
    }
    public static void writeFrame(OutputStream output, byte[] frame) throws IOException, Refusal {
        if (frame.length == 0 || frame.length > MAX_RESPONSE) throw new Refusal("RESPONSE_SIZE");
        DataOutputStream out = new DataOutputStream(output);
        out.writeInt(frame.length); out.write(frame); out.flush();
    }
    public static boolean uuid(String value) {
        if (value == null || value.length() != 36) return false;
        try { return UUID.fromString(value).toString().equals(value); }
        catch (IllegalArgumentException ignored) { return false; }
    }
    public static boolean packageName(String value) {
        return value != null && value.length() <= 253
            && value.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+");
    }
    private static long decimal(String value) throws Refusal {
        if (value == null || !value.matches("0|[1-9][0-9]{0,18}")) throw new Refusal("INVALID_INTEGER");
        try { return Long.parseLong(value); }
        catch (NumberFormatException ignored) { throw new Refusal("INTEGER_OVERFLOW"); }
    }
    private static String string(Map<String,Object> map, String key) throws Refusal {
        Object v = map.get(key); if (!(v instanceof String)) throw new Refusal("FIELD_TYPE");
        return (String) v;
    }
    private static long number(Map<String,Object> map, String key) throws Refusal {
        Object v = map.get(key); if (!(v instanceof Long)) throw new Refusal("FIELD_TYPE");
        return ((Long) v).longValue();
    }

    /** The request vocabulary needs only a flat object of strings and nonnegative integers. */
    private static final class FlatJson {
        private final String text; private int p;
        FlatJson(String text) { this.text = text; }
        private void ws() { while (p < text.length() && " \r\n\t".indexOf(text.charAt(p)) >= 0) p++; }
        private void take(char c) throws Refusal { ws(); if (p >= text.length() || text.charAt(p++) != c) throw new Refusal("INVALID_JSON"); }
        Map<String,Object> parse() throws Refusal {
            Map<String,Object> result = new LinkedHashMap<String,Object>(); take('{'); ws();
            if (p < text.length() && text.charAt(p) == '}') { p++; }
            else while (true) {
                String key = quoted(); take(':'); ws(); Object value;
                if (p < text.length() && text.charAt(p) == '"') value = quoted();
                else { int start = p; while (p < text.length() && Character.isDigit(text.charAt(p))) p++;
                    value = Long.valueOf(decimal(text.substring(start, p))); }
                if (result.containsKey(key)) throw new Refusal("DUPLICATE_FIELD");
                result.put(key, value); if (result.size() > 9) throw new Refusal("REQUEST_FIELDS");
                ws(); if (p < text.length() && text.charAt(p) == '}') { p++; break; }
                take(',');
            }
            ws(); if (p != text.length()) throw new Refusal("TRAILING_JSON"); return result;
        }
        private String quoted() throws Refusal {
            take('"'); StringBuilder value = new StringBuilder();
            while (p < text.length()) {
                char c = text.charAt(p++);
                if (c == '"') return value.toString();
                if (c < 0x20) throw new Refusal("INVALID_JSON_STRING");
                if (c == '\\') {
                    if (p == text.length()) throw new Refusal("INVALID_JSON_STRING");
                    c = text.charAt(p++);
                    if (c == '"' || c == '\\' || c == '/') { /* exact character */ }
                    else if (c == 'b') c = '\b'; else if (c == 'f') c = '\f';
                    else if (c == 'n') c = '\n'; else if (c == 'r') c = '\r'; else if (c == 't') c = '\t';
                    else if (c == 'u') {
                        if (p + 4 > text.length()) throw new Refusal("INVALID_JSON_STRING");
                        int v = 0; for (int i = 0; i < 4; i++) { int x = Character.digit(text.charAt(p++), 16);
                            if (x < 0) throw new Refusal("INVALID_JSON_STRING"); v = (v << 4) | x; }
                        c = (char) v;
                    } else throw new Refusal("INVALID_JSON_STRING");
                }
                value.append(c); if (value.length() > 256) throw new Refusal("FIELD_SIZE");
            }
            throw new Refusal("INVALID_JSON_STRING");
        }
    }
}
