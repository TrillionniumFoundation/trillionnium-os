package org.trillionnium.hepta.screen;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.CRC32;

/** Pure validation only. Constants are an allowlist, never claimed observations. */
public final class ScreenContract {
    public static final String SERIAL = "ZY22LS7WZT";
    public static final String PHYSICAL = "local:4630947043778501779";
    public static final int WIDTH = 1224, HEIGHT = 2992;
    public static final int MAX_PNG_BYTES = 16 * 1024 * 1024;
    public static final int MAX_ENCODED_BYTES = 196608;
    private static final byte[] PNG = {(byte)137,80,78,71,13,10,26,10};

    public static final class Viewport {
        public final String before, after, physicalId;
        public final int logicalId, rotation, width, height;
        Viewport(String before, String after, String physicalId, int logicalId, int rotation, int width, int height) {
            this.before=before; this.after=after; this.physicalId=physicalId;
            this.logicalId=logicalId; this.rotation=rotation; this.width=width; this.height=height;
        }
    }

    public static String safeCaptureId(String value) {
        if (value == null || !value.matches("[A-Za-z0-9_-]{1,64}")) throw new IllegalArgumentException("capture_id");
        return value;
    }

    public static String expectedPath(String id) {
        return "/data/local/tmp/hepta-shot-" + safeCaptureId(id) + ".png";
    }

    public static int maxBytes(String value) {
        if (value==null) return MAX_ENCODED_BYTES;
        if (!value.matches("[1-9][0-9]{4,5}")) throw new IllegalArgumentException("max_bytes");
        int result=Integer.parseInt(value);
        if (result<65536 || result>MAX_ENCODED_BYTES) throw new IllegalArgumentException("max_bytes");
        return result;
    }

    public static String strictMetadata(String encoded) {
        if (encoded == null || encoded.length() == 0 || encoded.length() > 8192)
            throw new IllegalArgumentException("metadata_bound");
        final byte[] bytes;
        try { bytes = Base64.getDecoder().decode(encoded); }
        catch (IllegalArgumentException invalid) { throw new IllegalArgumentException("metadata_base64"); }
        if (bytes.length == 0 || bytes.length > 6144) throw new IllegalArgumentException("metadata_bound");
        try {
            String text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
            if (text.indexOf('\0') >= 0 || text.indexOf('\n') >= 0 || text.indexOf('\r') >= 0)
                throw new IllegalArgumentException("metadata_line");
            return text;
        } catch (CharacterCodingException invalid) { throw new IllegalArgumentException("metadata_utf8"); }
    }

    private static String one(String text, String regex, String error) {
        Matcher matcher = Pattern.compile(regex).matcher(text);
        if (!matcher.find()) throw new IllegalArgumentException(error);
        String value = matcher.group(1);
        if (matcher.find()) throw new IllegalArgumentException(error + "_duplicate");
        return value;
    }

    private static int number(String text, String field) {
        return Integer.parseInt(one(text, "(?:^|,\\s*)" + field + "=([0-9]+)(?=,|$)", field));
    }

    public static Viewport viewport(String before, String after) {
        if (before == null || !before.equals(after)) throw new IllegalArgumentException("viewport_changed");
        if (!before.trim().startsWith("mViewports=[") || !before.trim().endsWith("]"))
            throw new IllegalArgumentException("viewport_envelope");
        String envelope = before.trim();
        String body = envelope.substring("mViewports=[".length(), envelope.length()-1);
        Matcher matcher = Pattern.compile("DisplayViewport\\{([^{}]+)\\}").matcher(body);
        String active = null;
        int count = 0, activeCount = 0, end = 0;
        ArrayList<Integer> ids = new ArrayList<Integer>();
        while (matcher.find()) {
            String separator = body.substring(end,matcher.start()).trim();
            if (!separator.equals(count==0?"":",")) throw new IllegalArgumentException("viewport_record_envelope");
            end = matcher.end();
            count++;
            String record = matcher.group(1);
            int id = number(record, "displayId");
            if (ids.contains(id)) throw new IllegalArgumentException("viewport_duplicate_display");
            ids.add(id);
            String enabled = one(record, "(?:^|,\\s*)isActive=(true|false)(?=,|$)", "viewport_active");
            if ("true".equals(enabled)) { activeCount++; active = record; }
        }
        if (!body.substring(end).trim().isEmpty()) throw new IllegalArgumentException("viewport_record_tail");
        if (count < 1 || activeCount != 1 || active == null) throw new IllegalArgumentException("viewport_active_count");
        if (!"INTERNAL".equals(one(active, "(?:^|,\\s*)type=([A-Z_]+)(?=,|$)", "viewport_type")))
            throw new IllegalArgumentException("viewport_type");
        if (!"true".equals(one(active, "(?:^|,\\s*)valid=(true|false)(?=,|$)", "viewport_valid")))
            throw new IllegalArgumentException("viewport_invalid");
        int id = number(active, "displayId"), rotation = number(active, "orientation");
        String physical = one(active, "(?:^|,\\s*)uniqueId='([^']+)'(?=,|$)", "viewport_physical_id");
        String logical = one(active, "(?:^|,\\s*)logicalFrame=(Rect\\([^)]+\\))(?=,|$)", "viewport_logical_frame");
        String physicalFrame = one(active, "(?:^|,\\s*)physicalFrame=(Rect\\([^)]+\\))(?=,|$)", "viewport_physical_frame");
        int width = number(active, "deviceWidth"), height = number(active, "deviceHeight");
        if (id != 0 || rotation != 0 || !PHYSICAL.equals(physical)
                || !"Rect(0, 0 - 1224, 2992)".equals(logical)
                || !"Rect(0, 0 - 1224, 2992)".equals(physicalFrame)
                || width != WIDTH || height != HEIGHT)
            throw new IllegalArgumentException("viewport_not_qualified");
        return new Viewport(before, after, physical, id, rotation, width, height);
    }

    private static long u32(byte[] value, int offset) {
        return ((long)(value[offset]&255)<<24) | ((long)(value[offset+1]&255)<<16)
                | ((long)(value[offset+2]&255)<<8) | (value[offset+3]&255L);
    }

    public static void validatePng(byte[] value) {
        if (value == null || value.length < 45 || value.length > MAX_PNG_BYTES)
            throw new IllegalArgumentException("png_bound");
        for (int i=0;i<PNG.length;i++) if (value[i]!=PNG[i]) throw new IllegalArgumentException("png_signature");
        int offset=8, count=0;
        boolean idat=false, ended=false;
        while (offset < value.length) {
            if (value.length-offset<12) throw new IllegalArgumentException("png_chunk_header");
            long size=u32(value,offset);
            if (size>MAX_PNG_BYTES || size>value.length-offset-12L) throw new IllegalArgumentException("png_chunk_bound");
            int length=(int)size;
            String type=new String(value,offset+4,4,StandardCharsets.US_ASCII);
            if (!type.matches("[A-Za-z]{4}")) throw new IllegalArgumentException("png_chunk_type");
            CRC32 crc=new CRC32(); crc.update(value,offset+4,length+4);
            if (crc.getValue()!=u32(value,offset+8+length)) throw new IllegalArgumentException("png_crc");
            if (count==0) {
                if (!"IHDR".equals(type) || length!=13 || u32(value,offset+8)!=WIDTH || u32(value,offset+12)!=HEIGHT)
                    throw new IllegalArgumentException("png_original_dimensions");
            } else if ("IHDR".equals(type)) throw new IllegalArgumentException("png_duplicate_ihdr");
            if ("acTL".equals(type) || "fcTL".equals(type) || "fdAT".equals(type)) throw new IllegalArgumentException("png_animation");
            if ("IDAT".equals(type)) idat=true;
            offset += length+12; count++;
            if ("IEND".equals(type)) {
                if (length!=0 || !idat || offset!=value.length) throw new IllegalArgumentException("png_end");
                ended=true; break;
            }
        }
        if (!ended) throw new IllegalArgumentException("png_incomplete");
    }

    public static int[] scaledSize(int originalWidth, int originalHeight, int maxEdge) {
        if (originalWidth!=WIDTH || originalHeight!=HEIGHT || (maxEdge!=1600 && maxEdge!=1280 && maxEdge!=1024 && maxEdge!=800))
            throw new IllegalArgumentException("scale_dimensions");
        double factor=Math.min(1.0, (double)maxEdge/Math.max(originalWidth,originalHeight));
        int width=Math.max(1,(int)Math.round(originalWidth*factor));
        int height=Math.max(1,(int)Math.round(originalHeight*factor));
        return new int[]{width,height};
    }

    private ScreenContract() {}
}
