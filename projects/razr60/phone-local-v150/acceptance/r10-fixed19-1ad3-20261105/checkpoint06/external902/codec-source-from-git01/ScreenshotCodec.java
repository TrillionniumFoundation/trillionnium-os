package org.trillionnium.hepta.screen;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Looper;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.ByteArrayOutputStream;
import java.io.FileDescriptor;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;

/** One read-only Android Shell screenshot encoding process. No UI or capture API. */
public final class ScreenshotCodec {
    private static final int SHELL_UID=2000;

    private static String sha(byte[] bytes) throws Exception {
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder result=new StringBuilder(64);
        for (byte b:digest) result.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
        return result.toString();
    }

    private static Map<String,String> args(String[] argv) {
        if ((argv.length!=11 && argv.length!=13) || !"encode".equals(argv[0])) throw new IllegalArgumentException("arguments");
        Map<String,String> result=new HashMap<String,String>();
        for (int i=1;i<argv.length;i+=2) {
            String key=argv[i];
            if (!(key.equals("--capture-id") || key.equals("--input") || key.equals("--serial")
                    || key.equals("--viewport-before-b64") || key.equals("--viewport-after-b64") || key.equals("--max-bytes")))
                throw new IllegalArgumentException("argument_name");
            if (result.put(key,argv[i+1])!=null) throw new IllegalArgumentException("duplicate_argument");
        }
        if (result.size()!=(argv.length-1)/2 || !result.containsKey("--capture-id") || !result.containsKey("--input")
                || !result.containsKey("--serial") || !result.containsKey("--viewport-before-b64") || !result.containsKey("--viewport-after-b64"))
            throw new IllegalArgumentException("arguments");
        return result;
    }

    private static void regular(StructStat value) {
        if (!OsConstants.S_ISREG(value.st_mode) || value.st_uid!=SHELL_UID || value.st_nlink!=1
                || value.st_size<45 || value.st_size>ScreenContract.MAX_PNG_BYTES || (value.st_mode&0022)!=0)
            throw new IllegalArgumentException("source_file_metadata");
    }

    private static boolean same(StructStat a,StructStat b) {
        return a.st_dev==b.st_dev && a.st_ino==b.st_ino && a.st_size==b.st_size
                && a.st_uid==b.st_uid && a.st_gid==b.st_gid && a.st_mode==b.st_mode && a.st_nlink==b.st_nlink
                && a.st_mtim.tv_sec==b.st_mtim.tv_sec && a.st_mtim.tv_nsec==b.st_mtim.tv_nsec
                && a.st_ctim.tv_sec==b.st_ctim.tv_sec && a.st_ctim.tv_nsec==b.st_ctim.tv_nsec;
    }

    private static final class SourceFile {
        final byte[] bytes;
        final StructStat stable;
        SourceFile(byte[] bytes,StructStat stable) {this.bytes=bytes;this.stable=stable;}
    }

    private static SourceFile source(String path) throws Exception {
        for (String parent:new String[]{"/data","/data/local","/data/local/tmp"})
            if (!OsConstants.S_ISDIR(Os.lstat(parent).st_mode)) throw new IllegalArgumentException("source_parent_symlink");
        StructStat before=Os.lstat(path); regular(before);
        long modified=before.st_mtim.tv_sec*1000L+before.st_mtim.tv_nsec/1000000L;
        long age=System.currentTimeMillis()-modified;
        if (age < -2000 || age>60000) throw new IllegalArgumentException("source_not_fresh");
        FileDescriptor fd=Os.open(path,OsConstants.O_RDONLY|OsConstants.O_CLOEXEC|OsConstants.O_NOFOLLOW,0);
        try {
            StructStat opened=Os.fstat(fd); regular(opened);
            if (!same(before,opened)) throw new IllegalArgumentException("source_changed_at_open");
            byte[] bytes=new byte[(int)opened.st_size];
            int at=0;
            while (at<bytes.length) {
                int count=Os.read(fd,bytes,at,bytes.length-at);
                if (count<=0) throw new IllegalArgumentException("source_truncated");
                at+=count;
            }
            if (Os.read(fd,new byte[1],0,1)!=0) throw new IllegalArgumentException("source_grew");
            StructStat after=Os.fstat(fd), named=Os.lstat(path); regular(after);regular(named);
            if (!same(before,after) || !same(before,named)) throw new IllegalArgumentException("source_changed_during_read");
            return new SourceFile(bytes,after);
        } finally { Os.close(fd); }
    }

    private static JSONObject encode(String[] argv) throws Exception {
        if (Os.getuid()!=SHELL_UID || Os.geteuid()!=SHELL_UID) throw new IllegalArgumentException("shell_uid_required");
        if (Looper.getMainLooper()==null && Looper.myLooper()==null) Looper.prepareMainLooper();
        Map<String,String> options=args(argv);
        int maxBytes=ScreenContract.maxBytes(options.get("--max-bytes"));
        String id=ScreenContract.safeCaptureId(options.get("--capture-id"));
        if (!ScreenContract.SERIAL.equals(options.get("--serial"))) throw new IllegalArgumentException("serial");
        String path=ScreenContract.expectedPath(id);
        if (!path.equals(options.get("--input"))) throw new IllegalArgumentException("source_path");
        String before=ScreenContract.strictMetadata(options.get("--viewport-before-b64"));
        String after=ScreenContract.strictMetadata(options.get("--viewport-after-b64"));
        ScreenContract.Viewport viewport=ScreenContract.viewport(before,after);
        SourceFile captured=source(path);
        byte[] png=captured.bytes; ScreenContract.validatePng(png);
        BitmapFactory.Options bounds=new BitmapFactory.Options(); bounds.inJustDecodeBounds=true;
        BitmapFactory.decodeByteArray(png,0,png.length,bounds);
        if (bounds.outWidth!=viewport.width || bounds.outHeight!=viewport.height || !"image/png".equals(bounds.outMimeType))
            throw new IllegalArgumentException("decoded_source_dimensions");
        BitmapFactory.Options decode=new BitmapFactory.Options(); decode.inScaled=false; decode.inPreferredConfig=Bitmap.Config.ARGB_8888;
        Bitmap original=BitmapFactory.decodeByteArray(png,0,png.length,decode);
        if (original==null) throw new IllegalArgumentException("png_decode_failed");
        try {
            if (original.getWidth()!=viewport.width || original.getHeight()!=viewport.height) throw new IllegalArgumentException("bitmap_source_dimensions");
            for (int edge:new int[]{1600,1280,1024,800}) {
                int[] size=ScreenContract.scaledSize(original.getWidth(),original.getHeight(),edge);
                Bitmap scaled=Bitmap.createScaledBitmap(original,size[0],size[1],true);
                try {
                    for (int quality:new int[]{80,70,60,50}) {
                        ByteArrayOutputStream output=new ByteArrayOutputStream();
                        if (!scaled.compress(Bitmap.CompressFormat.JPEG,quality,output)) throw new IllegalArgumentException("jpeg_encode_failed");
                        byte[] jpeg=output.toByteArray();
                        if (jpeg.length>maxBytes) continue;
                        if (jpeg.length<4 || (jpeg[0]&255)!=255 || (jpeg[1]&255)!=216
                                || (jpeg[jpeg.length-2]&255)!=255 || (jpeg[jpeg.length-1]&255)!=217)
                            throw new IllegalArgumentException("jpeg_envelope");
                        JSONObject result=new JSONObject();
                        result.put("schema","hepta.phone-screenshot.v1");
                        result.put("status","encoded");result.put("capture_id",id);result.put("serial",options.get("--serial"));
                        result.put("logical_display_id",viewport.logicalId);result.put("physical_display_id",viewport.physicalId);
                        result.put("rotation",viewport.rotation);result.put("viewport_before",viewport.before);result.put("viewport_after",viewport.after);
                        result.put("original_width",original.getWidth());result.put("original_height",original.getHeight());
                        result.put("encoded_width",scaled.getWidth());result.put("encoded_height",scaled.getHeight());
                        result.put("media_type","image/jpeg");result.put("encoding","base64");result.put("quality",quality);
                        result.put("data_base64",Base64.getEncoder().encodeToString(jpeg));
                        result.put("image_sha256",sha(jpeg));result.put("source_png_sha256",sha(png));
                        result.put("source_png_bytes",png.length);result.put("encoded_bytes",jpeg.length);
                        StructStat finalSource=Os.lstat(path);regular(finalSource);
                        if (!same(captured.stable,finalSource)) throw new IllegalArgumentException("source_changed_during_encoding");
                        return result;
                    }
                } finally { if (scaled!=original) scaled.recycle(); }
            }
            throw new IllegalArgumentException("jpeg_size_bound");
        } finally { original.recycle(); }
    }

    public static void main(String[] argv) {
        int exit=0;
        try { System.out.println(encode(argv).toString()); }
        catch (Throwable error) {
            exit=(error instanceof IllegalArgumentException)?20:22;
            // No stack trace or arbitrary input/output is emitted on failure.
            try {
                JSONObject result=new JSONObject();result.put("schema","hepta.phone-screenshot.v1");
                String reason=error instanceof IllegalArgumentException?error.getMessage():"codec_runtime_error";
                if (reason==null || !reason.matches("[a-z0-9_]{1,80}")) reason="invalid_argument";
                result.put("status","rejected");result.put("reason",reason);
                System.out.println(result.toString());
            } catch (Throwable unavailable) { System.out.println("{\"schema\":\"hepta.phone-screenshot.v1\",\"status\":\"rejected\",\"reason\":\"codec_failure\"}"); }
        }
        System.out.flush();
        System.exit(exit);
    }
}
