package org.trillionnium.hepta.local;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Locale;

/** Verify the official GGUF once per unchanged file in this app process. */
public final class ModelFileVerifier {
    public interface Cancellation { boolean requested(); }
    private String verifiedPath;
    private long verifiedLength = -1, verifiedModified = -1;

    public synchronized void verify(File model, Cancellation cancellation) throws Exception {
        File canonical = model.getCanonicalFile();
        if (!canonical.equals(model.getAbsoluteFile()) || !model.isFile() || model.length() == 0)
            throw new IOException("model must be the canonical nonempty app-private GGUF file");
        long length = model.length(), modified = model.lastModified();
        if (length != LocalRuntimeConfig.MODEL_BYTES)
            throw new IOException("selected LFM3 GGUF is incomplete or has an unexpected size");
        if (model.getPath().equals(verifiedPath) && length == verifiedLength && modified == verifiedModified) return;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream stream = new FileInputStream(model)) {
            byte[] bytes = new byte[1024 * 1024];
            int size;
            while ((size = stream.read(bytes)) >= 0) {
                if (cancellation.requested()) throw new IOException("model verification cancelled");
                if (size != 0) digest.update(bytes, 0, size);
            }
        }
        StringBuilder hash = new StringBuilder(64);
        for (byte value : digest.digest()) hash.append(String.format(Locale.ROOT, "%02x", value & 255));
        if (!LocalRuntimeConfig.MODEL_SHA256.equals(hash.toString()))
            throw new IOException("GGUF SHA-256 differs from the selected official LFM3 QAD Q4_0 model");
        if (length != model.length() || modified != model.lastModified())
            throw new IOException("model changed while its SHA-256 was being verified");
        verifiedPath = model.getPath(); verifiedLength = length; verifiedModified = modified;
    }
}
