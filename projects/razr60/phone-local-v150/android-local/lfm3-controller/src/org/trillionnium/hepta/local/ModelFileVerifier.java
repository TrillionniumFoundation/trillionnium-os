package org.trillionnium.hepta.local;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Locale;

/** Verify the official GGUF once per unchanged file in this app process. */
public final class ModelFileVerifier {
    public interface Cancellation { boolean requested(); }
    private String verifiedPath,verifiedProfile;
    private long verifiedLength = -1, verifiedModified = -1;

    public synchronized void verify(File model, Cancellation cancellation) throws Exception {
        verify(model,ModelProfile.LFM3,cancellation);
    }
    public synchronized void verify(File model, ModelProfile profile, Cancellation cancellation) throws Exception {
        if(profile==null)throw new IOException("pinned model profile required");
        verifyPinned(model,profile.id,profile.fileName,profile.bytes,profile.sha256,cancellation);
    }
    /** The caller supplies a pinned asset identity, never a path learned from model output. */
    synchronized void verifyPinned(File model,String identity,String fileName,long expectedBytes,
            String expectedSha,Cancellation cancellation)throws Exception{
        if(identity==null||identity.isEmpty()||fileName==null||fileName.isEmpty()||expectedBytes<=0
                ||expectedSha==null||!expectedSha.matches("[0-9a-f]{64}")||cancellation==null)
            throw new IOException("complete pinned asset identity required");
        File canonical = model.getCanonicalFile();
        if (!canonical.equals(model.getAbsoluteFile()) || !model.isFile() || model.length() == 0)
            throw new IOException("model must be the canonical nonempty app-private GGUF file");
        long length = model.length(), modified = model.lastModified();
        if (!fileName.equals(model.getName()) || length != expectedBytes)
            throw new IOException("selected profile GGUF filename or size differs");
        if ((identity+":"+expectedSha).equals(verifiedProfile) && model.getPath().equals(verifiedPath) && length == verifiedLength && modified == verifiedModified) return;
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
        if (!expectedSha.equals(hash.toString()))
            throw new IOException("GGUF SHA-256 differs from the selected pinned profile");
        if (length != model.length() || modified != model.lastModified())
            throw new IOException("model changed while its SHA-256 was being verified");
        verifiedProfile=identity+":"+expectedSha;verifiedPath = model.getPath(); verifiedLength = length; verifiedModified = modified;
    }
}
