package org.trillionnium.owneropen;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * Read-only, one-file snapshot export for authorized ADB shell backup.
 * No session transitions, agent dispatch, root service or GSI operations.
 * Shell-only despite manifest DUMP protection; no writable URI.
 */
public final class OwnerOpenStateBackupProvider extends ContentProvider {
    private static final String AUTH = "org.trillionnium.owneropen.audit";
    private static final String NAME = "owner-client-session-v1.bin";
    private static final String PENDING = "owner-client-session-v1.pending";

    @Override public boolean onCreate() { return true; }

    private void requireShell(Uri uri) throws FileNotFoundException {
        if (Binder.getCallingUid() != Process.SHELL_UID ||
                !AUTH.equals(uri.getAuthority()) ||
                uri.getPathSegments().size() != 1 ||
                !"session-v1".equals(uri.getPathSegments().get(0))) {
            throw new SecurityException("only Android shell may export a fixed read-only session");
        }
    }

    @Override public ParcelFileDescriptor openFile(Uri uri, String mode)
            throws FileNotFoundException {
        requireShell(uri);
        if (!"r".equals(mode)) throw new FileNotFoundException("read-only export");
        if (getContext() == null) throw new FileNotFoundException("app context unavailable");
        try {
            Path directory = getContext().getFilesDir().toPath();
            if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("state directory invalid");
            }
            Path pending = directory.resolve(PENDING);
            if (Files.exists(pending, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("ambiguous pending session write");
            }
            Path committed = directory.resolve(NAME);
            if (!Files.isRegularFile(committed, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("no committed session record");
            }
            if (Files.size(committed) > OwnerOpenClientStateCodec.MAX_RECORD_BYTES) {
                throw new IOException("state bound exceeded");
            }
            Object links = Files.getAttribute(committed, "unix:nlink",
                    LinkOption.NOFOLLOW_LINKS);
            if (!(links instanceof Number) || ((Number) links).intValue() != 1) {
                throw new IOException("invalid state link count");
            }
            // Atomic CAS rename makes the committed snapshot stable. Decode
            // checks the fixed version, fields and SHA256 before export.
            final byte[] record = Files.readAllBytes(committed);
            if (record.length <= 0 ||
                    record.length > OwnerOpenClientStateCodec.MAX_RECORD_BYTES) {
                throw new IOException("empty or oversized state");
            }
            OwnerOpenClientStateCodec.decode(record);
            final ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
            new Thread(() -> {
                try (ParcelFileDescriptor.AutoCloseOutputStream output =
                        new ParcelFileDescriptor.AutoCloseOutputStream(pipe[1])) {
                    output.write(record);
                } catch (IOException ignored) {
                    // Never disclose session bytes in logs, exceptions or UI.
                }
            }, "session-export-readonly").start();
            return pipe[0];
        } catch (IOException error) {
            throw new FileNotFoundException("committed session not exportable: "
                    + error.getClass().getSimpleName());
        }
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
            String[] selectionArgs, String sortOrder) {
        throw new UnsupportedOperationException("no query interface");
    }
    @Override public String getType(Uri uri) {
        return "application/octet-stream";
    }
    @Override public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("no mutation interface");
    }
    @Override public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("no mutation interface");
    }
    @Override public int update(Uri uri, ContentValues values, String selection,
            String[] selectionArgs) {
        throw new UnsupportedOperationException("no mutation interface");
    }
}
