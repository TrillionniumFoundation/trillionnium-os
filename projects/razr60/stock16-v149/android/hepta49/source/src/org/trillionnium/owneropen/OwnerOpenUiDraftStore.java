package org.trillionnium.owneropen;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.Optional;

/** Optional, app-private composer text. This file is never request/Stop authority. */
public final class OwnerOpenUiDraftStore {
    public static final int MAX_TEXT_CHARS = 65_536;
    private static final int MAGIC = 0x55494431; // UID1
    private static final int MAX_RECORD_BYTES = MAX_TEXT_CHARS * 2 + 2_048;
    // All Activities use the same application process; their UI I/O is also serialized.
    private static final Object FILE_LOCK = new Object();
    private final Path directory;

    public static final class Scope {
        public final String sessionId;
        public final String taskId;

        public Scope(String sessionId, String taskId) {
            if (sessionId == null || taskId == null || sessionId.isEmpty() || taskId.isEmpty()
                    || sessionId.length() > 256 || taskId.length() > 256)
                throw new IllegalArgumentException("draft requires a bounded conversation identity");
            this.sessionId = sessionId;
            this.taskId = taskId;
        }

        @Override public boolean equals(Object other) {
            if (!(other instanceof Scope)) return false;
            Scope value = (Scope) other;
            return sessionId.equals(value.sessionId) && taskId.equals(value.taskId);
        }

        @Override public int hashCode() { return Objects.hash(sessionId, taskId); }

        String fileName() {
            // Length framing avoids ambiguous concatenation; identities never become paths.
            String key = sessionId.length() + ":" + sessionId + taskId.length() + ":" + taskId;
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256")
                        .digest(key.getBytes(StandardCharsets.UTF_8));
                StringBuilder hex = new StringBuilder(64);
                for (byte value : digest) hex.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
                return hex + ".draft";
            } catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
        }
    }

    public static final class Draft {
        public final Scope scope;
        public final long revision;
        public final String text;
        public final int selectionStart;
        public final int selectionEnd;

        Draft(Scope scope, long revision, String text, int selectionStart, int selectionEnd) {
            if (scope == null || revision < 1 || text == null || text.length() > MAX_TEXT_CHARS)
                throw new IllegalArgumentException("invalid UI draft");
            this.scope = scope;
            this.revision = revision;
            this.text = text;
            this.selectionStart = safeSelection(text, selectionStart);
            this.selectionEnd = safeSelection(text, selectionEnd);
        }
    }

    /** Immutable click-time UI capture; this object cannot start or resume any request. */
    public static final class Submission {
        public final Scope scope;
        public final String text;
        public final long editSequence;

        public Submission(Scope scope, String text, long editSequence) {
            if (scope == null || text == null) throw new IllegalArgumentException("invalid draft capture");
            this.scope = scope;
            this.text = text;
            this.editSequence = editSequence;
        }

        public boolean stillMatches(Scope currentScope, String currentText, long currentEditSequence) {
            return scope.equals(currentScope) && editSequence == currentEditSequence && text.equals(currentText);
        }
    }

    public OwnerOpenUiDraftStore(Path appPrivateFilesDirectory) throws IOException {
        directory = appPrivateFilesDirectory.resolve("ui-composer-drafts-v1");
        Files.createDirectories(directory);
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("UI draft directory is unavailable");
    }

    public Optional<Draft> load(Scope scope) throws IOException {
        synchronized (FILE_LOCK) { return read(scope); }
    }

    /**
     * UI-only lookup hint for a composer closed before Activity identity publication.
     * Read the existing atomically replaced, bounded snapshot without its authority lock.
     * This does not initialize a session, inspect or repair pending writes, publish identity,
     * update cursors, or grant any operation permission. Normal restore still owns all that.
     */
    public static Scope readScopeHint(Path appPrivateFilesDirectory) throws IOException {
        Path file = appPrivateFilesDirectory.resolve("owner-client-session-v1.bin");
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("no existing conversation scope for the closing UI draft");
        byte[] bytes;
        try (InputStream input = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
            bytes = input.readNBytes(OwnerOpenClientStateCodec.MAX_RECORD_BYTES + 1);
        }
        if (bytes.length > OwnerOpenClientStateCodec.MAX_RECORD_BYTES)
            throw new IOException("conversation scope hint exceeds its bound");
        OwnerOpenClientState state = OwnerOpenClientStateCodec.decode(bytes).state;
        return new Scope(state.sessionId, state.taskId);
    }

    /** A stale Activity cannot erase a newer draft or any other conversation's file. */
    public Draft save(Scope scope, long expectedRevision, String text, int start, int end) throws IOException {
        if (expectedRevision < 0 || text == null || text.length() > MAX_TEXT_CHARS)
            throw new IllegalArgumentException("invalid UI draft write");
        synchronized (FILE_LOCK) {
            Optional<Draft> previous = read(scope);
            long actualRevision = previous.map(value -> value.revision).orElse(0L);
            if (actualRevision != expectedRevision)
                throw new IOException("UI draft changed in another Activity; current input was retained");
            int safeStart = safeSelection(text, start), safeEnd = safeSelection(text, end);
            if (previous.isPresent() && previous.get().text.equals(text)
                    && previous.get().selectionStart == safeStart && previous.get().selectionEnd == safeEnd)
                return previous.get();
            if (actualRevision == Long.MAX_VALUE) throw new IOException("UI draft revision exhausted");
            Draft next = new Draft(scope, actualRevision + 1, text, safeStart, safeEnd);
            byte[] record = encode(next);
            Path pending = Files.createTempFile(directory, ".draft-", ".pending");
            try {
                try (FileOutputStream output = new FileOutputStream(pending.toFile())) {
                    output.write(record);
                    output.getFD().sync();
                }
                Files.move(pending, directory.resolve(scope.fileName()),
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } finally { Files.deleteIfExists(pending); }
            return next;
        }
    }

    private Optional<Draft> read(Scope scope) throws IOException {
        Path file = directory.resolve(scope.fileName());
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) return Optional.empty();
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || Files.size(file) > MAX_RECORD_BYTES)
            throw new IOException("invalid UI draft file");
        byte[] record = Files.readAllBytes(file);
        if (record.length > MAX_RECORD_BYTES) throw new IOException("UI draft is too large");
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(record))) {
            if (input.readInt() != MAGIC) throw new IOException("unknown UI draft format");
            long revision = input.readLong();
            Scope stored = new Scope(input.readUTF(), input.readUTF());
            if (!scope.equals(stored)) throw new IOException("UI draft conversation mismatch");
            int chars = input.readInt();
            if (chars < 0 || chars > MAX_TEXT_CHARS || input.available() != chars * 2 + 8)
                throw new IOException("invalid UI draft bounds");
            StringBuilder text = new StringBuilder(chars);
            for (int i = 0; i < chars; i++) text.append(input.readChar());
            return Optional.of(new Draft(stored, revision, text.toString(), input.readInt(), input.readInt()));
        } catch (IllegalArgumentException invalid) { throw new IOException("damaged UI draft", invalid); }
    }

    private static byte[] encode(Draft draft) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(draft.text.length() * 2 + 256);
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(MAGIC);
            output.writeLong(draft.revision);
            output.writeUTF(draft.scope.sessionId);
            output.writeUTF(draft.scope.taskId);
            output.writeInt(draft.text.length());
            // Preserve UTF-16 exactly, including CJK, emoji, newlines and incomplete IME text.
            for (int i = 0; i < draft.text.length(); i++) output.writeChar(draft.text.charAt(i));
            output.writeInt(draft.selectionStart);
            output.writeInt(draft.selectionEnd);
        }
        return bytes.toByteArray();
    }

    public static int safeSelection(String text, int position) {
        int selected = Math.max(0, Math.min(text.length(), position));
        if (selected > 0 && selected < text.length() && Character.isHighSurrogate(text.charAt(selected - 1))
                && Character.isLowSurrogate(text.charAt(selected))) selected--;
        return selected;
    }
}
