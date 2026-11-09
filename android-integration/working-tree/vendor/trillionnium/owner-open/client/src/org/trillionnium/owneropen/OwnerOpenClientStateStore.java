package org.trillionnium.owneropen;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Optional;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Semaphore;

/** Fixed-file, bounded CAS store under the caller's already-existing app-private files directory. */
public final class OwnerOpenClientStateStore {
    private static final String STATE = "owner-client-session-v1.bin";
    private static final String PENDING = "owner-client-session-v1.pending";
    private static final String LOCK = "owner-client-session-v1.lock";
    private static final int MAX_PROCESS_PARTITIONS = 16;
    private static final int MAX_PARTITION_REFERENCES = 16;
    private static final Map<Path, ProcessGuard> PROCESS_GUARDS = new HashMap<>();
    private final Path directory;
    private final CommitHook hook;

    private static final class ProcessGuard {
        // A nonreentrant guard prevents a rejected same-process contender from opening/closing
        // another lock FD: POSIX fcntl locks can be released by closing any FD for that inode.
        final Semaphore permit = new Semaphore(1);
        int references;
    }

    public enum Failure {
        IO_FAILURE, CORRUPT_RECORD, PENDING_WRITE, INVALID_FILE, LOCK_BUSY,
        STALE_REVISION, STATE_CONFLICT
    }

    public static final class StoreException extends IOException {
        private static final long serialVersionUID = 1L;
        public final Failure failure;
        // true means the attempted snapshot may have become the committed file.
        // Every error blocks submission; neither value proves an external effect did not occur.
        public final boolean commitMayHaveOccurred;

        StoreException(Failure failure, boolean commitMayHaveOccurred, Throwable cause) {
            super("client state store: " + failure, cause);
            this.failure = failure;
            this.commitMayHaveOccurred = commitMayHaveOccurred;
        }
    }

    // Package-private fault injection runs actual filesystem operations in host behavior tests.
    interface CommitHook {
        void afterFileSync() throws IOException;
        default void atomicMove(Path pending, Path committed) throws IOException {
            Files.move(pending, committed,
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }
        void afterAtomicRename() throws IOException;
    }

    public OwnerOpenClientStateStore(Path appPrivateFilesDirectory) throws IOException {
        this(appPrivateFilesDirectory, new CommitHook() {
            public void afterFileSync() {}
            public void afterAtomicRename() {}
        });
    }

    OwnerOpenClientStateStore(Path appPrivateFilesDirectory, CommitHook hook) throws IOException {
        if (appPrivateFilesDirectory == null || hook == null
                || !Files.isDirectory(appPrivateFilesDirectory, LinkOption.NOFOLLOW_LINKS)) {
            throw new StoreException(Failure.INVALID_FILE, false, null);
        }
        this.directory = appPrivateFilesDirectory.toRealPath();
        this.hook = hook;
    }

    /** Empty means absent only. Corruption, pending writes or I/O failures never become empty. */
    public Optional<OwnerOpenClientStateCodec.Snapshot> load() throws IOException {
        return locked(new LockedOperation<Optional<OwnerOpenClientStateCodec.Snapshot>>() {
            public Optional<OwnerOpenClientStateCodec.Snapshot> run() throws IOException {
                return readCommitted();
            }
        }, false);
    }

    /** expectedRevision=0 creates the first identity; otherwise rejects stale writers. */
    public OwnerOpenClientStateCodec.Snapshot compareAndSet(
            long expectedRevision, OwnerOpenClientState next) throws IOException {
        if (expectedRevision < 0 || next == null) {
            throw new IllegalArgumentException("invalid expected revision/state");
        }
        return locked(new LockedOperation<OwnerOpenClientStateCodec.Snapshot>() {
            public OwnerOpenClientStateCodec.Snapshot run() throws IOException {
                Optional<OwnerOpenClientStateCodec.Snapshot> current = readCommitted();
                long actualRevision = current.isPresent() ? current.get().revision : 0;
                if (actualRevision != expectedRevision) {
                    throw new StoreException(Failure.STALE_REVISION, false, null);
                }
                try {
                    if (current.isPresent()) {
                        OwnerOpenClientState.requireSuccessor(current.get().state, next);
                    } else if (!next.cursors.isEmpty()) {
                        throw new IllegalArgumentException("initial identity cannot invent observed cursors");
                    }
                } catch (IllegalArgumentException error) {
                    throw new StoreException(Failure.STATE_CONFLICT, false, error);
                }
                final long newRevision;
                try {
                    newRevision = Math.addExact(actualRevision, 1);
                } catch (ArithmeticException error) {
                    throw new StoreException(Failure.STATE_CONFLICT, false, error);
                }
                OwnerOpenClientStateCodec.Snapshot snapshot =
                        new OwnerOpenClientStateCodec.Snapshot(newRevision, next);
                byte[] record = OwnerOpenClientStateCodec.encode(snapshot);
                Path pending = directory.resolve(PENDING);
                Path committed = directory.resolve(STATE);
                boolean renameAttempted = false;
                try {
                    // CREATE_NEW preserves a crash residue and prevents symlink replacement/following.
                    try (FileChannel output = FileChannel.open(pending,
                            java.util.Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                                    LinkOption.NOFOLLOW_LINKS),
                            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
                        ByteBuffer bytes = ByteBuffer.wrap(record);
                        while (bytes.hasRemaining()) {
                            output.write(bytes);
                        }
                        output.force(true);
                    }
                    hook.afterFileSync();
                    // A rename I/O error may leave the namespace outcome unknown.
                    renameAttempted = true;
                    hook.atomicMove(pending, committed);
                    hook.afterAtomicRename();
                    syncDirectory();
                    return snapshot;
                } catch (IOException error) {
                    // Do not repair/delete an ambiguous pending write or authorize submission.
                    throw new StoreException(Failure.IO_FAILURE, renameAttempted, error);
                }
            }
        }, true);
    }

    private Optional<OwnerOpenClientStateCodec.Snapshot> readCommitted() throws IOException {
        Path pending = directory.resolve(PENDING);
        if (attributesIfPresent(pending) != null) {
            throw new StoreException(Failure.PENDING_WRITE, true, null);
        }
        Path committed = directory.resolve(STATE);
        BasicFileAttributes attributes = attributesIfPresent(committed);
        if (attributes == null) {
            return Optional.empty();
        }
        requireRegular(committed);
        if (attributes.size() > OwnerOpenClientStateCodec.MAX_RECORD_BYTES) {
            throw new StoreException(Failure.CORRUPT_RECORD, false, null);
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(OwnerOpenClientStateCodec.MAX_RECORD_BYTES);
        try (InputStream input = Files.newInputStream(committed, LinkOption.NOFOLLOW_LINKS)) {
            byte[] buffer = new byte[128];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (bytes.size() + count > OwnerOpenClientStateCodec.MAX_RECORD_BYTES) {
                    throw new StoreException(Failure.CORRUPT_RECORD, false, null);
                }
                bytes.write(buffer, 0, count);
            }
        }
        try {
            return Optional.of(OwnerOpenClientStateCodec.decode(bytes.toByteArray()));
        } catch (OwnerOpenClientStateCodec.CorruptStateException error) {
            throw new StoreException(Failure.CORRUPT_RECORD, false, error);
        }
    }

    private interface LockedOperation<T> {
        T run() throws IOException;
    }

    private <T> T locked(LockedOperation<T> operation, boolean mayWrite) throws IOException {
        ProcessGuard processGuard = retainProcessGuard();
        boolean acquired = false;
        try {
            if (!processGuard.permit.tryAcquire()) {
                throw new StoreException(Failure.LOCK_BUSY, false, null);
            }
            acquired = true;
            // No lock inode FD may be opened before acquiring the local nonreentrant guard.
            return fileLocked(operation, mayWrite);
        } finally {
            // fileLocked has already closed its FileLock and channel, even on failure.
            if (acquired) {
                processGuard.permit.release();
            }
            releaseProcessGuard(processGuard);
        }
    }

    private ProcessGuard retainProcessGuard() throws IOException {
        synchronized (PROCESS_GUARDS) {
            ProcessGuard guard = PROCESS_GUARDS.get(directory);
            if (guard == null) {
                if (PROCESS_GUARDS.size() >= MAX_PROCESS_PARTITIONS) {
                    throw new StoreException(Failure.LOCK_BUSY, false, null);
                }
                guard = new ProcessGuard();
                PROCESS_GUARDS.put(directory, guard);
            }
            if (guard.references >= MAX_PARTITION_REFERENCES) {
                throw new StoreException(Failure.LOCK_BUSY, false, null);
            }
            guard.references++;
            return guard;
        }
    }

    private void releaseProcessGuard(ProcessGuard guard) {
        synchronized (PROCESS_GUARDS) {
            if (--guard.references == 0) {
                PROCESS_GUARDS.remove(directory);
            }
        }
    }

    private <T> T fileLocked(LockedOperation<T> operation, boolean mayWrite) throws IOException {
        Path lockPath = directory.resolve(LOCK);
        if (attributesIfPresent(lockPath) != null) {
            requireRegular(lockPath);
        }
        try (FileChannel lockChannel = FileChannel.open(lockPath,
                java.util.Set.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                        LinkOption.NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            try (FileLock lock = lockChannel.tryLock()) {
                if (lock == null) {
                    throw new StoreException(Failure.LOCK_BUSY, false, null);
                }
                return operation.run();
            } catch (OverlappingFileLockException error) {
                throw new StoreException(Failure.LOCK_BUSY, false, error);
            }
        } catch (StoreException error) {
            throw error;
        } catch (IOException error) {
            // A post-operation lock/channel close error must not claim the write did not commit.
            throw new StoreException(Failure.IO_FAILURE, mayWrite, error);
        }
    }

    private static void requireRegular(Path path) throws IOException {
        BasicFileAttributes attributes = attributesIfPresent(path);
        if (attributes == null || !attributes.isRegularFile()) {
            throw new StoreException(Failure.INVALID_FILE, false, null);
        }
    }

    private static BasicFileAttributes attributesIfPresent(Path path) throws IOException {
        try {
            return Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (NoSuchFileException absent) {
            return null;
        }
    }

    private void syncDirectory() throws IOException {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        }
    }
}
