/*
 * Minimal argv adapter for using one retained Zig binary as Cargo's host C
 * linker without a shell, PATH lookup, or an unmeasured compiler driver.
 *
 * The artifact builder passes the already-open Zig executable as
 * TRILLIONNIUM_ZIG_REAL=/proc/self/fd/<n>. The builder explicitly inherits
 * only its measured compiler-role descriptors into the complete Cargo child
 * tree. The wrapper inserts Zig's required `cc` subcommand and execs that
 * exact retained descriptor path.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int retained_fd_path(const char *value, const char *suffix) {
    static const char prefix[] = "/proc/";
    static const char self_separator[] = "self/fd/";
    static const char separator[] = "/fd/";
    const char *cursor;

    if (value == NULL || suffix == NULL ||
        strncmp(value, prefix, sizeof(prefix) - 1) != 0) {
        return 0;
    }
    cursor = value + sizeof(prefix) - 1;
    if (strncmp(cursor, self_separator, sizeof(self_separator) - 1) == 0) {
        cursor += sizeof(self_separator) - 1;
    } else {
        if (*cursor < '1' || *cursor > '9') {
            return 0;
        }
        for (++cursor; *cursor >= '0' && *cursor <= '9'; ++cursor) {
            /* scan the complete decimal process id */
        }
        if (strncmp(cursor, separator, sizeof(separator) - 1) != 0) {
            return 0;
        }
        cursor += sizeof(separator) - 1;
    }
    if (*cursor < '1' || *cursor > '9') {
        return 0;
    }
    for (++cursor; *cursor >= '0' && *cursor <= '9'; ++cursor) {
        /* scan the complete decimal descriptor */
    }
    return strcmp(cursor, suffix) == 0;
}

int main(int argc, char **argv, char **envp) {
    const char *driver = getenv("TRILLIONNIUM_ZIG_REAL");
    const char *lib_dir = getenv("ZIG_LIB_DIR");
    char **forwarded;
    size_t count;
    int index;

    if (argc < 1 || argv == NULL || !retained_fd_path(driver, "") ||
        !retained_fd_path(lib_dir, "/lib")) {
        return 125;
    }
    if ((size_t)argc > (SIZE_MAX / sizeof(*forwarded)) - 5) {
        return 125;
    }
    count = (size_t)argc + 5;
    forwarded = calloc(count, sizeof(*forwarded));
    if (forwarded == NULL) {
        return 125;
    }
    forwarded[0] = (char *)driver;
    forwarded[1] = (char *)"cc";
    forwarded[2] = (char *)"-target";
    forwarded[3] = (char *)"x86_64-linux-gnu";
    forwarded[4] = (char *)"-mcpu=baseline";
    for (index = 1; index < argc; ++index) {
        forwarded[index + 4] = argv[index];
    }
    forwarded[argc + 4] = NULL;
    execve(driver, forwarded, envp);
    return errno == ENOENT ? 127 : 126;
}
