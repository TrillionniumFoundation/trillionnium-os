#define _GNU_SOURCE

#include "trillionnium_provider_build_supervisor_protocol.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_execveat
#define SYS_execveat 322
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_renameat2
#define SYS_renameat2 316
#endif
#ifndef SYS_close_range
#define SYS_close_range 436
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1u << 2)
#endif
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1u << 0)
#endif

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "provider build protocol currently requires a little-endian Linux host"
#endif

#define ARRAY_LENGTH(value) (sizeof(value) / sizeof((value)[0]))
#define MAX_FRAME_FDS 8u
#define MAX_TREE_DEPTH 64u
#define MAX_TREE_ENTRIES 16384u
#define MAX_TREE_BYTES (UINT64_C(8) * 1024u * 1024u * 1024u)
#define CHILD_EXIT_SETUP 125
#define CHILD_EXIT_VERIFY 126

struct options {
    const char *provider;
    const char *profile;
    const char *output;
    const char *cache;
    const char *source_root;
    const char *python;
    const char *builder;
    const char *recipe;
    const char *containerfile;
    const char *docker;
    const char *cgroup_root;
    uid_t worker_uid;
    gid_t worker_gid;
};

struct retained_inputs {
    int python_fd;
    int builder_fd;
    int recipe_fd;
    int containerfile_fd;
    int docker_fd;
};

struct frame {
    uint8_t bytes[sizeof(struct tpbs_ready)];
    size_t length;
    int descriptors[MAX_FRAME_FDS];
    size_t descriptor_count;
    struct ucred credentials;
};

struct tree_totals {
    uint64_t entries;
    uint64_t bytes;
    dev_t device;
};

static void close_if_open(int *descriptor)
{
    if (*descriptor >= 0) {
        (void)close(*descriptor);
        *descriptor = -1;
    }
}

static int fail_errno(const char *message)
{
    fprintf(stderr, "provider build supervisor: %s: %s\n", message,
            strerror(errno));
    return -1;
}

static int fail_text(const char *message)
{
    fprintf(stderr, "provider build supervisor: %s\n", message);
    errno = EINVAL;
    return -1;
}

static bool normalized_absolute_path(const char *value)
{
    size_t length;
    if (value == NULL || value[0] != '/' || value[1] == '\0') {
        return false;
    }
    length = strlen(value);
    if (length >= 4096u || value[length - 1u] == '/' ||
        strstr(value, "//") != NULL || strstr(value, "/../") != NULL ||
        strstr(value, "/./") != NULL ||
        (length >= 3u && strcmp(value + length - 3u, "/..") == 0) ||
        (length >= 2u && strcmp(value + length - 2u, "/.") == 0) ||
        strchr(value, '\n') != NULL || strchr(value, '\r') != NULL) {
        return false;
    }
    return true;
}

static int parse_u32_identity(const char *value, uint32_t *result)
{
    char *end = NULL;
    unsigned long parsed;
    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed == 0 ||
        parsed > UINT32_MAX) {
        return -1;
    }
    *result = (uint32_t)parsed;
    return 0;
}

static int option_value(int argc, char **argv, const char *name,
                        const char **result)
{
    int found = 0;
    for (int index = 1; index < argc; ++index) {
        if (strcmp(argv[index], name) == 0) {
            if (index + 1 >= argc || argv[index + 1][0] == '-') {
                return -1;
            }
            *result = argv[index + 1];
            found++;
        }
    }
    return found == 1 ? 0 : -1;
}

static int parse_options(int argc, char **argv, struct options *options)
{
    const char *uid_value = NULL;
    const char *gid_value = NULL;
    uint32_t uid = 0;
    uint32_t gid = 0;
    const char *known[] = {
        "--provider",      "--builder-profile", "--output-dir",
        "--cache-dir",     "--source-root",     "--python",
        "--builder",       "--recipe",          "--containerfile",
        "--docker",        "--cgroup-root",     "--worker-uid",
        "--worker-gid",
    };
    if (argc != 1 + (int)(2u * ARRAY_LENGTH(known))) {
        return fail_text("exactly thirteen closed options are required");
    }
    for (size_t index = 0; index < ARRAY_LENGTH(known); ++index) {
        const char *ignored = NULL;
        if (option_value(argc, argv, known[index], &ignored) != 0) {
            return fail_text("one required option is missing or duplicated");
        }
    }
    for (int index = 1; index < argc; index += 2) {
        bool recognized = false;
        for (size_t item = 0; item < ARRAY_LENGTH(known); ++item) {
            if (strcmp(argv[index], known[item]) == 0) {
                recognized = true;
                break;
            }
        }
        if (!recognized) {
            return fail_text("unknown supervisor option");
        }
    }
    if (option_value(argc, argv, "--provider", &options->provider) != 0 ||
        option_value(argc, argv, "--builder-profile", &options->profile) != 0 ||
        option_value(argc, argv, "--output-dir", &options->output) != 0 ||
        option_value(argc, argv, "--cache-dir", &options->cache) != 0 ||
        option_value(argc, argv, "--source-root", &options->source_root) != 0 ||
        option_value(argc, argv, "--python", &options->python) != 0 ||
        option_value(argc, argv, "--builder", &options->builder) != 0 ||
        option_value(argc, argv, "--recipe", &options->recipe) != 0 ||
        option_value(argc, argv, "--containerfile", &options->containerfile) !=
            0 ||
        option_value(argc, argv, "--docker", &options->docker) != 0 ||
        option_value(argc, argv, "--cgroup-root", &options->cgroup_root) != 0 ||
        option_value(argc, argv, "--worker-uid", &uid_value) != 0 ||
        option_value(argc, argv, "--worker-gid", &gid_value) != 0) {
        return fail_text("closed supervisor option parsing failed");
    }
    if (strcmp(options->provider, "codex") != 0 ||
        (strcmp(options->profile, "amd64-cross") != 0 &&
         strcmp(options->profile, "arm64-native") != 0) ||
        strcmp(options->docker, "/usr/bin/docker") != 0 ||
        parse_u32_identity(uid_value, &uid) != 0 ||
        parse_u32_identity(gid_value, &gid) != 0) {
        return fail_text("provider, profile, or worker identity is outside the closed set");
    }
    const char *paths[] = {
        options->output,       options->cache,     options->source_root,
        options->python,       options->builder,   options->recipe,
        options->containerfile, options->docker,    options->cgroup_root,
    };
    for (size_t index = 0; index < ARRAY_LENGTH(paths); ++index) {
        if (!normalized_absolute_path(paths[index])) {
            return fail_text("one supervisor path is not normalized and absolute");
        }
    }
    options->worker_uid = (uid_t)uid;
    options->worker_gid = (gid_t)gid;
    return 0;
}

static int open_regular(const char *path, bool require_root_owner)
{
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat value;
    if (descriptor < 0) {
        return fail_errno("retained regular input open failed");
    }
    if (fstat(descriptor, &value) != 0 || !S_ISREG(value.st_mode) ||
        value.st_nlink != 1 || (value.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (require_root_owner && value.st_uid != 0)) {
        close(descriptor);
        return fail_text("retained regular input metadata is unsafe");
    }
    return descriptor;
}

static int same_named_inode(const char *path, int descriptor)
{
    struct stat named;
    struct stat opened;
    if (lstat(path, &named) != 0 || fstat(descriptor, &opened) != 0 ||
        !S_ISREG(named.st_mode) || (named.st_dev != opened.st_dev) ||
        (named.st_ino != opened.st_ino)) {
        return fail_text("retained source or executable path was rebound");
    }
    return 0;
}

static int split_output(const char *output, char *parent, size_t parent_size,
                        char *name, size_t name_size)
{
    const char *slash = strrchr(output, '/');
    size_t parent_length;
    if (slash == NULL || slash == output || slash[1] == '\0') {
        return fail_text("output must have a non-root parent and basename");
    }
    parent_length = (size_t)(slash - output);
    if (parent_length >= parent_size || strlen(slash + 1) >= name_size ||
        strchr(slash + 1, ',') != NULL) {
        return fail_text("output parent or basename is too long");
    }
    memcpy(parent, output, parent_length);
    parent[parent_length] = '\0';
    strcpy(name, slash + 1);
    return 0;
}

static int ensure_absent_at(int parent, const char *name)
{
    struct stat ignored;
    if (fstatat(parent, name, &ignored, AT_SYMLINK_NOFOLLOW) == 0) {
        return fail_text("final output or failure name already exists");
    }
    if (errno != ENOENT) {
        return fail_errno("final output absence check failed");
    }
    return 0;
}

static int same_named_directory(const char *path, int descriptor)
{
    struct stat named;
    struct stat opened;
    if (lstat(path, &named) != 0 || fstat(descriptor, &opened) != 0 ||
        !S_ISDIR(named.st_mode) || named.st_dev != opened.st_dev ||
        named.st_ino != opened.st_ino) {
        return fail_text("root output parent path was rebound");
    }
    return 0;
}

static int same_named_child(int parent, const char *name, int descriptor)
{
    struct stat named;
    struct stat opened;
    if (fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        fstat(descriptor, &opened) != 0 || !S_ISDIR(named.st_mode) ||
        named.st_dev != opened.st_dev || named.st_ino != opened.st_ino) {
        return fail_text("root-owned candidate name was rebound");
    }
    return 0;
}

static int random_hex(char *output, size_t byte_count)
{
    static const char digits[] = "0123456789abcdef";
    uint8_t bytes[32];
    if (byte_count > sizeof(bytes) ||
        getrandom(bytes, byte_count, GRND_NONBLOCK) != (ssize_t)byte_count) {
        return fail_errno("kernel random challenge failed");
    }
    for (size_t index = 0; index < byte_count; ++index) {
        output[index * 2u] = digits[bytes[index] >> 4u];
        output[index * 2u + 1u] = digits[bytes[index] & 15u];
    }
    output[byte_count * 2u] = '\0';
    return 0;
}

static int create_candidate(int parent, const char *name, uid_t uid, gid_t gid)
{
    int descriptor;
    struct stat value;
    if (mkdirat(parent, name, 0700) != 0) {
        return fail_errno("candidate mkdirat failed");
    }
    descriptor = openat(parent, name,
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fchown(descriptor, uid, gid) != 0 ||
        fchmod(descriptor, 0700) != 0 || fsync(descriptor) != 0 ||
        fsync(parent) != 0 || fstat(descriptor, &value) != 0 ||
        !S_ISDIR(value.st_mode) || value.st_uid != uid || value.st_gid != gid ||
        (value.st_mode & 07777) != 0700) {
        close_if_open(&descriptor);
        return fail_errno("candidate custody initialization failed");
    }
    return descriptor;
}

static int set_cloexec(int descriptor, bool enabled)
{
    int flags = fcntl(descriptor, F_GETFD);
    if (flags < 0 ||
        fcntl(descriptor, F_SETFD,
              enabled ? (flags | FD_CLOEXEC) : (flags & ~FD_CLOEXEC)) != 0) {
        return -1;
    }
    return 0;
}

static int close_all_on_exec(void)
{
    return (int)syscall(SYS_close_range, 3u, UINT_MAX,
                        CLOSE_RANGE_CLOEXEC);
}

static int write_all(int descriptor, const char *content)
{
    size_t length = strlen(content);
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(descriptor, content + offset, length - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

static int read_small_at(int parent, const char *name, char *output,
                         size_t capacity)
{
    int descriptor = openat(parent, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t amount;
    if (descriptor < 0) {
        return -1;
    }
    amount = read(descriptor, output, capacity - 1u);
    if (amount < 0 || (size_t)amount >= capacity - 1u) {
        close(descriptor);
        return -1;
    }
    output[amount] = '\0';
    close(descriptor);
    return 0;
}

static int attach_cgroup(const char *root_path, pid_t child, int *root_fd,
                         int *attempt_fd, char *attempt_name,
                         size_t attempt_capacity, char *expected_proc,
                         size_t expected_capacity)
{
    struct statfs filesystem;
    struct stat root_stat;
    char random[17];
    char pid_text[32];
    int procs = -1;
    *root_fd = open(root_path,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (*root_fd < 0 || fstatfs(*root_fd, &filesystem) != 0 ||
        filesystem.f_type != CGROUP2_SUPER_MAGIC ||
        fstat(*root_fd, &root_stat) != 0 || root_stat.st_uid != 0 ||
        (root_stat.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return fail_text("cgroup root is not root-owned cgroup v2 custody");
    }
    if (strncmp(root_path, "/sys/fs/cgroup/", 15) != 0 ||
        random_hex(random, 8) != 0 ||
        snprintf(attempt_name, attempt_capacity, "tpbs-%ld-%s", (long)child,
                 random) >= (int)attempt_capacity ||
        mkdirat(*root_fd, attempt_name, 0700) != 0) {
        return fail_errno("one-shot cgroup creation failed");
    }
    *attempt_fd = openat(*root_fd, attempt_name,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (*attempt_fd < 0 || fchown(*attempt_fd, 0, 0) != 0 ||
        fchmod(*attempt_fd, 0700) != 0) {
        return fail_errno("one-shot cgroup ownership closure failed");
    }
    procs = openat(*attempt_fd, "cgroup.procs",
                   O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (procs < 0 ||
        snprintf(pid_text, sizeof(pid_text), "%ld\n", (long)child) <= 0 ||
        write_all(procs, pid_text) != 0) {
        close_if_open(&procs);
        return fail_errno("worker cgroup placement failed");
    }
    close(procs);
    const char *relative = root_path + strlen("/sys/fs/cgroup");
    if (snprintf(expected_proc, expected_capacity, "0::%s/%s\n", relative,
                 attempt_name) >= (int)expected_capacity) {
        return fail_text("worker cgroup path is too long");
    }
    return 0;
}

static int read_proc_file(pid_t pid, const char *leaf, char *output,
                          size_t capacity)
{
    char path[128];
    int descriptor;
    ssize_t amount;
    if (snprintf(path, sizeof(path), "/proc/%ld/%s", (long)pid, leaf) >=
        (int)sizeof(path)) {
        return -1;
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return -1;
    }
    amount = read(descriptor, output, capacity - 1u);
    close(descriptor);
    if (amount <= 0 || (size_t)amount >= capacity - 1u) {
        return -1;
    }
    output[amount] = '\0';
    return 0;
}

static int proc_starttime(pid_t pid, unsigned long long *starttime)
{
    char value[4096];
    char *end_name;
    char *cursor;
    unsigned field = 3;
    if (read_proc_file(pid, "stat", value, sizeof(value)) != 0) {
        return -1;
    }
    end_name = strrchr(value, ')');
    if (end_name == NULL || end_name[1] != ' ') {
        return -1;
    }
    cursor = end_name + 2;
    while (field <= 22u) {
        char *next = strchr(cursor, ' ');
        if (field == 22u) {
            char *end = NULL;
            errno = 0;
            *starttime = strtoull(cursor, &end, 10);
            if (errno != 0 || end == cursor ||
                (*end != ' ' && *end != '\n' && *end != '\0')) {
                return -1;
            }
            return 0;
        }
        if (next == NULL) {
            return -1;
        }
        cursor = next + 1;
        field++;
    }
    return -1;
}

static int exact_worker_status(pid_t pid, uid_t uid, gid_t gid,
                               const char *expected_cgroup,
                               unsigned long long starttime, int python_fd)
{
    char status[8192];
    char cgroup[4096];
    char expected_uid[96];
    char expected_gid[96];
    char exe_path[128];
    struct stat expected_exe;
    struct stat observed_exe;
    int exe_fd = -1;
    unsigned long long observed_start = 0;
    if (read_proc_file(pid, "status", status, sizeof(status)) != 0 ||
        read_proc_file(pid, "cgroup", cgroup, sizeof(cgroup)) != 0 ||
        proc_starttime(pid, &observed_start) != 0 ||
        observed_start != starttime ||
        snprintf(expected_uid, sizeof(expected_uid), "Uid:\t%u\t%u\t%u\t%u\n",
                 (unsigned)uid, (unsigned)uid, (unsigned)uid,
                 (unsigned)uid) >= (int)sizeof(expected_uid) ||
        snprintf(expected_gid, sizeof(expected_gid), "Gid:\t%u\t%u\t%u\t%u\n",
                 (unsigned)gid, (unsigned)gid, (unsigned)gid,
                 (unsigned)gid) >= (int)sizeof(expected_gid) ||
        strstr(status, expected_uid) == NULL ||
        strstr(status, expected_gid) == NULL ||
        strstr(status, "Groups:\t\n") == NULL ||
        strstr(status, "NoNewPrivs:\t1\n") == NULL ||
        strstr(status, "CapInh:\t0000000000000000\n") == NULL ||
        strstr(status, "CapPrm:\t0000000000000000\n") == NULL ||
        strstr(status, "CapEff:\t0000000000000000\n") == NULL ||
        strstr(status, "CapBnd:\t0000000000000000\n") == NULL ||
        strstr(status, "CapAmb:\t0000000000000000\n") == NULL ||
        strcmp(cgroup, expected_cgroup) != 0) {
        return fail_text("worker runtime identity or cgroup drifted");
    }
    if (snprintf(exe_path, sizeof(exe_path), "/proc/%ld/exe", (long)pid) >=
        (int)sizeof(exe_path)) {
        return fail_text("worker executable path overflow");
    }
    exe_fd = open(exe_path, O_PATH | O_CLOEXEC);
    if (exe_fd < 0 || fstat(exe_fd, &observed_exe) != 0 ||
        fstat(python_fd, &expected_exe) != 0 ||
        observed_exe.st_dev != expected_exe.st_dev ||
        observed_exe.st_ino != expected_exe.st_ino) {
        close_if_open(&exe_fd);
        return fail_text("worker executable does not match retained interpreter");
    }
    close(exe_fd);
    return 0;
}

static int child_drop(uid_t uid, gid_t gid)
{
    for (int capability = 0; capability <= 63; ++capability) {
        if (prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 &&
            errno != EINVAL) {
            return -1;
        }
    }
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 ||
        setgroups(0, NULL) != 0 || setresgid(gid, gid, gid) != 0 ||
        setresuid(uid, uid, uid) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        return -1;
    }
    return 0;
}

static void child_exec_builder(const struct options *options,
                               const struct retained_inputs *inputs,
                               int protocol_socket, int release_pipe,
                               const char *success_host,
                               const char *failure_host, pid_t supervisor_pid)
{
    char release = 0;
    char socket_text[32];
    char builder_text[32];
    char supervisor_text[32];
    char script_path[64];
    char *arguments[32];
    int count = 0;
    char *environment[] = {
        "LANG=C", "LC_ALL=C", "TZ=UTC", "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONNOUSERSITE=1", "PATH=/usr/bin:/bin", NULL,
    };
    if (read(release_pipe, &release, 1) != 1 || release != 'R' ||
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0 ||
        getppid() != supervisor_pid || close_all_on_exec() != 0 ||
        child_drop(options->worker_uid,
                                                  options->worker_gid) != 0 ||
        set_cloexec(protocol_socket, false) != 0 ||
        set_cloexec(inputs->builder_fd, false) != 0) {
        _exit(CHILD_EXIT_SETUP);
    }
    close(release_pipe);
    if (snprintf(socket_text, sizeof(socket_text), "%d", protocol_socket) >=
            (int)sizeof(socket_text) ||
        snprintf(builder_text, sizeof(builder_text), "%d",
                 inputs->builder_fd) >= (int)sizeof(builder_text) ||
        snprintf(supervisor_text, sizeof(supervisor_text), "%ld",
                 (long)supervisor_pid) >= (int)sizeof(supervisor_text) ||
        snprintf(script_path, sizeof(script_path), "/proc/self/fd/%d",
                 inputs->builder_fd) >= (int)sizeof(script_path)) {
        _exit(CHILD_EXIT_SETUP);
    }
#define ARG(value) arguments[count++] = (char *)(value)
    ARG("python3");
    ARG(script_path);
    ARG("_supervised-build");
    ARG("--provider");
    ARG(options->provider);
    ARG("--builder-profile");
    ARG(options->profile);
    ARG("--output-dir");
    ARG(options->output);
    ARG("--cache-dir");
    ARG(options->cache);
    ARG("--source-root");
    ARG(options->source_root);
    ARG("--success-host-path");
    ARG(success_host);
    ARG("--failure-host-path");
    ARG(failure_host);
    ARG("--socket-fd");
    ARG(socket_text);
    ARG("--exec-builder-fd");
    ARG(builder_text);
    ARG("--supervisor-pid");
    ARG(supervisor_text);
    ARG("--container-engine");
    ARG("docker");
    arguments[count] = NULL;
#undef ARG
    syscall(SYS_execveat, inputs->python_fd, "", arguments, environment,
            AT_EMPTY_PATH);
    _exit(CHILD_EXIT_SETUP);
}

static void close_frame(struct frame *frame)
{
    for (size_t index = 0; index < frame->descriptor_count; ++index) {
        close(frame->descriptors[index]);
    }
    frame->descriptor_count = 0;
}

static int receive_frame(int socket_fd, pid_t expected_pid, uid_t expected_uid,
                         gid_t expected_gid, struct frame *frame)
{
    union {
        char bytes[CMSG_SPACE(sizeof(struct ucred)) +
                   CMSG_SPACE(sizeof(int) * MAX_FRAME_FDS)];
        struct cmsghdr align;
    } control;
    struct iovec vector = {
        .iov_base = frame->bytes,
        .iov_len = sizeof(frame->bytes),
    };
    struct msghdr message = {
        .msg_iov = &vector,
        .msg_iovlen = 1,
        .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes),
    };
    ssize_t amount;
    bool credential_seen = false;
    memset(frame, 0, sizeof(*frame));
    do {
        amount = recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC);
    } while (amount < 0 && errno == EINTR);
    if (amount <= 0 ||
        (message.msg_flags & ~MSG_CMSG_CLOEXEC) != 0 ||
        (size_t)amount < sizeof(struct tpbs_header)) {
        return fail_text("protocol frame is absent, truncated, or has unknown flags");
    }
    frame->length = (size_t)amount;
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header != NULL;
         header = CMSG_NXTHDR(&message, header)) {
        size_t payload;
        if (header->cmsg_level != SOL_SOCKET ||
            header->cmsg_len < CMSG_LEN(0)) {
            close_frame(frame);
            return fail_text("protocol frame has unknown ancillary metadata");
        }
        payload = header->cmsg_len - CMSG_LEN(0);
        if (header->cmsg_type == SCM_CREDENTIALS) {
            if (credential_seen || payload != sizeof(struct ucred)) {
                close_frame(frame);
                return fail_text("protocol frame credentials are duplicated");
            }
            memcpy(&frame->credentials, CMSG_DATA(header),
                   sizeof(frame->credentials));
            credential_seen = true;
        } else if (header->cmsg_type == SCM_RIGHTS) {
            size_t count;
            if (payload == 0 || payload % sizeof(int) != 0) {
                close_frame(frame);
                return fail_text("protocol frame rights payload is malformed");
            }
            count = payload / sizeof(int);
            if (frame->descriptor_count + count > MAX_FRAME_FDS) {
                close_frame(frame);
                return fail_text("protocol frame has excess SCM_RIGHTS FDs");
            }
            memcpy(frame->descriptors + frame->descriptor_count,
                   CMSG_DATA(header), payload);
            frame->descriptor_count += count;
        } else {
            close_frame(frame);
            return fail_text("protocol frame has unknown ancillary data");
        }
    }
    if (!credential_seen || frame->credentials.pid != expected_pid ||
        frame->credentials.uid != expected_uid ||
        frame->credentials.gid != expected_gid) {
        close_frame(frame);
        return fail_text("protocol frame SCM_CREDENTIALS are not the exact worker");
    }
    struct tpbs_header copied_header;
    memcpy(&copied_header, frame->bytes, sizeof(copied_header));
    const struct tpbs_header *header = &copied_header;
    if (header->magic != TPBS_MAGIC || header->version != TPBS_VERSION ||
        header->flags != 0 || header->size != frame->length) {
        close_frame(frame);
        return fail_text("protocol frame header is malformed");
    }
    return 0;
}

static int send_frame(int socket_fd, const void *content, size_t length,
                      const int *descriptors, size_t descriptor_count)
{
    union {
        char bytes[CMSG_SPACE(sizeof(int) * MAX_FRAME_FDS)];
        struct cmsghdr align;
    } control;
    struct iovec vector = {
        .iov_base = (void *)content,
        .iov_len = length,
    };
    struct msghdr message = {
        .msg_iov = &vector,
        .msg_iovlen = 1,
    };
    if (descriptor_count > MAX_FRAME_FDS) {
        return fail_text("outgoing protocol FD count is excessive");
    }
    if (descriptor_count != 0) {
        struct cmsghdr *header;
        message.msg_control = control.bytes;
        message.msg_controllen = CMSG_SPACE(sizeof(int) * descriptor_count);
        memset(control.bytes, 0, message.msg_controllen);
        header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int) * descriptor_count);
        memcpy(CMSG_DATA(header), descriptors, sizeof(int) * descriptor_count);
    }
    ssize_t amount;
    do {
        amount = sendmsg(socket_fd, &message, MSG_NOSIGNAL);
    } while (amount < 0 && errno == EINTR);
    if (amount != (ssize_t)length) {
        return fail_errno("protocol frame send failed");
    }
    return 0;
}

static int validate_hello(const struct frame *frame)
{
    const struct tpbs_hello *hello =
        (const struct tpbs_hello *)(const void *)frame->bytes;
    uint8_t zero[sizeof(hello->reserved)] = {0};
    if (frame->length != sizeof(*hello) ||
        hello->header.kind != TPBS_HELLO || frame->descriptor_count != 0 ||
        memcmp(hello->reserved, zero, sizeof(zero)) != 0) {
        return fail_text("worker HELLO is malformed or carries rights");
    }
    return 0;
}

static bool exact_hex(const uint8_t *value, size_t length)
{
    for (size_t index = 0; index < length; ++index) {
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f'))) {
            return false;
        }
    }
    return true;
}

static bool closed_container_name(
    const uint8_t value[TPBS_CONTAINER_NAME_BYTES])
{
    static const char prefix[] = "trillionnium-provider-";
    size_t length = 0;
    while (length < TPBS_CONTAINER_NAME_BYTES && value[length] != 0) {
        uint8_t character = value[length];
        if (!((character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') || character == '_' ||
              character == '.' || character == '-')) {
            return false;
        }
        length++;
    }
    if (length < sizeof(prefix) || length >= TPBS_CONTAINER_NAME_BYTES ||
        memcmp(value, prefix, sizeof(prefix) - 1u) != 0) {
        return false;
    }
    for (size_t index = length; index < TPBS_CONTAINER_NAME_BYTES; ++index) {
        if (value[index] != 0) {
            return false;
        }
    }
    return true;
}

static int create_cid_from_request(
    const struct frame *frame, const uint8_t challenge[TPBS_CHALLENGE_BYTES],
    int output_parent, uid_t uid, gid_t gid, int *cid_fd, char *cid_name,
    size_t cid_name_capacity)
{
    const struct tpbs_cid_request *request =
        (const struct tpbs_cid_request *)(const void *)frame->bytes;
    if (frame->length != sizeof(*request) ||
        request->header.kind != TPBS_CID_REQUEST ||
        frame->descriptor_count != 0 ||
        memcmp(request->challenge, challenge, TPBS_CHALLENGE_BYTES) != 0 ||
        !exact_hex(request->attempt, TPBS_ATTEMPT_BYTES) ||
        snprintf(cid_name, cid_name_capacity, "%s%.*s",
                 ".trillionnium-provider-cid-", (int)TPBS_ATTEMPT_BYTES,
                 request->attempt) >= (int)cid_name_capacity) {
        return fail_text("container CID allocation request is malformed");
    }
    *cid_fd = create_candidate(output_parent, cid_name, uid, gid);
    return *cid_fd < 0 ? -1 : 0;
}

static int validate_ready(const struct frame *frame,
                          const uint8_t challenge[TPBS_CHALLENGE_BYTES],
                          int success_fd, int failure_fd,
                          struct tpbs_ready *ready)
{
    struct stat received;
    struct stat expected;
    int expected_fd;
    if (frame->length != sizeof(*ready) ||
        frame->descriptor_count != 1) {
        return fail_text("READY frame has a missing or extra candidate FD");
    }
    memcpy(ready, frame->bytes, sizeof(*ready));
    if (ready->header.kind != TPBS_READY ||
        memcmp(ready->challenge, challenge, TPBS_CHALLENGE_BYTES) != 0 ||
        ready->descriptor_count != 1 ||
        !((ready->role == TPBS_ROLE_SUCCESS && ready->worker_status == 0) ||
          (ready->role == TPBS_ROLE_FAILURE && ready->worker_status == 1)) ||
        !closed_container_name(ready->container_name)) {
        return fail_text("READY outcome, challenge, or closed strings are malformed");
    }
    if (!exact_hex(ready->container_id, TPBS_CONTAINER_ID_BYTES)) {
        uint8_t zero[TPBS_CONTAINER_ID_BYTES] = {0};
        if (memcmp(ready->container_id, zero, sizeof(zero)) != 0) {
            return fail_text("READY container ID is neither exact 64hex nor absent");
        }
    }
    expected_fd =
        ready->role == TPBS_ROLE_SUCCESS ? success_fd : failure_fd;
    if (fstat(frame->descriptors[0], &received) != 0 ||
        fstat(expected_fd, &expected) != 0 || !S_ISDIR(received.st_mode) ||
        received.st_dev != expected.st_dev || received.st_ino != expected.st_ino ||
        ready->candidate_device != (uint64_t)expected.st_dev ||
        ready->candidate_inode != (uint64_t)expected.st_ino) {
        return fail_text("READY candidate FD or inode binding is cross-spliced");
    }
    return 0;
}

static bool cgroup_observed_empty(int descriptor)
{
    char events[1024];
    char procs[128];
    return read_small_at(descriptor, "cgroup.events", events, sizeof(events)) ==
               0 &&
           read_small_at(descriptor, "cgroup.procs", procs, sizeof(procs)) ==
               0 &&
           strstr(events, "populated 0\n") != NULL && procs[0] == '\0';
}

static int cgroup_empty(int descriptor)
{
    for (unsigned attempt = 0; attempt < 50u; ++attempt) {
        if (cgroup_observed_empty(descriptor)) {
            return 0;
        }
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000000};
        nanosleep(&delay, NULL);
    }
    return fail_text("worker cgroup is not empty after exact worker exit");
}

static int kill_cgroup_and_wait_empty(int descriptor)
{
    int kill_fd = openat(descriptor, "cgroup.kill",
                         O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (kill_fd < 0 || write_all(kill_fd, "1\n") != 0) {
        close_if_open(&kill_fd);
        return fail_errno("worker cgroup kill failed");
    }
    close(kill_fd);
    return cgroup_empty(descriptor);
}

static int retire_empty_cgroup(int root_fd, int descriptor, char *name)
{
    if (cgroup_empty(descriptor) != 0 ||
        unlinkat(root_fd, name, AT_REMOVEDIR) != 0) {
        return fail_errno("empty worker cgroup retirement failed");
    }
    name[0] = '\0';
    return 0;
}

static int verify_tree_recursive(int descriptor, uid_t owner, gid_t group,
                                 unsigned depth, struct tree_totals *totals)
{
    DIR *directory = NULL;
    struct dirent *entry;
    int scan_fd = dup(descriptor);
    if (scan_fd < 0 || depth > MAX_TREE_DEPTH) {
        close_if_open(&scan_fd);
        return fail_text("candidate tree depth or descriptor is invalid");
    }
    directory = fdopendir(scan_fd);
    if (directory == NULL) {
        close(scan_fd);
        return fail_errno("candidate directory scan failed");
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        struct stat value;
        int child = -1;
        mode_t closed_mode;
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (strchr(entry->d_name, '/') != NULL ||
            fstatat(descriptor, entry->d_name, &value, AT_SYMLINK_NOFOLLOW) !=
                0 ||
            value.st_dev != totals->device ||
            ++totals->entries > MAX_TREE_ENTRIES) {
            closedir(directory);
            return fail_text("candidate tree name, mount, or entry bound drifted");
        }
        if (S_ISREG(value.st_mode)) {
            if (value.st_nlink != 1 ||
                totals->bytes > MAX_TREE_BYTES - (uint64_t)value.st_size) {
                closedir(directory);
                return fail_text("candidate regular file links or byte bound drifted");
            }
            totals->bytes += (uint64_t)value.st_size;
            child = openat(descriptor, entry->d_name,
                           O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            if (child < 0) {
                closedir(directory);
                return fail_errno("candidate regular file open failed");
            }
            closed_mode =
                (value.st_mode & 0777) &
                (mode_t)~(mode_t)(S_IWUSR | S_IWGRP | S_IWOTH);
            if (fchown(child, owner, group) != 0 ||
                fchmod(child, closed_mode) != 0 || fsync(child) != 0) {
                close(child);
                closedir(directory);
                return fail_errno("candidate regular file closure failed");
            }
            close(child);
        } else if (S_ISDIR(value.st_mode)) {
            child = openat(descriptor, entry->d_name,
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0 ||
                verify_tree_recursive(child, owner, group, depth + 1u,
                                      totals) != 0) {
                close_if_open(&child);
                closedir(directory);
                return -1;
            }
            closed_mode =
                (value.st_mode & 0777) &
                (mode_t)~(mode_t)(S_IWUSR | S_IWGRP | S_IWOTH);
            if (fchown(child, owner, group) != 0 ||
                fchmod(child, closed_mode) != 0 || fsync(child) != 0) {
                close(child);
                closedir(directory);
                return fail_errno("candidate directory closure failed");
            }
            close(child);
        } else {
            closedir(directory);
            return fail_text("candidate tree contains a symlink or special inode");
        }
    }
    if (errno != 0) {
        closedir(directory);
        return fail_errno("candidate directory iteration failed");
    }
    if (closedir(directory) != 0 || fchown(descriptor, owner, group) != 0 ||
        fchmod(descriptor, 0500) != 0 || fsync(descriptor) != 0) {
        return fail_errno("candidate root closure failed");
    }
    return 0;
}

static int close_candidate_tree(int descriptor, uid_t owner, gid_t group)
{
    struct stat root;
    struct tree_totals totals = {0};
    if (fstat(descriptor, &root) != 0 || !S_ISDIR(root.st_mode)) {
        return fail_text("candidate root is not one retained directory");
    }
    totals.device = root.st_dev;
    return verify_tree_recursive(descriptor, owner, group, 0, &totals);
}

static int wait_exact_child(pid_t child, int expected_exit)
{
    int status = 0;
    pid_t observed;
    do {
        observed = waitpid(child, &status, 0);
    } while (observed < 0 && errno == EINTR);
    if (observed != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != expected_exit) {
        return fail_text("exact child exit status is inconsistent with READY");
    }
    return 0;
}

static int run_python_helper(const struct options *options,
                             const struct retained_inputs *inputs,
                             char *const arguments[], int *inherited,
                             size_t inherited_count)
{
    pid_t child = fork();
    if (child < 0) {
        return fail_errno("independent verifier fork failed");
    }
    if (child == 0) {
        char *environment[] = {
            "LANG=C", "LC_ALL=C", "TZ=UTC", "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONNOUSERSITE=1", "PATH=/usr/bin:/bin", NULL,
        };
        if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0 ||
            close_all_on_exec() != 0 ||
            child_drop(options->worker_uid, options->worker_gid) != 0 ||
            set_cloexec(inputs->builder_fd, false) != 0) {
            _exit(CHILD_EXIT_VERIFY);
        }
        for (size_t index = 0; index < inherited_count; ++index) {
            if (set_cloexec(inherited[index], false) != 0) {
                _exit(CHILD_EXIT_VERIFY);
            }
        }
        syscall(SYS_execveat, inputs->python_fd, "", arguments, environment,
                AT_EMPTY_PATH);
        _exit(CHILD_EXIT_VERIFY);
    }
    return wait_exact_child(child, 0);
}

static int verify_container_absence(const struct options *options,
                                    const struct retained_inputs *inputs,
                                    const struct tpbs_ready *ready)
{
    char script_path[64];
    char id[65];
    char name[TPBS_CONTAINER_NAME_BYTES + 1u];
    char *arguments[16];
    int count = 0;
    memcpy(name, ready->container_name, TPBS_CONTAINER_NAME_BYTES);
    name[TPBS_CONTAINER_NAME_BYTES] = '\0';
    if (snprintf(script_path, sizeof(script_path), "/proc/self/fd/%d",
                 inputs->builder_fd) >= (int)sizeof(script_path)) {
        return fail_text("container verifier script FD path overflow");
    }
#define ARG(value) arguments[count++] = (char *)(value)
    ARG("python3");
    ARG(script_path);
    ARG("_verify-container-absent");
    ARG("--container-engine");
    ARG("docker");
    ARG("--container-name");
    ARG(name);
    if (exact_hex(ready->container_id, TPBS_CONTAINER_ID_BYTES)) {
        memcpy(id, ready->container_id, TPBS_CONTAINER_ID_BYTES);
        id[64] = '\0';
        ARG("--container-id");
        ARG(id);
    }
    arguments[count] = NULL;
#undef ARG
    return run_python_helper(options, inputs, arguments, NULL, 0);
}

static int verify_candidate(const struct options *options,
                            const struct retained_inputs *inputs,
                            const struct tpbs_ready *ready, int candidate_fd,
                            int cid_fd)
{
    char script_path[64];
    char candidate_text[32];
    char builder_text[32];
    char recipe_text[32];
    char containerfile_text[32];
    char cid_text[32];
    char *arguments[24];
    int inherited[5];
    size_t inherited_count = 0;
    int count = 0;
    if (snprintf(script_path, sizeof(script_path), "/proc/self/fd/%d",
                 inputs->builder_fd) >= (int)sizeof(script_path) ||
        snprintf(candidate_text, sizeof(candidate_text), "%d", candidate_fd) >=
            (int)sizeof(candidate_text) ||
        snprintf(builder_text, sizeof(builder_text), "%d", inputs->builder_fd) >=
            (int)sizeof(builder_text) ||
        snprintf(recipe_text, sizeof(recipe_text), "%d", inputs->recipe_fd) >=
            (int)sizeof(recipe_text) ||
        snprintf(containerfile_text, sizeof(containerfile_text), "%d",
                 inputs->containerfile_fd) >= (int)sizeof(containerfile_text)) {
        return fail_text("candidate verifier FD argument overflow");
    }
#define ARG(value) arguments[count++] = (char *)(value)
    ARG("python3");
    ARG(script_path);
    ARG("_verify-supervised-candidate-fd");
    ARG("--role");
    ARG(ready->role == TPBS_ROLE_SUCCESS ? "success" : "failure");
    ARG("--candidate-fd");
    ARG(candidate_text);
    ARG("--expected-output");
    ARG(options->output);
    ARG("--builder-fd");
    ARG(builder_text);
    ARG("--recipe-fd");
    ARG(recipe_text);
    ARG("--containerfile-fd");
    ARG(containerfile_text);
    inherited[inherited_count++] = candidate_fd;
    inherited[inherited_count++] = inputs->builder_fd;
    inherited[inherited_count++] = inputs->recipe_fd;
    inherited[inherited_count++] = inputs->containerfile_fd;
    if (ready->role == TPBS_ROLE_FAILURE && cid_fd >= 0) {
        if (snprintf(cid_text, sizeof(cid_text), "%d", cid_fd) >=
            (int)sizeof(cid_text)) {
            return fail_text("candidate verifier CID FD argument overflow");
        }
        ARG("--retained-stage-fd");
        ARG(cid_text);
        inherited[inherited_count++] = cid_fd;
    }
    arguments[count] = NULL;
#undef ARG
    return run_python_helper(options, inputs, arguments, inherited,
                             inherited_count);
}

static int rename_candidate(int parent_fd, const char *candidate_name,
                            const char *final_name, int candidate_fd)
{
    struct stat expected;
    struct stat observed;
    int final_fd = -1;
    if (syscall(SYS_renameat2, parent_fd, candidate_name, parent_fd, final_name,
                RENAME_NOREPLACE) != 0 ||
        fsync(parent_fd) != 0 ||
        fstat(candidate_fd, &expected) != 0) {
        return fail_errno("atomic no-replace candidate publication failed");
    }
    final_fd = openat(parent_fd, final_name,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (final_fd < 0 || fstat(final_fd, &observed) != 0 ||
        observed.st_dev != expected.st_dev || observed.st_ino != expected.st_ino ||
        fsync(parent_fd) != 0) {
        close_if_open(&final_fd);
        return fail_text("published candidate identity changed after parent fsync");
    }
    close(final_fd);
    return 0;
}

int main(int argc, char **argv)
{
    struct options options = {0};
    struct retained_inputs inputs = {-1, -1, -1, -1, -1};
    char output_parent_path[4096];
    char output_name[256];
    char failure_name[300];
    char success_name[300];
    char failure_candidate_name[320];
    char suffix[9];
    char success_host[4096];
    char failure_host[4096];
    char cgroup_name[128];
    char expected_cgroup[4096];
    char boot_before[128];
    char boot_after[128];
    char cid_name[160] = {0};
    int output_parent_fd = -1;
    int success_fd = -1;
    int failure_fd = -1;
    int cid_fd = -1;
    int sockets[2] = {-1, -1};
    int release_pipe[2] = {-1, -1};
    int cgroup_root_fd = -1;
    int cgroup_fd = -1;
    int pidfd = -1;
    pid_t child = -1;
    unsigned long long starttime = 0;
    uint8_t challenge[TPBS_CHALLENGE_BYTES];
    struct frame frame;
    struct tpbs_ready ready;
    int ready_candidate_fd = -1;
    bool cid_allocated = false;
    int result = 1;

    if (geteuid() != 0 || parse_options(argc, argv, &options) != 0 ||
        split_output(options.output, output_parent_path,
                     sizeof(output_parent_path), output_name,
                     sizeof(output_name)) != 0 ||
        snprintf(failure_name, sizeof(failure_name), "%s.failure", output_name) >=
            (int)sizeof(failure_name)) {
        return 2;
    }
    output_parent_fd =
        open(output_parent_path,
             O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat output_parent_stat;
    if (output_parent_fd < 0 || fstat(output_parent_fd, &output_parent_stat) != 0 ||
        !S_ISDIR(output_parent_stat.st_mode) || output_parent_stat.st_uid != 0 ||
        output_parent_stat.st_gid != 0 ||
        (output_parent_stat.st_mode & 07777) != 0700 ||
        same_named_directory(output_parent_path, output_parent_fd) != 0 ||
        ensure_absent_at(output_parent_fd, output_name) != 0 ||
        ensure_absent_at(output_parent_fd, failure_name) != 0 ||
        random_hex(suffix, 4) != 0 ||
        snprintf(success_name, sizeof(success_name), ".%s.%s", output_name,
                 suffix) >= (int)sizeof(success_name) ||
        snprintf(failure_candidate_name, sizeof(failure_candidate_name),
                 ".%s.failure.%s", output_name, suffix) >=
            (int)sizeof(failure_candidate_name) ||
        snprintf(success_host, sizeof(success_host), "%s/%s",
                 output_parent_path, success_name) >= (int)sizeof(success_host) ||
        snprintf(failure_host, sizeof(failure_host), "%s/%s",
                 output_parent_path, failure_candidate_name) >=
            (int)sizeof(failure_host)) {
        goto cleanup;
    }
    inputs.python_fd = open_regular(options.python, true);
    inputs.builder_fd = open_regular(options.builder, false);
    inputs.recipe_fd = open_regular(options.recipe, false);
    inputs.containerfile_fd = open_regular(options.containerfile, false);
    inputs.docker_fd = open_regular(options.docker, true);
    if (inputs.python_fd < 0 || inputs.builder_fd < 0 || inputs.recipe_fd < 0 ||
        inputs.containerfile_fd < 0 || inputs.docker_fd < 0 ||
        same_named_inode(options.python, inputs.python_fd) != 0 ||
        same_named_inode(options.builder, inputs.builder_fd) != 0 ||
        same_named_inode(options.recipe, inputs.recipe_fd) != 0 ||
        same_named_inode(options.containerfile, inputs.containerfile_fd) != 0 ||
        same_named_inode(options.docker, inputs.docker_fd) != 0) {
        goto cleanup;
    }
    success_fd = create_candidate(output_parent_fd, success_name,
                                  options.worker_uid, options.worker_gid);
    failure_fd = create_candidate(output_parent_fd, failure_candidate_name,
                                  options.worker_uid, options.worker_gid);
    if (success_fd < 0 || failure_fd < 0 ||
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0 ||
        pipe2(release_pipe, O_CLOEXEC) != 0) {
        goto cleanup;
    }
    int passcred = 1;
    if (setsockopt(sockets[0], SOL_SOCKET, SO_PASSCRED, &passcred,
                   sizeof(passcred)) != 0 ||
        setsockopt(sockets[1], SOL_SOCKET, SO_PASSCRED, &passcred,
                   sizeof(passcred)) != 0 ||
        getrandom(challenge, sizeof(challenge), GRND_NONBLOCK) !=
            (ssize_t)sizeof(challenge) ||
        read_small_at(AT_FDCWD, "/proc/sys/kernel/random/boot_id", boot_before,
                      sizeof(boot_before)) != 0) {
        goto cleanup;
    }
    child = fork();
    if (child < 0) {
        goto cleanup;
    }
    if (child == 0) {
        close(sockets[0]);
        close(release_pipe[1]);
        child_exec_builder(&options, &inputs, sockets[1], release_pipe[0],
                           success_host, failure_host, getppid());
    }
    close_if_open(&sockets[1]);
    close_if_open(&release_pipe[0]);
    pidfd = (int)syscall(SYS_pidfd_open, child, 0);
    if (pidfd < 0 || proc_starttime(child, &starttime) != 0 ||
        attach_cgroup(options.cgroup_root, child, &cgroup_root_fd, &cgroup_fd,
                      cgroup_name, sizeof(cgroup_name), expected_cgroup,
                      sizeof(expected_cgroup)) != 0 ||
        write(release_pipe[1], "R", 1) != 1) {
        goto cleanup;
    }
    close_if_open(&release_pipe[1]);
    if (receive_frame(sockets[0], child, options.worker_uid, options.worker_gid,
                      &frame) != 0 ||
        validate_hello(&frame) != 0 ||
        exact_worker_status(child, options.worker_uid, options.worker_gid,
                            expected_cgroup, starttime, inputs.python_fd) != 0) {
        close_frame(&frame);
        goto cleanup;
    }
    close_frame(&frame);
    struct tpbs_init init = {
        .header = {
            .magic = TPBS_MAGIC,
            .version = TPBS_VERSION,
            .kind = TPBS_INIT,
            .size = sizeof(struct tpbs_init),
            .flags = 0,
        },
        .descriptor_count = TPBS_INIT_FD_COUNT,
        .worker_pid = (uint32_t)child,
        .worker_uid = (uint32_t)options.worker_uid,
        .worker_gid = (uint32_t)options.worker_gid,
    };
    memcpy(init.challenge, challenge, sizeof(challenge));
    int init_fds[TPBS_INIT_FD_COUNT] = {
        output_parent_fd, success_fd, failure_fd, inputs.builder_fd,
        inputs.recipe_fd, inputs.containerfile_fd,
    };
    if (send_frame(sockets[0], &init, sizeof(init), init_fds,
                   ARRAY_LENGTH(init_fds)) != 0) {
        goto cleanup;
    }
    if (receive_frame(sockets[0], child, options.worker_uid, options.worker_gid,
                      &frame) != 0) {
        goto cleanup;
    }
    const struct tpbs_header *next =
        (const struct tpbs_header *)(const void *)frame.bytes;
    if (next->kind == TPBS_CID_REQUEST) {
        if (create_cid_from_request(&frame, challenge, output_parent_fd,
                                    options.worker_uid, options.worker_gid,
                                    &cid_fd, cid_name, sizeof(cid_name)) != 0) {
            close_frame(&frame);
            goto cleanup;
        }
        const struct tpbs_cid_request *request =
            (const struct tpbs_cid_request *)(const void *)frame.bytes;
        struct tpbs_cid_response response = {
            .header = {
                .magic = TPBS_MAGIC,
                .version = TPBS_VERSION,
                .kind = TPBS_CID_RESPONSE,
                .size = sizeof(struct tpbs_cid_response),
                .flags = 0,
            },
            .descriptor_count = 1,
        };
        memcpy(response.challenge, challenge, sizeof(challenge));
        memcpy(response.attempt, request->attempt, sizeof(response.attempt));
        close_frame(&frame);
        if (send_frame(sockets[0], &response, sizeof(response), &cid_fd, 1) !=
                0 ||
            receive_frame(sockets[0], child, options.worker_uid,
                          options.worker_gid, &frame) != 0) {
            goto cleanup;
        }
        cid_allocated = true;
    }
    if (validate_ready(&frame, challenge, success_fd, failure_fd, &ready) != 0) {
        close_frame(&frame);
        goto cleanup;
    }
    ready_candidate_fd = frame.descriptors[0];
    frame.descriptors[0] = -1;
    frame.descriptor_count = 0;
    close_if_open(&sockets[0]);
    if (wait_exact_child(child, ready.worker_status == 0 ? 0 : 1) != 0) {
        child = -1;
        goto cleanup;
    }
    child = -1;
    if (retire_empty_cgroup(cgroup_root_fd, cgroup_fd, cgroup_name) != 0) {
        goto cleanup;
    }
    close_if_open(&cgroup_fd);
    if (read_small_at(AT_FDCWD, "/proc/sys/kernel/random/boot_id", boot_after,
                      sizeof(boot_after)) != 0 ||
        strcmp(boot_before, boot_after) != 0 ||
        same_named_directory(output_parent_path, output_parent_fd) != 0 ||
        same_named_inode(options.builder, inputs.builder_fd) != 0 ||
        same_named_inode(options.recipe, inputs.recipe_fd) != 0 ||
        same_named_inode(options.containerfile, inputs.containerfile_fd) != 0 ||
        same_named_inode(options.docker, inputs.docker_fd) != 0 ||
        same_named_child(output_parent_fd, success_name, success_fd) != 0 ||
        same_named_child(output_parent_fd, failure_candidate_name, failure_fd) !=
            0 ||
        (cid_allocated &&
         same_named_child(output_parent_fd, cid_name, cid_fd) != 0) ||
        verify_container_absence(&options, &inputs, &ready) != 0 ||
        close_candidate_tree(
            ready.role == TPBS_ROLE_SUCCESS ? failure_fd : success_fd, 0, 0) !=
            0 ||
        (cid_allocated && close_candidate_tree(cid_fd, 0, 0) != 0) ||
        close_candidate_tree(ready_candidate_fd, options.worker_uid,
                             options.worker_gid) != 0 ||
        verify_candidate(&options, &inputs, &ready, ready_candidate_fd,
                         cid_allocated ? cid_fd : -1) != 0 ||
        close_candidate_tree(ready_candidate_fd, 0, 0) != 0) {
        goto cleanup;
    }
    const char *final_name =
        ready.role == TPBS_ROLE_SUCCESS ? output_name : failure_name;
    const char *candidate_name =
        ready.role == TPBS_ROLE_SUCCESS ? success_name : failure_candidate_name;
    if (rename_candidate(output_parent_fd, candidate_name, final_name,
                         ready_candidate_fd) != 0) {
        goto cleanup;
    }
    printf("{\"decision\":\"PASS_ONE_SHOT_PRIVILEGE_SPLIT_NOT_PRODUCT_ACTIVE\","
           "\"role\":\"%s\"}\n",
           ready.role == TPBS_ROLE_SUCCESS ? "success" : "failure");
    result = ready.role == TPBS_ROLE_SUCCESS ? 0 : 1;

cleanup:
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
    }
    if (cgroup_fd >= 0 && cgroup_name[0] != '\0') {
        if (!cgroup_observed_empty(cgroup_fd) &&
            kill_cgroup_and_wait_empty(cgroup_fd) != 0) {
            result = 2;
        }
        if (cgroup_observed_empty(cgroup_fd) &&
            retire_empty_cgroup(cgroup_root_fd, cgroup_fd, cgroup_name) != 0) {
            result = 2;
        }
    }
    if (cgroup_fd < 0 && cgroup_root_fd >= 0 && cgroup_name[0] != '\0') {
        if (unlinkat(cgroup_root_fd, cgroup_name, AT_REMOVEDIR) == 0) {
            cgroup_name[0] = '\0';
        } else {
            result = 2;
        }
    }
    if (success_fd >= 0) {
        (void)close_candidate_tree(success_fd, 0, 0);
    }
    if (failure_fd >= 0) {
        (void)close_candidate_tree(failure_fd, 0, 0);
    }
    if (cid_fd >= 0) {
        (void)close_candidate_tree(cid_fd, 0, 0);
    }
    close_if_open(&release_pipe[0]);
    close_if_open(&release_pipe[1]);
    close_if_open(&sockets[0]);
    close_if_open(&sockets[1]);
    close_if_open(&ready_candidate_fd);
    close_if_open(&pidfd);
    close_if_open(&cid_fd);
    close_if_open(&success_fd);
    close_if_open(&failure_fd);
    close_if_open(&cgroup_fd);
    if (cgroup_root_fd >= 0 && cgroup_name[0] != '\0') {
        result = 2;
    }
    close_if_open(&cgroup_root_fd);
    close_if_open(&inputs.python_fd);
    close_if_open(&inputs.builder_fd);
    close_if_open(&inputs.recipe_fd);
    close_if_open(&inputs.containerfile_fd);
    close_if_open(&inputs.docker_fd);
    close_if_open(&output_parent_fd);
    return result;
}
