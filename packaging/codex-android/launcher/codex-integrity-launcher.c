#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef TRILLIONNIUM_CODEX_RUNTIME_PATH
#define TRILLIONNIUM_CODEX_RUNTIME_PATH                                      \
  "/usr/lib/trillionnium/agents/codex/0.144.1/aarch64-unknown-linux-musl" \
  "/bin/codex.real"
#endif

#ifndef TRILLIONNIUM_SYSTEM_API_TOOL_PATH
#define TRILLIONNIUM_SYSTEM_API_TOOL_PATH \
  "/usr/local/bin/trillionnium-agent-system-api"
#endif

#ifndef TRILLIONNIUM_ACCESSIBILITY_TOOL_PATH
#define TRILLIONNIUM_ACCESSIBILITY_TOOL_PATH \
  "/usr/local/bin/trillionnium-agent-accessibility"
#endif

#ifndef TRILLIONNIUM_CODEX_RUNTIME_SHA256
#error "TRILLIONNIUM_CODEX_RUNTIME_SHA256 must be supplied by the package build"
#endif

#ifndef TRILLIONNIUM_SYSTEM_API_TOOL_SHA256
#error "TRILLIONNIUM_SYSTEM_API_TOOL_SHA256 must be supplied by the package build"
#endif

#ifndef TRILLIONNIUM_ACCESSIBILITY_TOOL_SHA256
#define TRILLIONNIUM_ACCESSIBILITY_TOOL_SHA256 \
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
#endif

#ifndef TRILLIONNIUM_CODEX_REQUIRE_ACCESSIBILITY_TOOL
#define TRILLIONNIUM_CODEX_REQUIRE_ACCESSIBILITY_TOOL 1
#endif

#ifndef TRILLIONNIUM_EXPECTED_OWNER_UID
#define TRILLIONNIUM_EXPECTED_OWNER_UID 0
#endif

#ifndef TRILLIONNIUM_EXPECTED_OWNER_GID
#define TRILLIONNIUM_EXPECTED_OWNER_GID 0
#endif

#ifndef TRILLIONNIUM_CODEX_UID
#define TRILLIONNIUM_CODEX_UID 5901
#endif

#ifndef TRILLIONNIUM_CODEX_GID
#define TRILLIONNIUM_CODEX_GID 5901
#endif

#ifndef TRILLIONNIUM_CODEX_REQUIRE_EMPTY_GROUPS
#define TRILLIONNIUM_CODEX_REQUIRE_EMPTY_GROUPS 1
#endif

#define SHA256_BLOCK_BYTES 64U
#define SHA256_DIGEST_BYTES 32U
#define EXECUTABLE_MODE 0755U
#define EXECUTABLE_FD 3

struct sha256_context {
  uint32_t state[8];
  uint64_t bit_count;
  unsigned char block[SHA256_BLOCK_BYTES];
  size_t block_length;
};

static const uint32_t sha256_constants[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static const int forwarded_signals[] = {
    SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2,
};

static uint32_t rotate_right(uint32_t value, unsigned int count) {
  return (value >> count) | (value << (32U - count));
}

static uint32_t load_u32_be(const unsigned char *bytes) {
  return ((uint32_t)bytes[0] << 24U) | ((uint32_t)bytes[1] << 16U) |
         ((uint32_t)bytes[2] << 8U) | (uint32_t)bytes[3];
}

static void store_u32_be(unsigned char *bytes, uint32_t value) {
  bytes[0] = (unsigned char)(value >> 24U);
  bytes[1] = (unsigned char)(value >> 16U);
  bytes[2] = (unsigned char)(value >> 8U);
  bytes[3] = (unsigned char)value;
}

static void sha256_transform(struct sha256_context *context,
                             const unsigned char block[64]) {
  uint32_t words[64];
  for (size_t index = 0U; index < 16U; index++) {
    words[index] = load_u32_be(block + index * 4U);
  }
  for (size_t index = 16U; index < 64U; index++) {
    uint32_t left = words[index - 15U];
    uint32_t right = words[index - 2U];
    uint32_t sigma0 =
        rotate_right(left, 7U) ^ rotate_right(left, 18U) ^ (left >> 3U);
    uint32_t sigma1 =
        rotate_right(right, 17U) ^ rotate_right(right, 19U) ^ (right >> 10U);
    words[index] =
        words[index - 16U] + sigma0 + words[index - 7U] + sigma1;
  }

  uint32_t a = context->state[0];
  uint32_t b = context->state[1];
  uint32_t c = context->state[2];
  uint32_t d = context->state[3];
  uint32_t e = context->state[4];
  uint32_t f = context->state[5];
  uint32_t g = context->state[6];
  uint32_t h = context->state[7];
  for (size_t index = 0U; index < 64U; index++) {
    uint32_t sum1 =
        rotate_right(e, 6U) ^ rotate_right(e, 11U) ^ rotate_right(e, 25U);
    uint32_t choice = (e & f) ^ ((~e) & g);
    uint32_t temporary1 =
        h + sum1 + choice + sha256_constants[index] + words[index];
    uint32_t sum0 =
        rotate_right(a, 2U) ^ rotate_right(a, 13U) ^ rotate_right(a, 22U);
    uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temporary2 = sum0 + majority;
    h = g;
    g = f;
    f = e;
    e = d + temporary1;
    d = c;
    c = b;
    b = a;
    a = temporary1 + temporary2;
  }
  context->state[0] += a;
  context->state[1] += b;
  context->state[2] += c;
  context->state[3] += d;
  context->state[4] += e;
  context->state[5] += f;
  context->state[6] += g;
  context->state[7] += h;
  memset(words, 0, sizeof(words));
}

static void sha256_init(struct sha256_context *context) {
  static const uint32_t initial[8] = {
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
      0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
  };
  memcpy(context->state, initial, sizeof(initial));
  context->bit_count = 0U;
  context->block_length = 0U;
}

static void sha256_update(struct sha256_context *context,
                          const unsigned char *bytes, size_t length) {
  while (length > 0U) {
    size_t available = SHA256_BLOCK_BYTES - context->block_length;
    size_t copied = length < available ? length : available;
    memcpy(context->block + context->block_length, bytes, copied);
    context->block_length += copied;
    context->bit_count += (uint64_t)copied * 8U;
    bytes += copied;
    length -= copied;
    if (context->block_length == SHA256_BLOCK_BYTES) {
      sha256_transform(context, context->block);
      context->block_length = 0U;
    }
  }
}

static void sha256_final(struct sha256_context *context,
                         unsigned char digest[SHA256_DIGEST_BYTES]) {
  uint64_t bit_count = context->bit_count;
  context->block[context->block_length++] = 0x80U;
  if (context->block_length > 56U) {
    memset(context->block + context->block_length, 0,
           SHA256_BLOCK_BYTES - context->block_length);
    sha256_transform(context, context->block);
    context->block_length = 0U;
  }
  memset(context->block + context->block_length, 0,
         56U - context->block_length);
  for (size_t index = 0U; index < 8U; index++) {
    context->block[63U - index] =
        (unsigned char)(bit_count >> (index * 8U));
  }
  sha256_transform(context, context->block);
  for (size_t index = 0U; index < 8U; index++) {
    store_u32_be(digest + index * 4U, context->state[index]);
  }
  memset(context, 0, sizeof(*context));
}

static int decode_digest(const char *hex,
                         unsigned char digest[SHA256_DIGEST_BYTES]) {
  if (hex == NULL || strlen(hex) != SHA256_DIGEST_BYTES * 2U) {
    return -1;
  }
  for (size_t index = 0U; index < SHA256_DIGEST_BYTES; index++) {
    unsigned int values[2];
    for (size_t half = 0U; half < 2U; half++) {
      unsigned char value = (unsigned char)hex[index * 2U + half];
      if (value >= '0' && value <= '9') {
        values[half] = (unsigned int)(value - '0');
      } else if (value >= 'a' && value <= 'f') {
        values[half] = (unsigned int)(value - 'a') + 10U;
      } else {
        return -1;
      }
    }
    digest[index] = (unsigned char)((values[0] << 4U) | values[1]);
  }
  return 0;
}

static int hash_fd(int descriptor,
                   unsigned char digest[SHA256_DIGEST_BYTES]) {
  struct sha256_context context;
  unsigned char buffer[64U * 1024U];
  if (lseek(descriptor, 0, SEEK_SET) != 0) {
    return -1;
  }
  sha256_init(&context);
  for (;;) {
    ssize_t count = read(descriptor, buffer, sizeof(buffer));
    if (count > 0) {
      sha256_update(&context, buffer, (size_t)count);
      continue;
    }
    if (count == 0) {
      break;
    }
    if (errno != EINTR) {
      memset(buffer, 0, sizeof(buffer));
      return -1;
    }
  }
  memset(buffer, 0, sizeof(buffer));
  sha256_final(&context, digest);
  return lseek(descriptor, 0, SEEK_SET) == 0 ? 0 : -1;
}

static int same_stat(const struct stat *left, const struct stat *right) {
  return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
         left->st_mode == right->st_mode && left->st_nlink == right->st_nlink &&
         left->st_uid == right->st_uid && left->st_gid == right->st_gid &&
         left->st_size == right->st_size &&
         left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
         left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
         left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
         left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
}

static int open_measured_executable(const char *path, const char *expected,
                                    int retain) {
  struct stat before;
  struct stat after;
  unsigned char actual_digest[SHA256_DIGEST_BYTES];
  unsigned char expected_digest[SHA256_DIGEST_BYTES];
  int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (descriptor < 0 || fstat(descriptor, &before) != 0 ||
      !S_ISREG(before.st_mode) ||
      before.st_uid != (uid_t)TRILLIONNIUM_EXPECTED_OWNER_UID ||
      before.st_gid != (gid_t)TRILLIONNIUM_EXPECTED_OWNER_GID ||
      (before.st_mode & 07777U) != EXECUTABLE_MODE || before.st_nlink != 1 ||
      decode_digest(expected, expected_digest) != 0 ||
      hash_fd(descriptor, actual_digest) != 0 || fstat(descriptor, &after) != 0 ||
      !same_stat(&before, &after) ||
      memcmp(actual_digest, expected_digest, sizeof(actual_digest)) != 0) {
    fprintf(stderr,
            "codex-integrity-launcher: measured executable contract failed: %s\n",
            path);
    memset(actual_digest, 0, sizeof(actual_digest));
    memset(expected_digest, 0, sizeof(expected_digest));
    if (descriptor >= 0) {
      close(descriptor);
    }
    return -1;
  }
  memset(actual_digest, 0, sizeof(actual_digest));
  memset(expected_digest, 0, sizeof(expected_digest));
  if (!retain) {
    return close(descriptor) == 0 ? 0 : -1;
  }
  return descriptor;
}

static int require_process_identity(void) {
  if (getuid() != (uid_t)TRILLIONNIUM_CODEX_UID ||
      geteuid() != (uid_t)TRILLIONNIUM_CODEX_UID ||
      getgid() != (gid_t)TRILLIONNIUM_CODEX_GID ||
      getegid() != (gid_t)TRILLIONNIUM_CODEX_GID) {
    return -1;
  }
#if TRILLIONNIUM_CODEX_REQUIRE_EMPTY_GROUPS
  gid_t group;
  if (getgroups(1, &group) != 0) {
    return -1;
  }
#endif
  return 0;
}

static int reset_runtime_signals(void) {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = SIG_DFL;
  if (sigemptyset(&action.sa_mask) != 0) {
    return -1;
  }
  for (size_t index = 0U;
       index < sizeof(forwarded_signals) / sizeof(forwarded_signals[0]);
       index++) {
    if (sigaction(forwarded_signals[index], &action, NULL) != 0) {
      return -1;
    }
  }
  return 0;
}

static int move_runtime_to_exec_fd(int descriptor) {
  if (descriptor == EXECUTABLE_FD) {
    int flags = fcntl(descriptor, F_GETFD);
    return flags >= 0 && fcntl(descriptor, F_SETFD, flags & ~FD_CLOEXEC) == 0
               ? descriptor
               : -1;
  }
  if (dup3(descriptor, EXECUTABLE_FD, 0) != EXECUTABLE_FD) {
    return -1;
  }
  close(descriptor);
  return EXECUTABLE_FD;
}

static int close_untrusted_descriptors(void) {
#ifdef SYS_close_range
  if (syscall(SYS_close_range, (unsigned int)(EXECUTABLE_FD + 1), ~0U, 0U) ==
      0) {
    return 0;
  }
  if (errno != ENOSYS && errno != EINVAL) {
    return -1;
  }
#endif
  long limit = sysconf(_SC_OPEN_MAX);
  if (limit < 0 || limit > 1048576L) {
    limit = 1048576L;
  }
  for (int descriptor = EXECUTABLE_FD + 1; descriptor < limit; descriptor++) {
    (void)close(descriptor);
  }
  return 0;
}

static int apply_child_hardening(void) {
  struct rlimit no_core = {.rlim_cur = 0, .rlim_max = 0};
  umask(077);
  if (setrlimit(RLIMIT_CORE, &no_core) != 0 ||
      prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 ||
      prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
      prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() == 1) {
    return -1;
  }
  return 0;
}

static int execute_measured_runtime(int descriptor, char *const arguments[]) {
  extern char **environ;
#ifdef SYS_execveat
  return (int)syscall(SYS_execveat, descriptor, "", arguments, environ,
                      AT_EMPTY_PATH);
#else
  (void)descriptor;
  (void)arguments;
  errno = ENOSYS;
  return -1;
#endif
}

int main(int argc, char **argv) {
  int runtime_descriptor = -1;
  char **runtime_arguments = NULL;

  if (argc <= 0 || argv == NULL || require_process_identity() != 0) {
    fprintf(stderr,
            "codex-integrity-launcher: dedicated Codex UID/GID is required\n");
    return 125;
  }
  runtime_descriptor = open_measured_executable(
      TRILLIONNIUM_CODEX_RUNTIME_PATH, TRILLIONNIUM_CODEX_RUNTIME_SHA256, 1);
  if (runtime_descriptor < 0 ||
      open_measured_executable(TRILLIONNIUM_SYSTEM_API_TOOL_PATH,
                               TRILLIONNIUM_SYSTEM_API_TOOL_SHA256, 0) != 0
#if TRILLIONNIUM_CODEX_REQUIRE_ACCESSIBILITY_TOOL
      || open_measured_executable(TRILLIONNIUM_ACCESSIBILITY_TOOL_PATH,
                                  TRILLIONNIUM_ACCESSIBILITY_TOOL_SHA256, 0) != 0
#endif
  ) {
    if (runtime_descriptor >= 0) {
      close(runtime_descriptor);
    }
    return 125;
  }

#ifdef TRILLIONNIUM_INTEGRITY_LAUNCHER_TEST
  if (argc == 2 && strcmp(argv[1], "--verify-only") == 0) {
    close(runtime_descriptor);
    return 0;
  }
#endif

  runtime_arguments = calloc((size_t)argc + 1U, sizeof(*runtime_arguments));
  if (runtime_arguments == NULL) {
    close(runtime_descriptor);
    return 125;
  }
  runtime_arguments[0] = (char *)TRILLIONNIUM_CODEX_RUNTIME_PATH;
  for (int index = 1; index < argc; index++) {
    runtime_arguments[index] = argv[index];
  }

  /*
   * Preserve the supervisor-owned PID/pidfd/session across the launcher to
   * final-runtime transition. A forked wrapper would let the daemon observe
   * and release resources for the launcher while codex.real was still an
   * unverified descendant. The measured descriptor is therefore consumed by
   * a same-PID execveat after hardening; there is no signal-proxy parent.
   */
  runtime_descriptor = move_runtime_to_exec_fd(runtime_descriptor);
  if (runtime_descriptor != EXECUTABLE_FD || reset_runtime_signals() != 0 ||
      apply_child_hardening() != 0 || close_untrusted_descriptors() != 0) {
    free(runtime_arguments);
    if (runtime_descriptor >= 0) {
      close(runtime_descriptor);
    }
    return 125;
  }
  execute_measured_runtime(runtime_descriptor, runtime_arguments);
  fprintf(stderr,
          "codex-integrity-launcher: exact-fd runtime exec failed: %s\n",
          strerror(errno));
  free(runtime_arguments);
  close(runtime_descriptor);
  return 126;
}
