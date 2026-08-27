#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MARKER_FD 3

/*
 * This translation unit is deliberately only post-CRT provider code. The
 * freestanding hardening core and its mutually exclusive entry adapters live
 * under packaging/provider-post-exec-bootstrap and are linked as separate
 * objects by the host-kernel fixture producer.
 */
static void provider_fixture_constructor(void) __attribute__((constructor));

static void provider_fixture_constructor(void) {
  const uint8_t constructor_code = 0x43;
  if (syscall(SYS_write, MARKER_FD, &constructor_code,
              sizeof(constructor_code)) != (long)sizeof(constructor_code)) {
    _exit(86);
  }
}

int main(void) {
  pthread_t thread;
  void *thread_result = NULL;
  extern void *provider_fixture_thread(void *);
  if (pthread_create(&thread, NULL, provider_fixture_thread, NULL) != 0 ||
      pthread_join(thread, &thread_result) != 0 ||
      thread_result != (void *)(uintptr_t)0x54) {
    return 87;
  }
  errno = 0;
  if (fork() != -1 || errno != EPERM) {
    return 88;
  }
  errno = 0;
  if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != -1 || errno != EPERM) {
    return 89;
  }
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
    return 90;
  }
  char *const arguments[] = {"/trillionnium/fixture/missing-direct-tool", NULL};
  char *const environment[] = {NULL};
  errno = 0;
  if (execve(arguments[0], arguments, environment) != -1 || errno != ENOENT) {
    return 91;
  }
  errno = 0;
  if (execveat(-1, "", arguments, environment, AT_EMPTY_PATH) != -1 ||
      errno != EBADF) {
    return 92;
  }
  const uint8_t user_code = 0x5a;
  if (syscall(SYS_write, MARKER_FD, &user_code, sizeof(user_code)) !=
      (long)sizeof(user_code)) {
    return 93;
  }
  for (;;) {
    pause();
  }
}

void *provider_fixture_thread(void *unused) {
  (void)unused;
  const uint8_t thread_code = 0x54;
  if (syscall(SYS_write, MARKER_FD, &thread_code, sizeof(thread_code)) !=
      (long)sizeof(thread_code)) {
    return NULL;
  }
  return (void *)(uintptr_t)0x54;
}
