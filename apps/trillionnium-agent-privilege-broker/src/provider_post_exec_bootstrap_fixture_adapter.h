#ifndef TRILLIONNIUM_PROVIDER_POST_EXEC_BOOTSTRAP_FIXTURE_ADAPTER_H
#define TRILLIONNIUM_PROVIDER_POST_EXEC_BOOTSTRAP_FIXTURE_ADAPTER_H

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>

#define TRILLIONNIUM_FIXTURE_MARKER_FD 3

__attribute__((visibility("hidden"))) long
trillionnium_provider_bootstrap_raw_syscall6(long number, long argument_zero,
                                             long argument_one,
                                             long argument_two,
                                             long argument_three,
                                             long argument_four,
                                             long argument_five);

static __attribute__((unused)) void fixture_raw_marker(uint8_t marker) {
  (void)trillionnium_provider_bootstrap_raw_syscall6(
      SYS_write, TRILLIONNIUM_FIXTURE_MARKER_FD, (long)(uintptr_t)&marker,
      sizeof(marker), 0, 0, 0);
}

#ifdef FAULT_EARLY_MARKER
#define TRILLIONNIUM_BOOTSTRAP_BEFORE_HARDENING() fixture_raw_marker(0xe1)
#endif

#ifdef FAULT_NO_DUMPABLE
#define TRILLIONNIUM_BOOTSTRAP_SET_DUMPABLE_ZERO() 0L
#endif

#ifdef FAULT_WRONG_FILTER
__attribute__((used)) static const struct sock_filter
    trillionnium_fixture_wrong_filter[] = {
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
#define TRILLIONNIUM_BOOTSTRAP_FILTER_POINTER                             \
  trillionnium_fixture_wrong_filter
#define TRILLIONNIUM_BOOTSTRAP_FILTER_LENGTH 1U
#endif

#ifdef FAULT_SECOND_EXEC
static __attribute__((noreturn)) void fixture_second_exec(void) {
  static char executable[] = "/proc/self/exe";
  static char argument[] = "fault-second-exec";
  char *arguments[] = {executable, argument, (char *)0};
  char *environment[] = {(char *)0};
  (void)trillionnium_provider_bootstrap_raw_syscall6(
      SYS_execve, (long)(uintptr_t)executable, (long)(uintptr_t)arguments,
      (long)(uintptr_t)environment, 0, 0, 0);
  (void)trillionnium_provider_bootstrap_raw_syscall6(SYS_exit_group, 126, 0, 0,
                                                     0, 0, 0);
  __builtin_unreachable();
}
#define TRILLIONNIUM_BOOTSTRAP_BEFORE_FILTER() fixture_second_exec()
#endif

#ifdef FAULT_WRONG_SIGNAL
#define TRILLIONNIUM_BOOTSTRAP_STOP(pid, tid)                              \
  trillionnium_provider_bootstrap_raw_syscall6(SYS_kill, (pid), SIGSTOP, 0, \
                                                0, 0, 0)
#endif

#endif
