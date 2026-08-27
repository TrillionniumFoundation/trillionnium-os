#include "trillionnium_provider_post_exec_bootstrap.h"

#include <errno.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#ifndef TRILLIONNIUM_EXPECTED_UID
#error "TRILLIONNIUM_EXPECTED_UID must be fixed by the exact payload builder"
#endif
#ifndef TRILLIONNIUM_EXPECTED_GID
#error "TRILLIONNIUM_EXPECTED_GID must be fixed by the exact payload builder"
#endif

#if defined(__x86_64__)
#define TRILLIONNIUM_EXPECTED_AUDIT_ARCH AUDIT_ARCH_X86_64
#define TRILLIONNIUM_X32_SYSCALL_BIT 0x40000000U
#elif defined(__aarch64__)
#define TRILLIONNIUM_EXPECTED_AUDIT_ARCH AUDIT_ARCH_AARCH64
#define TRILLIONNIUM_X32_SYSCALL_BIT 0U
#endif

#ifndef __NR_clone
#define __NR_clone UINT32_MAX
#endif
#ifndef __NR_clone3
#define __NR_clone3 UINT32_MAX
#endif
#ifndef __NR_fork
#define __NR_fork UINT32_MAX
#endif
#ifndef __NR_vfork
#define __NR_vfork UINT32_MAX
#endif
#ifndef __NR_prctl
#define __NR_prctl UINT32_MAX
#endif

#define TRILLIONNIUM_DENY_ERRNO                                              \
  (SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))
#define TRILLIONNIUM_CLONE3_FALLBACK_ERRNO                                  \
  (SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA))
#define TRILLIONNIUM_REQUIRED_PTHREAD_CLONE_FLAGS                            \
  (CLONE_VM | CLONE_SIGHAND | CLONE_THREAD)
#define TRILLIONNIUM_EXACT_MUSL_VFORK_SPAWN_CLONE_FLAGS                     \
  (CLONE_VM | CLONE_VFORK | SIGCHLD)
#define TRILLIONNIUM_FORBIDDEN_PROCESS_CLONE_FLAGS                           \
  (CSIGNAL | CLONE_PIDFD | CLONE_PTRACE | CLONE_VFORK | CLONE_PARENT |      \
   CLONE_NEWNS | CLONE_DETACHED | CLONE_UNTRACED | CLONE_NEWCGROUP |        \
   CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID |             \
   CLONE_NEWNET)

#define TRILLIONNIUM_DENY_SYSCALL(number)                                   \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)(number), 0, 1),            \
      BPF_STMT(BPF_RET | BPF_K, TRILLIONNIUM_DENY_ERRNO)

/*
 * The named section is consumed by the bounded final-ELF gate. Its 37
 * instructions must remain byte-for-byte equivalent to the Rust expectation.
 * execve/execveat are intentionally not denied here: SELinux exact entrypoint
 * transitions plus retained broker/cgroup custody constrain direct-tool exec
 * and the one exact musl vfork/posix_spawn-compatible child shape. Seccomp
 * cannot authenticate that clone's callsite or count.
 */
__attribute__((used, visibility("hidden"),
               section(".trillionnium.provider_filter")))
const struct sock_filter trillionnium_provider_filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (uint32_t)offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
             TRILLIONNIUM_EXPECTED_AUDIT_ARCH, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (uint32_t)offsetof(struct seccomp_data, nr)),
    BPF_STMT(BPF_ALU | BPF_AND | BPF_K, TRILLIONNIUM_X32_SYSCALL_BIT),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (uint32_t)offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)__NR_clone3, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, TRILLIONNIUM_CLONE3_FALLBACK_ERRNO),
    TRILLIONNIUM_DENY_SYSCALL(__NR_fork),
    TRILLIONNIUM_DENY_SYSCALL(__NR_vfork),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)__NR_prctl, 0, 7),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (uint32_t)offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_DUMPABLE, 0, 5),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (uint32_t)offsetof(struct seccomp_data, args[1]) + 4U),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (uint32_t)offsetof(struct seccomp_data, args[1])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, TRILLIONNIUM_DENY_ERRNO),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (uint32_t)offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)__NR_clone, 0, 12),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (uint32_t)offsetof(struct seccomp_data, args[0]) + 4U),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, TRILLIONNIUM_DENY_ERRNO),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (uint32_t)offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
             TRILLIONNIUM_EXACT_MUSL_VFORK_SPAWN_CLONE_FLAGS, 7, 0),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (uint32_t)offsetof(struct seccomp_data, args[0])),
    BPF_STMT(BPF_ALU | BPF_AND | BPF_K,
             TRILLIONNIUM_REQUIRED_PTHREAD_CLONE_FLAGS),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
             TRILLIONNIUM_REQUIRED_PTHREAD_CLONE_FLAGS, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (uint32_t)offsetof(struct seccomp_data, args[0])),
    BPF_STMT(BPF_ALU | BPF_AND | BPF_K,
             TRILLIONNIUM_FORBIDDEN_PROCESS_CLONE_FLAGS),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, TRILLIONNIUM_DENY_ERRNO),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

__attribute__((visibility("hidden"))) long
trillionnium_provider_bootstrap_raw_syscall6(long number, long argument_zero,
                                             long argument_one,
                                             long argument_two,
                                             long argument_three,
                                             long argument_four,
                                             long argument_five) {
#if defined(__x86_64__)
  register long accumulator __asm__("rax") = number;
  register long fourth __asm__("r10") = argument_three;
  register long fifth __asm__("r8") = argument_four;
  register long sixth __asm__("r9") = argument_five;
  __asm__ volatile("syscall"
                   : "+a"(accumulator)
                   : "D"(argument_zero), "S"(argument_one), "d"(argument_two),
                     "r"(fourth), "r"(fifth), "r"(sixth)
                   : "rcx", "r11", "memory", "cc");
  return accumulator;
#elif defined(__aarch64__)
  register long x0 __asm__("x0") = argument_zero;
  register long x1 __asm__("x1") = argument_one;
  register long x2 __asm__("x2") = argument_two;
  register long x3 __asm__("x3") = argument_three;
  register long x4 __asm__("x4") = argument_four;
  register long x5 __asm__("x5") = argument_five;
  register long x8 __asm__("x8") = number;
  __asm__ volatile("svc 0"
                   : "+r"(x0)
                   : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                   : "memory", "cc");
  return x0;
#endif
}

#define TRILLIONNIUM_RAW_SYSCALL0(number)                                   \
  trillionnium_provider_bootstrap_raw_syscall6((number), 0, 0, 0, 0, 0, 0)
#define TRILLIONNIUM_RAW_SYSCALL1(number, a0)                               \
  trillionnium_provider_bootstrap_raw_syscall6((number), (long)(a0), 0, 0,  \
                                                0, 0, 0)
#define TRILLIONNIUM_RAW_SYSCALL2(number, a0, a1)                           \
  trillionnium_provider_bootstrap_raw_syscall6(                            \
      (number), (long)(a0), (long)(a1), 0, 0, 0, 0)
#define TRILLIONNIUM_RAW_SYSCALL3(number, a0, a1, a2)                       \
  trillionnium_provider_bootstrap_raw_syscall6(                            \
      (number), (long)(a0), (long)(a1), (long)(a2), 0, 0, 0)
#define TRILLIONNIUM_RAW_SYSCALL5(number, a0, a1, a2, a3, a4)               \
  trillionnium_provider_bootstrap_raw_syscall6(                            \
      (number), (long)(a0), (long)(a1), (long)(a2), (long)(a3), (long)(a4), \
      0)

#ifndef TRILLIONNIUM_BOOTSTRAP_BEFORE_HARDENING
#define TRILLIONNIUM_BOOTSTRAP_BEFORE_HARDENING() ((void)0)
#endif
#ifndef TRILLIONNIUM_BOOTSTRAP_SET_DUMPABLE_ZERO
#define TRILLIONNIUM_BOOTSTRAP_SET_DUMPABLE_ZERO()                          \
  TRILLIONNIUM_RAW_SYSCALL5(SYS_prctl, PR_SET_DUMPABLE, 0, 0, 0, 0)
#endif
#ifndef TRILLIONNIUM_BOOTSTRAP_FILTER_POINTER
#define TRILLIONNIUM_BOOTSTRAP_FILTER_POINTER trillionnium_provider_filter
#endif
#ifndef TRILLIONNIUM_BOOTSTRAP_FILTER_LENGTH
#define TRILLIONNIUM_BOOTSTRAP_FILTER_LENGTH                                \
  (sizeof(trillionnium_provider_filter) /                                  \
   sizeof(trillionnium_provider_filter[0]))
#endif
#ifndef TRILLIONNIUM_BOOTSTRAP_BEFORE_FILTER
#define TRILLIONNIUM_BOOTSTRAP_BEFORE_FILTER() ((void)0)
#endif
#ifndef TRILLIONNIUM_BOOTSTRAP_STOP
#define TRILLIONNIUM_BOOTSTRAP_STOP(pid, tid)                               \
  TRILLIONNIUM_RAW_SYSCALL3(SYS_tgkill, (pid), (tid), SIGSTOP)
#endif

static __attribute__((noreturn)) void fail_closed(void) {
  for (;;) {
    (void)TRILLIONNIUM_RAW_SYSCALL1(SYS_exit_group, 127);
    long pid = TRILLIONNIUM_RAW_SYSCALL0(SYS_getpid);
    long tid = TRILLIONNIUM_RAW_SYSCALL0(SYS_gettid);
    if (pid > 1 && tid > 1) {
      (void)TRILLIONNIUM_RAW_SYSCALL3(SYS_tgkill, pid, tid, SIGKILL);
    }
#if defined(__x86_64__)
    __asm__ volatile("ud2" ::: "memory");
#elif defined(__aarch64__)
    __asm__ volatile("brk #0" ::: "memory");
#endif
  }
}

static int capabilities_are_empty(void) {
  struct __user_cap_header_struct header;
  struct __user_cap_data_struct data[2];
  header.version = _LINUX_CAPABILITY_VERSION_3;
  header.pid = 0;
  for (size_t index = 0; index < 2; ++index) {
    data[index].effective = 0;
    data[index].permitted = 0;
    data[index].inheritable = 0;
  }
  if (TRILLIONNIUM_RAW_SYSCALL2(SYS_capget, (uintptr_t)&header,
                                (uintptr_t)data) != 0) {
    return 0;
  }
  for (size_t index = 0; index < 2; ++index) {
    if (data[index].effective != 0 || data[index].permitted != 0 ||
        data[index].inheritable != 0) {
      return 0;
    }
  }
  for (int capability = 0; capability < 64; ++capability) {
    long present = TRILLIONNIUM_RAW_SYSCALL5(
        SYS_prctl, PR_CAPBSET_READ, capability, 0, 0, 0);
    if (present > 0 || (present < 0 && present != -EINVAL)) {
      return 0;
    }
  }
  for (int capability = 0; capability < 64; ++capability) {
    long present = TRILLIONNIUM_RAW_SYSCALL5(
        SYS_prctl, PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, capability, 0, 0);
    if (present > 0 || (present < 0 && present != -EINVAL)) {
      return 0;
    }
  }
  return 1;
}

static int credentials_are_exact(void) {
  uint32_t real_uid = UINT32_MAX;
  uint32_t effective_uid = UINT32_MAX;
  uint32_t saved_uid = UINT32_MAX;
  uint32_t real_gid = UINT32_MAX;
  uint32_t effective_gid = UINT32_MAX;
  uint32_t saved_gid = UINT32_MAX;
  if (TRILLIONNIUM_RAW_SYSCALL3(SYS_getresuid, (uintptr_t)&real_uid,
                                (uintptr_t)&effective_uid,
                                (uintptr_t)&saved_uid) != 0 ||
      TRILLIONNIUM_RAW_SYSCALL3(SYS_getresgid, (uintptr_t)&real_gid,
                                (uintptr_t)&effective_gid,
                                (uintptr_t)&saved_gid) != 0 ||
      real_uid != TRILLIONNIUM_EXPECTED_UID ||
      effective_uid != TRILLIONNIUM_EXPECTED_UID ||
      saved_uid != TRILLIONNIUM_EXPECTED_UID ||
      real_gid != TRILLIONNIUM_EXPECTED_GID ||
      effective_gid != TRILLIONNIUM_EXPECTED_GID ||
      saved_gid != TRILLIONNIUM_EXPECTED_GID ||
      TRILLIONNIUM_RAW_SYSCALL1(SYS_setfsuid, UINT32_MAX) !=
          TRILLIONNIUM_EXPECTED_UID ||
      TRILLIONNIUM_RAW_SYSCALL1(SYS_setfsgid, UINT32_MAX) !=
          TRILLIONNIUM_EXPECTED_GID) {
    return 0;
  }
  return 1;
}

static void install_exact_filter(void) {
  struct sock_fprog program;
  program.len = (unsigned short)TRILLIONNIUM_BOOTSTRAP_FILTER_LENGTH;
  program.filter = (struct sock_filter *)TRILLIONNIUM_BOOTSTRAP_FILTER_POINTER;
  if (TRILLIONNIUM_RAW_SYSCALL5(SYS_prctl, PR_SET_SECCOMP,
                                SECCOMP_MODE_FILTER, (uintptr_t)&program, 0,
                                0) != 0) {
    fail_closed();
  }
}

void trillionnium_provider_post_final_exec_bootstrap(void) {
  TRILLIONNIUM_BOOTSTRAP_BEFORE_HARDENING();
  if (TRILLIONNIUM_BOOTSTRAP_SET_DUMPABLE_ZERO() != 0 ||
      TRILLIONNIUM_RAW_SYSCALL5(SYS_prctl, PR_GET_DUMPABLE, 0, 0, 0, 0) != 0 ||
      TRILLIONNIUM_RAW_SYSCALL5(SYS_prctl, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) !=
          1 ||
      TRILLIONNIUM_RAW_SYSCALL0(SYS_getuid) != TRILLIONNIUM_EXPECTED_UID ||
      TRILLIONNIUM_RAW_SYSCALL0(SYS_geteuid) != TRILLIONNIUM_EXPECTED_UID ||
      TRILLIONNIUM_RAW_SYSCALL0(SYS_getgid) != TRILLIONNIUM_EXPECTED_GID ||
      TRILLIONNIUM_RAW_SYSCALL0(SYS_getegid) != TRILLIONNIUM_EXPECTED_GID ||
      TRILLIONNIUM_RAW_SYSCALL2(SYS_getgroups, 0, 0) != 0 ||
      !credentials_are_exact() || !capabilities_are_empty()) {
    fail_closed();
  }

  TRILLIONNIUM_BOOTSTRAP_BEFORE_FILTER();
  install_exact_filter();
  if (TRILLIONNIUM_RAW_SYSCALL5(SYS_prctl, PR_GET_SECCOMP, 0, 0, 0, 0) !=
      SECCOMP_MODE_FILTER) {
    fail_closed();
  }
  long pid = TRILLIONNIUM_RAW_SYSCALL0(SYS_getpid);
  long tid = TRILLIONNIUM_RAW_SYSCALL0(SYS_gettid);
  if (pid <= 1 || tid <= 1 || TRILLIONNIUM_BOOTSTRAP_STOP(pid, tid) != 0) {
    fail_closed();
  }
}
