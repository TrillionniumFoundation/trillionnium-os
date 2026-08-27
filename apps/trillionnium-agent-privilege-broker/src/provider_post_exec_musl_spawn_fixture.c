#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef TRILLIONNIUM_PROVIDER_FILTER_INSTRUCTION_COUNT
#error "the exact provider filter instruction count must be supplied"
#endif

extern const struct sock_filter trillionnium_provider_filter[];
extern char **environ;

static int direct_tool_child(void) {
  if (prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 1) {
    return 41;
  }
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 ||
      prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0) {
    return 42;
  }
  errno = 0;
  if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != -1 || errno != EPERM) {
    return 43;
  }
  return 0;
}

static int unexpected_child(pid_t pid, int code) {
  if (pid == 0) {
    _exit(code);
  }
  if (pid > 0) {
    int status = 0;
    (void)waitpid(pid, &status, 0);
  }
  return code;
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--direct-tool-child") == 0) {
    return direct_tool_child();
  }
  if (argc != 1) {
    return 2;
  }

  int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
  if (null_fd < 0 || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    return 3;
  }
  struct sock_fprog program = {
      .len = TRILLIONNIUM_PROVIDER_FILTER_INSTRUCTION_COUNT,
      .filter = (struct sock_filter *)trillionnium_provider_filter,
  };
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) {
    return 4;
  }

#ifdef SYS_clone3
  errno = 0;
  if (syscall(SYS_clone3, NULL, 0) != -1 || errno != ENOSYS) {
    return 5;
  }
#endif

  errno = 0;
  pid_t raw_fork = fork();
  if (raw_fork != -1) {
    return unexpected_child(raw_fork, 6);
  }
  if (errno != EPERM) {
    return 7;
  }

#ifdef SYS_vfork
  errno = 0;
  pid_t raw_vfork = (pid_t)syscall(SYS_vfork);
  if (raw_vfork != -1) {
    return unexpected_child(raw_vfork, 8);
  }
  if (errno != EPERM) {
    return 9;
  }
#endif

  errno = 0;
  if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != -1 || errno != EPERM) {
    return 10;
  }
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
    return 11;
  }

  posix_spawn_file_actions_t actions;
  if (posix_spawn_file_actions_init(&actions) != 0) {
    return 12;
  }
  int action_error = 0;
  for (int descriptor = STDIN_FILENO; descriptor <= STDERR_FILENO;
       ++descriptor) {
    if (posix_spawn_file_actions_adddup2(&actions, null_fd, descriptor) != 0) {
      action_error = 1;
    }
  }
  if (action_error) {
    (void)posix_spawn_file_actions_destroy(&actions);
    return 13;
  }

  char *const child_arguments[] = {argv[0], "--direct-tool-child", NULL};
  pid_t child = -1;
  int spawn_error =
      posix_spawnp(&child, argv[0], &actions, NULL, child_arguments, environ);
  int destroy_error = posix_spawn_file_actions_destroy(&actions);
  if (spawn_error != 0 || destroy_error != 0 || child <= 0) {
    return 14;
  }
  int status = 0;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0) {
    return 15;
  }
  return 0;
}
