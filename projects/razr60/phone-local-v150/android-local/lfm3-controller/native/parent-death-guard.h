#ifndef HEPTA_PARENT_DEATH_GUARD_H
#define HEPTA_PARENT_DEATH_GUARD_H

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

/* The adapter owns this leading option; the frozen upstream parser never sees it. */
static inline int hepta_take_expected_parent(int *argc, char **argv, pid_t *expected) {
    if (!argc || !argv || !expected || *argc < 3 || !argv[1] || !argv[2]
            || strcmp(argv[1], "--expected-parent-pid")) { errno = EINVAL; return -1; }
    const char *number = argv[2];
    if (!*number) { errno = EINVAL; return -1; }
    unsigned long parsed = 0;
    for (const unsigned char *p = (const unsigned char *)number; *p; ++p) {
        if (*p < '0' || *p > '9' || parsed > ((unsigned long)INT_MAX - (*p - '0')) / 10) {
            errno = EINVAL; return -1;
        }
        parsed = parsed * 10 + (*p - '0');
    }
    if (parsed <= 1) { errno = EINVAL; return -1; }
    for (int i = 3; i < *argc; ++i) {
        if (!argv[i] || !strcmp(argv[i], "--expected-parent-pid")) { errno = EINVAL; return -1; }
    }
    *expected = (pid_t)parsed;
    /* Include the original terminating NULL while removing exactly two arguments. */
    memmove(argv + 1, argv + 3, (size_t)(*argc - 2) * sizeof(*argv));
    *argc -= 2;
    return 0;
}

/*
 * Guard before the first explicit SDK/plugin call. Checking both sides of prctl
 * closes the race where the expected parent dies before the signal is armed.
 * This is a termination mechanism, never proof that an old task was cleaned up.
 */
static inline int hepta_arm_parent_death_guard(pid_t expected) {
    if (expected <= 1 || getppid() != expected) { errno = ESRCH; return -1; }
    if (prctl(PR_SET_PDEATHSIG, (unsigned long)SIGKILL, 0UL, 0UL, 0UL) != 0) return -1;
    if (getppid() != expected) { errno = ESRCH; return -1; }
    int signal_number = 0;
    if (prctl(PR_GET_PDEATHSIG, &signal_number, 0UL, 0UL, 0UL) != 0) return -1;
    if (signal_number != SIGKILL) { errno = EIO; return -1; }
    return 0;
}

#endif
