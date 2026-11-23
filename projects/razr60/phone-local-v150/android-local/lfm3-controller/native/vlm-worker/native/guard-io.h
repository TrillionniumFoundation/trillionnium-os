#ifndef HEPTA_VLM_GUARD_IO_H
#define HEPTA_VLM_GUARD_IO_H
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct { const char *path; int fd; struct stat before; unsigned char *bytes; size_t size; char digest[65]; } HeptaInput;
int hv_read(HeptaInput *, const char *, size_t, int);
int hv_pin(HeptaInput *, const char *, uint64_t, const char *, int, int (*)(void *), void *);
int hv_unchanged(const HeptaInput *);
void hv_free(HeptaInput *);
void hv_hash(const void *, size_t, char out[65]);
int hv_publish(const char *, const char *, const void *, size_t);
int hv_private_directory(const char *, struct stat *);
int hv_parent(pid_t, uid_t);
int hv_scope_enter(const char *, const char *, const char *, pid_t);
int hv_scope_cleanup(int, char **);
int hv_arm_parent(pid_t);
int hv_id(const char *);
int hv_utf8(const unsigned char *, size_t);
uint64_t hv_now(void);
#ifdef __cplusplus
}
#endif
#endif
