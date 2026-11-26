#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include "guard-io.h"
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/fs.h>
#include "sha256-dispatch.h"
#include "parent-death-guard.h"
#include "private-io.inc"
// Exact production containment code, compiled as C with its established ABI.
#include "owned-generation.inc"

int hv_read(HeptaInput *in, const char *path, size_t limit, int text) {
    return read_input(in, path, limit, text != 0);
}
int hv_unchanged(const HeptaInput *in) { return input_unchanged(in); }
void hv_free(HeptaInput *in) { input_free(in); in->fd = -1; in->bytes = NULL; }
void hv_hash(const void *data, size_t size, char out[65]) { hash_bytes(data, size, out); }
int hv_id(const char *value) { return id_ok(value); }
int hv_utf8(const unsigned char *p, size_t n) { return utf8(p,n); }
uint64_t hv_now(void) { return hg_now(); }
int hv_arm_parent(pid_t parent) { return hepta_arm_parent_death_guard(parent) == 0; }
int hv_publish(const char *path, const char *nonce, const void *data, size_t size) {
    if (!id_ok(nonce)) return 0;
    return hg_publish_bytes(path, nonce, data, size);
}
int hv_private_directory(const char *path, struct stat *out) {
    return private_directory_stat(path,out);
}
/* Only the fixed runtime_pins loop uses private_model==0. Request::parse
 * already binds that directory to the installed worker's canonical /proc/self/exe
 * parent. Installed system-owned runtime files can have multiple directory
 * links (d125 observed three). Their complete size/SHA and held-FD /
 * named-path identity must still remain unchanged for this request.
 * App-owned models keep the original single-link / UID / 0600 policy. */
static bool pin_metadata_allowed(const struct stat *st, uint64_t bytes, int private_model) {
    if (!S_ISREG(st->st_mode) || st->st_nlink == 0 || st->st_size <= 0
        || (uint64_t)st->st_size != bytes) return false;
    if (private_model == 1) return st->st_nlink == 1 && st->st_uid == getuid()
        && (st->st_mode & 0777) == 0600;
    if (private_model != 0) return false;
    return st->st_uid == 1000 && st->st_gid == 1000
        && !(st->st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID));
}
int hv_pin(HeptaInput *in, const char *path, uint64_t bytes, const char *sha,
           int private_model, int (*fence)(void *), void *data) {
    in->fd = -1; in->path = path; in->bytes = NULL;
    if (!sha || strlen(sha) != 64) return 0;
    in->fd = open_canonical(path,O_RDONLY);
    if (in->fd < 0 || fstat(in->fd,&in->before) != 0
        || !pin_metadata_allowed(&in->before,bytes,private_model)) return 0;
    in->size = (size_t)bytes;
    Sha256 hash; sha_init(&hash);
    unsigned char *buffer = malloc(1024*1024);
    if (!buffer) return 0;
    uint64_t total = 0; int ok = 1;
    while (total < bytes) {
        if (fence && !fence(data)) { ok = 0; break; }
        ssize_t got = read(in->fd,buffer,1024*1024);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { ok = 0; break; }
        sha_update(&hash,buffer,(size_t)got); total += (uint64_t)got;
    }
    free(buffer);
    if (!ok || total != bytes) return 0;
    unsigned char extra; ssize_t got;
    do { got = read(in->fd,&extra,1); } while (got < 0 && errno == EINTR);
    if (got != 0 || !input_unchanged(in)) return 0;
    sha_finish(&hash,in->digest);
    fprintf(stderr,"HEPTA_VLM_PIN bytes=%llu sha=%s hash_backend=%s\n",
            (unsigned long long)bytes,in->digest,hepta_sha256_backend(&hash));
    return !strcmp(in->digest,sha);
}
int hv_parent(pid_t parent, uid_t uid) {
    if (uid < 10000 || getuid() != uid || geteuid() != uid || getppid() != parent) return 0;
    HgIdentity id = {.uid=(unsigned long)uid, .app_pid=(long)parent};
    const char *start = getenv(hg_env_keys[4]), *boot = getenv(hg_env_keys[5]);
    if (!hg_decimal(start,UINT64_MAX,&id.app_start) || !id.app_start || !hg_uuid(boot)) return 0;
    strcpy(id.boot,boot);
    if (!hg_caller(&id)) return 0;
    HgProcess p;
    if (hg_open_process(parent,&p) != 0) return 0;
    unsigned char cmd[4097]; size_t size = 0;
    int ok = hg_read_at(p.fd,"cmdline",cmd,sizeof(cmd)-1,&size) == 0;
    if (close(p.fd) != 0) ok = 0;
    const char package[] = "org.trillionnium.hepta.local";
    if (!ok || size < sizeof(package) || memcmp(cmd,package,sizeof(package)-1)) return 0;
    for (size_t i=sizeof(package)-1; i<size; ++i) if (cmd[i]) return 0;
    return hg_caller(&id);
}
int hv_scope_enter(const char *directory, const char *generation, const char *task, pid_t parent) {
    // Historical fixture exception is not accepted by this ordinary-task entry.
    for (unsigned i=0; i<6; ++i) if (!getenv(hg_env_keys[i])) return 0;
    if (!id_ok(generation) || !id_ok(task)) return 0;
    return hepta_owned_generation_enter(directory,generation,task,parent);
}
int hv_scope_cleanup(int argc, char **argv) { return hepta_owned_generation_cleanup(argc,argv); }
