/* Independent GPU-only diagnostic bootstrap; main QAIRT application is unchanged. */
#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include "vendor/geniex.h"
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/fs.h>

static void *probe_plugin_handle;
static int probe_bootstrap(void) {
    const char *dir = getenv("HEPTA_PROBE_NATIVE_LIB_DIR");
    char canonical[PATH_MAX], executable[PATH_MAX], plugin[PATH_MAX];
    if (!dir || !realpath(dir, canonical) || strcmp(canonical, dir)) {
        fputs("HEPTA_APPUID_BOOTSTRAP invalid native library directory\n", stderr); return 78;
    }
    ssize_t n = readlink("/proc/self/exe", executable, sizeof(executable)-1);
    if (n <= 0 || (size_t)n >= sizeof(executable)-1) return 78;
    executable[n] = 0;
    char *last = strrchr(executable, '/');
    if (!last) return 78;
    *last = 0;
    if (strcmp(executable, canonical)) {
        fputs("HEPTA_APPUID_BOOTSTRAP runner is outside installed library directory\n", stderr); return 78;
    }
    if (snprintf(plugin, sizeof(plugin), "%s/libgeniex_plugin_llama_cpp.so", dir) >= (int)sizeof(plugin)) return 78;
    probe_plugin_handle = dlopen(plugin, RTLD_NOW | RTLD_GLOBAL);
    if (!probe_plugin_handle) { fprintf(stderr,"HEPTA_APPUID_BOOTSTRAP dlopen: %s\n",dlerror()); return 78; }
    geniex_plugin_id_func id = (geniex_plugin_id_func)dlsym(probe_plugin_handle, "plugin_id");
    geniex_create_plugin_func create = (geniex_create_plugin_func)dlsym(probe_plugin_handle, "create_plugin");
    if (!id || !create || strcmp(id(), "llama_cpp")) { fputs("HEPTA_APPUID_BOOTSTRAP plugin export identity failed\n",stderr); return 78; }
    int32_t register_rc = geniex_register_plugin(id, create);
    fprintf(stderr,"HEPTA_APPUID_BOOTSTRAP uid=%lu euid=%lu pid=%ld plugin=llama_cpp register_rc=%d runtime=%s\n",
        (unsigned long)getuid(), (unsigned long)geteuid(), (long)getpid(), register_rc, dir);
    fflush(stderr);
    return register_rc == 0 ? 0 : 78;
}

#define main upstream_worker_main
#include "worker-gpu-appuid.c"
#undef main

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--help")) return upstream_worker_main(argc, argv);
    const char *version = geniex_version();
    if (!version || (strcmp(version,"v0.10.0") && strcmp(version,"0.10.0"))) {
        fputs("HEPTA_APPUID_BOOTSTRAP pinned SDK version mismatch\n",stderr); return 78;
    }
    int rc = probe_bootstrap();
    return rc == 0 ? upstream_worker_main(argc, argv) : rc;
}
