/* Fixed LFM3 app adapter. Upstream worker and exact GenieX 0.10.0 ABI stay vendored. */
#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include "vendor/geniex.h"
#include "vendor/llama/llama.h"
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/fs.h>
#include "prompt-budget.h"
#include "model-profile.h"
#include "parent-death-guard.h"

static void *probe_plugin_handle;
static int probe_bootstrap(void) {
    const char *dir = getenv("HEPTA_LOCAL_NATIVE_LIB_DIR");
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
    // The plugin constructor registers GGML backends immediately and rewrites
    // ADSP_LIBRARY_PATH from GENIEX_PLUGIN_PATH. Set it before create_plugin.
    if (setenv("GENIEX_PLUGIN_PATH", dir, 1) != 0) return 78;
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
#include "worker-appuid.c"
#undef main
#include "warm-protocol.inc"
#include "owned-generation.inc"

int main(int argc, char **argv) {
    if(argc>1&&!strcmp(argv[1],"--hepta-owned-generation-cleanup-v1"))
        return hepta_owned_generation_cleanup(argc,argv);
    if (argc == 2 && !strcmp(argv[1], "--help")) return upstream_worker_main(argc, argv);
    if(hepta_take_warm_arguments(&argc,argv)!=0)return 78;
    pid_t expected_parent = 0;
    if(hepta_take_model_profile(&argc,argv)!=0){
        fputs("HEPTA_MODEL_PROFILE missing, duplicated or unknown pinned profile\n",stderr);return 78;
    }
    if(hepta_model_profile->exact_tokens)hepta_prompt_budget=(HeptaPromptBudget){.exact=true,.model_sha256=hepta_model_profile->sha256};
    if (hepta_take_expected_parent(&argc, argv, &expected_parent) != 0) {
        fputs("HEPTA_PARENT_GUARD missing or invalid expected parent PID\n", stderr); return 78;
    }
    if (hepta_arm_parent_death_guard(expected_parent) != 0) {
        fprintf(stderr, "HEPTA_PARENT_GUARD refused expected=%ld observed=%ld errno=%d\n",
                (long)expected_parent, (long)getppid(), errno); return 78;
    }
    fprintf(stderr, "HEPTA_PARENT_GUARD armed expected=%ld observed=%ld signal=SIGKILL\n",
            (long)expected_parent, (long)getppid());
    fflush(stderr);
    if(!hepta_owned_generation_enter(hepta_warm_enabled?hepta_warm_session_dir:NULL,
            hepta_warm_enabled?hepta_warm_generation:NULL,
            hepta_warm_enabled?hepta_warm_task_id:NULL,expected_parent)){
        fputs("HEPTA_OWNED_GENERATION early identity unavailable; SDK not entered\n",stderr);return 78;
    }
    const char *version = geniex_version();
    if (!version || (strcmp(version,"v0.10.0") && strcmp(version,"0.10.0"))) {
        fputs("HEPTA_APPUID_BOOTSTRAP pinned SDK version mismatch\n",stderr); return 78;
    }
    if(!hepta_warm_prepare_control())return 78;
    int rc = probe_bootstrap();
    return rc == 0 ? (hepta_warm_enabled?hepta_warm_loop(argc,argv):upstream_worker_main(argc, argv)) : rc;
}
