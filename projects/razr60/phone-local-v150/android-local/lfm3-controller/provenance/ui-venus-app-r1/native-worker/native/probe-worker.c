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


#define main venus_worker_main
#include "worker-venus.c"
#undef main
#include "app-entry-guard.h"
int main(int argc,char **argv){
    if(argc==2&&!strcmp(argv[1],"--help"))return venus_worker_main(argc,argv);
    pid_t expected=0;
    VenusAppEntry entry={0};
    if(hepta_take_expected_parent(&argc,argv,&expected)!=0||
       !venus_app_take_arguments(&argc,argv,&entry)||
       !venus_app_uid_matches(&entry)||hepta_arm_parent_death_guard(expected)!=0){
        fputs("HEPTA_UI_VENUS parent death guard failed\n",stderr);return 78;
    }
    entry.expected_parent=expected;
    Options options;
    if(!parse(argc,argv,&options)||!venus_app_check_parent(&entry,false)||
       !venus_app_bind_scope(&entry,&options)){
        fputs("HEPTA_UI_VENUS_APP direct App parent or private request scope invalid\n",stderr);return 78;
    }
    fprintf(stderr,"HEPTA_UI_VENUS_APP parent=%ld uid=%lu euid=%lu pid=%ld private_scope=verified\n",
            (long)getppid(),(unsigned long)getuid(),(unsigned long)geteuid(),(long)getpid());
    const char *version=geniex_version();
    if(!version||(strcmp(version,"0.10.0")&&strcmp(version,"v0.10.0")))return 78;
    int rc=probe_bootstrap();
    if(rc)return rc;
    entry.same_directory_bootstrap_verified=true;
    int core_rc=venus_worker_main(argc,argv);
    bool parent_after=venus_app_check_parent(&entry,true);
    bool scope_after=venus_app_scope_unchanged(&entry);
    rc=parent_after&&scope_after?core_rc:78;
    if(!venus_app_publish_binding(&entry,&options,core_rc,rc,parent_after,scope_after))return 74;
    return rc;
}
