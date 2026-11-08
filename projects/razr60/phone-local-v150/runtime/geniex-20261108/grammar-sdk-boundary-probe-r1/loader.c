// C-only loader: no executable-owned C++ runtime.
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

typedef int (*probe_fn)(int, char**);
int main(int argc, char** argv) {
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core) != 0) return 65;
    alarm(20);
    if (argc < 4 || argc > 5) return 64;
    void* library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "loader: dlopen failed: %s\n", dlerror()); return 70; }
    void* raw = dlsym(library, "grammar_sdk_boundary_probe");
    probe_fn probe = NULL;
    _Static_assert(sizeof(probe) == sizeof(raw), "POSIX function pointer layout");
    memcpy(&probe, &raw, sizeof(probe));
    if (!probe) { fprintf(stderr, "loader: dlsym failed\n"); dlclose(library); return 71; }
    int result = probe(argc - 1, argv + 1);
    fprintf(stderr, "loader: returned %d before dlclose\n", result);
    if (dlclose(library) != 0) return 72;
    fprintf(stderr, "loader: normal dlclose complete\n");
    return result;
}

