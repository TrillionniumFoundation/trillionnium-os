#include "linked-backends.h"
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <stdexcept>
extern "C" void fixture_case(int value);
static unsigned checks;
#define CHECK(value) do { ++checks; if(!(value)){std::fprintf(stderr,"FAIL line %d\n",__LINE__);std::exit(1);} }while(0)
int main(int argc,char **argv) {
    CHECK(argc==2);
    void *library=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
    CHECK(library!=nullptr);
    // The linked library is usable but lacks the dynamic-plugin entry point.
    CHECK(dlsym(library,"ggml_backend_reg_by_name")!=nullptr);
    CHECK(dlsym(library,"ggml_backend_init")==nullptr);
    CHECK(dlsym(library,"ggml_backend_load")==nullptr);
    fixture_case(0);
    auto selected=hepta_vlm::require_linked_backends();
    CHECK(selected.htp==ggml_backend_dev_by_name("HTP0"));
    CHECK(selected.vision==ggml_backend_dev_by_name("GPUOpenCL"));
    CHECK(selected.htp!=ggml_backend_dev_by_name("CPU") && selected.vision!=ggml_backend_dev_by_name("CPU"));
    const char *cases[]={"missing_cpu_registry","missing_htp_registry","missing_opencl_registry",
        "missing_cpu_device","missing_htp0","missing_gpuopencl","wrong_htp_registry",
        "wrong_vision_registry","cpu_wrong_type","htp_cpu_fallback","vision_wrong_type",
        "registry_case_alias","device_case_alias"};
    for(int i=1;i<=13;++i) {
        fixture_case(i);bool rejected=false;
        try{(void)hepta_vlm::require_linked_backends();}catch(const std::runtime_error &){rejected=true;}
        if(!rejected)std::fprintf(stderr,"not rejected: %s\n",cases[i-1]);
        CHECK(rejected);
    }
    fixture_case(0);
    auto repeated=hepta_vlm::require_linked_backends();
    CHECK(repeated.htp==selected.htp && repeated.vision==selected.vision);
    CHECK(dlclose(library)==0);
    std::printf("{\"schema\":\"hepta.vlm.linked-backend-host.v1\",\"checks\":%u,\"rejection_cases\":13,\"passed\":true,\"plugin_init_absent\":true,\"phone_contacted\":false,\"model_inference_performed\":false}\n",checks);
}
