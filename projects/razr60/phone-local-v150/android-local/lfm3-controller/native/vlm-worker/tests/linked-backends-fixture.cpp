// Host fixture of the linked-registry API, not an Android SDK substitute.
#include "ggml-backend.h"
#include <cstring>
struct ggml_backend_reg { int index; };
struct ggml_backend_device { int index; };
static ggml_backend_reg registries[]={{0},{1},{2}};
static ggml_backend_device devices[]={{0},{1},{2}};
static int scenario;
static const char *registry_names[]={"CPU","HTP","OpenCL"};
static const char *device_names[]={"CPU","HTP0","GPUOpenCL"};
extern "C" void fixture_case(int value) { scenario=value; }
extern "C" ggml_backend_reg_t ggml_backend_reg_by_name(const char *name) {
    for(int i=0;i<3;++i) if(!std::strcmp(name,registry_names[i]))
        return scenario==i+1 ? nullptr : &registries[i];
    return nullptr;
}
extern "C" const char *ggml_backend_reg_name(ggml_backend_reg_t registry) {
    if(scenario==12 && registry->index==1)return "htp";
    return registry_names[registry->index];
}
extern "C" ggml_backend_dev_t ggml_backend_dev_by_name(const char *name) {
    for(int i=0;i<3;++i) if(!std::strcmp(name,device_names[i]))
        return scenario==i+4 ? nullptr : &devices[i];
    return nullptr;
}
extern "C" const char *ggml_backend_dev_name(ggml_backend_dev_t device) {
    if(scenario==13 && device->index==2)return "gpuopencl";
    return device_names[device->index];
}
extern "C" enum ggml_backend_dev_type ggml_backend_dev_type(ggml_backend_dev_t device) {
    if(scenario==9 && device->index==0)return GGML_BACKEND_DEVICE_TYPE_GPU;
    if(scenario==10 && device->index==1)return GGML_BACKEND_DEVICE_TYPE_CPU;
    if(scenario==11 && device->index==2)return GGML_BACKEND_DEVICE_TYPE_IGPU;
    return device->index==0 ? GGML_BACKEND_DEVICE_TYPE_CPU : GGML_BACKEND_DEVICE_TYPE_GPU;
}
extern "C" ggml_backend_reg_t ggml_backend_dev_backend_reg(ggml_backend_dev_t device) {
    if(scenario==7 && device->index==1)return &registries[2];
    if(scenario==8 && device->index==2)return &registries[1];
    return &registries[device->index];
}
// No ggml_backend_init, ggml_backend_load, registration or fallback symbols.
