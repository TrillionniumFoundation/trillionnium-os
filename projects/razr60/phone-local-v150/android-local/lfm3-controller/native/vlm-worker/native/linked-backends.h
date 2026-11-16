#ifndef HEPTA_VLM_LINKED_BACKENDS_H
#define HEPTA_VLM_LINKED_BACKENDS_H

#include "ggml-backend.h"
#include <cstring>
#include <stdexcept>

namespace hepta_vlm {
struct LinkedBackends {
    ggml_backend_dev_t htp;
    ggml_backend_dev_t vision;
};

inline ggml_backend_dev_t require_registered_device(const char *registry_name,
        const char *device_name, enum ggml_backend_dev_type type) {
    // The pinned GenieX build uses GGML_BACKEND_DL=OFF. Querying its registry
    // initializes the linked backends; their shared objects are not plugins.
    auto registry=ggml_backend_reg_by_name(registry_name);
    if (!registry || !ggml_backend_reg_name(registry)
            || std::strcmp(ggml_backend_reg_name(registry),registry_name))
        throw std::runtime_error("required pinned linked backend registry unavailable");
    auto device=ggml_backend_dev_by_name(device_name);
    if (!device || !ggml_backend_dev_name(device)
            || std::strcmp(ggml_backend_dev_name(device),device_name)
            || ggml_backend_dev_type(device)!=type
            || ggml_backend_dev_backend_reg(device)!=registry)
        throw std::runtime_error("required pinned linked backend device unavailable");
    return device;
}

inline LinkedBackends require_linked_backends() {
    // Require CPU only for the existing scheduler/unsupported-kernel closure.
    // It is never returned as a language-model or vision selection/fallback.
    (void)require_registered_device("CPU","CPU",GGML_BACKEND_DEVICE_TYPE_CPU);
    // The pinned Hexagon API reports type GPU for its physical HTP device.
    auto htp=require_registered_device("HTP","HTP0",GGML_BACKEND_DEVICE_TYPE_GPU);
    auto vision=require_registered_device("OpenCL","GPUOpenCL",GGML_BACKEND_DEVICE_TYPE_GPU);
    return {htp,vision};
}
} // namespace hepta_vlm
#endif
