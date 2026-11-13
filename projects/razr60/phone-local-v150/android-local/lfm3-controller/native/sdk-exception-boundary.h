/* App-owned C ABI exception boundary; the vendored GenieX ABI is unchanged. */
#ifndef HEPTA_SDK_EXCEPTION_BOUNDARY_H
#define HEPTA_SDK_EXCEPTION_BOUNDARY_H
#include "vendor/geniex.h"
typedef struct {
    int kind; /* 0 none, 1 std::exception, 2 other C++ exception */
    int message_truncated;
    int message_non_ascii_replaced;
    char message[512];
} HeptaSdkGenerateException;
#if defined(HEPTA_SDK_EXCEPTION_BOUNDARY)
#if HEPTA_SDK_EXCEPTION_BOUNDARY != 1
#error "The SDK exception boundary must be explicitly enabled with value 1"
#endif
#define HEPTA_SDK_EXCEPTION_BOUNDARY_ENABLED 1
#ifdef __cplusplus
extern "C" {
#endif
int32_t hepta_guarded_llm_generate(geniex_LLM *,const geniex_LlmGenerateInput *,geniex_LlmGenerateOutput *);
const HeptaSdkGenerateException *hepta_sdk_generate_exception(void);
#ifdef __cplusplus
}
#endif
#else
/* Existing pure-C host harnesses deliberately exercise the historical SDK
 * return-code path. Android builds require the C++ boundary and verify the
 * actual C object's unresolved call before linking. */
#define HEPTA_SDK_EXCEPTION_BOUNDARY_ENABLED 0
static int32_t hepta_guarded_llm_generate(geniex_LLM *h,const geniex_LlmGenerateInput *i,geniex_LlmGenerateOutput *o) {
    return geniex_llm_generate(h,i,o);
}
static const HeptaSdkGenerateException *hepta_sdk_generate_exception(void) {
    static const HeptaSdkGenerateException none={0};
    return &none;
}
#endif
#endif
