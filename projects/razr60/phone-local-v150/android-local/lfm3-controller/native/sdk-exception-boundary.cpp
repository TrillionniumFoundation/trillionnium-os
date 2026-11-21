/* A narrow exception boundary around one serialized SDK generation call.
 * No SDK retry, replacement sampler, model fallback or signal translation. */
#include "sdk-exception-boundary.h"
#include <exception>
#include <cstdio>
#include <cstring>
#if !HEPTA_SDK_EXCEPTION_BOUNDARY_ENABLED
#error "Production C++ boundary requires HEPTA_SDK_EXCEPTION_BOUNDARY=1"
#endif
static HeptaSdkGenerateException observed_exception;
static void retain_exception(int kind,const char *message) noexcept {
    observed_exception.kind=kind;
    if(!message)message="exception without diagnostic";
    size_t i=0;
    for(;i+1<sizeof(observed_exception.message)&&message[i];i++){
        const unsigned char c=static_cast<unsigned char>(message[i]);
        if(c>=32&&c<=126)observed_exception.message[i]=static_cast<char>(c);
        else{observed_exception.message[i]='?';observed_exception.message_non_ascii_replaced=1;}
    }
    observed_exception.message[i]=0;
    observed_exception.message_truncated=message[i]!=0;
    std::fprintf(stderr,"HEPTA_SDK_GENERATE_EXCEPTION kind=%d message_truncated=%d message_non_ascii_replaced=%d message=%s\n",
        observed_exception.kind,observed_exception.message_truncated,
        observed_exception.message_non_ascii_replaced,observed_exception.message);
    std::fflush(stderr);
}
extern "C" const HeptaSdkGenerateException *hepta_sdk_generate_exception(void) {
    return &observed_exception;
}
extern "C" int32_t hepta_guarded_llm_generate(geniex_LLM *handle,
        const geniex_LlmGenerateInput *input,geniex_LlmGenerateOutput *output) {
    /* The worker is serial and exits after any failed request. This reset is
     * per actual generate call; it cannot authorize another RUN after failure. */
    std::memset(&observed_exception,0,sizeof(observed_exception));
    try {
        return geniex_llm_generate(handle,input,output);
    } catch(const std::exception &error) {
        retain_exception(1,error.what());
    } catch(...) {
        retain_exception(2,"non-std C++ exception");
    }
    return GENIEX_ERROR_LLM_GENERATION_FAILED;
}
