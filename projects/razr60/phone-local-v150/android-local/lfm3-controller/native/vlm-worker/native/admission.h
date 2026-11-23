#ifndef HEPTA_VLM_ADMISSION_H
#define HEPTA_VLM_ADMISSION_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
static inline bool hepta_vlm_admit(size_t tokens,int64_t positions,size_t image_tokens,
                                    unsigned output,unsigned context) {
    // Token slots and M-RoPE positions have distinct capacity requirements.
    if (!tokens || positions<=0 || !image_tokens || image_tokens>1024
        || output==0 || output>256 || context!=8192) return false;
    size_t reserve=(size_t)output+16;
    return reserve<context && tokens<=context-reserve
        && (uint64_t)positions<=context-reserve && image_tokens<=tokens;
}
#endif
