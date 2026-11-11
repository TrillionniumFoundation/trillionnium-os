/* TEST DOUBLE ONLY. No inference, GPU, NPU or tool execution occurs here.
 * Compiled against the real v0.19.1 C API headers. Never package this file. */
#define _POSIX_C_SOURCE 200809L
#include "engine.h"
#include "conversation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int is_case(const char *name) {
    const char *v = getenv("HEPTA_FAKE_SCENARIO");
    return v && !strcmp(v, name);
}
static void hang(void) { for (;;) { struct timespec t={1,0}; nanosleep(&t,NULL); } }
#define NEW(fn, T) LiteRtLmStatusCode fn(T **out) { *out=(T *)calloc(1,8); return *out ? kLiteRtLmStatusOk : kLiteRtLmStatusResourceExhausted; }
#define DEL(fn, T) void fn(T *p) { free(p); }
#define SET(fn, T, V) LiteRtLmStatusCode fn(T *p, V v) { (void)p; (void)v; return kLiteRtLmStatusOk; }
LiteRtLmStatusCode litert_lm_get_api_version(int *a,int *b,int *c) { *a=1;*b=0;*c=0;return kLiteRtLmStatusOk; }
const char *litert_lm_get_last_error_message(void) { return "FAKE SDK controlled error; not a model result"; }
LiteRtLmStatusCode litert_lm_set_min_log_level(LiteRtLmLogSeverity p) { (void)p;return kLiteRtLmStatusOk; }
LiteRtLmStatusCode litert_lm_engine_settings_create_from_raw_file_descriptor(int fd,const char *b,const char *v,const char *a,LiteRtLmEngineSettings **out) {
    (void)b;(void)v;(void)a; close(fd); *out=(LiteRtLmEngineSettings *)calloc(1,8);
    puts("FAKE_SDK_STDOUT_MARKER"); fflush(stdout); return *out ? kLiteRtLmStatusOk:kLiteRtLmStatusResourceExhausted;
}
SET(litert_lm_engine_settings_set_max_num_tokens,LiteRtLmEngineSettings,int)
SET(litert_lm_engine_settings_set_cache_dir,LiteRtLmEngineSettings,const char *)
NEW(litert_lm_speculative_decoding_config_create,LiteRtLmSpeculativeDecodingConfig)
SET(litert_lm_speculative_decoding_config_set_mode,LiteRtLmSpeculativeDecodingConfig,LiteRtLmSpeculativeDecodingMode)
SET(litert_lm_engine_settings_set_speculative_decoding_config,LiteRtLmEngineSettings,const LiteRtLmSpeculativeDecodingConfig *)
LiteRtLmStatusCode litert_lm_engine_create(const LiteRtLmEngineSettings *s,LiteRtLmEngine **out) {
    (void)s;if(is_case("load_hang"))hang();*out=(LiteRtLmEngine *)calloc(1,8);return *out?kLiteRtLmStatusOk:kLiteRtLmStatusResourceExhausted;
}
NEW(litert_lm_session_config_create,LiteRtLmSessionConfig)
SET(litert_lm_session_config_set_max_output_tokens,LiteRtLmSessionConfig,int)
LiteRtLmStatusCode litert_lm_sampler_params_create(LiteRtLmSamplerType t,LiteRtLmSamplerParams **out) {(void)t;*out=(LiteRtLmSamplerParams *)calloc(1,8);return *out?kLiteRtLmStatusOk:kLiteRtLmStatusResourceExhausted;}
SET(litert_lm_sampler_params_set_seed,LiteRtLmSamplerParams,int32_t)
SET(litert_lm_session_config_set_sampler_params,LiteRtLmSessionConfig,const LiteRtLmSamplerParams *)
NEW(litert_lm_conversation_config_create,LiteRtLmConversationConfig)
SET(litert_lm_conversation_config_set_session_config,LiteRtLmConversationConfig,const LiteRtLmSessionConfig *)
SET(litert_lm_conversation_config_set_system_message,LiteRtLmConversationConfig,const char *)
SET(litert_lm_conversation_config_set_enable_constrained_decoding,LiteRtLmConversationConfig,bool)
SET(litert_lm_conversation_config_set_constraint_provider,LiteRtLmConversationConfig,LiteRtLmConstraintProviderType)
NEW(litert_lm_thinking_config_create,LiteRtLmThinkingConfig)
SET(litert_lm_thinking_config_set_enable_thinking,LiteRtLmThinkingConfig,bool)
SET(litert_lm_conversation_config_set_thinking_config,LiteRtLmConversationConfig,const LiteRtLmThinkingConfig *)
LiteRtLmStatusCode litert_lm_conversation_create(LiteRtLmEngine *e,LiteRtLmConversationConfig *c,LiteRtLmConversation **out) {(void)e;(void)c;*out=(LiteRtLmConversation *)calloc(1,8);return *out?kLiteRtLmStatusOk:kLiteRtLmStatusResourceExhausted;}
NEW(litert_lm_conversation_optional_args_create,LiteRtLmConversationOptionalArgs)
SET(litert_lm_conversation_optional_args_set_max_output_tokens,LiteRtLmConversationOptionalArgs,int)
LiteRtLmStatusCode litert_lm_conversation_optional_args_set_constraint(LiteRtLmConversationOptionalArgs *a,LiteRtLmConstraintType t,const char *s) {(void)a;(void)t;(void)s;return kLiteRtLmStatusOk;}
LiteRtLmStatusCode litert_lm_conversation_send_message(LiteRtLmConversation *c,const char *m,const char *x,const LiteRtLmConversationOptionalArgs *a,LiteRtLmJsonResponse **out) {
    (void)c;(void)m;(void)x;(void)a;
    if(is_case("generation_hang"))hang();
    if(is_case("generation_error"))return kLiteRtLmStatusInternal;
    *out=(LiteRtLmJsonResponse *)calloc(1,8);return *out?kLiteRtLmStatusOk:kLiteRtLmStatusResourceExhausted;
}
LiteRtLmStatusCode litert_lm_json_response_get_string(const LiteRtLmJsonResponse *r,const char **out) {
    (void)r;
    if(is_case("duplicate_response")){*out="{\"role\":\"assistant\",\"role\":\"tool\"}";return kLiteRtLmStatusOk;}
    if(is_case("large_response")){
        static char *large;size_t n=200000;large=malloc(n+100);
        strcpy(large,"{\"role\":\"assistant\",\"content\":\"");size_t start=strlen(large);
        memset(large+start,'x',n);strcpy(large+start+n,"\"}");*out=large;return kLiteRtLmStatusOk;
    }
    *out="{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"fixture claims done\"}],\"tool_calls\":[{\"type\":\"function\",\"function\":{\"name\":\"not_executed\",\"arguments\":{\"n\":1}}}]}";
    return kLiteRtLmStatusOk;
}
DEL(litert_lm_json_response_delete,LiteRtLmJsonResponse)
DEL(litert_lm_conversation_delete,LiteRtLmConversation)
DEL(litert_lm_conversation_optional_args_delete,LiteRtLmConversationOptionalArgs)
DEL(litert_lm_conversation_config_delete,LiteRtLmConversationConfig)
DEL(litert_lm_thinking_config_delete,LiteRtLmThinkingConfig)
DEL(litert_lm_sampler_params_delete,LiteRtLmSamplerParams)
DEL(litert_lm_session_config_delete,LiteRtLmSessionConfig)
DEL(litert_lm_speculative_decoding_config_delete,LiteRtLmSpeculativeDecodingConfig)
void litert_lm_engine_delete(LiteRtLmEngine *p){if(p&&is_case("cleanup_hang"))hang();free(p);}
DEL(litert_lm_engine_settings_delete,LiteRtLmEngineSettings)
