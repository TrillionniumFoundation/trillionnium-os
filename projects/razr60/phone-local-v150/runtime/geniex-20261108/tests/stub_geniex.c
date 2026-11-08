#define _POSIX_C_SOURCE 200809L
/* Host-only fault injection. Never link this file into an Android candidate. */
#include "geniex.h"
#include <assert.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct geniex_LLM { int marker; };
struct geniex_VLM { int marker; };
static int generation_calls;
static bool scenario(const char *value) {
    const char *actual=getenv("STUB_CASE");
    return actual && strcmp(actual,value)==0;
}
static void trace(const char *event) {
    const char *path=getenv("STUB_TRACE");
    if(!path)return;
    FILE *f=fopen(path,"a");assert(f);assert(fprintf(f,"%s\n",event)>0);assert(fclose(f)==0);
}
static void delay_ms(long milliseconds) {
    struct timespec remaining={.tv_sec=milliseconds/1000,.tv_nsec=(milliseconds%1000)*1000000};
    while(nanosleep(&remaining,&remaining)!=0) { }
}
static void assert_model(const geniex_ModelConfig *c,const char *plugin,const char *vit) {
    assert(c->power_mode==GENIEX_POWER_MODE_SUSTAINED_HIGH_PERFORMANCE);
    if(strcmp(plugin,"qairt")==0){assert(c->n_ctx==0);assert(c->n_gpu_layers==0);}
    const char *expected=getenv("STUB_EXPECT_CTX");
    if(expected)assert(c->n_ctx==atoi(expected));
    expected=getenv("STUB_EXPECT_VIT");
    if(expected)assert(vit && strcmp(expected,vit)==0);
}
const char *geniex_version(void) {
    if(scenario("version_bad"))return "v0.9.9";
    if(scenario("version_invalid"))return "\xff";
    return "v0.10.0";
}
void geniex_free(void *ptr) {free(ptr);}
int32_t geniex_set_log_level(geniex_LogLevel level) {
    (void)level;trace("set_log_level");return scenario("log_fail")?-110:0;
}
int32_t geniex_init(void) {trace("init");return scenario("init_fail")?-111:0;}
int32_t geniex_deinit(void) {trace("deinit");return scenario("deinit_fail")?-112:0;}
int32_t geniex_resolve_device(const geniex_ResolveDeviceInput *in,geniex_ResolveDeviceOutput *out) {
    trace("resolve");
    if(scenario("resolve_fail"))return -113;
    if(strcmp(in->plugin_id,"qairt")==0){out->device_id=strdup("NPU");out->ngl=0;}
    else if(strcmp(in->mode,"cpu")==0){out->device_id=NULL;out->ngl=0;}
    else{out->device_id=strdup(strcmp(in->mode,"npu")==0?"HTP0":"GPUOpenCL");out->ngl=in->ngl_default;}
    if(scenario("coerce"))out->warning=strdup("fixture coercion");
    return 0;
}
static int32_t create_common(void **handle,size_t size) {
    trace("create");
    if(scenario("create_fail"))return -114;
    if(scenario("create_null"))return 0;
    *handle=calloc(1,size);assert(*handle);
    if(scenario("create_partial"))return -115;
    if(scenario("signal_create"))raise(SIGTERM);
    return 0;
}
int32_t geniex_llm_create(const geniex_LlmCreateInput *in,geniex_LLM **out) {
    assert_model(&in->config,in->plugin_id,NULL);return create_common((void **)out,sizeof(**out));
}
int32_t geniex_vlm_create(const geniex_VlmCreateInput *in,geniex_VLM **out) {
    assert_model(&in->config,in->plugin_id,in->vit_device_id);return create_common((void **)out,sizeof(**out));
}
static int32_t destroy_common(void *handle) {
    trace("destroy");free(handle);
    if(scenario("signal_destroy"))raise(SIGTERM);
    return scenario("destroy_fail")?-116:0;
}
int32_t geniex_llm_destroy(geniex_LLM *handle) {return destroy_common(handle);}
int32_t geniex_vlm_destroy(geniex_VLM *handle) {return destroy_common(handle);}
static int32_t make_template(const char *system,const char *user,char **formatted) {
    trace("template");
    if(scenario("template_fail"))return -117;
    if(scenario("template_invalid")){*formatted=strdup("\xff");return 0;}
    if(scenario("template_large")){
        *formatted=malloc(4u*65536u+2u);assert(*formatted);
        memset(*formatted,'a',4u*65536u+1u);(*formatted)[4u*65536u+1u]=0;return 0;
    }
    if(!system)system="";
    size_t size=strlen(system)+strlen(user)+7;
    *formatted=malloc(size);assert(*formatted);
    assert(snprintf(*formatted,size,"S:%s\nU:%s",system,user)>0);return 0;
}
int32_t geniex_llm_apply_chat_template(geniex_LLM *h,const geniex_LlmApplyChatTemplateInput *in,geniex_LlmApplyChatTemplateOutput *out) {
    assert(h && !in->enable_thinking && in->add_generation_prompt && !in->parallel_tool_calls);
    assert(in->message_count==1 || in->message_count==2);
    return make_template(in->message_count==2?in->messages[0].content:NULL,in->messages[in->message_count-1].content,&out->formatted_text);
}
int32_t geniex_vlm_apply_chat_template(geniex_VLM *h,const geniex_VlmApplyChatTemplateInput *in,geniex_VlmApplyChatTemplateOutput *out) {
    assert(h && !in->enable_thinking && !in->parallel_tool_calls);
    assert(in->message_count==1 || in->message_count==2);
    const geniex_VlmChatMessage *user=&in->messages[in->message_count-1];
    assert(user->content_count==1 || user->content_count==2);
    if(getenv("STUB_EXPECT_IMAGE"))assert(user->content_count==2 && strcmp(user->contents[1].type,"image")==0);
    return make_template(in->message_count==2?in->messages[0].contents[0].text:NULL,user->contents[0].text,&out->formatted_text);
}
static int32_t generate_common(const geniex_GenerationConfig *cfg,geniex_token_callback cb,void *user_data,char **text,geniex_ProfileData *profile) {
    trace("generate");assert(++generation_calls==1);assert(cfg && cfg->sampler_config && cb);
    assert(cfg->sampler_config->top_k==1 && cfg->sampler_config->seed==42 && !cfg->sliding_window);
    const char *grammar=getenv("STUB_EXPECT_GRAMMAR");
    if(grammar)assert(cfg->sampler_config->grammar_string && strcmp(grammar,cfg->sampler_config->grammar_string)==0);
    if(getenv("STUB_EXPECT_IMAGE"))assert(cfg->image_count==1 && cfg->image_paths && cfg->image_paths[0]);
    if(scenario("wait_for_term")){trace("waiting");pause();}
    if(scenario("hard_hang")){for(;;)pause();}
    if(scenario("deadline"))delay_ms(25);
    /* Intentionally contaminates stdout; the worker must redirect SDK logging. */
    puts("SDK debug stdout is not JSON {\"fake_success\":true}");
    const char *value=getenv("STUB_TEXT");if(!value)value="42";
    if(scenario("output_invalid"))value="\xff";
    char *large=NULL;
    if(scenario("output_large")){
        large=malloc(1024u*1024u+2u);assert(large);
        memset(large,'x',1024u*1024u+1u);large[1024u*1024u+1u]=0;value=large;
    }
    bool keep_going=cb(value,user_data);
    if(scenario("signal_last_token"))raise(SIGTERM);
    if(scenario("input_changed")){
        const char *path=getenv("STUB_PROMPT_PATH");assert(path);
        FILE *f=fopen(path,"a");assert(f);fputs("x",f);assert(fclose(f)==0);
    }
    *profile=(geniex_ProfileData){.ttft=123,.media_time=234,.prompt_time=345,.decode_time=456,
        .prompt_tokens=789,.generated_tokens=2,.prefill_speed=123.5,.decoding_speed=45.5,
        .draft_n_total=0,.draft_n_accepted=0,.stop_reason="eos"};
    if(!keep_going)profile->stop_reason="user";
    if(scenario("length"))profile->stop_reason="length";
    if(scenario("stop_sequence"))profile->stop_reason="stop_sequence";
    if(scenario("context_length"))profile->stop_reason="context_length";
    if(scenario("user"))profile->stop_reason="user";
    if(scenario("unknown"))profile->stop_reason="fixture_unknown";
    if(scenario("missing_stop"))profile->stop_reason=NULL;
    if(scenario("nonfinite")){profile->prefill_speed=NAN;profile->decoding_speed=INFINITY;}
    if(scenario("generate_fail")){free(large);return -118;}
    *text=strdup(value);assert(*text);free(large);
    if(scenario("generate_fail_with_text")){profile->stop_reason="eos";return -119;}
    return 0;
}
int32_t geniex_llm_generate(geniex_LLM *h,const geniex_LlmGenerateInput *in,geniex_LlmGenerateOutput *out) {
    assert(h);return generate_common(in->config,in->on_token,in->user_data,&out->full_text,&out->profile_data);
}
int32_t geniex_vlm_generate(geniex_VLM *h,const geniex_VlmGenerateInput *in,geniex_VlmGenerateOutput *out) {
    assert(h);return generate_common(in->config,in->on_token,in->user_data,&out->full_text,&out->profile_data);
}
