/* Included after the fixed worker's file, SHA, fence, and JSON helpers.
 * No cast into opaque GenieX objects. This experiment never dispatches actions.
 */
#include "official-mobile.h"
#include "phase-timing.h"

typedef struct {
    const char *name, *expected_sha, *path;
    uint64_t expected_bytes, hashed_bytes, hardware_blocks, portable_blocks;
    int fd;
    struct stat before;
    char digest[65], fd_path[64];
    bool verified, unchanged;
    const char *hash_backend;
} VenusWeight;

static VenusWeight venus_weights[2]={
    {.name="UI-Venus-2-9B-Q4_K_M.gguf",
     .expected_sha="f2a8533b4adf7dc92d0731c39bd910438d229593f2e524b8f6e0e0e83fd1ec8d",
     .expected_bytes=UINT64_C(5910782752),.fd=-1},
    {.name="mmproj-UI-Venus-2-9B-f16.gguf",
     .expected_sha="6ef77c3bf87391664be7cd71c595352e7281dabe52f24e961e2deace550f3af2",
     .expected_bytes=UINT64_C(918165664),.fd=-1}
};
static struct llama_model *venus_vocab_model;
static char venus_architecture[64],venus_pre[64],venus_template_sha[65],venus_owner_sha[65];
static const char *venus_template;
static size_t venus_template_size;
static int32_t venus_text_token_count;
static llama_token *venus_text_token_ids;
static char venus_text_ids_sha[65];
static uint32_t venus_image_width,venus_image_height;
static bool venus_text_budget_passed,venus_evidence_complete;
static int32_t venus_capabilities_rc;
static bool venus_capabilities_attempted;
static geniex_VlmCapabilities venus_capabilities;
static char venus_sidecar_sha[4][65];

static bool venus_weight_unchanged(VenusWeight *weight){
    struct stat fd_stat,named;
    return weight->fd>=0&&weight->path&&fstat(weight->fd,&fd_stat)==0&&lstat(weight->path,&named)==0&&
        same_stat(&weight->before,&fd_stat)&&same_stat(&fd_stat,&named);
}
static bool venus_verify_weight(VenusWeight *weight,const char *path){
    const char *base=strrchr(path,'/');
    if(!base||strcmp(base+1,weight->name)||!canonical(path))return false;
    weight->path=path;
    weight->fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(weight->fd<0||fstat(weight->fd,&weight->before)!=0||
       !S_ISREG(weight->before.st_mode)||weight->before.st_uid!=getuid()||
       weight->before.st_nlink!=1||(weight->before.st_mode&0777)!=0600||
       weight->before.st_size<0||(uint64_t)weight->before.st_size!=weight->expected_bytes)return false;
    Sha256 hash;sha_init(&hash);weight->hash_backend=hepta_sha256_backend(&hash);
    unsigned char block[65536];
    for(;;){
        if(!fence(PH_CREATE))return false;
        ssize_t size=read(weight->fd,block,sizeof(block));
        if(size<0&&errno==EINTR)continue;
        if(size<0)return false;
        if(!size)break;
        weight->hashed_bytes+=(uint64_t)size;
        if(weight->hashed_bytes>weight->expected_bytes)return false;
        sha_update(&hash,block,(size_t)size);
    }
    sha_finish(&hash,weight->digest);
    weight->hardware_blocks=hash.hardware_blocks;weight->portable_blocks=hash.portable_blocks;
    if(weight->hashed_bytes!=weight->expected_bytes||strcmp(weight->digest,weight->expected_sha)||
       !venus_weight_unchanged(weight)||lseek(weight->fd,0,SEEK_SET)<0)return false;
    if(snprintf(weight->fd_path,sizeof(weight->fd_path),"/proc/self/fd/%d",weight->fd)>=(int)sizeof(weight->fd_path))return false;
    weight->verified=true;
    return true;
}
static bool venus_verify_weights(const Options *options){
    return venus_verify_weight(&venus_weights[0],options->model)&&venus_verify_weight(&venus_weights[1],options->mmproj);
}
static bool venus_weights_unchanged(void){
    bool all=true;
    for(unsigned i=0;i<2;i++){
        venus_weights[i].unchanged=venus_weights[i].verified&&venus_weight_unchanged(&venus_weights[i]);
        if(!venus_weights[i].unchanged)all=false;
    }
    return all;
}
static bool venus_load_vocab(void){
    struct llama_model_params params=llama_model_default_params();
    static ggml_backend_dev_t no_devices[]={NULL};
    params.vocab_only=true;params.n_gpu_layers=0;params.devices=no_devices;
    venus_vocab_model=llama_model_load_from_file(venus_weights[0].fd_path,params);
    if(!venus_vocab_model)return false;
    int32_t n=llama_model_meta_val_str(venus_vocab_model,"general.architecture",venus_architecture,sizeof(venus_architecture));
    if(n<=0||n>=(int32_t)sizeof(venus_architecture)||strcmp(venus_architecture,"qwen35"))return false;
    n=llama_model_meta_val_str(venus_vocab_model,"tokenizer.ggml.pre",venus_pre,sizeof(venus_pre));
    if(n<=0||n>=(int32_t)sizeof(venus_pre)||strcmp(venus_pre,"qwen35"))return false;
    venus_template=llama_model_chat_template(venus_vocab_model,NULL);
    if(!venus_template)return false;
    venus_template_size=strnlen(venus_template,65537);
    if(venus_template_size!=7740||!utf8((const unsigned char*)venus_template,venus_template_size))return false;
    hash_bytes(venus_template,venus_template_size,venus_template_sha);
    return !strcmp(venus_template_sha,"4a3d47f53cc133e5dc859e9532fcb74baf0459ef426b8f107a3ac6e5926533e5");
}
static uint32_t venus_be32(const unsigned char *p){
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static bool venus_first_frame(const Input inputs[4]){
    static const unsigned char label[]="Current Screenshot:\n";
    static const unsigned char signature[]={137,80,78,71,13,10,26,10};
    const size_t prefix=sizeof(HEPTA_OFFICIAL_MOBILE_PREFIX)-1;
    if(inputs[0].size!=sizeof(label)-1||memcmp(inputs[0].bytes,label,sizeof(label)-1)||
       !inputs[1].bytes||inputs[1].size<=prefix||inputs[1].size-prefix>4096||
       memcmp(inputs[1].bytes,HEPTA_OFFICIAL_MOBILE_PREFIX,prefix)||inputs[2].path)return false;
    hash_bytes(inputs[1].bytes+prefix,inputs[1].size-prefix,venus_owner_sha);
    const Input *image=&inputs[3];
    if(!image->bytes||image->size<33||memcmp(image->bytes,signature,8)||
       venus_be32(image->bytes+8)!=13||memcmp(image->bytes+12,"IHDR",4))return false;
    venus_image_width=venus_be32(image->bytes+16);venus_image_height=venus_be32(image->bytes+20);
    return venus_image_width&&venus_image_width<=4096&&venus_image_height&&venus_image_height<=4096&&
        (uint64_t)venus_image_width*venus_image_height<=UINT64_C(16777216)&&image->bytes[24]==8&&
        (image->bytes[25]==2||image->bytes[25]==6)&&image->bytes[26]==0&&image->bytes[27]==0&&image->bytes[28]==0;
}
static bool venus_measure_text(const char *prompt,size_t size,int output_tokens,int context_tokens){
    if(!venus_vocab_model||size>INT32_MAX)return false;
    const struct llama_vocab *vocabulary=llama_model_get_vocab(venus_vocab_model);
    if(!vocabulary)return false;
    int32_t n=llama_tokenize(vocabulary,prompt,(int32_t)size,NULL,0,true,true);
    if(n>=0||n==INT32_MIN)return false;
    n=-n;
    /* Necessary text-only bound. This does NOT count media expansion and these
     * IDs are deliberately never passed to geniex_vlm_generate. */
    if((int64_t)n+output_tokens+256>context_tokens)return false;
    venus_text_token_ids=malloc((size_t)n*sizeof(*venus_text_token_ids));
    if(!venus_text_token_ids)return false;
    if(llama_tokenize(vocabulary,prompt,(int32_t)size,venus_text_token_ids,n,true,true)!=n)return false;
    const int32_t vocabulary_size=llama_vocab_n_tokens(vocabulary);
    Sha256 hash;sha_init(&hash);
    for(int32_t i=0;i<n;i++){
        if(venus_text_token_ids[i]<0||venus_text_token_ids[i]>=vocabulary_size)return false;
        const uint32_t id=(uint32_t)venus_text_token_ids[i];
        const unsigned char little_endian[]={(unsigned char)id,(unsigned char)(id>>8),(unsigned char)(id>>16),(unsigned char)(id>>24)};
        sha_update(&hash,little_endian,sizeof(little_endian));
    }
    sha_finish(&hash,venus_text_ids_sha);venus_text_token_count=n;venus_text_budget_passed=true;
    return true;
}
static bool venus_write_blob(const Options *options,const char *name,const void *raw,size_t size,char digest[65]){
    char path[PATH_MAX];
    const char *slash=strrchr(options->result,'/');
    if(!slash||snprintf(path,sizeof(path),"%.*s/%s",(int)(slash-options->result),options->result,name)>=(int)sizeof(path))return false;
    Destination dest={.dir=-1,.fd=-1};
    bool ok=reserve_destination(&dest,path,options->id)&&write_all(dest.fd,raw,size)&&publish(&dest);
    if(ok)hash_bytes(raw,size,digest);
    destination_close(&dest);return ok;
}
static bool venus_capture_evidence(const Options *options,const char *formatted,size_t size,const geniex_ChatTemplateGrammar *grammar){
    if(!venus_template||!venus_text_token_ids)return false;
    if(!venus_write_blob(options,"formatted-prompt.txt",formatted,size,venus_sidecar_sha[0])||
       !venus_write_blob(options,"gguf-chat-template.jinja",venus_template,venus_template_size,venus_sidecar_sha[1]))return false;
    const size_t bytes=(size_t)venus_text_token_count*4;
    unsigned char *little_endian=malloc(bytes?bytes:1);if(!little_endian)return false;
    for(int32_t i=0;i<venus_text_token_count;i++){
        const uint32_t value=(uint32_t)venus_text_token_ids[i];
        for(unsigned b=0;b<4;b++)little_endian[4*(size_t)i+b]=(unsigned char)(value>>(8*b));
    }
    bool ok=venus_write_blob(options,"diagnostic-text-only-token-ids.le32",little_endian,bytes,venus_sidecar_sha[2]);
    free(little_endian);if(!ok)return false;
    const char *prefix=grammar->generation_prompt?grammar->generation_prompt:"";
    const size_t prefix_size=strnlen(prefix,65537);
    if(prefix_size>65536||!utf8((const unsigned char*)prefix,prefix_size)||
       !venus_write_blob(options,"sdk-generation-prefix.txt",prefix,prefix_size,venus_sidecar_sha[3]))return false;
    venus_evidence_complete=true;return true;
}
static void venus_release_vocab(void){
    if(venus_vocab_model)llama_model_free(venus_vocab_model);
    venus_vocab_model=NULL;venus_template=NULL;
    free(venus_text_token_ids);venus_text_token_ids=NULL;
}
static void venus_close_weights(void){
    venus_release_vocab();
    for(unsigned i=0;i<2;i++){if(venus_weights[i].fd>=0)close(venus_weights[i].fd);venus_weights[i].fd=-1;}
}
static void venus_write_contract(FILE *f,const Options *options,const geniex_ProfileData *profile,bool generated){
    fputs("\"model_profile\":\"ui-venus2-9b-q4_k_m-f16-mmproj\","
          "\"model_repository\":\"bartowski/UI-Venus-2-9B-GGUF\","
          "\"model_revision\":\"3d2022e8bbe1fb95f12ca530a9d6ef063807d593\","
          "\"official_mobile_revision\":\"6d5f8baf3d28868b3e32fefa9da501e99964a8c5\","
          "\"official_mobile_system_template_sha256\":\"" HEPTA_OFFICIAL_SYSTEM_TEMPLATE_SHA "\","
          "\"owner_embedded_system_suffix_sha256\":",f);json_string(f,venus_owner_sha);
    fputs(",\"weights\":[",f);
    for(unsigned i=0;i<2;i++){
        VenusWeight *w=&venus_weights[i];if(i)fputc(',',f);
        fputs("{\"name\":",f);json_string(f,w->name);fputs(",\"path\":",f);json_string(f,w->path);
        fputs(",\"expected_sha256\":",f);json_string(f,w->expected_sha);
        fputs(",\"actual_full_sha256\":",f);json_string(f,w->verified?w->digest:NULL);
        fprintf(f,",\"expected_bytes\":%" PRIu64 ",\"bytes_hashed\":%" PRIu64 ",\"verified\":%s,"
                  "\"metadata_unchanged\":%s,\"fd_path\":",w->expected_bytes,w->hashed_bytes,
                w->verified?"true":"false",w->unchanged?"true":"false");json_string(f,w->fd_path);
        fputs(",\"sha_backend\":",f);json_string(f,w->hash_backend);
        fprintf(f,",\"hardware_blocks\":%" PRIu64 ",\"portable_blocks\":%" PRIu64 "}",w->hardware_blocks,w->portable_blocks);
    }
    fputs("],\"model_architecture\":",f);json_string(f,venus_architecture);
    fputs(",\"tokenizer_pre\":",f);json_string(f,venus_pre);
    fputs(",\"gguf_template_sha256\":",f);json_string(f,venus_template_sha);
    fprintf(f,",\"vision_capability_query_attempted\":%s,\"vision_capability_query_rc\":",
            venus_capabilities_attempted?"true":"false");
    json_rc(f,venus_capabilities_attempted,venus_capabilities_rc);
    fprintf(f,",\"supports_vision\":%s,\"supports_audio\":%s,"
        "\"image_width_original\":%" PRIu32 ",\"image_height_original\":%" PRIu32 ","
        "\"image_resize_by_worker\":false,\"image_count\":1,\"history_turns\":0,"
        "\"chat_template_enable_thinking\":true,\"native_tools_argument\":false,"
        "\"handwritten_grammar\":false,\"sampler_auto_grammar_used\":false,"
        "\"request_sampler_defaults_are_explicit\":true,\"speculative_decoding\":false,"
        "\"model_config_requested\":{\"n_batch\":256,\"n_ubatch\":128,\"n_seq_max\":1},"
        "\"diagnostic_text_only_tokens\":%" PRId32 ",\"text_only_necessary_budget_passed\":%s,"
        "\"diagnostic_text_ids_passed_to_vlm\":false,"
        "\"pre_generation_multimodal_token_count_available\":false,"
        "\"no_context_shift_proven\":false,\"full_multimodal_input_qualified\":false,"
        "\"llama_cpp_sliding_window_false_does_not_disable_context_shift\":true,"
        "\"image_decoder_parameters_exposed_by_cabi\":false,"
        "\"vision_preprocess_shape_proven\":false,"
        "\"per_operator_backend_coverage_proven\":false,"
        "\"cpu_neural_retry_allowed\":false,\"ordinary_app_qualified\":false,"
        "\"actions_dispatched\":false,\"prompt_sidecars_complete\":%s,"
        "\"prompt_sidecar_sha256\":{",
        venus_capabilities.supports_vision?"true":"false",venus_capabilities.supports_audio?"true":"false",
        venus_image_width,venus_image_height,venus_text_token_count,venus_text_budget_passed?"true":"false",
        venus_evidence_complete?"true":"false");
    static const char *names[]={"formatted-prompt.txt","gguf-chat-template.jinja",
        "diagnostic-text-only-token-ids.le32","sdk-generation-prefix.txt"};
    for(unsigned i=0;i<4;i++){if(i)fputc(',',f);json_string(f,names[i]);fputc(':',f);json_string(f,venus_sidecar_sha[i][0]?venus_sidecar_sha[i]:NULL);}
    fputs("},\"sdk_reported_token_total\":",f);
    const bool valid_counts=generated&&profile->prompt_tokens>=0&&profile->generated_tokens>=0&&
        profile->prompt_tokens<=INT64_MAX-profile->generated_tokens;
    if(valid_counts)fprintf(f,"%" PRId64,profile->prompt_tokens+profile->generated_tokens);
    else fputs("null",f);
    fputs(",\"sdk_reported_total_within_requested_context\":",f);
    if(valid_counts)fputs(profile->prompt_tokens+profile->generated_tokens<=options->ctx?"true":"false",f);
    else fputs("null",f);
    fprintf(f,",\"token_total_is_post_run_supporting_observation_only\":true,"
        "\"uid\":%lu,\"euid\":%lu,\"parent_pid\":%ld,",
        (unsigned long)getuid(),(unsigned long)geteuid(),(long)getppid());
}
