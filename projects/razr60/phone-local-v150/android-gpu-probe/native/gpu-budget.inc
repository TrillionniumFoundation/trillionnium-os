/* Exact 19cce691 public C ABI. Counter-only metadata and placeholder images;
 * never encode an empty bitmap. The actual SDK still owns model execution. */
#include "vendor/llama/llama.h"
#include "vendor/llama/mtmd.h"

#define GPU_COUNTER_PIN "19cce6919992fdffd92e0ac152caaf1e2b8f254e"
#define GPU_CONTEXT 8192
#define GPU_MARGIN 64
static struct {
    bool checked, admitted, image_present, exact_match, small_alloc_override;
    int64_t input_tokens, text_tokens, image_tokens, profile_tokens;
    int32_t generation_reserve, image_min_tokens, image_max_tokens;
    uint32_t image_width, image_height;
    size_t vision_max_alloc;
    const char *error;
} gpu_budget;

static bool gpu_budget_fail(const char *error) {
    gpu_budget.error=error;
    fprintf(stderr,"HEPTA_GPU_BUDGET error=%s\n",error);
    return false;
}

#define GPU_LOAD_SYMBOL(name) \
    __typeof__(&name) p_##name=(__typeof__(&name))dlsym(RTLD_DEFAULT,#name); \
    if(!p_##name)return gpu_budget_fail("missing_" #name)

static uint32_t gpu_be32(const unsigned char *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3];
}

static bool gpu_count_input(const Options *o,const Input *image,const char *prompt,size_t prompt_size) {
    gpu_budget.generation_reserve=o->max_tokens;
    gpu_budget.image_present=o->image!=NULL;
    if(strcmp(o->runtime,"llama_cpp")||strcmp(o->compute,"gpu")||o->ctx!=GPU_CONTEXT||o->grammar)
        return gpu_budget_fail("unsupported_counter_configuration");
    if(prompt_size>INT32_MAX||o->max_tokens<1||o->max_tokens>1024)
        return gpu_budget_fail("counter_text_or_generation_bound");
    if(gpu_budget.image_present&&(!o->vit||!o->mmproj||strcmp(o->mode,"vlm")))
        return gpu_budget_fail("counter_image_configuration");
    GPU_LOAD_SYMBOL(llama_model_default_params);
    GPU_LOAD_SYMBOL(llama_model_load_from_file);
    GPU_LOAD_SYMBOL(llama_model_free);
    GPU_LOAD_SYMBOL(llama_model_get_vocab);
    GPU_LOAD_SYMBOL(llama_model_n_ctx_train);
    GPU_LOAD_SYMBOL(llama_tokenize);
    GPU_LOAD_SYMBOL(ggml_backend_dev_by_name);
    GPU_LOAD_SYMBOL(ggml_backend_dev_name);
    GPU_LOAD_SYMBOL(ggml_backend_dev_buffer_type);
    GPU_LOAD_SYMBOL(ggml_backend_buft_get_max_size);
    GPU_LOAD_SYMBOL(mtmd_context_params_default);
    GPU_LOAD_SYMBOL(mtmd_init_from_file);
    GPU_LOAD_SYMBOL(mtmd_free);
    GPU_LOAD_SYMBOL(mtmd_bitmap_init);
    GPU_LOAD_SYMBOL(mtmd_bitmap_free);
    GPU_LOAD_SYMBOL(mtmd_input_chunks_init);
    GPU_LOAD_SYMBOL(mtmd_input_chunks_free);
    GPU_LOAD_SYMBOL(mtmd_input_chunks_size);
    GPU_LOAD_SYMBOL(mtmd_input_chunks_get);
    GPU_LOAD_SYMBOL(mtmd_input_chunk_get_n_tokens);
    GPU_LOAD_SYMBOL(mtmd_input_chunk_get_type);
    GPU_LOAD_SYMBOL(mtmd_tokenize);
    struct llama_model *metadata=NULL;
    mtmd_context *vision=NULL;
    mtmd_bitmap *bitmap=NULL;
    mtmd_input_chunks *chunks=NULL;
    bool ok=false;
    ggml_backend_dev_t cpu=p_ggml_backend_dev_by_name("CPU");
    if(!cpu)return gpu_budget_fail("CPU_counter_device_missing");
    ggml_backend_dev_t counter_devices[2]={cpu,NULL};
    struct llama_model_params params=p_llama_model_default_params();
    params.vocab_only=true;
    params.n_gpu_layers=0;
    params.devices=counter_devices;
    fprintf(stderr,"HEPTA_GPU_BUDGET phase=metadata_load vocab_only=true source=%s\n",GPU_COUNTER_PIN);
    metadata=p_llama_model_load_from_file(o->model,params);
    if(!metadata){gpu_budget_fail("counter_vocab_load_failed");goto cleanup;}
    if(p_llama_model_n_ctx_train(metadata)<GPU_CONTEXT){gpu_budget_fail("model_training_context_below_requested");goto cleanup;}
    if(!gpu_budget.image_present){
        const struct llama_vocab *vocab=p_llama_model_get_vocab(metadata);
        if(!vocab){gpu_budget_fail("counter_vocab_missing");goto cleanup;}
        int32_t needed=p_llama_tokenize(vocab,prompt,(int32_t)prompt_size,NULL,0,true,true);
        if(needed==INT32_MIN||needed>=0){gpu_budget_fail("counter_text_token_query_failed");goto cleanup;}
        gpu_budget.input_tokens=-(int64_t)needed;
        gpu_budget.text_tokens=gpu_budget.input_tokens;
    }else{
        static const unsigned char png_magic[8]={137,80,78,71,13,10,26,10};
        if(image->size<33||memcmp(image->bytes,png_magic,8)||gpu_be32(image->bytes+8)!=13||memcmp(image->bytes+12,"IHDR",4)){
            gpu_budget_fail("counter_requires_preprocessed_PNG");goto cleanup;
        }
        gpu_budget.image_width=gpu_be32(image->bytes+16);
        gpu_budget.image_height=gpu_be32(image->bytes+20);
        uint64_t pixels=(uint64_t)gpu_budget.image_width*gpu_budget.image_height;
        if(!gpu_budget.image_width||!gpu_budget.image_height||pixels>262144){gpu_budget_fail("counter_image_pixel_bound");goto cleanup;}
        ggml_backend_dev_t actual_vision=p_ggml_backend_dev_by_name(o->vit);
        if(!actual_vision){gpu_budget_fail("requested_vision_device_missing");goto cleanup;}
        const char *vision_name=p_ggml_backend_dev_name(actual_vision);
        if(!vision_name||strcmp(vision_name,o->vit)){gpu_budget_fail("requested_vision_device_identity_differs");goto cleanup;}
        struct mtmd_context_params mparams=p_mtmd_context_params_default();
        /* Exactly match min/max and flash attention used by GenieX GPU VLM.
         * Only compute placement/warmup differ for this no-encode counter. */
        mparams.use_gpu=false;
        mparams.device=NULL;
        mparams.warmup=false;
        mparams.print_timings=false;
        mparams.n_threads=o->threads;
        mparams.flash_attn_type=LLAMA_FLASH_ATTN_TYPE_DISABLED;
        gpu_budget.vision_max_alloc=p_ggml_backend_buft_get_max_size(p_ggml_backend_dev_buffer_type(actual_vision));
        if(!strncmp(vision_name,"GPUOpenCL",9)&&gpu_budget.vision_max_alloc<=((size_t)1<<30)){
            mparams.image_max_tokens=1024;
            gpu_budget.small_alloc_override=true;
        }
        gpu_budget.image_min_tokens=mparams.image_min_tokens;
        gpu_budget.image_max_tokens=mparams.image_max_tokens;
        fprintf(stderr,"HEPTA_GPU_BUDGET phase=placeholder_init width=%u height=%u max_override=%d actual_device=%s max_alloc=%zu\n",
            gpu_budget.image_width,gpu_budget.image_height,mparams.image_max_tokens,vision_name,gpu_budget.vision_max_alloc);
        vision=p_mtmd_init_from_file(o->mmproj,metadata,mparams);
        if(!vision){gpu_budget_fail("counter_mmproj_load_failed");goto cleanup;}
        bitmap=p_mtmd_bitmap_init(gpu_budget.image_width,gpu_budget.image_height,NULL);
        chunks=p_mtmd_input_chunks_init();
        if(!bitmap||!chunks){gpu_budget_fail("counter_placeholder_allocation_failed");goto cleanup;}
        const mtmd_bitmap *images[1]={bitmap};
        const mtmd_input_text text={.text=prompt,.text_len=prompt_size,.add_special=true,.parse_special=true};
        int32_t token_rc=p_mtmd_tokenize(vision,chunks,&text,images,1);
        if(token_rc){gpu_budget_fail("counter_mtmd_tokenize_failed");goto cleanup;}
        size_t size=p_mtmd_input_chunks_size(chunks);
        if(size==0||size>4096){gpu_budget_fail("counter_chunk_count_invalid");goto cleanup;}
        for(size_t i=0;i<size;i++){
            const mtmd_input_chunk *chunk=p_mtmd_input_chunks_get(chunks,i);
            if(!chunk){gpu_budget_fail("counter_chunk_missing");goto cleanup;}
            size_t count=p_mtmd_input_chunk_get_n_tokens(chunk);
            if(count>INT32_MAX||gpu_budget.input_tokens>INT32_MAX-(int64_t)count){gpu_budget_fail("counter_token_overflow");goto cleanup;}
            enum mtmd_input_chunk_type type=p_mtmd_input_chunk_get_type(chunk);
            if(type==MTMD_INPUT_CHUNK_TYPE_TEXT)gpu_budget.text_tokens+=(int64_t)count;
            else if(type==MTMD_INPUT_CHUNK_TYPE_IMAGE)gpu_budget.image_tokens+=(int64_t)count;
            else {gpu_budget_fail("counter_unexpected_media_type");goto cleanup;}
            gpu_budget.input_tokens+=(int64_t)count;
        }
        if(gpu_budget.image_tokens<=0){gpu_budget_fail("counter_image_tokens_missing");goto cleanup;}
    }
    gpu_budget.checked=true;
    gpu_budget.admitted=gpu_budget.input_tokens>0&&gpu_budget.input_tokens+o->max_tokens+GPU_MARGIN<=GPU_CONTEXT;
    fprintf(stderr,"HEPTA_GPU_BUDGET phase=counted tokens=%" PRId64 " text=%" PRId64 " image=%" PRId64 " reserve=%d margin=%d ctx=%d admitted=%d\n",
        gpu_budget.input_tokens,gpu_budget.text_tokens,gpu_budget.image_tokens,o->max_tokens,GPU_MARGIN,GPU_CONTEXT,gpu_budget.admitted);
    if(!gpu_budget.admitted){gpu_budget_fail("input_budget_exceeds_context");goto cleanup;}
    ok=true;
cleanup:
    if(chunks)p_mtmd_input_chunks_free(chunks);
    if(bitmap)p_mtmd_bitmap_free(bitmap);
    if(vision)p_mtmd_free(vision);
    if(metadata)p_llama_model_free(metadata);
    return ok;
}
#undef GPU_LOAD_SYMBOL

static bool gpu_check_profile(const geniex_ProfileData *profile) {
    gpu_budget.profile_tokens=profile->prompt_tokens;
    gpu_budget.exact_match=gpu_budget.checked&&gpu_budget.admitted&&profile->prompt_tokens==gpu_budget.input_tokens;
    fprintf(stderr,"HEPTA_GPU_BUDGET phase=profile count=%" PRId64 " actual=%" PRId64 " exact=%d\n",
        gpu_budget.input_tokens,profile->prompt_tokens,gpu_budget.exact_match);
    if(!gpu_budget.exact_match)return gpu_budget_fail("actual_prompt_tokens_differ_from_precount");
    return true;
}

static void gpu_budget_json(FILE *f) {
    fputs(",\"input_budget\":{\"counter\":\"llama_mtmd_exact\",\"counter_source_commit\":\"" GPU_COUNTER_PIN "\",",f);
    fprintf(f,"\"checked\":%s,\"admitted\":%s,\"image_present\":%s,\"context_tokens\":%d,\"generation_reserve\":%d,\"additional_reserve\":%d,",
        gpu_budget.checked?"true":"false",gpu_budget.admitted?"true":"false",gpu_budget.image_present?"true":"false",GPU_CONTEXT,gpu_budget.generation_reserve,GPU_MARGIN);
    fprintf(f,"\"input_tokens\":%" PRId64 ",\"text_tokens\":%" PRId64 ",\"image_tokens\":%" PRId64 ",\"profile_prompt_tokens\":%" PRId64 ",\"profile_within_counted_bound\":%s,\"profile_exact_count_match\":%s,",
        gpu_budget.input_tokens,gpu_budget.text_tokens,gpu_budget.image_tokens,gpu_budget.profile_tokens,gpu_budget.exact_match?"true":"false",gpu_budget.exact_match?"true":"false");
    fprintf(f,"\"image_width\":%u,\"image_height\":%u,\"image_min_tokens_config\":%d,\"image_max_tokens_config\":%d,\"small_opencl_allocation_override\":%s,\"vision_device_max_allocation\":%zu,",
        gpu_budget.image_width,gpu_budget.image_height,gpu_budget.image_min_tokens,gpu_budget.image_max_tokens,gpu_budget.small_alloc_override?"true":"false",gpu_budget.vision_max_alloc);
    fputs("\"counter_vocabulary_only\":true,\"counter_placeholder_encode_called\":false,\"actual_formatted_prompt_counted\":true,\"add_special\":true,\"parse_special\":true,\"error\":",f);
    json_string(f,gpu_budget.error);fputc('}',f);
}
