/* Included after the frozen worker's SHA/stat/fence helpers. No opaque SDK casts. */
static int hepta_model_fd=-1;
static struct stat hepta_model_stat;
static char hepta_verified_model_sha[65],hepta_model_fd_path[64],hepta_architecture[64];
static bool hepta_model_unchanged,hepta_model_verified;
static struct llama_model *hepta_vocabulary_model;
static llama_token *hepta_input_ids;
static int32_t hepta_input_count;

static bool hepta_model_is_unchanged(const char *path){
    struct stat descriptor,named;
    return hepta_model_fd>=0&&fstat(hepta_model_fd,&descriptor)==0&&lstat(path,&named)==0&&
        same_stat(&hepta_model_stat,&descriptor)&&same_stat(&descriptor,&named);
}
static bool hepta_verify_model(const char *path){
    const char *name=strrchr(path,'/');
    if(!hepta_model_profile||!name||strcmp(name+1,hepta_model_profile->filename))return false;
    hepta_model_fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(hepta_model_fd<0||fstat(hepta_model_fd,&hepta_model_stat)!=0||!S_ISREG(hepta_model_stat.st_mode)||
       hepta_model_stat.st_uid!=getuid()||hepta_model_stat.st_nlink!=1||(hepta_model_stat.st_mode&0777)!=0600||
       hepta_model_stat.st_size<0||(uint64_t)hepta_model_stat.st_size!=hepta_model_profile->bytes)return false;
    Sha256 hash;sha_init(&hash);unsigned char block[65536];uint64_t count=0;
    for(;;){
        if(!fence(PH_CREATE))return false;
        ssize_t n=read(hepta_model_fd,block,sizeof(block));
        if(n<0&&errno==EINTR)continue;
        if(n<0)return false;
        if(n==0)break;
        count+=(uint64_t)n;if(count>hepta_model_profile->bytes)return false;
        sha_update(&hash,block,(size_t)n);
    }
    sha_finish(&hash,hepta_verified_model_sha);
    if(count!=hepta_model_profile->bytes||strcmp(hepta_verified_model_sha,hepta_model_profile->sha256)||
       !hepta_model_is_unchanged(path)||lseek(hepta_model_fd,0,SEEK_SET)<0)return false;
    if(snprintf(hepta_model_fd_path,sizeof(hepta_model_fd_path),"/proc/self/fd/%d",hepta_model_fd)>=(int)sizeof(hepta_model_fd_path))return false;
    hepta_model_verified=true;
    return true;
}
static bool hepta_load_vocabulary(void){
    struct llama_model_params params=llama_model_default_params();
    /* Tokenization only: no tensors, inference context or CPU neural fallback. */
    static ggml_backend_dev_t no_devices[]={NULL};
    params.vocab_only=true;params.n_gpu_layers=0;params.devices=no_devices;
    hepta_vocabulary_model=llama_model_load_from_file(hepta_model_fd_path,params);
    if(!hepta_vocabulary_model)return false;
    int32_t length=llama_model_meta_val_str(hepta_vocabulary_model,"general.architecture",hepta_architecture,sizeof(hepta_architecture));
    if(length<=0||length>=(int32_t)sizeof(hepta_architecture)||strcmp(hepta_architecture,hepta_model_profile->architecture))return false;
    if(!strcmp(hepta_model_profile->id,"minicpm5-2b-q4_k_m")){
        char pre[64];
        if(llama_model_meta_val_str(hepta_vocabulary_model,"tokenizer.ggml.pre",pre,sizeof(pre))<=0||strcmp(pre,"minicpm5"))return false;
    }
    return true;
}
static bool hepta_prepare_prompt(const char *prompt,size_t bytes,int generation,int context){
    if(!hepta_model_profile->exact_tokens)return hepta_check_prompt_budget(bytes,generation,context);
    if(!hepta_vocabulary_model||bytes>INT32_MAX)return false;
    const struct llama_vocab *vocabulary=llama_model_get_vocab(hepta_vocabulary_model);
    if(!vocabulary)return false;
    int32_t count=llama_tokenize(vocabulary,prompt,(int32_t)bytes,NULL,0,true,true);
    if(count>=0||count==INT32_MIN)return false;
    count=-count;
    if(!hepta_check_exact_prompt_budget(bytes,count,generation,context,hepta_model_profile->sha256))return false;
    hepta_input_ids=malloc((size_t)count*sizeof(*hepta_input_ids));if(!hepta_input_ids)return false;
    int32_t actual=llama_tokenize(vocabulary,prompt,(int32_t)bytes,hepta_input_ids,count,true,true);
    if(actual!=count)return false;
    Sha256 hash;sha_init(&hash);int32_t vocabulary_size=llama_vocab_n_tokens(vocabulary);
    for(int32_t i=0;i<count;i++){
        if(hepta_input_ids[i]<0||hepta_input_ids[i]>=vocabulary_size)return false;
        uint32_t id=(uint32_t)hepta_input_ids[i];
        unsigned char little_endian[4]={(unsigned char)id,(unsigned char)(id>>8),(unsigned char)(id>>16),(unsigned char)(id>>24)};
        sha_update(&hash,little_endian,sizeof(little_endian));
    }
    hepta_input_count=count;sha_finish(&hash,hepta_prompt_budget.input_ids_sha256);
    return true;
}
static void hepta_release_vocabulary(void){
    if(hepta_vocabulary_model)llama_model_free(hepta_vocabulary_model);
    hepta_vocabulary_model=NULL;
}
static void hepta_model_cleanup(void){
    hepta_release_vocabulary();free(hepta_input_ids);hepta_input_ids=NULL;
    if(hepta_model_fd>=0)close(hepta_model_fd);
    hepta_model_fd=-1;
}
static void hepta_write_model_contract(FILE *file){
    fputs("\"model_profile\":",file);json_string(file,hepta_model_profile?hepta_model_profile->id:NULL);
    fputs(",\"model_sha256_verified\":",file);json_string(file,hepta_model_verified?hepta_verified_model_sha:NULL);
    fputs(",\"model_architecture\":",file);json_string(file,hepta_architecture);
    fprintf(file,",\"model_bytes_verified\":%" PRIu64 ",\"model_metadata_unchanged\":%s,"
        "\"chat_template_enable_thinking\":false,\"automatic_cpu_fallback\":false,",
        hepta_model_verified?hepta_model_profile->bytes:0,hepta_model_unchanged?"true":"false");
}
