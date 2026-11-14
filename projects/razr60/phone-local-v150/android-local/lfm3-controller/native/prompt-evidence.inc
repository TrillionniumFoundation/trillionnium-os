/* Private, create-only prompt evidence. Include after model-runtime.inc.
 * Does not alter prompt bytes, tokenizer flags, IDs, sampler, or model state.
 * No raw prompt or token text is logged or embedded in a source manifest. */
static bool hepta_prompt_evidence_complete;
static char hepta_prompt_evidence_formatted_path[PATH_MAX];
static char hepta_prompt_evidence_ids_path[PATH_MAX];
static char hepta_prompt_evidence_meta_path[PATH_MAX];
static char hepta_prompt_evidence_template_sha[65];

static bool hepta_prompt_evidence_path(const Options *o,const char *name,char output[PATH_MAX]) {
    const char *slash=strrchr(o->result,'/');
    if(!slash)return false;
    size_t parent=(size_t)(slash-o->result),length=strlen(name);
    if(!parent||parent+length+2>PATH_MAX)return false;
    memcpy(output,o->result,parent);output[parent]='/';memcpy(output+parent+1,name,length+1);return true;
}
static bool hepta_capture_prompt_evidence(const Options *o,const Input inputs[4],const char *prompt,size_t bytes,const char *formatted_sha) {
    Destination text={.dir=-1,.fd=-1},ids={.dir=-1,.fd=-1},meta={.dir=-1,.fd=-1};
    bool ok=false;FILE *file=NULL;
    if(!o||!prompt||!bytes||bytes>4u*INPUT_LIMIT||!hepta_model_verified||
       !hepta_vocabulary_model||!hepta_model_profile||!formatted_sha||strlen(formatted_sha)!=64)return false;
    char computed[65];hash_bytes(prompt,bytes,computed);if(strcmp(computed,formatted_sha))return false;
    if(hepta_model_profile->exact_tokens&&(!hepta_input_ids||hepta_input_count<=0||
       hepta_input_count>o->ctx||strlen(hepta_prompt_budget.input_ids_sha256)!=64))return false;
    if(!hepta_prompt_evidence_path(o,"formatted-prompt.txt",hepta_prompt_evidence_formatted_path)||
       !hepta_prompt_evidence_path(o,"formatted-input-ids.le32",hepta_prompt_evidence_ids_path)||
       !hepta_prompt_evidence_path(o,"prompt-evidence.json",hepta_prompt_evidence_meta_path))return false;
    const char *template_text=llama_model_chat_template(hepta_vocabulary_model,NULL);
    size_t template_bytes=template_text?strnlen(template_text,1024u*1024u+1u):0;
    if(template_bytes>1024u*1024u)return false;
    if(template_text)hash_bytes(template_text,template_bytes,hepta_prompt_evidence_template_sha);
    if(!reserve_destination(&text,hepta_prompt_evidence_formatted_path,o->id)||
       !reserve_destination(&ids,hepta_prompt_evidence_ids_path,o->id)||
       !reserve_destination(&meta,hepta_prompt_evidence_meta_path,o->id))goto close_evidence;
    if(!fence(PH_TEMPLATE)||!write_all(text.fd,prompt,bytes)||!publish(&text))goto close_evidence;
    Sha256 ids_hash;sha_init(&ids_hash);
    for(int32_t start=0;start<hepta_input_count;start+=256){
        unsigned char block[1024];int32_t count=hepta_input_count-start;if(count>256)count=256;
        for(int32_t i=0;i<count;i++){
            uint32_t id=(uint32_t)hepta_input_ids[start+i];
            block[4*i]=(unsigned char)id;block[4*i+1]=(unsigned char)(id>>8);
            block[4*i+2]=(unsigned char)(id>>16);block[4*i+3]=(unsigned char)(id>>24);
        }
        if(!fence(PH_TEMPLATE)||!write_all(ids.fd,block,(size_t)count*4u))goto close_evidence;
        sha_update(&ids_hash,block,(size_t)count*4u);
    }
    char ids_sha[65];sha_finish(&ids_hash,ids_sha);
    if(hepta_model_profile->exact_tokens&&strcmp(ids_sha,hepta_prompt_budget.input_ids_sha256))goto close_evidence;
    if(!publish(&ids))goto close_evidence;
    file=fdopen(dup(meta.fd),"w");if(!file)goto close_evidence;
    fputs("{\"schema\":\"hepta.private-prompt-evidence.v1\",\"request_id\":",file);json_string(file,o->id);
    fputs(",\"model_profile\":",file);json_string(file,hepta_model_profile->id);
    fputs(",\"model_sha256\":",file);json_string(file,hepta_verified_model_sha);
    fputs(",\"sdk_source_commit\":\"" SDK_PIN "\",\"llama_source_commit\":\"19cce6919992fdffd92e0ac152caaf1e2b8f254e\",",file);
    fputs("\"formatted_prompt_sha256\":",file);json_string(file,formatted_sha);
    fprintf(file,",\"formatted_prompt_bytes\":%zu,\"input_ids_count\":%" PRId32 ",\"input_ids_bytes\":%" PRIu64 ",",bytes,hepta_input_count,(uint64_t)hepta_input_count*4u);
    fputs("\"input_ids_encoding\":\"uint32-little-endian\",\"input_ids_sha256\":",file);json_string(file,ids_sha);
    fprintf(file,",\"input_ids_will_be_passed_directly\":%s,\"add_special\":true,\"parse_special\":true,",hepta_model_profile->exact_tokens?"true":"false");
    fputs("\"gguf_default_template_sha256\":",file);json_string(file,template_text?hepta_prompt_evidence_template_sha:NULL);
    fprintf(file,",\"gguf_default_template_bytes\":%zu,\"chat_template_override\":false,\"use_jinja\":true,\"enable_thinking\":false,\"add_generation_prompt\":true,\"native_tools_argument\":false,",template_bytes);
    fputs("\"source_input_sha256\":{",file);
    const char *names[4]={"prompt","system","grammar","image"};
    for(unsigned i=0;i<4;i++){if(i)fputc(',',file);json_string(file,names[i]);fputc(':',file);json_string(file,inputs[i].path?inputs[i].digest:NULL);}
    fputs("},\"diagnostic_only\":true,\"action_authorized\":false,\"does_not_prove_generation_completed\":true}\n",file);
    ok=fflush(file)==0&&!ferror(file);if(fclose(file)!=0)ok=false;file=NULL;
    if(!ok||!fence(PH_TEMPLATE)||!publish(&meta)){ok=false;goto close_evidence;}
    hepta_prompt_evidence_complete=true;
close_evidence:
    if(file)fclose(file);
    destination_close(&text);destination_close(&ids);destination_close(&meta);return ok;
}
static void hepta_write_prompt_evidence_meta(FILE *f){
    fprintf(f,"\"prompt_evidence\":{\"schema\":\"hepta.private-prompt-evidence.v1\",\"complete\":%s,",hepta_prompt_evidence_complete?"true":"false");
    fputs("\"formatted_file\":",f);json_string(f,hepta_prompt_evidence_complete?hepta_prompt_evidence_formatted_path:NULL);
    fputs(",\"input_ids_file\":",f);json_string(f,hepta_prompt_evidence_complete?hepta_prompt_evidence_ids_path:NULL);
    fputs(",\"metadata_file\":",f);json_string(f,hepta_prompt_evidence_complete?hepta_prompt_evidence_meta_path:NULL);
    fputs("},",f);
}
