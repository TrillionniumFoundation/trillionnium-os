#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
/* One invocation, at most one generate(). This is NOT a production receipt
 * server. A separate supervisor must observe waitpid/pidfd and own cancellation
 * ordering. SIGTERM during SDK init/prefill can still require external SIGKILL.
 * Build only against the vendored GenieX v0.10.0 C ABI. */
#include "geniex.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define INPUT_LIMIT 65536u
#define IMAGE_LIMIT (8u * 1024u * 1024u)
#define OUTPUT_LIMIT (1024u * 1024u)
#define STOP_LIMIT 127u
#define SDK_PIN "071f609995470bdb0e0769ab964754adfaab7e47"
#define MODEL_POWER_MODE GENIEX_POWER_MODE_SUSTAINED_HIGH_PERFORMANCE

#include "sha256-dispatch.h"

static bool utf8(const unsigned char *p,size_t n) {
    size_t i=0;
    while(i<n) {
        uint32_t v;unsigned more;unsigned char c=p[i++];
        if(c<0x80)continue;
        if(c>=0xc2&&c<=0xdf){v=c&31u;more=1;}
        else if(c>=0xe0&&c<=0xef){v=c&15u;more=2;}
        else if(c>=0xf0&&c<=0xf4){v=c&7u;more=3;}else return false;
        if(n-i<more)return false;
        for(unsigned j=0;j<more;j++){c=p[i++];if((c&0xc0u)!=0x80u)return false;v=(v<<6)|(c&63u);}
        if((more==1&&v<0x80)||(more==2&&v<0x800)||(more==3&&v<0x10000)||v>0x10ffff||(v>=0xd800&&v<=0xdfff))return false;
    }
    return true;
}
static bool same_stat(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&
        a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&a->st_mtim.tv_sec==b->st_mtim.tv_sec&&
        a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static bool canonical(const char *path) {
    if(!path||path[0]!='/'||strlen(path)>=PATH_MAX||!utf8((const unsigned char*)path,strlen(path)))return false;
    char real[PATH_MAX];return realpath(path,real)&&strcmp(real,path)==0;
}
typedef struct { const char *path;int fd;struct stat before;unsigned char *bytes;size_t size;char digest[65]; } Input;
static bool read_input(Input *in,const char *path,size_t limit,bool text) {
    in->fd=-1;in->path=path;
    if(!path)return true;
    if(!canonical(path))return false;
    in->fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(in->fd<0||fstat(in->fd,&in->before)<0||!S_ISREG(in->before.st_mode)||in->before.st_nlink!=1||
       in->before.st_uid!=getuid()||(in->before.st_mode&0777)!=0600||in->before.st_size<=0||
       (uint64_t)in->before.st_size>limit)return false;
    in->size=(size_t)in->before.st_size;in->bytes=malloc(in->size+1);if(!in->bytes)return false;
    size_t done=0;
    while(done<in->size){ssize_t n=read(in->fd,in->bytes+done,in->size-done);if(n<0&&errno==EINTR)continue;if(n<=0)return false;done+=(size_t)n;}
    unsigned char extra;ssize_t n;do{n=read(in->fd,&extra,1);}while(n<0&&errno==EINTR);if(n!=0)return false;
    in->bytes[in->size]=0;struct stat after,named;
    if(fstat(in->fd,&after)<0||lstat(path,&named)<0||!same_stat(&in->before,&after)||!same_stat(&after,&named))return false;
    if(text&&(memchr(in->bytes,0,in->size)||!utf8(in->bytes,in->size)))return false;
    hash_bytes(in->bytes,in->size,in->digest);return true;
}
static bool input_unchanged(const Input *in) {
    if(!in->path)return true;
    struct stat a,b;
    return fstat(in->fd,&a)==0&&lstat(in->path,&b)==0&&same_stat(&in->before,&a)&&same_stat(&a,&b);
}
static void input_free(Input *in) { if(in->fd>=0)close(in->fd);free(in->bytes); }

typedef struct {int dir,fd;char name[201],pending[240];bool published;} Destination;
static bool reserve_destination(Destination *d,const char *path,const char *id) {
    d->dir=d->fd=-1;
    if(!path||path[0]!='/'||strlen(path)>=PATH_MAX)return false;
    const char *slash=strrchr(path,'/');size_t len=(size_t)(slash-path);
    if(len==0||strlen(slash+1)==0||strlen(slash+1)>200)return false;
    char parent[PATH_MAX];memcpy(parent,path,len);parent[len]=0;
    if(!canonical(parent)||!utf8((const unsigned char*)(slash+1),strlen(slash+1)))return false;
    strcpy(d->name,slash+1);if(!strcmp(d->name,".")||!strcmp(d->name,".."))return false;
    d->dir=open(parent,O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);struct stat st;
    if(d->dir<0||fstat(d->dir,&st)<0||st.st_uid!=getuid()||(st.st_mode&0777)!=0700)return false;
    if(fstatat(d->dir,d->name,&st,AT_SYMLINK_NOFOLLOW)==0||errno!=ENOENT)return false;
    (void)snprintf(d->pending,sizeof(d->pending),"%s.%s.pending",d->name,id);
    d->fd=openat(d->dir,d->pending,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    return d->fd>=0;
}
static bool publish(Destination *d) {
    if(fsync(d->fd)<0){
        int saved=errno;
        fprintf(stderr,"HEPTA_APPUID_PUBLISH stage=file_fsync file=%s errno=%d error=%s\n",d->name,saved,strerror(saved));
        return false;
    }
    /* Android app domains can forbid hard links. renameat2 NOREPLACE keeps
     * the original no-overwrite guarantee; no ordinary rename fallback. */
    if(syscall(SYS_renameat2,d->dir,d->pending,d->dir,d->name,RENAME_NOREPLACE)<0){
        int saved=errno;
        fprintf(stderr,"HEPTA_APPUID_PUBLISH stage=renameat2_noreplace file=%s errno=%d error=%s\n",d->name,saved,strerror(saved));
        return false;
    }
    if(fsync(d->dir)<0){
        int saved=errno;
        fprintf(stderr,"HEPTA_APPUID_PUBLISH stage=directory_fsync file=%s errno=%d error=%s\n",d->name,saved,strerror(saved));
        return false;
    }
    fprintf(stderr,"HEPTA_APPUID_PUBLISH method=renameat2_noreplace file=%s published=true\n",d->name);
    d->published=true;return true;
}

static void destination_close(Destination *d) {
    if(d->fd>=0)close(d->fd);
    if(d->dir>=0)close(d->dir);
    /* Failed/incomplete pending files deliberately remain as incomplete data. */
}
static bool write_all(int fd,const void *data,size_t size) {
    const unsigned char *p=data;
    while(size){ssize_t n=write(fd,p,size);if(n<0&&errno==EINTR)continue;if(n<=0)return false;p+=n;size-=(size_t)n;}return true;
}

typedef struct {
    const char *id,*mode,*runtime,*compute,*vit,*model,*mmproj,*tokenizer,*prompt,*system,*grammar,*image,*result,*text;
    int ctx,max_tokens,threads,timeout_ms;geniex_LogLevel log_level;
} Options;
static void usage(void) {
    fputs("hepta-geniex-once --request-id HEX32 --mode llm|vlm --runtime llama_cpp|qairt\n"
          " --compute cpu|gpu|npu|hybrid --model ABS --prompt-file ABS --result-file ABS --text-file ABS\n"
          " [--mmproj ABS] [--tokenizer ABS] [--image ABS] [--system-file ABS] [--grammar-file ABS]\n"
          " [--vit-device CPU|HTP0|HTP1|GPUOpenCL] [--ctx-size 0..32768] [--max-tokens 1..1024]\n"
          " [--threads 1..8] [--timeout-ms 1..300000] [--log-level error|warn|info|debug|trace]\n"
          "Input files: canonical regular owner files, mode0600. Output parent: canonical mode0700.\n"
          "One chat-template application and at most one generate. No automatic retry.\n",stderr);
}
static bool number(const char *s,int lo,int hi,int *out) {
    if(!s||!*s||(*s=='0'&&s[1]))return false;
    int64_t n=0;for(const char *p=s;*p;p++){if(*p<'0'||*p>'9')return false;n=n*10+(*p-'0');if(n>hi)return false;}
    if(n<lo)return false;
    *out=(int)n;return true;
}
static bool id_ok(const char *s) {
    if(!s||strlen(s)!=32)return false;
    for(size_t i=0;i<32;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return false;
    return true;
}
static bool parse(int argc,char **argv,Options *o) {
    *o=(Options){.ctx=0,.max_tokens=256,.threads=4,.timeout_ms=120000,.log_level=GENIEX_LOG_LEVEL_WARN};
    uint32_t seen=0;
    static const char *names[]={"--request-id","--mode","--runtime","--compute","--vit-device","--model","--mmproj","--tokenizer",
        "--prompt-file","--system-file","--grammar-file","--image","--result-file","--text-file","--ctx-size","--max-tokens",
        "--threads","--timeout-ms","--log-level"};
    if(argc<2||(argc%2)!=1)return false;
    for(int i=1;i<argc;i+=2){size_t j;for(j=0;j<sizeof(names)/sizeof(names[0]);j++)if(!strcmp(argv[i],names[j]))break;
        if(j==sizeof(names)/sizeof(names[0])||(seen&(UINT32_C(1)<<j)))return false;
        seen|=UINT32_C(1)<<j;const char *v=argv[i+1];
        if(!*v)return false;
        switch(j){case 0:o->id=v;break;case 1:o->mode=v;break;case 2:o->runtime=v;break;case 3:o->compute=v;break;case 4:o->vit=v;break;
            case 5:o->model=v;break;case 6:o->mmproj=v;break;case 7:o->tokenizer=v;break;case 8:o->prompt=v;break;case 9:o->system=v;break;
            case 10:o->grammar=v;break;case 11:o->image=v;break;case 12:o->result=v;break;case 13:o->text=v;break;
            case 14:if(!number(v,0,32768,&o->ctx))return false;break;case 15:if(!number(v,1,1024,&o->max_tokens))return false;break;
            case 16:if(!number(v,1,8,&o->threads))return false;break;case 17:if(!number(v,1,300000,&o->timeout_ms))return false;break;
            case 18:if(!strcmp(v,"error"))o->log_level=GENIEX_LOG_LEVEL_ERROR;else if(!strcmp(v,"warn"))o->log_level=GENIEX_LOG_LEVEL_WARN;
                else if(!strcmp(v,"info"))o->log_level=GENIEX_LOG_LEVEL_INFO;else if(!strcmp(v,"debug"))o->log_level=GENIEX_LOG_LEVEL_DEBUG;
                else if(!strcmp(v,"trace"))o->log_level=GENIEX_LOG_LEVEL_TRACE;else return false;
                break;
            default:return false;}
    }
    if(!id_ok(o->id)||!o->mode||!o->runtime||!o->compute||!o->model||!o->prompt||!o->result||!o->text||!strcmp(o->result,o->text))return false;
    bool vlm=!strcmp(o->mode,"vlm"),llama=!strcmp(o->runtime,"llama_cpp");
    if((!vlm&&strcmp(o->mode,"llm"))||(!llama&&strcmp(o->runtime,"qairt")))return false;
    if(strcmp(o->compute,"cpu")&&strcmp(o->compute,"gpu")&&strcmp(o->compute,"npu")&&strcmp(o->compute,"hybrid"))return false;
    if(!vlm&&(o->image||o->mmproj||o->vit))return false;
    if(vlm&&llama&&!o->mmproj)return false;
    if(!llama&&(strcmp(o->compute,"npu")||o->ctx!=0||o->mmproj||o->vit))return false;
    if(o->vit&&strcmp(o->vit,"CPU")&&strcmp(o->vit,"HTP0")&&strcmp(o->vit,"HTP1")&&strcmp(o->vit,"GPUOpenCL"))return false;
    if(!canonical(o->model)||(o->mmproj&&!canonical(o->mmproj))||(o->tokenizer&&!canonical(o->tokenizer)))return false;
    struct stat st;if(stat(o->model,&st)<0||(!S_ISREG(st.st_mode)&&!S_ISDIR(st.st_mode)))return false;
    if(llama&&!S_ISREG(st.st_mode))return false;
    if(o->mmproj&&(stat(o->mmproj,&st)<0||!S_ISREG(st.st_mode)))return false;
    if(o->tokenizer&&(stat(o->tokenizer,&st)<0||!S_ISREG(st.st_mode)))return false;
    return true;
}

enum Phase {PH_INPUT=1,PH_RESOLVE,PH_INIT,PH_CREATE,PH_TEMPLATE,PH_GENERATE,PH_DESTROY,PH_DEINIT,PH_RESULT};
static volatile sig_atomic_t cancel_signal=0,cancel_phase=0,current_phase=PH_INPUT;
static bool deadline_hit=false,callback_limit=false;
static uint64_t start_ns=0,deadline_ns=0,callback_count=0,callback_bytes=0;
static unsigned char callback_raw[OUTPUT_LIMIT];
static size_t callback_retained=0;
static uint64_t monotonic_ns(void) {struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t)<0)return 0;return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;}
static void on_signal(int signal_number) {if(!cancel_signal){cancel_phase=current_phase;cancel_signal=signal_number;}}
static bool fence(enum Phase phase) {
    current_phase=phase;uint64_t now=monotonic_ns();if(!now||now>=deadline_ns)deadline_hit=true;
    return !cancel_signal&&!deadline_hit;
}
static bool on_token(const char *token,void *unused) {
    (void)unused;callback_count++;
    if(!token){callback_limit=true;return false;}
    size_t size=strnlen(token,OUTPUT_LIMIT+1u);
    size_t room=OUTPUT_LIMIT-callback_retained,take=size<room?size:room;
    memcpy(callback_raw+callback_retained,token,take);callback_retained+=take;
    callback_bytes+=size;
    if(size>=room)callback_limit=true;
    return fence(PH_GENERATE)&&!callback_limit;
}
static bool install_signals(void) {
    struct sigaction a;memset(&a,0,sizeof(a));a.sa_handler=on_signal;sigemptyset(&a.sa_mask);
    /* Serialize these handlers so the diagnostic first-signal pair cannot be
     * overwritten by a differently numbered cancellation signal mid-handler. */
    if(sigaddset(&a.sa_mask,SIGTERM)<0||sigaddset(&a.sa_mask,SIGINT)<0||sigaddset(&a.sa_mask,SIGHUP)<0)return false;
    return sigaction(SIGTERM,&a,NULL)==0&&sigaction(SIGINT,&a,NULL)==0&&sigaction(SIGHUP,&a,NULL)==0;
}
static void grammar_free(geniex_ChatTemplateGrammar *g) {
    if(g->triggers){for(int32_t i=0;i<g->trigger_count;i++)geniex_free(g->triggers[i].value);geniex_free(g->triggers);}
    geniex_free(g->grammar);geniex_free(g->generation_prompt);geniex_free(g->preserved_tokens);memset(g,0,sizeof(*g));
}
static void json_string(FILE *f,const char *s) {
    if(!s){fputs("null",f);return;}fputc('"',f);
    for(const unsigned char *p=(const unsigned char*)s;*p;p++){
        if(*p=='"'||*p=='\\'){fputc('\\',f);fputc(*p,f);}else if(*p<32)fprintf(f,"\\u%04x",*p);else fputc(*p,f);
    }fputc('"',f);
}
static void json_double(FILE *f,double v) {if(isfinite(v))fprintf(f,"%.17g",v);else fputs("null",f);}
static void json_rc(FILE *f,bool attempted,int32_t value) {if(attempted)fprintf(f,"%" PRId32,value);else fputs("null",f);}
#include "venus-runtime.inc"

static bool output_metadata(Destination *dest,const Options *o,const Input inputs[4],const char *version,
    const geniex_ResolveDeviceOutput *device,const char *error,bool resolved,bool log_set,bool initialized,bool created,bool templated,bool generated,bool destroyed,
    int32_t resolve_rc,int32_t log_rc,int32_t init_rc,int32_t create_rc,int32_t template_rc,int32_t generate_rc,int32_t destroy_rc,int32_t deinit_rc,
    const geniex_ProfileData *profile,const char *stop,bool output_present,size_t output_size,const char *output_sha,
    bool output_utf8,bool output_truncated,const char *raw_source,bool unchanged,bool complete,const char *outcome,int exit_status,const char *prompt_sha) {
    FILE *f=fdopen(dup(dest->fd),"w");if(!f)return false;
    fputs("{\"schema\":\"hepta.ui-venus-vlm-once.result.v1\",\"production_receipt\":false,\"native_action_authorized\":false,\"process_exit_observed\":false,",f);
    venus_write_contract(f,o,profile,generated);
    hepta_write_phase_timing(f);
    fputs("\"request_id\":",f);json_string(f,o->id);fputs(",\"sdk_source_commit\":\"" SDK_PIN "\",\"sdk_version\":",f);json_string(f,version);
    fputs(",\"mode\":",f);json_string(f,o->mode);fputs(",\"runtime\":",f);json_string(f,o->runtime);fputs(",\"compute_requested\":",f);json_string(f,o->compute);
    fputs(",\"device_resolved\":",f);json_string(f,device->device_id);fputs(",\"device_warning\":",f);json_string(f,device->warning);
    fputs(",\"vit_device_requested\":",f);json_string(f,o->vit);fputs(",\"model_path\":",f);json_string(f,o->model);
    fprintf(f,",\"n_ctx_create\":%d,\"n_gpu_layers_create\":%" PRId32 ",\"max_tokens\":%d,\"generate_attempt_count\":%d,\"automatic_retry\":false,",
        o->ctx,device->ngl,o->max_tokens,generated?1:0);
    fprintf(f,"\"power_mode_create\":%d,\"power_mode_name\":\"sustained_high_performance\",",(int)MODEL_POWER_MODE);
    fputs("\"sampler_requested\":{\"temperature\":0.1,\"top_p\":0.95,\"top_k\":40,\"min_p\":0.05,\"repetition_penalty\":1.05,\"presence_penalty\":0,\"frequency_penalty\":0.3,\"seed\":42},\"image_token_bounds_exposed_by_abi\":false,",f);
    fprintf(f,"\"pid\":%ld,\"pgid\":%ld,\"sid\":%ld,\"signal_observed\":%d,\"first_signal_phase\":%d,\"deadline_observed\":%s,\"callback_limit_observed\":%s,",
        (long)getpid(),(long)getpgrp(),(long)getsid(0),(int)cancel_signal,(int)cancel_phase,deadline_hit?"true":"false",callback_limit?"true":"false");
    fprintf(f,"\"callback_count\":%" PRIu64 ",\"callback_text_bytes\":%" PRIu64 ",\"elapsed_ms\":%.3f,",callback_count,callback_bytes,(double)(monotonic_ns()-start_ns)/1e6);
    fputs("\"sdk_rc\":{\"resolve\":",f);json_rc(f,resolved,resolve_rc);fputs(",\"set_log_level\":",f);json_rc(f,log_set,log_rc);
    fputs(",\"init\":",f);json_rc(f,initialized,init_rc);
    fputs(",\"create\":",f);json_rc(f,created,create_rc);fputs(",\"template\":",f);json_rc(f,templated,template_rc);
    fputs(",\"generate\":",f);json_rc(f,generated,generate_rc);fputs(",\"destroy\":",f);json_rc(f,destroyed,destroy_rc);
    fputs(",\"deinit\":",f);json_rc(f,initialized&&init_rc==0,deinit_rc);fputs("},\"stop_reason\":",f);json_string(f,stop);
    fputs(",\"profile\":",f);
    if(generated){fprintf(f,"{\"ttft_us\":%" PRId64 ",\"media_time_us\":%" PRId64 ",\"prompt_time_us\":%" PRId64 ",\"decode_time_us\":%" PRId64
        ",\"prompt_tokens\":%" PRId64 ",\"generated_tokens\":%" PRId64 ",\"draft_n_total\":%" PRId64 ",\"draft_n_accepted\":%" PRId64 ",\"prefill_tokens_per_second\":",
        profile->ttft,profile->media_time,profile->prompt_time,profile->decode_time,profile->prompt_tokens,profile->generated_tokens,profile->draft_n_total,profile->draft_n_accepted);
    json_double(f,profile->prefill_speed);fputs(",\"decode_tokens_per_second\":",f);json_double(f,profile->decoding_speed);fputc('}',f);
    }else fputs("null",f);
    fputs(",\"input_sha256\":{",f);
    const char *names[4]={"prompt","system","grammar","image"};for(unsigned i=0;i<4;i++){if(i)fputc(',',f);json_string(f,names[i]);fputc(':',f);json_string(f,inputs[i].path?inputs[i].digest:NULL);}
    fputs("},\"formatted_prompt_sha256\":",f);json_string(f,prompt_sha);fputs(",\"raw_text_file\":",f);json_string(f,o->text);
    fprintf(f,",\"raw_text_present\":%s,\"raw_text_bytes\":%zu,\"raw_text_utf8\":%s,\"raw_text_sha256\":",output_present?"true":"false",output_size,output_utf8?"true":"false");json_string(f,output_sha);
    fprintf(f,",\"raw_text_truncated\":%s,\"callback_bytes_retained\":%zu,\"raw_text_source\":",output_truncated?"true":"false",callback_retained);json_string(f,raw_source);
    fprintf(f,",\"input_metadata_unchanged\":%s,\"generation_complete\":%s,\"worker_exit_status_planned\":%d,\"worker_outcome\":",unchanged?"true":"false",complete?"true":"false",exit_status);
    json_string(f,outcome);fputs(",\"error\":",f);json_string(f,error);fputs("}\n",f);
    bool ok=fflush(f)==0&&!ferror(f);if(fclose(f)!=0)ok=false;return ok;
}

int main(int argc,char **argv) {
    Options o;if(argc==2&&!strcmp(argv[1],"--help")){usage();return 0;}
    if(!parse(argc,argv,&o)){usage();return 64;}
    if(strcmp(o.runtime,"llama_cpp")||strcmp(o.mode,"vlm")||!o.image||!o.system||!o.mmproj||
       o.grammar||o.tokenizer||!o.vit||strcmp(o.vit,"GPUOpenCL")||
       (strcmp(o.compute,"gpu")&&strcmp(o.compute,"npu"))||o.ctx!=8192||
       o.max_tokens!=1024||o.threads!=4||o.timeout_ms!=300000){
        fputs("fixed UI-Venus first-frame VLM profile requires image, official system, 8192/1024/4/300000, GPU vision, GPU/NPU LLM\n",stderr);
        return 64;
    }
    const char *required_paths[]={o.prompt,o.system,o.image,o.result,o.text};
    const char *required_names[]={"prompt.txt","system.txt","screen.png","native-result.json","raw.txt"};
    const char *base=strrchr(o.prompt,'/');
    for(unsigned i=0;i<5;i++){
        const char *slash=strrchr(required_paths[i],'/');
        if(!base||!slash||strcmp(slash+1,required_names[i])||slash-required_paths[i]!=base-o.prompt||
           strncmp(required_paths[i],o.prompt,(size_t)(base-o.prompt))){
            fputs("all request inputs/outputs must use fixed names in one private canonical run directory\n",stderr);return 64;
        }
    }
    umask(077);(void)setlocale(LC_NUMERIC,"C");start_ns=monotonic_ns();if(!start_ns)return 74;deadline_ns=start_ns+(uint64_t)o.timeout_ms*1000000u;
    if(!install_signals())return 74;
    Input inputs[4]={{.fd=-1},{.fd=-1},{.fd=-1},{.fd=-1}};
    Destination result={.dir=-1,.fd=-1},text={.dir=-1,.fd=-1};int status=74;
    if(!read_input(&inputs[0],o.prompt,INPUT_LIMIT,true)||!read_input(&inputs[1],o.system,INPUT_LIMIT,true)||
       !read_input(&inputs[2],o.grammar,INPUT_LIMIT,true)||!read_input(&inputs[3],o.image,IMAGE_LIMIT,false)) {
        fputs("input path, ownership, mode, size or UTF-8 differs\n",stderr);status=65;goto final_close;
    }
    if(!reserve_destination(&result,o.result,o.id)||!reserve_destination(&text,o.text,o.id)) {
        fputs("output must be absent in a canonical private directory\n",stderr);status=73;goto final_close;
    }
    /* Native plugins may printf directly. Never put their output in result JSON. */
    if(fflush(stdout)!=0||dup2(STDERR_FILENO,STDOUT_FILENO)<0)goto final_close;
    geniex_ResolveDeviceOutput device={0};geniex_LLM *llm=NULL;geniex_VLM *vlm=NULL;
    bool resolved=false,log_set=false,initialized=false,created=false,templated=false,generated=false,destroyed=false,output_present=false;
    int32_t resolve_rc=0,log_rc=0,init_rc=0,create_rc=0,template_rc=0,generate_rc=0,destroy_rc=0,deinit_rc=0;
    geniex_LlmApplyChatTemplateOutput lt={0};geniex_VlmApplyChatTemplateOutput vt={0};
    geniex_LlmGenerateOutput lo={0};geniex_VlmGenerateOutput vo={0};geniex_ProfileData profile={0};
    const char *error=NULL,*sdk_version=geniex_version(),*version=NULL;
    char version_copy[128]={0},stop_copy[STOP_LIMIT+1]={0},formatted_sha[65]={0},raw_sha[65];
    const char *stop=NULL,*raw_source="absent";unsigned char *raw=NULL;size_t raw_size=0;
    bool raw_utf8=true,raw_truncated=false,sdk_output_present=false,unchanged=true;
    if(sdk_version){size_t size=strnlen(sdk_version,sizeof(version_copy));
        if(size<sizeof(version_copy)&&utf8((const unsigned char*)sdk_version,size)){memcpy(version_copy,sdk_version,size);version=version_copy;}}
    if(!version||(strcmp(version,"v0.10.0")&&strcmp(version,"0.10.0"))){error="runtime_version_differs_from_pinned_abi";goto sdk_cleanup;}
    if(!venus_first_frame(inputs)){error="official_first_frame_inputs_differ";goto sdk_cleanup;}
    hepta_timing_begin(HEPTA_TIMED_HASH);
    bool weights_ok=venus_verify_weights(&o);
    hepta_timing_end(HEPTA_TIMED_HASH);
    if(!weights_ok){error="pinned_model_or_mmproj_identity_failed";goto sdk_cleanup;}
    if(!fence(PH_RESOLVE))goto sdk_cleanup;
    geniex_ResolveDeviceInput resolve={.plugin_id=o.runtime,.mode=o.compute,.ngl_default=-1};
    resolved=true;resolve_rc=geniex_resolve_device(&resolve,&device);if(resolve_rc!=0){error="device_resolution_failed";goto sdk_cleanup;}
    if(!strcmp(o.runtime,"qairt")&&device.ngl!=0){error="qairt_resolved_ngl_nonzero";goto sdk_cleanup;}
    if(device.warning){error="device_was_coerced";goto sdk_cleanup;}
    const char *expected_device=!strcmp(o.compute,"npu")?"HTP0":"GPUOpenCL";
    if(!device.device_id||strcmp(device.device_id,expected_device)||device.ngl==0){
        error="requested_accelerator_not_selected";goto sdk_cleanup;
    }
    if(!fence(PH_INIT))goto sdk_cleanup;
    log_set=true;log_rc=geniex_set_log_level(o.log_level);if(log_rc!=0){error="sdk_log_configuration_failed";goto sdk_cleanup;}
    initialized=true;init_rc=geniex_init();if(init_rc!=0){error="sdk_init_failed";goto sdk_cleanup;}
    geniex_ModelConfig model_config={.n_ctx=o.ctx,.n_threads=o.threads,.n_threads_batch=o.threads,
        .n_gpu_layers=device.ngl,.n_batch=256,.n_ubatch=128,.n_seq_max=1,.spec_type="none",.power_mode=MODEL_POWER_MODE};
    if(!fence(PH_CREATE))goto sdk_cleanup;
    hepta_timing_begin(HEPTA_TIMED_VOCAB);
    bool vocab_ok=venus_load_vocab();
    hepta_timing_end(HEPTA_TIMED_VOCAB);
    if(!vocab_ok){error="pinned_architecture_tokenizer_or_template_failed";goto sdk_cleanup;}
    if(!venus_weights_unchanged()||!input_unchanged(&inputs[3])||!fence(PH_CREATE)){
        error="weight_or_image_changed_before_create";goto sdk_cleanup;
    }
    created=true;
    hepta_timing_begin(HEPTA_TIMED_CREATE);
    if(!strcmp(o.mode,"vlm")){
        geniex_VlmCreateInput in={.model_path=venus_weights[0].fd_path,.mmproj_path=venus_weights[1].fd_path,.config=model_config,.plugin_id=o.runtime,
            .device_id=device.device_id,.vit_device_id=o.vit,.tokenizer_path=o.tokenizer};
        create_rc=geniex_vlm_create(&in,&vlm);
    }else{
        geniex_LlmCreateInput in={.model_path=o.model,.config=model_config,.plugin_id=o.runtime,.device_id=device.device_id,.tokenizer_path=o.tokenizer};
        create_rc=geniex_llm_create(&in,&llm);
    }
    hepta_timing_end(HEPTA_TIMED_CREATE);
    if(create_rc!=0||!vlm||llm){error="vlm_create_failed";goto sdk_cleanup;}
    venus_capabilities_attempted=true;
    venus_capabilities_rc=geniex_vlm_get_capabilities(vlm,&venus_capabilities);
    if(venus_capabilities_rc!=0||!venus_capabilities.supports_vision){
        error="vision_modality_not_available";goto sdk_cleanup;
    }
    if(!fence(PH_TEMPLATE))goto sdk_cleanup;
    templated=true;
    hepta_timing_begin(HEPTA_TIMED_TEMPLATE_TOKENIZE);
    if(vlm){
        geniex_VlmContent sys={.type="text",.text=(char*)inputs[1].bytes};
        geniex_VlmContent user[2]={{.type="text",.text=(char*)inputs[0].bytes},{.type="image",.text=o.image}};
        geniex_VlmChatMessage messages[2]={{.role="system",.contents=&sys,.content_count=1},{.role="user",.contents=user,.content_count=o.image?2:1}};
        geniex_VlmApplyChatTemplateInput in={.messages=messages+(o.system?0:1),.message_count=o.system?2:1,.enable_thinking=true,.parallel_tool_calls=false};
        template_rc=geniex_vlm_apply_chat_template(vlm,&in,&vt);
    }else{
        geniex_LlmChatMessage messages[2]={{.role="system",.content=(char*)inputs[1].bytes},{.role="user",.content=(char*)inputs[0].bytes}};
        geniex_LlmApplyChatTemplateInput in={.messages=messages+(o.system?0:1),.message_count=o.system?2:1,.enable_thinking=false,.add_generation_prompt=true,.parallel_tool_calls=false};
        template_rc=geniex_llm_apply_chat_template(llm,&in,&lt);
    }
    char *prompt=vlm?vt.formatted_text:lt.formatted_text;
    if(template_rc!=0||!prompt){error="chat_template_failed";goto sdk_cleanup;}
    size_t prompt_size=strnlen(prompt,4u*INPUT_LIMIT+1u);
    if(prompt_size>4u*INPUT_LIMIT||!utf8((unsigned char*)prompt,prompt_size)){error="formatted_prompt_invalid_or_oversized";goto sdk_cleanup;}
    hash_bytes(prompt,prompt_size,formatted_sha);
    if(!venus_measure_text(prompt,prompt_size,o.max_tokens,o.ctx)){
        error="formatted_text_alone_exceeds_context_or_tokenizer_failed";goto sdk_cleanup;
    }
    if(!venus_capture_evidence(&o,prompt,prompt_size,&vt.chat_template_grammar)){
        error="exact_prompt_evidence_publication_failed";goto sdk_cleanup;
    }
    venus_release_vocab();
    hepta_timing_end(HEPTA_TIMED_TEMPLATE_TOKENIZE);
    if(!venus_weights_unchanged()||!input_unchanged(&inputs[3])){
        error="weight_or_image_changed_before_generation";goto sdk_cleanup;
    }
    geniex_SamplerConfig sampler={.temperature=0.1f,.top_p=0.95f,.top_k=40,.min_p=0.05f,
        .repetition_penalty=1.05f,.presence_penalty=0.0f,.frequency_penalty=0.3f,.seed=42,
        .grammar_string=NULL,.chat_template_grammar=(geniex_ChatTemplateGrammar){0}};
    geniex_Path image_path=o.image;
    geniex_GenerationConfig generation={.max_tokens=o.max_tokens,.sampler_config=&sampler,
        .image_paths=o.image?&image_path:NULL,.image_count=o.image?1:0,.sliding_window=false};
    if(!fence(PH_GENERATE))goto sdk_cleanup;
    generated=true;
    hepta_timing_begin(HEPTA_TIMED_GENERATE);
    if(vlm){geniex_VlmGenerateInput in={.prompt_utf8=prompt,.config=&generation,.on_token=on_token};generate_rc=geniex_vlm_generate(vlm,&in,&vo);profile=vo.profile_data;}
    else{geniex_LlmGenerateInput in={.prompt_utf8=prompt,.config=&generation,.on_token=on_token};generate_rc=geniex_llm_generate(llm,&in,&lo);profile=lo.profile_data;}
    hepta_timing_end(HEPTA_TIMED_GENERATE);
    (void)fence(PH_GENERATE);
    if(profile.stop_reason){size_t n=strnlen(profile.stop_reason,STOP_LIMIT+1u);
        if(n<=STOP_LIMIT&&utf8((const unsigned char*)profile.stop_reason,n)){memcpy(stop_copy,profile.stop_reason,n);stop=stop_copy;}else error="invalid_sdk_stop_reason";}
    char *returned=vlm?vo.full_text:lo.full_text;
    if(returned){sdk_output_present=true;raw_source="sdk_full_text";raw_size=strnlen(returned,OUTPUT_LIMIT+1u);
        if(raw_size>=OUTPUT_LIMIT){raw_size=OUTPUT_LIMIT;raw_truncated=true;error="returned_output_reached_bound";}
        raw=malloc(raw_size?raw_size:1);if(!raw){error="output_allocation_failed";raw_size=0;}
        else{memcpy(raw,returned,raw_size);output_present=true;raw_utf8=utf8(raw,raw_size);}}
    else if(callback_retained){raw_source="callback_prefix";raw_size=callback_retained;raw_truncated=true;
        raw=malloc(raw_size);if(!raw){error="output_allocation_failed";raw_size=0;}
        else{memcpy(raw,callback_raw,raw_size);output_present=true;raw_utf8=utf8(raw,raw_size);}}
    if(generate_rc!=0&&!error)error="sdk_generate_failed";
sdk_cleanup:
    hepta_timing_end_active();
    venus_release_vocab();
    current_phase=PH_DESTROY;
    if(vlm||llm)hepta_timing_begin(HEPTA_TIMED_DESTROY);
    if(vlm){destroyed=true;destroy_rc=geniex_vlm_destroy(vlm);}
    if(llm){destroyed=true;destroy_rc=geniex_llm_destroy(llm);}
    hepta_timing_end(HEPTA_TIMED_DESTROY);
    geniex_free(vo.full_text);geniex_free(lo.full_text);geniex_free(vt.formatted_text);geniex_free(lt.formatted_text);
    grammar_free(&vt.chat_template_grammar);grammar_free(&lt.chat_template_grammar);
    current_phase=PH_DEINIT;
    if(initialized&&init_rc==0){
        hepta_timing_begin(HEPTA_TIMED_DEINIT);deinit_rc=geniex_deinit();hepta_timing_end(HEPTA_TIMED_DEINIT);
    }
    (void)fence(PH_RESULT);
    for(unsigned i=0;i<4;i++)if(!input_unchanged(&inputs[i]))unchanged=false;
    if(!venus_weights_unchanged()){unchanged=false;if(!error)error="weight_changed_during_request";}
    bool complete=generated&&generate_rc==0&&stop&&(!strcmp(stop,"eos")||!strcmp(stop,"stop_sequence"))&&sdk_output_present&&output_present&&raw_utf8&&!raw_truncated&&
        !error&&!cancel_signal&&!deadline_hit&&!callback_limit&&unchanged&&destroy_rc==0&&deinit_rc==0;
    const char *outcome=complete?"completed":cancel_signal?"signal_observed":deadline_hit?"deadline_observed":"not_completed";
    status=complete?0:cancel_signal?128+(int)cancel_signal:deadline_hit?124:70;
    hash_bytes(raw,raw_size,raw_sha);
    if(!write_all(text.fd,raw,raw_size)||!publish(&text)){fputs("raw output publication failed\n",stderr);status=74;goto sdk_final;}
    /* Cancellation arriving while publishing is still recorded as a fence.
     * A later signal is resolved by the supervising process's own ordering. */
    if(!fence(PH_RESULT)){complete=false;outcome=cancel_signal?"signal_observed":"deadline_observed";status=cancel_signal?128+(int)cancel_signal:124;}
    if(!output_metadata(&result,&o,inputs,version,&device,error,resolved,log_set,initialized,created,templated,generated,destroyed,
       resolve_rc,log_rc,init_rc,create_rc,template_rc,generate_rc,destroy_rc,deinit_rc,&profile,stop,output_present,raw_size,raw_sha,
       raw_utf8,raw_truncated,raw_source,unchanged,complete,outcome,status,formatted_sha[0]?formatted_sha:NULL)||!publish(&result))status=74;
sdk_final:
    free(raw);geniex_free(device.device_id);geniex_free(device.warning);
final_close:
    venus_close_weights();
    for(unsigned i=0;i<4;i++)input_free(&inputs[i]);
    destination_close(&result);destination_close(&text);return status;
}
