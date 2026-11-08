#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
/* A one-shot, CPU-only count using the exact tokenizers-cpp C ABI already
 * exported by the pinned Android libgeniex-proc.so. No model/Genie/QNN API is
 * loaded or called. This JSON is NOT a native process or business receipt.
 * Parent supervision owns waitpid, group cleanup and cancellation ordering. */
#include "vendor/tokenizers_c.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TEXT_LIMIT 65536u
#define IMAGE_LIMIT (8u * 1024u * 1024u)
#define TOKENIZER_LIMIT (32u * 1024u * 1024u)
#define LIBRARY_LIMIT (64u * 1024u * 1024u)
#define TOKEN_RESULT_LIMIT (1024u * 1024u)
#define PROMPT_LIMIT 3584u
#define SDK_PIN "071f609995470bdb0e0769ab964754adfaab7e47"
#define PROC_PIN "6b68dd0de5b9a84c316cc3babfe9f2477d9c6079"
#define FORMATTER_BLOB "41eee100525d06dc9c040b24f44a71cfd0d2d31f"
#define METHOD "exact_sdk_formatted_text_segments_plus_bos_upper_bound"
#define IMAGE_MARKER "<__image__>"

typedef struct { uint32_t h[8]; uint64_t bits; unsigned char block[64]; size_t used; } Sha256;
static uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32u - n)); }
static void sha_block(Sha256 *s, const unsigned char *p) {
    static const uint32_t k[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
    uint32_t w[64],a,b,c,d,e,f,g,h;
    for(unsigned i=0;i<16;i++) w[i]=((uint32_t)p[4*i]<<24)|((uint32_t)p[4*i+1]<<16)|((uint32_t)p[4*i+2]<<8)|p[4*i+3];
    for(unsigned i=16;i<64;i++) { uint32_t x=w[i-15],y=w[i-2];
        w[i]=w[i-16]+(rotr(x,7)^rotr(x,18)^(x>>3))+w[i-7]+(rotr(y,17)^rotr(y,19)^(y>>10)); }
    a=s->h[0];b=s->h[1];c=s->h[2];d=s->h[3];e=s->h[4];f=s->h[5];g=s->h[6];h=s->h[7];
    for(unsigned i=0;i<64;i++) {
        uint32_t t1=h+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^((~e)&g))+k[i]+w[i];
        uint32_t t2=(rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static void sha_init(Sha256 *s) {
    *s=(Sha256){.h={0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u}};
}
static void sha_update(Sha256 *s,const void *data,size_t n) {
    const unsigned char *p=data;s->bits+=(uint64_t)n*8u;
    while(n) {size_t take=64u-s->used;if(take>n)take=n;memcpy(s->block+s->used,p,take);s->used+=take;p+=take;n-=take;
        if(s->used==64u){sha_block(s,s->block);s->used=0;}}
}
static void sha_finish(Sha256 *s,char out[65]) {
    uint64_t bits=s->bits;unsigned char one=0x80,zero=0;sha_update(s,&one,1);
    while(s->used!=56)sha_update(s,&zero,1);
    unsigned char tail[8];for(unsigned i=0;i<8;i++)tail[7-i]=(unsigned char)(bits>>(8*i));sha_update(s,tail,8);
    for(unsigned i=0;i<8;i++)(void)snprintf(out+8*i,9,"%08" PRIx32,s->h[i]);
    out[64]='\0';
}
static void hash_bytes(const void *p,size_t n,char out[65]) {Sha256 s;sha_init(&s);sha_update(&s,p,n);sha_finish(&s,out);}
static bool utf8(const unsigned char *p,size_t n) {
    size_t i=0;
    while(i<n) {uint32_t v;unsigned more;unsigned char c=p[i++];if(c<0x80)continue;
        if(c>=0xc2&&c<=0xdf){v=c&31u;more=1;}else if(c>=0xe0&&c<=0xef){v=c&15u;more=2;}
        else if(c>=0xf0&&c<=0xf4){v=c&7u;more=3;}else return false;
        if(n-i<more)return false;
        for(unsigned j=0;j<more;j++){c=p[i++];if((c&0xc0u)!=0x80u)return false;v=(v<<6)|(c&63u);}
        if((more==1&&v<0x80)||(more==2&&v<0x800)||(more==3&&v<0x10000)||v>0x10ffff||(v>=0xd800&&v<=0xdfff))return false;
    }return true;
}
static bool hex(const char *s,size_t n) {if(!s||strlen(s)!=n)return false;for(size_t i=0;i<n;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return false;return true;}
static bool same_stat(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&
        a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static bool canonical(const char *path) {char real[PATH_MAX];return path&&path[0]=='/'&&strlen(path)<PATH_MAX&&utf8((const unsigned char*)path,strlen(path))&&realpath(path,real)&&!strcmp(real,path);}
static bool private_parent(const char *path) {
    char parent[PATH_MAX];const char *slash=strrchr(path,'/');if(!slash||slash==path)return false;
    size_t n=(size_t)(slash-path);if(n>=sizeof(parent))return false;memcpy(parent,path,n);parent[n]=0;
    struct stat st;return canonical(parent)&&lstat(parent,&st)==0&&S_ISDIR(st.st_mode)&&st.st_uid==getuid()&&(st.st_mode&0777)==0700;
}
typedef struct {const char *path;int fd;struct stat before;unsigned char *bytes;size_t size;char digest[65];bool loaded;} Input;
static bool read_input(Input *in,const char *path,size_t limit,bool text,bool private) {
    in->path=path;if(!path)return true;
    if(!canonical(path)||(private&&!private_parent(path)))return false;
    in->fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(in->fd<0||fstat(in->fd,&in->before)<0||!S_ISREG(in->before.st_mode)||in->before.st_nlink!=1||in->before.st_size<=0||
       (uint64_t)in->before.st_size>limit)return false;
    if(private&&(in->before.st_uid!=getuid()||(in->before.st_mode&0777)!=0600))return false;
    if(!private&&((in->before.st_mode&0022)!=0||(in->before.st_uid!=0&&in->before.st_uid!=getuid())))return false;
    in->size=(size_t)in->before.st_size;in->bytes=malloc(in->size+1);if(!in->bytes)return false;
    size_t done=0;while(done<in->size){ssize_t n=read(in->fd,in->bytes+done,in->size-done);if(n<0&&errno==EINTR)continue;if(n<=0)return false;done+=(size_t)n;}
    unsigned char extra;ssize_t n;do{n=read(in->fd,&extra,1);}while(n<0&&errno==EINTR);if(n!=0)return false;
    in->bytes[in->size]=0;struct stat after,named;
    if(fstat(in->fd,&after)<0||lstat(path,&named)<0||!same_stat(&in->before,&after)||!same_stat(&after,&named))return false;
    if(text&&(memchr(in->bytes,0,in->size)||!utf8(in->bytes,in->size)))return false;
    hash_bytes(in->bytes,in->size,in->digest);in->loaded=true;return true;
}
static bool unchanged(const Input *in) {if(!in->path)return true;struct stat a,b;return in->loaded&&fstat(in->fd,&a)==0&&lstat(in->path,&b)==0&&same_stat(&in->before,&a)&&same_stat(&a,&b);}
static void close_input(Input *in) {if(in->fd>=0)close(in->fd);free(in->bytes);}

typedef struct {int dir,fd;char name[201],pending[240];} Destination;
static bool reserve(Destination *d,const char *path,const char *id) {
    if(!path||path[0]!='/'||strlen(path)>=PATH_MAX||!private_parent(path))return false;
    const char *slash=strrchr(path,'/');size_t n=(size_t)(slash-path);char parent[PATH_MAX];memcpy(parent,path,n);parent[n]=0;
    if(!slash[1]||strlen(slash+1)>200||!utf8((const unsigned char*)(slash+1),strlen(slash+1))||!strcmp(slash+1,".")||!strcmp(slash+1,".."))return false;
    strcpy(d->name,slash+1);d->dir=open(parent,O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);struct stat st;
    if(d->dir<0||fstat(d->dir,&st)<0||st.st_uid!=getuid()||(st.st_mode&0777)!=0700)return false;
    if(fstatat(d->dir,d->name,&st,AT_SYMLINK_NOFOLLOW)==0||errno!=ENOENT)return false;
    (void)snprintf(d->pending,sizeof(d->pending),"%s.%s.pending",d->name,id);
    d->fd=openat(d->dir,d->pending,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);return d->fd>=0;
}
static bool publish(Destination *d) {return fsync(d->fd)==0&&linkat(d->dir,d->pending,d->dir,d->name,0)==0&&unlinkat(d->dir,d->pending,0)==0&&fsync(d->dir)==0;}
static void close_destination(Destination *d) {if(d->fd>=0)close(d->fd);if(d->dir>=0)close(d->dir);}
static void json_string(FILE *f,const char *s) {
    if(!s){fputs("null",f);return;}fputc('"',f);
    for(const unsigned char *p=(const unsigned char*)s;*p;p++){if(*p=='"'||*p=='\\'){fputc('\\',f);fputc(*p,f);}else if(*p<32)fprintf(f,"\\u%04x",*p);else fputc(*p,f);}fputc('"',f);
}
typedef struct {const char *id,*library,*library_sha,*tokenizer,*tokenizer_sha,*prompt,*system,*image,*result,*max_prompt;} Options;
static bool parse(int argc,char **argv,Options *o) {
    const char *names[]={"--request-id","--library","--library-sha256","--tokenizer","--tokenizer-sha256","--prompt-file","--system-file","--image","--result-file","--max-prompt"};
    const char **dest[]={&o->id,&o->library,&o->library_sha,&o->tokenizer,&o->tokenizer_sha,&o->prompt,&o->system,&o->image,&o->result,&o->max_prompt};
    if(argc<1||(argc%2)!=1)return false;
    for(int i=1;i<argc;i+=2){size_t j;for(j=0;j<sizeof(names)/sizeof(names[0]);j++)if(!strcmp(argv[i],names[j]))break;
        if(j==sizeof(names)/sizeof(names[0])||*dest[j])return false;
        *dest[j]=argv[i+1];}
    return hex(o->id,32)&&hex(o->library_sha,64)&&hex(o->tokenizer_sha,64)&&o->library&&o->tokenizer&&o->prompt&&o->system&&o->result&&o->max_prompt&&!strcmp(o->max_prompt,"3584");
}
typedef struct {
    TokenizerHandle (*create)(const char*,size_t);
    void (*encode)(TokenizerHandle,const char*,size_t,int,TokenizerEncodeResult*);
    void (*free_results)(TokenizerEncodeResult*,size_t);
    void (*destroy)(TokenizerHandle);
} Api;
static bool symbol(void *lib,const char *name,void *out,size_t size) {void *p=dlsym(lib,name);if(!p||size!=sizeof(p))return false;memcpy(out,&p,size);return true;}
static bool load_api(void *lib,Api *a) {
    return symbol(lib,"tokenizers_new_from_str",&a->create,sizeof(a->create))&&symbol(lib,"tokenizers_encode",&a->encode,sizeof(a->encode))&&
        symbol(lib,"tokenizers_free_encode_results",&a->free_results,sizeof(a->free_results))&&symbol(lib,"tokenizers_free",&a->destroy,sizeof(a->destroy));
}
typedef struct {char *bytes;size_t size,count;char digest[65];bool counted;} Segment;
static bool segment(Segment *s,const char *a,const Input *x,const char *b,const Input *y,const char *c) {
    size_t na=strlen(a),nb=strlen(b),nc=strlen(c),nx=x?x->size:0,ny=y?y->size:0;
    s->size=na+nx+nb+ny+nc;s->bytes=malloc(s->size+1);if(!s->bytes)return false;
    char *p=s->bytes;memcpy(p,a,na);p+=na;if(x){memcpy(p,x->bytes,nx);p+=nx;}memcpy(p,b,nb);p+=nb;if(y){memcpy(p,y->bytes,ny);p+=ny;}memcpy(p,c,nc);p[nc]=0;
    hash_bytes(s->bytes,s->size,s->digest);return true;
}
static bool count(Api *api,TokenizerHandle handle,Segment *s) {
    TokenizerEncodeResult r={0};api->encode(handle,s->bytes,s->size,0,&r);
    bool ok=r.token_ids&&r.len>0&&r.len<=TOKEN_RESULT_LIMIT;
    if(ok)for(size_t i=0;i<r.len;i++)if(r.token_ids[i]<0){ok=false;break;}
    if(ok){s->count=r.len;s->counted=true;}
    if(r.token_ids)api->free_results(&r,1);
    return ok;
}
static bool is_image(const Input *in) {
    static const unsigned char png[]={137,80,78,71,13,10,26,10};
    return (in->size>=8&&!memcmp(in->bytes,png,8))||(in->size>=3&&in->bytes[0]==255&&in->bytes[1]==216&&in->bytes[2]==255);
}
static bool record(Destination *dest,const Options *o,const Input files[5],const Segment segments[2],size_t nsegments,
                   const char *status,const char *error,bool inputs_ok,size_t total,bool counted) {
    FILE *f=fdopen(dup(dest->fd),"w");if(!f)return false;
    fputs("{\"schema\":\"hepta.geniex-token-count.v1\",\"request_id\":",f);json_string(f,o->id);
    fputs(",\"method\":\"" METHOD "\",\"is_exact_token_count\":false,\"status\":",f);json_string(f,status);
    fprintf(f,",\"success\":%s,\"error\":",!strcmp(status,"success")?"true":"false");json_string(f,error);
    fprintf(f,",\"pid\":%ld,\"pgid\":%ld,\"sid\":%ld",(long)getpid(),(long)getpgrp(),(long)getsid(0));
    fprintf(f,",\"input_unchanged\":%s,\"raw_input_preserved\":%s",inputs_ok?"true":"false",inputs_ok?"true":"false");
    fputs(",\"input_sha256\":{",f);const char *names[]={"prompt","system","image"};
    for(size_t i=0;i<3;i++){if(i)fputc(',',f);json_string(f,names[i]);fputc(':',f);json_string(f,files[i].loaded?files[i].digest:NULL);}fputc('}',f);
    fputs(",\"input_bytes\":{",f);for(size_t i=0;i<3;i++){if(i)fputc(',',f);json_string(f,names[i]);fprintf(f,":%zu",files[i].loaded?files[i].size:0);}fputc('}',f);
    fputs(",\"tokenizer_sha256\":",f);json_string(f,files[3].loaded?files[3].digest:NULL);fputs(",\"library_sha256\":",f);json_string(f,files[4].loaded?files[4].digest:NULL);
    fputs(",\"segment_token_counts\":[",f);for(size_t i=0;i<nsegments;i++){if(i)fputc(',',f);if(segments[i].counted)fprintf(f,"%zu",segments[i].count);else fputs("null",f);}fputc(']',f);
    fputs(",\"segment_utf8_bytes\":[",f);for(size_t i=0;i<nsegments;i++){if(i)fputc(',',f);fprintf(f,"%zu",segments[i].size);}fputc(']',f);
    fputs(",\"segment_sha256\":[",f);for(size_t i=0;i<nsegments;i++){if(i)fputc(',',f);json_string(f,segments[i].bytes?segments[i].digest:NULL);}fputc(']',f);
    fputs(",\"formatted_text_tokens\":",f);if(counted)fprintf(f,"%zu",total);else fputs("null",f);
    unsigned pads=o->image?256u:0u,boundary=o->image?2u:0u;
    fprintf(f,",\"formatter_overhead_utf8_bytes\":80,\"image_pad_tokens\":%u,\"vision_boundary_tokens\":%u,\"bos_token_upper_bound\":1",pads,boundary);
    fputs(",\"prompt_tokens_upper_bound\":",f);if(counted)fprintf(f,"%zu",total+pads+boundary+1u);else fputs("null",f);
    fputs(",\"context_tokens\":4096,\"max_prompt_tokens\":3584,\"generation_tokens\":256,\"reserved_tokens\":256,\"ffi_add_special_tokens\":false",f);
    fputs(",\"sdk_commit\":\"" SDK_PIN "\",\"processor_commit\":\"" PROC_PIN "\",\"processor_blob\":\"" FORMATTER_BLOB "\",\"model_loaded\":false,\"native_receipt\":false}\n",f);
    bool ok=!ferror(f)&&fflush(f)==0;if(fclose(f)!=0)ok=false;return ok;
}
int main(int argc,char **argv) {
    Options o={0};if(!parse(argc,argv,&o)){fputs("invalid token counter arguments\n",stderr);return 64;}
    umask(077);alarm(3);
    const struct rlimit no_core={0,0};
    if(setrlimit(RLIMIT_CORE,&no_core)<0||dup2(STDERR_FILENO,STDOUT_FILENO)<0)return 1;
    Destination dest={.dir=-1,.fd=-1};Input files[5]={{.fd=-1},{.fd=-1},{.fd=-1},{.fd=-1},{.fd=-1}};
    Segment segments[2]={{0},{0}};size_t nsegments=0,total=0;bool counted=false,inputs_ok=false;
    void *lib=NULL;TokenizerHandle handle=NULL;Api api={0};const char *error=NULL,*status="error";int exit_code=1;
    if(!reserve(&dest,o.result,o.id)){fputs("private create-only result reservation failed\n",stderr);close_destination(&dest);return 1;}
    if(!read_input(&files[0],o.prompt,TEXT_LIMIT,true,true)||!read_input(&files[1],o.system,TEXT_LIMIT,true,true)||
       !read_input(&files[2],o.image,IMAGE_LIMIT,false,true)||!read_input(&files[3],o.tokenizer,TOKENIZER_LIMIT,true,false)||
       !read_input(&files[4],o.library,LIBRARY_LIMIT,false,false)){error="input_file_invalid";goto done;}
    if(strcmp(files[3].digest,o.tokenizer_sha)||strcmp(files[4].digest,o.library_sha)){error="artifact_sha256_mismatch";goto done;}
    if(strstr((char*)files[0].bytes,IMAGE_MARKER)||strstr((char*)files[1].bytes,IMAGE_MARKER)){error="reserved_image_marker_in_text";goto done;}
    if(o.image&&!is_image(&files[2])){error="image_format_invalid";goto done;}
    /* The library is loaded through its still-open, SHA-checked fd, preventing
     * a pathname swap from silently selecting a different ELF. Its pinned
     * DT_NEEDED entries are Android log/m/dl/c only. */
    char fdpath[64];(void)snprintf(fdpath,sizeof(fdpath),"/proc/self/fd/%d",files[4].fd);
    lib=dlopen(fdpath,RTLD_NOW|RTLD_LOCAL);if(!lib){error="tokenizer_library_load_failed";goto done;}
    if(!load_api(lib,&api)){error="tokenizer_ffi_symbol_missing";goto done;}
    handle=api.create((char*)files[3].bytes,files[3].size);if(!handle){error="tokenizer_create_failed";goto done;}
    /* Qwen2VLProcessor::build_template_text and build_input_ids_from_text at
     * the source pins above. The SDK encodes whole segments, not independent
     * raw system/owner text. NFC, added-token matching and BPE stay in the
     * actual pinned Rust tokenizer. Fixed image preprocessing is 512x512,
     * patch16/merge2 => 256 pads; start/end add two tokens. The core pipeline
     * may prepend at most one BOS. We preserve that one-token upper bound. */
    const char *head="<|im_start|>system\n",*middle="<|im_end|>\n<|im_start|>user\n",*tail="<|im_end|>\n<|im_start|>assistant\n";
    nsegments=o.image?2u:1u;
    if(o.image){if(!segment(&segments[0],head,&files[1],middle,NULL,"")||!segment(&segments[1],"",&files[0],tail,NULL,"")){error="allocation_failed";goto done;}}
    else if(!segment(&segments[0],head,&files[1],middle,&files[0],tail)){error="allocation_failed";goto done;}
    for(size_t i=0;i<nsegments;i++){if(!count(&api,handle,&segments[i])){error="tokenizer_encode_result_invalid";goto done;}total+=segments[i].count;}
    counted=true;
    if(total+(o.image?258u:0u)+1u>PROMPT_LIMIT){status="oversize";error="prompt_exceeds_3584_tokens";exit_code=2;}
    else {status="success";exit_code=0;}
done:
    if(handle)api.destroy(handle);
    if(lib&&dlclose(lib)!=0){status="error";error="tokenizer_library_close_failed";exit_code=1;}
    inputs_ok=true;for(size_t i=0;i<5;i++)if(!unchanged(&files[i]))inputs_ok=false;
    if(!inputs_ok&&strcmp(status,"error")){status="error";error="input_changed";exit_code=1;}
    if(!record(&dest,&o,files,segments,nsegments,status,error,inputs_ok,total,counted)||!publish(&dest))exit_code=1;
    for(size_t i=0;i<2;i++)free(segments[i].bytes);
    for(size_t i=0;i<5;i++)close_input(&files[i]);
    close_destination(&dest);
    alarm(0);return exit_code;
}
