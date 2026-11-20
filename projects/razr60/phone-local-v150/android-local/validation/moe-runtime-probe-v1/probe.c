/* Independent local-only GenieX 0.10 / Hexagon probe. No UI or download APIs. */
#define _GNU_SOURCE
#include "vendor/geniex.h"
#include <stdatomic.h>
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MIB (UINT64_C(1024)*1024)
#define GIB (UINT64_C(1024)*1024*1024)
#define RESERVE_BYTES (UINT64_C(3072)*MIB)
#define OVERHEAD_BYTES (UINT64_C(1536)*MIB)
#define MAX_MODEL_BYTES (UINT64_C(12)*GIB)
#define OUTPUT_LIMIT (UINT64_C(16)*MIB)
#ifndef PROBE_WALL_SECONDS
#define PROBE_WALL_SECONDS 240
#endif
#define SDK_COMMIT "071f609995470bdb0e0769ab964754adfaab7e47"
#define LLAMA_COMMIT "19cce6919992fdffd92e0ac152caaf1e2b8f254e"
#define HEADER_SHA "c5d441ee290c5ec83f01ec1af9a7c16cdd8c740b522b78c23ed667062fc21e40"
#define RELEASE_SHA "248b49c83bc74238babc0d9ebf46f0c8b6d2e9b6de3ffb90c2a5a2042523831f"

/* SHA256 implementation; known-answer checks run before every invocation. */
typedef struct { uint32_t h[8]; uint64_t bytes; unsigned used; unsigned char b[64]; } Sha;
static uint32_t rr(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
static void sha_block(Sha*s,const unsigned char*p){
 static const uint32_t k[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
 uint32_t w[64],a,b,c,d,e,f,g,h;
 for(unsigned i=0;i<16;i++)w[i]=((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|p[i*4+3];
 for(unsigned i=16;i<64;i++)w[i]=w[i-16]+(rr(w[i-15],7)^rr(w[i-15],18)^(w[i-15]>>3))+w[i-7]+(rr(w[i-2],17)^rr(w[i-2],19)^(w[i-2]>>10));
 a=s->h[0];b=s->h[1];c=s->h[2];d=s->h[3];e=s->h[4];f=s->h[5];g=s->h[6];h=s->h[7];
 for(unsigned i=0;i<64;i++){uint32_t t=h+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^(~e&g))+k[i]+w[i];uint32_t u=(rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&c)^(b&c));h=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+u;}
 s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static void sha_init(Sha*s){*s=(Sha){.h={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}};}
static void sha_update(Sha*s,const void*v,size_t n){const unsigned char*p=v;s->bytes+=n;while(n){size_t z=64-s->used;if(z>n)z=n;memcpy(s->b+s->used,p,z);s->used+=(unsigned)z;p+=z;n-=z;if(s->used==64){sha_block(s,s->b);s->used=0;}}}
static void sha_final(Sha*s,char out[65]){uint64_t bits=s->bytes*8;s->b[s->used++]=128;if(s->used>56){memset(s->b+s->used,0,64-s->used);sha_block(s,s->b);s->used=0;}memset(s->b+s->used,0,56-s->used);for(unsigned i=0;i<8;i++)s->b[63-i]=(unsigned char)(bits>>(8*i));sha_block(s,s->b);for(unsigned i=0;i<8;i++)snprintf(out+i*8,9,"%08" PRIx32,s->h[i]);out[64]=0;}
static bool sha_test(void){Sha s;char out[65];sha_init(&s);sha_final(&s,out);if(strcmp(out,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))return false;sha_init(&s);sha_update(&s,"abc",3);sha_final(&s,out);if(strcmp(out,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))return false;sha_init(&s);for(unsigned i=0;i<1000000;i++)sha_update(&s,"a",1);sha_final(&s,out);return strcmp(out,"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")==0;}
static int hash_fd(int fd,char out[65]){unsigned char b[65536];Sha s;sha_init(&s);if(lseek(fd,0,SEEK_SET)<0)return -1;for(;;){ssize_t n=read(fd,b,sizeof b);if(n<0){if(errno==EINTR)continue;return -1;}if(!n)break;sha_update(&s,b,(size_t)n);}sha_final(&s,out);return lseek(fd,0,SEEK_SET)<0?-1:0;}

typedef struct {const char *path,*sha;uint64_t bytes;} Pin;
static const Pin pins[]={
 {"libgeniex.so","99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56",19781824},
 {"llama_cpp/libggml-cpu.so","b603d578bb3beb0c3727be748f327c002619827df701bf0b894632272670943b",936328},
 {"llama_cpp/libggml-base.so","bdd15d0ea024fd34a64d2eba32de79f615d35b79253e25b27b1440944fa6df40",3534496},
 {"llama_cpp/libggml-opencl.so","e395cf83e695aa9d21dd90a89460f936742c7c8c706cfbbdfa647dd316dd0875",7886880},
 {"llama_cpp/libmtmd.so","ccf32e264cdccc6378d5e4e005f4aedae39eb3e9a198550c5f7f3a4583bcaa4d",1643536},
 {"llama_cpp/libggml-hexagon.so","67b886eb9bcdd298268a8463d74f07da4213024fe7ed89911c2e76c9e0d1491f",3874328},
 {"llama_cpp/libggml-htp-v73.so","e8ed08627e9faa5739c6185187a2c3dbe0a2ac7d0a9aded15fea3f1009de18c8",842432},
 {"llama_cpp/libllama-common.so","8b05589a739339dd38ad524e9733d89650ef40b0a83fe3a95ff83716c98c6122",6242864},
 {"llama_cpp/libgeniex_plugin.so","cc186649cc0dab10240395f89d14d007e62b3bc78283060027d37ee80a21604a",377040},
 {"llama_cpp/libggml-htp-v85.so","3a4c104a0a12b2b63245f1f866f0f37bff0be5eebc08d104678a71a379618c7a",871232},
 {"llama_cpp/libggml-htp-v75.so","bd7837ec03fd123cb0cf33608fb0d8c7d49f86fdd4001683e0918b72f0f1ca07",838272},
 {"llama_cpp/libggml-htp-v79.so","110d9e6ff7cff02fa73b0a3c03d8259222758934bdbcae5c819dae6729f362d5",858848},
 {"llama_cpp/libllama.so","4bb7bd0f4fe0bd24ac32a80f920838fd2f525430ad58c5d5742cc745f7d0b835",5642424},
 {"llama_cpp/libggml.so","5dff1d15e528d1accb1704a1049a6556784cbfc32131fb64cef5c8847c171149",41088},
 {"llama_cpp/libggml-htp-v81.so","1bd534df154a45a261aeedaf7be316d01e4f6c0d2c18ed2c235e991c74160d00",871232},
 {"llama_cpp/libomp.so","b0b507bb9e89360304272ba335d5fb2f6661f88842c2b3c749474cb7b8acda76",1234864}
};
#define NPINS (sizeof pins/sizeof pins[0])
typedef struct {const char *runtime,*model,*sha,*source,*output;uint64_t bytes;bool run;bool test_watchdog;} Options;
static FILE *events;
static double epoch;
static volatile sig_atomic_t interrupted;
static atomic_int observed_context,observed_model,callback_overflow;
static unsigned callback_count;
static size_t raw_bytes;
static int raw_fd=-1;
static double now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;return (double)t.tv_sec+t.tv_nsec/1e9;}
static void json_str(FILE*f,const char*s){if(!s){fputs("null",f);return;}fputc('"',f);for(size_t i=0;s[i];i++){unsigned char c=(unsigned char)s[i];if(c=='"'||c=='\\'){fputc('\\',f);fputc(c,f);}else if(c<32||c>=127)fprintf(f,"\\u%04x",c);else fputc(c,f);}fputc('"',f);}
static void event(const char*stage,const char*status,int rc,const char*detail){flockfile(events);fprintf(events,"{\"elapsed_ms\":%.3f,\"stage\":",(now()-epoch)*1000);json_str(events,stage);fputs(",\"status\":",events);json_str(events,status);fprintf(events,",\"rc\":%d,\"detail\":",rc);json_str(events,detail);fputs("}\n",events);fflush(events);funlockfile(events);}
static void signal_handler(int sig){interrupted=sig;}
static bool same_stat(const struct stat*a,const struct stat*b){return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_size==b->st_size&&a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;}
static uint64_t mem_available(void){FILE*f=fopen("/proc/meminfo","r");if(!f)return 0;char b[256];uint64_t value=0;while(fgets(b,sizeof b,f)){unsigned long long k;if(sscanf(b,"MemAvailable: %llu kB",&k)==1){value=(uint64_t)k*1024;break;}}fclose(f);return value;}
static uint64_t resident(pid_t pid){char p[64],b[256];snprintf(p,sizeof p,"/proc/%ld/status",(long)pid);FILE*f=fopen(p,"r");if(!f)return 0;uint64_t z=0;while(fgets(b,sizeof b,f)){unsigned long long k;if(sscanf(b,"VmRSS: %llu kB",&k)==1||sscanf(b,"VmSwap: %llu kB",&k)==1)z+=(uint64_t)k*1024;}fclose(f);return z;}
static int bounded_path(char*out,size_t n,const char*a,const char*b){int r=snprintf(out,n,"%s/%s",a,b);return r<0||(size_t)r>=n?-1:0;}
static int regular_open(const char*p,uint64_t size,struct stat*st){int fd=open(p,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;if(fstat(fd,st)||!S_ISREG(st->st_mode)||(uint64_t)st->st_size!=size){close(fd);errno=EINVAL;return -1;}return fd;}
static int set_limit(int resource,rlim_t soft,rlim_t hard){struct rlimit r={soft,hard};return setrlimit(resource,&r);}
extern char **environ;
static int fixed_hexagon_environment(void){
 for(;;){
  const char*entry=NULL;
  for(char**p=environ;p&&*p;p++)if(!strncmp(*p,"GGML_HEXAGON_",13)){entry=*p;break;}
  if(!entry)break;
  const char*eq=strchr(entry,'=');if(!eq||eq-entry>=128)return -1;
  char key[128];memcpy(key,entry,(size_t)(eq-entry));key[eq-entry]=0;
  if(unsetenv(key))return -1;
 }
 return setenv("GGML_HEXAGON_DEVICES","1",1)||setenv("GGML_HEXAGON_VERBOSE","1",1)?-1:0;
}
static void sdk_log(geniex_LogLevel level,const char*msg){
 if(!msg)return;
 const char*p=strstr(msg,"[Optimise] context params: ");
 if(p){int c=0,b=0,u=0,s=0,t=0,tb=0;int n=sscanf(p,"[Optimise] context params: n_ctx=%d, n_batch=%d, n_ubatch=%d, n_seq_max=%d, n_threads=%d, n_threads_batch=%d",&c,&b,&u,&s,&t,&tb);atomic_store(&observed_context,n==6&&c==2048&&b==128&&u==128&&s==1&&t==4&&tb==4?1:-1);}
 if(strstr(msg,"[Optimise] model params: "))atomic_store(&observed_model,strstr(msg,"n_gpu_layers=-1")&&strstr(msg,"load_mode=none")?1:-1);
 char clipped[4097];size_t n=strnlen(msg,sizeof clipped-1);memcpy(clipped,msg,n);clipped[n]=0;event("sdk_log","observed",(int)level,clipped);
}
static bool token_cb(const char*token,void*opaque){(void)opaque;callback_count++;if(!token)return true;size_t n=strnlen(token,16385);if(n>16384||raw_bytes+n>16384||callback_count>256){atomic_store(&callback_overflow,1);return false;}size_t off=0;while(off<n){ssize_t w=write(raw_fd,token+off,n-off);if(w<0){if(errno==EINTR)continue;atomic_store(&callback_overflow,1);return false;}off+=(size_t)w;}raw_bytes+=n;return true;}

typedef struct {
 int32_t(*init)(void);int32_t(*deinit)(void);
 int32_t(*set_log)(geniex_log_callback);int32_t(*set_log_level)(geniex_LogLevel);
 const char*(*version)(void);const char*(*plugin_version)(geniex_PluginId);
 void(*free_)(void*);
 int32_t(*resolve)(const geniex_ResolveDeviceInput*,geniex_ResolveDeviceOutput*);
 int32_t(*devices)(const geniex_GetDeviceListInput*,geniex_GetDeviceListOutput*);
 int32_t(*create)(const geniex_LlmCreateInput*,geniex_LLM**);
 int32_t(*destroy)(geniex_LLM*);
 int32_t(*info)(geniex_LLM*,geniex_LlmModelInfo*);
 int32_t(*generate)(geniex_LLM*,const geniex_LlmGenerateInput*,geniex_LlmGenerateOutput*);
} Api;
#define SYM(member,name) do{void*s=dlsym(handle,name);if(!s){event("dlsym","failed",70,name);return 70;}memcpy(&a.member,&s,sizeof s);}while(0)
static int load_api(void*handle,Api*out){Api a={0};SYM(init,"geniex_init");SYM(deinit,"geniex_deinit");SYM(set_log,"geniex_set_log");SYM(set_log_level,"geniex_set_log_level");SYM(version,"geniex_version");SYM(plugin_version,"geniex_get_plugin_version");SYM(free_,"geniex_free");SYM(resolve,"geniex_resolve_device");SYM(devices,"geniex_get_device_list");SYM(create,"geniex_llm_create");SYM(destroy,"geniex_llm_destroy");SYM(info,"geniex_llm_get_model_info");SYM(generate,"geniex_llm_generate");*out=a;return 0;}
#undef SYM

static bool layout_ok(const char*root){
 DIR*d=opendir(root);if(!d)return false;
 bool ok=true;struct dirent*e;char p[PATH_MAX];struct stat st;
 while((e=readdir(d))){
  if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;
  if(bounded_path(p,sizeof p,root,e->d_name)||lstat(p,&st)){ok=false;break;}
  if(S_ISDIR(st.st_mode)){if(strcmp(e->d_name,"llama_cpp")){ok=false;break;}}
  else if(S_ISLNK(st.st_mode)||(strstr(e->d_name,".so")&&strcmp(e->d_name,"libgeniex.so"))){ok=false;break;}
 }
 closedir(d);if(!ok)return false;
 if(bounded_path(p,sizeof p,root,"llama_cpp"))return false;
 d=opendir(p);if(!d)return false;
 while((e=readdir(d))){
  if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;
  char rel[PATH_MAX],file[PATH_MAX];
  if(bounded_path(rel,sizeof rel,"llama_cpp",e->d_name)||bounded_path(file,sizeof file,root,rel)||lstat(file,&st)){ok=false;break;}
  bool pinned=false;for(size_t i=0;i<NPINS;i++)if(!strcmp(pins[i].path,rel))pinned=true;
  if(S_ISDIR(st.st_mode)||S_ISLNK(st.st_mode)||(strstr(e->d_name,".so")&&!pinned)){ok=false;break;}
 }
 closedir(d);return ok;
}
static int run_worker(const Options*o,uint64_t rss_cap,uint64_t as_cap,pid_t expected_parent){
 int code=70,model_fd=-1,lib_fds[NPINS];struct stat lib_stats[NPINS],model_stat,after;char p[PATH_MAX],digest[65],detail[1024];
 for(size_t i=0;i<NPINS;i++)lib_fds[i]=-1;
 if(setpgid(0,0)||prctl(PR_SET_PDEATHSIG,SIGKILL)||set_limit(RLIMIT_CORE,0,0)||set_limit(RLIMIT_FSIZE,OUTPUT_LIMIT,OUTPUT_LIMIT)||set_limit(RLIMIT_NOFILE,256,256)||set_limit(RLIMIT_CPU,180,181)||set_limit(RLIMIT_AS,as_cap,as_cap)){event("resource_limits","failed",errno,"no SDK loaded");return 70;}
 if(getppid()!=expected_parent)return 70;
 (void)setpriority(PRIO_PROCESS,0,10);
 snprintf(detail,sizeof detail,"reserve_bytes=%" PRIu64 ",rss_plus_swap_cap_bytes=%" PRIu64 ",rlimit_as_bytes=%" PRIu64 ",wall_seconds=%d,cpu_seconds=180",RESERVE_BYTES,rss_cap,as_cap,PROBE_WALL_SECONDS);event("resource_limits","set",0,detail);
#ifdef PROBE_TEST_BUILD
 if(o->test_watchdog){event("test_only","child_sleeping",0,"no SDK/model/device calls");for(;;)pause();}
#endif
 model_fd=regular_open(o->model,o->bytes,&model_stat);if(model_fd<0){event("model","preflight_blocked",errno,"model missing, symlinked, nonregular, or size mismatch");code=66;goto done;}
 unsigned char magic[4];if(pread(model_fd,magic,4,0)!=4||memcmp(magic,"GGUF",4)){event("model","preflight_blocked",65,"GGUF magic mismatch");code=65;goto done;}
 if(mem_available()<o->bytes+OVERHEAD_BYTES+RESERVE_BYTES){event("memory","preflight_blocked",75,"MemAvailable below model bytes + 1536 MiB estimated overhead + 3072 MiB reserve; no override");code=75;goto done;}
 event("model_hash","started",0,"full SHA256 via retained read-only descriptor");
 if(hash_fd(model_fd,digest)||strcmp(digest,o->sha)||fstat(model_fd,&after)||!same_stat(&model_stat,&after)){event("model_hash","preflight_blocked",65,"model SHA256 mismatch/read failure/metadata changed");code=65;goto done;}
 event("model_hash","verified",0,digest);
 if(!layout_ok(o->runtime)){event("runtime_layout","preflight_blocked",65,"requires only the pinned llama_cpp plugin; no QAIRT/extra shared objects/symlinks");code=65;goto done;}
 for(size_t i=0;i<NPINS;i++){
  if(bounded_path(p,sizeof p,o->runtime,pins[i].path)){code=64;goto done;}
  lib_fds[i]=regular_open(p,pins[i].bytes,&lib_stats[i]);
  if(lib_fds[i]<0||hash_fd(lib_fds[i],digest)||strcmp(digest,pins[i].sha)||fstat(lib_fds[i],&after)||!same_stat(&lib_stats[i],&after)){event("runtime_hash","preflight_blocked",65,pins[i].path);code=65;goto done;}
  event("runtime_hash","verified",0,pins[i].path);
 }
 if(!o->run){event("preflight","ready_not_executed",0,"identities and conservative admission passed; model inference NOT executed");code=0;goto done;}
 if(mem_available()<o->bytes+OVERHEAD_BYTES+RESERVE_BYTES){event("memory","preflight_blocked",75,"memory changed after hashing; no SDK loaded");code=75;goto done;}
 if(setenv("GENIEX_PLUGIN_PATH",o->runtime,1)||fixed_hexagon_environment()){code=70;goto done;}
 /* No model-manager pull, HTTP, activity, input, display, ADB, or settings API. */
 if(bounded_path(p,sizeof p,o->runtime,"libgeniex.so")){code=64;goto done;}
 event("runtime_load","started",0,p);void*handle=dlopen(p,RTLD_NOW|RTLD_LOCAL);if(!handle){event("runtime_load","failed",70,dlerror());code=70;goto done;}
 Api a={0};if(load_api(handle,&a)){code=70;goto done;}
 if(a.set_log(sdk_log)||a.set_log_level(GENIEX_LOG_LEVEL_INFO)){event("logging","failed",70,"required SDK actual-parameter logging unavailable");code=70;goto done;}
 event("sdk_version","observed",0,a.version());
 int32_t rc=a.init();event("sdk_init",rc?"failed":"complete",rc,NULL);if(rc){code=70;goto done;}
 geniex_LLM*model=NULL;geniex_ResolveDeviceOutput resolved={0};geniex_GetDeviceListOutput devs={0};geniex_LlmGenerateOutput out={0};
 geniex_ResolveDeviceInput ri={.plugin_id="llama_cpp",.mode="npu",.ngl_default=-1};
 rc=a.resolve(&ri,&resolved);event("resolve_device",rc?"failed":"observed",rc,resolved.device_id);
 if(rc||!resolved.device_id||strcmp(resolved.device_id,"HTP0")||resolved.ngl!=-1||resolved.warning){event("resolve_device","failed",70,"HTP0/-1 without warning required; no fallback");goto sdk_done;}
 geniex_GetDeviceListInput di={.plugin_id="llama_cpp"};rc=a.devices(&di,&devs);bool has_htp=false;
 if(!rc&&devs.device_count>=0&&devs.device_count<256){for(int32_t i=0;i<devs.device_count;i++){const char*id=devs.device_ids?devs.device_ids[i]:NULL;event("enumerated_device","observed",i,id);if(id&&!strcmp(id,"HTP0"))has_htp=true;}}
 if(rc||!has_htp){event("enumerate","failed",rc,"required HTP0 absent; no CPU/GPU fallback");goto sdk_done;}
 event("llama_cpp_version","observed",0,a.plugin_version("llama_cpp"));
 char model_descriptor[64];snprintf(model_descriptor,sizeof model_descriptor,"/proc/self/fd/%d",model_fd);
 geniex_ModelConfig cfg={.n_ctx=2048,.n_threads=4,.n_threads_batch=4,.n_batch=128,.n_ubatch=128,.n_seq_max=1,.n_gpu_layers=-1,.spec_type="none",.power_mode=GENIEX_POWER_MODE_SUSTAINED_HIGH_PERFORMANCE};
 geniex_LlmCreateInput ci={.model_path=model_descriptor,.config=cfg,.plugin_id="llama_cpp",.device_id="HTP0"};
 event("model_create","started",0,"ctx=2048,batch=128,ubatch=128,seq=1,threads=4,ngl=-1,power=6,spec=none; requested, not inferred actual");
 rc=a.create(&ci,&model);event("model_create",rc?"failed":"complete",rc,NULL);if(rc||!model)goto sdk_done;
 if(atomic_load(&observed_context)!=1||atomic_load(&observed_model)!=1){event("actual_runtime_parameters","failed",70,"required SDK context/model logs absent or differ; no inference result accepted");goto sdk_done;}
 event("actual_runtime_parameters","verified_from_sdk_logs",0,"ctx2048/batch128/ubatch128/seq1/threads4/ngl-1/load-mode-none");
 geniex_LlmModelInfo mi={0};rc=a.info(model,&mi);if(rc||mi.vocab_size<=0||mi.add_bos<0||mi.add_bos>1||(mi.add_bos&&(mi.bos_token<0||mi.bos_token>=mi.vocab_size))){event("model_info","failed",rc,"invalid vocabulary/BOS metadata");goto sdk_done;}
 int32_t input_ids[128];uint32_t rng=42;for(size_t i=0;i<128;i++){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;input_ids[i]=(int32_t)(rng%(uint32_t)mi.vocab_size);}if(mi.add_bos)input_ids[0]=mi.bos_token;
 Sha sh;sha_init(&sh);for(size_t i=0;i<128;i++){uint32_t v=(uint32_t)input_ids[i];unsigned char le[4]={(unsigned char)v,(unsigned char)(v>>8),(unsigned char)(v>>16),(unsigned char)(v>>24)};sha_update(&sh,le,4);}sha_final(&sh,digest);
 event("synthetic_input_ids","exact_128_tokens_sha256_le32",0,digest);
 geniex_SamplerConfig sampler={.temperature=0,.top_p=1,.top_k=1,.repetition_penalty=1,.seed=42,.ignore_eos=true};
 geniex_GenerationConfig gc={.max_tokens=64,.sampler_config=&sampler};
 geniex_LlmGenerateInput gi={.config=&gc,.on_token=token_cb,.input_ids=input_ids,.input_ids_count=128};
 event("generate","started",0,"synthetic pp128/tg64; measures runtime only, NOT Chinese/tool quality");double gs=now();rc=a.generate(model,&gi,&out);
 snprintf(detail,sizeof detail,"elapsed_ms=%.3f,ttft_us=%" PRId64 ",prefill_us=%" PRId64 ",decode_us=%" PRId64 ",prompt_tokens=%" PRId64 ",generated_tokens=%" PRId64 ",prefill_tps=%.6f,decode_tps=%.6f,callbacks=%u,raw_bytes=%zu",(now()-gs)*1000,out.profile_data.ttft,out.profile_data.prompt_time,out.profile_data.decode_time,out.profile_data.prompt_tokens,out.profile_data.generated_tokens,out.profile_data.prefill_speed,out.profile_data.decoding_speed,callback_count,raw_bytes);
 event("generate",rc?"failed":"returned",rc,detail);event("stop_reason","observed",0,out.profile_data.stop_reason);
 if(!rc&&!atomic_load(&callback_overflow)&&out.profile_data.prompt_tokens==128&&out.profile_data.generated_tokens==64&&out.profile_data.stop_reason&&!strcmp(out.profile_data.stop_reason,"length"))code=0;
 else event("generation_acceptance","failed",70,"requires SDK success, pp128/tg64, length stop, and bounded complete callbacks");
 sdk_done:
 if(out.full_text)a.free_(out.full_text);
 if(devs.device_ids)a.free_((void*)devs.device_ids);
 if(devs.device_names)a.free_((void*)devs.device_names);
 if(resolved.device_id)a.free_(resolved.device_id);
 if(resolved.warning)a.free_(resolved.warning);
 if(model){rc=a.destroy(model);event("model_destroy",rc?"failed":"complete",rc,NULL);if(rc)code=70;}
 rc=a.deinit();event("sdk_deinit",rc?"failed":"complete",rc,NULL);if(rc)code=70;
 /* Process exit releases matched library closure; avoid mixed-SDK dlclose order. */
 done:
 if(model_fd>=0){if(fstat(model_fd,&after)||!same_stat(&model_stat,&after)){event("model_identity_after","failed",65,"held model changed");code=65;}close(model_fd);}
 for(size_t i=0;i<NPINS;i++)if(lib_fds[i]>=0){if(fstat(lib_fds[i],&after)||!same_stat(&lib_stats[i],&after)){event("runtime_identity_after","failed",65,pins[i].path);code=65;}close(lib_fds[i]);}
 event("worker_finished",code?"not_passed":o->run?"inference_completed":"preflight_only",code,"all_expert_op_placement_proven=false; app/UI/tool success not tested");
 return code;
}
static bool hex64(const char*s){if(!s||strlen(s)!=64)return false;for(unsigned i=0;i<64;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return false;return true;}
static void usage(FILE*f){fputs("moe-runtime-probe --runtime-lib-dir /absolute/lib --model /absolute/model.gguf --model-bytes EXACT_BYTES --model-sha256 SHA256 --model-source SOURCE_URL --output /new/absolute/result-dir [--run]\nDefault is preflight only. Fixed pp128/tg64, ctx2048, batch128, ubatch128, HTP0, threads4. No resource guard can be disabled. --self-test checks SHA256 only.\n",f);}
static int parse(int argc,char**argv,Options*o){memset(o,0,sizeof *o);for(int i=1;i<argc;i++){const char*k=argv[i];if(!strcmp(k,"--run")){o->run=true;continue;}
#ifdef PROBE_TEST_BUILD
 if(!strcmp(k,"--test-watchdog")){o->test_watchdog=true;continue;}
#endif
 if(i+1>=argc)return -1;
 const char*v=argv[++i];
 if(!strcmp(k,"--runtime-lib-dir"))o->runtime=v;else if(!strcmp(k,"--model"))o->model=v;else if(!strcmp(k,"--model-sha256"))o->sha=v;else if(!strcmp(k,"--model-source"))o->source=v;else if(!strcmp(k,"--output"))o->output=v;
 else if(!strcmp(k,"--model-bytes")){char*end=NULL;errno=0;unsigned long long z=strtoull(v,&end,10);if(errno||!v[0]||*end||v[0]=='-')return -1;o->bytes=(uint64_t)z;}else return -1;
 }
 if(!o->output||o->output[0]!='/'||strlen(o->output)>PATH_MAX-32)return -1;
#ifdef PROBE_TEST_BUILD
 if(o->test_watchdog){o->runtime="/not-used";o->model="/not-used";o->source="test-only";o->sha="";o->bytes=0;return 0;}
#endif
 if(!o->runtime||o->runtime[0]!='/'||!o->model||o->model[0]!='/'||!hex64(o->sha)||!o->source||strlen(o->source)>2048||o->bytes<4||o->bytes>MAX_MODEL_BYTES||strlen(o->runtime)>PATH_MAX-64||strlen(o->model)>PATH_MAX-64)return -1;
 return 0;
}
static void kill_own_child(pid_t pid,int sig){if(getpgid(pid)==pid)kill(-pid,sig);else kill(pid,sig);}
int main(int argc,char**argv){
 if(argc==2&&!strcmp(argv[1],"--self-test")){bool ok=sha_test();printf("{\"sha256_self_test\":%s,\"sdk_loaded\":false,\"phone_contacted\":false}\n",ok?"true":"false");return ok?0:70;}
 Options o;if(parse(argc,argv,&o)){usage(stderr);return 64;}
 if(!sha_test()){fputs("SHA256 self-test failed\n",stderr);return 70;}
 epoch=now();if(epoch<0)return 70;
 if(mkdir(o.output,0700)){perror("exclusive output directory");return 73;}
 char path[PATH_MAX];
 if(bounded_path(path,sizeof path,o.output,"events.jsonl"))return 73;
 int evfd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(evfd<0)return 73;events=fdopen(evfd,"w");if(!events)return 73;setvbuf(events,NULL,_IOLBF,0);
 if(bounded_path(path,sizeof path,o.output,"sdk.log"))return 73;
 int logfd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(logfd<0)return 73;
 if(bounded_path(path,sizeof path,o.output,"raw-output.txt"))return 73;
 raw_fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(raw_fd<0)return 73;
 flockfile(events);
 fprintf(events,"{\"schema\":\"hepta.moe-runtime-probe.v1\",\"sdk_source_commit\":\"%s\",\"llama_source_commit\":\"%s\",\"header_sha256\":\"%s\",\"release_archive_sha256\":\"%s\",\"model_path\":",SDK_COMMIT,LLAMA_COMMIT,HEADER_SHA,RELEASE_SHA);
 json_str(events,o.model);fputs(",\"model_expected_sha256\":",events);json_str(events,o.sha);
 fprintf(events,",\"model_expected_bytes\":%" PRIu64 ",\"model_identity_source\":",o.bytes);json_str(events,o.source);
 fprintf(events,",\"run_requested\":%s,\"synthetic_input_ids\":true,\"phone_ui_operations\":0,\"network_operations\":0,\"production_app_qualification\":false,\"all_expert_op_placement_proven\":false",o.run?"true":"false");
#ifdef PROBE_TEST_BUILD
 fputs(",\"test_build\":true",events);
#else
 fputs(",\"test_build\":false",events);
#endif
 fputs("}\n",events);fflush(events);funlockfile(events);
 uint64_t available=mem_available(),rss_cap=o.bytes+OVERHEAD_BYTES,as_cap=rss_cap+2*GIB;
 if(rss_cap<2*GIB)rss_cap=2*GIB;
 if(as_cap<4*GIB)as_cap=4*GIB;
 char d[512];snprintf(d,sizeof d,"MemAvailable=%" PRIu64 ",required=%" PRIu64 ",reserve=%" PRIu64 ",rss_cap=%" PRIu64 ",as_cap=%" PRIu64,available,o.bytes+OVERHEAD_BYTES+RESERVE_BYTES,RESERVE_BYTES,rss_cap,as_cap);event("admission","observed",0,d);
 struct sigaction sa={0};sa.sa_handler=signal_handler;sigemptyset(&sa.sa_mask);sigaction(SIGTERM,&sa,NULL);sigaction(SIGINT,&sa,NULL);sigaction(SIGHUP,&sa,NULL);signal(SIGPIPE,SIG_IGN);
 fflush(NULL);pid_t expected_parent=getpid();pid_t child=fork();if(child<0){event("fork","failed",errno,NULL);return 70;}
 if(!child){
  signal(SIGTERM,SIG_DFL);signal(SIGINT,SIG_DFL);signal(SIGHUP,SIG_DFL);
  close(STDIN_FILENO);int nullfd=open("/dev/null",O_RDONLY);if(nullfd!=STDIN_FILENO&&nullfd>=0){dup2(nullfd,STDIN_FILENO);close(nullfd);}
  if(dup2(logfd,STDOUT_FILENO)<0||dup2(logfd,STDERR_FILENO)<0)_exit(70);
  close(logfd);int rc=run_worker(&o,rss_cap,as_cap,expected_parent);fflush(events);fsync(fileno(events));fsync(raw_fd);_exit(rc);
 }
 close(raw_fd);raw_fd=-1;close(logfd);fclose(events);events=NULL;
 uint64_t peak=0,min_available=UINT64_MAX;int status=0;bool reaped=false,killed=false;const char*reason=NULL;double killed_at=0;struct rusage usage_r={0};
 for(;;){
  pid_t w=wait4(child,&status,WNOHANG,&usage_r);if(w==child){reaped=true;break;}if(w<0&&errno!=EINTR){reason="wait_failed";break;}
  double elapsed=now()-epoch;uint64_t m=mem_available(),r=resident(child);if(r>peak)peak=r;if(m<min_available)min_available=m;
  if(!killed){
   if(interrupted)reason="external_signal";
   else if(elapsed>PROBE_WALL_SECONDS)reason="wall_deadline";
   else if(m<RESERVE_BYTES)reason="memory_reserve_guard";
   else if(r>rss_cap)reason="resident_plus_swap_guard";
   else {struct stat st;const char*names[]={"events.jsonl","sdk.log","raw-output.txt"};for(size_t i=0;i<3;i++){if(!bounded_path(path,sizeof path,o.output,names[i])&&!stat(path,&st)&&(uint64_t)st.st_size>OUTPUT_LIMIT){reason="output_limit_guard";break;}}}
   if(reason){kill_own_child(child,SIGKILL);killed=true;killed_at=now();}
  }else if(now()-killed_at>5){reason="kill_sent_but_not_reaped";break;}
  struct timespec pause_time={0,100000000};nanosleep(&pause_time,NULL);
 }
 int result=70;
 if(reaped&&!reason&&WIFEXITED(status))result=WEXITSTATUS(status);
 else if(reason&&!strcmp(reason,"wall_deadline"))result=124;
 else if(reason&&(!strcmp(reason,"memory_reserve_guard")||!strcmp(reason,"resident_plus_swap_guard")))result=75;
 else if(reaped&&WIFSIGNALED(status))result=128+WTERMSIG(status);
 if(bounded_path(path,sizeof path,o.output,"supervisor.json"))return 73;
 int reportfd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(reportfd<0)return 73;FILE*report=fdopen(reportfd,"w");if(!report)return 73;
 const char*final_status=result==0?(o.run?"inference_completed":"preflight_ready_not_executed"):result==66?"preflight_blocked_model":result==65?"identity_or_layout_failed":result==75?(reason?"memory_guard_stopped":"preflight_blocked_memory"):result==124?"timeout":"sdk_or_environment_failed";
 fprintf(report,"{\"schema\":\"hepta.moe-runtime-probe.supervisor.v1\",\"status\":");json_str(report,final_status);
 fprintf(report,",\"exit_code\":%d,\"child_pid\":%ld,\"child_reaped\":%s,\"child_signal\":%d,\"watchdog_kill_sent\":%s,\"watchdog_reason\":",result,(long)child,reaped?"true":"false",reaped&&WIFSIGNALED(status)?WTERMSIG(status):0,killed?"true":"false");json_str(report,reason);
 fprintf(report,",\"elapsed_ms\":%.3f,\"sampled_peak_rss_plus_swap_bytes\":%" PRIu64 ",\"minimum_observed_MemAvailable_bytes\":%" PRIu64 ",\"ru_maxrss_kib\":%ld,\"reserve_bytes\":%" PRIu64 ",\"memory_sampling_ms\":100,\"model_inference_requested\":%s,\"signals_limited_to_owned_child_group\":true,\"app_ui_tool_quality_tested\":false,\"all_expert_op_placement_proven\":false}\n",(now()-epoch)*1000,peak,min_available==UINT64_MAX?0:min_available,usage_r.ru_maxrss,RESERVE_BYTES,o.run?"true":"false");
 fflush(report);fsync(reportfd);fclose(report);
 printf("{\"status\":");json_str(stdout,final_status);printf(",\"exit_code\":%d,\"report\":",result);json_str(stdout,path);puts("}");return result;
}

