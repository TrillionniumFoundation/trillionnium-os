#define _GNU_SOURCE 1
#include "guard-io.h"
#include "admission.h"
#include "llama.h"
#include "ggml-backend.h"
#include "linked-backends.h"
#include "stage-clock.h"
#include "mtmd.h"
#include "mtmd-helper.h"
#include "common/chat.h"
#include "common/json.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

namespace {
constexpr uint32_t kContext = 8192, kBatch = 256, kUbatch = 128;
constexpr size_t kRawLimit = 65536, kImageLimit = 32*1024*1024;
volatile sig_atomic_t interrupted = 0;
void signal_handler(int number) { interrupted = number; }
void need(bool value, const char *message) { if (!value) throw std::runtime_error(message); }
struct Failure : std::runtime_error {
    int code;
    Failure(int value, const char *why) : std::runtime_error(why), code(value) {}
};
std::string digest(const void *data, size_t size) {
    char out[65]; hv_hash(data,size,out); return out;
}
std::string digest(const std::string &text) { return digest(text.data(),text.size()); }
bool sha_valid(const std::string &s) {
    return s.size()==64 && std::all_of(s.begin(),s.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');});
}
uint64_t decimal(const char *s, uint64_t maximum) {
    need(s && *s && !(s[0]=='0'&&s[1]),"noncanonical integer");
    uint64_t n=0;
    for (const unsigned char *p=reinterpret_cast<const unsigned char *>(s); *p; ++p) {
        need(*p>='0'&&*p<='9' && n<=(maximum-(*p-'0'))/10,"integer out of range");
        n=n*10+(*p-'0');
    }
    return n;
}
std::string text(const common_json &j, const char *key, size_t maximum=256) {
    const auto &v=j.at(key); need(v.is_string(),"expected string field");
    auto s=v.get<std::string>();
    need(!s.empty()&&s.size()<=maximum&&s.find('\0')==std::string::npos,"invalid string field");
    return s;
}
int64_t integer(const common_json &j, const char *key, int64_t low, int64_t high) {
    const auto &v=j.at(key); need(v.is_number_integer(),"expected integer field");
    auto n=v.get<int64_t>(); need(n>=low&&n<=high,"integer field out of range"); return n;
}

struct Pin { const char *name; uint64_t bytes; const char *sha; };
struct Profile {
    const char *id, *directory, *architecture, *tokenizer_pre, *template_sha;
    Pin model, projector;
};
const Profile profiles[] = {
    {"ui-venus-2-9b-q4_0", "ui-venus-model", "qwen35", "qwen35",
     "4a3d47f53cc133e5dc859e9532fcb74baf0459ef426b8f107a3ac6e5926533e5",
     {"UI-Venus-2-9B-Q4_0.gguf",5482832672ULL,"2e881d6e74899b47b1f0c9052abeeb0a7ff55913dfb18d942a3de3cadb3d1adb"},
     {"mmproj-UI-Venus-2-9B-f16.gguf",918165664ULL,"6ef77c3bf87391664be7cd71c595352e7281dabe52f24e961e2deace550f3af2"}},
    {"gui-owl-1.5-4b-instruct-i1-q4_0", "gui-owl-model", "qwen3vl", "qwen2",
     "3636d0f0bd6bef02654cdffdc447b79cb2cef8ab02cc75267345946291a489e4",
     {"GUI-Owl-1.5-4B-Instruct.i1-Q4_0.gguf",2375774624ULL,"c71f372d2e2b71f173622f1966ac6a1bc60da1c2dbdd6d92534ab6f83724b8df"},
     {"GUI-Owl-1.5-4B-Instruct.mmproj-f16.gguf",836180288ULL,"eabdc0291d460f2e68874f51044030a7da8fe956c2a6b86abd69fd701227c105"}}
};
const Pin runtime_pins[] = {
    {"libllama.so",5642424,"4bb7bd0f4fe0bd24ac32a80f920838fd2f525430ad58c5d5742cc745f7d0b835"},
    {"libmtmd.so",1643536,"ccf32e264cdccc6378d5e4e005f4aedae39eb3e9a198550c5f7f3a4583bcaa4d"},
    {"libllama-common.so",6242864,"8b05589a739339dd38ad524e9733d89650ef40b0a83fe3a95ff83716c98c6122"},
    {"libggml.so",41088,"5dff1d15e528d1accb1704a1049a6556784cbfc32131fb64cef5c8847c171149"},
    {"libggml-base.so",3534496,"bdd15d0ea024fd34a64d2eba32de79f615d35b79253e25b27b1440944fa6df40"},
    {"libggml-cpu.so",936328,"b603d578bb3beb0c3727be748f327c002619827df701bf0b894632272670943b"},
    {"libggml-hexagon.so",3874328,"67b886eb9bcdd298268a8463d74f07da4213024fe7ed89911c2e76c9e0d1491f"},
    {"libggml-htp-v79.so",858848,"110d9e6ff7cff02fa73b0a3c03d8259222758934bdbcae5c819dae6729f362d5"},
    {"libggml-opencl.so",7886880,"e395cf83e695aa9d21dd90a89460f936742c7c8c706cfbbdfa647dd316dd0875"},
    {"libomp.so",1234864,"b0b507bb9e89360304272ba335d5fb2f6661f88842c2b3c749474cb7b8acda76"}
};

struct Held {
    std::string path;
    HeptaInput input{};
    explicit Held(std::string p) : path(std::move(p)) { input.fd=-1; }
    ~Held() { hv_free(&input); }
    Held(const Held &)=delete; Held &operator=(const Held &)=delete;
    std::string str() const { return {reinterpret_cast<const char *>(input.bytes),input.size}; }
    std::string fdpath() const { return "/proc/self/fd/"+std::to_string(input.fd); }
};
struct Directory { std::string path; struct stat before; };
struct Request {
    pid_t parent=0; uid_t uid=0;
    std::string files, generation, task, id, generation_dir, directory, native_dir;
    const Profile *profile=nullptr;
    std::vector<Directory> directories;
    std::vector<std::unique_ptr<Held>> held;
    Held *manifest=nullptr,*owner=nullptr,*prompt=nullptr,*system=nullptr,*image=nullptr,*grammar=nullptr;
    Held *model=nullptr,*projector=nullptr,*generation_identity=nullptr;
    common_json binding;
    uint64_t began=0, deadline=0;
    int maximum=0,width=0,height=0;
    bool bound=false;
    void check(bool clock=true,bool signals=true) const {
        if (signals && interrupted) throw Failure(130,"cancelled");
        if (clock && (!hv_now() || hv_now()>=deadline)) throw Failure(124,"deadline");
        need(hv_parent(parent,uid),"App parent identity changed");
        for (const auto &h:held) need(hv_unchanged(&h->input),"held input identity changed");
        for (const auto &d:directories) {
            struct stat now;
            need(hv_private_directory(d.path.c_str(),&now) && now.st_dev==d.before.st_dev
                && now.st_ino==d.before.st_ino && now.st_uid==d.before.st_uid
                && now.st_gid==d.before.st_gid && now.st_mode==d.before.st_mode,"private scope changed");
        }
    }
    void add_directory(const std::string &path) {
        Directory d{path,{}}; need(hv_private_directory(path.c_str(),&d.before),"nonprivate directory");
        directories.push_back(d);
    }
    Held *read(const char *name,size_t limit,bool is_text) {
        auto h=std::make_unique<Held>(directory+"/"+name);
        need(hv_read(&h->input,h->path.c_str(),limit,is_text),"request file rejected");
        auto p=h.get(); held.push_back(std::move(h)); return p;
    }
    static int progress(void *data) noexcept {
        try { static_cast<Request *>(data)->check(); return 1; } catch (...) { return 0; }
    }
    Held *pin(const std::string &dir,const Pin &pin,bool model_file) {
        auto h=std::make_unique<Held>(dir+"/"+pin.name);
        need(hv_pin(&h->input,h->path.c_str(),pin.bytes,pin.sha,model_file,progress,this),"pinned bytes differ or cancelled");
        auto p=h.get(); held.push_back(std::move(h)); return p;
    }
    void publish(const char *name,const std::string &bytes) const {
        need(hv_publish((directory+"/"+name).c_str(),id.c_str(),bytes.data(),bytes.size()),"create-only publication failed");
    }
};

Request parse(int argc,char **argv) {
    need(argc==15,"exact worker arguments required");
    const char *keys[]={"--expected-parent-pid","--expected-app-uid","--app-files-dir",
        "--generation","--task-id","--request-id","--model-profile"};
    for (int i=0;i<7;++i) need(!std::strcmp(argv[i*2+1],keys[i]),"argument order differs");
    Request r;
    r.parent=static_cast<pid_t>(decimal(argv[2],INT_MAX)); r.uid=static_cast<uid_t>(decimal(argv[4],INT_MAX));
    need(r.parent>1 && r.uid>=10000,"ordinary App identity required");
    r.files=argv[6]; r.generation=argv[8];r.task=argv[10];r.id=argv[12];
    need(hv_id(r.generation.c_str())&&hv_id(r.task.c_str())&&hv_id(r.id.c_str()),"invalid task identity");
    for (const auto &p:profiles) if (!std::strcmp(p.id,argv[14])) r.profile=&p;
    need(r.profile,"unknown explicit model profile");
    need(hv_parent(r.parent,r.uid)&&hv_arm_parent(r.parent),"direct App parent required");
    r.generation_dir=r.files+"/runs/"+r.generation;
    r.directory=r.generation_dir+"/vlm/"+r.id;
    for (const auto &p:{r.files,r.files+"/runs",r.generation_dir,r.generation_dir+"/vlm",r.directory}) r.add_directory(p);
    need(hv_scope_enter(r.generation_dir.c_str(),r.generation.c_str(),r.task.c_str(),r.parent),"task generation scope unavailable");
    auto identity=std::make_unique<Held>(r.generation_dir+"/worker-generation.identity");
    need(hv_read(&identity->input,identity->path.c_str(),2047,1),"generation identity unreadable");
    r.generation_identity=identity.get();r.held.push_back(std::move(identity));
    r.manifest=r.read("request.json",16384,true);
    const std::string original=r.manifest->str();
    const common_json j=common_json::parse(original);
    need(j.is_object() && j.size()==14 && (j.dump()==original || j.dump()+"\n"==original),"manifest must be canonical and have exactly 14 fields");
    need(text(j,"schema")=="hepta.vlm.request.v1" && text(j,"profile")==r.profile->id
        && text(j,"request_id")==r.id && text(j,"generation")==r.generation && text(j,"task_id")==r.task,"manifest identity differs");
    r.maximum=static_cast<int>(integer(j,"max_tokens",1,256));
    r.width=static_cast<int>(integer(j,"image_width",1,8192)); r.height=static_cast<int>(integer(j,"image_height",1,8192));
    need(static_cast<int64_t>(r.width)*r.height<=24000000,"image pixel bound exceeded");
    r.began=hv_now();r.deadline=static_cast<uint64_t>(integer(j,"deadline_monotonic_ns",1,INT64_MAX));
    need(r.began && r.deadline>r.began && r.deadline-r.began<=300000000000ULL,"original monotonic deadline invalid");
    r.owner=r.read("owner.json",131072,true); r.prompt=r.read("prompt.txt",131072,true);
    r.system=r.read("system.txt",65536,true);r.image=r.read("screen.png",kImageLimit,false);
    r.grammar=r.read("decision.gbnf",262144,true);
    const std::pair<const char *,Held *> hashes[]={{"owner_sha256",r.owner},{"prompt_sha256",r.prompt},
        {"system_sha256",r.system},{"image_sha256",r.image},{"grammar_sha256",r.grammar}};
    for (const auto &h:hashes) { auto sha=text(j,h.first); need(sha_valid(sha)&&sha==h.second->input.digest,"request content SHA differs"); }
    r.binding=common_json::parse(r.owner->str());
    const auto &o=r.binding;
    need(o.is_object() && text(o,"schema")=="hepta.vlm.current-frame.v1"
        && text(o,"task_id")==r.task && text(o,"generation")==r.generation && text(o,"request_id")==r.id
        && text(o,"scope_token")==std::getenv("HEPTA_WORKER_SCOPE_TOKEN")
        && text(o,"image_sha256")==r.image->input.digest && text(o,"grammar_sha256")==r.grammar->input.digest
        && integer(o,"image_width",1,8192)==r.width && integer(o,"image_height",1,8192)==r.height,"current frame owner differs");
    (void)text(o,"observation_id",128); (void)text(o,"background_generation",128);
    (void)text(o,"package_name",256); (void)text(o,"task_owner_sha256",64);
    need(sha_valid(text(o,"task_owner_sha256",64)),"task owner digest invalid");
    (void)integer(o,"display_id",1,INT_MAX); (void)integer(o,"window_id",0,INT_MAX);
    (void)integer(o,"rotation",0,3); (void)integer(o,"captured_elapsed_ms",1,INT64_MAX);
    const unsigned char *png=r.image->input.bytes;
    const unsigned char magic[]={137,80,78,71,13,10,26,10};
    need(r.image->input.size>=33&&!std::memcmp(png,magic,8)&&!std::memcmp(png+12,"IHDR",4),"original PNG required");
    auto be=[](const unsigned char *p){return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|p[3];};
    need(be(png+8)==13&&be(png+16)==uint32_t(r.width)&&be(png+20)==uint32_t(r.height),"PNG original geometry differs");
    const char *native=std::getenv("HEPTA_LOCAL_NATIVE_LIB_DIR"); char real[PATH_MAX],exe[PATH_MAX];
    need(native && realpath(native,real) && !std::strcmp(native,real),"native library directory is not canonical");
    ssize_t n=readlink("/proc/self/exe",exe,sizeof(exe)-1); need(n>0&&size_t(n)<sizeof(exe)-1,"native executable unavailable");
    exe[n]=0;char *slash=std::strrchr(exe,'/');need(slash,"native executable path invalid");*slash=0;
    need(!std::strcmp(exe,native),"worker outside installed native library directory");r.native_dir=native;
    r.add_directory(r.files+"/"+r.profile->directory);
    r.bound=true;r.check();return r;
}

std::string meta(llama_model *model,const char *key) {
    std::array<char,65537> buf{};int32_t n=llama_model_meta_val_str(model,key,buf.data(),buf.size());
    need(n>0 && size_t(n)<buf.size(),"required GGUF metadata absent"); return {buf.data(),size_t(n)};
}
bool load_progress(float,void *data) noexcept { return Request::progress(data); }
bool abort_compute(void *data) noexcept { return !Request::progress(data); }
struct Resources {
    llama_model *model=nullptr;llama_context *context=nullptr;mtmd_context *vision=nullptr;
    mtmd_bitmap *bitmap=nullptr;mtmd_input_chunks *chunks=nullptr;llama_sampler *sampler=nullptr;
    ~Resources() {
        if(sampler)llama_sampler_free(sampler);
        if(chunks)mtmd_input_chunks_free(chunks);
        if(bitmap)mtmd_bitmap_free(bitmap);
        if(vision)mtmd_free(vision);
        if(context)llama_free(context);
        if(model)llama_model_free(model);
    }
};
struct BackendLifecycle {
    BackendLifecycle() { llama_backend_init(); }
    ~BackendLifecycle() { llama_backend_free(); }
};

void tokenize_once(Request &r, Resources &res, const common_chat_prompt &prompt) {
    struct Segment { std::string text; bool parse_special; bool media; };
    std::vector<Segment> segments;size_t markers=0;
    const std::string marker=mtmd_default_marker();
    for(const auto &part:prompt.parts) {
        size_t start=0,pos;
        while((pos=part.text.find(marker,start))!=std::string::npos) {
            segments.push_back({part.text.substr(start,pos-start),!part.is_input,false});
            segments.push_back({"",false,true});++markers;start=pos+marker.size();
        }
        segments.push_back({part.text.substr(start),!part.is_input,false});
    }
    need(markers==1,"exactly one original image marker required");
    std::vector<mtmd_input_text> texts(segments.size());
    std::vector<mtmd_input_part> parts(segments.size());
    std::vector<const mtmd_input_part *> pointers;
    for(size_t i=0;i<segments.size();++i) {
        auto &s=segments[i];
        if(s.media)parts[i]={nullptr,res.bitmap};
        else {texts[i]={s.text.c_str(),s.text.size(),false,s.parse_special};parts[i]={&texts[i],nullptr};}
        pointers.push_back(&parts[i]);
    }
    r.check();res.chunks=mtmd_input_chunks_init();need(res.chunks,"chunk allocation failed");
    need(mtmd_tokenize_from_parts(res.vision,res.chunks,pointers.data(),pointers.size(),true)==0,"multimodal tokenization failed");
}

void infer(Request &r,common_json &receipt,std::string &raw) {
    hepta_vlm::StageClock stages(hv_now,r.generation.c_str(),r.id.c_str());
    stages.enter("runtime_hash");
    for(const auto &pin:runtime_pins)r.pin(r.native_dir,pin,false);
    receipt["runtime_files_full_sha_verified"]=true;
    stages.enter("model_hash");
    r.model=r.pin(r.files+"/"+r.profile->directory,r.profile->model,true);
    r.projector=r.pin(r.files+"/"+r.profile->directory,r.profile->projector,true);
    receipt["model_files_full_sha_verified"]=true;
    r.check();stages.enter("backend_init");
    need(setenv("ADSP_LIBRARY_PATH",r.native_dir.c_str(),1)==0,"ADSP path setup failed");
    need(unsetenv("GGML_HEXAGON_NDEV")==0 && setenv("GGML_HEXAGON_DEVICES","1",1)==0,
        "single explicit HTP device setup failed");
    // Validate linked registration before llama_backend_init, whose empty-registry
    // branch would otherwise scan for dynamic plugins. No plugin loading/fallback.
    const auto selected=hepta_vlm::require_linked_backends();
    BackendLifecycle backend_lifecycle;
    auto htp=selected.htp,gpu=selected.vision;
    need(htp && gpu && std::strcmp(ggml_backend_dev_name(htp),"HTP0")==0
        && std::strcmp(ggml_backend_dev_name(gpu),"GPUOpenCL")==0
        && ggml_backend_dev_type(htp)!=GGML_BACKEND_DEVICE_TYPE_CPU
        && ggml_backend_dev_type(gpu)!=GGML_BACKEND_DEVICE_TYPE_CPU,"strict device selection unavailable");
    receipt["lm_device"]=ggml_backend_dev_name(htp);receipt["vision_device"]=ggml_backend_dev_name(gpu);
    receipt["lm_device_description"]=ggml_backend_dev_description(htp);
    receipt["vision_device_description"]=ggml_backend_dev_description(gpu);
    Resources res;ggml_backend_dev_t devices[]={htp,nullptr};
    auto mp=llama_model_default_params();mp.devices=devices;mp.n_gpu_layers=-1;
    mp.split_mode=LLAMA_SPLIT_MODE_NONE;mp.main_gpu=0;mp.load_mode=LLAMA_LOAD_MODE_NONE;
    mp.progress_callback=load_progress;mp.progress_callback_user_data=&r;
    const auto model_fd=r.model->fdpath(),projector_fd=r.projector->fdpath();
    stages.enter("language_model_load");
    res.model=llama_model_load_from_file(model_fd.c_str(),mp);need(res.model,"HTP0 model load failed");r.check();
    stages.enter("language_metadata");
    need(meta(res.model,"general.architecture")==r.profile->architecture,"pinned architecture differs");
    auto pre=meta(res.model,"tokenizer.ggml.pre");
    if(r.profile->tokenizer_pre)need(pre==r.profile->tokenizer_pre,"pinned tokenizer pre differs");
    const char *source=llama_model_chat_template(res.model,nullptr);need(source,"GGUF chat template unavailable");
    size_t source_bytes=strnlen(source,65537);need(source_bytes&&source_bytes<=65536,"chat template bound exceeded");
    const std::string source_sha=digest(source,source_bytes);
    if(r.profile->template_sha)need(source_sha==r.profile->template_sha,"GGUF template SHA differs");
    receipt["architecture"]=r.profile->architecture;receipt["tokenizer_pre"]=pre;
    receipt["tokenizer_model"]=meta(res.model,"tokenizer.ggml.model");
    receipt["chat_template_sha256"]=source_sha;receipt["chat_template_bytes"]=uint64_t(source_bytes);
    r.publish("gguf-chat-template.jinja",{source,source_bytes});
    auto cp=llama_context_default_params();cp.n_ctx=kContext;cp.n_batch=kBatch;cp.n_ubatch=kUbatch;
    cp.n_seq_max=1;cp.n_outputs_max=1;cp.n_outputs_max_per_seq=1;cp.n_threads=4;cp.n_threads_batch=4;
    cp.flash_attn_type=LLAMA_FLASH_ATTN_TYPE_ENABLED;cp.offload_kqv=true;cp.op_offload=true;
    cp.abort_callback=abort_compute;cp.abort_callback_data=&r;
    stages.enter("language_context_init");
    res.context=llama_init_from_model(res.model,cp);need(res.context,"HTP0 context load failed");
    need(llama_n_ctx(res.context)==kContext,"actual context differs");r.check();
    auto vp=mtmd_context_params_default();vp.use_gpu=true;vp.device=gpu;vp.n_threads=4;
    vp.warmup=false;vp.image_max_tokens=1024;vp.flash_attn_type=cp.flash_attn_type;
    vp.progress_callback=load_progress;vp.progress_callback_user_data=&r;
    stages.enter("vision_model_load");
    res.vision=mtmd_init_from_file(projector_fd.c_str(),res.model,vp);
    need(res.vision && mtmd_support_vision(res.vision),"GPUOpenCL vision load failed; fallback forbidden");r.check();
    receipt["vision_max_allocation_bytes"]=uint64_t(ggml_backend_buft_get_max_size(ggml_backend_dev_buffer_type(gpu)));
    stages.enter("original_image_decode");
    auto bitmap=mtmd_helper_bitmap_init_from_buf(res.vision,r.image->input.bytes,r.image->input.size,false,mtmd_helper_init_opt_default());
    res.bitmap=bitmap.bitmap;
    if(bitmap.video_ctx){mtmd_helper_video_free(bitmap.video_ctx);throw std::runtime_error("video input forbidden");}
    need(res.bitmap&&!mtmd_bitmap_is_audio(res.bitmap)&&mtmd_bitmap_get_data(res.bitmap)
        && mtmd_bitmap_get_nx(res.bitmap)==uint32_t(r.width)&&mtmd_bitmap_get_ny(res.bitmap)==uint32_t(r.height),"original image decode geometry differs");
    mtmd_bitmap_set_id(res.bitmap,r.image->input.digest);mtmd_bitmap_set_mergeable(res.bitmap,false);
    stages.enter("chat_template");
    auto templates=common_chat_templates_init(res.model,"");need(bool(templates),"GGUF chat template initialization failed");
    common_chat_templates_inputs chat;
    chat.enable_thinking=false;chat.force_pure_content=true;chat.use_jinja=true;
    chat.add_generation_prompt=true;
    receipt["template_now_unix_ms"]=int64_t(std::chrono::duration_cast<std::chrono::milliseconds>(chat.now.time_since_epoch()).count());
    common_chat_msg system;system.role="system";system.content=r.system->str();
    common_chat_msg user;user.role="user";const auto user_text=r.prompt->str();
    const std::string marker=mtmd_default_marker();
    need(system.content.find(marker)==std::string::npos&&user_text.find(marker)==std::string::npos,"input contains reserved media marker");
    user.content_parts={{"media_marker",marker},{"text",user_text}};
    chat.messages={std::move(system),std::move(user)};
    const auto rendered=common_chat_templates_apply(templates.get(),chat);
    const auto formatted=rendered.prompt.str();need(!formatted.empty()&&formatted.size()<=1048576,"formatted prompt bound exceeded");
    receipt["formatted_prompt_sha256"]=digest(formatted);r.publish("formatted-prompt.txt",formatted);
    stages.enter("tokenize_and_admit");
    tokenize_once(r,res,rendered.prompt);
    const size_t n_tokens=mtmd_helper_get_n_tokens(res.chunks);const llama_pos n_pos=mtmd_helper_get_n_pos(res.chunks);
    size_t images=0,image_tokens=0,sum_tokens=0;llama_pos sum_pos=0;
    common_json chunks=common_json::array();
    for(size_t i=0;i<mtmd_input_chunks_size(res.chunks);++i) {
        const auto *c=mtmd_input_chunks_get(res.chunks,i);auto kind=mtmd_input_chunk_get_type(c);
        const auto nt=mtmd_input_chunk_get_n_tokens(c);const auto np=mtmd_input_chunk_get_n_pos(c);
        need(np>=0&&nt<=kContext&&sum_tokens<=kContext-nt&&sum_pos<=int(kContext)-np,"chunk bound exceeded");
        common_json item={{"index",uint64_t(i)},{"type",int(kind)},{"tokens",uint64_t(nt)},{"positions",np}};
        if(kind==MTMD_INPUT_CHUNK_TYPE_IMAGE){++images;image_tokens+=nt;const char *id=mtmd_input_chunk_get_id(c);
            need(id&&std::string(id)==r.image->input.digest,"chunk image identity differs");item["image_sha256"]=id;}
        else if(kind==MTMD_INPUT_CHUNK_TYPE_TEXT){size_t count=0;const auto *tokens=mtmd_input_chunk_get_tokens_text(c,&count);
            need(count==nt&&(tokens||!count),"text chunk mismatch");item["token_ids_sha256_le32"]=digest(tokens,count*sizeof(llama_token));}
        else throw std::runtime_error("non-image media chunk forbidden");
        sum_tokens+=nt;sum_pos+=np;chunks.push_back(item);
    }
    need(images>0&&n_tokens==sum_tokens&&n_pos==sum_pos
        && hepta_vlm_admit(n_tokens,n_pos,image_tokens,unsigned(r.maximum),kContext),
        "full multimodal context admission failed");
    receipt["prompt_tokens"]=uint64_t(n_tokens);receipt["prompt_positions"]=n_pos;
    receipt["image_tokens"]=uint64_t(image_tokens);receipt["output_reserved_tokens"]=r.maximum;
    const auto chunk_json=chunks.dump();r.publish("chunks.json",chunk_json+"\n");receipt["chunks_sha256"]=digest(chunk_json+"\n");
    receipt["full_multimodal_admission_passed"]=true;r.check();
    // No re-tokenization, truncation, KV shifting, or second chunk object occurs
    // between admission and this exact evaluation call.
    llama_pos past=0;
    stages.enter("multimodal_prefill");
    const int eval_rc=mtmd_helper_eval_chunks(res.vision,res.context,res.chunks,0,0,kBatch,true,&past);
    receipt["prefill_return_code"]=eval_rc;receipt["prefill_positions"]=past;
    need(eval_rc==0&&past==n_pos,"same-chunk prefill failed or positions differ");r.check();
    receipt["same_chunks_counted_and_evaluated"]=true;
    stages.enter("constrained_decode");
    const auto *vocab=llama_model_get_vocab(res.model);need(vocab,"model vocabulary missing");
    res.sampler=llama_sampler_chain_init(llama_sampler_chain_default_params());need(res.sampler,"sampler allocation failed");
    auto grammar=llama_sampler_init_grammar(vocab,r.grammar->str().c_str(),"root");need(grammar,"current frame GBNF rejected");
    llama_sampler_chain_add(res.sampler,grammar);llama_sampler_chain_add(res.sampler,llama_sampler_init_greedy());
    int generated=0;bool eog=false;
    for(int i=0;i<r.maximum;++i) {
        r.check();const llama_token token=llama_sampler_sample(res.sampler,res.context,-1);
        need(token>=0,"sampling failed");++generated;
        if(llama_vocab_is_eog(vocab,token)){eog=true;break;}
        std::vector<char> piece(256);int32_t n=llama_token_to_piece(vocab,token,piece.data(),int32_t(piece.size()),0,true);
        if(n<0){need(n!=INT32_MIN&&size_t(-n)<=kRawLimit,"token piece bound exceeded");piece.resize(size_t(-n));n=llama_token_to_piece(vocab,token,piece.data(),int32_t(piece.size()),0,true);}
        need(n>=0&&raw.size()+size_t(n)<=kRawLimit,"raw output bound exceeded");raw.append(piece.data(),size_t(n));
        need(past<int(kContext),"decoder context capacity exhausted");
        llama_token one=token;llama_pos pos=past;int32_t nseq=1;llama_seq_id seq=0;llama_seq_id *seqs[]={&seq};int8_t logits=1;
        llama_batch batch={1,&one,nullptr,&pos,&nseq,seqs,&logits};
        const int rc=llama_decode(res.context,batch);need(rc==0,"HTP0 decode failed");++past;
    }
    receipt["generated_tokens_including_eog"]=generated;receipt["eog_observed"]=eog;
    receipt["generation_completed"]=eog;receipt["final_position"]=past;
    need(hv_utf8(reinterpret_cast<const unsigned char *>(raw.data()),raw.size()),"raw output is not complete UTF-8");
    if(!eog)throw Failure(65,"token_limit");
    need(!raw.empty(),"empty model output");r.check();
    // Declared before the backend and Resources: the last interval includes
    // their existing destructors, rather than guessing teardown from totals.
    stages.enter("resource_teardown");
}

int execute(int argc,char **argv) {
    Request r=parse(argc,argv);
    common_json receipt={{"schema","hepta.vlm.result.v1"},{"request_id",r.id},{"task_id",r.task},
        {"generation",r.generation},{"scope_token",std::getenv("HEPTA_WORKER_SCOPE_TOKEN")},
        {"profile",r.profile->id},{"request_sha256",r.manifest->input.digest},{"owner_sha256",r.owner->input.digest},
        {"image_sha256",r.image->input.digest},{"grammar_sha256",r.grammar->input.digest},
        {"prompt_sha256",r.prompt->input.digest},{"system_sha256",r.system->input.digest},
        {"generation_identity_sha256",r.generation_identity->input.digest},
        {"app_uid",uint64_t(r.uid)},{"app_pid",int64_t(r.parent)},{"worker_pid",int64_t(getpid())},
        {"expected_app_uid",uint64_t(r.uid)},{"expected_parent_pid",int64_t(r.parent)},
        {"app_start_ticks",decimal(std::getenv("HEPTA_WORKER_SCOPE_PARENT_START"),UINT64_MAX)},
        {"boot_id",std::getenv("HEPTA_WORKER_SCOPE_BOOT")},{"parent_death_signal",int(SIGKILL)},
        {"parent_verified_before",true},{"private_scope_verified_before",true},
        {"observed_parent_pid_before",int64_t(getppid())},
        {"model_sha256",r.profile->model.sha},{"projector_sha256",r.profile->projector.sha},
        {"model_filename",r.profile->model.name},{"model_bytes",r.profile->model.bytes},
        {"projector_filename",r.profile->projector.name},{"projector_bytes",r.profile->projector.bytes},
        {"model_files_full_sha_verified",false},{"runtime_files_full_sha_verified",false},
        {"image_width",r.width},{"image_height",r.height},{"current_frame",r.binding},
        {"context_tokens",kContext},{"max_output_tokens",r.maximum},{"image_max_tokens",1024},
        {"started_monotonic_ns",r.began},{"deadline_monotonic_ns",r.deadline},
        {"sampler","current-frame-gbnf-then-greedy"},{"grammar_root","root"},
        {"template_enable_thinking",false},{"native_tools_argument",false},
        {"automatic_device_fallback",false},{"zero_cpu_operations_proven",false},
        {"same_chunks_counted_and_evaluated",false},{"context_shift_used",false},
        {"input_image_transformed_by_worker",false},{"mtmd_internal_image_preprocessing",true},
        {"actions_dispatched",false},{"action_authorized",false},{"business_completion_verified",false},
        {"generation_completed",false},{"full_multimodal_admission_passed",false},
        {"process_exit_observed",false},{"cleanup_known",false}};
    std::string raw,error="none";int rc=0;
    try { infer(r,receipt,raw); }
    catch(const Failure &f){rc=f.code;error=f.what();}
    catch(const std::exception &e){rc=interrupted?130:(hv_now()>=r.deadline?124:74);error=e.what();}
    // A receipt describes completed inference only. Java must separately wait
    // on its exact Process and seal the unchanged OwnedGenerationScope proof.
    bool parent_after=hv_parent(r.parent,r.uid);bool unchanged=true;
    try { r.check(false,false); } catch(...) { unchanged=false; }
    if(!parent_after||!unchanged){if(!rc)rc=78;receipt["generation_completed"]=false;}
    receipt["parent_verified_after"]=parent_after;receipt["scope_unchanged_after"]=unchanged;
    receipt["observed_parent_pid_after"]=int64_t(getppid());
    receipt["native_return_code"]=rc;receipt["error"]=error;receipt["cancel_signal"]=int(interrupted);
    receipt["ended_monotonic_ns"]=hv_now();receipt["raw_sha256"]=digest(raw);receipt["raw_bytes"]=uint64_t(raw.size());
    if(!parent_after||!unchanged){std::fputs("HEPTA_VLM_REFUSED final identity changed; no output publication\n",stderr);return 78;}
    r.publish("raw.txt",raw);r.publish("native-result.json",receipt.dump()+"\n");
    std::fprintf(stderr,"HEPTA_VLM_EXIT request=%s rc=%d raw_bytes=%zu action_authorized=false\n",r.id.c_str(),rc,raw.size());
    return rc;
}
} // namespace

int main(int argc,char **argv) {
    if(argc>1&&!std::strcmp(argv[1],"--hepta-owned-generation-cleanup-v1"))return hv_scope_cleanup(argc,argv);
    if(argc==2&&!std::strcmp(argv[1],"--help")){
        std::puts("Hepta current-frame VLM worker v1: explicit pinned model; HTP0 + GPUOpenCL; no dispatch. See PROTOCOL.md.");return 0;
    }
    struct sigaction action{};action.sa_handler=signal_handler;sigemptyset(&action.sa_mask);
    if(sigaction(SIGINT,&action,nullptr)||sigaction(SIGTERM,&action,nullptr))return 78;
    try { return execute(argc,argv); }
    catch(const std::exception &e){std::fprintf(stderr,"HEPTA_VLM_REFUSED %s\n",e.what());return 78;}
    catch(...){std::fputs("HEPTA_VLM_REFUSED unknown native exception\n",stderr);return 78;}
}
