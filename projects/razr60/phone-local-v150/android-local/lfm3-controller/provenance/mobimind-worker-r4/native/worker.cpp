// One request, one process, no actions and no external model calls.
#include "model_pins.hpp"
#include "probe_util.hpp"
#include <MNN/Interpreter.hpp>
#include <llm/llm.hpp>
#include <cv/imgcodecs.hpp>
#include <atomic>
#include <chrono>
#include <csignal>
#include <dlfcn.h>
#include <fstream>
#include <iostream>
#include <limits.h>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <streambuf>
#include <sys/prctl.h>
#include <thread>

using MNN::Transformer::Llm;
using Clock = std::chrono::steady_clock;
static long long monotonic_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
}
struct Options {
    std::string request, model, prompt, image, output, prompt_sha, image_sha;
    int parent = 0, deadline = 120000, max_tokens = 256, long_edge = 1024;
};
struct OpCount { unsigned long long count=0, errors=0; std::string sample; };
struct Phase { std::string name; long long started=0, elapsed=0; bool complete=false, failed=false; };
struct State {
    Options options;
    long long started = monotonic_ms();
    std::atomic<bool> done{false}, terminating{false};
    std::atomic<int> phase_number{0}, raw_fd{-1};
    std::atomic<std::size_t> raw_bytes{0};
    int events_fd = -1;
    std::mutex telemetry_mutex;
    std::map<std::string, OpCount> operations;
    std::map<std::string, unsigned long long> runtimes;
    std::vector<Phase> phases;
    std::string current_phase="startup", prompt_hash, image_hash, input_ids_hash, library_hash, library_path;
    std::size_t input_tokens=0, token_hook_calls=0, verified_models=0;
    HashEvidence prompt_hash_evidence,image_hash_evidence,library_hash_evidence;
    std::uint64_t model_hash_bytes=0,model_hardware_blocks=0,model_portable_blocks=0;
    bool backend_preflight=false, input_binding=false, post_binding=false;
    int original_width=0, original_height=0, resized_width=0, resized_height=0;
};
static State* state = nullptr;
static volatile std::sig_atomic_t signal_received = 0;
static void signal_handler(int number) { signal_received = number; }

static Object identity(const char* outcome) {
    Object j; j.str("schema", "hepta.mobimind.model_only.v1");
    j.str("request_id", state->options.request); j.str("outcome", outcome);
    j.num("pid", getpid()); j.num("uid", getuid()); j.num("expected_parent_pid", state->options.parent);
    j.num("elapsed_ms", monotonic_ms()-state->started); j.num("phase_index", state->phase_number.load());
    j.flag("actions_executed", false); j.flag("external_model_used", false);
    j.flag("http_resources_compiled", false); return j;
}
[[noreturn]] static void hard_fail(const char* reason, int exit_code) {
    if (!state->terminating.exchange(true)) {
        try {
            int fd = state->raw_fd.load(); if (fd >= 0) ::fsync(fd);
            Object j = identity(reason); j.num("expected_exit_code", exit_code);
            j.flag("generation_complete", false); j.flag("receipt_complete", false);
            j.num("raw_bytes_observed", state->raw_bytes.load());
            j.str("prompt_expected_sha256", state->options.prompt_sha);
            j.str("image_expected_sha256", state->options.image_sha);
            write_new(state->options.output+"/terminal.json", j.done()+"\n");
        } catch (...) {}
    }
    ::_exit(exit_code);
}
static void event(const std::string& phase, const char* status) {
    Object j; j.str("phase",phase); j.str("status",status); j.num("elapsed_ms",monotonic_ms()-state->started);
    std::string text=j.done()+"\n"; write_all(state->events_fd,text.data(),text.size()); ::fsync(state->events_fd);
}
static void phase_complete() {
    if (!state->phases.empty() && !state->phases.back().complete && !state->phases.back().failed) {
        auto& p=state->phases.back(); p.elapsed=monotonic_ms()-p.started; p.complete=true; event(p.name,"complete");
    }
}
static void phase_failed() {
    if (!state->phases.empty() && !state->phases.back().complete) {
        auto& p=state->phases.back();p.elapsed=monotonic_ms()-p.started;p.failed=true;event(p.name,"failed");
    }
}
static void phase_begin(const std::string& name) {
    phase_complete();
    { std::lock_guard<std::mutex> lock(state->telemetry_mutex); state->current_phase=name; }
    state->phases.push_back({name,monotonic_ms(),0,false,false}); state->phase_number.fetch_add(1); event(name,"begin");
}
extern "C" __attribute__((visibility("default"))) void hepta_mnn_runtime(int requested, int actual) {
    if (!state) return;
    try {
        std::lock_guard<std::mutex> lock(state->telemetry_mutex);
        ++state->runtimes[state->current_phase+":"+std::to_string(requested)+"->"+std::to_string(actual)];
    } catch (...) { hard_fail("runtime_telemetry_failed",93); }
    if (requested == 3 && actual != 3) hard_fail("opencl_runtime_fallback_rejected",86);
}
extern "C" __attribute__((visibility("default"))) void hepta_mnn_observe(const char* op, const char* name, int backend, int error) {
    if (!state) return;
    try {
    std::lock_guard<std::mutex> lock(state->telemetry_mutex);
    std::string key=state->current_phase+":"+std::to_string(backend)+":"+(op?op:"unknown");
    // Bound telemetry cardinality without hiding the aggregate count.
    if (state->operations.size() >= 4096 && !state->operations.count(key)) key="overflow:"+std::to_string(backend);
    auto& row=state->operations[key]; ++row.count; if (error) ++row.errors;
    if (row.sample.empty() && name) row.sample=std::string(name).substr(0,240);
    } catch (...) { hard_fail("operation_telemetry_failed",94); }
}
extern "C" __attribute__((visibility("default"))) void hepta_mnn_input_ids(const int* ids, std::size_t count) {
    if (!state) return;
    ++state->token_hook_calls; state->input_tokens=count;
    if (!ids || count == 0 || state->token_hook_calls != 1) hard_fail("input_ids_hook_invalid",87);
    state->input_ids_hash=token_ids_sha(ids,count);
    if (count+static_cast<std::size_t>(state->options.max_tokens)>4096) hard_fail("exact_context_budget_exceeded",88);
    Object j; j.num("count",count); j.str("encoding","signed-token-id-as-uint32-little-endian");
    j.str("sha256",state->input_ids_hash); j.num("max_new_tokens",state->options.max_tokens); j.num("context_limit",4096);
    try { write_new(state->options.output+"/input-token-binding.json",j.done()+"\n"); }
    catch (...) { hard_fail("token_binding_write_failed",89); }
    try { phase_begin("prefill_decode"); }
    catch (...) { hard_fail("phase_record_failed",95); }
}
class RawBuffer : public std::streambuf {
public:
    explicit RawBuffer(const std::string& path) {
        fd=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
        if(fd<0) throw std::runtime_error("raw_create_failed"); state->raw_fd=fd;
    }
    ~RawBuffer() override { if(fd>=0) { ::fsync(fd); state->raw_fd=-1; ::close(fd); } }
    void finish() { if(::fsync(fd)) throw std::runtime_error("raw_fsync_failed"); }
protected:
    std::streamsize xsputn(const char* data,std::streamsize n) override {
        if(n<0 || state->raw_bytes.load()+static_cast<std::size_t>(n)>1048576) hard_fail("raw_output_limit",90);
        try { write_all(fd,data,static_cast<std::size_t>(n)); }
        catch (...) { hard_fail("raw_write_failed",91); }
        state->raw_bytes.fetch_add(static_cast<std::size_t>(n)); return n;
    }
    int overflow(int c) override { if(c==traits_type::eof()) return traits_type::not_eof(c); char v=static_cast<char>(c); return xsputn(&v,1)==1?c:traits_type::eof(); }
    int sync() override { return ::fsync(fd); }
private: int fd=-1;
};
static std::string canonical(const std::string& p) {
    char resolved[PATH_MAX]; if(!::realpath(p.c_str(),resolved)) throw std::runtime_error("canonical_path_failed:"+p); return resolved;
}
static int integer(const std::string& s,int low,int high) {
    if(s.empty() || !std::all_of(s.begin(),s.end(),[](char c){return c>='0'&&c<='9';})) throw std::runtime_error("invalid_integer");
    long long n=std::stoll(s); if(n<low||n>high) throw std::runtime_error("integer_out_of_range"); return static_cast<int>(n);
}
static Options parse(int argc,char** argv) {
    std::map<std::string,std::string> a;
    for(int i=1;i<argc;i+=2) {
        if(i+1==argc || std::string(argv[i]).rfind("--",0)!=0 || !a.emplace(argv[i],argv[i+1]).second)
            throw std::runtime_error("invalid_or_duplicate_argument");
    }
    auto required=[&a](const char* key){auto it=a.find(key);if(it==a.end())throw std::runtime_error(std::string("missing_argument:")+key);std::string v=it->second;a.erase(it);return v;};
    auto optional=[&a](const char* key,int fallback,int low,int high){auto it=a.find(key);if(it==a.end())return fallback;int v=integer(it->second,low,high);a.erase(it);return v;};
    Options o; o.request=required("--request-id"); o.model=required("--model-dir");
    o.prompt=required("--prompt-file"); o.image=required("--image-file"); o.output=required("--output-dir");
    o.prompt_sha=required("--expected-prompt-sha256"); o.image_sha=required("--expected-image-sha256");
    o.parent=integer(required("--expected-parent-pid"),2,INT_MAX);
    o.deadline=optional("--deadline-ms",120000,1000,600000);
    o.max_tokens=optional("--max-tokens",256,1,512); o.long_edge=optional("--image-long-edge",1024,256,1536);
    if(!a.empty() || !lower_hex(o.request,32) || !lower_hex(o.prompt_sha,64) || !lower_hex(o.image_sha,64)) throw std::runtime_error("unknown_argument_or_invalid_identity");
    for(const auto* p:{&o.model,&o.prompt,&o.image,&o.output}) if(p->empty()||(*p)[0]!='/') throw std::runtime_error("absolute_paths_required");
    return o;
}
static std::string config_text(const Options& o) {
    Object j; j.str("base_dir",o.model+"/"); j.str("llm_config","llm_config.json");
    j.str("llm_model","llm.mnn"); j.str("llm_weight","llm.mnn.weight"); j.str("visual_model","visual.mnn");
    j.str("embedding_file","embeddings_bf16.bin"); j.str("tokenizer_file","tokenizer.mtok");
    // On OpenCL this field is a GPU mode bitmask, not a CPU thread count.
    // 16 = MNN_GPU_TUNING_FAST; Llm/Omni add 64 = memory buffer mode.
    j.str("backend_type","opencl"); j.num("thread_num",16); j.str("precision","low"); j.str("memory","low");
    j.str("sampler_type","greedy"); j.num("max_all_tokens",4096); j.num("max_new_tokens",o.max_tokens);
    j.flag("use_template",false); j.flag("reuse_kv",false); j.flag("prompt_cache",false); j.flag("async",false);
    j.num("timeout_ms",o.deadline); j.str("tmp_path",o.output+"/cache");
    Object vision; vision.str("backend_type","opencl"); vision.num("thread_num",16); vision.str("precision","normal"); vision.str("memory","low");
    j.raw("mllm",vision.done()); return j.done()+"\n";
}
static Object hash_evidence_json(const HashEvidence& value) {
    Object row;row.str("hash_backend",value.backend);row.flag("complete",value.complete);
    row.flag("selected_hardware",value.selected_hardware);row.num("bytes_hashed",value.bytes);
    row.num("hardware_blocks",value.hardware_blocks);row.num("portable_blocks",value.portable_blocks);
    return row;
}
static Object receipt(const std::string& outcome, const MNN::Transformer::LlmContext* context,
                      const std::string& raw, bool raw_valid) {
    Object j=identity(outcome.c_str()); j.flag("receipt_complete",true);
    j.str("model_repo",MODEL_REPO);j.str("model_revision",MODEL_REVISION);j.str("mnn_revision",MNN_REVISION);
    j.str("loaded_mnn_path",state->library_path);j.str("loaded_mnn_sha256",state->library_hash);
    j.num("pinned_files_verified",state->verified_models);j.flag("initial_input_binding",state->input_binding);
    Object hashing;hashing.str("schema","hepta.mobimind.sha256-dispatch.v1");
    hashing.flag("compiled_armv8_sha2",HEPTA_SHA256_ARMV8_COMPILED!=0);
    hashing.flag("runtime_hwcap_sha2",hepta_sha256_runtime_sha2());
    hashing.str("hash_backend",state->model_hardware_blocks>0
        ?(state->model_portable_blocks>0?"mixed":"armv8-sha2")
        :(state->model_portable_blocks>0?"portable":"not_observed"));
    hashing.num("model_files_hashed",state->verified_models);hashing.num("model_bytes_hashed",state->model_hash_bytes);
    hashing.num("model_hardware_blocks",state->model_hardware_blocks);hashing.num("model_portable_blocks",state->model_portable_blocks);
    hashing.flag("complete_model_files_only",true);hashing.flag("padding_included_in_block_counts",true);
    hashing.flag("full_file_hash_each_request",true);hashing.flag("digest_cache",false);
    hashing.raw("prompt",hash_evidence_json(state->prompt_hash_evidence).done());
    hashing.raw("image",hash_evidence_json(state->image_hash_evidence).done());
    hashing.raw("loaded_library",hash_evidence_json(state->library_hash_evidence).done());
    j.raw("sha256_dispatch",hashing.done());
    j.flag("post_generation_file_binding",state->post_binding);j.str("file_binding_method","full SHA256 then held fd + path dev/inode/size/uid/mode/mtime/ctime recheck");
    j.str("prompt_expected_sha256",state->options.prompt_sha);j.str("image_expected_sha256",state->options.image_sha);
    j.str("prompt_actual_sha256",state->prompt_hash);j.str("image_actual_sha256",state->image_hash);
    j.str("input_ids_sha256",state->input_ids_hash);j.num("input_tokens_exact",state->input_tokens);j.num("input_ids_hook_calls",state->token_hook_calls);
    j.num("context_limit",4096);j.num("max_new_tokens",state->options.max_tokens);j.str("sampling","greedy");
    j.num("original_width",state->original_width);j.num("original_height",state->original_height);
    j.num("resized_width",state->resized_width);j.num("resized_height",state->resized_height);
    j.str("image_preprocess","BGR decoded once; Qwen3VL MNN vision resizes to recorded 32-aligned dimensions and converts BGR to RGB");
    j.str("requested_text_backend","opencl");j.str("requested_vision_backend","opencl");j.flag("opencl_preflight",state->backend_preflight);
    j.str("placement_scope","MNN Pipeline selected execution backend; counts are calls, not FLOPs or elapsed GPU time; CPU embedding/tokenization/sampling are outside this counter");
    Object runtime_rows,op_rows; unsigned long long gpu=0,cpu=0,other=0,errors=0,opencl_runtimes=0;
    {
        std::lock_guard<std::mutex> lock(state->telemetry_mutex);
        for(const auto& pair:state->runtimes) { runtime_rows.num(pair.first,pair.second); if(pair.first.find(":3->3")!=std::string::npos)opencl_runtimes+=pair.second; }
        for(const auto& pair:state->operations) {
            Object row;row.num("calls",pair.second.count);row.num("error_calls",pair.second.errors);row.str("sample_name",pair.second.sample);op_rows.raw(pair.first,row.done());errors+=pair.second.errors;
            auto a=pair.first.find(':');auto b=pair.first.find(':',a+1);std::string backend=pair.first.substr(a+1,b-a-1);
            if(backend=="3")gpu+=pair.second.count;else if(backend=="0"||backend=="13")cpu+=pair.second.count;else other+=pair.second.count;
        }
    }
    j.raw("runtime_selections",runtime_rows.done());j.raw("operation_backend_counts",op_rows.done());
    j.num("opencl_runtime_selections",opencl_runtimes);j.num("opencl_execution_calls",gpu);j.num("cpu_execution_calls",cpu);j.num("other_execution_calls",other);j.num("execution_errors",errors);
    j.flag("gpu_execution_observed",gpu>0);j.flag("all_gpu_claim",false);
    j.flag("backend_probe_qualified",state->backend_preflight && opencl_runtimes>=2 && gpu>0 && errors==0);
    j.num("raw_bytes",raw.size());j.str("raw_sha256",hash_string(raw));j.flag("raw_valid_utf8",raw_valid);
    j.flag("generation_complete",context && context->status==MNN::Transformer::LlmStatus::NORMAL_FINISHED && raw_valid && !raw.empty() && outcome=="completed");
    if(context) {
        Object c;c.num("status",static_cast<int>(context->status));c.num("prompt_len",context->prompt_len);c.num("gen_seq_len",context->gen_seq_len);c.num("all_seq_len",context->all_seq_len);
        c.num("load_us",context->load_us);c.num("vision_us",context->vision_us);c.num("prefill_us",context->prefill_us);c.num("decode_us",context->decode_us);c.num("sample_us",context->sample_us);
        c.num("output_token_count",context->output_tokens.size());c.str("output_token_ids_sha256",token_ids_sha(context->output_tokens.data(),context->output_tokens.size()));j.raw("mnn_context",c.done());
    }
    std::string stages="[";bool first=true;
    for(const auto& p:state->phases) {if(!first)stages+=',';first=false;Object x;x.str("name",p.name);x.flag("complete",p.complete);x.flag("failed",p.failed);x.num("elapsed_ms",(p.complete||p.failed)?p.elapsed:monotonic_ms()-p.started);stages+=x.done();}
    j.raw("phases",stages+"]");return j;
}

int main(int argc,char** argv) {
    State local; state=&local; std::thread watchdog; Llm* llm=nullptr; std::unique_ptr<RawBuffer> raw_buffer;
    std::vector<std::unique_ptr<BoundFile>> bound_models;
    std::unique_ptr<BoundFile> prompt_file,image_file;
    std::unique_ptr<MNN::Transformer::LlmContext> finished_context;
    std::string raw;bool raw_valid=false;int rc=1;std::string outcome="startup_failed";
    try {
        local.options=parse(argc,argv);
        if(getppid()!=local.options.parent || prctl(PR_SET_PDEATHSIG,SIGKILL) || getppid()!=local.options.parent)
            throw std::runtime_error("parent_identity_mismatch");
        if(::mkdir(local.options.output.c_str(),0700)) throw std::runtime_error("output_directory_must_be_new");
        local.options.output=canonical(local.options.output);local.options.model=canonical(local.options.model);
        local.events_fd=::open((local.options.output+"/phases.jsonl").c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
        if(local.events_fd<0)throw std::runtime_error("events_create_failed");
        std::signal(SIGTERM,signal_handler);std::signal(SIGINT,signal_handler);std::signal(SIGPIPE,SIG_IGN);
        watchdog=std::thread([] {
            while(!state->done.load()) {
                if(signal_received)hard_fail("cancelled",128+signal_received);
                if(getppid()!=state->options.parent)hard_fail("parent_changed",92);
                if(monotonic_ms()-state->started>=state->options.deadline)hard_fail("deadline_exceeded",124);
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
        });
        phase_begin("bind_inputs");
        prompt_file=std::make_unique<BoundFile>(local.options.prompt,65536);
        image_file=std::make_unique<BoundFile>(local.options.image,32*1024*1024);
        std::string prompt=prompt_file->read(65536);std::string image=image_file->read(32*1024*1024);
        validate_prompt(prompt);local.prompt_hash=hash_string_evidence(prompt,local.prompt_hash_evidence);local.image_hash=hash_string_evidence(image,local.image_hash_evidence);
        if(local.prompt_hash!=local.options.prompt_sha||local.image_hash!=local.options.image_sha)throw std::runtime_error("input_sha256_mismatch");
        // Bind PNG dimensions before the decoder can allocate memory from attacker-controlled dimensions.
        const unsigned char signature[]={137,80,78,71,13,10,26,10};
        if(image.size()<33||std::memcmp(image.data(),signature,8)||image.substr(12,4)!="IHDR")throw std::runtime_error("screenshot_must_be_png");
        auto be32=[&image](std::size_t at){const auto* p=reinterpret_cast<const unsigned char*>(image.data()+at);return (unsigned(p[0])<<24)|(unsigned(p[1])<<16)|(unsigned(p[2])<<8)|unsigned(p[3]);};
        unsigned w=be32(16),h=be32(20);if(w>8192||h>8192)throw std::runtime_error("png_dimensions_rejected");
        local.original_width=static_cast<int>(w);local.original_height=static_cast<int>(h);
        auto target=image_target(local.original_width,local.original_height,local.options.long_edge);local.resized_width=target.first;local.resized_height=target.second;
        write_new(local.options.output+"/prompt.txt",prompt);local.input_binding=true;
        phase_begin("hash_model_assets");
        Object files;
        for(const auto& pin:MODEL_PINS) {
            auto f=std::make_unique<BoundFile>(local.options.model+"/"+pin.name,pin.size);
            HashEvidence hashing;
            if(static_cast<std::uint64_t>(f->initial.st_size)!=pin.size || f->hash(&hashing)!=pin.sha)throw std::runtime_error(std::string("model_pin_mismatch:")+pin.name);
            Object row;row.num("bytes",pin.size);row.str("sha256",pin.sha);row.raw("hash_execution",hash_evidence_json(hashing).done());
            files.raw(pin.name,row.done());bound_models.push_back(std::move(f));++local.verified_models;
            local.model_hash_bytes+=hashing.bytes;local.model_hardware_blocks+=hashing.hardware_blocks;local.model_portable_blocks+=hashing.portable_blocks;
        }
        write_new(local.options.output+"/model-binding.json",files.done()+"\n");
        Dl_info library{};
        if(::dladdr(reinterpret_cast<void*>(&MNN::getVersion),&library) && library.dli_fname) {
            local.library_path=canonical(library.dli_fname);BoundFile f(local.library_path,512*1024*1024,false);local.library_hash=f.hash(&local.library_hash_evidence);
        } else throw std::runtime_error("loaded_mnn_identity_unavailable");
        phase_begin("opencl_preflight");
        {
            MNN::ScheduleConfig config;config.type=MNN_FORWARD_OPENCL;config.numThread=MNN_GPU_TUNING_FAST|MNN_GPU_MEMORY_BUFFER;
            auto runtime=MNN::Interpreter::createRuntime({config});
            auto found=runtime.first.find(MNN_FORWARD_OPENCL);
            if(found==runtime.first.end()||!found->second)throw std::runtime_error("opencl_unavailable");
            local.backend_preflight=true;
        }
        phase_begin("image_decode");
        std::vector<std::uint8_t> image_bytes(image.begin(),image.end());
        auto pixels=MNN::CV::imdecode(image_bytes,MNN::CV::IMREAD_COLOR);
        if(!pixels.get()||!pixels->getInfo())throw std::runtime_error("png_decode_failed");
        auto dimensions=pixels->getInfo()->dim;
        if(dimensions.size()!=3||dimensions[0]!=local.original_height||dimensions[1]!=local.original_width||dimensions[2]!=3)
            throw std::runtime_error("decoded_image_dimensions_mismatch");
        phase_begin("create_load");
        if(::mkdir((local.options.output+"/cache").c_str(),0700))throw std::runtime_error("cache_directory_failed");
        std::string config=config_text(local.options);write_new(local.options.output+"/runtime-config.json",config);
        for(const auto& f:bound_models)f->verify();
        llm=Llm::createLLM(local.options.output+"/runtime-config.json");
        if(!llm||!llm->load())throw std::runtime_error("model_create_or_load_failed");
        write_new(local.options.output+"/effective-config.json",llm->dump_config());
        MNN::Transformer::MultimodalPrompt multimodal;
        multimodal.prompt_template=prompt;multimodal.images["screen"]={pixels,local.resized_width,local.resized_height};
        raw_buffer=std::make_unique<RawBuffer>(local.options.output+"/raw.txt");std::ostream raw_stream(raw_buffer.get());
        phase_begin("vision_tokenize");
        llm->response(multimodal,&raw_stream,"",local.options.max_tokens);raw_stream.flush();raw_buffer->finish();phase_complete();
        if(!llm->getContext())throw std::runtime_error("missing_llm_context");
        finished_context=std::make_unique<MNN::Transformer::LlmContext>(*llm->getContext());
        if(local.token_hook_calls!=1)throw std::runtime_error("required_token_hook_not_observed");
        {
            std::lock_guard<std::mutex> lock(local.telemetry_mutex);
            unsigned long long gpu_calls=0, runtime_calls=0, errors=0;
            for(const auto& row:local.runtimes)if(row.first.find(":3->3")!=std::string::npos)runtime_calls+=row.second;
            for(const auto& row:local.operations) {
                auto a=row.first.find(':');auto b=row.first.find(':',a+1);
                if(row.first.substr(a+1,b-a-1)=="3")gpu_calls+=row.second.count;
                errors+=row.second.errors;
            }
            if(runtime_calls<2||gpu_calls==0||errors)throw std::runtime_error("opencl_execution_not_qualified");
        }
        phase_begin("destroy");Llm::destroy(llm);llm=nullptr;raw_buffer.reset();phase_complete();
        phase_begin("post_binding");for(const auto& f:bound_models)f->verify();prompt_file->verify();image_file->verify();local.post_binding=true;
        BoundFile raw_file(local.options.output+"/raw.txt",1048576);raw=raw_file.read(1048576);
        raw_valid=utf8(reinterpret_cast<const unsigned char*>(raw.data()),raw.size());phase_complete();
        const auto status=finished_context->status;
        if(status==MNN::Transformer::LlmStatus::MAX_TOKENS_FINISHED) { outcome="max_tokens_reached";rc=3; }
        else if(status!=MNN::Transformer::LlmStatus::NORMAL_FINISHED) { outcome="mnn_generation_failed";rc=4; }
        else if(raw.empty()||!raw_valid) { outcome="empty_or_invalid_output";rc=5; }
        else { outcome="completed";rc=0; }
        // No output is an executed action. Qualification is separate from model semantics.
    } catch(const std::exception& e) {
        outcome=e.what();rc=2;std::cerr<<"HEPTA_PROBE_ERROR "<<outcome<<"\n";
        try { if(local.events_fd>=0)phase_failed(); } catch(...) {}
        if(llm) { try { phase_begin("error_destroy");Llm::destroy(llm);llm=nullptr;phase_complete(); } catch(...) {} }
        raw_buffer.reset();
        try { BoundFile f(local.options.output+"/raw.txt",1048576);raw=f.read(1048576);raw_valid=utf8(reinterpret_cast<const unsigned char*>(raw.data()),raw.size()); } catch(...) {}
    }
    if(!local.options.output.empty()&&local.events_fd>=0) {
        try {
            Object j=receipt(outcome,finished_context.get(),raw,raw_valid);j.num("expected_exit_code",rc);
            write_new(local.options.output+"/receipt.json",j.done()+"\n");
            Object t=identity(outcome.c_str());t.flag("receipt_complete",true);t.num("expected_exit_code",rc);write_new(local.options.output+"/terminal.json",t.done()+"\n");
        } catch(const std::exception& e) {std::cerr<<"HEPTA_RECEIPT_ERROR "<<e.what()<<"\n";rc=6;}
    }
    local.done=true;if(watchdog.joinable())watchdog.join();if(local.events_fd>=0)::close(local.events_fd);
    return rc;
}
