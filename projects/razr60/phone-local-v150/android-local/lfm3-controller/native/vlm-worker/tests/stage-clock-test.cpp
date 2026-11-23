#include "stage-clock.h"
#include <cassert>
#include <stdexcept>
#include <string>

static uint64_t tick=100;
static uint64_t now() { return tick; }
static std::string contents(FILE *file) {
    std::fflush(file);std::rewind(file);std::string value;char buf[1024];size_t n;
    while((n=std::fread(buf,1,sizeof(buf),file))>0)value.append(buf,n);
    return value;
}
int main() {
    FILE *file=std::tmpfile();assert(file);
    {
        hepta_vlm::StageClock clock(now,"generation-1","request-1",file);
        clock.enter("runtime_hash");tick=500;clock.enter("model_hash");tick=900;
    }
    auto text=contents(file);
    assert(text.find("generation=generation-1 request=request-1 stage=runtime_hash phase=begin monotonic_ns=100")!=std::string::npos);
    assert(text.find("stage=runtime_hash phase=end monotonic_ns=500 elapsed_ns=400 clock_valid=true closed_by=next_stage")!=std::string::npos);
    assert(text.find("stage=model_hash phase=end monotonic_ns=900 elapsed_ns=400 clock_valid=true closed_by=scope_exit")!=std::string::npos);
    std::fclose(file);file=std::tmpfile();assert(file);
    try {
        hepta_vlm::StageClock clock(now,"generation-2","request-2",file);
        clock.enter("constrained_decode");tick=1000;throw std::runtime_error("fixture");
    } catch(const std::runtime_error &) {}
    text=contents(file);assert(text.find("elapsed_ns=100 clock_valid=true closed_by=scope_exit")!=std::string::npos);
    std::fclose(file);file=std::tmpfile();assert(file);
    {
        tick=2000;hepta_vlm::StageClock clock(now,"generation-3","request-3",file);
        clock.enter("resource_teardown");tick=1900;clock.finish();clock.finish();
    }
    text=contents(file);assert(text.find("elapsed_ns=0 clock_valid=false closed_by=explicit")!=std::string::npos);
    assert(text.find("phase=end")==text.rfind("phase=end"));std::fclose(file);
    std::puts("{\"passed\":true,\"checks\":6,\"phone_contacted\":false,\"model_inference_performed\":false}");
}
