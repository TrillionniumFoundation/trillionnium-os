#ifndef HEPTA_VLM_STAGE_CLOCK_H
#define HEPTA_VLM_STAGE_CLOCK_H

#include <cstdint>
#include <cstdio>

namespace hepta_vlm {
// Diagnostic-only monotonic intervals. These lines confer no result, ownership,
// freshness, acceleration or dispatch authority and never change a deadline.
class StageClock {
    using Clock = uint64_t (*)();
    Clock now_;
    const char *generation_,*request_,*stage_=nullptr;
    FILE *stream_;
    uint64_t start_=0;
public:
    StageClock(Clock now,const char *generation,const char *request,FILE *stream=stderr) noexcept
        :now_(now),generation_(generation),request_(request),stream_(stream) {}
    StageClock(const StageClock &)=delete;
    StageClock &operator=(const StageClock &)=delete;
    ~StageClock() noexcept { finish("scope_exit"); }
    void enter(const char *stage) noexcept {
        finish("next_stage");stage_=stage;start_=now_();
        std::fprintf(stream_,"HEPTA_VLM_STAGE v=1 generation=%s request=%s stage=%s phase=begin monotonic_ns=%llu\n",
                generation_,request_,stage_,static_cast<unsigned long long>(start_));
    }
    void finish(const char *reason="explicit") noexcept {
        if(!stage_)return;
        const uint64_t end=now_();const bool valid=start_>0 && end>=start_;
        std::fprintf(stream_,"HEPTA_VLM_STAGE v=1 generation=%s request=%s stage=%s phase=end monotonic_ns=%llu elapsed_ns=%llu clock_valid=%s closed_by=%s\n",
                generation_,request_,stage_,static_cast<unsigned long long>(end),
                static_cast<unsigned long long>(valid?end-start_:0),valid?"true":"false",reason);
        stage_=nullptr;
    }
};
}
#endif
