#ifndef HEPTA_PHASE_TIMING_H
#define HEPTA_PHASE_TIMING_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

/* Diagnostics only. The worker supplies monotonic_ns(). No timing failure
 * changes a fence, SDK return code, cancellation state or result acceptance.
 * "ended" identifies a timing boundary, not successful stage completion. */
enum HeptaTimedPhase {
    HEPTA_TIMED_HASH,
    HEPTA_TIMED_VOCAB,
    HEPTA_TIMED_CREATE,
    HEPTA_TIMED_TEMPLATE_TOKENIZE,
    HEPTA_TIMED_GENERATE,
    HEPTA_TIMED_DESTROY,
    HEPTA_TIMED_DEINIT,
    HEPTA_TIMED_PHASE_COUNT
};

typedef struct {
    uint64_t start_ns, elapsed_ns;
    bool started, ended, clock_valid;
} HeptaPhaseTiming;

static HeptaPhaseTiming hepta_phase_timings[HEPTA_TIMED_PHASE_COUNT];

static uint64_t hepta_timing_now(void) {
    const int saved_errno=errno;
    const uint64_t value=monotonic_ns();
    errno=saved_errno;
    return value;
}

static void hepta_timing_begin(enum HeptaTimedPhase phase) {
    HeptaPhaseTiming *timing=&hepta_phase_timings[phase];
    if(timing->started)return;
    timing->start_ns=hepta_timing_now();
    timing->started=true;
    timing->clock_valid=timing->start_ns!=0;
}

static void hepta_timing_end(enum HeptaTimedPhase phase) {
    HeptaPhaseTiming *timing=&hepta_phase_timings[phase];
    if(!timing->started||timing->ended)return;
    const uint64_t ended_ns=hepta_timing_now();
    timing->ended=true;
    timing->clock_valid=timing->clock_valid&&ended_ns!=0&&ended_ns>=timing->start_ns;
    if(timing->clock_valid)timing->elapsed_ns=ended_ns-timing->start_ns;
}

/* Error paths can leave template/tokenization early. Close only the active
 * timer on entry to SDK cleanup; previously measured phases stay unchanged. */
static void hepta_timing_end_active(void) {
    for(int phase=0;phase<HEPTA_TIMED_PHASE_COUNT;phase++)
        hepta_timing_end((enum HeptaTimedPhase)phase);
}

static void hepta_write_phase_timing(FILE *file) {
    static const char *names[HEPTA_TIMED_PHASE_COUNT]={
        "hash","vocab","create","template_tokenize","generate","destroy","deinit"
    };
    fputs("\"phase_timing\":{\"schema\":\"hepta.native-phase-timing.v1\","
          "\"clock\":\"CLOCK_MONOTONIC\",\"unit\":\"ms\",\"stages\":{",file);
    for(int phase=0;phase<HEPTA_TIMED_PHASE_COUNT;phase++){
        const HeptaPhaseTiming *timing=&hepta_phase_timings[phase];
        if(phase)fputc(',',file);
        fprintf(file,"\"%s\":{\"started\":%s,\"ended\":%s,\"clock_valid\":%s,\"elapsed_ms\":",
                names[phase],timing->started?"true":"false",timing->ended?"true":"false",
                timing->clock_valid?"true":"false");
        if(timing->started&&timing->ended&&timing->clock_valid)
            fprintf(file,"%.3f",(double)timing->elapsed_ns/1e6);
        else fputs("null",file);
        fputc('}',file);
    }
    fputs("}},",file);
}

#endif
