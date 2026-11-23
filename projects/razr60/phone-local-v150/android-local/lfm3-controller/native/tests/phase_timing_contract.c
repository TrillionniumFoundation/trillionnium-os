#define _GNU_SOURCE 1
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t clock_values[32];
static size_t clock_length,clock_index;
static uint64_t monotonic_ns(void){
    assert(clock_index<clock_length);
    errno=EIO; /* Diagnostic reads must not disturb the worker's saved errno. */
    return clock_values[clock_index++];
}
#include "../phase-timing.h"

static void clocks(const uint64_t *values,size_t length){
    assert(length<=sizeof(clock_values)/sizeof(clock_values[0]));
    memcpy(clock_values,values,length*sizeof(values[0]));clock_length=length;clock_index=0;
    memset(hepta_phase_timings,0,sizeof(hepta_phase_timings));
}
static char *receipt(void){
    char *text=NULL;size_t length=0;FILE *file=open_memstream(&text,&length);assert(file);
    fputc('{',file);hepta_write_phase_timing(file);fputs("\"retained_existing_field\":true}",file);
    assert(fclose(file)==0&&length>0);return text;
}

int main(void){
    /* A failed template can jump straight to cleanup. Completed phases retain
     * their original values, the open phase ends, and later phases stay null. */
    const uint64_t failure_path[]={1000000,6000000,7000000,9000000,10000000,13500000};
    clocks(failure_path,sizeof(failure_path)/sizeof(failure_path[0]));errno=EPERM;
    hepta_timing_begin(HEPTA_TIMED_HASH);hepta_timing_end(HEPTA_TIMED_HASH);
    hepta_timing_begin(HEPTA_TIMED_VOCAB);hepta_timing_end(HEPTA_TIMED_VOCAB);
    hepta_timing_begin(HEPTA_TIMED_TEMPLATE_TOKENIZE);hepta_timing_end_active();
    assert(errno==EPERM&&clock_index==clock_length);
    assert(hepta_phase_timings[HEPTA_TIMED_HASH].elapsed_ns==5000000);
    assert(hepta_phase_timings[HEPTA_TIMED_VOCAB].elapsed_ns==2000000);
    assert(hepta_phase_timings[HEPTA_TIMED_TEMPLATE_TOKENIZE].elapsed_ns==3500000);
    assert(!hepta_phase_timings[HEPTA_TIMED_CREATE].started);
    assert(!hepta_phase_timings[HEPTA_TIMED_GENERATE].started);
    hepta_timing_end_active();hepta_timing_begin(HEPTA_TIMED_HASH);
    assert(clock_index==clock_length); /* Cleanup never rewrites prior timing. */
    char *text=receipt();
    assert(strstr(text,"\"hash\":{\"started\":true,\"ended\":true,\"clock_valid\":true,\"elapsed_ms\":5.000}"));
    assert(strstr(text,"\"generate\":{\"started\":false,\"ended\":false,\"clock_valid\":false,\"elapsed_ms\":null}"));
    puts(text);free(text);

    /* A clock failure/rollback is diagnostic null, never unsigned underflow
     * or a value that could be mistaken for a valid measured zero. */
    const uint64_t invalid_clock[]={0,5000000,9000000,8000000};
    clocks(invalid_clock,sizeof(invalid_clock)/sizeof(invalid_clock[0]));errno=EACCES;
    hepta_timing_begin(HEPTA_TIMED_CREATE);hepta_timing_end(HEPTA_TIMED_CREATE);
    hepta_timing_begin(HEPTA_TIMED_DEINIT);hepta_timing_end(HEPTA_TIMED_DEINIT);
    assert(errno==EACCES&&clock_index==clock_length);
    assert(hepta_phase_timings[HEPTA_TIMED_CREATE].ended&&!hepta_phase_timings[HEPTA_TIMED_CREATE].clock_valid);
    assert(hepta_phase_timings[HEPTA_TIMED_DEINIT].ended&&!hepta_phase_timings[HEPTA_TIMED_DEINIT].clock_valid);
    text=receipt();
    assert(strstr(text,"\"create\":{\"started\":true,\"ended\":true,\"clock_valid\":false,\"elapsed_ms\":null}"));
    puts(text);free(text);

    /* Equal readings are a valid zero-duration measurement. */
    const uint64_t equal_clock[]={7000000,7000000};
    clocks(equal_clock,sizeof(equal_clock)/sizeof(equal_clock[0]));
    hepta_timing_begin(HEPTA_TIMED_GENERATE);hepta_timing_end(HEPTA_TIMED_GENERATE);
    assert(hepta_phase_timings[HEPTA_TIMED_GENERATE].clock_valid);
    assert(hepta_phase_timings[HEPTA_TIMED_GENERATE].elapsed_ns==0);
    text=receipt();puts(text);free(text);
    return 0;
}
