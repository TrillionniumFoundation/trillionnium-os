#ifndef HEPTA_FIRST_TOKEN_CHECKPOINT_H
#define HEPTA_FIRST_TOKEN_CHECKPOINT_H
/* Diagnostic metadata only. Never grants action authority, extends a deadline,
 * retries generation, or establishes native cleanup. No generated text is logged. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
typedef struct {
    bool armed, emitted;
    char generation[33], task[33], request[33];
} HeptaFirstTokenCheckpoint;
static bool hepta_first_token_id(const char *s) {
    if(!s||strlen(s)!=32)return false;
    for(size_t i=0;i<32;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return false;
    return true;
}
static void hepta_first_token_begin(HeptaFirstTokenCheckpoint *s,bool warm,
        const char *generation,const char *task,const char *request) {
    memset(s,0,sizeof(*s));
    if(!warm||!hepta_first_token_id(generation)||!hepta_first_token_id(task)||!hepta_first_token_id(request))return;
    memcpy(s->generation,generation,33);memcpy(s->task,task,33);memcpy(s->request,request,33);s->armed=true;
}
static void hepta_first_token_observe(HeptaFirstTokenCheckpoint *s,FILE *log,size_t size,
        uint64_t callbacks,uint64_t now,pid_t pid) {
    if(!s->armed||s->emitted||!size)return;
    s->emitted=true; /* At most one attempt per actual request, including logging failure. */
    if(!log||!callbacks||!now||pid<=0)return;
    int saved_errno=errno;
    (void)fprintf(log,"HEPTA_FIRST_NONEMPTY_TOKEN schema=hepta.first-token-checkpoint.v1 task_id=%s worker_generation=%s request_id=%s pid=%ld clock=CLOCK_MONOTONIC monotonic_ns=%" PRIu64 " callback_count=%" PRIu64 " diagnostics_only=true\n",
            s->task,s->generation,s->request,(long)pid,now,callbacks);
    (void)fflush(log); /* Visibility in the existing task-generation stderr log; no fsync or new file. */
    errno=saved_errno; /* Diagnostic failure does not change callback cancellation/error semantics. */
}
#endif
