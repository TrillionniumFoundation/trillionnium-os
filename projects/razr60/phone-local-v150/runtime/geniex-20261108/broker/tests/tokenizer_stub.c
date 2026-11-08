#define _POSIX_C_SOURCE 200809L
/* HOST TEST FIXTURE ONLY. These byte counts and synthetic IDs are not a real
 * tokenizer/model measurement. Never install this library on the phone. */
#include "../vendor/tokenizers_c.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {char *json;int encodes;bool control;} Stub;
TokenizerHandle tokenizers_new_from_str(const char *json,size_t len) {
    Stub *s=calloc(1,sizeof(*s));if(!s)abort();s->json=malloc(len+1);if(!s->json)abort();
    memcpy(s->json,json,len);s->json[len]=0;
    const char *prefix="{\"hepta_tokenizer_host_fixture_v1\":";
    s->control=len<=1024&&len>=strlen(prefix)&&!memcmp(json,prefix,strlen(prefix));
    if(s->control&&strstr(s->json,"\"null_handle\"")){free(s->json);free(s);return NULL;}
    return s;
}
#ifndef HEPTA_FIXTURE_OMIT_ENCODE
void tokenizers_encode(TokenizerHandle handle,const char *data,size_t len,int flag,TokenizerEncodeResult *result) {
    Stub *s=handle;if(flag!=0)abort();s->encodes++;
    if(s->control&&strstr(s->json,"\"abort\""))abort();
    if(s->control&&strstr(s->json,"\"hold\""))sleep(6);
    if(s->control&&strstr(s->json,"\"bad_result\"")){*result=(TokenizerEncodeResult){.token_ids=NULL,.len=7};return;}
    const char *capture=getenv("HEPTA_TOKENIZER_FIXTURE_CAPTURE");
    if(capture){FILE *f=fopen(capture,"ab");if(!f)abort();fprintf(f,"%zu\n",len);if(fwrite(data,1,len,f)!=len)abort();fputc('\n',f);fclose(f);}
    const char *mutate=getenv("HEPTA_TOKENIZER_FIXTURE_MUTATE");
    if(mutate&&s->encodes==1){FILE *f=fopen(mutate,"ab");if(!f)abort();fputc('X',f);fclose(f);}
    const char *race=getenv("HEPTA_TOKENIZER_FIXTURE_RACE_RESULT");
    if(race&&s->encodes==1){FILE *f=fopen(race,"wx");if(!f)abort();fputs("preexisting result wins",f);fclose(f);}
    size_t count=len;const char *forced=s->control?strstr(s->json,"\"forced_count\":"):NULL;
    if(forced&&sscanf(forced,"\"forced_count\": %zu",&count)!=1)abort();
    result->token_ids=malloc(count*sizeof(int));if(!result->token_ids)abort();result->len=count;
    for(size_t i=0;i<count;i++)result->token_ids[i]=(int)(1+i%100);
    if(s->control&&strstr(s->json,"\"negative_id\"")&&count)result->token_ids[0]=-1;
}
#endif
void tokenizers_free_encode_results(TokenizerEncodeResult *results,size_t n) {for(size_t i=0;i<n;i++)free(results[i].token_ids);}
void tokenizers_free(TokenizerHandle handle) {Stub *s=handle;free(s->json);free(s);}
