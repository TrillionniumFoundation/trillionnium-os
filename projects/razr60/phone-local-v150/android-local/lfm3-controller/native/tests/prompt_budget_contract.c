#include <assert.h>
#include <string.h>
#include "../prompt-budget.h"

int main(void) {
    assert(hepta_check_prompt_budget(3582,256,4096));
    assert(hepta_prompt_budget.total_upper==4096);
    assert(!hepta_check_prompt_budget(3583,256,4096));
    assert(!hepta_check_prompt_budget(0,256,4096));
    assert(!hepta_check_prompt_budget(20,0,4096));
    assert(!hepta_check_prompt_budget(20,1025,4096));
    assert(!hepta_check_prompt_budget(20,256,0));
    assert(!hepta_check_prompt_budget(20,256,32768));
    assert(hepta_check_prompt_budget(7678,256,8192));
    assert(!hepta_check_prompt_budget(7679,256,8192));
    assert(!hepta_check_prompt_budget(SIZE_MAX,256,4096));
    assert(hepta_check_prompt_budget(strlen("中文😀"),256,4096));
    assert(hepta_prompt_budget.formatted_bytes==10);
    FILE *file=tmpfile(); assert(file);
    hepta_write_prompt_budget(file); assert(fflush(file)==0); rewind(file);
    char json[2048]={0};size_t length=fread(json,1,sizeof(json)-1,file);assert(length>0);fclose(file);
    assert(strstr(json,"\"is_exact_token_count\":false"));
    assert(strstr(json,"\"formatted_utf8_bytes\":10"));
    assert(strstr(json,HEPTA_MODEL_SHA256));
    puts("PASS: rendered UTF-8 budget boundaries, overflow, invalid configuration and receipt");
    return 0;
}
