/* Host only. The frozen worker is unmodified; this SDK fixture selects faults
 * from explicit fixture markers. Never compile into an Android candidate. */
#define geniex_vlm_generate original_fixture_vlm_generate
#define geniex_vlm_apply_chat_template original_fixture_vlm_apply_chat_template
#include "../../tests/stub_geniex.c"
#undef geniex_vlm_generate
#undef geniex_vlm_apply_chat_template

int32_t geniex_vlm_apply_chat_template(geniex_VLM *handle,const geniex_VlmApplyChatTemplateInput *in,geniex_VlmApplyChatTemplateOutput *out) {
    assert(handle && !in->enable_thinking && !in->parallel_tool_calls && in->message_count==2);
    const geniex_VlmChatMessage *user=&in->messages[1];
    assert(user->content_count==1 || user->content_count==2);
    const char *system=in->messages[0].contents[0].text,*prompt=user->contents[0].text;
    const char *marker=user->content_count==2?"<__image__>":"";
    const char *head="<|im_start|>system\n",*middle="<|im_end|>\n<|im_start|>user\n",*tail="<|im_end|>\n<|im_start|>assistant\n";
    size_t length=strlen(head)+strlen(system)+strlen(middle)+strlen(marker)+strlen(prompt)+strlen(tail);
    out->formatted_text=malloc(length+1);assert(out->formatted_text);
    assert(snprintf(out->formatted_text,length+1,"%s%s%s%s%s%s",head,system,middle,marker,prompt,tail)==(int)length);
    return 0;
}

int32_t geniex_vlm_generate(geniex_VLM *handle,const geniex_VlmGenerateInput *in,geniex_VlmGenerateOutput *out) {
    if(strstr(in->prompt_utf8,"[[case=sdk_abort]]"))abort();
    if(strstr(in->prompt_utf8,"[[case=exit134]]"))_exit(134);
    if(strstr(in->prompt_utf8,"[[case=exit124]]"))_exit(124);
    if(strstr(in->prompt_utf8,"[[case=worker_deadline]]"))delay_ms(750);
    const char *cases[]={"length","generate_fail_with_text","generate_fail","signal_last_token","hard_hang","deadline"};
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++){
        char marker[96];snprintf(marker,sizeof(marker),"[[case=%s]]",cases[i]);
        if(strstr(in->prompt_utf8,marker))setenv("STUB_CASE",cases[i],1);
    }
    const char *valid="{\"name\":\"mobile_use\",\"arguments\":{\"action\":\"screenshot\",\"display_id\":0,\"summary\":\"Inspect current screen\"}}";
    if(strstr(in->prompt_utf8,"[[case=malformed_json]]"))valid="{\"name\":\"mobile_use\",\"arguments\":{\"action\":\"screenshot\"}";
    setenv("STUB_TEXT",valid,1);
    int32_t rc=original_fixture_vlm_generate(handle,in,out);
    /* Match this host fixture's byte-count tokenizer exactly. These synthetic
     * counts are never presented as official tokenizer or NPU measurements. */
    assert(in->config->image_count==0 || in->config->image_count==1);
    size_t count=strlen(in->prompt_utf8);
    if(in->config->image_count){assert(strstr(in->prompt_utf8,"<__image__>"));count-=strlen("<__image__>");count+=258;}
    out->profile_data.prompt_tokens=(int64_t)count;
    return rc;
}
