/* Included after the worker JSON helpers and the closed model profile table.
 * Only Orvena changes requested sampling. The SDK 0.10.0 zero-value defaults
 * remain untouched: top_k=40/min_p=.05 are explicit SDK-compatible conditions,
 * not additional values asserted to be in the model's generation_config.json.
 */
static bool hepta_orvena_sampler(void){
    return hepta_model_profile&&hepta_model_profile->id&&
        !strcmp(hepta_model_profile->id,"orvena-4b-q4_k_m");
}

static geniex_SamplerConfig hepta_requested_sampler(void){
    geniex_SamplerConfig sampler={.temperature=0.0f,.top_p=1.0f,.top_k=1,
        .min_p=0.0f,.repetition_penalty=1.0f,.seed=42};
    if(hepta_orvena_sampler()){
        sampler.temperature=0.7f;
        sampler.top_p=0.8f;
        sampler.top_k=40;
        sampler.min_p=0.05f;
        sampler.presence_penalty=0.0f;
        sampler.frequency_penalty=0.0f;
    }
    return sampler;
}

/* Serialize the actual request-local object supplied to geniex_llm_generate.
 * Non-Orvena retains the original five-key JSON shape and numeric spelling.
 * Orvena records all explicit numeric fields, including their real F32 values.
 */
static void hepta_write_sampler_requested(FILE *f,const geniex_SamplerConfig *sampler){
    fputs("\"sampler_requested\":{\"temperature\":",f);json_double(f,sampler->temperature);
    fputs(",\"top_p\":",f);json_double(f,sampler->top_p);
    fprintf(f,",\"top_k\":%" PRId32 ",\"repetition_penalty\":",sampler->top_k);
    json_double(f,sampler->repetition_penalty);
    fprintf(f,",\"seed\":%" PRId32,sampler->seed);
    if(hepta_orvena_sampler()){
        fputs(",\"min_p\":",f);json_double(f,sampler->min_p);
        fputs(",\"presence_penalty\":",f);json_double(f,sampler->presence_penalty);
        fputs(",\"frequency_penalty\":",f);json_double(f,sampler->frequency_penalty);
    }
    fputs("},\"image_token_bounds_exposed_by_abi\":false,",f);
}
