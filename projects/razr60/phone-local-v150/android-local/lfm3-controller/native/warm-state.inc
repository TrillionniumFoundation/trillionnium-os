/* Task-scoped state. Only the serial native owner thread touches SDK handles. */
static bool hepta_warm_enabled,hepta_warm_initialized,hepta_warm_hash_this_request;
static char hepta_warm_generation[33],hepta_warm_task_id[33];
static geniex_LLM *hepta_warm_llm;
static int hepta_warm_sequence,hepta_warm_init_count,hepta_warm_create_count;
static int hepta_warm_hash_count,hepta_warm_reset_count;
static int32_t hepta_warm_reset_rc;

static void hepta_write_warm_contract(FILE *f) {
    if(!hepta_warm_enabled)return;
    fputs("\"worker_generation\":",f);json_string(f,hepta_warm_generation);
    fputs(",\"task_id\":",f);json_string(f,hepta_warm_task_id);
    fprintf(f,",\"request_sequence\":%d,\"worker_retained\":%s,"
        "\"model_hash_scope\":\"task_generation\",\"model_hash_count\":%d,"
        "\"model_hash_performed_this_request\":%s,\"model_create_count\":%d,"
        "\"sdk_init_count\":%d,\"model_reset_count\":%d,\"model_reset_rc\":%" PRId32 ",",
        hepta_warm_sequence,hepta_warm_llm?"true":"false",hepta_warm_hash_count,hepta_warm_hash_this_request?"true":"false",
        hepta_warm_create_count,hepta_warm_init_count,hepta_warm_reset_count,hepta_warm_reset_rc);
}
