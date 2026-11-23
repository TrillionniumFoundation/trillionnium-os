"""Explicit task-lifetime SDK reuse; the original one-shot branch remains available."""


def adapt(source):
    def once(old, new):
        nonlocal source
        if source.count(old) != 1:
            raise ValueError("warm integration location differs: " + old)
        source = source.replace(old, new)

    once('#include "phase-timing.h"', '#include "phase-timing.h"\n#include "warm-state.inc"')
    once('    hepta_write_model_contract(f);',
         '    hepta_write_warm_contract(f);\n    hepta_write_model_contract(f);')
    once('fputs("{\\"schema\\":\\"hepta.geniex-once.result.v1\\",\\"production_receipt\\":false,\\"native_action_authorized\\":false,\\"process_exit_observed\\":false,",f);',
         'fputs(hepta_warm_enabled?"{\\"schema\\":\\"hepta.geniex-task-request.result.v1\\",\\"production_receipt\\":false,\\"native_action_authorized\\":false,\\"process_exit_observed\\":false,":'
         '"{\\"schema\\":\\"hepta.geniex-once.result.v1\\",\\"production_receipt\\":false,\\"native_action_authorized\\":false,\\"process_exit_observed\\":false,",f);')
    once('json_rc(f,initialized&&init_rc==0,deinit_rc);',
         'json_rc(f,initialized&&init_rc==0&&!hepta_warm_enabled,deinit_rc);')
    once('    hepta_timing_begin(HEPTA_TIMED_HASH);\n    bool hepta_hash_ok=hepta_verify_model(o.model);\n    hepta_timing_end(HEPTA_TIMED_HASH);', '''    bool hepta_hash_ok;
    hepta_warm_hash_this_request=!hepta_warm_enabled||!hepta_model_verified;
    if(hepta_warm_hash_this_request){
        if(hepta_warm_enabled)hepta_warm_hash_count++;
        hepta_timing_begin(HEPTA_TIMED_HASH);
        hepta_hash_ok=hepta_verify_model(o.model);
        hepta_timing_end(HEPTA_TIMED_HASH);
    }else hepta_hash_ok=hepta_model_is_unchanged(o.model);''')
    once('    initialized=true;init_rc=geniex_init();if(init_rc!=0){error="sdk_init_failed";goto sdk_cleanup;}', '''    if(!hepta_warm_enabled||!hepta_warm_initialized){
        initialized=true;if(hepta_warm_enabled)hepta_warm_init_count++;
        init_rc=geniex_init();
        if(init_rc!=0){error="sdk_init_failed";goto sdk_cleanup;}
        if(hepta_warm_enabled)hepta_warm_initialized=true;
    }''')
    once('    hepta_timing_begin(HEPTA_TIMED_VOCAB);\n    bool hepta_vocab_ok=hepta_load_vocabulary();\n    hepta_timing_end(HEPTA_TIMED_VOCAB);', '''    bool hepta_vocab_ok=hepta_vocabulary_model!=NULL;
    if(!hepta_vocab_ok){
        hepta_timing_begin(HEPTA_TIMED_VOCAB);
        hepta_vocab_ok=hepta_load_vocabulary();
        hepta_timing_end(HEPTA_TIMED_VOCAB);
    }''')
    once('    created=true;\n    hepta_timing_begin(HEPTA_TIMED_CREATE);', '''    if(hepta_warm_enabled&&hepta_warm_llm)llm=hepta_warm_llm;
    else{
    created=true;if(hepta_warm_enabled)hepta_warm_create_count++;
    hepta_timing_begin(HEPTA_TIMED_CREATE);''')
    once('    hepta_timing_end(HEPTA_TIMED_CREATE);\n    if(create_rc!=0', '''    hepta_timing_end(HEPTA_TIMED_CREATE);
    if(hepta_warm_enabled)hepta_warm_llm=llm;
    }
    if(create_rc!=0''')
    # Both releases are per-request in the original path. Warm mode retains a
    # vocabulary-only model and frees the direct input IDs after every request.
    if source.count('    hepta_release_vocabulary();') != 2:
        raise ValueError('vocabulary release count differs')
    source=source.replace('    hepta_release_vocabulary();',
                          '    if(!hepta_warm_enabled)hepta_release_vocabulary();')
    once('    if(!fence(PH_GENERATE))goto sdk_cleanup;', '''    if(!fence(PH_GENERATE))goto sdk_cleanup;
    if(hepta_warm_enabled){
        hepta_warm_reset_count++;
        hepta_warm_reset_rc=geniex_llm_reset(llm);
        if(hepta_warm_reset_rc!=0){error="task_model_reset_failed";goto sdk_cleanup;}
        if(!fence(PH_GENERATE))goto sdk_cleanup;
    }''')
    once('    if(llm){destroyed=true;destroy_rc=geniex_llm_destroy(llm);}',
         '    if(llm&&!hepta_warm_enabled){destroyed=true;destroy_rc=geniex_llm_destroy(llm);}')
    once('    if(initialized&&init_rc==0){\n        hepta_timing_begin(HEPTA_TIMED_DEINIT);',
         '    if(initialized&&init_rc==0&&!hepta_warm_enabled){\n        hepta_timing_begin(HEPTA_TIMED_DEINIT);')
    once('    if(vlm||llm)hepta_timing_begin(HEPTA_TIMED_DESTROY);',
         '    if(vlm||(llm&&!hepta_warm_enabled))hepta_timing_begin(HEPTA_TIMED_DESTROY);')
    once('    hepta_model_cleanup();', '''    if(!hepta_warm_enabled)hepta_model_cleanup();
    else{free(hepta_input_ids);hepta_input_ids=NULL;hepta_input_count=0;}''')
    once('    fprintf(f,",\\"input_metadata_unchanged\\":%s,\\"generation_complete\\":%s,\\"worker_exit_status_planned\\":%d,\\"worker_outcome\\":",unchanged?"true":"false",complete?"true":"false",exit_status);', '''    fprintf(f,",\\"input_metadata_unchanged\\":%s,\\"generation_complete\\":%s,",unchanged?"true":"false",complete?"true":"false");
    if(hepta_warm_enabled)fprintf(f,"\\"worker_exit_status_planned\\":null,\\"request_status\\":%d,\\"worker_outcome\\":",exit_status);
    else fprintf(f,"\\"worker_exit_status_planned\\":%d,\\"worker_outcome\\":",exit_status);''')
    return source
