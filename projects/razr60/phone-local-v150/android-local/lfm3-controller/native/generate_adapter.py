"""Generate closed model profiles and context guards; preserve upstream source."""
from pathlib import Path
import hashlib, json, difflib
from prompt_evidence_adapter import adapt as add_prompt_evidence
from warm_runtime_adapter import adapt as add_warm_runtime

def generate(root, out):
    source_path=root/'native/worker-upstream.c'
    original=source_path.read_bytes()
    upstream_sha=hashlib.sha256(original).hexdigest()
    assert upstream_sha=='07cd434bea9d1214acef499a69ed204ecef879a6ac05c82f24d062160e2efb3e'
    source=original.decode('utf-8')
    first=source.index('static bool publish(Destination *d) {')
    last=source.index('static void destination_close(',first)
    replacement=(root/'native/publish-appuid.inc').read_text()
    adapted=source[:first]+replacement+'\n'+source[last:]
    # The probe sets feature macros before its first system include. glibc may
    # raise their values for _GNU_SOURCE; a subsequently included worker must
    # preserve that already-selected feature set. Standalone generation keeps
    # the original POSIX/XOPEN defaults when neither macro has been defined.
    feature_prefix = '#define _POSIX_C_SOURCE 200809L\n#define _XOPEN_SOURCE 700\n'
    assert adapted.startswith(feature_prefix)
    guarded_prefix = '#ifndef _POSIX_C_SOURCE\n#define _POSIX_C_SOURCE 200809L\n#endif\n#ifndef _XOPEN_SOURCE\n#define _XOPEN_SOURCE 700\n#endif\n'
    adapted = guarded_prefix + adapted[len(feature_prefix):]
    # Replace only the generated primitive. The pinned upstream bytes, full
    # per-request model read, SHA comparison, held FD and metadata fences stay.
    first=adapted.index('typedef struct { uint32_t h[8]; uint64_t bits; unsigned char block[64]; size_t used; } Sha256;')
    last=adapted.index('static bool utf8(',first)
    adapted=adapted[:first]+'#include "sha256-dispatch.h"\n\n'+adapted[last:]
    old='if(n<=0)return false;p+=n;size-=(size_t)n;'
    new='if(n<=0){int saved=errno;fprintf(stderr,"HEPTA_APPUID_PUBLISH stage=write_all fd=%d errno=%d error=%s\\n",fd,saved,strerror(saved));errno=saved;return false;}p+=n;size-=(size_t)n;'
    assert adapted.count(old)==1
    adapted=adapted.replace(old,new)
    marker='    if(!parse(argc,argv,&o)){usage();return 64;}\n'
    assert adapted.count(marker)==1
    adapted=adapted.replace(marker, marker + '''    if(strcmp(o.runtime,"llama_cpp")||strcmp(o.mode,"llm")||o.image||o.mmproj||o.tokenizer||o.vit||
       (strcmp(o.compute,"npu")&&strcmp(o.compute,"gpu"))||(o.ctx!=4096&&o.ctx!=8192)) {
        fputs("pinned text adapter accepts only llama_cpp llm npu/gpu, ctx4096/8192, no media\\n",stderr);return 64;
    }
    if(o.grammar){
        const char *grammar_name=strrchr(o.grammar,'/'),*prompt_name=strrchr(o.prompt,'/');
        if(!grammar_name||!prompt_name||strcmp(grammar_name,"/grammar.gbnf")||
           grammar_name-o.grammar!=prompt_name-o.prompt||strncmp(o.grammar,o.prompt,(size_t)(prompt_name-o.prompt))){
            fputs("controller grammar must be grammar.gbnf in the same canonical private request directory\\n",stderr);return 64;
        }
    }
''')
    def replace_once(old,new):
        nonlocal adapted
        assert adapted.count(old)==1,old
        adapted=adapted.replace(old,new)
    replace_once('static bool output_metadata(', '#include "model-runtime.inc"\n#include "sampler-profile.inc"\n#include "phase-timing.h"\n\nstatic bool output_metadata(')
    replace_once('    if(!fence(PH_RESOLVE))goto sdk_cleanup;', '''    if(!hepta_verify_model(o.model)){error="pinned_model_identity_failed";goto sdk_cleanup;}
    if(!fence(PH_RESOLVE))goto sdk_cleanup;''')
    replace_once('    if(!hepta_verify_model(o.model)){error="pinned_model_identity_failed";goto sdk_cleanup;}', '''    hepta_timing_begin(HEPTA_TIMED_HASH);
    bool hepta_hash_ok=hepta_verify_model(o.model);
    hepta_timing_end(HEPTA_TIMED_HASH);
    if(!hepta_hash_ok){error="pinned_model_identity_failed";goto sdk_cleanup;}''')
    replace_once('    if(device.warning){error="device_was_coerced";goto sdk_cleanup;}', '''    if(device.warning){error="device_was_coerced";goto sdk_cleanup;}
    const char *expected_device=!strcmp(o.compute,"npu")?"HTP0":"GPUOpenCL";
    if(!device.device_id||strcmp(device.device_id,expected_device)||device.ngl==0){error="requested_accelerator_not_selected";goto sdk_cleanup;}''')
    replace_once('    created=true;', '''    hepta_timing_begin(HEPTA_TIMED_VOCAB);
    bool hepta_vocab_ok=hepta_load_vocabulary();
    hepta_timing_end(HEPTA_TIMED_VOCAB);
    if(!hepta_vocab_ok){error="pinned_vocabulary_or_architecture_failed";goto sdk_cleanup;}
    if(!hepta_model_is_unchanged(o.model)||!fence(PH_CREATE)){error="model_changed_before_create";goto sdk_cleanup;}
    created=true;
    hepta_timing_begin(HEPTA_TIMED_CREATE);''')
    replace_once('    if(create_rc!=0||(!llm&&!vlm)){error="model_create_failed";goto sdk_cleanup;}', '''    hepta_timing_end(HEPTA_TIMED_CREATE);
    if(create_rc!=0||(!llm&&!vlm)){error="model_create_failed";goto sdk_cleanup;}''')
    replace_once('    templated=true;', '    templated=true;\n    hepta_timing_begin(HEPTA_TIMED_TEMPLATE_TOKENIZE);')
    assert adapted.count('.model_path=o.model')==2
    adapted=adapted.replace('.model_path=o.model','.model_path=hepta_model_fd_path')
    marker='    hash_bytes(prompt,prompt_size,formatted_sha);\n'
    assert adapted.count(marker)==1
    adapted=adapted.replace(marker, marker + '''    if(!hepta_prepare_prompt(prompt,prompt_size,o.max_tokens,o.ctx)) {
        error="formatted_prompt_exceeds_fixed_context";goto sdk_cleanup;
    }
    hepta_release_vocabulary();
    if(!hepta_model_is_unchanged(o.model)){error="model_changed_before_generation";goto sdk_cleanup;}
    hepta_timing_end(HEPTA_TIMED_TEMPLATE_TOKENIZE);
''')
    # One fresh request-local sampler is both consumed by the SDK and serialized.
    # This also runs on every invocation of the existing warm worker request path.
    replace_once('    geniex_LlmGenerateOutput lo={0};geniex_VlmGenerateOutput vo={0};geniex_ProfileData profile={0};',
                 '    geniex_SamplerConfig sampler=hepta_requested_sampler();\n    geniex_LlmGenerateOutput lo={0};geniex_VlmGenerateOutput vo={0};geniex_ProfileData profile={0};')
    replace_once('    geniex_SamplerConfig sampler={.temperature=0.0f,.top_p=1.0f,.top_k=1,.repetition_penalty=1.0f,.seed=42,\n'
                 '        .grammar_string=(char*)inputs[2].bytes,.chat_template_grammar=vlm?vt.chat_template_grammar:lt.chat_template_grammar};',
                 '    sampler.grammar_string=(char*)inputs[2].bytes;\n'
                 '    sampler.chat_template_grammar=vlm?vt.chat_template_grammar:lt.chat_template_grammar;')
    replace_once('    const geniex_ProfileData *profile,const char *stop,',
                 '    const geniex_SamplerConfig *sampler,const geniex_ProfileData *profile,const char *stop,')
    replace_once('generate_rc,destroy_rc,deinit_rc,&profile,stop,',
                 'generate_rc,destroy_rc,deinit_rc,&sampler,&profile,stop,')
    sampler_lines=[line for line in adapted.splitlines() if 'sampler_requested' in line]
    assert len(sampler_lines)==1
    replace_once(sampler_lines[0], '    hepta_write_sampler_requested(f,sampler);')
    replace_once('.chat_template_grammar=vlm?vt.chat_template_grammar:lt.chat_template_grammar',
                 '.chat_template_grammar=inputs[2].bytes?(geniex_ChatTemplateGrammar){0}:(vlm?vt.chat_template_grammar:lt.chat_template_grammar)')
    replace_once('else{geniex_LlmGenerateInput in={.prompt_utf8=prompt,.config=&generation,.on_token=on_token};',
                 'else{geniex_LlmGenerateInput in={.prompt_utf8=hepta_model_profile->exact_tokens?NULL:prompt,.input_ids=hepta_input_ids,.input_ids_count=hepta_input_count,.config=&generation,.on_token=on_token};')
    replace_once('    generated=true;', '    hepta_prompt_budget.input_ids_passed=hepta_model_profile->exact_tokens&&hepta_input_ids&&hepta_input_count>0;\n    generated=true;\n    hepta_timing_begin(HEPTA_TIMED_GENERATE);')
    replace_once('    (void)fence(PH_GENERATE);', '    hepta_timing_end(HEPTA_TIMED_GENERATE);\n    (void)fence(PH_GENERATE);')
    replace_once('sdk_cleanup:\n', 'sdk_cleanup:\n    hepta_timing_end_active();\n    hepta_release_vocabulary();\n')
    replace_once('    current_phase=PH_DESTROY;', '    current_phase=PH_DESTROY;\n    if(vlm||llm)hepta_timing_begin(HEPTA_TIMED_DESTROY);')
    replace_once('    if(llm){destroyed=true;destroy_rc=geniex_llm_destroy(llm);}', '''    if(llm){destroyed=true;destroy_rc=geniex_llm_destroy(llm);}
    hepta_timing_end(HEPTA_TIMED_DESTROY);''')
    replace_once('    current_phase=PH_DEINIT;if(initialized&&init_rc==0)deinit_rc=geniex_deinit();', '''    current_phase=PH_DEINIT;
    if(initialized&&init_rc==0){
        hepta_timing_begin(HEPTA_TIMED_DEINIT);
        deinit_rc=geniex_deinit();
        hepta_timing_end(HEPTA_TIMED_DEINIT);
    }''')
    replace_once('    bool complete=generated&&generate_rc==0', '''    hepta_model_unchanged=hepta_model_verified&&hepta_model_is_unchanged(o.model);
    if(!hepta_model_unchanged){unchanged=false;if(!error)error="model_changed_during_request";}
    bool complete=generated&&generate_rc==0''')
    replace_once('final_close:\n', 'final_close:\n    hepta_model_cleanup();\n')
    lines=adapted.splitlines(True)
    insertions=0
    for index,line in enumerate(lines):
        if line.startswith('    fputs(') and 'request_id' in line and 'SDK_PIN' in line:
            lines[index]='    hepta_write_model_contract(f);\n    hepta_write_prompt_budget(f);\n    hepta_write_phase_timing(f);\n'+line
            insertions+=1
    assert insertions==1
    adapted=''.join(lines)
    adapted=add_prompt_evidence(adapted)
    adapted=add_warm_runtime(adapted)
    # App-owned warm cancellation policy; the pinned upstream file stays exact.
    # One-shot calls pass false and keep their original signal behavior.
    replace_once('#include <signal.h>\n', '#include <signal.h>\n#include <poll.h>\n')
    replace_once('static bool install_signals(void) {', 'static bool install_signals(bool owned_warm) {')
    replace_once('    struct sigaction a;memset(&a,0,sizeof(a));a.sa_handler=on_signal;sigemptyset(&a.sa_mask);',
                 '''    struct sigaction a;memset(&a,0,sizeof(a));a.sa_handler=on_signal;sigemptyset(&a.sa_mask);
    if(owned_warm){
        /* Eligible syscalls may restart; actual FastRPC behavior remains unproven. */
        a.sa_flags=SA_RESTART;
        /* Process.destroy may close the parent's control pipe. EPIPE must reach
         * the warm owner so SDK cleanup runs; it is never a successful CLOSE. */
        struct sigaction pipe_action;memset(&pipe_action,0,sizeof(pipe_action));
        pipe_action.sa_handler=SIG_IGN;sigemptyset(&pipe_action.sa_mask);
        if(sigaction(SIGPIPE,&pipe_action,NULL)!=0)return false;
    }''')
    replace_once('    if(!install_signals())return 74;',
                 '    if(!install_signals(hepta_warm_enabled))return 74;')
    (out/'worker-appuid.c').write_text(adapted)
    difference=''.join(difflib.unified_diff(source.splitlines(True),adapted.splitlines(True),fromfile='frozen/worker-upstream.c',tofile='generated/worker-appuid.c'))
    (out/'worker-adapter.diff').write_text(difference)
    receipt={'upstream_sha256':upstream_sha,'adapted_sha256':hashlib.sha256(adapted.encode()).hexdigest(),
        'publication':'renameat2(RENAME_NOREPLACE)','no_overwrite':True,'fallback_overwriting_rename':False,
        'errno_diagnostics':['write_all','file_fsync','renameat2_noreplace','directory_fsync'],
        'runtime':'llama_cpp','mode':'llm','compute_modes':['npu','gpu'],'context_sizes':[4096,8192],
        'prompt_guard':'all pinned profiles including LFM3: exact same input_ids + output + reserve256',
        'llama_source_commit':'19cce6919992fdffd92e0ac152caaf1e2b8f254e',
        'model_verification':'native full SHA256, exact filename/size/architecture, held descriptor, unchanged metadata',
        'sha256_dispatch':'runtime HWCAP_SHA2; target(sha2) function; exact upstream portable compression fallback',
        'model_digest_cache':False,'full_model_read_every_one_shot_request':True,
        'warm_cancellation_policy':{'eligible_syscalls_restart':True,'sigpipe_ignored_only_in_warm_process':True,
            'control_epipe_does_not_skip_sdk_cleanup':True,'sdk_or_phone_healthy_cancellation_verified':False},
        'task_worker_mode':{'schema':'hepta.geniex-task-request.result.v1','hash_scope':'one_full_read_per_owned_generation',
            'reuse_scope':'one_task','reset_every_request':True,'one_shot_contract_unchanged':True},
        'private_prompt_evidence':'create-only formatted bytes and actual direct input IDs; same private request directory',
        'new_profile_exact_token_count':True,'no_context_truncation':True,
        'phase_timing_schema':'hepta.native-phase-timing.v1',
        'phase_timing_clock':'CLOCK_MONOTONIC',
        'phase_timing_stages':['hash','vocab','create','template_tokenize','generate','destroy','deinit'],
        'phase_timing_diagnostic_only':True,
        'controller_grammar':'optional fixed-schema per-observation GBNF; same private request directory and native SHA binding',
        'model_contract_sha256':'43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452'}
    (out/'worker-adapter.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt
