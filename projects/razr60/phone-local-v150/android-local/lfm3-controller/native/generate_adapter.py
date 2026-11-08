"""Generate closed model profiles and context guards; preserve upstream source."""
from pathlib import Path
import hashlib, json, difflib

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
    old='if(n<=0)return false;p+=n;size-=(size_t)n;'
    new='if(n<=0){int saved=errno;fprintf(stderr,"HEPTA_APPUID_PUBLISH stage=write_all fd=%d errno=%d error=%s\\n",fd,saved,strerror(saved));return false;}p+=n;size-=(size_t)n;'
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
    replace_once('static bool output_metadata(', '#include "model-runtime.inc"\n\nstatic bool output_metadata(')
    replace_once('    if(!fence(PH_RESOLVE))goto sdk_cleanup;', '''    if(!hepta_verify_model(o.model)){error="pinned_model_identity_failed";goto sdk_cleanup;}
    if(!fence(PH_RESOLVE))goto sdk_cleanup;''')
    replace_once('    if(device.warning){error="device_was_coerced";goto sdk_cleanup;}', '''    if(device.warning){error="device_was_coerced";goto sdk_cleanup;}
    const char *expected_device=!strcmp(o.compute,"npu")?"HTP0":"GPUOpenCL";
    if(!device.device_id||strcmp(device.device_id,expected_device)||device.ngl==0){error="requested_accelerator_not_selected";goto sdk_cleanup;}''')
    replace_once('    created=true;', '''    if(!hepta_load_vocabulary()){error="pinned_vocabulary_or_architecture_failed";goto sdk_cleanup;}
    if(!hepta_model_is_unchanged(o.model)||!fence(PH_CREATE)){error="model_changed_before_create";goto sdk_cleanup;}
    created=true;''')
    assert adapted.count('.model_path=o.model')==2
    adapted=adapted.replace('.model_path=o.model','.model_path=hepta_model_fd_path')
    marker='    hash_bytes(prompt,prompt_size,formatted_sha);\n'
    assert adapted.count(marker)==1
    adapted=adapted.replace(marker, marker + '''    if(!hepta_prepare_prompt(prompt,prompt_size,o.max_tokens,o.ctx)) {
        error="formatted_prompt_exceeds_fixed_context";goto sdk_cleanup;
    }
    hepta_release_vocabulary();
    if(!hepta_model_is_unchanged(o.model)){error="model_changed_before_generation";goto sdk_cleanup;}
''')
    replace_once('.top_p=1.0f,.top_k=1,.repetition_penalty=1.0f', '.top_p=1.0f,.top_k=1,.min_p=0.0f,.repetition_penalty=1.0f')
    replace_once('.chat_template_grammar=vlm?vt.chat_template_grammar:lt.chat_template_grammar',
                 '.chat_template_grammar=inputs[2].bytes?(geniex_ChatTemplateGrammar){0}:(vlm?vt.chat_template_grammar:lt.chat_template_grammar)')
    replace_once('else{geniex_LlmGenerateInput in={.prompt_utf8=prompt,.config=&generation,.on_token=on_token};',
                 'else{geniex_LlmGenerateInput in={.prompt_utf8=hepta_model_profile->exact_tokens?NULL:prompt,.input_ids=hepta_input_ids,.input_ids_count=hepta_input_count,.config=&generation,.on_token=on_token};')
    replace_once('    generated=true;', '    hepta_prompt_budget.input_ids_passed=hepta_model_profile->exact_tokens&&hepta_input_ids&&hepta_input_count>0;\n    generated=true;')
    replace_once('sdk_cleanup:\n', 'sdk_cleanup:\n    hepta_release_vocabulary();\n')
    replace_once('    bool complete=generated&&generate_rc==0', '''    hepta_model_unchanged=hepta_model_verified&&hepta_model_is_unchanged(o.model);
    if(!hepta_model_unchanged){unchanged=false;if(!error)error="model_changed_during_request";}
    bool complete=generated&&generate_rc==0''')
    replace_once('final_close:\n', 'final_close:\n    hepta_model_cleanup();\n')
    lines=adapted.splitlines(True)
    insertions=0
    for index,line in enumerate(lines):
        if line.startswith('    fputs(') and 'request_id' in line and 'SDK_PIN' in line:
            lines[index]='    hepta_write_model_contract(f);\n    hepta_write_prompt_budget(f);\n'+line
            insertions+=1
    assert insertions==1
    adapted=''.join(lines)
    (out/'worker-appuid.c').write_text(adapted)
    difference=''.join(difflib.unified_diff(source.splitlines(True),adapted.splitlines(True),fromfile='frozen/worker-upstream.c',tofile='generated/worker-appuid.c'))
    (out/'worker-adapter.diff').write_text(difference)
    receipt={'upstream_sha256':upstream_sha,'adapted_sha256':hashlib.sha256(adapted.encode()).hexdigest(),
        'publication':'renameat2(RENAME_NOREPLACE)','no_overwrite':True,'fallback_overwriting_rename':False,
        'errno_diagnostics':['write_all','file_fsync','renameat2_noreplace','directory_fsync'],
        'runtime':'llama_cpp','mode':'llm','compute_modes':['npu','gpu'],'context_sizes':[4096,8192],
        'prompt_guard':'LFM3 original byte bound; other profiles exact same input_ids + output + reserve256',
        'llama_source_commit':'19cce6919992fdffd92e0ac152caaf1e2b8f254e',
        'model_verification':'native full SHA256, exact filename/size/architecture, held descriptor, unchanged metadata',
        'new_profile_exact_token_count':True,'no_context_truncation':True,
        'controller_grammar':'optional fixed-schema per-observation GBNF; same private request directory and native SHA binding',
        'model_contract_sha256':'43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452'}
    (out/'worker-adapter.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt
