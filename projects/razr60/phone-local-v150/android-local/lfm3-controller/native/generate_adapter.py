"""Generate Android publication + pinned LFM3 context guard; preserve upstream source."""
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
        fputs("fixed LFM3 text adapter accepts only llama_cpp llm npu/gpu, ctx4096/8192, no media\\n",stderr);return 64;
    }
    if(o.grammar){
        const char *grammar_name=strrchr(o.grammar,'/'),*prompt_name=strrchr(o.prompt,'/');
        if(!grammar_name||!prompt_name||strcmp(grammar_name,"/grammar.gbnf")||
           grammar_name-o.grammar!=prompt_name-o.prompt||strncmp(o.grammar,o.prompt,(size_t)(prompt_name-o.prompt))){
            fputs("controller grammar must be grammar.gbnf in the same canonical private request directory\\n",stderr);return 64;
        }
    }
''')
    marker='    hash_bytes(prompt,prompt_size,formatted_sha);\n'
    assert adapted.count(marker)==1
    adapted=adapted.replace(marker, marker + '''    if(!hepta_check_prompt_budget(prompt_size,o.max_tokens,o.ctx)) {
        error="formatted_prompt_exceeds_fixed_context";goto sdk_cleanup;
    }
''')
    lines=adapted.splitlines(True)
    insertions=0
    for index,line in enumerate(lines):
        if line.startswith('    fputs(') and 'request_id' in line and 'SDK_PIN' in line:
            lines[index]='    hepta_write_prompt_budget(f);\n'+line
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
        'prompt_guard':'actual rendered UTF-8 byte bound + 2 special + output + reserve256',
        'prompt_guard_is_exact_token_count':False,'no_context_truncation':True,
        'controller_grammar':'optional fixed-schema per-observation GBNF; same private request directory and native SHA binding',
        'model_contract_sha256':'43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452'}
    (out/'worker-adapter.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt
