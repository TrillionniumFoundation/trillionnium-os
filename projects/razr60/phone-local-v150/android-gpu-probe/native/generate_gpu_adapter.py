"""Pinned GPU diagnostic adapter. Preserves upstream and the proven QAIRT runner."""
from pathlib import Path
import hashlib, json, difflib

def generate_gpu(root, out):
    source=(out/'worker-appuid.c').read_text()
    patches=[
        ('    if(!parse(argc,argv,&o)){usage();return 64;}',
         '    if(!parse(argc,argv,&o)||strcmp(o.runtime,"llama_cpp")||strcmp(o.compute,"gpu")||o.ctx!=8192||o.grammar||(o.vit&&strcmp(o.vit,"CPU")&&strcmp(o.vit,"GPUOpenCL"))){usage();return 64;}'),
        ('static bool output_metadata(', '#include "gpu-budget.inc"\n\nstatic bool output_metadata('),
        ('    hash_bytes(prompt,prompt_size,formatted_sha);',
         '    hash_bytes(prompt,prompt_size,formatted_sha);\n    if(!gpu_count_input(&o,&inputs[3],prompt,prompt_size)){error=gpu_budget.error?gpu_budget.error:"input_budget_failed";goto sdk_cleanup;}'),
        ('    (void)fence(PH_GENERATE);',
         '    if(generate_rc==0&&!gpu_check_profile(&profile))error=gpu_budget.error;\n    (void)fence(PH_GENERATE);'),
        ('json_string(f,outcome);fputs(",\\"error\\":",f);',
         'json_string(f,outcome);gpu_budget_json(f);fputs(",\\"error\\":",f);'),
    ]
    result=source
    for before,after in patches:
        assert result.count(before)==1,repr(before)
        result=result.replace(before,after)
    (out/'worker-gpu-appuid.c').write_text(result)
    diff=''.join(difflib.unified_diff(source.splitlines(True),result.splitlines(True),fromfile='proven/worker-appuid.c',tofile='generated/worker-gpu-appuid.c'))
    (out/'worker-gpu-adapter.diff').write_text(diff)
    receipt={'schema':'hepta.gpu-probe.native-adapter.v1','base_adapter_sha256':hashlib.sha256(source.encode()).hexdigest(),
        'gpu_adapter_sha256':hashlib.sha256(result.encode()).hexdigest(),'budget_source_sha256':hashlib.sha256((root/'native/gpu-budget.inc').read_bytes()).hexdigest(),
        'counter_source_commit':'19cce6919992fdffd92e0ac152caaf1e2b8f254e','generation_context':8192,
        'original_qairt_runner_modified':False,'placeholder_encode_called':False,'profile_equality_required':True}
    (out/'worker-gpu-adapter.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt
