from pathlib import Path
import ast,hashlib,json
D=Path(__file__).resolve().parent;P=D.parent/'R5-neg01-bound02-probe01'
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def need(v,s):
    if not v:raise ValueError(s)
manifest=json.loads((D/'MANIFEST.json').read_bytes());auth_raw=(D/'AUTHORITY.json').read_bytes();auth=json.loads(auth_raw);targets_raw=(D/'TARGETS.original.json').read_bytes();controller_raw=(P/'ROOT-READONLY-DISPATCH-CONTROLLER.original.json').read_bytes();root_manifest_raw=(D.parent/'R5-root/root-chain/SOURCE-MANIFEST.json').read_bytes()
need(len(root_manifest_raw)==50107 and sha(root_manifest_raw)=='f9145ce2f0e5864a78ed8bece2d926187dc83e8baf15799758200bb646057282','actual original root source manifest')
bound={'source':manifest['source'],'request':manifest['request'],'targets':auth['source_targets'],'report':auth['scope_report'],'inputs':auth['input_original'],'actor':{'path':'/home/alex/razr60-local-model-v150/ops/phone_once.py','bytes':5652,'sha256':'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'},'label':manifest['actor_label'],'operation':'/home/alex/razr60-local-model-v150/operations/'+manifest['actor_label'],'admission':'/home/alex/razr60-local-model-v150/fc33-neg01-bound02-owned-recovery01-HOST-ADMISSION.json'}
parent=(P/'prepare_inputs_host.template.py').read_text();t=ast.parse(parent);names=['need','sha','enc','strict','full9','original','terminal_proof'];defs={n.name:ast.get_source_segment(parent,n) for n in t.body if isinstance(n,ast.FunctionDef)}
header='#!/usr/bin/env python3\n"""Root-reviewed host preservation gate. --verify-only never calls phone."""\nfrom pathlib import Path\nimport argparse,ast,base64,hashlib,json,lzma,os,shlex,stat,zlib\n'
for name,value in [('BOUND',bound),('AUTHORITY_RAW',auth_raw),('TARGETS_RAW',targets_raw),('CONTROLLER_RAW',controller_raw),('ROOT_SOURCE_MANIFEST_RAW',root_manifest_raw),('FROZEN',None),('HOST',None)]:header+=name+' = '+repr(value)+'\n'
extension=(D/'host_guard_extension.py').read_bytes();source=header.encode()+('\n\n'.join(defs[n] for n in names)+'\n\n').encode()+extension+b'\nif __name__=="__main__":raise SystemExit(guard_main())\n'
ast.parse(source);ns={'__name__':'host_guard_definition_only'};exec(compile(source,'<host-guard-review>','exec'),ns);need(ns['CACHE']=={} and ns['READ_BYTES']==0 and ns['HOST'] is None,'guard definition load no I/O')
proof=json.loads((P/'SENDER-TERMINAL-PROOF.json').read_bytes());host_source=(P/'prepare_inputs_host_BOUND.py').read_text();tree=ast.parse(host_source)
host_raw=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(a,ast.Name) and a.id=='HOST_ORIGINALS_RAW' for a in n.targets)))
ns['HOST']=json.loads(host_raw);inputs=json.loads((P/'INPUTS.json').read_bytes());ns['FROZEN']={'label':inputs['label'],'sender_root':'/home/alex/codex-hepta-natural-'+inputs['label']+'-root-v150','lease_sha256':inputs['lease_sha256'],'package_sha256':inputs['package_sha256']}
need(ns['terminal_proof']()==proof,'same actual terminal proof full pure revalidation')
readonly_request=(P/'PHONE-REQUEST.json').read_bytes();result_pin=json.loads(targets_raw)['source_result'];controller=ns['verify_controller'](json.loads(controller_raw),readonly_request,result_pin)
(D/'HOST-PRE-DISPATCH.py').write_bytes(source)
report={'schema':'hepta.fc33.bound02.host-preservation-guard-binding.v1','source':{'bytes':len(source),'sha256':sha(source)},'extension':{'bytes':len(extension),'sha256':sha(extension)},'source_binding':bound,'actual_readonly_controller':{'bytes':len(controller_raw),'sha256':sha(controller_raw)},'actual_root_source_manifest':{'bytes':len(root_manifest_raw),'sha256':sha(root_manifest_raw)},'same_exact_host_terminal_pure_control':True,'same_actual_readonly_controller_fullEOF_control':controller,'phone_execution_performed':False,'admission_file_created':False}
(D/'HOST-GUARD-BINDING.json').write_bytes(enc(report))
dispatch={'host':'pocket4','executable':'/usr/bin/python3','args':['-I','-B','-','--execute-once'],'stdin':source.decode(),'idempotency_key':manifest['idempotency_key'],'timeout_seconds':180}
(D/'DISPATCH.json').write_bytes(enc(dispatch));preview=dict(dispatch,args=['-I','-B','-','--verify-only'],idempotency_key='fc33-neg01-bound02-recovery01-host-preview01',timeout_seconds=90);(D/'HOST-PREVIEW-REQUEST.json').write_bytes(enc(preview))
print(json.dumps({'source':report['source'],'extension':report['extension'],'readonly_controller':controller,'dispatch_bytes':len(enc(dispatch)),'preview_key':preview['idempotency_key'],'phone_calls':0},sort_keys=True))
