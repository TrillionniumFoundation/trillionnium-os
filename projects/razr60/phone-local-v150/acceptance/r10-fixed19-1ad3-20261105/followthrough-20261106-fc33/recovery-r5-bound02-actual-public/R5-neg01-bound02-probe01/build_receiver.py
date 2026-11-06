from pathlib import Path
import ast,hashlib,json
D=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def need(v,s):
    if not v:raise ValueError(s)
donor=D.parent/'R5-final05-probe01/verify_probe_result_host_v2.py';raw=donor.read_bytes();s=raw.decode();wanted=['need','sha','enc','strict','full9','read_exact','decode_zlib','write_new','check_metadata_row','tree_complete'];t=ast.parse(s)
defs={n.name:ast.get_source_segment(s,n) for n in t.body if isinstance(n,ast.FunctionDef)}
header='#!/usr/bin/env python3\n"""P4 host-only complete private receiver; no phone, signal, or subprocess."""\nfrom pathlib import Path\nimport argparse,ast,base64,hashlib,io,json,os,re,shlex,stat,tarfile,zlib\n'
manifest=json.loads((D/'MANIFEST.json').read_bytes());inputs=(D/'INPUTS.json').read_bytes()
bindings={'SOURCE_BYTES':manifest['source']['bytes'],'SOURCE_SHA':manifest['source']['sha256'],'REQUEST_BYTES':manifest['request']['bytes'],'REQUEST_SHA':manifest['request']['sha256'],'INPUTS_BYTES':len(inputs),'INPUTS_SHA':sha(inputs),'ACTOR_LABEL':manifest['dispatch']['label']}
header+=''.join(k+' = '+repr(v)+'\n' for k,v in bindings.items())+'\n'
extension=(D/'receiver_extension.py').read_bytes();source=header.encode()+('\n\n'.join(defs[n] for n in wanted)+'\n\n').encode()+extension+b'\nif __name__=="__main__":raise SystemExit(receiver_main())\n'
tree=ast.parse(source);need(not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id in ('subprocess','socket','signal') for n in ast.walk(tree)),'host receiver no phone or signal path')
ns={'__name__':'independent_bound02_receiver_review'};exec(compile(source,'<receiver-review>','exec'),ns)
need(all(ast.get_source_segment(source.decode(),next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name))==defs[name] for name in wanted),'complete unchanged original host receiver helpers')
(D/'verify_probe_result_host.py').write_bytes(source)
report={'schema':'hepta.fc33.bound02.independent-host-receiver-derivation.v1','source':{'bytes':len(source),'sha256':sha(source)},'parent':{'bytes':len(raw),'sha256':sha(raw)},'unchanged_helpers':wanted,'extension':{'bytes':len(extension),'sha256':sha(extension)},'bindings':bindings,'production_or_phone_source_executed':False,'host_definition_load_only':True,'private_UI_bodies_in_public_report':False,'actual_result_binding':'CLI must supply Root observed exact result path, bytes, sha256, and version; no task invocation','scope_closure':False}
(D/'HOST-RECEIVER-DERIVATION.json').write_bytes(enc(report));print(json.dumps(report,sort_keys=True))
