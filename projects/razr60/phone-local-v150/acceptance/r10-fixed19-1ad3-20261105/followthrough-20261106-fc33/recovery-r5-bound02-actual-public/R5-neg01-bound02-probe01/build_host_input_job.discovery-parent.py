from pathlib import Path
import ast,base64,hashlib,json
D=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def need(v,s):
    if not v:raise ValueError(s)
sources={p.name:p for p in (D/'inputs').iterdir() if p.is_file()}
sources['phone-stage.stdout.original.json']=sources.pop('phone-stage.stdout.original')
sources.update({n:D.parent/'R5-root/runtime/source'/n for n in ('stage_component.py','send_new_native_guard_task_r10_r4.py')})
sources['run_component_root_once.py']=D.parent/'R5-root/root-chain/source/run_component_root_once.py'
host={n:{'bytes':len(p.read_bytes()),'sha256':sha(p.read_bytes()),'base64':base64.b64encode(p.read_bytes()).decode()} for n,p in sorted(sources.items())}
raw=enc(host);plan=json.loads((D/'inputs/ROOT-PLAN.original.json').read_bytes());lease=json.loads((D/'inputs/LEASE.original.json').read_bytes());prep=json.loads((D/'inputs/PREPARED.original.json').read_bytes())
old=json.loads((D.parent/'R5-final05-probe01/INPUTS.json').read_bytes())
nonce=plan['nonce'];label=plan['label'];base='/home/alex/razr60-local-model-v150'
frozen={'label':label,'nonce':nonce,'phone_home':prep['phone_home'],'android_home':'/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/'+label,'gnu_stage':'/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1','android_stage':'/proc/1/root/data/local/tmp/hepta-phone-local-v150-r1','lease_sha256':prep['lease']['sha256'],'package_sha256':plan['package']['sha256'],'host_originals_sha256':sha(raw),'sender_root':'/home/alex/codex-hepta-natural-'+label+'-root-v150','destination':base+'/fc33-neg01-bound02-probe-inputs01','baseline':old['baseline'],'boundary':old['boundary'],
 'baseline_host':{'path':base+'/fc33-final05-failed-scope-readonly01-import02/originals/'+old['baseline']['sha256']+'.bin','bytes':old['baseline']['bytes'],'sha256':old['baseline']['sha256']},
 'archive':dict(path='/home/alex/codex-native-guard-chain-r10-r1/'+nonce+'/inputs/component-inputs.tar.gz',**prep['archive']),
 'stage_source':{'path':'/home/alex/codex-native-guard-chain-r10-r1/'+nonce+'/inputs/stage_component.py','bytes':host['stage_component.py']['bytes'],'sha256':host['stage_component.py']['sha256']},
 'sender_archive':{'path':base+'/fc33-neg01-bound02-sender-preservation01/ORIGINALS.PRIVATE.json.gz','bytes':275964,'sha256':'a8f987d6886a405550050e0ade474971f7e4b81773b4f4d81eee8861237d41c9'},
 'sender_public':{'path':base+'/fc33-neg01-bound02-sender-preservation01/PUBLIC-OBSERVATION.json','bytes':27864,'sha256':'79b261a4e6c65b747f983bda939d32ef3aed7a6be523f1d85db5796e8a67a1b2'}}
s=(D/'prepare_inputs_host.template.py').read_text();need(s.count('FROZEN = None')==s.count('HOST_ORIGINALS_RAW = None')==1,'single exact bindings')
bound=s.replace('FROZEN = None','FROZEN = '+repr(frozen),1).replace('HOST_ORIGINALS_RAW = None','HOST_ORIGINALS_RAW = '+repr(raw),1)
t=ast.parse(bound);safe=ast.Module(body=[n for n in t.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef,ast.Assign))],type_ignores=[])
# Use only definitions/imports and the two explicit bindings. Never run the
# remote reads/publication statements during this host-source construction.
safe.body=[n for n in safe.body if not isinstance(n,ast.Assign) or any(isinstance(a,ast.Name) and a.id in ('FROZEN','HOST_ORIGINALS_RAW') for a in n.targets)]
ns={};exec(compile(safe,'<bound02-host-input-pure>','exec'),ns);ns['HOST']=ns['strict'](raw)
proof=ns['terminal_proof']()
(D/'prepare_inputs_host_BOUND.py').write_text(bound)
(D/'HOST-ORIGINALS-MANIFEST.json').write_bytes(enc({n:{k:v for k,v in r.items() if k!='base64'} for n,r in host.items()}))
(D/'SENDER-TERMINAL-PROOF.local.json').write_bytes(enc(proof))
(D/'HOST-PREPARE-BINDING.json').write_bytes(enc({'schema':'hepta.fc33.bound02.host-input-source-binding.v1','source':{'bytes':len(bound.encode()),'sha256':sha(bound.encode())},'frozen':frozen,'host_originals_count':len(host),'host_original_bytes':sum(r['bytes'] for r in host.values()),'host_originals_sha256':sha(raw),'local_terminal_proof':{'bytes':len(enc(proof)),'sha256':sha(enc(proof))},'phone_calls':0}))
print(json.dumps({'source_bytes':len(bound.encode()),'source_sha256':sha(bound.encode()),'host_originals':len(host),'terminal_proof':proof},sort_keys=True))
