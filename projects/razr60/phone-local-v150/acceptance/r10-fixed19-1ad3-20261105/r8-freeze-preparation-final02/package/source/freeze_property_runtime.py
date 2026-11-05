#!/usr/bin/env python3
"""Create-only R8 host freeze after a new explicitly adopted property policy.

This source candidate is disabled by FINALIZATION=None. It preserves all five
actual native failures and the separate non-native attempt05. It does not
construct or apply a policy, call a phone, create a native nonce, or run a case.
"""
import argparse
import ast
import copy
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types
sys.dont_write_bytecode=True
B=Path("/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1")
PARENT=B/'native-guard-r10-r1-operator-r7'
PARENT_ROOT_DIRECTORY=B/'native-guard-r10-r1-root-launch-budget01'
CANDIDATE=B/'native-guard-property-tail-r8-candidate01'
ROOT_CANDIDATE=B/'native-guard-property-root-r8-transport-candidate03-1ad3'
OUT=B/'native-guard-r10-r1-operator-r8'
FINALIZATION=None
PARENT_PKG='683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c'
PARENT_ROOT='a47fc188ab7e6998419ec072530c1e9c38efd47f0219c3ac19aa9a7f32331d91'
PARENT_COMBINATION='ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'
PARENT_POLICY='50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
PARENT_ADOPTION='a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5'
NEW_REFERENCE='reference/property_parent_late_boundary_r7.py'
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
FIXED={key:(Path(value[0]),value[1],value[2]) for key,value in json.loads("{\"parent_freeze_result\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r7/FREEZE-RESULT.json\",24722,\"14e8e4c12b7ec7f4e1ea3d7bdeda0d5116f3a7bb0785a50cc82b3cc1158c2974\"],\"parent_runtime_manifest\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r7/runtime/MANIFEST.json\",13446,\"683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c\"],\"parent_root_manifest\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-root-launch-budget01/SOURCE-MANIFEST.json\",8259,\"a47fc188ab7e6998419ec072530c1e9c38efd47f0219c3ac19aa9a7f32331d91\"],\"parent_combination\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r7/COMBINATION.json\",4702,\"ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837\"],\"parent_adoption\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-native5-r10-live-root-02/POLICY-ADOPTION.json\",146368,\"a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5\"],\"reader_candidate_manifest\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-property-tail-r8-candidate01/SOURCE-MANIFEST.json\",1703,\"c3be417dbaf310ac05e27390d3c02eb0e20297aeecd0acd8ffce84052cf7b73c\"],\"root_candidate_manifest\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-property-root-r8-transport-candidate03-1ad3/SOURCE-MANIFEST.json\",4450,\"077c86ee40a5e239ed7c46200d414624d4e8b76d8e936c101b1cabdaefac3aa8\"],\"shared_materials\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/r10-boundary-consumers-material-r1/actual-material-01/SHARED-MATERIALS.json\",3519,\"121416839ffdac15485270cda0e95445e376b0a24801fa283659a3da084ae45f\"],\"history08_boundary\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/LATE-BOUNDARY.original.json\",9373,\"eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10\"],\"history08_inventory\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/INVENTORY.json\",849854,\"80b8a56ee78055c19caf3b342af5bc5e479180843b0f3bc223751649188b7fc4\"],\"history08_closure\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/CLOSURE.json\",54785,\"7e42ed77926bdf3bc728e4aef5009ffb23d50adfe1f6ce6b9e236fc621aa17cb\"],\"history07_boundary\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/LATE-BOUNDARY.original.json\",9078,\"46b03cd66426395198b4a3093117659d5cfb128cc981815934fc1ea695c97be0\"],\"history07_inventory\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/INVENTORY.json\",776988,\"32726cebc8d85dc7086073ba9d6494248a3ec625826a5ed635cffa6715811432\"],\"history07_closure\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07/CLOSURE.json\",25716,\"d5a6433d473ced291328536664497d9fa9861b42f126ecf9ad189df497520a57\"],\"history06_boundary\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-06/LATE-BOUNDARY.original.json\",8774,\"eca628a18327146b7710a478fc2c2f716f79d55907b2821666828a0795e2060f\"],\"history06_inventory\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-06/INVENTORY.json\",737114,\"fcd752b17eed7d36718f81e61a0f81d22554aa1a478180371619de1c10d98759\"],\"history06_closure\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-06/CLOSURE.json\",54878,\"8fc9d05e877d91f6706558968276848e252784414983ea026b5c9ef00a8deb2a\"],\"history04_boundary\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261104-04/LATE-BOUNDARY.original.json\",4748,\"3216ab18adcafa0dda95e8a93ad35a2070e7aec286d7a518794918068ce31d12\"],\"history04_inventory\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261104-04/INVENTORY.json\",633600,\"e48c39003bd26f65dde74958f0081a89c23027da19a11afd4fc2a81414c5c349\"],\"history04_closure\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261104-04/CLOSURE.json\",49087,\"559f2440fdd1c9f43c64399351f3fda0be95890d21cbde4aea211751e5f9aa81\"],\"history03_boundary\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-attempt03-external-publication-r1/actual-02/originals/BOUNDARY.original.json\",5003,\"ee008c3b2adec701be4c0bdfd38ca7ac0d650da9b7783f51d3fe4638bfdc5b58\"],\"history03_inventory\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-attempt03-external-publication-r1/actual-02/originals/AFTER-INVENTORY.original.json\",563365,\"145d5937cd328ed568b1af9c73f7d331211d1c44cfad8ecf960b47d91f308eee\"],\"history03_closure\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-attempt03-external-publication-r1/actual-02/originals/CLOSURE.original.json\",119753,\"b8a27617eaff8dda0f1c61b5aa14a89d7014a157e0b33280b14162c7591bcaa3\"],\"history08_descriptor\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/LATE-BOUNDARY-DESCRIPTOR.json\",367,\"724d7d54679299433498654530ad3dc082c107aa76fde9de54b0ed6c0ad3de08\"],\"history08_previous\":[\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/ACTUAL-PREVIOUS-INPUT.json\",1428,\"9133e2511a66a809be647cb8bb49e3afb351825db5e465f75b1f2f0b6d9d88f4\"]}").items()}

def need(v,m):
    if not v:raise ValueError(m)

def sha(b):return hashlib.sha256(b).hexdigest()

def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()

def combination_enc(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()

def strict(b):
    def pairs(rows):
        d={}
        for k,v in rows:need(k not in d,'duplicate key');d[k]=v
        return d
    return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))

def desc(p,b):return {'path':str(p),'bytes':len(b),'sha256':sha(b)}

def metadata(v):return [getattr(v,k) for k in META]

class Originals:
    def __init__(self):self.observed={};self.raw={}
    def read(self,row):
        need(type(row) is dict and set(row)=={'path','bytes','sha256'}
             and type(row['bytes']) is int and 0<=row['bytes']<=64*1024*1024
             and isinstance(row['sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['sha256']),'exact bounded descriptor')
        p=Path(row['path']);need(p.is_absolute() and str(p)==row['path'] and p.resolve(strict=True)==p,'canonical original path')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==row['bytes'],'bounded original regular file')
            with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(row['bytes']+1)
            m=metadata(a);need(len(b)==row['bytes'] and sha(b)==row['sha256']
                 and m==metadata(os.fstat(fd))==metadata(p.lstat()),'original pin or metadata changed')
        finally:os.close(fd)
        if str(p) in self.observed:need(self.observed[str(p)]==m and self.raw[str(p)]==b,'original changed during freeze')
        self.observed[str(p)]=m;self.raw[str(p)]=b
        return b
    def fixed(self,key):
        p,n,h=FIXED[key];return self.read({'path':str(p),'bytes':n,'sha256':h})
    def recheck(self):
        for p,b in list(self.raw.items()):self.read(desc(p,b))

def members(o,root,mf):
    rows=mf['files'];need(type(rows) is list and len({r['path'] for r in rows})==len(rows),'unique complete manifest members')
    result={}
    for r in rows:
        n=r['path'];p=Path(n)
        need(set(r)=={'path','bytes','sha256'} and str(p)==n and not p.is_absolute()
             and '..' not in p.parts and n not in ('','.'),'canonical relative manifest member')
        result[n]=o.read({'path':str(root/p),'bytes':r['bytes'],'sha256':r['sha256']})
    return result

def assignment(raw,name):
    text=raw.decode();tree=ast.parse(text)
    nodes=[n for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1
           and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name]
    need(len(nodes)==1,'one fixed assignment required: '+name)
    node=nodes[0];need(node.lineno==node.end_lineno,'single-line literal assignment')
    lines=text.splitlines(keepends=True);old=lines[node.lineno-1]
    return ast.literal_eval(node.value),old

def fill(raw,name,expected,value):
    old,whole=assignment(raw,name);need(old==expected,'original assignment differs: '+name)
    line=whole.split('#',1)[0].rstrip()
    need('=' in line,'literal assignment marker')
    new=name+'='+repr(value)+whole[len(line):]
    text=raw.decode();need(text.count(whole)==1,'whole assignment not unique')
    result=text.replace(whole,new,1).encode()
    # Reverse the actual line rather than guessing quote or whitespace style.
    _,actual_line=assignment(result,name)
    need(result.decode().replace(actual_line,whole,1).encode()==raw,'pin assignment inverse differs')
    return result

def modules(rawmap,root):
    saved=sys.modules.get('component_common');old_path=sys.path[:];old_dwb=sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode=True
        common=types.ModuleType('component_common');common.__file__=str(root/'source/component_common.py')
        sys.modules['component_common']=common
        exec(compile(rawmap['source/component_common.py'],common.__file__,'exec'),common.__dict__)
        late=types.ModuleType('reviewed_r7_late');late.__file__=str(root/'source/late_boundary.py')
        late.__reviewed_source_sha256__=sha(rawmap['source/late_boundary.py']);late.__reviewed_package_sources__=rawmap
        exec(compile(rawmap['source/late_boundary.py'],late.__file__,'exec'),late.__dict__)
        return common,late
    finally:
        sys.path[:]=old_path;sys.dont_write_bytecode=old_dwb
        if saved is None:sys.modules.pop('component_common',None)
        else:sys.modules['component_common']=saved

def newdir(path):
    path.mkdir(mode=0o700)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def put(path,b):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def require_finalization():
    f=FINALIZATION
    need(type(f) is dict and set(f)=={'schema','scope_decision','policy_adoption',
         'verifier_source','actual_export','combination_sha256'}
         and f['schema']=='hepta.native-guard.property-policy-finalization.v1',
         'new property-policy scope, adoption, verifier and combination are not reviewed')
    for key in ('scope_decision','policy_adoption','verifier_source','actual_export'):
        row=f[key]
        need(type(row) is dict and set(row)=={'path','bytes','sha256'}
             and type(row['bytes']) is int and 0<row['bytes']<=16*1024*1024
             and isinstance(row['path'],str) and Path(row['path']).is_absolute()
             and isinstance(row['sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['sha256']),
             'explicit future original descriptor differs: '+key)
    need(f['verifier_source']['bytes']<=131072
         and f['policy_adoption']['sha256']!=PARENT_ADOPTION
         and f['actual_export']['sha256']!=PARENT_POLICY
         and isinstance(f['combination_sha256'],str)
         and re.fullmatch('[0-9a-f]{64}',f['combination_sha256'])
         and f['combination_sha256']!=PARENT_COMBINATION,
         'a new explicit policy generation must not reuse its historical identity')
    return f


def historical_originals(o,late):
    records=late.property_parent_records()
    values=[];inventories=[];closings=[]
    for name,record in zip(('08','07','06','04','03'),records):
        raw=o.fixed('history'+name+'_boundary')
        inv=o.fixed('history'+name+'_inventory')
        closed=o.fixed('history'+name+'_closure')
        original=late.property_parent_reader()
        value,inventory,closure=original.closed_boundary_originals(
            raw,inv,closed,original_descriptor=record['boundary'],
            combination_sha256=PARENT_COMBINATION,package_sha256=PARENT_PKG)
        need(value['component_qualified'] is False and value['native_status']=='provider_failed'
             and type(closure['unknown_effects']) is int and closure['unknown_effects']==0,
             'a retained failed original cannot supply current qualification')
        values.append(value);inventories.append(inventory);closings.append(closure)
    late.require_failed_ancestor_tail(values)
    need(strict(o.fixed('history08_descriptor'))==records[0]['boundary'],
         'exact actual08 full original descriptor differs')
    previous=strict(o.fixed('history08_previous'))
    need(previous['identity']==values[0]['scope'] and previous['late_boundary']==records[0]['boundary']
         and previous['component_qualified'] is False
         and previous['terminal']['status']=='provider_failed'
         and previous['known_all_dispatched_tools_confirmed_terminal'] is True
         and previous['automatic_replay'] is False,
         'actual08 latest native previous input differs')
    side=late.non_native_sidebranch()
    role_rows=[tuple(row) for value in values for row in value['component_role_identities'].values()]
    role_rows.extend(tuple(row) for row in side['binding']['component_role_identities'].values())
    need(len(role_rows)==len(set(role_rows))==18 and len(role_rows)<=24,
         'exact retained component roles changed or duplicate a generation')
    need(late.effective_prior_inventory(values[0],inventories[0],side) is inventories[0],
         'actual08 retains its own complete cumulative inventory')
    return records,values,inventories,closings,side,role_rows


def build(plan,raw):
    f=require_finalization()
    need(type(plan) is dict and set(plan)==set(FIXED)|{'schema','finalization','out'}
         and plan['schema']=='hepta.native-guard.property-r8-freeze-inputs.v1'
         and plan['out']==str(OUT) and plan['finalization']==f,
         'exact explicitly reviewed R8 freeze inputs are required')
    o=Originals()
    for key,(path,size,digest) in FIXED.items():
        need(plan[key]=={'path':str(path),'bytes':size,'sha256':digest},
             'fixed immutable source input differs: '+key)
        o.read(plan[key])
    parent_result=strict(o.fixed('parent_freeze_result'))
    need(parent_result['runtime_manifest']==plan['parent_runtime_manifest']
         and parent_result['combination']==plan['parent_combination']
         and parent_result['policy_adoption']==plan['parent_adoption']
         and parent_result['actual_adopted_policy_sha256']==PARENT_POLICY
         and parent_result['all_inputs_rechecked'] is True
         and parent_result['all_output_files_read_back'] is True,
         'actual parent R7 freeze result differs')
    parent_manifest=strict(o.fixed('parent_runtime_manifest'))
    parent_files=members(o,PARENT/'runtime',parent_manifest)
    need(len(parent_files)==31 and parent_manifest['current_policy_sha256']==PARENT_POLICY
         and parent_manifest['current_combination_sha256']==PARENT_COMBINATION
         and parent_manifest['explicit_policy_adoption_sha256']==PARENT_ADOPTION,
         'exact original R7 runtime generation required')
    root_manifest=strict(o.fixed('parent_root_manifest'))
    root_parent=members(o,PARENT_ROOT_DIRECTORY,root_manifest)
    root_names={'source/run_component_root_once.py','source/phone_chain_bridge.py',
                'reference/policy_native5_verifier.py'}
    need(set(root_parent)==root_names and root_manifest['frozen_component_package_sha256']==PARENT_PKG
         and root_manifest['current_combination_sha256']==PARENT_COMBINATION,
         'actual Q2 Root source package differs')
    candidate_manifest=strict(o.fixed('reader_candidate_manifest'))
    candidate=members(o,CANDIDATE,candidate_manifest)
    need(candidate_manifest['state']=='SOURCE_ONLY_NOT_FROZEN'
         and candidate_manifest['runtime_proposed_count']==32
         and sha(candidate['source/late_boundary.py'])=='f42cf7da63df8e3ecd31e984b2deac5d5fc7e1ee0f2bdbb095a8268243a133d4'
         and candidate[NEW_REFERENCE]==parent_files['source/late_boundary.py'],
         'reviewed R8 reader source candidate differs')
    gates=strict(candidate['validation/HOST-RESULT.json'])
    need(gates['state']=='HISTORICAL_ORIGINALS_VERIFIED_NEW_CURRENT_PINS_UNFROZEN'
         and len(gates['checks'])==8 and all(row['passed'] is True for row in gates['checks'])
         and gates['qualification_claimed'] is False and gates['main_calls']==gates['phone_calls']==0,
         'actual reviewed historical reader source checks differ')
    root_candidate_manifest=strict(o.fixed('root_candidate_manifest'))
    root_candidate=members(o,ROOT_CANDIDATE,root_candidate_manifest)
    need(root_candidate_manifest['state']=='HOST_SOURCE_ONLY_NOT_ROOT_EXECUTION_READY'
         and sha(root_candidate['source/run_component_root_once.py'])=='50a500e0c1cc014d3d4043f8c86172bf0b6068719473eb5646aca818416ed649'
         and sha(root_candidate['source/phone_chain_bridge.py'])=='6694b106ee8ccf2177bf758367fda214f27b7ebfbea1611e11e67604a2bfd572',
         'reviewed exact08 Root admission candidate differs')
    root_gates=strict(root_candidate['validation/HOST-RESULT.json'])
    need(root_gates['state']=='FIVE_NARROW_SOURCE_CHECKS_PASSED'
         and len(root_gates['checks'])==5 and all(row['passed'] is True for row in root_gates['checks'])
         and root_gates['main_calls']==root_gates['phone_calls']==0,
         'actual reviewed Root source gates differ')
    for key in ('scope_decision','policy_adoption','verifier_source','actual_export'):
        o.read(f[key])
    adoption_raw=o.read(f['policy_adoption']);adoption=strict(adoption_raw)
    verifier_raw=o.read(f['verifier_source'])
    verifier=types.ModuleType('reviewed_r8_property_policy_verifier')
    verifier.__file__=f['verifier_source']['path']
    verifier.__reviewed_source_sha256__=sha(verifier_raw)
    exec(compile(verifier_raw,verifier.__file__,'exec'),verifier.__dict__)
    verified=verifier.verify_adoption(adoption_raw,read_pinned=o.read)
    actual=o.read(f['actual_export'])
    need(adoption['actual_export']==f['actual_export']
         and verified['runtime_policy']=={'bytes':len(actual),'sha256':sha(actual)}
         and verified['current_adoption_sha256']==sha(adoption_raw)==f['policy_adoption']['sha256']
         and verified['root_scope_decision_sha256']==f['scope_decision']['sha256']
         and verified['parent_adoption_sha256']==PARENT_ADOPTION
         and verified['prior_boundary_sha256']=='eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10',
         'new explicit property-policy adoption does not retain actual50f/a5f/08')
    parent_combo_raw=o.fixed('parent_combination');parent_combo=strict(parent_combo_raw)
    need(combination_enc(parent_combo)==parent_combo_raw and parent_combo['live_policy_sha256']==PARENT_POLICY,
         'original canonical parent combination differs')
    combo=copy.deepcopy(parent_combo);combo['live_policy_sha256']=sha(actual)
    combo_raw=combination_enc(combo)
    reversed_combo=copy.deepcopy(combo);reversed_combo['live_policy_sha256']=PARENT_POLICY
    need(combination_enc(reversed_combo)==parent_combo_raw and sha(combo_raw)==f['combination_sha256'],
         'only the reviewed current policy pin may change in this combination')
    runtime=dict(parent_files)
    late_source=candidate['source/late_boundary.py']
    for name,value in (
        ('REVIEWED_CURRENT_COMBINATION_SHA256',sha(combo_raw)),
        ('REVIEWED_CURRENT_POLICY_SHA256',sha(actual)),
        ('REVIEWED_CURRENT_POLICY_ADOPTION_SHA256',sha(adoption_raw))):
        late_source=fill(late_source,name,None,value)
    reverse=late_source
    for name in ('REVIEWED_CURRENT_COMBINATION_SHA256','REVIEWED_CURRENT_POLICY_SHA256',
                 'REVIEWED_CURRENT_POLICY_ADOPTION_SHA256'):
        value,_=assignment(reverse,name);reverse=fill(reverse,name,value,None)
    # fill preserves the reviewed source's complete line on each inverse pair;
    # normalizing all three values back to None must also restore every byte.
    for name in ('REVIEWED_CURRENT_COMBINATION_SHA256','REVIEWED_CURRENT_POLICY_SHA256',
                 'REVIEWED_CURRENT_POLICY_ADOPTION_SHA256'):
        _,old_line=assignment(candidate['source/late_boundary.py'],name)
        _,new_line=assignment(reverse,name)
        reverse=reverse.decode().replace(new_line,old_line,1).encode()
    need(reverse==candidate['source/late_boundary.py'],'three current reader pins must reverse to exact reviewed source')
    runtime['source/late_boundary.py']=late_source
    runtime[NEW_REFERENCE]=candidate[NEW_REFERENCE]
    need(len(runtime)==32 and set(runtime)==set(parent_files)|{NEW_REFERENCE}
         and sum(runtime[name]==body for name,body in parent_files.items())==30,
         'exact runtime32 is one changed current reader plus one exact old R7 reference')
    common,late=modules(runtime,OUT/'runtime')
    records,values,inventories,closings,side,roles=historical_originals(o,late)
    need(side['binding']==parent_manifest['non_native_sidebranch']
         and verified['retirement_sha256']==values[0]['retirement']['proof']['sha256'],
         'non-native attempt05 or original retirement lineage changed')
    shared_raw=o.fixed('shared_materials');shared=strict(shared_raw)
    need(shared['schema']=='hepta.r10.shared-production-materials.v1'
         and len(shared['files'])==17,'same actual seventeen shared originals required')
    shared_root=Path(plan['shared_materials']['path']).parent
    shared_files=members(o,shared_root,shared)
    production=strict(runtime['reference/REVIEWED-PRODUCTION-PINS.json'])
    need(set(shared_files)=={'provider/source/'+name for name in production}
          |{'local-config-r10-r1.json','PHONE-SERVICE-INPUTS-v150-r10-r1.json'}
         and all(sha(shared_files['provider/source/'+name])==digest for name,digest in production.items()),
         'shared production15/configuration/service must remain exact original bytes')
    new_manifest=copy.deepcopy(parent_manifest)
    new_manifest.update(revision='r10-r1-operator-r8',parent_package_sha256=PARENT_PKG,
        current_combination_sha256=sha(combo_raw),current_policy_sha256=sha(actual),
        explicit_policy_adoption_sha256=sha(adoption_raw),actual_combination_generated=True,
        current_combination_unchanged=False,
        property_parent_ancestors=records[:2],
        full_historical_tail_is_exact_actual08_then07_then06_then04_then_external03=True,
        full_historical_tail_is_exact_actual06_then_actual04_then_external03=False,
        retained_environment_suffix_is_exact_actual06_then04_then_external03=True,
        files=[{'path':name,'bytes':len(body),'sha256':sha(body)} for name,body in sorted(runtime.items())])
    mf_raw=enc(new_manifest);new_pkg=sha(mf_raw)
    need(new_pkg not in (PARENT_PKG,late.POLICY_PARENT_PACKAGE_SHA256,
         late.ENVIRONMENT_PARENT_PACKAGE_SHA256,late.LEGACY_PACKAGE_SHA256),'new R8 source generation required')
    for name,record in zip(('08','07','06','04','03'),records):
        late.closed_boundary_originals(o.fixed('history'+name+'_boundary'),
            o.fixed('history'+name+'_inventory'),o.fixed('history'+name+'_closure'),
            original_descriptor=record['boundary'],combination_sha256=sha(combo_raw),package_sha256=new_pkg)
    late.require_failed_ancestor_tail(values)
    coordinator=root_candidate['source/run_component_root_once.py']
    current_slots={'PKG':new_pkg,'COMBINATION':sha(combo_raw),'VERIFIER_SHA':sha(verifier_raw),
        'VERIFIER_BYTES':len(verifier_raw),'POLICY_SHA':sha(actual),'ADOPTION_SHA':sha(adoption_raw),
        'ROOT_SCOPE_SHA':f['scope_decision']['sha256']}
    for name,value in current_slots.items():coordinator=fill(coordinator,name,None,value)
    bridge=fill(root_candidate['source/phone_chain_bridge.py'],'PKG',None,new_pkg)
    root_files={'source/run_component_root_once.py':coordinator,
        'source/phone_chain_bridge.py':bridge,'reference/policy_native5_verifier.py':verifier_raw}
    for name,body in root_files.items():compile(body,name,'exec')
    root_mf=copy.deepcopy(root_manifest)
    root_mf.update(state='HOST_REVIEWED_PROPERTY_POLICY_SOURCES_FROZEN_NOT_PHONE_QUALIFIED',
        parent_source_package_sha256=PARENT_ROOT,frozen_component_package_sha256=new_pkg,
        current_combination_sha256=sha(combo_raw),explicit_policy_adoption_sha256=sha(adoption_raw),
        property_parent_ancestors=records[:2],runtime_package_rebuilt=True,
        full_historical_tail_is_exact_actual08_then07_then06_then04_then_external03=True,
        full_historical_tail_is_exact_actual06_then_actual04_then_external03=False,
        retained_environment_suffix_is_exact_actual06_then04_then_external03=True,
        files=[{'path':name,'bytes':len(body),'sha256':sha(body)} for name,body in sorted(root_files.items())])
    root_mf_raw=enc(root_mf)
    increments=candidate['validation/INCREMENT.patch']+root_candidate['validation/INCREMENT.patch']
    for name,old,new in [('runtime/source/late_boundary.py',candidate['source/late_boundary.py'],late_source),
        ('root-chain/source/run_component_root_once.py',root_candidate['source/run_component_root_once.py'],coordinator),
        ('root-chain/source/phone_chain_bridge.py',root_candidate['source/phone_chain_bridge.py'],bridge)]:
        increments+=''.join(difflib.unified_diff(old.decode().splitlines(True),new.decode().splitlines(True),
            fromfile='reviewed-template/'+name,tofile='frozen-r8/'+name)).encode()
    derivation={'schema':'hepta.native-guard.property-r8-derivation.v1',
        'parent_runtime':plan['parent_runtime_manifest'],'parent_root_sources':plan['parent_root_manifest'],
        'reader_candidate':plan['reader_candidate_manifest'],'root_candidate':plan['root_candidate_manifest'],
        'finalization':f,'exact_property_parent_ancestors':records[:2],
        'full_historical_tail':records,'historical_native_call_counts':[1,0,1,1,0],
        'historical_qualified_cases':0,'non_native_sidebranch':side['binding'],
        'actual_distinct_retained_component_roles':[list(row) for row in roles],
        'component_role_cap':24,'future_role_slots':24-len(roles),
        'native_chain_cap':8,'runtime_paths':sorted(runtime),'runtime_count':32,
        'changed_runtime_paths':['source/late_boundary.py'],'new_runtime_paths':[NEW_REFERENCE],
        'unchanged_parent_runtime_files':30,'root_source_paths':sorted(root_files),
        'shared17_bytes_unchanged':True,'eight_artifact_descriptors_unchanged':combo['artifacts']==parent_combo['artifacts'],
        'combination_only_live_policy_field_changed':True,'bundle_limit_unchanged':33554432,
        'future_actual_bundle_union_not_evaluated':True,'new_qualified_cases':0,
        'phone_calls':0,'native_submissions':0,'new_nonces':0,'active_policy_writes':0}
    outputs={'runtime/'+name:body for name,body in runtime.items()}
    outputs.update({'root-chain/'+name:body for name,body in root_files.items()})
    outputs.update({'runtime/MANIFEST.json':mf_raw,'root-chain/SOURCE-MANIFEST.json':root_mf_raw,
        'COMBINATION.json':combo_raw,'PROPERTY-PARENT-ANCESTORS.original.json':enc(records[:2]),
        'FULL-HISTORICAL-ANCESTOR-PINS.json':enc(records),
        'ACTUAL08-PREVIOUS.original.json':o.fixed('history08_previous'),
        'PARENT-FREEZE-RESULT.original.json':o.fixed('parent_freeze_result'),
        'PARENT-Q2-SOURCE-MANIFEST.original.json':o.fixed('parent_root_manifest'),
        'PARENT-POLICY-ADOPTION.original.json':o.fixed('parent_adoption'),
        'POLICY-ADOPTION.original.json':adoption_raw,'ROOT-SCOPE-DECISION.original.json':o.read(f['scope_decision']),
        'FREEZE-INPUTS.original.json':raw,'DERIVATION.json':enc(derivation),'SOURCE-INCREMENT.patch':increments})
    for name in ('NON-NATIVE-REVIEWED-RECORD.original.json','HISTORICAL-ANCESTOR-PINS.json'):
        need(name in parent_result['files'],'actual R7 retained original descriptor is absent')
        outputs[name]=o.read(parent_result['files'][name])
    o.recheck()
    return o,outputs,derivation


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs',required=True,type=Path)
    parser.add_argument('--inputs-sha256',required=True)
    parser.add_argument('--execute-host-freeze',action='store_true')
    args=parser.parse_args()
    finalization=require_finalization()
    original=Originals()
    raw=original.read({'path':str(args.inputs),'bytes':args.inputs.stat().st_size,
                       'sha256':args.inputs_sha256})
    source_path=Path(__file__).resolve(strict=True)
    source_raw=source_path.read_bytes()
    source_row=desc(source_path,source_raw);original.read(source_row)
    observed,outputs,derivation=build(strict(raw),raw)
    outputs['FREEZE-SOURCE.original.py']=source_raw
    summary={'schema':'hepta.native-guard.property-r8-freeze-result.v1',
        'state':'HOST_PREVIEW_NO_RUNTIME_CREATED' if not args.execute_host_freeze
          else 'REVIEWED_PROPERTY_POLICY_R8_HOST_SOURCES_FROZEN_NOT_PHONE_QUALIFIED',
        'source':source_row,'inputs':desc(args.inputs,raw),
        'runtime_manifest':desc(OUT/'runtime/MANIFEST.json',outputs['runtime/MANIFEST.json']),
        'root_chain_manifest':desc(OUT/'root-chain/SOURCE-MANIFEST.json',outputs['root-chain/SOURCE-MANIFEST.json']),
        'combination':desc(OUT/'COMBINATION.json',outputs['COMBINATION.json']),
        'derivation':desc(OUT/'DERIVATION.json',outputs['DERIVATION.json']),
        'source_increment':desc(OUT/'SOURCE-INCREMENT.patch',outputs['SOURCE-INCREMENT.patch']),
        'historical_ancestor_pins':desc(OUT/'FULL-HISTORICAL-ANCESTOR-PINS.json',outputs['FULL-HISTORICAL-ANCESTOR-PINS.json']),
        'non_native_reviewed_record':desc(OUT/'NON-NATIVE-REVIEWED-RECORD.original.json',outputs['NON-NATIVE-REVIEWED-RECORD.original.json']),
        'policy_adoption':finalization['policy_adoption'],'verifier':finalization['verifier_source'],
        'actual_adopted_policy_sha256':finalization['actual_export']['sha256'],
        'runtime_path_count':32,'root_source_path_count':3,'unchanged_parent_runtime_files':30,
        'shared17_bytes_unchanged':True,'historical_case_credit':False,'non_native_case_count':0,
        'component_qualified':False,'four_role_qualified':False,'native_scope_created':False,
        'phone_operations':0,'active_policy_writes':0,'native_submissions':0,'new_nonces_generated':0,
        'automatic_retry':False,'all_inputs_rechecked':True,'all_output_files_read_back':False}
    if not args.execute_host_freeze:
        observed.recheck();original.recheck()
        print(enc(summary).decode(),end='');return 0
    os.umask(0o077);newdir(OUT)
    for name,body in sorted(outputs.items()):
        target=OUT/name;current=OUT
        for part in target.parent.relative_to(OUT).parts:
            current=current/part
            if not current.exists():newdir(current)
            need(current.resolve(strict=True)==current and stat.S_ISDIR(current.lstat().st_mode)
                 and stat.S_IMODE(current.lstat().st_mode)==0o700,
                 'private create-only output directory required')
        put(target,body)
    observed.recheck();original.recheck()
    readback=Originals()
    for name,body in outputs.items():readback.read(desc(OUT/name,body))
    summary['all_output_files_read_back']=True
    summary['files']={name:desc(OUT/name,body) for name,body in sorted(outputs.items())}
    put(OUT/'FREEZE-RESULT.json',enc(summary))
    print(enc({'state':summary['state'],'result':desc(OUT/'FREEZE-RESULT.json',enc(summary)),
       'runtime_manifest':summary['runtime_manifest'],'root_chain_manifest':summary['root_chain_manifest'],
       'combination':summary['combination'],'phone_operations':0}).decode(),end='')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
