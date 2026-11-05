#!/usr/bin/env python3
"""Bind the reviewed R8 freezer to a completed actual policy adoption.

The original freezer build() performs the complete read-only preflight. Only a
new host source/input package is written. The fixed R8 output, policy, phone,
runtime, task identities and historical originals are never written here.
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

B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
FREEZER = {'path':str(B/'native-guard-property-r8-freeze-preparation-final02-1ad3/source/freeze_property_runtime.py'),
    'bytes':35543,'sha256':'78dad9b3a122ee7c52e673aa08a28041f809aa9428b73b8d1ea88b09f0f6839d'}
TEMPLATE = {'path':str(B/'native-guard-property-r8-freeze-transport-candidate02-1ad3/FREEZE-INPUTS.template.json'),
    'bytes':8368,'sha256':'debd3165e14bf357f13bfa3b997ea3bb0b23e5d2bb4a0a8b54078477deff2934'}
VERIFIER = {'path':str(B/'policy-runtime-properties-r10-independent-host-verifier-r1-candidate01/source/policy_runtime_properties_verifier.py'),
    'bytes':126796,'sha256':'74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152'}
APPLIED = {'bytes':124306,'sha256':'5cd18af19e1cd4cbe98542996fa41960bc36f697c6687ce201312b8ceda91c00'}
META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
MAX_ORIGINAL = 64*1024*1024


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()


def strict(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'duplicate JSON member')
            value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def exact3(row, maximum=MAX_ORIGINAL):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact original descriptor required')
    need(type(row['path']) is str and '\0' not in row['path']
        and Path(row['path']).is_absolute() and str(Path(row['path']))==row['path']
        and '..' not in Path(row['path']).parts,'canonical absolute original path required')
    need(type(row['bytes']) is int and 0<=row['bytes']<=maximum
        and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
        'bounded exact original byte identity required')
    return dict(row)


def descriptor(path, raw):
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}


def metadata(value):
    return [getattr(value,key) for key in META]


class Originals:
    def __init__(self):
        self.rows={}
        self.raw={}
        self.total=0

    def read(self,row):
        row=exact3(row);path=Path(row['path'])
        need(path.resolve(strict=True)==path,'original path is not canonical')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==row['bytes'],
                'regular single-link exact-size original required')
            with os.fdopen(fd,'rb',closefd=False) as stream:
                raw=stream.read(row['bytes']+1)
            need(metadata(before)==metadata(os.fstat(fd))==metadata(path.lstat())
                and len(raw)==row['bytes'] and sha(raw)==row['sha256'],'original bytes or identity changed')
        finally:
            os.close(fd)
        record={'descriptor':row,'metadata':metadata(before)}
        if row['path'] in self.rows:
            need(self.rows[row['path']]==record and self.raw[row['path']]==raw,'original changed between reads')
        else:
            need(len(self.rows)<512 and self.total+len(raw)<=MAX_ORIGINAL,'bounded preparation input set')
            self.rows[row['path']]=record;self.raw[row['path']]=raw;self.total+=len(raw)
        return raw

    def known_source(self,path):
        need(path.is_absolute() and path.resolve(strict=True)==path,'canonical preparation source required')
        before=path.lstat()
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=65536,
            'bounded preparation source required')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            need(metadata(before)==metadata(os.fstat(fd)),'preparation source changed before read')
            with os.fdopen(fd,'rb',closefd=False) as stream:
                raw=stream.read(before.st_size+1)
            need(len(raw)==before.st_size and metadata(before)==metadata(os.fstat(fd))==metadata(path.lstat()),
                'preparation source changed during read')
        finally:
            os.close(fd)
        row=descriptor(path,raw);need(self.read(row)==raw,'preparation source changed')
        return row

    def recheck(self):
        for row in list(self.rows.values()):
            self.read(row['descriptor'])


def module(raw,path,name):
    value=types.ModuleType(name);value.__file__=str(path)
    value.__reviewed_source_sha256__=sha(raw)
    exec(compile(raw,str(path),'exec',optimize=0),value.__dict__)
    return value


def freezer_source(raw):
    need(len(raw)==FREEZER['bytes'] and sha(raw)==FREEZER['sha256'],'exact reviewed compact source required')
    value=module(raw,FREEZER['path'],'reviewed_unfrozen_r8_freezer')
    need(value.FINALIZATION is None and value.OUT==B/'native-guard-r10-r1-operator-r8',
        'original unbound finalization and fixed R8 output required')
    return value


def derive_inputs(F,template_raw,adoption_row,adoption,actual_raw,parent_raw):
    """Extract bindings only. Original finalized F.build must verify them next."""
    template=strict(template_raw)
    need(F.enc(template)==template_raw and type(template) is dict
        and set(template)==set(F.FIXED)|{'schema','finalization','out'}
        and template['schema']=='hepta.native-guard.property-r8-freeze-inputs.v1'
        and template['finalization'] is None and template['out']==str(F.OUT),
        'exact original canonical freeze-input template required')
    for key,(path,size,digest) in F.FIXED.items():
        need(template[key]=={'path':str(path),'bytes':size,'sha256':digest},'fixed template input differs: '+key)
    need(type(adoption) is dict and adoption.get('schema')=='hepta.runtime-properties-r10.policy-adoption.v1',
        'completed actual adoption required; inputs or preview cannot be frozen')
    actual=exact3(adoption['actual_export'],16*1024*1024)
    scope=exact3(adoption['root_scope_decision'],16*1024*1024)
    need(actual==descriptor(actual['path'],actual_raw) and actual['sha256']!=F.PARENT_POLICY,
        'actual export must be independently supplied bytes of a new policy')
    decision=adoption.get('root_decision')
    need(type(decision) is dict and decision.get('schema')=='hepta.root.runtime-properties-policy-adoption-decision.v1'
        and decision.get('decision')=='ADOPT_INDEPENDENTLY_VERIFIED_ACTUAL_EXPORTED_POLICY'
        and decision.get('actual_policy_sha256')==actual['sha256'],
        'explicit actual Root adoption decision required before freeze preparation')
    pool=adoption.get('verification_originals')
    need(type(pool) is list,'actual adoption original inventory required')
    independent=[r for r in pool if type(r) is dict and
        {k:r.get(k) for k in ('bytes','sha256')}=={k:VERIFIER[k] for k in ('bytes','sha256')}]
    need(independent==[VERIFIER] and len([r for r in pool if type(r) is dict and
            {k:r.get(k) for k in ('bytes','sha256')}==APPLIED])==1,
        'one canonical independent74f4 and one actual applied5cd original required')
    parent=strict(parent_raw)
    need(F.combination_enc(parent)==parent_raw and sha(parent_raw)==F.PARENT_COMBINATION
        and parent['live_policy_sha256']==F.PARENT_POLICY,'exact canonical parent combination required')
    combination=copy.deepcopy(parent);combination['live_policy_sha256']=actual['sha256']
    combo_raw=F.combination_enc(combination)
    reverse=copy.deepcopy(combination);reverse['live_policy_sha256']=F.PARENT_POLICY
    need(F.combination_enc(reverse)==parent_raw,'only current live-policy field may change in combination')
    frozen={'schema':'hepta.native-guard.property-policy-finalization.v1',
        'scope_decision':scope,'policy_adoption':exact3(adoption_row,16*1024*1024),
        'verifier_source':dict(VERIFIER),'actual_export':actual,'combination_sha256':sha(combo_raw)}
    inputs=copy.deepcopy(template);inputs['finalization']=frozen
    reverse=copy.deepcopy(inputs);reverse['finalization']=None
    need(F.enc(reverse)==template_raw,'only original input finalization field may change')
    return frozen,F.enc(inputs),combo_raw


def bind_source(F,raw,frozen):
    need(len(raw)==FREEZER['bytes'] and sha(raw)==FREEZER['sha256'],'exact reviewed compact source required for one-RHS binding')
    result=F.fill(raw,'FINALIZATION',None,frozen)
    need(F.fill(result,'FINALIZATION',frozen,None)==raw,'whole-source inverse must be exact reviewed compact source')
    before,after=ast.parse(raw),ast.parse(result)
    def normalize(tree):
        nodes=[n for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1
            and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='FINALIZATION']
        need(len(nodes)==1,'one FINALIZATION assignment required')
        nodes[0].value=ast.Constant(value=None)
        return ast.dump(tree,include_attributes=False)
    need(normalize(before)==normalize(after),'source changed outside FINALIZATION RHS')
    return result


def fresh_output(out,runtime_out):
    need(out.is_absolute() and out.parent==B and out.parent.resolve(strict=True)==B
        and re.fullmatch('native-guard-property-r8-freeze-actual-[a-z0-9-]{3,64}',out.name)
        and not out.exists() and not out.is_symlink(),'explicit fresh host source output required')
    need(runtime_out==B/'native-guard-r10-r1-operator-r8'
        and not runtime_out.exists() and not runtime_out.is_symlink(),
        'fixed R8 output already exists; inspect originals without renaming or replay')


def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def put(path,raw):
    need(type(raw) is bytes and path.parent.resolve(strict=True)==path.parent,'exact new host output')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    sync(path.parent)
    row=descriptor(path,raw);need(Originals().read(row)==raw,'new host output exact readback')
    return row


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy-adoption-desc',required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--execute-host-preparation',action='store_true')
    args=parser.parse_args(argv)
    if not args.execute_host_preparation:
        print(encoded({'state':'PREVIEW_NO_ORIGINAL_READ_NO_RUNTIME_FREEZE',
            'freezer':FREEZER,'verifier':VERIFIER,'source_output':str(args.out),
            'phone_calls':0,'policy_writes':0,'native_nonces_created':0}).decode(),end='')
        return 0
    sys.dont_write_bytecode=True;os.umask(0o077)
    adoption_row=exact3(strict(args.policy_adoption_desc),16*1024*1024)
    o=Originals();self_source=o.known_source(Path(__file__).resolve(strict=True))
    original=o.read(FREEZER);F=freezer_source(original)
    fresh_output(args.out,F.OUT)
    template_raw=o.read(TEMPLATE);verifier_raw=o.read(VERIFIER)
    need(0<len(verifier_raw)<=131072,'unchanged verifier source budget')
    adoption_raw=o.read(adoption_row);adoption=strict(adoption_raw)
    need(type(adoption) is dict,'actual adoption must be an object')
    actual_raw=o.read(exact3(adoption['actual_export'],16*1024*1024))
    o.read(exact3(adoption['root_scope_decision'],16*1024*1024))
    path,size,digest=F.FIXED['parent_combination']
    parent_raw=o.read({'path':str(path),'bytes':size,'sha256':digest})
    frozen,input_raw,combo_raw=derive_inputs(F,template_raw,adoption_row,adoption,actual_raw,parent_raw)
    derived=bind_source(F,original,frozen)
    source_path=args.out/'source/freeze_property_runtime.py'
    final=module(derived,source_path,'reviewed_actual_r8_freezer')
    need(final.require_finalization()==frozen,'original freezer finalization gate rejected derived binding')
    # Original build is a pure preparation factory: it verifies74f4 adoption,
    # every fixed historical original, Root3/runtime32 and all source gates.
    # It neither calls main nor writes the fixed R8 output.
    observed,prospective,derivation=final.build(strict(input_raw),input_raw)
    need(derivation['runtime_count']==32 and len(derivation['root_source_paths'])==3
        and derivation['phone_calls']==derivation['native_submissions']==derivation['new_nonces']
            ==derivation['active_policy_writes']==0
        and prospective['COMBINATION.json']==combo_raw,
        'original R8 build must retain exact inventories and zero side effects')
    o.recheck();observed.recheck();fresh_output(args.out,final.OUT)
    source_row=descriptor(source_path,derived)
    inputs_row=descriptor(args.out/'FREEZE-INPUTS.json',input_raw)
    preview=['/usr/bin/python3','-I','-B',str(source_path),
        '--inputs',inputs_row['path'],'--inputs-sha256',inputs_row['sha256']]
    entry={'schema':'hepta.native-guard.property-r8-freeze-entry.v1',
        'source':source_row,'inputs':inputs_row,'preview_argv':preview,
        'execute_argv':preview+['--execute-host-freeze'],'fixed_runtime_out':str(final.OUT),
        'expected_result':str(final.OUT/'FREEZE-RESULT.json'),
        'expected_state':'REVIEWED_PROPERTY_POLICY_R8_HOST_SOURCES_FROZEN_NOT_PHONE_QUALIFIED',
        'phone_calls':0,'active_policy_writes':0,'native_submissions':0,'new_nonces':0,
        'automatic_execution':False,'automatic_retry':False}
    predicted={name:descriptor(final.OUT/name,prospective[name]) for name in
        ('runtime/MANIFEST.json','root-chain/SOURCE-MANIFEST.json','COMBINATION.json')}
    review={'schema':'hepta.native-guard.actual-r8-freeze-source-preparation.v1',
        'state':'ACTUAL_ADOPTION_AND_ORIGINAL_FREEZER_BUILD_VERIFIED_NO_RUNTIME_CREATED',
        'preparer_source':self_source,'parent_source':FREEZER,'parent_input_template':TEMPLATE,
        'verifier':VERIFIER,'policy_adoption':adoption_row,'actual_export':frozen['actual_export'],
        'finalization':frozen,'derived_source':source_row,'inputs':inputs_row,
        'whole_source_inverse_exact':True,'source_changed_rhs_only':'FINALIZATION',
        'input_changed_field_only':'finalization','combination_changed_field_only':'live_policy_sha256',
        'original_build_preflight_completed':True,'full_adoption_reverified_by_original_build':True,
        'predicted_generation':predicted,'runtime_path_count':32,'root_source_path_count':3,
        'verifier_source_budget_bytes':131072,'runtime_written':False,'freeze_main_calls':0,
        'phone_calls':0,'active_policy_writes':0,'native_submissions':0,'new_nonces':0,
        'component_qualified':False,'automatic_retry':False}
    read_set={'preparer_inputs':o.rows,'original_build_inputs':{
        path:{'descriptor':descriptor(path,body),'metadata':observed.observed[path]}
        for path,body in sorted(observed.raw.items())}}
    files={'source/freeze_property_runtime.py':derived,
        'reference/freeze_property_runtime.compact.original.py':original,
        'reference/FREEZE-INPUTS.template.original.json':template_raw,
        'FINALIZATION.json':encoded(frozen),'FREEZE-INPUTS.json':input_raw,
        'COMBINATION.preview.json':combo_raw,'ORIGINAL-BUILD-DERIVATION.preview.json':encoded(derivation),
        'DERIVATION.json':encoded(review),'ORIGINAL-READ-SET.json':encoded(read_set),
        'EXECUTION-ENTRY.json':encoded(entry),'SOURCE-INCREMENT.patch':''.join(difflib.unified_diff(
            original.decode().splitlines(keepends=True),derived.decode().splitlines(keepends=True),
            fromfile='reviewed-compact/freeze_property_runtime.py',tofile='actual/source/freeze_property_runtime.py')).encode()}
    args.out.mkdir(mode=0o700);sync(args.out.parent)
    for name in ('source','reference'):
        (args.out/name).mkdir(mode=0o700);sync(args.out)
    for name,body in sorted(files.items()):put(args.out/name,body)
    o.recheck();observed.recheck()
    manifest={'schema':'hepta.native-guard.property-r8-freeze-source-binding.v1',
        'state':'SOURCE_AND_INPUTS_FROZEN_ACTUAL_RUNTIME_NOT_CREATED',
        'files':[{'path':name,'bytes':len(body),'sha256':sha(body)} for name,body in sorted(files.items())],
        'source':source_row,'inputs':inputs_row,'verifier':VERIFIER,'policy_adoption':adoption_row,
        'whole_source_inverse_exact':True,'original_build_preflight_completed':True,
        'runtime_written':False,'phone_calls':0,'new_nonces':0}
    manifest_row=put(args.out/'SOURCE-MANIFEST.json',encoded(manifest))
    result={'schema':'hepta.native-guard.actual-r8-freeze-preparation-result.v1',
        'state':review['state'],'source_manifest':manifest_row,'source':source_row,'inputs':inputs_row,
        'entry':descriptor(args.out/'EXECUTION-ENTRY.json',files['EXECUTION-ENTRY.json']),
        'policy_adoption':adoption_row,'verifier':VERIFIER,'actual_export':frozen['actual_export'],
        'predicted_generation':predicted,'runtime_written':False,'phone_calls':0,
        'policy_writes':0,'native_nonces_created':0,'automatic_execution':False,'automatic_retry':False}
    result_row=put(args.out/'RESULT.json',encoded(result))
    print(encoded({'state':result['state'],'result':result_row,'entry':result['entry'],
        'execute_argv':entry['execute_argv'],'phone_calls':0,'runtime_written':False}).decode(),end='')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
