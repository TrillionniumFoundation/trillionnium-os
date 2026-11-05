#!/usr/bin/env python3
"""Prepare one explicitly identified R8 NEG01/NEG02 Root plan on the host.

This helper never generates an identity, fixes a lease, instantiates Chain,
starts a process, or contacts the phone.  The caller supplies a pinned input
file only after choosing an authorized one-use identity and exact request.
The default performs the complete pure validation without creating files.
--execute-host-plan creates a new host plan directory after validation.
"""
import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types

B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
R8 = B/'native-guard-r10-r1-operator-r8'
CHAINS = B/'native-guard-root-chains-r10-r1'
OLD08 = CHAINS/'root-r10-neg01-20261105-08'
OLD08_NONCE = '2b0b103ee6de7a422064b9571266bf5d'
BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
ROOT_TEMPLATE_SHA = '50a500e0c1cc014d3d4043f8c86172bf0b6068719473eb5646aca818416ed649'
BRIDGE_TEMPLATE_SHA = '6694b106ee8ccf2177bf758367fda214f27b7ebfbea1611e11e67604a2bfd572'
FREEZER_TEMPLATE_SHA = '78dad9b3a122ee7c52e673aa08a28041f809aa9428b73b8d1ea88b09f0f6839d'
ROOT_CANDIDATE_MANIFEST = {
    'path':str(B/'native-guard-property-root-r8-transport-candidate03-1ad3/SOURCE-MANIFEST.json'),
    'bytes':4450,'sha256':'077c86ee40a5e239ed7c46200d414624d4e8b76d8e936c101b1cabdaefac3aa8',
}
FIRST_PRIOR = {
    'history08_previous':{'path':str(OLD08/'ACTUAL-PREVIOUS-INPUT.json'),'bytes':1428,
        'sha256':'9133e2511a66a809be647cb8bb49e3afb351825db5e465f75b1f2f0b6d9d88f4'},
    'history08_boundary':{'path':str(OLD08/'LATE-BOUNDARY.original.json'),'bytes':9373,
        'sha256':'eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10'},
    'history08_descriptor':{'path':str(OLD08/'LATE-BOUNDARY-DESCRIPTOR.json'),'bytes':367,
        'sha256':'724d7d54679299433498654530ad3dc082c107aa76fde9de54b0ed6c0ad3de08'},
}
PLAN_KEYS = {'schema','label','case_id','nonce','boot_id','session_id','profile_id','request','previous',
    'preserved_draft','sender_retirement_resolution','package','shared_materials','shared_root','artifacts',
    'policy_adoption','live_policy_sha256','retirement_descriptor','retirement_originals',
    'prior_boundary_descriptor','prior_boundary_original','source_package','out'}
STABLE_PLAN_KEYS = {'preserved_draft','sender_retirement_resolution','shared_materials','shared_root',
    'artifacts','retirement_descriptor','retirement_originals'}
META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
MAX_ORIGINAL = 64*1024*1024


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()


def strict(raw):
    def pairs(rows):
        result = {}
        for key,value in rows:
            need(key not in result,'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def descriptor(path, raw):
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}


class Originals:
    def __init__(self):
        self.seen = {}

    def read(self, row):
        need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact original descriptor required')
        need(type(row['bytes']) is int and 0<=row['bytes']<=MAX_ORIGINAL
            and isinstance(row['sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['sha256']),
            'bounded original descriptor required')
        path = Path(row['path'])
        need(path.is_absolute() and '..' not in path.parts and path.resolve(strict=True)==path,
            'canonical original path required')
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==row['bytes'],
                'single-link regular original differs')
            with os.fdopen(fd,'rb',closefd=False) as stream:
                raw = stream.read(row['bytes']+1)
            metadata = [getattr(before,key) for key in META]
            need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'original byte pin differs: '+str(path))
            need(metadata==[getattr(os.fstat(fd),key) for key in META]
                ==[getattr(path.lstat(),key) for key in META],'original changed while reading')
        finally:
            os.close(fd)
        record = {'descriptor':copy.deepcopy(row),'metadata':metadata}
        need(str(path) not in self.seen or self.seen[str(path)]==record,'original changed across reads')
        self.seen[str(path)] = record
        return raw

    def discovered(self, path, maximum=262144):
        need(path.is_absolute() and '..' not in path.parts and path.resolve(strict=True)==path,
            'canonical discovered original required')
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=maximum,
                'bounded regular discovered original required')
            with os.fdopen(fd,'rb',closefd=False) as stream:
                raw = stream.read(before.st_size+1)
            metadata = [getattr(before,key) for key in META]
            need(len(raw)==before.st_size and metadata==[getattr(os.fstat(fd),key) for key in META]
                ==[getattr(path.lstat(),key) for key in META],'discovered original changed while reading')
        finally:
            os.close(fd)
        row = descriptor(path,raw)
        record = {'descriptor':copy.deepcopy(row),'metadata':metadata}
        need(str(path) not in self.seen or self.seen[str(path)]==record,'discovered original changed across reads')
        self.seen[str(path)] = record
        return row,raw

    def recheck(self):
        for record in list(self.seen.values()):
            self.read(record['descriptor'])


def relative(name):
    path = Path(name)
    need(isinstance(name,str) and str(path)==name and not path.is_absolute()
        and '..' not in path.parts and name not in ('','.'),'canonical relative member required')
    return path


def literal(raw, name):
    tree = ast.parse(raw)
    nodes = [node for node in tree.body if isinstance(node,ast.Assign) and len(node.targets)==1
        and isinstance(node.targets[0],ast.Name) and node.targets[0].id==name]
    need(len(nodes)==1 and nodes[0].lineno==nodes[0].end_lineno,'one single-line literal required: '+name)
    node = nodes[0]
    return ast.literal_eval(node.value),node


def set_literal(raw, name, old, value):
    observed,node = literal(raw,name)
    need(observed==old,'reviewed literal differs: '+name)
    lines = raw.decode().splitlines(keepends=True)
    whole = lines[node.lineno-1]
    prefix = whole.split('#',1)[0].rstrip()
    lines[node.lineno-1] = name+'='+repr(value)+whole[len(prefix):]
    return ''.join(lines).encode()


def member_map(originals, manifest_row, expected):
    manifest = strict(originals.read(manifest_row))
    rows = manifest['files']
    need(type(rows) is list and len(rows)==len(expected)
        and {row['path'] for row in rows}==set(expected),'exact manifest membership required')
    root = Path(manifest_row['path']).parent
    descriptors,blobs = {},{}
    for row in rows:
        need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact manifest member required')
        rel = relative(row['path'])
        desc = {'path':str(root/rel),'bytes':row['bytes'],'sha256':row['sha256']}
        descriptors[row['path']] = desc
        blobs[row['path']] = originals.read(desc)
    return manifest,descriptors,blobs


def validate_freeze(originals, freeze_row):
    freeze = strict(originals.read(freeze_row))
    need(Path(freeze_row['path'])==R8/'FREEZE-RESULT.json'
        and freeze['schema']=='hepta.native-guard.property-r8-freeze-result.v1'
        and freeze['state']=='REVIEWED_PROPERTY_POLICY_R8_HOST_SOURCES_FROZEN_NOT_PHONE_QUALIFIED'
        and freeze['all_inputs_rechecked'] is True and freeze['all_output_files_read_back'] is True
        and freeze['runtime_path_count']==32 and freeze['root_source_path_count']==3
        and freeze['phone_operations']==freeze['active_policy_writes']==freeze['native_submissions']
            ==freeze['new_nonces_generated']==0 and freeze['component_qualified'] is False,
        'actual completed R8 host freeze required')
    inputs = strict(originals.read(freeze['inputs']))
    need(inputs['schema']=='hepta.native-guard.property-r8-freeze-inputs.v1'
        and inputs['out']==str(R8) and inputs['root_candidate_manifest']==ROOT_CANDIDATE_MANIFEST,
        'reviewed transport R8 freeze inputs differ')
    for key,row in FIRST_PRIOR.items():
        need(inputs[key]==row,'exact actual08 generation entry differs: '+key)
    finalization = inputs['finalization']
    need(type(finalization) is dict,'actual policy finalization is absent')
    freezer = originals.read(freeze['source'])
    need(literal(freezer,'FINALIZATION')[0]==finalization
        and sha(set_literal(freezer,'FINALIZATION',finalization,None))==FREEZER_TEMPLATE_SHA,
        'actual freezer differs beyond the reviewed finalization literal')
    files = freeze['files']
    need(type(files) is dict and 35<=len(files)<=128,'complete bounded freeze output inventory required')
    for name,row in files.items():
        need(Path(row['path'])==R8/relative(name),'freeze output location differs')
        originals.read(row)
    for key,name in (('runtime_manifest','runtime/MANIFEST.json'),
        ('root_chain_manifest','root-chain/SOURCE-MANIFEST.json'),('combination','COMBINATION.json'),
        ('derivation','DERIVATION.json'),('source_increment','SOURCE-INCREMENT.patch'),
        ('historical_ancestor_pins','FULL-HISTORICAL-ANCESTOR-PINS.json')):
        need(freeze[key]==files[name],'freeze output crosslink differs: '+key)
    combo = strict(originals.read(freeze['combination']))
    adoption = strict(originals.read(freeze['policy_adoption']))
    need(freeze['policy_adoption']==finalization['policy_adoption']
        and freeze['verifier']==finalization['verifier_source']
        and freeze['actual_adopted_policy_sha256']==finalization['actual_export']['sha256']
        and combo['live_policy_sha256']==freeze['actual_adopted_policy_sha256']
        and freeze['combination']['sha256']==finalization['combination_sha256']
        and adoption['actual_export']==finalization['actual_export'],
        'actual R8 policy/adoption/combination crosslinks differ')
    source_names = {'source/run_component_root_once.py','source/phone_chain_bridge.py',
        'reference/policy_native5_verifier.py'}
    root_manifest,root_rows,root_raw = member_map(originals,freeze['root_chain_manifest'],source_names)
    runtime = strict(originals.read(freeze['runtime_manifest']))
    need(Path(freeze['runtime_manifest']['path'])==R8/'runtime/MANIFEST.json'
        and Path(freeze['root_chain_manifest']['path'])==R8/'root-chain/SOURCE-MANIFEST.json'
        and root_manifest['schema']=='hepta.native-guard.root-chain-source-package.v1'
        and root_manifest['frozen_component_package_sha256']==freeze['runtime_manifest']['sha256']
        and root_manifest['current_combination_sha256']==freeze['combination']['sha256']
        and root_manifest['explicit_policy_adoption_sha256']==freeze['policy_adoption']['sha256']
        and runtime['schema']=='hepta.native-guard.adapter-package.v1'
        and runtime['current_combination_sha256']==freeze['combination']['sha256']
        and runtime['current_policy_sha256']==freeze['actual_adopted_policy_sha256']
        and runtime['explicit_policy_adoption_sha256']==freeze['policy_adoption']['sha256']
        and len(runtime['files'])==32,'frozen root/runtime generation differs')
    slots = {'PKG':freeze['runtime_manifest']['sha256'],'COMBINATION':freeze['combination']['sha256'],
        'VERIFIER_SHA':freeze['verifier']['sha256'],'VERIFIER_BYTES':freeze['verifier']['bytes'],
        'POLICY_SHA':freeze['actual_adopted_policy_sha256'],'ADOPTION_SHA':freeze['policy_adoption']['sha256'],
        'ROOT_SCOPE_SHA':finalization['scope_decision']['sha256']}
    coordinator = root_raw['source/run_component_root_once.py']
    restored = coordinator
    for name,value in slots.items():
        restored = set_literal(restored,name,value,None)
    need(sha(restored)==ROOT_TEMPLATE_SHA,'frozen coordinator is not the exact reviewed capture R8 plus seven pins')
    need(sha(set_literal(root_raw['source/phone_chain_bridge.py'],'PKG',slots['PKG'],None))==BRIDGE_TEMPLATE_SHA,
        'frozen phone bridge differs beyond its package pin')
    need(root_raw['reference/policy_native5_verifier.py']==originals.read(freeze['verifier']),
        'Root adoption verifier is not the actual frozen verifier original')
    for row in runtime['files']:
        name = 'runtime/'+str(relative(row['path']))
        need(name in files and files[name]=={'path':str(R8/name),'bytes':row['bytes'],'sha256':row['sha256']},
            'runtime member differs from actual freezer inventory')
    mod = types.ModuleType('reviewed_r8_prepare_only_coordinator')
    mod.__file__ = root_rows['source/run_component_root_once.py']['path']
    mod.__reviewed_source_sha256__ = root_rows['source/run_component_root_once.py']['sha256']
    exec(compile(coordinator,mod.__file__,'exec'),mod.__dict__)
    return freeze,inputs,mod


def choose_prior(originals, inputs, freeze, case_id, result_row):
    if case_id=='NEG-01':
        need(result_row is None,'first NEG01 must enter through the exact frozen actual08 predecessor')
        return {'previous':inputs['history08_previous'],
            'prior_boundary_original':inputs['history08_boundary'],
            'prior_boundary_descriptor':inputs['history08_descriptor']}
    need(case_id=='NEG-02' and type(result_row) is dict,'NEG02 requires its actual qualified current NEG01 Root result')
    result = strict(originals.read(result_row))
    home = Path(result_row['path']).parent
    need(home.parent==CHAINS and Path(result_row['path'])==home/'ROOT-RESULT.json'
        and result['state']=='ORIGINAL_COMPONENT_CLOSED_AND_LATE_BOUNDARY_PUBLISHED'
        and result['component_qualified'] is True and result['native_status']=='completed'
        and result['automatic_retry'] is False,'qualified current NEG01 Root result required')
    predecessor_plan_row,predecessor_plan_raw = originals.discovered(home/'ROOT-PLAN.original.json')
    predecessor = strict(predecessor_plan_raw)
    need(set(predecessor)==PLAN_KEYS and predecessor['case_id']=='NEG-01'
        and predecessor['out']==str(home) and predecessor['label']==home.name
        and predecessor['package']==freeze['runtime_manifest']
        and predecessor['source_package']==freeze['root_chain_manifest']
        and predecessor['policy_adoption']==freeze['policy_adoption']
        and predecessor['live_policy_sha256']==freeze['actual_adopted_policy_sha256'],
        'NEG02 predecessor belongs to another runtime/policy generation or case')
    previous_row = result['previous']
    need(Path(previous_row['path'])==home/'ACTUAL-PREVIOUS-INPUT.json','standard current predecessor original required')
    previous = strict(originals.read(previous_row))
    need(previous['identity']==result['scope'] and previous['component_qualified'] is True
        and previous['terminal']['status']=='completed' and previous['late_boundary']==result['late_boundary'],
        'qualified NEG01 result and actual previous differ')
    boundary_desc_row,boundary_desc_raw = originals.discovered(home/'LATE-BOUNDARY-DESCRIPTOR.json')
    need(strict(boundary_desc_raw)==result['late_boundary'],'current predecessor published boundary descriptor differs')
    boundary_row = {'path':str(home/'LATE-BOUNDARY.original.json'),
        'bytes':result['late_boundary']['bytes'],'sha256':result['late_boundary']['sha256']}
    boundary = strict(originals.read(boundary_row))
    need(boundary['case_id']=='NEG-01' and boundary['component_qualified'] is True
        and boundary['native_status']=='completed' and boundary['nonce']==predecessor['nonce'],
        'qualified current predecessor boundary required')
    return {'previous':previous_row,'prior_boundary_original':boundary_row,
        'prior_boundary_descriptor':boundary_desc_row}


def assemble(originals, inputs, freeze, base_row, case_id, label, nonce, request_row, prior):
    base = strict(originals.read(base_row))
    need(Path(base_row['path'])==OLD08/'ROOT-PLAN.original.json' and set(base)==PLAN_KEYS
        and base['schema']=='hepta.native-guard.root-chain-plan.v1' and base['case_id']=='NEG-01'
        and base['nonce']==OLD08_NONCE and base['out']==str(OLD08) and base['boot_id']==BOOT,
        'exact reviewed actual08 Root plan is the retained stable-material template')
    need(case_id in ('NEG-01','NEG-02') and isinstance(label,str)
        and re.fullmatch('[a-z0-9][a-z0-9-]{5,35}',label)
        and isinstance(nonce,str) and re.fullmatch('[0-9a-f]{32}',nonce),'explicit one-use Root identity required')
    request = originals.read(request_row)
    need(20<=len(request)<=16000 and b'\0' not in request and request.decode('utf8',errors='strict').count(nonce)==1,
        'exact UTF8 owner request must contain the supplied nonce exactly once')
    previous = strict(originals.read(prior['previous']))
    boundary = strict(originals.read(prior['prior_boundary_original']))
    prior_nonces = {OLD08_NONCE,boundary['nonce']}
    for key,row in inputs.items():
        if re.fullmatch(r'history[0-9]+_boundary',key):
            prior_nonces.add(strict(originals.read(row))['nonce'])
    need(nonce not in prior_nonces and all(value.encode() not in request for value in prior_nonces),
        'new request may not reuse or retain a historical native nonce')
    need(request!=originals.read(base['request']),'old actual08 request must not be replayed')
    plan = {key:copy.deepcopy(base[key]) for key in STABLE_PLAN_KEYS}
    plan.update(schema='hepta.native-guard.root-chain-plan.v1',label=label,case_id=case_id,nonce=nonce,
        boot_id=BOOT,session_id=previous['identity']['session_id'],profile_id=previous['identity']['profile_id'],
        request=copy.deepcopy(request_row),package=copy.deepcopy(freeze['runtime_manifest']),
        source_package=copy.deepcopy(freeze['root_chain_manifest']),policy_adoption=copy.deepcopy(freeze['policy_adoption']),
        live_policy_sha256=freeze['actual_adopted_policy_sha256'],out=str(CHAINS/label),**copy.deepcopy(prior))
    need(set(plan)==PLAN_KEYS and plan['shared_materials']==inputs['shared_materials'],
        'assembled exact Root schema or shared material pin differs')
    for key in STABLE_PLAN_KEYS-{'shared_root','retirement_originals'}:
        originals.read(plan[key])
    return plan


def require_unused(plan, host_out):
    execution_out = Path(plan['out'])
    need(not execution_out.exists() and not execution_out.is_symlink(),
        'Root execution namespace already exists; reconcile the original attempt without replacement identity')
    for suffix in ('.preview.actor.py','.actor.py','.local-once.json','.send-result.json'):
        path = B/(plan['label']+suffix)
        need(not path.exists() and not path.is_symlink(),'sender identity already has a retained local attempt')
    need(host_out.is_absolute() and '..' not in host_out.parts and B in host_out.parents
        and host_out.parent.resolve(strict=True)==host_out.parent
        and R8 not in host_out.parents and CHAINS not in host_out.parents
        and host_out not in (execution_out,Path(plan['package']['path']).parent)
        and execution_out not in host_out.parents and host_out not in execution_out.parents
        and not host_out.exists() and not host_out.is_symlink(),'new separate host plan output directory required')


def syncdir(path):
    fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def put(path, raw):
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    syncdir(path.parent)
    row = descriptor(path,raw)
    need(Originals().read(row)==raw,'host output readback differs')
    return row


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs-desc',required=True,help='JSON descriptor for the explicitly pinned preparation inputs')
    parser.add_argument('--execute-host-plan',action='store_true')
    args = parser.parse_args(argv)
    originals = Originals()
    input_row = strict(args.inputs_desc)
    input_raw = originals.read(input_row)
    value = strict(input_raw)
    need(type(value) is dict and set(value)=={'schema','freeze_result','base_plan','case_id','label','nonce',
        'request','qualified_neg01_result','host_out'}
        and value['schema']=='hepta.native-guard.r8-root-plan-preparation-inputs.v1',
        'exact explicit preparation inputs required')
    freeze,freeze_inputs,coordinator = validate_freeze(originals,value['freeze_result'])
    prior = choose_prior(originals,freeze_inputs,freeze,value['case_id'],value['qualified_neg01_result'])
    plan = assemble(originals,freeze_inputs,freeze,value['base_plan'],value['case_id'],value['label'],
        value['nonce'],value['request'],prior)
    out = Path(value['host_out'])
    require_unused(plan,out)
    raw = encoded(plan)
    validated,manifest = coordinator.validate_plan(raw)
    need(validated==plan and manifest['current_combination_sha256']==freeze['combination']['sha256'],
        'actual frozen coordinator pure validation returned a different plan or combination')
    source_row,source_raw = originals.discovered(Path(__file__).resolve(strict=True),262144)
    originals.recheck()
    require_unused(plan,out)
    result = {'schema':'hepta.native-guard.r8-root-plan-preparation-result.v1',
        'state':'HOST_PREVIEW_PURE_ROOT_VALIDATION_PASSED_NO_FILES',
        'helper':source_row,'inputs':input_row,'freeze_result':value['freeze_result'],
        'coordinator':descriptor(Path(coordinator.__file__),originals.read(
            freeze['files']['root-chain/source/run_component_root_once.py'])),
        'runtime_manifest':freeze['runtime_manifest'],'root_chain_manifest':freeze['root_chain_manifest'],
        'combination':freeze['combination'],'policy_adoption':freeze['policy_adoption'],
        'case_id':plan['case_id'],'label':plan['label'],'nonce':plan['nonce'],
        'plan_sha256':sha(raw),'planned_execution_out':plan['out'],'host_out':str(out),
        'pure_validate_plan_passed':True,'actual_phone_state_read':False,'remote_nonce_absence_proven':False,
        'phone_calls':0,'process_starts':0,'native_submissions':0,'new_nonces_generated':0,
        'lease_fixed':False,'automatic_retry':False,'component_qualified':False,'business_qualified':False}
    if args.execute_host_plan:
        os.umask(0o077)
        out.mkdir(mode=0o700)
        syncdir(out);syncdir(out.parent)
        put(out/'PREPARATION-INPUTS.original.json',input_raw)
        put(out/'PREPARATION-SOURCE.original.py',source_raw)
        result['plan'] = put(out/'ROOT-PLAN.json',raw)
        originals.recheck()
        result['all_selected_originals_rechecked'] = True
        result['state'] = 'HOST_PLAN_CREATED_AND_PURE_ROOT_VALIDATION_PASSED_NOT_EXECUTED'
        result_row = put(out/'PREPARATION-RESULT.json',encoded(result))
        print(encoded({'state':result['state'],'result':result_row,'plan':result['plan'],
            'phone_calls':0,'native_submissions':0,'new_nonces_generated':0}).decode(),end='')
    else:
        print(encoded(result).decode(),end='')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
