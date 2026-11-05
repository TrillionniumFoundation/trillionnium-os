#!/usr/bin/env python3
"""Build the actual expectation and Root plan from pinned host preparation.

This helper only reads host originals and creates a new host plan directory.
The default is read-only preview. --execute-host-plan creates the expectation
using the frozen reviewed helper, creates the plan, and runs only the driver's
pure load_transport()/validate() functions. It never calls Chain, phone(),
subprocess, driver.main(), or any policy-apply endpoint.
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import types

META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
SOURCE_NAMES = {
    'apply_runtime_properties_once.template.sh', 'capture_runtime_properties_originals.py',
    'guard_live_runtime_properties.py', 'make_runtime_properties_adoption.py',
    'make_runtime_properties_adoption_inputs.py', 'make_runtime_properties_expectation.py',
    'runtime_properties_host_originals.py', 'policy_runtime_properties_verifier.py',
    'prepare_live_runtime_properties.py',
}
OLD_VALIDATOR = {'bytes':43438,'sha256':'860aaf747e89411efa993783b950f709b1d8ac5d7b606575065bdff74ef98e22'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()


def strict(raw):
    def pairs(rows):
        value = {}
        for key,item in rows:
            need(key not in value,'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def bytepin(row):
    return {key:row[key] for key in ('bytes','sha256')}


def descriptor(path, raw):
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}


class Originals:
    def __init__(self):
        self.seen = {}

    def read(self,row):
        need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact descriptor required')
        need(type(row['bytes']) is int and 0<=row['bytes']<=32*1024*1024
             and isinstance(row['sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['sha256']),
             'bounded original descriptor required')
        p = Path(row['path'])
        need(p.is_absolute() and '..' not in p.parts and p.resolve(strict=True)==p,'canonical original path')
        fd = os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            a = os.fstat(fd)
            need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==row['bytes'],'regular single-link original')
            with os.fdopen(fd,'rb',closefd=False) as stream:
                raw = stream.read(row['bytes']+1)
            meta = [getattr(a,key) for key in META]
            need(meta==[getattr(os.fstat(fd),key) for key in META]
                 ==[getattr(p.lstat(),key) for key in META],'original changed while read')
            need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'original bytes differ: '+str(p))
        finally:
            os.close(fd)
        record = {'descriptor':row,'metadata':meta}
        need(str(p) not in self.seen or self.seen[str(p)]==record,'original changed across reads')
        self.seen[str(p)] = record
        return raw

    def recheck(self):
        for item in list(self.seen.values()):
            self.read(item['descriptor'])


def module_from_raw(name,row,raw):
    module = types.ModuleType(name)
    module.__file__ = row['path']
    module.__reviewed_source_sha256__ = row['sha256']
    exec(compile(raw,row['path'],'exec'),module.__dict__)
    return module


def put(path,raw):
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    fd = os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    need(path.read_bytes()==raw,'new host output readback differs')
    return descriptor(path,raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze-result-desc',required=True,
        help='JSON path/bytes/sha256 for the actual final validation/FREEZE-RESULT.json')
    parser.add_argument('--prepared-desc',required=True,
        help='JSON path/bytes/sha256 for the actual prepared-01/PREPARED.json')
    parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--execute-host-plan',action='store_true')
    args = parser.parse_args(argv)
    out = args.out
    need(out.is_absolute() and '..' not in out.parts and out.parent.resolve(strict=True)==out.parent
         and not out.exists() and not out.is_symlink(),'new canonical plan output required')
    originals = Originals()
    freeze_desc,prepared_desc = strict(args.freeze_result_desc),strict(args.prepared_desc)
    freeze = strict(originals.read(freeze_desc))
    need(freeze['state']=='EXACT_LITERAL_SOURCE_FREEZE_AND_PREPARATION_INPUTS_WRITTEN_HOST_ONLY'
         and freeze['phone_calls']==freeze['policy_writes']==0
         and freeze['host_preparation_executed'] is False
         and freeze['native_or_business_qualification'] is False,'actual completed host freeze required')
    source_manifest = strict(originals.read(freeze['source_manifest']))
    source_root = Path(freeze['source_manifest']['path']).parent
    need(source_manifest['files']==freeze['source_files']
         and len(source_manifest['files'])==len(SOURCE_NAMES)
         and {row['path'] for row in source_manifest['files']}=={'source/'+n for n in SOURCE_NAMES},
         'exact frozen operator source package required')
    source_rows,source_bytes = {},{}
    for row in source_manifest['files']:
        key = Path(row['path']).name
        source_rows[key] = {'path':str(source_root/row['path']),**bytepin(row)}
        source_bytes[key] = originals.read(source_rows[key])
    verifier_row = source_rows['policy_runtime_properties_verifier.py']
    V = module_from_raw('actual_frozen_runtime_property_verifier',verifier_row,
                        source_bytes['policy_runtime_properties_verifier.py'])
    need(verifier_row['sha256']==freeze['verifier_sha256'],'final verifier identity differs')
    inputs_raw = originals.read(freeze['preparation_inputs'])
    inputs = strict(inputs_raw)
    prepared_raw = originals.read(prepared_desc);prepared = strict(prepared_raw)
    prepared_dir = Path(prepared_desc['path']).parent
    need(Path(prepared_desc['path']).name=='PREPARED.json'
         and prepared['schema']=='hepta.runtime-properties-r10.live-host-preparation.v1'
         and prepared['state']=='ACTUAL_INPUTS_BOUND_HOST_PREPARED_NOT_EXECUTED'
         and prepared['phone_calls']==prepared['policy_apply_attempts']==0
         and prepared['automatic_retry'] is False and prepared['automatic_rollback'] is False
         and prepared['policy_adoption_authorized'] is False,'actual host preparation required')
    original_inputs = {'path':str(prepared_dir/'PREPARATION-INPUTS.original.json'),
                      **bytepin(freeze['preparation_inputs'])}
    need(originals.read(original_inputs)==inputs_raw,'preparation does not use the frozen actual inputs')
    binding_row = {'path':str(prepared_dir/'tree/BINDING.json'),**bytepin(prepared['binding'])}
    binding_raw = originals.read(binding_row);binding = strict(binding_raw)
    need(binding['verifier_source']==bytepin(verifier_row)
         and binding['guard_source']==bytepin(source_rows['guard_live_runtime_properties.py']),
         'preparation bound another final verifier or guard')
    staged_verifier = {'path':str(prepared_dir/'tree/policy_runtime_properties_verifier.py'),**bytepin(verifier_row)}
    staged_guard = {'path':str(prepared_dir/'tree/guard_live_runtime_properties.py'),
                    **bytepin(source_rows['guard_live_runtime_properties.py'])}
    originals.read(staged_verifier);originals.read(staged_guard)
    decision_row = inputs['root_scope_decision'];comparison_row = inputs['complete_offline_comparison']
    need(comparison_row==freeze['offline_comparison'],'actual mirrored offline comparison differs')
    expectation = V.expectation_value(binding_raw,binding_descriptor=binding_row,
        decision_descriptor=decision_row,comparison_descriptor=comparison_row)
    expectation_raw = V.encoded(expectation)
    V.verify_pre_live_expectation(expectation_raw,read_pinned=originals.read)
    expectation_row = descriptor(out/'PRE-LIVE-EXPECTATION.json',expectation_raw)
    root_package_row,driver_row,transport_row = (freeze[key] for key in
        ('root_source_package','root_driver_source','root_transport_source'))
    root_package = strict(originals.read(root_package_row))
    root_directory = Path(root_package_row['path']).parent
    expected = {'source/run_runtime_properties_policy_once.py':bytepin(driver_row),
                'source/run_component_root_once.py':bytepin(transport_row),
                'reference/run_component_root_once.r4.original.py':OLD_VALIDATOR}
    need(root_package['schema']=='hepta.root.runtime-properties-live-source-package.v1'
         and len(root_package['files'])==3 and {r['path']:bytepin(r) for r in root_package['files']}==expected,
         'exact final three-source Root package required')
    need(Path(driver_row['path'])==root_directory/'source/run_runtime_properties_policy_once.py'
         and Path(transport_row['path'])==root_directory/'source/run_component_root_once.py'
         and bytepin(driver_row)==V.ROOT_DRIVER and bytepin(transport_row)==V.ROOT_TRANSPORT_SOURCE
         and bytepin(root_package_row)==V.ROOT_SOURCE_PACKAGE,'Root sources do not match the frozen verifier')
    for name,pin in expected.items():
        originals.read({'path':str(root_directory/name),**pin})
    D = module_from_raw('reviewed_final_runtime_properties_root_driver',driver_row,originals.read(driver_row))
    need(str(D.TRANSPORT_SOURCE)==transport_row['path'] and D.TRANSPORT_SHA==transport_row['sha256']
         and D.TRANSPORT_BYTES==transport_row['bytes'],'actual Root driver transport dependency differs')
    old_plan = {'path':str(D.TRANSPORT_PLAN),'bytes':4715,'sha256':D.TRANSPORT_PLAN_SHA}
    originals.read(old_plan)
    need(D.BOOT==V.BOOT and not D.OUT.exists() and not D.OUT.is_symlink(),
         'Root target must be the declared unused transaction on the same boot')
    for key in ('stage_requests','apply_request','stage_request_provenance'):
        originals.read(prepared[key])
    stages = strict(originals.read(prepared['stage_requests']))
    need(isinstance(stages,list) and 2<=len(stages)<=9,'bounded actual stage request count')
    for row in stages:
        originals.read(row['request'])
    provenance = strict(originals.read(prepared['stage_request_provenance']))
    for row in provenance:
        originals.read(row['source'])
    plan = {'schema':'hepta.root.runtime-properties-live-plan.v1','boot_id':V.BOOT,
            'prepared':prepared_desc,'stage_requests':prepared['stage_requests'],
            'apply_request':prepared['apply_request'],'binding':binding_row,
            'pre_live_expectation':expectation_row,
            'capture_source':source_rows['capture_runtime_properties_originals.py'],
            'verifier_source':verifier_row,'transport_root_plan':old_plan,
            'source_package':root_package_row,'driver_source':driver_row,'out':str(D.OUT)}
    plan_raw = encoded(plan);plan_row = descriptor(out/'ROOT-POLICY-PLAN.json',plan_raw)
    originals.recheck()
    preview = {'state':'HOST_PLAN_PREVIEW_NO_OUTPUT_NO_PHONE','expectation':expectation_row,
        'root_plan':plan_row,'root_target':str(D.OUT),'stage_request_count':len(stages),
        'phone_calls':0,'policy_writes':0,'root_driver_full_validation_performed':False,
        'expected_live_export':None,'policy_adoption_authorized':False}
    if not args.execute_host_plan:
        print(json.dumps(preview,sort_keys=True));return 0
    os.umask(0o077);out.mkdir(mode=0o700)
    fd=os.open(out.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    put(out/'FREEZE-RESULT-DESCRIPTOR.json',encoded(freeze_desc))
    put(out/'PREPARED-DESCRIPTOR.json',encoded(prepared_desc))
    E = module_from_raw('reviewed_frozen_host_expectation_helper',
        source_rows['make_runtime_properties_expectation.py'],source_bytes['make_runtime_properties_expectation.py'])
    expectation_args = ['--binding',binding_row['path'],'--binding-sha256',binding_row['sha256'],
        '--root-scope-decision',decision_row['path'],'--root-scope-decision-sha256',decision_row['sha256'],
        '--complete-offline-comparison',comparison_row['path'],
        '--complete-offline-comparison-sha256',comparison_row['sha256'],
        '--out',expectation_row['path'],'--execute-host-expectation']
    with contextlib.redirect_stdout(io.StringIO()) as helper_output:
        expectation_rc = E.main(expectation_args)
    need(expectation_rc==0,'reviewed host expectation helper failed')
    helper_result_raw = helper_output.getvalue().encode()
    helper_result = strict(helper_result_raw)
    need(helper_result['state']=='EXPLICIT_PRE_LIVE_EXPECTATION_CREATED'
         and helper_result['expectation']==expectation_row
         and originals.read(expectation_row)==expectation_raw,'actual reviewed expectation output differs')
    put(out/'EXPECTATION-HELPER-RESULT.json',helper_result_raw)
    put(out/'ROOT-POLICY-PLAN.json',plan_raw)
    # This exact interface is pure host validation. No Chain or main is invoked.
    transport,_transport_raw,old_validator = D.load_transport()
    need(_transport_raw==originals.read(transport_row),'loaded transport changed')
    verified_plan,_closed_plan,requests,_apply_pair,_verifier = D.validate(transport,old_validator,plan_raw)
    need(verified_plan==plan and len(requests)==len(stages),'complete Root validation differs')
    originals.recheck()
    argv = ['-I','-B',driver_row['path'],'--plan',plan_row['path'],'--plan-sha256',plan_row['sha256']]
    preview_entry = {'executable':'/usr/bin/python3','argv':argv,'phone_calls':0,'policy_writes':0}
    execute_entry = {'executable':'/usr/bin/python3','argv':argv+['--execute-root-runtime-properties-policy-once'],
        'requires_explicit_single_root_owner_execution':True,'maximum_policy_apply_attempts':1,
        'automatic_retry':False,'automatic_rollback':False,'automatic_policy_adoption':False}
    preview_entry_row = put(out/'ROOT-PREVIEW-ENTRY.json',encoded(preview_entry))
    execute_entry_row = put(out/'ROOT-EXECUTION-ENTRY.json',encoded(execute_entry))
    result = {**preview,'state':'ACTUAL_PRE_LIVE_EXPECTATION_AND_ROOT_PLAN_HOST_VALIDATED_NO_PHONE',
        'root_driver_full_validation_performed':True,'freeze_result':freeze_desc,'prepared':prepared_desc,
        'root_preview_entry':preview_entry_row,'root_execution_entry':execute_entry_row,
        'original_bookends':list(originals.seen.values())}
    result_row = put(out/'HOST-PLAN-RESULT.json',encoded(result))
    print(json.dumps({'state':result['state'],'root_plan':plan_row,'expectation':expectation_row,
        'result':result_row,'preview_entry':preview_entry,'explicit_root_execution_entry':execute_entry,
        'phone_calls':0,'policy_writes':0},sort_keys=True));return 0


if __name__=='__main__':
    raise SystemExit(main())
