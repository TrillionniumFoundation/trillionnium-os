#!/usr/bin/env python3
"""Prepare the unique capture-only v3/f821 Root plan, without phone execution.

Preview reads actual frozen/source/history/policy originals and calls only the
exact Root.validate_plan using a discarded historical identity carrier.
--create-host-plan-once reserves one new input directory before drawing exactly
one nonce. It never starts Root, a sender, a process, network, model or lease.
Actual JAR installation and fresh phone admission remain external prerequisites.
"""
import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import types

PROJECT_ROOT = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
INSTALL = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-v3-f821-plan-preparer-a1055-r1.py'
FROZEN = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1'
ACTUAL_FREEZE = {'bytes': 617894, 'sha256': '77a05571bb57f7106373bb19753bf63c87cfff6b042815752cf2852e8887fbef', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/FREEZE-RESULT.json'}
FREEZE_INTENT = {'bytes': 524, 'sha256': '6bd6be5e1f366cad8080a3ab5a338560e31702f45892ea7af52b996ef9ec73aa', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/FREEZE-INTENT.json'}
ACTUAL820_PLAN = {'bytes': 4816, 'sha256': '15399913b9d80e94ac44971ba99116ebb9f2d0042eab9fa327fb92f8f5805400', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/ROOT-PLAN.original.json'}
ACTUAL820_PREVIOUS = {'bytes': 1435, 'sha256': '9d841e878f6a967d039fe559e68a2974dad497570f3692e22c324ed99865d9dc', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/ACTUAL-PREVIOUS-INPUT.json'}
ACTUAL820_BOUNDARY = {'bytes': 21002, 'sha256': '2433dd817e470e9536ec314b6a8e9d395a47053f7c1aba1cd7adee35635843fc', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/LATE-BOUNDARY.original.json'}
ACTUAL820_DESCRIPTOR = {'bytes': 369, 'sha256': 'f7d7f662ee9aba82713d4d7c16384b5435061c8dfb39362c88b4ab6afd8cb7dd', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/LATE-BOUNDARY-DESCRIPTOR.json'}
ACTUAL820_CLOSURE = {'bytes': 66879, 'sha256': 'd2671a0f936f3c1c7e4846117050880bb3140e13fe4fb7723be7786d83d66ccf', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/CLOSURE.json'}
ACTUAL820_INVENTORY = {'bytes': 1107000, 'sha256': '115893679cea5f3606f4adef61c4b01ecdc65870b6aa0c8c862df4e0313f90aa', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-sides01/INVENTORY.json'}
HISTORICAL08_CARRIER_PLAN = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/ROOT-PLAN.original.json', 'bytes': 4735, 'sha256': '7bdbfbcdf676e186a7669925f6c1de5fb384e27bf10087bd92b6ce164a12ed82'}
ADOPTION_SHA = '527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a'
POLICY_SHA = 'f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'
BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
ROOT_SCOPE_SHA = '5a08041da77eeec9168c869ae76adae0a117a5e34872aa07a1a096bc06a36132'
VERIFIER = {'bytes': 126796, 'sha256': '74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152'}
CONSUMED_LABELS = ['root-r10-neg01-1ad3-01', 'root-r10-neg01-20261105-08', 'root-r10-neg01-20261105-09', 'root-r10-neg01-7c907661-01', 'root-r10-neg01-7c907661-diag01', 'root-r10-neg01-7c907661-diag02', 'root-r10-neg01-7c907661-sides01']
CONSUMED_NONCES = ['154588e3a15591a21ec18950d18e3ecd', '16805e43f9787c44c262d5b6c6d8ed95', '2b0b103ee6de7a422064b9571266bf5d', '6077fc8f045572edc4acfb13ed7e09a8', '7c74b84aefb177d15f746fa7eae29d54', '7c79195945d64e569a191166ac122a08', '82012c7447c5f35d97c832d1d9481860', '88d68d88130d3c74e6c950a6346357c1', '8daaaad6a322963e87973613c1fac762', '902e851c3ca1f90deab3d880ab993774', 'c705647dd4ebb5d421be1041a9c41ca6', 'e4c3ccb0b2d706be3b7bf105ae772405']
SELECTED_LABEL = 'root-r10-neg01-a1055-v3stack01'
EXPECTED_SCREEN_HELPER = {'bytes': 26156, 'gid': 0, 'mode': 420, 'path': '/data/local/tmp/hepta-screen-codec-runtime-diag-a1055-v3-r1/codec.jar', 'selinux': 'u:object_r:trillionnium_owner_open_phone_helper_file:s0', 'sha256': '54adf8e1434380b9b8414fac7ce1632a35ce8ebe97b5f1dc8b68af64fb6de60f', 'uid': 0}
EXPECTED_TUPLE = {'runtime_manifest': {'bytes': 39790, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/runtime/MANIFEST.json', 'sha256': 'd30e58c42205fa99cdb9367d7f1186532d27a1d20a2bfe20a1c41c387ddffc70'}, 'root_chain_manifest': {'bytes': 33063, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/root-chain/SOURCE-MANIFEST.json', 'sha256': '720b30e2828d8b3a2170b558fe525018f4851724187416e9ac67284d38752664'}, 'shared_materials': {'bytes': 3519, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/shared/SHARED-MATERIALS.json', 'sha256': '2ea9a478b366d6a69fdb8942699b6241d72330cfa789baa4b3132fdaca169e68'}, 'combination': {'bytes': 4695, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/COMBINATION.json', 'sha256': 'f265d39c001aa09a813a03b92b0a96689ab1bcc431c8e408c8ce4da80693a945'}}
MAX_ORIGINAL = 16777216
MAX_ROOT_READ = 67108864
K = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
_WRITE = {'allowed': False, 'directory': None, 'fds': set()}


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode('utf-8')


def strict(raw):
    def pairs(rows):
        value = {}
        for key,item in rows:
            need(key not in value,'duplicate JSON field')
            value[key] = item
        return value
    if type(raw) is bytes:
        raw = raw.decode('utf-8','strict')
    need(type(raw) is str,'JSON text required')
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _: need(False,'nonfinite JSON'))


def md(value):
    return [getattr(value,key) for key in K]


def pin(raw):
    return {'bytes':len(raw),'sha256':sha(raw)}


def descriptor(row, maximum=MAX_ORIGINAL):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'}
        and type(row['path']) is str and type(row['bytes']) is int
        and 0 <= row['bytes'] <= maximum and type(row['sha256']) is str
        and re.fullmatch('[0-9a-f]{64}',row['sha256']), 'bounded exact descriptor required')
    path = Path(row['path'])
    need(path.is_absolute() and str(path)==row['path'] and '..' not in path.parts
        and '\x00' not in row['path'], 'canonical absolute descriptor path required')
    return path


def audit(event, args):
    # Reviewed code remains trusted source; this additionally excludes accidental effects.
    if event.startswith(('subprocess.', 'socket.')) or event in {
            'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','os.kill','os.killpg',
            'os.putenv','os.unsetenv','ctypes.dlopen','ctypes.dlsym'}:
        raise PermissionError('host-only preparation excludes process, signal or network events')
    if event == 'open':
        path,mode,flags = args
        writes = ((type(mode) is str and any(x in mode for x in 'wax+'))
                  or (type(flags) is int and bool(flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))))
        if writes:
            need(_WRITE['allowed'],'writes excluded outside one owned publication call')
            if type(path) is int:
                need(path in _WRITE['fds'],'only the just-created owned file descriptor may be written')
            else:
                path = Path(path)
                need(_WRITE['directory'] is not None and path.parent == _WRITE['directory']
                    and type(flags) is int and flags & os.O_EXCL and flags & os.O_CREAT
                    and flags & os.O_NOFOLLOW,'only create-only files in reserved input directory')
    if event == 'os.mkdir':
        need(_WRITE['allowed'] and Path(args[0]) == _WRITE['directory'],
             'only the explicitly selected input directory may be reserved')
    if event in {'os.remove','os.unlink','os.rmdir','os.rename','os.replace','os.symlink',
                 'os.link','os.chmod','os.chown','os.truncate','os.utime','os.chflags'}:
        raise PermissionError('originals and existing namespaces are immutable')


class Originals:
    def __init__(self):
        self.rows = {}

    def remember(self, path, raw, before):
        row = {'path':str(path),**pin(raw),'metadata':before}
        need(str(path) not in self.rows or self.rows[str(path)] == row,
             'original full metadata or bytes changed across reads')
        self.rows[str(path)] = row
        return raw

    def raw(self, path, maximum=MAX_ROOT_READ):
        path = Path(path)
        need(type(maximum) is int and 0 <= maximum <= MAX_ROOT_READ
             and path.is_absolute() and path.resolve(strict=True) == path,
             'canonical bounded read required')
        before = md(path.lstat())
        need(stat.S_ISREG(before[2]) and before[5] == 1 and 0 <= before[6] <= maximum,
             'bounded regular single-link original required')
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            first = md(os.fstat(fd)); need(first == before,'original changed before open')
            with os.fdopen(fd,'rb',closefd=False) as stream:
                raw = stream.read(maximum+1)
            after = md(os.fstat(fd))
        finally:
            os.close(fd)
        need(first == after == md(path.lstat()) and len(raw) == first[6],
             'original changed during bounded read')
        return self.remember(path,raw,first)

    def read(self, row):
        path = descriptor(row)
        raw = self.raw(path,row['bytes'])
        need(pin(raw) == {k:row[k] for k in ('bytes','sha256')},'original length or SHA differs')
        return raw

    def delegate(self, original_read, path, maximum=MAX_ROOT_READ):
        # Retain the exact Root read checks and return bytes; add cross-call bookends only.
        path = Path(path); before = md(path.lstat())
        raw = original_read(path,maximum)
        need(before == md(path.lstat()),'original changed around the pinned Root reader')
        return self.remember(path,raw,before)

    def recheck(self):
        for row in list(self.rows.values()):
            raw = self.raw(Path(row['path']),row['bytes'])
            need(pin(raw) == {k:row[k] for k in ('bytes','sha256')},'bookend original differs')


def pure_module(raw, name, filename):
    module = types.ModuleType(name)
    module.__file__ = str(filename)
    exec(compile(raw,str(filename),'exec'),module.__dict__)
    return module


def literal(raw, name):
    nodes = [node for node in ast.parse(raw).body if isinstance(node,ast.Assign)
        and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id==name]
    need(len(nodes)==1,'one reviewed source constant required: '+name)
    return ast.literal_eval(nodes[0].value)


def require_unused(label):
    need(type(label) is str and re.fullmatch('[a-z0-9][a-z0-9-]{5,35}',label)
         and label not in CONSUMED_LABELS,'explicit Root-selected unused label required')
    base = Path(PROJECT_ROOT)
    directory = base/'native-guard-root-inputs-r10-r1'/label
    out = base/'native-guard-root-chains-r10-r1'/label
    need(directory.parent.resolve(strict=True)==directory.parent
         and out.parent.resolve(strict=True)==out.parent
         and not os.path.lexists(directory) and not os.path.lexists(out),
         'selected input or execution namespace already exists; no reuse or replay')
    for suffix in ('.preview.actor.py','.actor.py','.local-once.json','.send-result.json'):
        need(not os.path.lexists(base/(label+suffix)),'sender identity already retained; no replay')
    return directory,out


def synchronize(path):
    fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def reserve(directory):
    need(_WRITE['directory'] is None,'one input-directory reservation only')
    _WRITE['directory'] = directory; _WRITE['allowed'] = True
    try:
        directory.mkdir(mode=0o700)
    finally:
        _WRITE['allowed'] = False
    synchronize(directory); synchronize(directory.parent)


def put(path, raw):
    need(type(raw) is bytes and path.parent == _WRITE['directory'],'owned publication only')
    _WRITE['allowed'] = True
    try:
        fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        _WRITE['fds'].add(fd)
        try:
            with os.fdopen(fd,'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        finally:
            _WRITE['fds'].discard(fd)
    finally:
        _WRITE['allowed'] = False
    synchronize(path.parent)
    need(path.read_bytes()==raw,'published bytes differ')
    return {'path':str(path),**pin(raw)}


def validate_current_plan(o, raw, context):
    entry=context['entry'];body=o.read(entry)
    need(body==context['root_raw'],'selected Root source changed')
    old_path=list(sys.path);old_dwb=sys.dont_write_bytecode
    present='component_common' in sys.modules;saved=sys.modules.get('component_common')
    try:
        sys.dont_write_bytecode=True
        module=pure_module(body,'diagnostic_root_plan_pure_validation',entry['path'])
        need(str(module.MATERIAL_ROOT)==context['updates']['shared_root'],
             'exact new shared source namespace required')
        original_read=module.read
        module.read=lambda path,n=MAX_ROOT_READ: o.delegate(original_read,path,n)
        result,manifest=module.validate_plan(raw)
        need(result==strict(raw) and manifest['current_combination_sha256']==context['freeze']['combination']['sha256'],
             'exact pure Root validator changed plan or combination')
    finally:
        sys.path[:]=old_path;sys.dont_write_bytecode=old_dwb
        if present:sys.modules['component_common']=saved
        else:sys.modules.pop('component_common',None)
    return {'validator_source':entry,'method':'validate_plan',
        'original_read_delegated_only_for_cross_call_full9_and_sha_bookends':True,
        'Chain_or_main_called':False,'phone_calls':0}


def historical_validation_carrier(o, context):
    old=strict(o.read(HISTORICAL08_CARRIER_PLAN))
    need(old['label']=='root-r10-neg01-20261105-08'
         and old['nonce']=='2b0b103ee6de7a422064b9571266bf5d' and old['case_id']=='NEG-01',
         'exact old08 in-memory validation carrier required')
    old_owner=o.read(old['request'])
    need(old_owner.replace(old['nonce'].encode(),context['parent']['nonce'].encode())==context['owner']
         and old_owner.count(old['nonce'].encode())==1,
         'historical carrier public request differs beyond its old nonce')
    carrier=copy.deepcopy(context['parent']);carrier.update(context['updates'])
    for key in ('label','nonce','out','request'):
        carrier[key]=old[key]
    validation=validate_current_plan(o,enc(carrier),context)
    del carrier
    return {'kind':'historical-validation-carrier','source':HISTORICAL08_CARRIER_PLAN,
        'validation':validation,'identity_generated':False,'historical_carrier_discarded':True,
        'actual_plan_admitted':False,'carrier_or_request_bytes_published':False,
        'qualification':'Only the exact pure validator paths covered by this call; fresh identity and phone gates remain unexecuted.'}


def read_actual_freeze(o):
    raw=o.read(ACTUAL_FREEZE);value=strict(raw)
    need(value['schema']=='hepta.diagnostic-only.actual-host-freeze-result.v1'
         and value['state']=='HOST_FROZEN_DIAGNOSTIC_ONLY_V3_F821_NOT_PHONE_QUALIFIED'
         and value['diagnostic_only'] is True and value['all_inputs_rechecked'] is True
         and value['all_output_files_read_back'] is True and value['automatic_retry'] is False
         and value['actual_worker_stack_observed'] is False and value['current_live_policy_claimed'] is False
         and value['full19_budget_or_qualification_claimed'] is False,
         'actual reviewed capture-only freeze required')
    for key,expected in {'runtime_path_count':36,'root_source_path_count':3,'shared_file_count':17,
        'historical_native_count':8,'historical_non_native_count':2,'historical_role_count':30,
        'native_chain_cap':9,'component_role_cap':33,'fixture_root_cap':11,'inventory_root_cap':39,
        'current_prefix_maximum':1,'maximum_native_calls':1,'phone_calls':0,
        'native_submissions':0,'new_nonces_generated':0,'policy_applications':0}.items():
        need(type(value[key]) is int and value[key]==expected, 'actual diagnostic freeze field differs: '+key)
    need(type(value['files']) is dict and len(value['files'])==143
         and type(value['actual_input_files']) is dict and len(value['actual_input_files'])==750,
         'complete actual143 outputs and750 original inputs required')
    # Recheck every original input's actual nine-field identity, not only a
    # result's true flags. These are read-only; no source consumer is executed.
    for path,row in value['actual_input_files'].items():
        need(path==row['path'],'input path alias')
        o.read({k:row[k] for k in ('path','bytes','sha256')})
        need(o.rows[path]==row,'original input differs from actual freeze bookend')
    outputs={}
    for name,row in value['files'].items():
        p=Path(name)
        need(not p.is_absolute() and str(p)==name and '..' not in p.parts
             and row['path']==str(Path(FROZEN)/p), 'frozen output left exact directory')
        outputs[name]=o.read(row)
    intent=o.read(FREEZE_INTENT)
    payload=sum(map(len,outputs.values()))
    need(payload==value['output_payload_bytes']==15697853
         and len(intent)==value['freeze_intent_bytes']==524
         and len(raw)==value['freeze_result_bytes']==617894
         and payload+len(intent)+len(raw)==value['complete_frozen_directory_raw_bytes']==16316271
         and value['frozen_directory_limit_includes_payload_intent_and_result']==33554432,
         'actual complete frozen directory accounting differs')
    for header,expected in EXPECTED_TUPLE.items():
        need(value[header]==expected,'actual frozen current tuple differs: '+header)
    for name,count,header in [('runtime/MANIFEST.json',36,'runtime_manifest'),
            ('root-chain/SOURCE-MANIFEST.json',3,'root_chain_manifest'),
            ('shared/SHARED-MATERIALS.json',17,'shared_materials')]:
        manifest=strict(outputs[name]);prefix=Path(name).parent
        need(value[header]==value['files'][name] and len(manifest['files'])==count,
             'manifest header/member count differs')
        for row in manifest['files']:
            need(pin(outputs[str(prefix/row['path'])])=={k:row[k] for k in ('bytes','sha256')},
                 'actual manifest member differs')
    checks=strict(outputs['HOST-VALIDATION.json']);history=checks['history']
    need(checks['schema']=='hepta.diagnostic-only.complete-host-validation.v1'
         and checks['diagnostic_only'] is True and checks['source_tuple_frozen'] is True
         and checks['actual_worker_stack_observed'] is False and checks['phone_operations']==0
         and checks['actual_device_deployment_or_current_live_read'] is False,
         'host proof must not imply phone/helper or worker qualification')
    need(history['historical_native_count']==8 and history['historical_non_native_count']==2
         and history['historical_role_count']==30 and history['inventory_roots']==36
         and history['fixture_roots']==10 and history['historical_native_call_counts']==[1,1,1,1,0,1,1,0]
         and len(history['component_roles'])==len({tuple(r) for r in history['component_roles']})==30
         and history['records']==strict(outputs['FULL-HISTORICAL-ANCESTOR-PINS.json']),
         'eight failed native histories and both branches must remain complete')
    policy=checks['unchanged_actual_policy_adoption']
    need(policy['current_adoption_sha256']==ADOPTION_SHA
         and policy['runtime_policy']=={'bytes':2667740,'sha256':POLICY_SHA}
         and policy['verification_original_count']==554 and policy['verification_original_bytes']==31518321
         and policy['independent_verifier_source']['sha256']==VERIFIER['sha256'],
         'unchanged actual f821/527 independent verification differs')
    java=checks['selected_java'];combo=strict(outputs['COMBINATION.json'])
    need(java['jar']=={'bytes':26156,'sha256':EXPECTED_SCREEN_HELPER['sha256']}
         and java['native_streams_combined_maximum']==600000
         and java['new_maximum_stderr_bytes_including_lf']==4096
         and combo['artifacts']['screen_helper']==EXPECTED_SCREEN_HELPER
         and combo['live_policy_sha256']==POLICY_SHA,
         'selected v3 helper and its exact existing byte caps differ')
    root_manifest=strict(outputs['root-chain/SOURCE-MANIFEST.json'])
    need(root_manifest['diagnostic_only'] is True and root_manifest['root_fixture_phases']==['setup']
         and root_manifest['maximum_native_calls_in_current_generation']==1,
         'Root must remain one capture with setup only')
    return value,outputs


def selected_inputs(o):
    directory,out=require_unused(SELECTED_LABEL)
    freeze,outputs=read_actual_freeze(o)
    parent_raw=o.read(ACTUAL820_PLAN);parent=strict(parent_raw)
    need(parent['label']=='root-r10-neg01-7c907661-sides01'
         and parent['nonce']=='82012c7447c5f35d97c832d1d9481860' and parent['case_id']=='NEG-01'
         and parent['boot_id']==BOOT and parent['live_policy_sha256']==POLICY_SHA
         and parent['policy_adoption']['bytes']==208226 and parent['policy_adoption']['sha256']==ADOPTION_SHA,
         'actual failed820 public request parent differs')
    owner=o.read(parent['request'])
    need(len(owner)==317 and owner.count(parent['nonce'].encode())==1 and b'\x00' not in owner,
         'actual public owner request shape differs')
    previous_raw=o.read(ACTUAL820_PREVIOUS);previous=strict(previous_raw)
    boundary_raw=o.read(ACTUAL820_BOUNDARY);boundary=strict(boundary_raw)
    prior_descriptor=strict(o.read(ACTUAL820_DESCRIPTOR))
    closure_raw=o.read(ACTUAL820_CLOSURE);closed=strict(closure_raw)
    inventory_raw=o.read(ACTUAL820_INVENTORY)
    history=strict(outputs['HOST-VALIDATION.json'])['history']
    need(history['records'][0]=={'boundary':prior_descriptor,'inventory':boundary['inventory'],'closure':boundary['closure']}
         and outputs['retained-history/failed820/boundary.original.json']==boundary_raw
         and outputs['retained-history/failed820/closure.original.json']==closure_raw
         and outputs['retained-history/failed820/inventory.original.json']==inventory_raw,
         'selected host originals differ from complete frozen failed820 history')
    need(previous['late_boundary']==prior_descriptor
         and {k:prior_descriptor[k] for k in ('bytes','sha256')}==pin(boundary_raw)
         and previous['closed_component']==ACTUAL820_CLOSURE
         and boundary['nonce']==parent['nonce'] and boundary['scope']==previous['identity']
         and previous['terminal']['status']==boundary['native_status']==closed['native_status']=='provider_failed'
         and previous['component_qualified'] is boundary['component_qualified'] is closed['component_qualified'] is False
         and type(closed['actual_native_calls']) is int and closed['actual_native_calls']==1
         and type(closed['unknown_effects']) is int and closed['unknown_effects']==0,
         'actual failed820 closure or terminal accounting differs')
    root_manifest=strict(outputs['root-chain/SOURCE-MANIFEST.json'])
    row=next(r for r in root_manifest['files'] if r['path']=='source/run_component_root_once.py')
    entry={'path':str(Path(freeze['root_chain_manifest']['path']).parent/row['path']),
           **{k:row[k] for k in ('bytes','sha256')}}
    root_raw=o.read(entry)
    expected={'PKG':freeze['runtime_manifest']['sha256'],'COMBINATION':freeze['combination']['sha256'],
        'SHARED':freeze['shared_materials']['sha256'],'CONFIG':sha(outputs['shared/local-config-r10-r1.json']),
        'SERVICE':sha(outputs['shared/PHONE-SERVICE-INPUTS-v150-r10-r1.json']),
        'POLICY_SHA':POLICY_SHA,'ADOPTION_SHA':ADOPTION_SHA,'ROOT_SCOPE_SHA':ROOT_SCOPE_SHA,
        'VERIFIER_SHA':VERIFIER['sha256'],'VERIFIER_BYTES':VERIFIER['bytes'],'BOOT':BOOT}
    need(all(literal(root_raw,key)==value for key,value in expected.items()),
         'actual source constants do not bind selected diagnostic freeze')
    updates={'package':freeze['runtime_manifest'],'source_package':freeze['root_chain_manifest'],
        'shared_materials':freeze['shared_materials'],'shared_root':str(Path(freeze['shared_materials']['path']).parent),
        'artifacts':freeze['files']['ARTIFACTS.json'],'previous':ACTUAL820_PREVIOUS,
        'prior_boundary_descriptor':ACTUAL820_DESCRIPTOR,'prior_boundary_original':ACTUAL820_BOUNDARY}
    return {'directory':directory,'out':out,'parent':parent,'parent_raw':parent_raw,'owner':owner,
        'freeze':freeze,'outputs':outputs,'entry':entry,'root_raw':root_raw,'updates':updates,
        'prior_descriptor':prior_descriptor,'selected_label':SELECTED_LABEL}


def create_plan(o, context, source_desc, source_raw, preview_validation):
    directory,out=require_unused(SELECTED_LABEL)
    need(directory==context['directory'] and out==context['out'],'selected namespaces changed')
    os.umask(0o077);reserve(directory)
    generated=0;attempts=0
    try:
        put(directory/'GENERATION-INTENT.json',enc({
            'schema':'hepta.root.v3-stack-diagnostic-generation-intent.v1','source':source_desc,
            'label':SELECTED_LABEL,'execution_out':str(out),'actual_freeze_result':ACTUAL_FREEZE,
            'automatic_retry':False,'maximum_nonce_generations':1,'phone_calls':0,'root_chain_executions':0}))
        attempts=1;nonce=secrets.token_hex(16);generated=1
        need(re.fullmatch('[0-9a-f]{32}',nonce) and nonce not in CONSUMED_NONCES,
             'generated nonce collides with retained identity; no retry')
        identity=put(directory/'IDENTITY.original.json',enc({
            'schema':'hepta.root.v3-stack-diagnostic-generated-identity.v1',
            'label':SELECTED_LABEL,'nonce':nonce,'case_id':'NEG-01','generation_count':1,
            'automatic_retry':False,'phone_calls':0}))
        parent=context['parent'];owner=context['owner']
        newowner=owner.replace(parent['nonce'].encode(),nonce.encode())
        need(newowner.count(nonce.encode())==1 and len(newowner)==317
             and newowner.replace(nonce.encode(),parent['nonce'].encode())==owner,
             'only the exact public owner request nonce may change')
        plan=copy.deepcopy(parent);plan.update(context['updates'])
        plan.update(label=SELECTED_LABEL,nonce=nonce,out=str(out))
        request_desc={'path':str(directory/'REQUEST.txt'),**pin(newowner)};plan['request']=request_desc
        changed=sorted(k for k in parent if plan[k]!=parent[k])
        need(set(plan)==set(parent) and set(changed)=={'label','nonce','out','request','package',
            'source_package','shared_materials','shared_root','artifacts','previous','prior_boundary_descriptor','prior_boundary_original'},
            'only reviewed current generation plan fields may change')
        need(plan['preserved_draft']==parent['preserved_draft'] and plan['policy_adoption']==parent['policy_adoption']
             and plan['live_policy_sha256']==parent['live_policy_sha256'] and plan['boot_id']==parent['boot_id'],
             'preserved draft, unchanged policy or original boot differs')
        put(directory/'REQUEST.txt',newowner)
        actual_validation=validate_current_plan(o,enc(plan),context);o.recheck()
        plan_desc=put(directory/'ROOT-PLAN.json',enc(plan));put(directory/'PREPARE.original.py',source_raw)
        evidence=put(directory/'PREPARATION-EVIDENCE.json',enc({
            'schema':'hepta.root.v3-stack-diagnostic-plan-preparation.v1','source':source_desc,
            'actual_freeze_result':ACTUAL_FREEZE,'identity_original':identity,'public_request':request_desc,
            'parent_actual820_plan':ACTUAL820_PLAN,'actual820_previous':ACTUAL820_PREVIOUS,
            'actual_runtime':context['freeze']['runtime_manifest'],
            'actual_root_source_package':context['freeze']['root_chain_manifest'],
            'actual_shared_materials':context['freeze']['shared_materials'],'actual_artifacts':context['updates']['artifacts'],
            'historical_native_boundaries':8,'historical_non_native_branches':2,'historical_component_roles':30,
            'component_role_cap':33,'native_chain_cap':9,'current_case_prefix_maximum':1,
            'fixture_root_cap':11,'inventory_root_cap':39,'maximum_native_calls':1,'root_fixture_phases':['setup'],
            'historical_preview':preview_validation,'actual_pure_validation':actual_validation,
            'actual_plan_admitted_by_pure_root_validator':True,'fresh_phone_admission_proven':False,
            'helper_deployment_verified_by_this_preparer':False,'native_execution_authorized_by_this_preparer':False,
            'changed_fields':changed,'only_public_request_nonce_changed':True,
            'private_draft_contents_read':True,'private_draft_read_scope':'pinned pure Root.validate_plan only',
            'private_draft_or_inner_digest_output':False,'originals':list(o.rows.values()),
            'new_nonces':1,'lease_fixed':False,'phone_calls':0,'root_chain_executions':0}))
        o.recheck()
        result={'schema':'hepta.root.v3-stack-diagnostic-preparation-result.v1',
            'state':'ONE_CAPTURE_ONLY_DIAGNOSTIC_ROOT_PLAN_PREPARED_NO_PHONE_EXECUTION',
            'plan':plan_desc,'entry':context['entry'],'evidence':evidence,'label':SELECTED_LABEL,
            'nonce':nonce,'case_id':'NEG-01','actual_pure_validate_plan_passed':True,
            'retained_native_boundaries':8,'retained_non_native_branches':2,'retained_component_roles':30,
            'expected_roles_after_one_diagnostic':33,'component_role_cap':33,'native_chain_cap':9,
            'current_case_prefix_maximum':1,'fixture_root_cap':11,'inventory_root_cap':39,
            'maximum_native_calls':1,'diagnostic_only':True,'root_fixture_phases':['setup'],
            'capture_success_still_stops_before_mapper_prepare':True,'business_or_NEG_credit':False,
            'helper_deployment_verified_by_this_preparer':False,
            'actual_helper_deployment_and_fresh_external_admission_required_before_native':True,
            'native_execution_authorized_by_this_preparer':False,'lease_fixed':False,
            'phone_calls':0,'root_chain_executions':0,'automatic_retry':False,
            'exact_argv':['/usr/bin/python3','-I','-B',context['entry']['path'],'--plan',plan_desc['path'],
                '--plan-sha256',plan_desc['sha256'],'--execute-root-chain-once']}
        result_desc=put(directory/'RESULT.json',enc(result));return dict(result,result=result_desc)
    except BaseException as error:
        put(directory/'PREPARATION-FAILURE.json',enc({
            'schema':'hepta.root.v3-stack-diagnostic-preparation-failure.v1',
            'state':'HOST_GENERATION_RETAINED_NO_AUTOMATIC_RETRY','source':source_desc,'label':SELECTED_LABEL,
            'error_type':type(error).__name__,'nonce_generation_count':generated,'nonce_generation_attempts':attempts,
            'root_plan_qualification_not_inferred':True,'phone_calls':0,'root_chain_executions':0,
            'automatic_retry':False,'preserved_existing_root_output':True}))
        raise


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reviewed-source-sha256',required=True)
    parser.add_argument('--create-host-plan-once',action='store_true')
    args=parser.parse_args(argv);sys.dont_write_bytecode=True
    source_path=Path(__file__).resolve(strict=True)
    need(source_path==Path(INSTALL),'fixed independent create-only preparer source required')
    sys.addaudithook(audit)
    o=Originals();source_raw=o.raw(source_path,MAX_ORIGINAL)
    need(re.fullmatch('[0-9a-f]{64}',args.reviewed_source_sha256)
         and sha(source_raw)==args.reviewed_source_sha256,'exact reviewed source identity required')
    source_desc={'path':str(source_path),**pin(source_raw)}
    context=selected_inputs(o);preview=historical_validation_carrier(o,context)
    o.recheck();require_unused(SELECTED_LABEL)
    if not args.create_host_plan_once:
        print(enc({'schema':'hepta.root.v3-stack-diagnostic-preparation-preview.v1',
            'state':'ACTUAL143_FREEZE_AND750_INPUTS_AND_PURE_ROOT_VALIDATION_CHECKED_NO_NEW_IDENTITY',
            'source':source_desc,'actual_freeze_result':ACTUAL_FREEZE,'selected_label':SELECTED_LABEL,
            'selected_input_path':str(context['directory']),'selected_root_output_path':str(context['out']),
            'historical_validation':preview,'identity_generated':False,'new_nonces':0,
            'request_files_created':0,'root_plans_created':0,'output_directories_created':0,
            'retained_native_boundaries':8,'retained_non_native_branches':2,'retained_component_roles':30,
            'native_chain_cap':9,'component_role_cap':33,'fixture_root_cap':11,'inventory_root_cap':39,
            'current_case_prefix_maximum':1,'maximum_native_calls':1,'diagnostic_only':True,
            'root_fixture_phases':['setup'],'lease_fixed':False,'private_draft_contents_read':True,
            'private_draft_or_inner_digest_output':False,'phone_calls':0,'root_chain_executions':0,
            'fresh_phone_state_observed':False,'helper_deployment_verified_by_this_preparer':False,
            'native_execution_authorized_by_this_preparer':False,'automatic_retry':False,
            'bookended_host_original_count':len(o.rows)}).decode(),end='')
        return 0
    result=create_plan(o,context,source_desc,source_raw,preview)
    print(enc(result).decode(),end='');return 0


if __name__=='__main__':
    raise SystemExit(main())
