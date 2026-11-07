#!/usr/bin/env python3
"""One fixed ended diag02 no-Send attempt: read originals, never start a native task.

Only a fresh capture directory and its evidence files are written. The native
chain remains the exact seven native ancestors plus original05 sidebranch. No native scope or terminal is invented.
"""
import argparse
import ast
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import types

sys.dont_write_bytecode=True
BASE=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
LABEL='root-r10-neg01-7c907661-diag02'
NONCE='8daaaad6a322963e87973613c1fac762'
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
HOME=BASE/'native-guard-r10-r1'/LABEL
OUT=BASE/'native-guard-snapshots-r10-r1'/(LABEL+'-nonsend-capture-7c907661-r1')
NATIVE=Path('/var/lib/trillionnium/owner-open/turn-events.jsonl.segments')
OWNER='caa9a5091e758975ef1b94903f0cd06705f88ef8c9fe94cc8a17e773240a777f'
PACKAGE={'bytes': 21251, 'sha256': '8e5ba081f1780da2ec73a3c103e7a27f6a0ba4e6e15ceab502fa8221ed410863'}
LEASE={'bytes': 2504, 'sha256': '9c420ebd9b1e7b24847fab5e2851921c3857f80c9281514e806a8bbe8ac790e3'}
COMBINATION={'bytes': 4695, 'sha256': '765e66acedee58e41de0ef45b6ea8061709e5b63a7aef43437876349289e86ec'}
PRIOR_BOUNDARY='621f82a3c071c755f4460f591ac1faa92ec6940b2a19c7a4d76948668abf669e'
ROOT_PLAN={'bytes': 4853, 'sha256': '6b61d2f178c3238c6d4a6508e171874ffb3e6811a4f9dc26bb24c2d00e53ac27'}
ROOT_FAILURE={'bytes': 13590, 'sha256': '6fda21d802643191763af4e980eace98160bb49f68e9db509762aecd558701c2'}
DEPENDENCIES={'component_common': {'bytes': 19138, 'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}, 'native_proc_profile': {'bytes': 4633, 'sha256': '12719e58d2e3e1a1e86b8a6a9dc9587e37bfcb36c4c3b26b023138752bb3e67b'}, 'component_lifecycle': {'bytes': 40261, 'sha256': '144836347482b8871703b882283ffac63d5df480e3333a9bd631409f890fc1c2'}, 'component_snapshot': {'bytes': 24187, 'sha256': '2d624aaafb7df75ad3c78b35e866a44022ee4f5205b20aaeb4515458e05eaffa'}, 'late_boundary': {'bytes': 93980, 'sha256': '9660de4542ce833b899fad51fe59a1d0c0c05222f7bf5897e4a234abd508d756'}}
MAX_NATIVE_FILE=64*1024*1024
MAX_NATIVE_TOTAL=128*1024*1024
MAX_LINE=4*1024*1024


ROOT_PLAN_DESCRIPTOR={'bytes': 4853, 'sha256': '6b61d2f178c3238c6d4a6508e171874ffb3e6811a4f9dc26bb24c2d00e53ac27', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag02/ROOT-PLAN.original.json'}
ROOT_FAILURE_DESCRIPTOR={'bytes': 13590, 'sha256': '6fda21d802643191763af4e980eace98160bb49f68e9db509762aecd558701c2', 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-7c907661-diag02/ROOT-FAILURE.json'}
PRIOR_DESCRIPTOR={'bytes': 9998, 'metadata': [65086, 149888, 33152, 0, 0, 1, 9998, 1793894221355909793, 1793894221355909793], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/6077fc8f045572edc4acfb13ed7e09a8.json', 'sha256': '621f82a3c071c755f4460f591ac1faa92ec6940b2a19c7a4d76948668abf669e'}
POLICY='f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'
EXPECTED_ROOTS=['/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/evidence', '/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6/evidence', '/var/lib/trillionnium/owner-open/phone-local-v150/client-receipts', '/var/lib/trillionnium/owner-open/phone-local-v150/executor-r6', '/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/health-contracts/bindings', '/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/task-contracts/bindings', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03', '/proc/1/root/data/local/tmp/hepta-native-guard-88d68d88130d3c74e6c950a6346357c1', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04', '/proc/1/root/data/local/tmp/hepta-native-guard-c705647dd4ebb5d421be1041a9c41ca6', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05', '/proc/1/root/data/local/tmp/hepta-native-guard-e4c3ccb0b2d706be3b7bf105ae772405', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06', '/proc/1/root/data/local/tmp/hepta-native-guard-154588e3a15591a21ec18950d18e3ecd', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07', '/proc/1/root/data/local/tmp/hepta-native-guard-16805e43f9787c44c262d5b6c6d8ed95', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08', '/proc/1/root/data/local/tmp/hepta-native-guard-2b0b103ee6de7a422064b9571266bf5d', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01', '/proc/1/root/data/local/tmp/hepta-native-guard-902e851c3ca1f90deab3d880ab993774', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag01/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag01', '/proc/1/root/data/local/tmp/hepta-native-guard-6077fc8f045572edc4acfb13ed7e09a8', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02', '/proc/1/root/data/local/tmp/hepta-native-guard-8daaaad6a322963e87973613c1fac762']
CURRENT_ROLES={'supervisor': [12457, 12457, 12457, 24667528], 'provider': [12992, 12992, 12992, 24670040], 'sidecar': [12988, 12988, 12988, 24670008]}
INVENTORY_ORIGINAL={'bytes': 3041, 'sha256': '72106d464cf062e8d59d1964e745792c592e6b311a1775d219f760a80a08a92d'}
INVENTORY_CURRENT={'bytes': 3041, 'sha256': '4afd8432a8caa1d521f982255599a8e861ffc2b812c75e7372227e17bf3d4ece'}

def need(ok,reason):
    if not ok:raise ValueError(reason)


def digest(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def strict(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'duplicate JSON key')
            value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _x:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),
        ensure_ascii=False,allow_nan=False)+'\n').encode()


def metadata(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,
        s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def raw_source(path,pin):
    """No-follow GNU source walk. No normal import or bytecode search."""
    p=Path(path)
    need(p.is_absolute() and '..' not in p.parts,'source path is not absolute')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in p.parts[1:-1]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=nxt
        leaf=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
        try:
            a=os.fstat(leaf)
            need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==a.st_gid==0
                and stat.S_IMODE(a.st_mode)==0o600 and a.st_size==pin['bytes'],
                'actual private source metadata differs')
            with os.fdopen(leaf,'rb',closefd=False) as stream:raw=stream.read(pin['bytes']+1)
            need(metadata(a)==metadata(os.fstat(leaf))==
                metadata(os.stat(p.name,dir_fd=fd,follow_symlinks=False))
                and digest(raw)==pin,'actual source raw pin changed')
            return raw
        finally:os.close(leaf)
    finally:os.close(fd)


def load_modules():
    modules={}
    for name,pin in DEPENDENCIES.items():
        need(name not in sys.modules,'unexpected preloaded runtime module')
        path=HOME/'package/source'/(name+'.py')
        raw=raw_source(path,pin)
        module=types.ModuleType(name);module.__file__=str(path);module.__package__=''
        module.__reviewed_source_sha256__=pin['sha256']
        sys.modules[name]=module
        try:exec(compile(raw,str(path),'exec'),module.__dict__)
        except BaseException:sys.modules.pop(name,None);raise
        modules[name]=module
    return modules


def original_absence(C,path):
    """A named missing entry, anchored to held/reopened canonical parent FDs."""
    path=Path(path);fd,leaf=C.parent_fd(path)
    try:
        before=os.fstat(fd)
        need(stat.S_ISDIR(before.st_mode),'absence parent is not directory')
        names=sorted(os.listdir(fd))
        need(len(names)<=20000,'absence parent directory bound')
        for _ in range(2):
            try:os.stat(leaf,dir_fd=fd,follow_symlinks=False)
            except OSError as error:need(error.errno==errno.ENOENT,'absence is unknown')
            else:need(False,'required pre-native path is present: '+str(path))
        second,again=C.parent_fd(path)
        try:
            current=os.fstat(second)
            need(again==leaf and metadata(before)==metadata(current)==metadata(os.fstat(fd))
                and names==sorted(os.listdir(second))==sorted(os.listdir(fd)),
                'absence parent changed or path was replaced')
            try:os.stat(again,dir_fd=second,follow_symlinks=False)
            except OSError as error:need(error.errno==errno.ENOENT,'final absence unknown')
            else:need(False,'required absent path appeared')
        finally:os.close(second)
        return {'path':str(path),'absence':'ENOENT','parent_path':str(path.parent),
            'parent_metadata':metadata(before),'parent_names':names,
            'observed_monotonic_ns':time.monotonic_ns()}
    finally:os.close(fd)


def check_empty_claims(C):
    path=C.private_dir(HOME/'claims')
    a=path.lstat();names=sorted(p.name for p in path.iterdir())
    need(names==[] and metadata(a)==metadata(path.lstat()),'one-use claim exists or changed')
    return {'path':str(path),'metadata':metadata(a),'names':names}


def native_nonce_absence(C,cap,root):
    """Read every complete original segment; retain exact read provenance, not fake scope."""
    root=Path(root);start=root.lstat()
    need(stat.S_ISDIR(start.st_mode) and not stat.S_ISLNK(start.st_mode),'native directory differs')
    names=sorted(p.name for p in root.iterdir())
    need(len(names)<=1024,'native segment count limit')
    segments=[name for name in names if name.endswith('.jsonl')]
    need(segments,'native segment set is absent')
    source=[];total=records=0
    for name in segments:
        cap.check()
        path=root/name;before=path.lstat()
        raw=C.read(path,MAX_NATIVE_FILE,private=False)
        need(metadata(before)==metadata(path.lstat()),'native segment changed during read')
        total+=len(raw)
        need(total<=MAX_NATIVE_TOTAL,'native full-scan byte bound')
        need(NONCE.encode() not in raw and OWNER.encode() not in raw,
             'failed-attempt nonce or owner hash appears in native originals')
        count=0
        for line in raw.splitlines(keepends=True):
            need(line.endswith(b'\n') and len(line)<=MAX_LINE,'native line incomplete or oversized')
            need(isinstance(C.strict(line),dict),'native original line is not an object')
            count+=1
        records+=count
        row={'path':str(path),'metadata':metadata(before),**digest(raw),'complete_lines':count}
        source.append(row)
        cap.originals[str(path)]={'metadata':row['metadata'],'bytes':row['bytes'],'sha256':row['sha256']}
    need(metadata(start)==metadata(root.lstat()) and names==sorted(p.name for p in root.iterdir()),
         'native segment namespace changed during absence scan')
    # A second complete byte/hash pass, not an mtime-only absence bookend.
    for row in source:
        cap.check();raw=C.read(row['path'],MAX_NATIVE_FILE,private=False)
        need(metadata(Path(row['path']).lstat())==row['metadata']
            and digest(raw)=={k:row[k] for k in ('bytes','sha256')},
            'native originals changed after full absence scan')
    need(metadata(start)==metadata(root.lstat()) and names==sorted(p.name for p in root.iterdir()),
         'native namespace changed after second read')
    cap.directories[str(root)]={'metadata':metadata(start),'names':names,'capture_path':None}
    return {'schema':'hepta.native-guard.non-native-nonce-absence.v1','nonce':NONCE,
        'owner_request_sha256':OWNER,'directory':{'path':str(root),'metadata':metadata(start),'names':names},
        'sources':source,'complete_lines_scanned':records,'file_bytes_scanned':total,
        'nonce_occurrences':0,'owner_hash_occurrences':0,'all_segment_bytes_rechecked':True,
        'native_scope_assigned':False,'native_hash_chain_verified':False,
        'native_store_raw_bytes_copied':False,
        'evidence_kind':'Pinned read-only observer scanned all bounded complete original lines twice.'}


def capture_controls(C,cap,root,logical):
    before=root.lstat();names=sorted(p.name for p in root.iterdir())
    need(len(names)<=20000,'control root entry bound')
    skipped=[]
    for name in names:
        cap.check();path=root/name
        if re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',name):
            need(not name.endswith(NONCE),'failed attempt already has a native run')
            need(stat.S_ISDIR(path.lstat().st_mode) and not path.is_symlink(),'native run entry differs')
            skipped.append(name);continue
        s=path.lstat()
        if stat.S_ISDIR(s.st_mode):cap.tree(path,logical+'/'+name)
        else:cap.file(path,logical+'/'+name)
    need(metadata(before)==metadata(root.lstat()) and names==sorted(p.name for p in root.iterdir()),
         'global controls changed during capture')
    return {'path':str(root),'metadata':metadata(before),'names':names,
        'old_run_directories_inventory_hashed_not_recopied':skipped}


def compare_inventory(C,LATE,left,right):
    need(LATE.inventory_value(left)==LATE.inventory_value(right),
         'original complete cumulative inventory changed during capture')


PROGRESS={'stage':'source-plan-validation','absence_censuses':{}}


def validate_capture_plan(a,source,plan_raw):
    need(type(source) is bytes and type(plan_raw) is bytes,'explicit raw source and plan required')
    need(digest(source)['sha256']==a.source_sha256 and digest(plan_raw)['sha256']==a.plan_sha256,
         'raw source or plan pin differs')
    plan=strict(plan_raw)
    need(set(plan)=={'schema','state','label','nonce','boot_id','phone_home','phone_output',
        'lease','package','combination','owner_request_sha256','native_prior_boundary_sha256',
        'root_plan','root_failure','source','dependencies','native_submissions','ui_actions',
        'signals','automatic_retry'},'exact capture plan field set required')
    need(plan['schema']=='hepta.native-guard.non-native-capture-plan.v1'
        and plan['state']=='ROOT_REVIEWABLE_READONLY_FAILED_ATTEMPT_CAPTURE'
        and plan['label']==LABEL and plan['nonce']==NONCE and plan['boot_id']==BOOT
        and plan['phone_home']==str(HOME) and plan['phone_output']==str(OUT)
        and plan['lease']==LEASE and plan['package']==PACKAGE and plan['combination']==COMBINATION
        and plan['owner_request_sha256']==OWNER
        and plan['native_prior_boundary_sha256']==PRIOR_BOUNDARY
        and plan['root_plan']==ROOT_PLAN_DESCRIPTOR and plan['root_failure']==ROOT_FAILURE_DESCRIPTOR
        and plan['source']==digest(source) and plan['dependencies']==DEPENDENCIES
        and all(type(plan[k]) is int and plan[k]==0 for k in ('native_submissions','ui_actions','signals'))
        and plan['automatic_retry'] is False,'only this fixed ended no-Send diag02 is allowed')
    return plan


def inventory_reader(C,L):
    """New observer implementation, not a claim that the old eight-fixture body ran."""
    raw=raw_source(HOME/'package/source/component_lifecycle.py',DEPENDENCIES['component_lifecycle'])
    text=raw.decode('utf-8');tree=ast.parse(text)
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='inventory']
    need(len(nodes)==1 and not nodes[0].decorator_list,'one fixed original inventory function required')
    original=ast.get_source_segment(text,nodes[0])+'\n'
    need(digest(original.encode())==INVENTORY_ORIGINAL,'original inventory fragment differs')
    old='len(fixture_roots)<=8';new='len(fixture_roots)<=9'
    need(original.count(old)==1,'only the exact fixture-count literal is adapted')
    adapted=original.replace(old,new)
    need(digest(adapted.encode())==INVENTORY_CURRENT and adapted.replace(new,old)==original,
         'current observer inventory body differs')
    namespace={'__name__':'diag02_nonsend_current_inventory_reader','__file__':'<current-diag02-capture-inventory>',
        'Path':Path,'re':re,'time':time,'stat':stat,'errno':errno,'need':C.need,'metadata':C.metadata,
        'read':C.read,'descriptor':C.descriptor,'fixture_absence':L.fixture_absence}
    exec(compile(adapted,'<current-diag02-capture-inventory>','exec'),namespace)
    provenance={'schema':'hepta.diag02.fixed-nine-fixture-inventory-reader.v1',
        'historical_runtime_source':DEPENDENCIES['component_lifecycle'],
        'original_function':INVENTORY_ORIGINAL,'current_function':INVENTORY_CURRENT,
        'current_implementation_owner':'this exact pinned capture source',
        'original_runtime_module_modified':False,'historical_runtime_function_claimed_unchanged':False,
        'fixture_roots_limit':9,'exact_expected_roots':EXPECTED_ROOTS,'expected_root_count':33,
        'expected_fixture_count':9,'entry_limit':30000,'per_file_bytes':67108864,
        'total_file_bytes':536870912,'per_inventory_seconds':30}
    return namespace['inventory'],provenance,original.encode(),adapted.encode()


def observed_absence(C,identities,key):
    """Preserve the fixed common predicate and zero-signal ESRCH gate, plus failure context."""
    C.need(1<=len(identities)<=64 and all(len(x)==4 and all(type(n) is int and n>1
        for n in x) and x[0]==x[1]==x[2] for x in identities),'owned-session identities required')
    ids={x[0] for x in identities};expected={x[0]:x for x in identities}
    context={'expected_identities':identities,'numeric_pids':None,'members':[],
        'kernel_queries':[],'census_complete':False,'kernel_group_absence':None,
        'signal_number':0,'signals_delivered':0}
    PROGRESS['absence_censuses'][key]=context
    names=[n for n in os.listdir('/proc') if n.isdecimal()]
    context['numeric_pids']=len(names);C.need(len(names)<=4096,'proc census PID bound')
    members=context['members'];deadline=time.monotonic()+2
    for name in names:
        C.need(time.monotonic()<deadline,'proc census deadline exceeded; absence unknown')
        row=C.proc_stat(int(name),census=True)
        if row is None:continue
        if ((row['pid'] in expected and C.generation(row)==expected[row['pid']])
            or row['pgid'] in ids or row['sid'] in ids):members.append(row)
    context['census_complete']=True
    C.need(not members,'owned group/session still observed')
    for pid in sorted(ids):
        query={'pgid':pid,'signal':0,'errno':None,'syscall_returned':False}
        context['kernel_queries'].append(query)
        try:os.kill(-pid,0)
        except OSError as error:
            query['errno']=error.errno
            C.need(error.errno==errno.ESRCH,'group absence unknown')
        else:
            query['syscall_returned']=True
            C.need(False,'kernel still observes owned group')
    context['kernel_group_absence']=True
    # Keep the exact four-field observation accepted by the historical pure absence verifier.
    return {'numeric_pids':len(names),'members':[],'kernel_group_absence':True,
        'observed_monotonic_ns':time.monotonic_ns()}


def fixed_roles_and_endpoints(C,S,home,phase):
    ended=C.strict(C.read(home/'LIFECYCLE-ENDED.json'))
    C.need(ended.get('schema')=='hepta.native-guard.lifecycle-ended.v1'
        and ended.get('roles_joined_and_groups_absent') is True
        and ended.get('model_requests')==0 and ended.get('automatic_restart') is False,
        'independent lifecycle exit/join originals required before capture')
    supervisor=C.strict(C.read(home/'SUPERVISOR.json'))
    roles={'supervisor':supervisor['identity']}
    for name in ('provider','sidecar'):
        spawned=C.strict(C.read(home/(name+'.SPAWNED.json')))
        roles[name]=spawned['identity'];original=ended['roles'][name]
        C.need(original.get('child_wait_returned') is True and original.get('dedicated_process_group_absent') is True,
            'component owned child lacks actual join')
        C.need(original==C.strict(C.read(home/(name+'.JOINED.json')))
            and original.get('identity')==roles[name] and original.get('role')==name,
            'lifecycle join differs from original owned generation receipt')
    C.need(roles==CURRENT_ROLES,'actual three diag02 generations differ')
    observations=[observed_absence(C,list(roles.values()),phase+'-current-'+str(i)) for i in range(2)]
    tables,endpoint=S.endpoint_absence()
    return {'schema':'hepta.native-guard.after-role-observation.v1','roles':roles,
        'original_lifecycle_ended_sha256':C.sha(C.read(home/'LIFECYCLE-ENDED.json')),
        'absence_observations':observations,**endpoint,'model_requests':0,
        'native_turn_verified':False,'component_qualified':False},tables


def execute(a):
    source=globals().get('__capture_source_original__');plan_raw=globals().get('__capture_plan_original__')
    plan=validate_capture_plan(a,source,plan_raw)
    need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'existing timer must not be replaced')
    old=signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('75-second capture bound')))
    signal.alarm(75);cap=None;created=False
    try:
        PROGRESS['stage']='pinned-modules-and-expired-original-lease'
        mods=load_modules();C=mods['component_common'];L=mods['component_lifecycle']
        S=mods['component_snapshot'];LATE=mods['late_boundary']
        own=L.native_root(BOOT)
        lease,lease_raw=L.load_lease(HOME,LEASE['sha256'],require_live=False)
        need(digest(lease_raw)==LEASE and lease['label']==LABEL and lease['nonce']==NONCE
            and lease['owner_request_sha256']==OWNER and lease['package_sha256']==PACKAGE['sha256']
            and lease['combination']==COMBINATION and lease['prior_boundary']==PRIOR_DESCRIPTOR,
            'actual ended lease or fixed6077 predecessor differs')
        need(int(time.time()*1000)>lease['expires_unix_ms'],'expired original lease required; never extend it')
        C.verify_package(HOME/'package/MANIFEST.json',PACKAGE['sha256'])
        combination_raw=C.pinned(HOME/'inputs/COMBINATION.json',COMBINATION)
        combo,_=C.load_combination(HOME/'inputs',combination_raw,
            C.strict(C.read(HOME/'package/reference/REVIEWED-PRODUCTION-PINS.json')))
        need(combo['live_policy_sha256']==POLICY,'fixed adopted policy differs')
        bound_raw=C.read(HOME/'BOUND-CONTRACT.json',65536);bound=C.strict(bound_raw)
        need(bound['lease_sha256']==LEASE['sha256'] and bound['contract']['nonce']==NONCE
            and bound['contract']['owner_request_sha256']==OWNER
            and re.fullmatch(r'[0-9]{8}-[0-9]{6}-'+NONCE,bound['run_basename']),
            'actual ready-but-not-accepted sidecar bound contract differs')
        fixture=C.ANDROID/'data/local/tmp'/('hepta-native-guard-'+NONCE)
        roots=list(dict.fromkeys(S.inventory_roots(HOME,lease)+[fixture]))
        fixtures=[p for p in roots if re.fullmatch(r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}',str(p))]
        need(list(map(str,roots))==EXPECTED_ROOTS and len(roots)==33 and len(fixtures)==9,
            'exact prior30 plus currentthree complete roots required')
        need(all(OUT!=p and p not in OUT.parents and OUT not in p.parents for p in roots),
            'capture output overlaps original inventory')
        inventory,inventory_provenance,inventory_original,inventory_current=inventory_reader(C,L)
        # Only these new owned evidence paths are written. The target home, lease and roots remain immutable.
        C.private_dir(OUT.parent);C.private_dir(OUT,create=True);created=True
        cap=S.Capture(OUT/'snapshot')
        cap.save('provenance/CAPTURE-SOURCE.original.py',source)
        cap.save('provenance/CAPTURE-PLAN.original.json',plan_raw)
        cap.save('provenance/INVENTORY-ORIGINAL-FUNCTION.py',inventory_original)
        cap.save('provenance/INVENTORY-CURRENT-FUNCTION.py',inventory_current)
        cap.save('provenance/INVENTORY-READER.json',C.encoded(inventory_provenance))
        PROGRESS['stage']='current-eight-artifacts-environment-before'
        external_before=C.verify_external(combo)
        PROGRESS['stage']='current-roles-and-endpoints-before'
        after_roles,tables=fixed_roles_and_endpoints(C,S,HOME,'before')
        PROGRESS['stage']='pre-accept-claims-run-fixture-absence'
        paths=[HOME/name for name in ('CONNECTION-ACCEPTED.json','ACCEPTED.json','PROVIDER-ENDED.json',
            'LIFECYCLE-FAILURE.json','ROOT-SETUP-PLAN.json','ROOT-SETUP-RESULT.json')]
        paths.append(C.COMPONENT_EVIDENCE/bound['run_basename'])
        missing=[original_absence(C,p) for p in paths];claims=check_empty_claims(C)
        fixture_before=L.fixture_absence(fixture)
        PROGRESS['stage']='fixed-seven-native-history-and-original05'
        chain,chain_originals=LATE.chain_originals(lease['prior_boundary'],
            combination_sha256=COMBINATION['sha256'],package_sha256=PACKAGE['sha256'],
            boot_id=BOOT,retirement=lease['retirement'])
        need(len(chain)==7,'exact seven original native ancestors required')
        retired,old_roles=LATE.retired_originals(lease['retirement'],BOOT)
        sidebranch=LATE.non_native_sidebranch(phone_originals=True)
        component_roles=list(after_roles['roles'].values())+list(sidebranch['binding']['component_role_identities'].values())
        for value,_inv,_closed in chain:component_roles.extend(value['component_role_identities'].values())
        need(len(component_roles)==27 and len({tuple(x) for x in component_roles})==27,
            'seven native plus05 plus current must preserve27 unique role generations')
        role_identities=component_roles+old_roles
        need(len(old_roles)==4 and len(role_identities)==31 and len({tuple(x) for x in role_identities})==31,
            'all27 component and originalfour production role identities required')
        PROGRESS['stage']='all31-generations-absence-before'
        all_absence_before=[observed_absence(C,role_identities,'before-all-'+str(i)) for i in range(2)]
        PROGRESS['stage']='complete33-root-inventory-before'
        before=inventory(roots,fixture_roots=fixtures)
        PROGRESS['stage']='copy-current-home-executor-and-global-controls'
        cap.tree(HOME,'home');journal=C.ANDROID/lease['android_journal'].lstrip('/')
        cap.tree(journal,'executor')
        controls=[capture_controls(C,cap,p,'controls/'+name)
            for name,p in (('production',C.PRODUCTION_EVIDENCE),('component',C.COMPONENT_EVIDENCE))]
        for key,row in lease['retirement'].items():cap.file(row['path'],'retirement/'+key+'.original')
        cap.file(lease['prior_boundary']['path'],'retirement/prior-boundary.original.json')
        S.capture_boundary_chain(cap,lease)
        # The complete immutable05 proof/closure/inventory remain an independent non-native sidebranch.
        prefix='non-native-sidebranch/'+sidebranch['binding']['nonce']+'/'
        for key,filename in LATE.NON_NATIVE_CAPTURE_FILES.items():
            row=sidebranch['binding'][key];body=cap.file(row['path'],prefix+filename)
            need(body==sidebranch['raw'][key] and cap.files[prefix+filename]['source_metadata']==row['metadata'],
                'original05 sidebranch raw or full9 differs')
        LATE.recheck_originals(sidebranch['originals'])
        cap.save('observation/NON-NATIVE-SIDEBRANCH.json',C.encoded({'binding':sidebranch['binding'],
            'originals':sidebranch['originals'],'native_case_count':0,'component_qualified':False}))
        PROGRESS['stage']='complete-bounded-native-nonce-and-owner-absence'
        native=native_nonce_absence(C,cap,NATIVE)
        PROGRESS['stage']='complete33-root-inventory-after'
        after=inventory(roots,fixture_roots=fixtures);compare_inventory(C,LATE,before,after)
        PROGRESS['stage']='current-roles-and-endpoints-after'
        roles_again,tables_again=fixed_roles_and_endpoints(C,S,HOME,'after')
        need(roles_again['roles']==after_roles['roles']
            and roles_again['original_lifecycle_ended_sha256']==after_roles['original_lifecycle_ended_sha256'],
            'actual lifecycle originals changed after capture')
        PROGRESS['stage']='all31-generations-absence-after'
        all_absence_after=[observed_absence(C,role_identities,'after-all-'+str(i)) for i in range(2)]
        for old_row,path in zip(missing,paths):
            new_row=original_absence(C,path)
            need({k:old_row[k] for k in ('path','absence','parent_path','parent_metadata','parent_names')}==
                {k:new_row[k] for k in ('path','absence','parent_path','parent_metadata','parent_names')},
                'pre-accept absence observation changed')
        need(check_empty_claims(C)==claims,'original one-use claims changed')
        fixture_after=L.fixture_absence(fixture)
        need(fixture_after['canonical_parent_identity']==fixture_before['canonical_parent_identity'],
            'fixture absence identity changed')
        PROGRESS['stage']='current-eight-artifacts-environment-after'
        external_after=C.verify_external(combo);own_after=L.native_root(BOOT)
        need(external_before==external_after and own_after['identity']==own['identity'],
            'current artifact or observer identity changed across capture')
        LATE.recheck_originals(chain_originals+list(lease['retirement'].values())+sidebranch['originals'])
        cap.save('before/BEFORE-INVENTORY.json',C.encoded(before))
        cap.save('after/AFTER-INVENTORY.json',C.encoded(after))
        cap.save('observation/NATIVE-NONCE-ABSENCE.json',C.encoded(native))
        cap.save('observation/PRE-NATIVE-ABSENCES.json',C.encoded({
            'schema':'hepta.native-guard.pre-native-absence-set.v1','nonce':NONCE,
            'paths':missing,'claims':claims,'fixture_before':fixture_before,'fixture_after':fixture_after}))
        cap.save('observation/AFTER-ROLES.json',C.encoded({
            'schema':'hepta.native-guard.non-native-after-roles.v1','first':after_roles,'last':roles_again,
            'all_actual_and_historical_generations':role_identities,
            'component_role_generations':component_roles,'original_production_generations':old_roles,
            'component_role_count':27,'current_frozen_role_cap':30,'role_cap_changed':False,
            'all_groups_absent_before':all_absence_before,'all_groups_absent_after':all_absence_after,
            'component_qualified':False,'native_scope_assigned':False}))
        cap.save('observation/ENVIRONMENT-EXTERNAL-BOOKENDS.json',C.encoded({
            'boot_id':BOOT,'runtime_policy_sha256':POLICY,'policy_verified_before_and_after':True,
            'selinux_enforcing_before_and_after':True,'external_before':external_before,
            'external_after':external_after,'observer_before':own,'observer_after':own_after,
            'expired_original_lease_preserved':True,'lease_extended':False}))
        for prefix,values in (('before',tables),('after',tables_again)):
            for name,raw in values.items():cap.save('observation/'+prefix+'-proc-net-'+name+'.original',raw)
        cap.save('observation/GLOBAL-CONTROL-NAMES.json',C.encoded(controls))
        cap.save('observation/ABSENCE-CENSUS-DETAILS.json',C.encoded(PROGRESS['absence_censuses']))
        PROGRESS['stage']='final-original-bookends-and-archive'
        cap.recheck()
        report={'schema':'hepta.native-guard.non-native-original-capture.v2',
            'state':'ORIGINAL_PRE_NATIVE_FAILURE_BYTES_CAPTURED_NOT_CLOSED',
            'scope_profile':'diag02_ready_observed_no_send','label':LABEL,'nonce':NONCE,
            'boot_id':BOOT,'owner_request_sha256':OWNER,'lease':LEASE,'package':PACKAGE,
            'combination':COMBINATION,'native_prior_boundary':lease['prior_boundary'],
            'retirement_proof_sha256':lease['retirement']['proof']['sha256'],
            'capture_source':digest(source),'capture_plan':digest(plan_raw),
            'root_plan':plan['root_plan'],'root_failure':plan['root_failure'],
            'observer_identity':own,'files':cap.files,'directories':cap.directories,
            'retained_bytes':cap.total,'inventory_roots':list(map(str,roots)),
            'component_role_identities':after_roles['roles'],'component_role_count':27,
            'historical_native_count':7,'previous_non_native_count':1,'inventory_reader':inventory_provenance,
            'native_nonce_absence':digest(C.encoded(native)),'native_scope_assigned':False,
            'native_case_created':False,'capture_is_closure':False,'component_qualified':False,
            'business_qualified':False,'global_unknown_effect_count':None,
            'capture_operations':{'ui_actions':0,'signals':0,'service_launches':0,
                'native_submissions':0,'model_requests':0,'socket_connections':0,
                'source_original_writes':0,'kernel_signal_zero_queries_only':True},
            'automatic_retry':False,'original_sender_and_restore_must_be_verified_independently':True,
            'original_host_sender_wait_claimed':False,'original_supervisor_wait_claimed':False}
        report_raw=C.encoded(report)
        need(len(report_raw)<=S.MAX_FILE and cap.total+len(report_raw)<=S.MAX_BYTES,
            'capture manifest exceeds existing byte bounds')
        C.put(OUT/'CAPTURE.json',report_raw);C.put(cap.destination/'CAPTURE.json',report_raw)
        archive=S.make_archive(cap.destination,{**cap.files,'CAPTURE.json':C.descriptor(report_raw)})
        C.put(OUT/'ORIGINALS.tar.gz',archive)
        result={'schema':'hepta.native-guard.non-native-snapshot-result.v2',
            'state':'ORIGINAL_PRE_NATIVE_CAPTURE_ARCHIVED_NOT_CLOSED','scope_profile':'diag02_ready_observed_no_send',
            'label':LABEL,'nonce':NONCE,'capture':digest(report_raw),'archive':digest(archive),
            'capture_path':str(OUT/'CAPTURE.json'),'archive_path':str(OUT/'ORIGINALS.tar.gz'),
            'capture_source':digest(source),'capture_plan':digest(plan_raw),
            'archive_members':len(cap.files)+1,'component_qualified':False,'native_case_created':False,
            'native_submissions':0,'automatic_retry':False,'component_role_count':27,
            'global_unknown_effect_count':None}
        C.put(OUT/'RESULT.json',result);print(C.encoded(result).decode(),end='');return 0
    except BaseException as error:
        partial={'schema':'hepta.diag02.non-native-capture-gap.v1','state':'OBSERVED_NOT_CLOSED',
            'label':LABEL,'nonce':NONCE,'error_type':type(error).__name__,'detail':str(error)[:1024],
            'progress':PROGRESS,'files':{} if cap is None else cap.files,
            'component_qualified':False,'native_case_created':False,'global_unknown_effect_count':None,
            'original_host_sender_wait_claimed':False,'original_supervisor_wait_claimed':False,
            'automatic_retry':False,'target_original_writes':0}
        body=encoded(partial)
        if len(body)>16*1024*1024:
            body=encoded({'schema':partial['schema'],'state':'OBSERVED_NOT_CLOSED_OUTPUT_BOUND',
                'stage':PROGRESS['stage'],'original_report_retained':False,
                'global_unknown_effect_count':None,'native_case_created':False})
        if created:C.put(OUT/'PARTIAL-CAPTURE.json',body)
        print(body.decode(),end='');return 2
    finally:
        signal.alarm(0);signal.signal(signal.SIGALRM,old)


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source-sha256',required=True)
    p.add_argument('--plan-sha256',required=True)
    p.add_argument('--execute-readonly-capture-once',action='store_true')
    a=p.parse_args()
    if not a.execute_readonly_capture_once:
        print(json.dumps({'state':'PREVIEW_ONLY','phone_reads':0,'phone_writes':0,
            'native_submissions':0,'nonce_generated':False,'out':str(OUT)},sort_keys=True))
        return 0
    return execute(a)


if __name__=='__main__':raise SystemExit(main())
