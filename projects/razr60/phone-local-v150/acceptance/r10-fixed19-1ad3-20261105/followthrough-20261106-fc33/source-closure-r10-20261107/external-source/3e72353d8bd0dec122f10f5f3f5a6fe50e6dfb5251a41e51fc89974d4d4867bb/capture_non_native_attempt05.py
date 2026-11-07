#!/usr/bin/env python3
"""One fixed ended attempt05: read originals, never start a native task.

Only a fresh capture directory and its evidence files are written. The native
chain remains actual04 -> external03. No native scope or terminal is invented.
"""
import argparse
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
LABEL='root-r10-neg01-20261105-05'
NONCE='e4c3ccb0b2d706be3b7bf105ae772405'
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
HOME=BASE/'native-guard-r10-r1'/LABEL
OUT=BASE/'native-guard-snapshots-r10-r1'/(LABEL+'-non-native-capture-01')
NATIVE=Path('/var/lib/trillionnium/owner-open/turn-events.jsonl.segments')
OWNER='592b45a023fe54fe085d2ee91aa7d11b4c6d52a66d19e353001a38acf1c10079'
PACKAGE={'bytes':6253,'sha256':'9c2e08ce171d8212b5f21abbc97ded5ba2fb578e221a8579db8aef3568ff969e'}
LEASE={'bytes':2496,'sha256':'4420765e2968387b861e938726349e17e18d798fd2e11c5deaa46ee57f2f0541'}
COMBINATION={'bytes':4702,'sha256':'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'}
PRIOR_BOUNDARY='3216ab18adcafa0dda95e8a93ad35a2070e7aec286d7a518794918068ce31d12'
ROOT_PLAN={'bytes':4737,'sha256':'30f50baff1418464d6abef24744f61ba88de927185208679a3a19cb3dbfa62f6'}
ROOT_FAILURE={'bytes':10082,'sha256':'ae8f5bc9d8897c561adcc901b93e1fd12e997afe655eeb0de44eb32a7263f857'}
DEPENDENCIES={
 'component_common':{'bytes':18133,'sha256':'8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02'},
 'native_proc_profile':{'bytes':4633,'sha256':'12719e58d2e3e1a1e86b8a6a9dc9587e37bfcb36c4c3b26b023138752bb3e67b'},
 'component_lifecycle':{'bytes':35636,'sha256':'e3569cc0bef630d4a19ed799e7e67f22bfc416fb7ab5c62787b3df563f9c0448'},
 'component_snapshot':{'bytes':22184,'sha256':'c33334cf96847d1ad1ba2da45f5d66158c747b7cd1d64f027d9a1642ef7831ba'},
 'late_boundary':{'bytes':43089,'sha256':'e4146ccbd854c1f2d2b7a2a6a4ab8c4686af0bc45298590132e48817bee9e1dc'}}
MAX_NATIVE_FILE=64*1024*1024
MAX_NATIVE_TOTAL=128*1024*1024
MAX_LINE=4*1024*1024


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


def execute(a):
    source=globals().get('__capture_source_original__')
    plan_raw=globals().get('__capture_plan_original__')
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
        and {k:plan['root_plan'][k] for k in ('bytes','sha256')}==ROOT_PLAN
        and {k:plan['root_failure'][k] for k in ('bytes','sha256')}==ROOT_FAILURE
        and plan['source']==digest(source) and plan['dependencies']==DEPENDENCIES
        and all(type(plan[k]) is int and plan[k]==0 for k in ('native_submissions','ui_actions','signals'))
        and plan['automatic_retry'] is False,'only the fixed ended failed attempt05 is allowed')
    need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'existing timer must not be replaced')
    old=signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('75-second capture bound')))
    signal.alarm(75);cap=None
    try:
        mods=load_modules();C=mods['component_common'];L=mods['component_lifecycle']
        S=mods['component_snapshot'];LATE=mods['late_boundary']
        own=L.native_root(BOOT)
        lease,lease_raw=L.load_lease(HOME,LEASE['sha256'],require_live=False)
        need(digest(lease_raw)==LEASE and lease['label']==LABEL and lease['nonce']==NONCE
            and lease['owner_request_sha256']==OWNER and lease['package_sha256']==PACKAGE['sha256']
            and lease['combination']==COMBINATION
            and lease['prior_boundary']['sha256']==PRIOR_BOUNDARY,'actual ended lease differs')
        C.verify_package(HOME/'package/MANIFEST.json',PACKAGE['sha256'])
        combination_raw=C.pinned(HOME/'inputs/COMBINATION.json',COMBINATION)
        C.load_combination(HOME/'inputs',combination_raw,
            C.strict(C.read(HOME/'package/reference/REVIEWED-PRODUCTION-PINS.json')))
        # Do not call verify_external here: this capture does not execute the runtime.
        # The actual adopted policy remains independently bound by the Root plan.
        bound_raw=C.read(HOME/'BOUND-CONTRACT.json',65536);bound=C.strict(bound_raw)
        need(bound['lease_sha256']==LEASE['sha256'] and
            bound['contract']['nonce']==NONCE and bound['contract']['owner_request_sha256']==OWNER
            and re.fullmatch(r'[0-9]{8}-[0-9]{6}-'+NONCE,bound['run_basename']),
            'actual pre-native sidecar bound contract differs')
        after_roles,tables=S.verify_role_end(HOME)
        paths=[HOME/name for name in ('READY.json','CONNECTION-ACCEPTED.json','ACCEPTED.json',
            'PROVIDER-HEALTH.original.json','PROVIDER-ENDED.json')]
        paths.append(C.COMPONENT_EVIDENCE/bound['run_basename'])
        missing=[original_absence(C,p) for p in paths]
        claims=check_empty_claims(C)
        fixture=C.ANDROID/'data/local/tmp'/('hepta-native-guard-'+NONCE)
        fixture_before=L.fixture_absence(fixture)
        roots=list(dict.fromkeys(S.inventory_roots(HOME,lease)+[fixture]))
        fixtures=[p for p in roots if re.fullmatch(
            r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}',str(p))]
        need(all(OUT!=p and p not in OUT.parents and OUT not in p.parents for p in roots),
             'capture output overlaps original inventory')
        # Keep the actual native chain separate; it contains no invented attempt05 scope.
        chain,chain_originals=LATE.chain_originals(lease['prior_boundary'],
            combination_sha256=COMBINATION['sha256'],package_sha256=PACKAGE['sha256'],
            boot_id=BOOT,retirement=lease['retirement'])
        retired,old_roles=LATE.retired_originals(lease['retirement'],BOOT)
        role_identities=list(after_roles['roles'].values())+old_roles
        for value,_inv,_closed in chain:role_identities.extend(value['component_role_identities'].values())
        need(len({tuple(row) for row in role_identities})==len(role_identities),'old/current generation repeats')
        all_absence_before=[C.absent_groups(role_identities),C.absent_groups(role_identities)]
        before=L.inventory(roots,fixture_roots=fixtures)
        C.private_dir(OUT.parent);C.private_dir(OUT,create=True)
        cap=S.Capture(OUT/'snapshot')
        cap.save('provenance/CAPTURE-SOURCE.original.py',source)
        cap.save('provenance/CAPTURE-PLAN.original.json',plan_raw)
        cap.tree(HOME,'home')
        journal=C.ANDROID/lease['android_journal'].lstrip('/')
        cap.tree(journal,'executor')
        controls=[capture_controls(C,cap,p,'controls/'+name)
            for name,p in (('production',C.PRODUCTION_EVIDENCE),('component',C.COMPONENT_EVIDENCE))]
        for key,row in lease['retirement'].items():cap.file(row['path'],'retirement/'+key+'.original')
        cap.file(lease['prior_boundary']['path'],'retirement/prior-boundary.original.json')
        S.capture_boundary_chain(cap,lease)
        native=native_nonce_absence(C,cap,NATIVE)
        after=L.inventory(roots,fixture_roots=fixtures)
        compare_inventory(C,LATE,before,after)
        roles_again,tables_again=S.verify_role_end(HOME)
        need(roles_again['roles']==after_roles['roles']
            and roles_again['original_lifecycle_ended_sha256']==after_roles['original_lifecycle_ended_sha256'],
            'actual lifecycle originals changed after capture')
        all_absence_after=[C.absent_groups(role_identities),C.absent_groups(role_identities)]
        for old_row,path in zip(missing,paths):
            new_row=original_absence(C,path)
            need({k:old_row[k] for k in ('path','absence','parent_path','parent_metadata','parent_names')}==
                {k:new_row[k] for k in ('path','absence','parent_path','parent_metadata','parent_names')},
                'pre-native absence observation changed')
        need(check_empty_claims(C)==claims,'original one-use claims changed')
        fixture_after=L.fixture_absence(fixture)
        need(fixture_after['canonical_parent_identity']==fixture_before['canonical_parent_identity'],
             'fixture absence identity changed')
        LATE.recheck_originals(chain_originals+list(lease['retirement'].values()))
        cap.save('before/BEFORE-INVENTORY.json',C.encoded(before))
        cap.save('after/AFTER-INVENTORY.json',C.encoded(after))
        cap.save('observation/NATIVE-NONCE-ABSENCE.json',C.encoded(native))
        cap.save('observation/PRE-NATIVE-ABSENCES.json',C.encoded({
            'schema':'hepta.native-guard.pre-native-absence-set.v1','nonce':NONCE,
            'paths':missing,'claims':claims,'fixture_before':fixture_before,'fixture_after':fixture_after}))
        cap.save('observation/AFTER-ROLES.json',C.encoded({
            'schema':'hepta.native-guard.non-native-after-roles.v1','first':after_roles,'last':roles_again,
            'all_actual_and_historical_generations':role_identities,
            'all_groups_absent_before':all_absence_before,'all_groups_absent_after':all_absence_after,
            'component_qualified':False,'native_scope_assigned':False}))
        for prefix,values in (('before',tables),('after',tables_again)):
            for name,raw in values.items():cap.save('observation/'+prefix+'-proc-net-'+name+'.original',raw)
        cap.save('observation/GLOBAL-CONTROL-NAMES.json',C.encoded(controls))
        cap.recheck()
        report={'schema':'hepta.native-guard.non-native-original-capture.v1',
            'state':'ORIGINAL_PRE_NATIVE_FAILURE_BYTES_CAPTURED_NOT_CLOSED',
            'label':LABEL,'nonce':NONCE,'boot_id':BOOT,'owner_request_sha256':OWNER,
            'lease':LEASE,'package':PACKAGE,'combination':COMBINATION,
            'native_prior_boundary':lease['prior_boundary'],
            'retirement_proof_sha256':lease['retirement']['proof']['sha256'],
            'capture_source':digest(source),'capture_plan':digest(plan_raw),
            'root_plan':plan['root_plan'],'root_failure':plan['root_failure'],
            'observer_identity':own,'files':cap.files,'directories':cap.directories,
            'retained_bytes':cap.total,'inventory_roots':list(map(str,roots)),
            'component_role_identities':after_roles['roles'],
            'native_nonce_absence':digest(C.encoded(native)),
            'native_scope_assigned':False,'native_case_created':False,
            'capture_is_closure':False,'component_qualified':False,'business_qualified':False,
            'capture_operations':{'ui_actions':0,'signals':0,'service_launches':0,
                'native_submissions':0,'model_requests':0,'socket_connections':0,
                'source_original_writes':0},
            'automatic_retry':False,
            'original_sender_and_restore_must_be_verified_independently':True}
        report_raw=C.encoded(report)
        need(len(report_raw)<=S.MAX_FILE and cap.total+len(report_raw)<=S.MAX_BYTES,
             'capture manifest exceeds existing byte bounds')
        C.put(OUT/'CAPTURE.json',report_raw);C.put(cap.destination/'CAPTURE.json',report_raw)
        archive=S.make_archive(cap.destination,{**cap.files,'CAPTURE.json':C.descriptor(report_raw)})
        C.put(OUT/'ORIGINALS.tar.gz',archive)
        result={'schema':'hepta.native-guard.non-native-snapshot-result.v1',
            'state':'ORIGINAL_PRE_NATIVE_CAPTURE_ARCHIVED_NOT_CLOSED','label':LABEL,'nonce':NONCE,
            'capture':digest(report_raw),'archive':digest(archive),
            'capture_path':str(OUT/'CAPTURE.json'),'archive_path':str(OUT/'ORIGINALS.tar.gz'),
            'capture_source':digest(source),'capture_plan':digest(plan_raw),
            'archive_members':len(cap.files)+1,'component_qualified':False,
            'native_case_created':False,'native_submissions':0,'automatic_retry':False}
        C.put(OUT/'RESULT.json',result)
        print(C.encoded(result).decode(),end='')
        return 0
    except BaseException as error:
        if cap is not None:
            C.put(OUT/'PARTIAL-CAPTURE.json',{'schema':'hepta.native-guard.non-native-partial-capture.v1',
                'state':'PARTIAL_ORIGINALS_PRESERVED_NOT_CLOSED','error_type':type(error).__name__,
                'detail':str(error)[:1024],'files':cap.files,'component_qualified':False,
                'native_case_created':False,'automatic_retry':False})
        raise
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
