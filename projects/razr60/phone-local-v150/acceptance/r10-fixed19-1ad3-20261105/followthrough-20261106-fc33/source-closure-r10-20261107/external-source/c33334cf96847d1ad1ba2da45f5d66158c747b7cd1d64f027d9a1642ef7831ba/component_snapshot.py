#!/usr/bin/env python3
"""Capture an ended isolated component's actual originals, without executing it.

This explicit Root entry writes only a fresh private capture directory/archive.
It never connects to a provider/sidecar, sends UI input, restarts a process,
submits a task or makes a model request. A capture is evidence, not qualification.
"""
import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import signal
import stat
import sys
import tarfile
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
import component_common as C
import component_lifecycle as LIFE

NATIVE=Path('/var/lib/trillionnium/owner-open/turn-events.jsonl.segments')
MAX_BYTES=64*1024*1024
MAX_FILE=16*1024*1024
MAX_FILES=8192
MAX_SCAN=128*1024*1024
MAX_LINE=4*1024*1024


class Capture:
    def __init__(self,destination):
        self.destination=C.private_dir(destination,create=True)
        self.files={};self.directories={};self.originals={};self.total=0
        self.deadline=time.monotonic()+55

    def check(self):
        C.need(time.monotonic()<self.deadline,'original capture read deadline exceeded')
        C.need(len(self.files)<MAX_FILES,'original capture file count exceeded')

    def save(self,name,raw,*,origin=None):
        self.check();p=C.relative(name)
        C.need(name not in self.files and 0<=len(raw)<=MAX_FILE,'duplicate/oversized capture original')
        C.need(self.total+len(raw)<=MAX_BYTES,'capture retained byte limit')
        target=self.destination/p
        parent=self.destination
        for part in p.parts[:-1]:
            parent=parent/part
            try:C.private_dir(parent)
            except FileNotFoundError:C.private_dir(parent,create=True)
        C.put(target,raw);self.total+=len(raw)
        self.files[name]={'path':name,**C.descriptor(raw),
            'source_path':None if origin is None else origin['source_path'],
            'source_metadata':None if origin is None else origin['source_metadata'],
            'kind':'derived_read_observation' if origin is None else 'original_file_bytes'}

    def file(self,path,name,*,private=True,maximum=MAX_FILE):
        self.check();path=Path(path);before=path.lstat()
        raw=C.read(path,maximum,private=private)
        C.need(C.metadata(before)==C.metadata(path.lstat()),'original raced before capture copy')
        origin={'source_path':str(path),'source_metadata':C.metadata(before)}
        self.save(name,raw,origin=origin)
        self.originals[str(path)]={'metadata':C.metadata(before),**C.descriptor(raw)}
        return raw

    def tree(self,path,name,*,private=True,depth=0):
        self.check();C.need(depth<=12,'capture tree depth exceeded')
        path=Path(path);before=path.lstat()
        C.need(stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode),'capture original directory differs')
        if private:C.private_dir(path)
        names=sorted(p.name for p in path.iterdir());C.need(len(names)<=20000,'capture directory count')
        self.directories[str(path)]={'metadata':C.metadata(before),'names':names,'capture_path':name}
        for leaf in names:
            p=path/leaf;s=p.lstat()
            C.need(not stat.S_ISLNK(s.st_mode),'capture symlink is never followed')
            if stat.S_ISDIR(s.st_mode):self.tree(p,name+'/'+leaf,private=private,depth=depth+1)
            else:self.file(p,name+'/'+leaf,private=private)
        C.need(C.metadata(path.lstat())==C.metadata(before)
               and sorted(p.name for p in path.iterdir())==names,'original directory changed during capture')

    def recheck(self):
        for path,row in self.originals.items():
            self.check();p=Path(path)
            C.need(C.metadata(p.lstat())==row['metadata'],'captured original changed afterwards')
        for path,row in self.directories.items():
            self.check();p=Path(path)
            C.need(C.metadata(p.lstat())==row['metadata'] and sorted(q.name for q in p.iterdir())==row['names'],
                   'captured directory changed afterwards')


def bounded_proc(path,maximum=1024*1024):
    path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        C.need(stat.S_ISREG(os.fstat(fd).st_mode),'proc observation is not a regular pseudo-file')
        with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(maximum+1)
        C.need(len(raw)<=maximum,'proc observation byte bound')
        return raw
    finally:os.close(fd)


def endpoint_absence():
    raw={key:bounded_proc(path) for key,path in {
        'tcp':'/proc/net/tcp','tcp6':'/proc/net/tcp6','unix':'/proc/net/unix'}.items()}
    for key in ('tcp','tcp6'):
        lines=raw[key].splitlines();C.need(lines,'proc TCP table has no header')
        for line in lines[1:]:
            cols=line.split();C.need(len(cols)>=10,'proc TCP row incomplete')
            local=cols[1].rsplit(b':',1);C.need(len(local)==2,'proc TCP address differs')
            C.need(not (int(local[1],16)==18080 and cols[3]==b'0A'),'port 18080 still listening')
    for line in raw['unix'].splitlines()[1:]:
        cols=line.split();C.need(len(cols)>=7,'proc UNIX row incomplete')
        C.need(len(cols)==7 or cols[7] != ('@'+C.SOCKET_NAME).encode(),'component abstract socket still present')
    return raw,{'port_18080_listener_absent':True,'r6_abstract_endpoint_absent':True,
                'socket_connections':0,'observed_monotonic_ns':time.monotonic_ns()}


def native_capture(capture,scope):
    C.scope(scope);before=NATIVE.lstat()
    C.need(stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode),'native segment directory differs')
    names=sorted(p.name for p in NATIVE.iterdir());C.need(len(names)<=1024,'native segment count bound')
    files=[n for n in names if n.endswith('.jsonl')]
    C.need(files,'native original segment files absent')
    selected=[];sources=[];scanned=0
    for name in files:
        capture.check();p=NATIVE/name;s=p.lstat();data=C.read(p,64*1024*1024,private=False)
        C.need(C.metadata(s)==C.metadata(p.lstat()),'native segment generation changed')
        scanned+=len(data);C.need(scanned<=MAX_SCAN,'native full scan byte bound')
        source={'source_path':str(p),'source_metadata':C.metadata(s),**C.descriptor(data)};sources.append(source)
        capture.originals[str(p)]={'metadata':C.metadata(s),**C.descriptor(data)}
        offset=0
        for index,line in enumerate(data.splitlines(keepends=True),1):
            C.need(line.endswith(b'\n') and len(line)<=MAX_LINE,'incomplete/oversized native original line')
            value=C.strict(line)
            if value.get('scope')==scope:
                C.need(len(selected)<2048,'selected native record limit')
                selected.append((value,line,{'source_path':str(p),'line_1based':index,'offset':offset,
                    **C.descriptor(line),'store_seq':value.get('store_seq'),'turn_seq':value.get('turn_seq')}))
            offset+=len(line)
    C.need(C.metadata(NATIVE.lstat())==C.metadata(before)
           and sorted(p.name for p in NATIVE.iterdir())==names,'native segment set changed')
    capture.directories[str(NATIVE)]={'metadata':C.metadata(before),'names':names,'capture_path':None}
    C.need(selected and all(type(v[0].get('store_seq')) is int for v in selected),'selected native sequence absent')
    selected.sort(key=lambda x:x[0]['store_seq']);rows=[x[0] for x in selected]
    C.need(len({r['store_seq'] for r in rows})==len(rows)
           and [r.get('turn_seq') for r in rows]==list(range(len(rows)))
           and rows[0].get('kind')=='turn.accepted' and rows[-1].get('kind')=='turn.end',
           'selected native original lacks complete accepted/end sequence')
    capture.save('native/selected.jsonl',b''.join(x[1] for x in selected))
    capture.save('native/ORIGINS.json',C.encoded({'schema':'hepta.native-guard.native-original-origins.v1',
        'scope':scope,'sources':sources,'selected_lines':[x[2] for x in selected],
        'bytes_scanned':scanned,'global_chain_complete':False,
        'selection':'All five actual scope fields; original lines retained without reserialization.'}))
    return {'records':len(rows),'first_store_seq':rows[0]['store_seq'],'last_store_seq':rows[-1]['store_seq']}


def verify_role_end(home):
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
    observations=[C.absent_groups(list(roles.values())),C.absent_groups(list(roles.values()))]
    tables,endpoint=endpoint_absence()
    return {'schema':'hepta.native-guard.after-role-observation.v1','roles':roles,
        'original_lifecycle_ended_sha256':C.sha(C.read(home/'LIFECYCLE-ENDED.json')),
        'absence_observations':observations,**endpoint,'model_requests':0,
        'native_turn_verified':False,'component_qualified':False},tables


def inventory_roots(home,lease):
    # Production evidence includes its complete claims and action-ledger roots.
    # Their original files are also copied independently below for offline audit.
    current=[C.PRODUCTION_EVIDENCE,C.COMPONENT_EVIDENCE,C.BASE/'client-receipts',C.BASE/'executor-r6',
        C.BASE/'provider-state/health-contracts/bindings',C.BASE/'provider-state/task-contracts/bindings',
        C.ANDROID/lease['android_journal'].lstrip('/'),home]
    previous=[]
    if lease['prior_boundary'] is not None:
        row=lease['prior_boundary'];path=Path(row['path'])
        raw=C.pinned(path,{k:row[k] for k in ('bytes','sha256')},16*1024*1024)
        C.need(C.metadata(path.lstat())==row['metadata'],'prior boundary original metadata changed')
        import late_boundary as LATE
        value=LATE.boundary_from_original(raw,original_descriptor=row,
            combination_sha256=lease['combination']['sha256'],package_sha256=lease['package_sha256'])
        C.need(value['boot_id']==lease['boot_id'] and value['retirement']==lease['retirement'],
               'prior inventory boot/retirement changed')
        previous=list(map(Path,value['roots']))
        C.need(len(previous)<=64 and len(set(previous))==len(previous)
            and all(p.is_absolute() and '..' not in p.parts for p in previous),'prior cumulative roots differ')
    union=list(dict.fromkeys(previous+current))
    C.need(all(a==b or not (a in b.parents or b in a.parents) for a in union for b in union),
           'prior/current inventory roots unexpectedly overlap')
    return union


def capture_boundary_chain(capture,lease):
    import late_boundary as LATE
    row=lease['prior_boundary'];seen_nonce=set();seen_scope=set();values=[]
    while row is not None:
        capture.check();C.need(len(seen_nonce)<8,'closed component boundary chain count bound')
        C.need(set(row)=={'path','bytes','sha256','metadata'},'original boundary descriptor differs')
        path=Path(row['path']);raw=C.pinned(path,{k:row[k] for k in ('bytes','sha256')},MAX_FILE)
        C.need(C.metadata(path.lstat())==row['metadata'],'original boundary metadata changed')
        value=LATE.boundary_from_original(raw,original_descriptor=row,
            combination_sha256=lease['combination']['sha256'],package_sha256=lease['package_sha256'])
        nonce=value['nonce'];scope=C.scope(value['scope'])
        C.need(re.fullmatch('[0-9a-f]{32}',nonce) and nonce not in seen_nonce
            and tuple(scope[k] for k in C.SCOPE) not in seen_scope
            and path==C.BASE/'native-guard-boundaries-r10-r1'/(nonce+'.json'),
            'boundary chain identity repeated or path differs')
        C.need(value['boot_id']==lease['boot_id'] and value['retirement']==lease['retirement'],
               'prior closed boundary boot/retirement differs')
        seen_nonce.add(nonce);seen_scope.add(tuple(scope[k] for k in C.SCOPE))
        capture.file(path,'boundary-chain/'+nonce+'/BOUNDARY.original.json')
        originals={}
        for name,key in (('INVENTORY','inventory'),('CLOSURE','closure')):
            item=value[key];p=Path(item['path'])
            C.need(set(item)=={'path','bytes','sha256','metadata'} and
                p.parent==C.BASE/'native-guard-boundaries-r10-r1'/nonce,
                'closed boundary original left its private nonce directory')
            original=C.pinned(p,{k:item[k] for k in ('bytes','sha256')},MAX_FILE)
            C.need(C.metadata(p.lstat())==item['metadata'],'closed boundary original metadata changed')
            capture.file(p,'boundary-chain/'+nonce+'/'+name+'.original.json');originals[key]=original
        LATE.closed_boundary_originals(raw,originals['inventory'],originals['closure'],
            original_descriptor=row,combination_sha256=lease['combination']['sha256'],
            package_sha256=lease['package_sha256'])
        values.append(value);row=value['prior_boundary']
    LATE.require_failed_ancestor_tail(values)


def make_archive(snapshot,files):
    target=io.BytesIO()
    with tarfile.open(fileobj=target,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(files):
            raw=C.read(snapshot/C.relative(name),MAX_FILE)
            C.need(C.descriptor(raw)=={k:files[name][k] for k in ('bytes','sha256')},'captured bytes changed before archive')
            row=tarfile.TarInfo(name);row.size=len(raw);row.uid=row.gid=0;row.mode=0o600;row.mtime=0
            archive.addfile(row,io.BytesIO(raw))
    plain=target.getvalue();C.need(len(plain)<=MAX_BYTES+8*1024*1024,'archive total bound')
    raw=gzip.compress(plain,mtime=0);C.need(len(raw)<=MAX_BYTES,'archive compressed byte bound')
    return raw


def snapshot(a):
    C.need(a.execute_original_snapshot_once,'explicit new original capture required')
    os.umask(0o077);home=C.private_dir(Path(a.lease))
    lease,lease_raw=LIFE.load_lease(home,a.lease_sha256,require_live=False)
    LIFE.native_root(lease['boot_id'])
    C.need(a.package_sha256==lease['package_sha256'],'explicit snapshot adapter pin differs')
    C.verify_package(home/'package/MANIFEST.json',a.package_sha256)
    C.need(Path(__file__)==home/'package/source/component_snapshot.py','snapshot must use the staged pinned source')
    combo_raw=C.pinned(home/'inputs/COMBINATION.json',lease['combination'])
    combo,_=C.load_combination(home/'inputs',combo_raw,
        C.strict(C.read(home/'package/reference/REVIEWED-PRODUCTION-PINS.json')))
    C.verify_external(combo)
    accepted=C.strict(C.read(home/'ACCEPTED.json'));scope=C.scope(accepted['scope'])
    bound=C.strict(C.read(home/'BOUND-CONTRACT.json'))
    C.need(bound['lease_sha256']==a.lease_sha256 and C.sha(C.encoded(bound['contract']))==accepted['contract_sha256']
           and bound['contract']['owner_request_sha256']==lease['owner_request_sha256'],'accepted original contract differs')
    run=C.COMPONENT_EVIDENCE/bound['run_basename']
    C.need(re.fullmatch(r'[0-9]{8}-[0-9]{6}-'+lease['nonce'],bound['run_basename'])
           and accepted['run_dir']==str(run),'exact original component run required')
    first=C.strict(C.read(run/'provider-in-00.jsonl',C.MAX_FRAME))
    C.need(first['kind']=='turn.start' and {k:first['turn'][k] for k in C.SCOPE}==scope
           and first['turn']['user_input'].encode()==C.read(home/'owner-request.txt',16000),
           'original owner/five-scope first native frame differs')
    after,tables=verify_role_end(home)
    out=Path(a.out)
    C.need(out.parent==C.BASE/'native-guard-snapshots-r10-r1'
           and re.fullmatch(re.escape(lease['label'])+r'-capture-[0-9]{2}',out.name),
           'new explicit per-lease capture namespace required')
    try:C.private_dir(out.parent)
    except FileNotFoundError:C.private_dir(out.parent,create=True)
    C.private_dir(out,create=True)
    original_handler=signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('component snapshot 75-second hard bound')))
    signal.alarm(75);cap=Capture(out/'snapshot')
    try:
        cap.tree(home,'home');cap.tree(run,'run')
        journal=C.ANDROID/lease['android_journal'].lstrip('/')
        cap.tree(journal,'executor');cap.tree(C.PRODUCTION_EVIDENCE/'action-ledger','ledger')
        for key,row in lease['retirement'].items():cap.file(row['path'],'retirement/'+key+'.original')
        if lease['prior_boundary'] is not None:cap.file(lease['prior_boundary']['path'],'retirement/prior-boundary.original.json')
        capture_boundary_chain(cap,lease)
        actions=[]
        for phase in ('capture','guard'):
            path=run/(phase+'.dispatch-intent.json')
            try:value=C.strict(C.read(path))
            except FileNotFoundError:continue
            action=value['action_id'];C.need(re.fullmatch('[0-9a-f]{32}',action),'native action id differs')
            C.need(action not in actions,'component duplicate native action id');actions.append(action)
        client=C.BASE/'client-receipts';names=sorted(p.name for p in client.iterdir())
        for action in actions:
            for name in names:
                if not name.startswith(action+'.'):continue
                p=client/name
                if stat.S_ISDIR(p.lstat().st_mode):cap.tree(p,'client/'+name)
                else:cap.file(p,'client/'+name)
        fixture=C.ANDROID/'data/local/tmp'/('hepta-native-guard-'+lease['nonce'])
        native=native_capture(cap,scope)
        roots=list(dict.fromkeys(inventory_roots(home,lease)+[fixture]))
        fixtures=[p for p in roots if re.fullmatch(
            r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}',str(p))]
        absent=[]
        for prior in fixtures:
            try:prior.lstat()
            except OSError as error:
                C.need(error.errno==2,'fixture existence unknown; never infer absence')
                absent.append(LIFE.fixture_absence(prior))
            else:cap.tree(prior,'fixture' if prior==fixture else 'prior-fixture/'+prior.name.rsplit('-',1)[1],private=False)
        full=LIFE.inventory(roots,fixture_roots=fixtures)
        if absent:
            for row in absent:LIFE.fixture_absence(row['path'])
            cap.save('observation/FIXTURE-ABSENCE.json',C.encoded({'schema':'hepta.native-guard.fixture-absence-set.v1',
                'scope':scope,'observations':absent,'absence_does_not_qualify_component':True}))
        cap.save('after/AFTER-INVENTORY.json',C.encoded(full))
        cap.save('observation/AFTER-ROLES.json',C.encoded(after))
        for name,raw in tables.items():cap.save('observation/proc-net-'+name+'.original',raw)
        cap.recheck()
        # No inventory root is permitted to contain this new capture.
        C.need(all(out!=p and p not in out.parents and out not in p.parents for p in roots),'capture overlaps original inventory')
        report={'schema':'hepta.native-guard.original-capture.v1',
            'state':'ORIGINAL_BYTES_CAPTURED_FOR_INDEPENDENT_AUDIT','boot_id':lease['boot_id'],
            'scope':scope,'owner_request_sha256':lease['owner_request_sha256'],'nonce':lease['nonce'],
            'case_id':lease['case_id'],'lease_sha256':C.sha(lease_raw),'package_sha256':a.package_sha256,
            'combination_sha256':C.sha(combo_raw),'run_basename':bound['run_basename'],
            'retirement_proof_sha256':lease['retirement']['proof']['sha256'],
            'prior_boundary_sha256':None if lease['prior_boundary'] is None else lease['prior_boundary']['sha256'],
            'files':cap.files,'directories':cap.directories,'retained_bytes':cap.total,'native':native,
            'action_ids':actions,'component_qualified':False,'business_qualified':False,'model_requests':0,
            'native_dispatches':0,'ui_actions':0,'socket_connections':0,'source_original_writes':0,
            'automatic_retry':False,'inventory_is_closure_or_retirement':False}
        report_raw=C.encoded(report);C.put(out/'CAPTURE.json',report_raw)
        archive_files={**cap.files,'CAPTURE.json':C.descriptor(report_raw)}
        C.put(cap.destination/'CAPTURE.json',report_raw)
        body=make_archive(cap.destination,archive_files);C.put(out/'ORIGINALS.tar.gz',body)
        result={'schema':'hepta.native-guard.snapshot-result.v1','state':'ORIGINAL_CAPTURE_ARCHIVED',
            'capture':C.descriptor(report_raw),'archive':C.descriptor(body),'archive_members':len(archive_files),
            'capture_path':str(out/'CAPTURE.json'),'archive_path':str(out/'ORIGINALS.tar.gz'),
            'component_qualified':False,'business_qualified':False,'model_requests':0,'automatic_retry':False}
        C.put(out/'RESULT.json',result);print(C.encoded(result).decode(),end='');return 0
    except BaseException as error:
        C.put(out/'PARTIAL-CAPTURE.json',{'state':'PARTIAL_ORIGINALS_PRESERVED_NOT_QUALIFIED',
            'error_type':type(error).__name__,'detail':str(error)[:1024],'files':cap.files,
            'component_qualified':False,'business_qualified':False,'automatic_retry':False})
        raise
    finally:signal.alarm(0);signal.signal(signal.SIGALRM,original_handler)


def main():
    p=argparse.ArgumentParser()
    for name in ('lease','lease-sha256','package-sha256','out'):p.add_argument('--'+name,required=True)
    p.add_argument('--execute-original-snapshot-once',action='store_true')
    return snapshot(p.parse_args())


if __name__=='__main__':raise SystemExit(main())
