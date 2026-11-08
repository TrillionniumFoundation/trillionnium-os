#!/usr/bin/env python3
"""Offline closure of the one actual ended attempt05 before native Send.

Reads existing Mac originals and a complete original phone archive. It never
runs an Actor, shell, socket, phone command, signal, model or native task.
The result is an independent non-native sidebranch closure, not ROOT-RESULT.
"""
import argparse
import ast
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import sys
import tarfile
import types
import zlib

sys.dont_write_bytecode=True
B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
CANDIDATE=B/'native-guard-attempt05-nonnative-closure-r1-candidate03'
CAPDIR=B/'native-guard-attempt05-nonnative-capture-r1/capture-01'
F=B/'native-guard-root-chains-r10-r1/root-r10-neg01-20261105-05'
R=B/'native-guard-r10-r1-operator-r5/runtime'
DEST=B/'native-guard-attempt05-nonnative-closure-r1'
LABEL='root-r10-neg01-20261105-05'
NONCE='e4c3ccb0b2d706be3b7bf105ae772405'
HOME='/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/'+LABEL
JOURNAL='/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/'+LABEL+'/executor'
FIXTURE='/proc/1/root/data/local/tmp/hepta-native-guard-'+NONCE
MAX_FILE=16*1024*1024
MAX_ARCHIVE=64*1024*1024
MAX_PLAIN=72*1024*1024
EMPTY=hashlib.sha256(b'').hexdigest()

def desc(path,size,digest):return {'path':str(path),'bytes':size,'sha256':digest}
VERIFIER=desc(CANDIDATE/'source/non_native_attempt05.py',19740,
 'a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4')
SENDER=desc(B/'native-guard-attempt05-sender-no-send-audit-r1-candidate02/source/sender_no_send.py',33366,
 '3117035c31ab46e865a93a4ff797388c18d4e9e6c669bc5d4b48ae9711f1842e')
SENDER_PLAN=desc(B/'native-guard-attempt05-sender-no-send-audit-r1-candidate02/inputs/PLAN.json',963,
 'd1483afc427ef8325698a7c7c56cc6361f8bdb82c42177ba3ee1367ea95cde43')
SENDER_PROOF=desc(B/'native-guard-attempt05-sender-no-send-audit-r1-candidate02/actual-host-audit-01/RESULT.json',33374,
 '3fe548949e33edb51caa1063632f789d419d63e10b7efaa4e7cec37a497d76aa')
DRIVER=desc(B/'native-guard-attempt05-nonnative-capture-r1-candidate01/source/run_non_native_capture05.py',27734,
 '17fe5e803ff55f6f752ebadfab11163c619e5de42a4ee09d5c1e549df7635d80')
CAPTURE_SOURCE=desc(B/'native-guard-attempt05-nonnative-capture-r1-candidate01/source/capture_non_native_attempt05.py',22313,
 '3e72353d8bd0dec122f10f5f3f5a6fe50e6dfb5251a41e51fc89974d4d4867bb')
ROOT_CAPTURE=desc(CAPDIR/'ROOT-CAPTURE-RESULT.json',16217,
 'a087274e7e5639f2226a3ed8f29d3083c08e1e044678afcba188263dba4fe10c')
ROOT_PLAN=desc(F/'ROOT-PLAN.original.json',4737,
 '30f50baff1418464d6abef24744f61ba88de927185208679a3a19cb3dbfa62f6')
ROOT_FAILURE=desc(F/'ROOT-FAILURE.json',10082,
 'ae8f5bc9d8897c561adcc901b93e1fd12e997afe655eeb0de44eb32a7263f857')
RUNTIME_MANIFEST=desc(R/'MANIFEST.json',6253,
 '9c2e08ce171d8212b5f21abbc97ded5ba2fb578e221a8579db8aef3568ff969e')
FIXED={'root_capture_result':ROOT_CAPTURE,'root_plan':ROOT_PLAN,'root_failure':ROOT_FAILURE,
 'runtime_manifest':RUNTIME_MANIFEST,'capture_source':CAPTURE_SOURCE,'capture_driver':DRIVER,
 'sidebranch_verifier':VERIFIER,'sender_verifier':SENDER,'sender_plan':SENDER_PLAN,'sender_proof':SENDER_PROOF}
DEPENDENCIES={'component_common':(18133,'8ad9a3b17e7475555af7dd9a113025740447fcebdf0400d984d8a9e84accfb02'),
 'late_boundary':(43089,'e4146ccbd854c1f2d2b7a2a6a4ab8c4686af0bc45298590132e48817bee9e1dc')}


def need(ok,reason):
    if not ok:raise ValueError(reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def pin(raw):return {'bytes':len(raw),'sha256':sha(raw)}


def enc(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()


def strict(raw):
    def pairs(rows):
        out={}
        for k,v in rows:
            need(k not in out,'duplicate original JSON key');out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite original JSON')))


def md(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


class Originals:
    def __init__(self):self.rows={}
    def read(self,path,maximum=MAX_ARCHIVE):
        p=Path(path);need(p.is_absolute() and p.resolve(strict=True)==p,'canonical host original required')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            a=os.fstat(fd)
            need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=maximum,
                 'bounded single-link original required')
            with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(maximum+1)
            need(len(raw)==a.st_size and md(a)==md(os.fstat(fd))==md(p.lstat()),'host original changed')
        finally:os.close(fd)
        row={'path':str(p),**pin(raw),'metadata':md(a)}
        need(str(p) not in self.rows or self.rows[str(p)]==row,'original changed across reads')
        self.rows[str(p)]=row
        return raw
    def pinned(self,row,maximum=MAX_ARCHIVE):
        need(type(row) is dict and set(row)=={'path','bytes','sha256'}
            and type(row['bytes']) is int and 0<=row['bytes']<=maximum
            and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
            'exact bounded original descriptor required')
        raw=self.read(row['path'],maximum)
        need(pin(raw)=={k:row[k] for k in ('bytes','sha256')},'actual original pin differs')
        return raw
    pin=pinned
    def recheck(self):
        for path,row in list(self.rows.items()):
            need(md(Path(path).lstat())==row['metadata'],'original metadata changed before close')
            need(pin(self.read(path))=={k:row[k] for k in ('bytes','sha256')},
                 'original bytes changed before close')


def module(o,row,name):
    raw=o.pinned(row);m=types.ModuleType(name);m.__file__=row['path']
    m.__reviewed_source_sha256__=row['sha256']
    exec(compile(raw,row['path'],'exec'),m.__dict__)
    return m


def syncdir(p):
    f=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(f)
    finally:os.close(f)


def newdir(p):
    p.mkdir(mode=0o700);syncdir(p);syncdir(p.parent)


def put(p,raw):
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    syncdir(p.parent);need(p.read_bytes()==raw,'new host output byte readback differs')


def plan_value(o):
    own=o.read(Path(__file__),1024*1024)
    return {'schema':'hepta.native-guard.attempt05.non-native-closure-plan.v1',
        **FIXED,'closer_source':{'path':str(Path(__file__)),**pin(own)}}


def unpack(raw):
    need(len(raw)<=MAX_ARCHIVE,'original archive byte bound')
    d=zlib.decompressobj(16+zlib.MAX_WBITS);plain=d.decompress(raw,MAX_PLAIN+1)
    need(len(plain)<=MAX_PLAIN and d.eof and not d.unconsumed_tail and not d.unused_data,
         'bounded complete original gzip stream required')
    out={}
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as t:
        members=t.getmembers();need(0<len(members)<=8192,'original archive member count')
        for row in members:
            p=PurePosixPath(row.name)
            need(row.isfile() and not row.issym() and not row.islnk()
                and not p.is_absolute() and '..' not in p.parts and str(p)==row.name
                and row.name not in out and 0<=row.size<=MAX_FILE
                and row.uid==row.gid==0 and row.mode==0o600,
                'nonregular/duplicate/escaped/unbounded archive member')
            out[row.name]=t.extractfile(row).read(row.size+1)
            need(len(out[row.name])==row.size,'original archive member incomplete')
    return out


def host_step(o,step,base):
    phase=step['phase'];need(re.fullmatch('[a-z0-9-]{1,55}',phase),'original phase name differs')
    d=base/phase;raw=o.read(d/'RESULT.json',262144)
    need(strict(raw)==step and step['state']=='ORIGINAL_HOST_CHILD_JOINED'
        and type(step['returncode']) is int and step['returncode']==0
        and step['automatic_retry'] is False,'actual original host phase not joined zero')
    intent_raw=o.read(d/'INTENT.json',1024*1024);intent=strict(intent_raw)
    child=strict(o.read(d/'CHILD.json',65536))
    need(intent['schema']=='hepta.native-guard.root-host-command.v1' and intent['phase']==phase
        and intent['maximum_starts']==1 and intent['automatic_retry'] is False
        and intent['signals_on_timeout'] is False and type(intent['maximum_wait_seconds']) is int
        and 0<intent['maximum_wait_seconds']<=900,
        'actual original one-start host intent differs')
    need(child['pid']==step['pid'] and child['source_intent_sha256']==sha(intent_raw)
        and child['maximum_starts']==1,'actual host child/intent differs')
    need((child['pgid']==child['sid']==child['pid'] and child['identity_missing_only_if_actual_child_already_joined'] is False)
        or (child['pgid'] is child['sid'] is None and child['identity_missing_only_if_actual_child_already_joined'] is True),
        'host process group or original early join differs')
    if intent['stdin_sha256'] is not None:
        need(sha(o.read(d/'stdin.original',8*1024*1024))==intent['stdin_sha256'],'original stdin differs')
    need(step['stdout']['path']==str(d/'stdout.original') and step['stderr']['path']==str(d/'stderr.original'),
         'host phase original stream paths differ')
    out=o.pinned(step['stdout']);err=o.pinned(step['stderr'])
    need(err==b'','original host phase has stderr')
    return out,intent


def capture_provenance(o,D,V):
    execution=strict(o.pinned(ROOT_CAPTURE));plan_raw=o.pinned(execution['root_capture_plan'])
    p=strict(plan_raw)
    need(execution['schema']=='hepta.root.non-native-capture-execution.v1'
        and execution['state']=='ORIGINAL_NON_NATIVE_CAPTURE_AND_EXPORT_COMPLETE_NOT_CLOSED'
        and execution['source']==DRIVER and execution['capture_source']==CAPTURE_SOURCE
        and execution['nonce']==NONCE and execution['label']==LABEL
        and execution['capture_calls']==1 and execution['export_calls']==3
        and execution['original_root_plan']==ROOT_PLAN and execution['original_root_failure']==ROOT_FAILURE,
        'actual capture execution binding differs')
    need(p['driver_source']==DRIVER and p['capture_source']==CAPTURE_SOURCE
        and p['out']==str(CAPDIR),'original capture plan source/path differs')
    source=o.pinned(CAPTURE_SOURCE);capture_plan=o.pinned(p['capture_plan'])
    checked_source,_v,_root,_lease=D.source_and_inputs(o)
    need(checked_source==source,'frozen full Root transport/source input validation differs')
    expected_request,wire,bootstrap=D.phone_request(source,capture_plan)
    request=strict(o.pinned(p['capture_request']))
    need(request==expected_request and wire==p['actual_adb_wire_bytes']
        and o.pinned(p['capture_bootstrap'])==bootstrap,'exact actual capture request/bootstrap differs')
    need(o.read(CAPDIR/'CAPTURE-DRIVER.original.py')==o.pinned(DRIVER)
        and o.read(CAPDIR/'ROOT-CAPTURE-PLAN.original.json')==plan_raw
        and o.read(CAPDIR/'CAPTURE-PLAN.original.json')==capture_plan
        and strict(o.read(CAPDIR/'PHONE-CAPTURE-REQUEST.original.json'))==request,
        'durable Root before-call originals differ')
    tags=['nn05-capture01']+['nn05-export-%03d'%i for i in range(3)]
    need(execution['phone_phase_names']==tags and len(execution['operations'])==4,
         'actual capture/export call count differs')
    wanted=['nn05-namespace-preflight']
    for tag in tags:wanted+=['phone-'+tag,'read-'+tag]
    need([x['phase'] for x in execution['steps']]==wanted,'actual capture host step inventory differs')
    streams={}
    for step in execution['steps']:streams[step['phase']]=host_step(o,step,CAPDIR)
    namespace=strict(streams[wanted[0]][0])
    alltags=['nn05-capture01']+['nn05-export-%03d'%i for i in range(112)]
    transport_plan=strict(o.read(CAPDIR/'ROOT-PLAN.original.json',262144))
    need(transport_plan['native_chain_run_is_called'] is False and transport_plan['nonce']==NONCE,
         'original capture did not use separate non-native transport')
    paths=[]
    for tag in alltags:
        label='ng-'+NONCE+'-'+tag
        paths+=['/home/alex/razr60-local-model-v150/requests/'+label+'.json',
                '/home/alex/razr60-local-model-v150/operations/'+label,
                '/home/alex/codex-native-guard-chain-r10-r1/'+NONCE+'/phone-'+tag]
    need(namespace['state']=='ALL_EXACT_ONCE_NAMES_ABSENT' and namespace['phone_calls']==0
        and namespace['paths']==paths and len(set(namespace['paths']))==len(paths),'actual namespace preflight differs')
    chunks=[];capture_result=None
    for i,op in enumerate(execution['operations']):
        tag=tags[i];need(op['phase']==tag,'operation phase order differs')
        envelope=strict(streams['phone-'+tag][0])
        row=op['operation'];V.descriptor(row['original'],maximum=MAX_FILE)
        need(row['original']['path']=='/home/alex/razr60-local-model-v150/operations/ng-'+NONCE+'-'+tag+'/result.json'
            and row['copy']['path']==str(CAPDIR/(tag+'.WRAPPER.original.json')),
            'actual independent wrapper path differs')
        raw=o.pinned(row['copy'])
        need(pin(raw)=={k:row['original'][k] for k in ('bytes','sha256')},
             'original and copied wrapper pins differ')
        readback=strict(streams['read-'+tag][0])
        need({k:readback[k] for k in row['original']}==row['original']
            and base64.b64decode(readback['raw_b64'],validate=True)==raw,
            'independent full metadata/raw wrapper readback differs')
        w=strict(raw)
        need(envelope['actor_rc']==0 and envelope['wrapper_sha256']==sha(raw)
            and envelope['wrapper']==w and w['schema']=='hepta.phone-local.operator-result.v150.1'
            and w['label']=='ng-'+NONCE+'-'+tag and w['model_decision'] is False
            and w['native_task_result'] is False and w['status']=='command_exited',
            'actual independent Actor operation is not a known read-only completion')
        ph=w['phone'];need(type(ph['rc']) is int and ph['rc']==0 and ph['stderr']==''
            and ph['route']==[5037,'23'],'actual phone observation failed')
        phone_raw=ph['stdout'].encode()
        need(sha(phone_raw)==op['phone_stdout_sha256']
            and o.read(CAPDIR/(tag+'.RESULT.original.json'))==phone_raw,
            'original phone stdout bytes differ')
        result=strict(phone_raw)
        req=request if i==0 else D.chunk_request(capture_result,i-1)
        need(ph['command']=='/debug_ramdisk/su -c '+shlex.quote(req['command']),
             'actual phone command differs from reviewed capture/export command')
        if i==0:
            capture_result=result
            need(result['nonce']==NONCE and result['label']==LABEL
                and result['state']=='ORIGINAL_PRE_NATIVE_CAPTURE_ARCHIVED_NOT_CLOSED'
                and result['archive']==V.ARCHIVE and result['capture']==V.CAPTURE
                and result['capture_source']==pin(source) and result['capture_plan']==pin(capture_plan),
                'actual phone capture source/output differs')
        else:
            body=base64.b64decode(result['raw_b64'],validate=True)
            need(result['schema']=='hepta.native-guard.non-native-export-chunk.v1'
                and result['index']==i-1 and result['count']==3
                and result['offset']==(i-1)*D.CHUNK and pin(body)=={k:result[k] for k in ('bytes','sha256')}
                and result['archive']==V.ARCHIVE and result['capture']==V.CAPTURE
                and result['archive_metadata']==execution['phone_archive_original']['metadata']
                and result['capture_metadata']==execution['phone_capture_original']['metadata']
                and result['phone_writes']==result['ui_actions']==result['native_submissions']==0,
                'actual read-only chunk provenance differs')
            chunks.append(body)
    archive=o.pinned(execution['archive']);cap_raw=o.pinned(execution['capture'])
    need(b''.join(chunks)==archive and pin(archive)==V.ARCHIVE and pin(cap_raw)==V.CAPTURE,
         'actual full archive does not match its independently returned chunks')
    for key,expected in [('phone_archive_original',V.ARCHIVE),('phone_capture_original',V.CAPTURE)]:
        V.descriptor(execution[key],phone=True,maximum=MAX_ARCHIVE)
        need({k:execution[key][k] for k in ('bytes','sha256')}==expected,'phone output original differs')
    D.decode_archive(archive,capture_result)
    files=unpack(archive);need(len(files)==195 and files['CAPTURE.json']==cap_raw,'complete capture original differs')
    cap=strict(cap_raw)
    need(files['provenance/CAPTURE-SOURCE.original.py']==source
        and files['provenance/CAPTURE-PLAN.original.json']==capture_plan,
        'archive actual source/plan provenance differs')
    need(sum(len(files[k]) for k in cap['files'])==cap['retained_bytes'],
         'complete retained original byte count differs')
    return execution,cap,files,{'archive_members':len(files),'retained_bytes':cap['retained_bytes'],
        'independent_actor_operations':4,'capture_calls':1,'readonly_export_calls':3,
        'all_original_wrapper_raw_and_full9_verified':True,'actual_wire_bytes':wire}


def runtime_modules(files):
    old=sys.modules.get('component_common');previous=sys.path[:];dwb=sys.dont_write_bytecode
    modules={}
    try:
        for name,(size,digest) in DEPENDENCIES.items():
            raw=files['home/package/source/'+name+'.py']
            need(len(raw)==size and sha(raw)==digest,'actual reviewed runtime dependency differs')
            m=types.ModuleType(name);m.__file__=str(R/'source'/(name+'.py'))
            m.__reviewed_source_sha256__=digest
            m.__reviewed_package_sources__={k[len('home/package/'):]:v for k,v in files.items()
                                            if k.startswith('home/package/')}
            if name=='component_common':sys.modules[name]=m
            exec(compile(raw,m.__file__,'exec'),m.__dict__);modules[name]=m
        return modules
    finally:
        sys.path[:]=previous;sys.dont_write_bytecode=dwb
        if old is None:sys.modules.pop('component_common',None)
        else:sys.modules['component_common']=old


def captured_original(cap,files,logical,row):
    need(logical in files and logical in cap['files'],'required actual original member absent')
    item=cap['files'][logical]
    need(item['kind']=='original_file_bytes' and item['source_path']==row['path']
        and item['source_metadata']==row['metadata']
        and pin(files[logical])=={k:row[k] for k in ('bytes','sha256')},
        'original archive file/phone full metadata binding differs')
    return files[logical]


def validate_original_trees(cap,files,after,V):
    for name,row in cap['files'].items():
        need(row['path']==name and pin(files[name])=={k:row[k] for k in ('bytes','sha256')},
             'retained logical member pin differs')
        if row['kind']=='derived_read_observation':
            need(row['source_path'] is None and row['source_metadata'] is None,
                 'derived observation falsely names an original')
            continue
        need(row['kind']=='original_file_bytes','unknown retained file provenance')
        original=after['entries'].get(row['source_path'])
        if original is not None:
            need(original['kind']=='file' and row['source_metadata']==original['metadata']
                and {k:row[k] for k in ('bytes','sha256')}=={k:original[k] for k in ('bytes','sha256')},
                'independent copied original does not match final inventory')
    for root,logical in [(HOME,'home'),(JOURNAL,'executor')]:
        rows={p:r for p,r in after['entries'].items() if p==root or p.startswith(root+'/')}
        expected_files={logical+p[len(root):] for p,r in rows.items() if r['kind']=='file'}
        actual_files={p for p in files if p==logical or p.startswith(logical+'/')}
        need(actual_files==expected_files,'complete private tree capture omitted or added a file')
        for p,r in rows.items():
            if r['kind']=='directory':
                d=cap['directories'].get(p)
                need(d and d['metadata']==r['metadata'] and d['names']==r['names']
                    and d['capture_path']==logical+p[len(root):],
                    'complete private directory metadata/names were not retained')
        need(all(r['kind'] in ('directory','file') for r in rows.values()),'private tree contains unknown entries')
    for p,row in after['entries'].items():
        if p==JOURNAL or p.startswith(JOURNAL+'/'):
            alias=HOME+'/executor'+p[len(JOURNAL):]
            need(after['entries'].get(alias)==row,'GNU and Android journal aliases differ')


def package_and_root(o,cap,files,C,V):
    root=strict(o.pinned(ROOT_PLAN));failure=strict(o.pinned(ROOT_FAILURE))
    lease_raw=files['home/LEASE.json'];lease=strict(lease_raw)
    combo_raw=files['home/inputs/COMBINATION.json']
    need(pin(lease_raw)==V.LEASE and pin(combo_raw)==V.COMBINATION
        and lease['nonce']==NONCE and lease['label']==LABEL and lease['boot_id']==V.BOOT
        and lease['owner_request_sha256']==V.OWNER and lease['package_sha256']==V.PACKAGE['sha256']
        and lease['prior_boundary']==cap['native_prior_boundary'],
        'actual original lease/combination differs')
    need(root['nonce']==NONCE and root['label']==LABEL and root['case_id']=='NEG-01'
        and root['package']==RUNTIME_MANIFEST and root['live_policy_sha256']==V.POLICY
        and root['policy_adoption']['sha256']==V.ADOPTION,'actual Root fixed policy/attempt differs')
    mfraw=o.pinned(RUNTIME_MANIFEST);need(mfraw==files['home/package/MANIFEST.json'],'captured package manifest differs')
    mf=strict(mfraw);rows=mf['files']
    need(len(rows)==25 and len({r['path'] for r in rows})==25,'exact original runtime package set differs')
    wanted={'home/package/MANIFEST.json'}
    for row in rows:
        p=PurePosixPath(row['path']);need(not p.is_absolute() and '..' not in p.parts,'package path escaped')
        name='home/package/'+row['path'];wanted.add(name)
        need(name in files and pin(files[name])=={k:row[k] for k in ('bytes','sha256')},
             'actual package source original changed')
        need(o.pinned(desc(R/row['path'],row['bytes'],row['sha256']))==files[name],
             'actual reviewed host source differs from staged phone original')
    need({p for p in files if p.startswith('home/package/')}==wanted,'unindexed package original or bytecode cache')
    prepared=strict(o.read(F/'material/PREPARED.json',65536));archive_pin=prepared['archive']
    staged=o.pinned({'path':str(F/'material/component-inputs.tar.gz'),**archive_pin})
    staged_files=unpack(staged)
    need(len(staged_files)==prepared['archive_members']==49,'actual prepared complete tree count differs')
    for name,body in staged_files.items():
        need(files.get('home/'+name)==body and o.read(F/'material/tree'/name,MAX_FILE)==body,
             'actual staged member differs from original host tree/archive')
    combo,cfg=C.load_combination(F/'material/tree/inputs',combo_raw,
        strict(files['home/package/reference/REVIEWED-PRODUCTION-PINS.json']),private_inputs=False)
    need(combo['live_policy_sha256']==V.POLICY,'actual combination policy differs')
    need(failure['state']=='FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION'
        and failure['detail']=='component ended before phase; preserve, no additional Root UI'
        and failure['root_fixture_attempts']==[],'actual original failure/Root phase differs')
    wanted_phases=['prepare-material','host-stage-material','phone-push-material','phone-copy-material',
        'phone-push-stage-source','phone-copy-stage-source','phone-stage','sender-preview','sender-prepared',
        'phone-launch','phone-plan-setup']
    need([s['phase'] for s in failure['steps']]==wanted_phases,'original Root executed phase inventory differs')
    for step in failure['steps']:host_step(o,step,F)
    stage=strict(files['home/STAGE-COMPLETE.json'])
    need(stage['archive_sha256']==archive_pin['sha256'] and stage['members']==49
        and stage['lease_sha256']==V.LEASE['sha256'] and stage['package_sha256']==V.PACKAGE['sha256']
        and stage['state']=='PRIVATE_COMPONENT_INPUTS_STAGED_NO_ROLES'
        and stage['existing_files_overwritten']==stage['existing_helper_or_policy_changes']==0,
        'original successful private stage differs')
    need(stage['journal_layout']['state']=='NEW_EXECUTOR_LEAF_SHARED_ANCESTORS_PRESERVED'
        and stage['journal_layout']['existing_directory_label_writes']==0
        and stage['journal_layout']['new_journal_label_writes']==1
        and stage['journal_layout']['journal']['path']==JOURNAL,
        'actual journal-only original stage differs')
    return root,lease,stage,{'staged_members':49,'package_members':25,
        'original_root_steps':len(wanted_phases),'root_fixture_attempts':0,
        'captured_package_exact_host_originals':True,'original_combination_17_inputs_revalidated':True}


def absence(rows):
    need(type(rows) is list and len(rows)==2,'two original group absence observations required')
    last=0
    for r in rows:
        need(set(r)=={'kernel_group_absence','members','numeric_pids','observed_monotonic_ns'}
            and r['kernel_group_absence'] is True and r['members']==[]
            and type(r['numeric_pids']) is int and 1<=r['numeric_pids']<=4096
            and type(r['observed_monotonic_ns']) is int and r['observed_monotonic_ns']>last,
            'actual complete process census/group ESRCH observation differs')
        last=r['observed_monotonic_ns']


def endpoints(files,prefix):
    for name in ('tcp','tcp6'):
        raw=files['observation/'+prefix+'-proc-net-'+name+'.original']
        lines=raw.splitlines();need(lines,'original proc TCP table missing')
        for line in lines[1:]:
            c=line.split();need(len(c)>=10,'original proc TCP row incomplete')
            addr=c[1].rsplit(b':',1);need(len(addr)==2,'original proc TCP address differs')
            need(not(int(addr[1],16)==18080 and c[3]==b'0A'),'original provider listener was present')
    raw=files['observation/'+prefix+'-proc-net-unix.original']
    need(raw.splitlines(),'original proc UNIX table missing')
    for line in raw.splitlines()[1:]:
        c=line.split();need(len(c)>=7,'original proc UNIX row incomplete')
        need(len(c)==7 or c[7]!=b'@hepta_phone_executor_v150_r6','original abstract executor socket present')


def roles_and_failure(files,V):
    def J(n):return strict(files['home/'+n])
    supervisor=J('SUPERVISOR.json');roles=dict(V.ROLES)
    need(supervisor['identity']==roles['supervisor'] and supervisor['ppid']==1
        and supervisor['domain']=='u:r:magisk:s0' and supervisor['exe']=='/usr/bin/python3'
        and supervisor['uid']==supervisor['gid']==[0]*4,'original native-init supervisor generation differs')
    intent=J('DETACHED-LAUNCH-INTENT.json');result=J('DETACHED-LAUNCH-RESULT.json')
    argv=base64.b64decode(supervisor['argv_b64'],validate=True)
    need(sha(argv)==supervisor['argv_sha256']
        and argv==b'\0'.join(x.encode() for x in intent['supervisor_argv'])+b'\0'
        and intent['maximum_forks']==intent['maximum_execs']==1
        and intent['automatic_retry'] is False and intent['lease_sha256']==V.LEASE['sha256']
        and intent['supervisor_parent_required_before_admission']==1
        and result['fork_returned_pid']==roles['supervisor'][0]
        and result['launcher_identity']==intent['launcher_identity']['identity']
        and result['lease_sha256']==V.LEASE['sha256'],'original one-fork identity chain differs')
    ended=J('LIFECYCLE-ENDED.json')
    need(ended['schema']=='hepta.native-guard.lifecycle-ended.v1'
        and ended['roles_joined_and_groups_absent'] is True
        and ended['automatic_restart'] is False and ended['model_requests']==0
        and ended['component_qualified'] is False and ended['native_turn_terminal_verified'] is False,
        'original actual role lifecycle not ended')
    for name,exitcode,signals in [('provider',1,[]),('sidecar',0,['SIGTERM_SYSCALL_RETURNED'])]:
        spawned=J(name+'.SPAWNED.json');admit=J(name+'.ADMIT.json');barrier=J(name+'.barrier.json')
        joined=J(name+'.JOINED.json');spawn_intent=J(name+'.SPAWN-INTENT.json')
        expected_argv=['/usr/bin/python3','-I','-B',HOME+'/package/source/component_lifecycle.py',
            '--lease',HOME,'--lease-sha256',V.LEASE['sha256'],'--package',HOME+'/package/MANIFEST.json',
            '--package-sha256',V.PACKAGE['sha256'],'--role',name,'--execute-child-role-once']
        if name=='provider':expected_argv+=['--listener-fd','4']
        need(spawned['pid']==roles[name][0] and spawned['identity']==roles[name]
            and spawned['automatic_retry'] is False and spawned['argv']==expected_argv
            and spawn_intent=={'role':name,'lease_sha256':V.LEASE['sha256'],
                'new_owned_session':True,'no_model_role':True,'automatic_restart':False},
            'actual owned child spawn identity/command/intent differs')
        need(admit=={'identity':roles[name],'parent_identity':roles['supervisor'],
            'lease_sha256':V.LEASE['sha256'],'role':name}
            and barrier=={'identity':roles[name],'parent_identity':roles['supervisor'],
                'domain':'u:r:magisk:s0','application_not_executed':True},
            'actual child original parent/admission barrier differs')
        need(joined==ended['roles'][name] and joined['identity']==roles[name]
            and joined['role']==name and joined['child_wait_returned'] is True
            and joined['child_exit_code']==exitcode and joined['signals']==signals
            and joined['dedicated_process_group_absent'] is True and joined['automatic_retry'] is False,
            'actual owned child original wait/known terminal differs')
        absence(joined['absence'])
    term=J('sidecar.TERM-INTENT.json')
    need(term=={'target_identity':roles['sidecar'],'signal':'SIGTERM','via':'pidfd',
        'maximum_signal_attempts':1,'automatic_retry':False},'original owned sidecar pidfd signal differs')
    bound=J('BOUND-CONTRACT.json')
    need(bound['lease_sha256']==V.LEASE['sha256'] and bound['contract']['nonce']==NONCE
        and bound['contract']['owner_request_sha256']==V.OWNER
        and bound['sidecar_identity']['identity']==roles['sidecar']
        and bound['sidecar_identity']['ppid']==roles['supervisor'][0]
        and bound['sidecar_identity']['domain']=='u:r:trillionnium_owner_open_phone_executor:s0',
        'actual pre-native sidecar identity binding differs')
    stderr=files['home/provider.stderr']
    need(b'OSError: [Errno 16] Device or resource busy:' in stderr
        and b"'/proc/1/root/sys/fs/selinux/policy'" in stderr
        and b'line 287, in child_role\n    verify_external(combo)' in stderr
        and files['home/provider.stdout']==b'','actual provider failure was not before listener execution')
    tree=ast.parse(files['home/package/source/component_lifecycle.py'])
    fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='child_role')
    calls=[n for n in ast.walk(fn) if isinstance(n,ast.Call)]
    gates=[n.lineno for n in calls if isinstance(n.func,ast.Name) and n.func.id=='verify_external']
    execs=[n.lineno for n in calls if isinstance(n.func,ast.Attribute) and n.func.attr=='execve']
    need(gates==[287] and execs and min(execs)>287,'actual source gate no longer precedes listener exec')
    observation=strict(files['observation/AFTER-ROLES.json'])
    for which in ('first','last'):
        r=observation[which]
        need(r['roles']==roles and r['original_lifecycle_ended_sha256']==sha(files['home/LIFECYCLE-ENDED.json'])
            and r['port_18080_listener_absent'] is True and r['r6_abstract_endpoint_absent'] is True
            and r['socket_connections']==r['model_requests']==0
            and r['native_turn_verified'] is False and r['component_qualified'] is False,
            'independent three-role original observation differs')
        absence(r['absence_observations'])
    absence(observation['all_groups_absent_before']);absence(observation['all_groups_absent_after'])
    endpoints(files,'before');endpoints(files,'after')
    return bound,observation,{'roles':roles,'provider_exit_code':1,'sidecar_exit_code':0,
        'provider_original_error_errno':16,'provider_failed_before_listener_exec':True,
        'actual_owned_children_joined':True,'supervisor_independently_absent_twice':True,
        'original_lifecycle_supervisor_wait_not_claimed':True}


def pre_native_absence(files,cap,after,bound,V):
    obs=strict(files['observation/PRE-NATIVE-ABSENCES.json'])
    wanted=[HOME+'/'+n for n in ('READY.json','CONNECTION-ACCEPTED.json','ACCEPTED.json',
        'PROVIDER-HEALTH.original.json','PROVIDER-ENDED.json')]
    run=V.BASE+'/component-probe-r6/evidence/'+bound['run_basename'];wanted.append(run)
    need(re.fullmatch(r'[0-9]{8}-[0-9]{6}-'+NONCE,bound['run_basename'])
        and obs['schema']=='hepta.native-guard.pre-native-absence-set.v1'
        and obs['nonce']==NONCE and [r['path'] for r in obs['paths']]==wanted,
        'exact original pre-native absence set differs')
    for row in obs['paths']:
        need(row['absence']=='ENOENT' and row['path'] not in after['entries']
            and row['parent_path']==str(PurePosixPath(row['path']).parent),
            'pre-native absence is not genuine original ENOENT')
        parent=after['entries'][row['parent_path']]
        need(parent['kind']=='directory' and parent['metadata']==row['parent_metadata']
            and parent['names']==row['parent_names']
            and PurePosixPath(row['path']).name not in row['parent_names'],
            'original pre-native parent identity/name census differs')
    claims=obs['claims'];claimrow=after['entries'][HOME+'/claims']
    need(claims=={'path':HOME+'/claims','metadata':claimrow['metadata'],'names':[]}
        and claimrow['names']==[] and after['entries'][HOME+'/operator']['names']==[],
        'actual claims or Root operator phases exist')
    for key in ('fixture_before','fixture_after'):
        row=obs[key]
        need(row['schema']=='hepta.native-guard.fixture-absence.v1' and row['path']==FIXTURE
            and row['absence']=='ENOENT' and row['ui_actions']==0
            and type(row['canonical_parent_identity']) is list and len(row['canonical_parent_identity'])==5,
            'original fixture absence differs')
    need(obs['fixture_before']['canonical_parent_identity']==obs['fixture_after']['canonical_parent_identity']
        and after['entries'][FIXTURE]=={'kind':'absent','absence':'ENOENT'},
        'fixture original canonical parent/absence changed')
    native_raw=files['observation/NATIVE-NONCE-ABSENCE.json'];n=strict(native_raw)
    need(pin(native_raw)==cap['native_nonce_absence']
        and n['schema']=='hepta.native-guard.non-native-nonce-absence.v1'
        and n['nonce']==NONCE and n['owner_request_sha256']==V.OWNER
        and type(n['nonce_occurrences']) is int and n['nonce_occurrences']==0
        and type(n['owner_hash_occurrences']) is int and n['owner_hash_occurrences']==0
        and n['all_segment_bytes_rechecked'] is True and n['native_scope_assigned'] is False
        and n['native_hash_chain_verified'] is False and n['native_store_raw_bytes_copied'] is False,
        'bounded original native nonce absence differs')
    directory=n['directory'];base='/var/lib/trillionnium/owner-open/turn-events.jsonl.segments'
    need(directory['path']==base and directory['names']==sorted(set(directory['names']))
        and len(directory['names'])<=1024 and cap['directories'][base]['metadata']==directory['metadata']
        and cap['directories'][base]['names']==directory['names'],
        'original complete native store namespace differs')
    segments=[x for x in directory['names'] if x.endswith('.jsonl')]
    need([PurePosixPath(x['path']).name for x in n['sources']]==segments and segments,
         'absence observer omitted a native segment')
    for row in n['sources']:
        V.descriptor({k:row[k] for k in ('path','bytes','sha256','metadata')},maximum=64*1024*1024)
        need(str(PurePosixPath(row['path']).parent)==base and type(row['complete_lines']) is int
            and row['complete_lines']>0,'native absence source provenance differs')
    need(sum(x['bytes'] for x in n['sources'])==n['file_bytes_scanned']<=128*1024*1024
        and sum(x['complete_lines'] for x in n['sources'])==n['complete_lines_scanned'],
        'complete bounded original scan accounting differs')
    return {'pre_native_absent_paths':wanted,'fixture_absent':True,'claims_empty':True,
        'native_scan_original':pin(native_raw),'native_scan_files':len(n['sources']),
        'native_scan_bytes':n['file_bytes_scanned'],'native_scan_complete_lines':n['complete_lines_scanned'],
        'observer_double_hash_scan':True,'host_native_store_full_bytes_available':False,
        'native_hash_chain_verified':False}


def inventories(files,cap,lease,stage,L,V):
    before=strict(files['before/BEFORE-INVENTORY.json'])
    after=strict(files['after/AFTER-INVENTORY.json']);baseline=strict(files['home/BASELINE-INVENTORY.json'])
    need(L.inventory_value(before)==L.inventory_value(after),'complete actual inventory changed during capture')
    L.inventory_value(baseline)
    need(pin(files['after/AFTER-INVENTORY.json'])==V.AFTER
        and after['roots']==cap['inventory_roots'],'actual complete after-inventory pin/roots differs')
    validate_original_trees(cap,files,after,V)
    changed=[];added=[]
    for path,row in baseline['entries'].items():
        need(path in after['entries'],'baseline original disappeared')
        if after['entries'][path]!=row:changed.append(path)
    for path in after['entries']:
        if path not in baseline['entries'] and any(path==r or path.startswith(r+'/') for r in baseline['roots']):
            added.append(path)
    expected_added=[JOURNAL+'/'+x for x in ('actions','server.lock','sidecar.stderr','sidecar.stdout')]
    need(changed==[JOURNAL] and sorted(added)==sorted(expected_added),
         'baseline mutation exceeds the actual four journal originals')
    old=baseline['entries'][JOURNAL];new=after['entries'][JOURNAL]
    need(old['kind']==new['kind']=='directory' and old['metadata'][:5]==new['metadata'][:5]
        and old['names']==[] and new['names']==['actions','server.lock','sidecar.stderr','sidecar.stdout'],
        'actual journal directory identity/names changed unexpectedly')
    need(after['entries'][JOURNAL+'/actions']['kind']=='directory'
        and after['entries'][JOURNAL+'/actions']['names']==[]
        and after['entries'][JOURNAL+'/server.lock']['bytes']==0
        and after['entries'][JOURNAL+'/server.lock']['sha256']==EMPTY,
        'executor action or nonempty lock original exists')
    for row in stage['created_directories']:
        current=after['entries'].get(row['path'])
        need(current and current['kind']=='directory' and current['metadata'][:5]==row['metadata'][:5],
             'original stage-created directory identity changed')
    retirement=lease['retirement']
    raw={}
    for key,row in retirement.items():
        raw[key]=captured_original(cap,files,'retirement/'+key+'.original',row)
    ret=strict(raw['proof']);pre=strict(raw['preflight']);bound=strict(raw['bound_inputs'])
    need(ret['schema']=='hepta.r9-r2-retirement-observation.v1'
        and ret['state']=='ORIGINAL_FOUR_GROUPS_ABSENT_STATE_PRESERVED' and ret['boot_id']==V.BOOT
        and ret['server_lock_now_unheld'] is True and ret['global_pending_clear'] is True
        and ret['old_claims_deleted'] is False and ret['old_task_terminal_rewritten'] is False
        and ret['automatic_restart'] is False and ret['automatic_replay'] is False
        and pre['groups']==ret['original_role_identities']
        and pre['preserved_state']==ret['preserved_state']
        and bound['complete_current_accepted_case_union_verified'] is True
        and raw['disabled_flag']==b'','original retirement facts changed')
    prior=lease['prior_boundary'];chain=[];head=None;oldroles=list(pre['groups'].values())
    while prior is not None:
        need(len(chain)<2,'actual04 to external03 native tail only')
        nonce=PurePosixPath(prior['path']).stem;prefix='boundary-chain/'+nonce+'/'
        br=captured_original(cap,files,prefix+'BOUNDARY.original.json',prior)
        value=strict(br)
        ir=captured_original(cap,files,prefix+'INVENTORY.original.json',value['inventory'])
        cr=captured_original(cap,files,prefix+'CLOSURE.original.json',value['closure'])
        checked,inv,closed=L.closed_boundary_originals(br,ir,cr,original_descriptor=prior,
            combination_sha256=V.COMBINATION['sha256'],package_sha256=V.PACKAGE['sha256'])
        need(checked==value and value['boot_id']==V.BOOT and value['retirement']==retirement,
             'actual native predecessor original differs')
        if head is None:
            head=value;head_inventory=inv
            need(prior==cap['native_prior_boundary'] and prior['sha256']==V.PRIOR,
                 'actual04 native predecessor differs')
            need(all(after['entries'].get(k)==v for k,v in inv['entries'].items()),
                 'the current native head original changed during this non-native attempt')
        else:
            # The immutable03 originals describe its historical time, before04.
            # Its two global directories may have gained the legitimate04 names.
            # Compare05 to head04 above; prove historical membership/bytes here.
            need(set(inv['entries'])<=set(head_inventory['entries'])
                 and all(head_inventory['entries'][k]==v for k,v in inv['entries'].items()
                         if v['kind'] in ('file','absent')),
                 'the current native head lost or changed a historical original')
        need(set(inv['roots'])<=set(after['roots']),'prior native cumulative roots were dropped')
        oldroles.extend(value['component_role_identities'].values())
        chain.append({'nonce':nonce,'boundary':prior,'closure':value['closure'],'inventory':value['inventory'],
                      'native_status':value['native_status'],'component_qualified':value['component_qualified']})
        prior=value['prior_boundary']
    need([r['nonce'] for r in chain]==['c705647dd4ebb5d421be1041a9c41ca6','88d68d88130d3c74e6c950a6346357c1'],
         'original native predecessor tail differs')
    expected_roots=list(dict.fromkeys(head['roots']+[JOURNAL,HOME,FIXTURE]))
    need(after['roots']==expected_roots,'complete cumulative non-native roots differ')
    return after,oldroles,{'baseline_changed_paths':changed,'baseline_added_paths':sorted(added),
        'original_journal_before':old,'original_journal_after':new,
        'before_after_equal_except_elapsed':True,'prior_native_chain':chain,
        'native_chain_unchanged':True,'actual_after_entries':len(after['entries']),
        'actual_after_file_bytes_hashed':after['file_bytes_hashed']}


def close(o,plan):
    V=module(o,VERIFIER,'reviewed_non_native_attempt05');D=module(o,DRIVER,'reviewed_capture05_host')
    Sender=module(o,SENDER,'reviewed_sender_no_send05')
    execution,cap,files,provenance=capture_provenance(o,D,V)
    mods=runtime_modules(files);C=mods['component_common'];L=mods['late_boundary']
    root,lease,stage,packageproof=package_and_root(o,cap,files,C,V)
    after,oldroles,inventoryproof=inventories(files,cap,lease,stage,L,V)
    bound,roleobs,roleproof=roles_and_failure(files,V)
    expected_roles=list(V.ROLES.values())+oldroles
    need(len({tuple(x) for x in expected_roles})==len(expected_roles)==13
        and roleobs['all_actual_and_historical_generations']==expected_roles,
        'independent current/historical original absence set differs')
    absenceproof=pre_native_absence(files,cap,after,bound,V)
    sender_plan=strict(o.pinned(SENDER_PLAN))
    sender=Sender.verify_sender_no_send(o,sender_plan)
    prior_sender=strict(o.pinned(SENDER_PROOF))
    need(prior_sender==sender,'actual fresh sender audit differs from independent original proof')
    need(sender['send_attempt_count']==0 and sender['original_sender_ssh_returncode']==2
        and sender['selected_previous04_checksum_and_identity_verified'] is True
        and sender['exact_original_draft_restored'] is True and sender['draft_restore_attempts']==1
        and sender['host_parent_wait_receipt_available'] is False
        and sender['host_child_wait_returned_claimed'] is False
        and sender['original_UI_activity_performed'] is True and sender['UI_zero_claimed'] is False,
        'original sender no-Send or restore facts differ')
    own=o.pinned(plan['closer_source'])
    sources={'verifier':VERIFIER['sha256'],'closer':sha(own),'sender_verifier':SENDER['sha256'],
        'capture':CAPTURE_SOURCE['sha256'],'capture_driver':DRIVER['sha256']}
    o.recheck();Sender.recheck_sender_directories(o)
    observations={'capture_provenance':provenance,'package_and_root':packageproof,
        'role_lifecycle':roleproof,'pre_native_absence':absenceproof,
        'inventory_preservation':inventoryproof,'sender_no_send':sender}
    originals={**FIXED,'archive':execution['archive'],'capture':execution['capture'],
               'closure_plan':plan['__original_descriptor__'],'closer_source':plan['closer_source']}
    closed={'schema':'hepta.native-guard.non-native-attempt-closure.v1',
        'state':'ORIGINAL_PRE_NATIVE_ATTEMPT_FAILED_CLOSED','label':LABEL,'nonce':NONCE,
        'boot_id':V.BOOT,'owner_request_sha256':V.OWNER,'package':V.PACKAGE,'combination':V.COMBINATION,
        'lease':V.LEASE,'runtime_policy_sha256':V.POLICY,'policy_adoption_sha256':V.ADOPTION,
        'retirement':lease['retirement'],'native_predecessor':lease['prior_boundary'],
        'roots':after['roots'],'private_roots':[HOME,JOURNAL,FIXTURE],
        'component_role_identities':V.ROLES,'after_inventory':V.AFTER,
        'sources':sources,'facts':dict(V.FACTS),'verified_checks':{k:True for k in V.CHECKS},
        'capture':V.CAPTURE,'archive':V.ARCHIVE,'originals':originals,'observations':observations,
        'input_originals':[o.rows[k] for k in sorted(o.rows)]}
    raw=V.encoded(closed);inventory_raw=files['after/AFTER-INVENTORY.json']
    V.validate_closed_attempt(raw,inventory_raw,expected_sources=sources)
    return raw,inventory_raw,len(o.rows),Sender


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--plan');p.add_argument('--plan-sha256');p.add_argument('--out')
    g=p.add_mutually_exclusive_group()
    g.add_argument('--prepare-host-plan-once',action='store_true')
    g.add_argument('--execute-host-close-once',action='store_true')
    a=p.parse_args()
    if not (a.prepare_host_plan_once or a.execute_host_close_once):
        print(json.dumps({'state':'PREVIEW_ONLY','host_reads':0,'host_writes':0,'phone_calls':0,
            'native_case_created':False,'nonces_generated':0},sort_keys=True));return 0
    o=Originals()
    if a.prepare_host_plan_once:
        need(not a.plan and not a.plan_sha256 and a.out,'fresh explicit host plan output required')
        value=plan_value(o)
        for row in FIXED.values():o.pinned(row)
        o.recheck();out=Path(a.out)
        need(out.parent==CANDIDATE and out.name=='inputs','fixed new candidate input directory required')
        newdir(out);raw=enc(value);put(out/'PLAN.json',raw)
        print(json.dumps({'state':'HOST_CLOSURE_PLAN_PREPARED_NOT_EXECUTED',
            'plan':{'path':str(out/'PLAN.json'),**pin(raw)},'phone_calls':0},sort_keys=True));return 0
    need(a.plan and a.plan_sha256 and a.out,'explicit source-bound actual host closure plan required')
    plan_raw=o.read(Path(a.plan),262144);need(sha(plan_raw)==a.plan_sha256,'explicit closure plan SHA differs')
    value=strict(plan_raw);need(value==plan_value(o),'fixed source-bound actual closure plan differs')
    value['__original_descriptor__']={'path':a.plan,**pin(plan_raw)}
    raw,inventory,count,Sender=close(o,value)
    out=Path(a.out);need(out.parent==DEST and re.fullmatch(r'closed-[0-9]{2}',out.name),
                         'fixed independent closure output root required')
    o.recheck();Sender.recheck_sender_directories(o)
    if not DEST.exists():newdir(DEST)
    need(DEST.resolve(strict=True)==DEST and stat.S_IMODE(DEST.stat().st_mode)==0o700,
         'private closure root differs')
    newdir(out)
    for name,body in [('PLAN.original.json',plan_raw),('CLOSURE.original.json',raw),
                      ('AFTER-INVENTORY.original.json',inventory)]:put(out/name,body)
    result={'schema':'hepta.native-guard.attempt05.non-native-host-close-result.v1',
        'state':'ORIGINAL_PRE_NATIVE_ATTEMPT_FAILED_CLOSED_PENDING_PUBLICATION',
        'closure':{'path':str(out/'CLOSURE.original.json'),**pin(raw)},
        'inventory':{'path':str(out/'AFTER-INVENTORY.original.json'),**pin(inventory)},
        'input_original_count':count,'native_case_count':0,'native_scope_assigned':False,
        'component_qualified':False,'phone_calls':0,'automatic_retry':False}
    result_raw=enc(result);put(out/'RESULT.json',result_raw)
    print(json.dumps(result,sort_keys=True),flush=True);return 0


if __name__=='__main__':raise SystemExit(main())
