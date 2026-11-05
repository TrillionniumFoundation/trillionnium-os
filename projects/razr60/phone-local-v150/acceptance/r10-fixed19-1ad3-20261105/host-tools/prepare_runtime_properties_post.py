#!/usr/bin/env python3
"""Prepare a real captured live policy for the independent P4 comparison.

mac-stage validates the actual captured transaction and creates an exact transfer
archive. unpack and p4-plan are create-only host operations. No phase contacts a
phone, starts a child, parses a policy image, adopts policy, or runs comparison.
Each write phase requires its explicit execute flag; previews only read files.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import types

B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
P4_ROOT = Path('/home/alex/razr60-local-model-v150/policy-runtime-properties-r10-r1')
OFFLINE = P4_ROOT/'offline-candidate01/actual-01'
META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
SOURCES = {
 'run_post_live_actual.py': (9767,'0f6cb3d1a73a59f880566f5adc1afaa285fcb5366ceebf3a5373caf3167518a1'),
 'post_live_compare_runtime_properties.py': (64188,'151a1d724a82d611202054eb0dd5326fe4f4311ff78599b61c6bf58d68a2cf8f'),
 'policy_runtime_properties_image.c': (22838,'da60ee90209a26216f053064a7ca47ebcb73c4730b4e00378886b5d653de09aa'),
}
POST_FIELDS = {'schema','root_scope_decision','parent_adoption','parent','candidate','image_build_result',
 'live_provenance_inputs','live_verifier_source','input_original_map','delta_rule','full_rule','parent_rule',
 'tool_inventory','image_comparator','image_comparator_source','parent_av_originals','parent_set_av_originals',
 'parent_apex_original','candidate_av_tool','candidate_av_source','secondary_observation'}


def need(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def enc(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def bp(row):return {k:row[k] for k in ('bytes','sha256')}
def desc(path,raw):return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}
def strict(raw):
    def pairs(rows):
        value={}
        for key,item in rows:need(key not in value,'duplicate JSON key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
def key(row):return (row['path'],row['bytes'],row['sha256'])
def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def put(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    sync(path.parent);need(path.read_bytes()==raw,'new original readback differs');return desc(path,raw)
def fresh(path):
    need(path.is_absolute() and '..' not in path.parts and path.parent.resolve(strict=True)==path.parent
        and not path.exists() and not path.is_symlink(),'new canonical host output required')
    os.umask(0o077);path.mkdir(mode=0o700);sync(path.parent)
def relative(name):
    q=PurePosixPath(name)
    need(isinstance(name,str) and name==str(q) and not q.is_absolute()
         and all(x not in ('','.','..') for x in q.parts) and '\0' not in name,'safe exact relative file name')
    return q
def p4_destination(path):
    need(path.is_absolute() and path.parent==P4_ROOT
         and re.fullmatch('post-live-[a-z0-9][a-z0-9-]{2,70}',path.name),'explicit fresh P4 post-live project root required')


class Originals:
    def __init__(self):self.seen={}
    def read(self,row):
        need(type(row) is dict and set(row)=={'path','bytes','sha256'}
             and type(row['bytes']) is int and 0<=row['bytes']<=128*1024*1024
             and isinstance(row['sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['sha256']),
             'exact bounded original descriptor required')
        path=Path(row['path'])
        need(path.is_absolute() and '..' not in path.parts and path.resolve(strict=True)==path,'canonical original')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==row['bytes'],'regular original size')
            with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(row['bytes']+1)
            z,n=os.fstat(fd),path.lstat();meta=[getattr(a,k) for k in META]
            need(meta==[getattr(z,k) for k in META]==[getattr(n,k) for k in META],'original read raced')
        finally:os.close(fd)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'original bytes differ: '+str(path))
        record={'descriptor':row,'metadata':meta}
        need(str(path) not in self.seen or self.seen[str(path)]==record,'original changed between reads')
        self.seen[str(path)]=record;return raw
    def known(self,path):
        need(path.is_absolute() and path.resolve(strict=True)==path,'canonical discovered original')
        s=path.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<=s.st_size<=128*1024*1024,'bounded discovered original')
        raw=path.read_bytes();row=desc(path,raw);self.read(row);return row
    def recheck(self):
        for item in list(self.seen.values()):self.read(item['descriptor'])


def load_verifier(row,raw):
    need(0<len(raw)<=131072,'bounded captured verifier')
    module=types.ModuleType('reviewed_actual_runtime_properties_post_verifier')
    module.__file__=row['path'];module.__reviewed_source_sha256__=row['sha256']
    exec(compile(raw,row['path'],'exec'),module.__dict__);return module


def archive_bytes(files):
    need(1<=len(files)<=520 and sum(map(len,files.values()))<=128*1024*1024,'bounded exact transfer payload')
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name,raw in sorted(files.items()):
            relative(name);item=tarfile.TarInfo(name);item.size=len(raw);item.mode=0o600
            item.uid=item.gid=item.mtime=0;archive.addfile(item,io.BytesIO(raw))
    packed=gzip.compress(buffer.getvalue(),mtime=0)
    need(len(packed)<=128*1024*1024,'bounded transfer archive');return packed


def mac_stage(a):
    out=a.out;p4_destination(a.p4_root)
    need(out.is_absolute() and out.parent.resolve(strict=True)==out.parent
         and not out.exists() and not out.is_symlink(),'new Mac stage output')
    o=Originals();freeze_desc=strict(a.freeze_result_desc);execution_desc=strict(a.root_execution_desc)
    freeze=strict(o.read(freeze_desc));execution=strict(o.read(execution_desc))
    need(freeze['state']=='EXACT_LITERAL_SOURCE_FREEZE_AND_PREPARATION_INPUTS_WRITTEN_HOST_ONLY'
         and execution['schema']=='hepta.root.runtime-properties-live-execution.v1'
         and execution['state']=='ORIGINAL_POLICY_APPLY_CAPTURED_PENDING_INDEPENDENT_COMPARISON'
         and execution['policy_apply_calls']==1 and execution['known_apply_error'] is None,
         'completed exact one-apply Root capture required')
    source_manifest=strict(o.read(freeze['source_manifest']))
    rows={r['path']:r for r in source_manifest['files']}
    expected_verifier=bp(rows['source/policy_runtime_properties_verifier.py'])
    host=strict(o.read(execution['host_capture']));capture_dir=Path(execution['host_capture']['path']).parent
    need(host['clean_apply_observed'] is True,'clean complete actual capture required')
    cap_row={'path':str(capture_dir/'originals/CAPTURE.json'),**bp(host['capture'])}
    cap=strict(o.read(cap_row));members={r['path']:r for r in cap['files']}
    need(len(members)==len(cap['files']),'capture member names duplicated')
    captured_verifier={'path':str(capture_dir/'originals/policy_runtime_properties_verifier.original.py'),
                       **expected_verifier}
    V=load_verifier(captured_verifier,o.read(captured_verifier))
    need(V.ROOT_DRIVER==bp(execution['driver_source']) and V.ROOT_SOURCE_PACKAGE==bp(execution['source_package'])
         and captured_verifier['sha256']==freeze['verifier_sha256'],'capture or Root final source differs')
    originals={}
    for name in sorted(V.MANDATORY_LIVE_FILES):
        need(name in members and '/' not in name and '\0' not in name,'exact flat actual captured original required')
        originals[name]={'path':str(capture_dir/'originals'/name),**bp(members[name])}
    live={'schema':'hepta.runtime-properties-r10.live-provenance-inputs.v1',
        **{k:execution[k] for k in ('prepared','host_capture','original_operation','actor_wrapper',
            'pre_live_expectation','root_plan','root_intent')},
        'root_execution':execution_desc,'archive':{'path':str(capture_dir/'ORIGINALS.tar.gz'),**bp(host['archive'])},
        'capture_manifest':cap_row,'originals':originals}
    used={}
    def get(row):
        raw=o.read(row);used[key(row)]=(row,raw);return raw
    summary=V.verify_live_capture(live,read_pinned=get)
    need(summary['actual_after_policy']==host['actual_live_policy'] and summary['policy_adoption_authorized'] is False,
         'actual export relationship differs')
    live_raw=V.encoded(live);live_host=desc(out/'LIVE-PROVENANCE-INPUTS.original.json',live_raw)
    files={};mapping=[];aliases={}
    for index,(identity,(row,raw)) in enumerate(sorted(used.items())):
        name='inputs/%04d-'%index+re.sub('[^A-Za-z0-9._-]','_',Path(row['path']).name)[:100]
        files[name]=raw;retained=desc(a.p4_root/name,raw)
        mapping.append({'original':row,'retained':retained});aliases[identity]=retained
    def retained(row):return aliases[key(row)]
    provenance_name='inputs/LIVE-PROVENANCE-INPUTS.original.json';files[provenance_name]=live_raw
    source_root=B/'policy-runtime-properties-r10-r1-source-final02/source'
    for name,pin in SOURCES.items():
        files['source/'+name]=o.read({'path':str(source_root/name),'bytes':pin[0],'sha256':pin[1]})
    self_row=o.known(Path(__file__).resolve());files['source/prepare_runtime_properties_post.py']=o.read(self_row)
    offline_exec_raw=o.read(freeze['offline_execution']);offline_exec=strict(offline_exec_raw)
    need(offline_exec['state']=='ACTUAL_HOST_CONSTRUCTION_AND_COMPLETE_COMPARISON_FINISHED'
         and offline_exec['check_count']==offline_exec['passed_count']==16,'actual offline execution required')
    seed={'schema':'hepta.runtime-properties.actual-post-seed.v1','p4_root':str(a.p4_root),
        'root_execution':execution_desc,'offline_execution':{'path':str(OFFLINE/'EXECUTION.RESULT.json'),
            **bp(freeze['offline_execution'])},
        'live_provenance_original':live_host,'live_provenance_inputs':desc(a.p4_root/provenance_name,live_raw),
        'live_verifier_source':retained(captured_verifier),'input_original_map':mapping,
        'root_scope_decision':retained(summary['root_scope_decision']),
        'parent_adoption':retained(summary['parent_adoption_history']),
        'parent':retained(summary['parent']),'candidate':retained(summary['candidate']),
        'delta_rule':retained(originals['runtime-properties.delta.rule']),
        'parent_rule':retained(originals['parent-candidate.rule']),
        'full_rule':retained(originals['full-candidate.rule']),
        'actual_export_observed':summary['actual_after_policy'],
        'offline_candidate':summary['binding']['offline_candidate'],
        'phone_calls':0,'policy_writes':0,'comparison_executed':False,'policy_adoption_authorized':False}
    files['POST-SEED.json']=enc(seed)
    stage={'schema':'hepta.runtime-properties.actual-post-stage.v1','p4_root':str(a.p4_root),
        'files':[{'path':name,'bytes':len(raw),'sha256':sha(raw)} for name,raw in sorted(files.items())],
        'phone_calls':0,'policy_writes':0,'comparison_executed':False}
    stage_raw=enc(stage);files['STAGE-MANIFEST.json']=stage_raw
    packed=archive_bytes(files);o.recheck()
    result={'state':'ACTUAL_LIVE_CHAIN_POST_STAGE_PREVIEW_NO_OUTPUT','actual_export':summary['actual_after_policy'],
        'offline_candidate':summary['binding']['offline_candidate'],'original_map_count':len(mapping),
        'p4_root':str(a.p4_root),'archive_bytes':len(packed),'archive_sha256':sha(packed),
        'stage_manifest':desc(a.p4_root/'STAGE-MANIFEST.json',stage_raw),
        'phone_calls':0,'policy_writes':0,'comparison_executed':False,'policy_adoption_authorized':False}
    if not a.execute_host_stage:print(json.dumps(result,sort_keys=True));return 0
    fresh(out);live_desc=put(out/'LIVE-PROVENANCE-INPUTS.original.json',live_raw)
    need(live_desc==live_host,'live provenance descriptor differs')
    archive=put(out/'P4-STAGE.tar.gz',packed)
    put(out/'STAGE-MANIFEST.original.json',stage_raw);put(out/'POST-SEED.original.json',files['POST-SEED.json'])
    o.recheck();result.update(state='ACTUAL_LIVE_CHAIN_POST_STAGE_WRITTEN_HOST_ONLY',archive=archive,
        live_provenance=live_desc,root_execution=execution_desc,freeze_result=freeze_desc,
        original_bookends=list(o.seen.values()),
        p4_plan_entry={'executable':'/usr/bin/python3','argv':['-I','-B',
            str(a.p4_root/'source/prepare_runtime_properties_post.py'),'p4-plan',
            '--stage-manifest-desc',json.dumps(desc(a.p4_root/'STAGE-MANIFEST.json',stage_raw),sort_keys=True),
            '--execute-host-plan']})
    result_desc=put(out/'POST-STAGE-RESULT.json',enc(result))
    print(json.dumps({k:v for k,v in result.items() if k!='original_bookends'}|{'result':result_desc},sort_keys=True));return 0


def unpack(a):
    p4_destination(a.out);o=Originals();packed=o.read(strict(a.archive_desc))
    files={};total=0
    with tarfile.open(fileobj=io.BytesIO(packed),mode='r:gz') as archive:
        for item in archive:
            relative(item.name)
            need(item.isfile() and item.name not in files and 0<=item.size<=64*1024*1024
                 and len(files)<520,'regular bounded exact archive member')
            total+=item.size;need(total<=128*1024*1024,'bounded expanded transfer')
            with archive.extractfile(item) as stream:raw=stream.read(item.size+1)
            need(len(raw)==item.size,'complete transfer member');files[item.name]=raw
    stage_raw=files['STAGE-MANIFEST.json'];need(sha(stage_raw)==a.manifest_sha256,'explicit stage manifest SHA')
    stage=strict(stage_raw);need(stage['schema']=='hepta.runtime-properties.actual-post-stage.v1'
        and stage['p4_root']==str(a.out),'declared stage destination differs')
    rows=stage['files'];need(len(rows)==len(files)-1
        and {r['path'] for r in rows}==set(files)-{'STAGE-MANIFEST.json'},'exact staged file set')
    for row in rows:need(bp(row)=={'bytes':len(files[row['path']]),'sha256':sha(files[row['path']])},'stage member bytes differ')
    o.recheck()
    if not a.execute_host_stage:
        print(json.dumps({'state':'EXACT_STAGE_ARCHIVE_PREVIEW_NO_OUTPUT','files':len(files),'phone_calls':0}));return 0
    fresh(a.out)
    for name,raw in sorted(files.items()):
        q=relative(name);parent=a.out
        for part in q.parts[:-1]:
            child=parent/part
            if not child.exists():child.mkdir(mode=0o700);sync(parent)
            need(child.resolve(strict=True)==child and child.is_dir(),'private stage parent');parent=child
        put(a.out/name,raw)
    o.recheck()
    print(json.dumps({'state':'EXACT_HOST_STAGE_CREATED_NO_COMPARISON','root':str(a.out),
        'stage_manifest':desc(a.out/'STAGE-MANIFEST.json',stage_raw),'files':len(files),
        'phone_calls':0,'policy_writes':0,'comparison_executed':False},sort_keys=True));return 0


def p4_plan(a):
    o=Originals();stage_row=strict(a.stage_manifest_desc);stage=strict(o.read(stage_row))
    root=Path(stage['p4_root']);p4_destination(root)
    need(Path(stage_row['path'])==root/'STAGE-MANIFEST.json'
         and stage['schema']=='hepta.runtime-properties.actual-post-stage.v1','actual complete stage required')
    staged={}
    for row in stage['files']:
        relative(row['path']);need(row['path'] not in staged,'duplicate stage row')
        staged[row['path']]=o.read({'path':str(root/row['path']),**bp(row)})
    need(staged['source/prepare_runtime_properties_post.py']==Path(__file__).resolve().read_bytes(),
         'actual stage preparer differs')
    for name,pin in SOURCES.items():need(desc(root/'source'/name,staged['source/'+name])==
        {'path':str(root/'source'/name),'bytes':pin[0],'sha256':pin[1]},'reviewed comparator source differs')
    seed=strict(staged['POST-SEED.json']);need(seed['p4_root']==str(root),'post seed destination differs')
    mappings=seed['input_original_map'];index={};original_paths=set()
    for row in mappings:
        original,retained=row['original'],row['retained'];identity=key(original)
        need(original['path'] not in original_paths and identity not in index and bp(original)==bp(retained),
             'cross-host original mapping differs')
        original_paths.add(original['path']);index[identity]=retained;o.read(retained)
    def get(row):need(key(row) in index,'unmapped live original');return o.read(index[key(row)])
    V=load_verifier(seed['live_verifier_source'],o.read(seed['live_verifier_source']))
    live_raw=o.read(seed['live_provenance_inputs']);live=strict(live_raw)
    summary=V.verify_live_capture(live,read_pinned=get)
    for name,field in (('parent','parent'),('candidate','candidate'),('root_scope_decision','root_scope_decision'),
                       ('parent_adoption_history','parent_adoption')):
        need(index[key(summary[name])]==seed[field],'post parser copy differs from actual captured original')
    need(summary['actual_after_policy']==seed['actual_export_observed'],'actual export pin changed in staging')
    offline=strict(o.read(seed['offline_execution']))
    need(offline['state']=='ACTUAL_HOST_CONSTRUCTION_AND_COMPLETE_COMPARISON_FINISHED'
         and offline['check_count']==offline['passed_count']==16,'actual successful offline execution required')
    old_plan=strict(o.read(offline['plan']));old_report_raw=o.read(offline['report'])
    V.verified_offline(old_report_raw,o.read(seed['root_scope_decision']))
    need(offline['candidate']==old_plan['candidate'] and bp(offline['candidate'])==seed['offline_candidate'],
         'immutable offline candidate relationship differs')
    plan={name:old_plan[name] for name in ('tool_inventory','image_comparator','image_comparator_source',
        'parent_av_originals','parent_set_av_originals','parent_apex_original',
        'candidate_av_tool','candidate_av_source','secondary_observation')}
    plan.update({name:seed[name] for name in ('root_scope_decision','parent_adoption','parent','candidate',
        'live_provenance_inputs','live_verifier_source','input_original_map','delta_rule','full_rule','parent_rule')})
    plan.update(schema='hepta.runtime-properties-r10.post-live-complete-policy-comparison-plan.v1',
                image_build_result=offline['build'])
    need(set(plan)==POST_FIELDS,'exact post comparison plan fields')
    for name,row in plan.items():
        if isinstance(row,dict) and set(row)=={'path','bytes','sha256'}:o.read(row)
        if name in ('parent_av_originals','parent_set_av_originals'):
            for item in row:o.read(item)
    build=strict(o.read(plan['image_build_result']))
    need(build['returncode']==0 and build['source']==plan['image_comparator_source']
         and build['binary']==plan['image_comparator'],'original proven image build linkage')
    for row in [build['stdout'],build['stderr'],build['compiler'],build['static_library'],
                build['runtime_library'],*build['installed_headers']]:o.read(row)
    for stream in ('stdout','stderr'):need(o.read(build[stream])==b'','original compiler stderr/stdout differs')
    o.recheck();out=root/'prepared-01';plan_raw=enc(plan);plan_desc=desc(out/'POST-PLAN.json',plan_raw)
    entry={'executable':'/usr/bin/python3','argv':['-I','-B',str(root/'source/run_post_live_actual.py'),
        '--plan',plan_desc['path'],'--plan-sha256',plan_desc['sha256'],'--out',str(root/'actual-01'),'--execute-host-only'],
        'maximum_comparison_seconds':780,'automatic_retry':False,'phone_operations':0,'active_policy_writes':0}
    result={'state':'ACTUAL_POST_PLAN_PREVIEW_NO_OUTPUT','post_plan':plan_desc,'entry':entry,
        'actual_export':summary['actual_after_policy'],'offline_candidate':seed['offline_candidate'],
        'live_provenance_inputs':seed['live_provenance_inputs'],'stage_manifest':stage_row,
        'phone_calls':0,'policy_writes':0,'comparison_executed':False,'policy_adoption_authorized':False}
    if not a.execute_host_plan:print(json.dumps(result,sort_keys=True));return 0
    fresh(out);put(out/'POST-PLAN.json',plan_raw);put(out/'POST-COMPARISON-ENTRY.json',enc(entry));o.recheck()
    result.update(state='ACTUAL_POST_PLAN_HOST_PREPARED_NOT_EXECUTED',original_bookends=list(o.seen.values()))
    result_desc=put(out/'POST-PREPARATION-RESULT.json',enc(result))
    print(json.dumps({k:v for k,v in result.items() if k!='original_bookends'}|{'result':result_desc},sort_keys=True));return 0


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='phase',required=True)
    p=sub.add_parser('mac-stage');p.add_argument('--freeze-result-desc',required=True)
    p.add_argument('--root-execution-desc',required=True);p.add_argument('--p4-root',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--execute-host-stage',action='store_true')
    p=sub.add_parser('unpack');p.add_argument('--archive-desc',required=True)
    p.add_argument('--manifest-sha256',required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--execute-host-stage',action='store_true')
    p=sub.add_parser('p4-plan');p.add_argument('--stage-manifest-desc',required=True)
    p.add_argument('--execute-host-plan',action='store_true')
    a=parser.parse_args(argv)
    return {'mac-stage':mac_stage,'unpack':unpack,'p4-plan':p4_plan}[a.phase](a)


if __name__=='__main__':raise SystemExit(main())
