#!/usr/bin/env python3
"""Retain actual comparison proof and prepare explicit adoption inputs.

p4-proof reads an actually completed 16-check comparison, validates the reviewed
small proof, and creates exact original archives. mac-inputs consumes the two
transferred proof archives and the actual Mac live stage, preserves origin maps,
and creates reviewed adoption-helper entries. No phone, child process, policy
parser, service operation, or policy adoption is executed by this helper.
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

META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')


def need(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def enc(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def bp(row):return {k:row[k] for k in ('bytes','sha256')}
def desc(path,raw):return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}
def key(row):return (row['path'],row['bytes'],row['sha256'])
def strict(raw):
    def pairs(rows):
        value={}
        for name,item in rows:need(name not in value,'duplicate JSON key');value[name]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def fresh(path):
    need(path.is_absolute() and '..' not in path.parts and path.parent.resolve(strict=True)==path.parent
         and not path.exists() and not path.is_symlink(),'new canonical output required')
    os.umask(0o077);path.mkdir(mode=0o700);sync(path.parent)
def put(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    sync(path.parent);need(path.read_bytes()==raw,'created original readback differs');return desc(path,raw)
def relative(name):
    q=PurePosixPath(name)
    need(isinstance(name,str) and name==str(q) and not q.is_absolute() and '\0' not in name
         and all(p not in ('','.','..') for p in q.parts),'exact safe relative member')
    return q


class Originals:
    def __init__(self):self.seen={}
    def read(self,row):
        need(type(row) is dict and set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int
             and 0<=row['bytes']<=256*1024*1024 and isinstance(row['sha256'],str)
             and re.fullmatch('[0-9a-f]{64}',row['sha256']),'bounded exact descriptor')
        path=Path(row['path']);need(path.is_absolute() and path.resolve(strict=True)==path,'canonical original')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==row['bytes'],'regular original')
            with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(row['bytes']+1)
            z,n=os.fstat(fd),path.lstat();meta=[getattr(a,k) for k in META]
            need(meta==[getattr(z,k) for k in META]==[getattr(n,k) for k in META],'original read raced')
        finally:os.close(fd)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'original bytes differ: '+str(path))
        record={'descriptor':row,'metadata':meta}
        need(str(path) not in self.seen or self.seen[str(path)]==record,'original changed between reads')
        self.seen[str(path)]=record;return raw
    def known(self,path):
        need(path.is_absolute() and path.resolve(strict=True)==path,'canonical discovered original')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=256*1024*1024,
                 'bounded regular discovered original')
            with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(before.st_size+1)
            meta=[getattr(before,k) for k in META]
            need(len(raw)==before.st_size and meta==[getattr(os.fstat(fd),k) for k in META]
                 ==[getattr(path.lstat(),k) for k in META],'discovered original read raced')
        finally:os.close(fd)
        row=desc(path,raw);record={'descriptor':row,'metadata':meta}
        need(str(path) not in self.seen or self.seen[str(path)]==record,'discovered original changed')
        self.seen[str(path)]=record;return row
    def recheck(self):
        for item in list(self.seen.values()):self.read(item['descriptor'])


def verifier(row,raw):
    need(0<len(raw)<=131072,'bounded actual verifier source')
    module=types.ModuleType('reviewed_actual_runtime_properties_proof_verifier')
    module.__file__=row['path'];module.__reviewed_source_sha256__=row['sha256']
    exec(compile(raw,row['path'],'exec'),module.__dict__);return module


def pack_rows(rows,read):
    buffer=io.BytesIO();total=0
    with gzip.GzipFile(fileobj=buffer,mode='wb',mtime=0) as compressed:
        with tarfile.open(fileobj=compressed,mode='w|',format=tarfile.USTAR_FORMAT) as archive:
            for name,row in rows:
                relative(name);raw=read(row);total+=len(raw)
                need(total<=256*1024*1024,'bounded complete comparison tree')
                info=tarfile.TarInfo(name);info.size=len(raw);info.uid=info.gid=info.mtime=0;info.mode=0o600
                archive.addfile(info,io.BytesIO(raw))
    raw=buffer.getvalue();need(len(raw)<=256*1024*1024,'bounded archive');return raw


def complete_archive(o,actual,out):
    need(actual.is_absolute() and actual.resolve(strict=True)==actual and actual.is_dir(),
         'actual comparison output directory required')
    rows=[];directories={}
    def walk(directory):
        status=directory.lstat();need(stat.S_ISDIR(status.st_mode) and not directory.is_symlink(),'real comparison directory')
        children=sorted(directory.iterdir(),key=lambda p:p.name)
        directories[str(directory)]=[p.name for p in children]
        for child in children:
            s=child.lstat()
            if stat.S_ISDIR(s.st_mode):walk(child)
            else:
                need(stat.S_ISREG(s.st_mode) and not child.is_symlink(),'comparison archive has an unreviewed object')
                row=o.known(child);name=str(child.relative_to(actual));relative(name)
                rows.append((name,row));need(len(rows)<=2048,'bounded complete comparison member count')
    walk(actual)
    raw=pack_rows(rows,o.read)
    for name,children in directories.items():
        need(sorted(p.name for p in Path(name).iterdir())==children,'complete comparison namespace changed')
    o.recheck()
    manifest={'schema':'hepta.runtime-properties.complete-comparison-archive-manifest.v1',
        'original_root':str(actual),'members':[{'member':name,'original':row} for name,row in rows],
        'file_count':len(rows),'complete_original_tree_rechecked':True,'phone_operations':0,'active_policy_writes':0}
    return raw,enc(manifest),desc(out/'COMPLETE-COMPARISON.tar.gz',raw),desc(out/'COMPLETE-ARCHIVE-MANIFEST.json',enc(manifest))


def live_summary(V,o,plan):
    index={};paths=set()
    for item in plan['input_original_map']:
        a,b=item['original'],item['retained']
        need(a['path'] not in paths and key(a) not in index and bp(a)==bp(b),'exact live original mapping')
        paths.add(a['path']);index[key(a)]=b
    def get(row):need(key(row) in index,'missing explicit live origin');return o.read(index[key(row)])
    raw=o.read(plan['live_provenance_inputs'])
    return V.verify_live_capture(strict(raw),read_pinned=get),raw


def p4_proof(a):
    o=Originals();execution_row=strict(a.execution_desc);vrow=strict(a.verifier_desc)
    V=verifier(vrow,o.read(vrow));execution=strict(o.read(execution_row))
    kinds={'ACTUAL_HOST_CONSTRUCTION_AND_COMPLETE_COMPARISON_FINISHED':'offline_candidate',
           'ACTUAL_HOST_POST_LIVE_COMPLETE_COMPARISON_FINISHED':'post_live_export'}
    need(execution.get('state') in kinds and execution['check_count']==execution['passed_count']==16,
         'actually completed sixteen-check comparison required')
    kind=kinds[execution['state']];plan=strict(o.read(execution['plan']));report=strict(o.read(execution['report']))
    actual=Path(execution_row['path']).parent
    need(Path(execution['comparison_process']['path']).parent==actual
         and Path(execution['report']['path']).parent==actual/'comparison'
         and not a.out.is_relative_to(actual),'new proof output must be outside the original execution tree')
    records={}
    def add(row):
        raw=o.read(row);old=records.get(row['path'])
        need(old is None or old[0]==row,'same original path has different pins');records[row['path']]=(row,raw);return raw
    for row in (execution['report'],execution['plan'],execution['comparison_process'],execution_row):add(row)
    for name in ('root_scope_decision','parent_adoption','delta_rule','parent_rule','full_rule'):add(plan[name])
    for name in ('comparator','image_comparator','image_comparator_source','existing_tools','candidate_av_tool','candidate_av_source'):
        add(report['sources'][name])
    add(execution['source'])
    outer=strict(add(execution['comparison_process']))
    add(outer['stdout']);add(outer['stderr'])
    children={Path(row['path']).name:row for row in report['retained_originals']}
    need(len(children)==len(report['retained_originals']),'duplicate comparison original child filename')
    labels=['complete-image']+['candidate-complete-av-%02d'%i for i in range(1,12)]+[
        'candidate-property-set-deny-%02d'%i for i in range(1,12)]+['candidate-existing-apex-search']
    for label in labels:
        process=strict(add(children[label+'.PROCESS.json']))
        need(process['stdout']==children[label+'.stdout.original'] and process['stderr']==children[label+'.stderr.original'],
             'actual child process/stream index differs')
        add(process['stdout']);add(process['stderr'])
    for row in plan['parent_av_originals']+plan['parent_set_av_originals']+[plan['parent_apex_original']]:add(row)
    summary=live_raw=None
    if kind=='offline_candidate':
        receipt=strict(add(plan['construction_receipt']));build_row=receipt['build_result']
        construction=strict(add(receipt['process']));add(construction['stdout']);add(construction['stderr'])
    else:
        need(bp(plan['live_verifier_source'])==bp(vrow),'post used another actual verifier')
        add(plan['live_verifier_source']);add(plan['live_provenance_inputs']);build_row=plan['image_build_result']
        summary,live_raw=live_summary(V,o,plan)
    build=strict(add(build_row));add(build['stdout']);add(build['stderr'])
    need(sum(len(raw) for row,raw in records.values())<=16*1024*1024,'small proof exceeds existing consumer bound')
    archive,manifest,archive_row,manifest_row=complete_archive(o,actual,a.out)
    originals=[row for row,raw in sorted(records.values(),key=lambda pair:pair[0]['path'])]
    index={'schema':'hepta.runtime-properties-r10.adoption-proof-inputs.v1','comparison_kind':kind,
        'report':execution['report'],'plan':execution['plan'],'process':execution['comparison_process'],
        'execution':execution_row,'files':originals,
        'origin_map':[{'original':row,'retained':row} for row in originals],
        'complete_archive':archive_row,'complete_archive_manifest':manifest_row,
        'complete_comparison_outputs_retained_elsewhere':True,'all_orbit_images_embedded':False,
        'phone_operations':0,'active_policy_writes':0}
    index_raw=V.encoded(index)
    result=V.verify_comparison_proof(index_raw,expected_kind=kind,read_pinned=o.read,
        decision_raw=o.read(plan['root_scope_decision']),live_summary=summary,live_inputs_raw=live_raw)
    o.recheck()
    validation={'state':'ACTUAL_COMPARISON_SMALL_PROOF_VERIFIED_HOST_ONLY','comparison_kind':kind,
        'original_execution':execution_row,'original_report':execution['report'],
        'small_originals_read':result['small_originals_read'],'small_original_bytes':result['small_original_bytes'],
        'all_orbit_images_read_by_consumer':False,'complete_tree_archive':archive_row,
        'phone_calls':0,'policy_writes':0,'policy_adoption_authorized':False}
    index_row=desc(a.out/'PROOF-INDEX.json',index_raw)
    exported={'proof/PROOF-INDEX.original.json':index_raw,'proof/VALIDATION.original.json':enc(validation)}
    mapping=[]
    for i,(row,raw) in enumerate(sorted(records.values(),key=lambda pair:pair[0]['path'])):
        member='files/%04d-'%i+re.sub('[^A-Za-z0-9._-]','_',Path(row['path']).name)[:85]
        exported[member]=raw;mapping.append({'original':row,'member':member})
    export={'schema':'hepta.runtime-properties.small-proof-export.v1','comparison_kind':kind,
        'proof_index_original':index_row,'originals':mapping,
        'files':[{'path':name,'bytes':len(raw),'sha256':sha(raw)} for name,raw in sorted(exported.items())],
        'complete_archive':archive_row,'complete_archive_manifest':manifest_row,
        'phone_operations':0,'active_policy_writes':0}
    exported['PROOF-EXPORT.json']=enc(export)
    packed=pack_rows([(name,raw) for name,raw in sorted(exported.items())],lambda raw:raw)
    if not a.execute_host_proof:
        print(json.dumps({**validation,'state':'ACTUAL_PROOF_PREVIEW_NO_OUTPUT','proof_export_bytes':len(packed)},sort_keys=True));return 0
    fresh(a.out);put(a.out/'COMPLETE-COMPARISON.tar.gz',archive);put(a.out/'COMPLETE-ARCHIVE-MANIFEST.json',manifest)
    put(a.out/'PROOF-INDEX.json',index_raw);put(a.out/'PROOF-VALIDATION.json',enc(validation))
    export_row=put(a.out/'PROOF-EXPORT.tar.gz',packed);o.recheck()
    print(json.dumps({**validation,'proof_index':index_row,'proof_export':export_row,
        'complete_archive_manifest':manifest_row},sort_keys=True));return 0


def decode_export(o,row):
    packed=o.read(row);files={};total=0
    with tarfile.open(fileobj=io.BytesIO(packed),mode='r:gz') as archive:
        for item in archive:
            relative(item.name);need(item.isfile() and item.name not in files and 0<=item.size<=16*1024*1024
                and len(files)<520,'bounded regular small proof member')
            total+=item.size;need(total<=20*1024*1024,'bounded transferred small proof')
            with archive.extractfile(item) as stream:raw=stream.read(item.size+1)
            need(len(raw)==item.size,'complete small proof member');files[item.name]=raw
    manifest=strict(files['PROOF-EXPORT.json']);need(manifest['schema']=='hepta.runtime-properties.small-proof-export.v1',
        'actual small proof export required')
    rows=manifest['files'];need(len(rows)==len(files)-1
        and {r['path'] for r in rows}==set(files)-{'PROOF-EXPORT.json'},'exact small proof export inventory')
    for item in rows:need(bp(item)=={'bytes':len(files[item['path']]),'sha256':sha(files[item['path']])},'proof export member bytes')
    need(bp(manifest['proof_index_original'])==bp(desc(Path('/placeholder'),files['proof/PROOF-INDEX.original.json'])),
         'original P4 proof index bytes differ')
    index=strict(files['proof/PROOF-INDEX.original.json'])
    need(index['comparison_kind']==manifest['comparison_kind'] and index['complete_archive']==manifest['complete_archive']
        and index['complete_archive_manifest']==manifest['complete_archive_manifest'],'proof complete-evidence references differ')
    origins={}
    for item in manifest['originals']:
        original=item['original'];member=item['member'];raw=files[member]
        need(key(original) not in origins and bp(original)=={'bytes':len(raw),'sha256':sha(raw)},'original proof copy differs')
        origins[key(original)]=(original,raw)
    need({key(row) for row in index['files']}==set(origins),'complete required P4 small proof originals missing')
    need(index['origin_map']==[{'original':row,'retained':row} for row in index['files']],
         'export must retain the unmodified P4-origin proof index')
    return manifest,index,origins,files


def mac_inputs(a):
    o=Originals();stage_result_row=strict(a.post_stage_result_desc);stage_result=strict(o.read(stage_result_row))
    need(stage_result['state']=='ACTUAL_LIVE_CHAIN_POST_STAGE_WRITTEN_HOST_ONLY','actual completed live stage required')
    freeze=strict(o.read(stage_result['freeze_result']));live_raw=o.read(stage_result['live_provenance']);live=strict(live_raw)
    captured_v=live['originals']['policy_runtime_properties_verifier.original.py'];V=verifier(captured_v,o.read(captured_v))
    need(captured_v['sha256']==freeze['verifier_sha256'],'final captured verifier differs')
    live_state=V.verify_live_capture(live,read_pinned=o.read)
    stage_dir=Path(stage_result_row['path']).parent
    stage_manifest=strict(o.read({'path':str(stage_dir/'STAGE-MANIFEST.original.json'),**bp(stage_result['stage_manifest'])}))
    seed_row=next(r for r in stage_manifest['files'] if r['path']=='POST-SEED.json')
    seed=strict(o.read({'path':str(stage_dir/'POST-SEED.original.json'),**bp(seed_row)}))
    aliases={};alias_paths={};planned={}
    def alias(original,retained):
        need(bp(original)==bp(retained),'retained alias changed bytes')
        old=aliases.get(key(original));need(old is None or old==retained,'ambiguous original alias')
        previous=alias_paths.get(original['path']);need(previous is None or previous==original,'original path changed pins')
        aliases[key(original)]=retained;alias_paths[original['path']]=original
    for row in seed['input_original_map']:alias(row['retained'],row['original'])
    alias(seed['live_provenance_inputs'],stage_result['live_provenance'])
    offline_exec=strict(o.read(freeze['offline_execution']))
    alias(seed['offline_execution'],freeze['offline_execution'])
    alias(offline_exec['report'],freeze['offline_comparison'])
    def read(row):
        if key(row) in planned:return planned[key(row)]
        return o.read(row)
    indices={};exports={};new_files={}
    for kind,arg in (('offline_candidate',a.offline_proof_archive_desc),('post_live_export',a.post_proof_archive_desc)):
        manifest,index,origin_data,bodies=decode_export(o,strict(arg));need(index['comparison_kind']==kind,'explicit proof kind differs')
        prefix='offline' if kind=='offline_candidate' else 'post-live'
        remap={};used_retained=set()
        for i,(identity,(original,raw)) in enumerate(sorted(origin_data.items())):
            retained=aliases.get(identity)
            if retained is not None:need(read(retained)==raw,'actual existing Mac alias differs from transferred proof')
            else:
                name=prefix+'/files/%04d-'%i+re.sub('[^A-Za-z0-9._-]','_',Path(original['path']).name)[:85]
                retained=desc(a.out/name,raw);new_files[name]=raw;planned[key(retained)]=raw;alias(original,retained)
            need(key(retained) not in used_retained,'two distinct originals collapsed inside one proof')
            used_retained.add(key(retained));remap[identity]=retained
        mac_index=dict(index)
        for name in ('report','plan','process','execution'):mac_index[name]=remap[key(index[name])]
        mac_index['files']=[remap[key(row)] for row in index['files']]
        mac_index['origin_map']=[{'original':row,'retained':remap[key(row)]} for row in index['files']]
        index_raw=V.encoded(mac_index);index_row=desc(a.out/prefix/'ADOPTION-PROOF-INPUTS.json',index_raw)
        new_files[prefix+'/ADOPTION-PROOF-INPUTS.json']=index_raw;planned[key(index_row)]=index_raw
        new_files[prefix+'/PROOF-INDEX.p4.original.json']=bodies['proof/PROOF-INDEX.original.json']
        new_files[prefix+'/PROOF-EXPORT.original.json']=bodies['PROOF-EXPORT.json']
        verification=V.verify_comparison_proof(index_raw,expected_kind=kind,read_pinned=read,
            decision_raw=o.read(live['originals']['ROOT-SCOPE-DECISION.original.json']),
            live_summary=live_state if kind=='post_live_export' else None,
            live_inputs_raw=live_raw if kind=='post_live_export' else None)
        indices[kind]=index_row;exports[kind]={'complete_archive':mac_index['complete_archive'],
            'complete_archive_manifest':mac_index['complete_archive_manifest'],
            'small_originals_read':verification['small_originals_read'],'small_original_bytes':verification['small_original_bytes']}
    collection={'schema':'hepta.runtime-properties-r10.adoption-input-collection-plan.v1',
        'live_provenance':stage_result['live_provenance'],'offline_proof_inputs':indices['offline_candidate'],
        'post_live_proof_inputs':indices['post_live_export']}
    collection_raw=V.encoded(collection);collection_row=desc(a.out/'ADOPTION-COLLECTION-PLAN.json',collection_raw)
    new_files['ADOPTION-COLLECTION-PLAN.json']=collection_raw
    source_root=Path(freeze['source_manifest']['path']).parent
    source_manifest=strict(o.read(freeze['source_manifest']));source_rows={r['path']:r for r in source_manifest['files']}
    for name in ('make_runtime_properties_adoption_inputs.py','make_runtime_properties_adoption.py',
                 'runtime_properties_host_originals.py','policy_runtime_properties_verifier.py'):
        o.read({'path':str(source_root/'source'/name),**bp(source_rows['source/'+name])})
    inputs_entry={'executable':'/usr/bin/python3','argv':['-I','-B',
        str(source_root/'source/make_runtime_properties_adoption_inputs.py'),'--plan',collection_row['path'],
        '--plan-sha256',collection_row['sha256'],'--out',str(a.out/'ADOPTION-INPUTS.json'),'--execute-host-inputs'],
        'phone_calls':0,'policy_writes':0,'automatic_adoption':False}
    result={'state':'ACTUAL_ADOPTION_COLLECTION_PREVIEW_NO_OUTPUT','collection_plan':collection_row,
        'inputs_entry':inputs_entry,'actual_policy':live_state['actual_after_policy'],'proofs':exports,
        'policy_adoption_authorized':False,'phone_calls':0,'policy_writes':0,
        'adoption_source':str(source_root/'source/make_runtime_properties_adoption.py'),
        'adoption_arguments_after_actual_inputs_created':{'--inputs':str(a.out/'ADOPTION-INPUTS.json'),
            '--inputs-sha256':'MUST_HASH_THE_ACTUAL_NEW_ADOPTION_INPUTS',
            '--out':str(a.out/'POLICY-ADOPTION.json'),
            '--expected-actual-policy-sha256':live_state['actual_after_policy']['sha256'],
            '--execute-root-adoption':True}}
    o.recheck()
    if not a.execute_host_inputs:print(json.dumps(result,sort_keys=True));return 0
    fresh(a.out)
    for name,raw in sorted(new_files.items()):
        parent=a.out
        for part in relative(name).parts[:-1]:
            child=parent/part
            if not child.exists():child.mkdir(mode=0o700);sync(parent)
            need(child.resolve(strict=True)==child and child.is_dir(),'canonical new proof output');parent=child
        put(a.out/name,raw)
    put(a.out/'ADOPTION-INPUTS-ENTRY.json',enc(inputs_entry))
    for kind,index_row in indices.items():
        V.verify_comparison_proof(o.read(index_row),expected_kind=kind,read_pinned=o.read,
            decision_raw=o.read(live['originals']['ROOT-SCOPE-DECISION.original.json']),
            live_summary=live_state if kind=='post_live_export' else None,
            live_inputs_raw=live_raw if kind=='post_live_export' else None)
    o.recheck();result.update(state='ACTUAL_ADOPTION_COLLECTION_HOST_PREPARED_NOT_ADOPTED',
        original_bookends=list(o.seen.values()))
    result_row=put(a.out/'ADOPTION-COLLECTION-RESULT.json',enc(result))
    print(json.dumps({k:v for k,v in result.items() if k!='original_bookends'}|{'result':result_row},sort_keys=True));return 0


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='phase',required=True)
    p=sub.add_parser('p4-proof');p.add_argument('--execution-desc',required=True)
    p.add_argument('--verifier-desc',required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--execute-host-proof',action='store_true')
    p=sub.add_parser('mac-inputs');p.add_argument('--post-stage-result-desc',required=True)
    p.add_argument('--offline-proof-archive-desc',required=True);p.add_argument('--post-proof-archive-desc',required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--execute-host-inputs',action='store_true')
    a=parser.parse_args(argv);return {'p4-proof':p4_proof,'mac-inputs':mac_inputs}[a.phase](a)


if __name__=='__main__':raise SystemExit(main())
