#!/usr/bin/env python3
"""Archive one completed runtime-properties post comparison without rerunning it.

All policy orbit bytes and source/input trees remain in a separate complete
archive. The explicit small proof index includes the originals actually consumed
by the adoption verifier, including original live inputs and the captured verifier.
This source has no compiler, parser, query, network, phone, or policy-write call.
"""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

BASE=Path('/home/alex/razr60-local-model-v150/policy-runtime-properties-r10-r1')
ROOT=BASE/'independent-post-source01/source'
ACTUAL=BASE/'post-live-root02-actual01'
INPUT_ROOT=BASE/'post-live-root02-inputs01'
SOURCE_ROOT=BASE/'post-live-root02-independent-evidence-source01'
OUT=BASE/'post-live-root02-independent-evidence01'
POST_SHA='85f325f9525c3470b2fbfe1bf7167f80a54febcffd87d08d2e6cbcdde4597471'
RUNNER_SHA='0793b960f8aed79421097cc8be5ab465ce49a080af1231fbcd9b51e6a4209d6e'
PARENT_SHA='50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
# A separate reviewed revision may bind only actual completed post originals.
ACTUAL_COMPLETION=None

def need(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def enc(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def meta(s):return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def put(path,raw):
    if not isinstance(raw,bytes):raw=enc(raw)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    sync(path.parent);need(path.read_bytes()==raw,'archive output readback')
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}

class Originals:
    def __init__(self):self.rows={};self.objects={};self.directories={}
    def read(self,path,expected=None):
        p=Path(path);need(p.is_absolute() and p.resolve(strict=True)==p,'canonical original')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=64*1024*1024,'bounded single-link original')
            with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(a.st_size+1)
            need(meta(a)==meta(os.fstat(fd))==meta(p.lstat()) and len(raw)==a.st_size,'original changed during archive read')
        finally:os.close(fd)
        d={'path':str(p),'bytes':len(raw),'sha256':sha(raw)}
        need(expected is None or d==expected,'exact original pin differs')
        row={'descriptor':d,'metadata':meta(a),'archive_at':'objects/'+d['sha256']}
        need(str(p) not in self.rows or self.rows[str(p)]==row,'source generation changed')
        need(d['sha256'] not in self.objects or self.objects[d['sha256']]==raw,'SHA alias bytes differ')
        self.rows[str(p)]=row;self.objects[d['sha256']]=raw
        need(len(self.rows)<=2048 and sum(len(b) for b in self.objects.values())<=256*1024*1024,'bounded complete original archive')
        return raw,d
    def descriptor(self,d):
        need(type(d) is dict and set(d)=={'path','bytes','sha256'},'exact three-field original')
        return self.read(d['path'],d)[0]
    def tree(self,path):
        p=Path(path);a=p.lstat();need(stat.S_ISDIR(a.st_mode) and p.resolve(strict=True)==p,'canonical archive tree')
        names=sorted(os.listdir(p));row={'metadata':meta(a),'names':names};self.directories[str(p)]=row
        for name in names:
            q=p/name;s=q.lstat()
            if stat.S_ISDIR(s.st_mode):self.tree(q)
            else:self.read(q)
        need(meta(p.lstat())==row['metadata'] and sorted(os.listdir(p))==names,'archive tree changed')
    def recheck(self):
        for row in list(self.rows.values()):self.descriptor(row['descriptor'])
        for p,row in self.directories.items():
            need(meta(Path(p).lstat())==row['metadata'] and sorted(os.listdir(p))==row['names'],'archive directories changed')


def strict(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate JSON key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))

def contained_descriptors(value):
    if type(value) is dict:
        if set(value)=={'path','bytes','sha256'}:
            need(type(value['path']) is str and Path(value['path']).is_absolute()
                 and type(value['bytes']) is int and 0<=value['bytes']<=64*1024*1024
                 and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['sha256']),
                 'exact contained original descriptor')
            yield value
        else:
            for child in value.values():yield from contained_descriptors(child)
    elif type(value) is list:
        for child in value:yield from contained_descriptors(child)


def require_actual_completion():
    value=ACTUAL_COMPLETION
    need(type(value) is dict and set(value)=={'report','execution','controller_job_id'},
         'actual post completion remains unpublished')
    for key,path in (('report',ACTUAL/'comparison/RESULT.json'),('execution',ACTUAL/'EXECUTION.RESULT.json')):
        row=value[key]
        need(type(row) is dict and set(row)=={'path','bytes','sha256'}
             and row['path']==str(path) and type(row['bytes']) is int and 0<row['bytes']<=64*1024*1024
             and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
             'only exact actual post originals may be collected')
    need(type(value['controller_job_id']) is str and 1<=len(value['controller_job_id'])<=80,
         'actual original controller identity required')
    return value

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request',type=Path,required=True)
    parser.add_argument('--request-sha256',required=True)
    parser.add_argument('--execute-host-archive',action='store_true')
    a=parser.parse_args(argv)
    if not a.execute_host_archive:
        print(json.dumps({'state':'PREVIEW_NO_ORIGINAL_READ_NO_ARCHIVE','phone_operations':0,
            'active_policy_writes':0,'parser_or_query_executions':0}));return 0
    actual=require_actual_completion()
    os.umask(0o077);sys.dont_write_bytecode=True;o=Originals()
    source_raw,collector_source=o.read(Path(__file__).resolve())
    request_raw,request_desc=o.read(a.request)
    need(request_desc['sha256']==a.request_sha256 and re.fullmatch('[0-9a-f]{64}',a.request_sha256),'explicit archive request original')
    request=strict(request_raw)
    need(set(request)=={'schema','collector_source','report','execution','controller_status','controller_read','controller_job_id'}
         and request['schema']=='hepta.runtime-properties-r10.post-comparison-archive-request.v1'
         and request['collector_source']==collector_source,'exact current collector request')
    need(all(request[k]==actual[k] for k in actual),'actual post completion pins differ')
    need(request['report']['path']==str(ACTUAL/'comparison/RESULT.json')
         and request['execution']['path']==str(ACTUAL/'EXECUTION.RESULT.json'),'only the original Root02 post process')
    report_desc=request['report'];execution_desc=request['execution']
    report_raw=o.descriptor(report_desc);execution_raw=o.descriptor(execution_desc)
    report=strict(report_raw);execution=strict(execution_raw)
    need(report['schema']=='hepta.runtime-properties-r10.complete-policy-comparison.v1'
         and report['state']=='EXACT_APPROVED_RUNTIME_PROPERTY_READ_DELTA_VERIFIED'
         and report['check_count']==report['passed_count']==len(report['checks'])==16
         and all(r['passed'] is True for r in report['checks'])
         and report['comparison_kind']=='post_live_export'
         and report['parent']['sha256']==PARENT_SHA
         and report['sources']['comparator']['sha256']==POST_SHA,
         'complete actual independent post comparison required')
    need(execution['schema']=='hepta.runtime-properties.actual-host-execution.v1'
         and execution['state']=='ACTUAL_HOST_POST_LIVE_COMPLETE_COMPARISON_FINISHED'
         and type(execution['returncode']) is int and execution['returncode']==0
         and execution['timed_out'] is False and execution['captured_streams_complete'] is True
         and execution['all_originals_rechecked'] is True and execution['automatic_retry'] is False
         and execution['source']['sha256']==RUNNER_SHA and execution['source']['bytes']==9767
         and execution['report']==report_desc and execution['parent']==report['parent']
         and execution['candidate']==report['candidate'],'original reviewed outer process terminal')
    controller_status_raw=o.descriptor(request['controller_status'])
    controller_read_raw=o.descriptor(request['controller_read'])
    status=strict(controller_status_raw);read=strict(controller_read_raw)
    need(type(request['controller_job_id']) is str and len(request['controller_job_id'])<=80
         and status['job_id']==read['job_id']==request['controller_job_id']
         and status['state']=='succeeded' and type(status['exit_code']) is int and status['exit_code']==0
         and status['output_complete'] is True and status['output_durable'] is True
         and status['timed_out'] is False and status['log_bytes']['stderr']['stored']==0,
         'authoritative original controller terminal')
    stdout=read['stdout'];stderr=read['stderr'];summary_raw=stdout['text'].encode('utf-8')
    need(stdout['offset']==0 and stdout['eof'] is True
         and stdout['next_offset']==stdout['size']==len(summary_raw)==status['log_bytes']['stdout']['stored']
         and status['log_bytes']['stdout']['seen']==len(summary_raw)
         and bytes.fromhex(stdout['bytes_hex'])==summary_raw
         and stderr['text']=='' and stderr['eof'] is True and stderr['size']==0
         and stderr['bytes_hex']=='','complete lossless original controller streams')
    summary=strict(summary_raw)
    need(summary['state']=='ACTUAL_HOST_POST_LIVE_COMPLETE' and summary['report']==report_desc
         and summary['execution']==execution_desc and summary['candidate']==report['candidate']
         and summary['checks']==16,'controller stdout original output linkage')
    plan_desc=execution['plan'];plan=strict(o.descriptor(plan_desc))
    process_desc=execution['comparison_process'];process=strict(o.descriptor(process_desc))
    need(plan['schema']=='hepta.runtime-properties-r10.post-live-complete-policy-comparison-plan.v2'
         and process['returncode']==0 and process['timed_out'] is False
         and process['captured_streams_complete'] is True and process['automatic_retry'] is False
         and process['input_originals_before']==process['input_originals_after'],
         'actual post child terminal and source bookends')
    expected_argv=['/usr/bin/python3','-I','-B',report['sources']['comparator']['path'],
        '--plan',plan_desc['path'],'--plan-sha256',plan_desc['sha256'],
        '--out',str(ACTUAL/'comparison'),'--execute-host-only']
    need(process['argv']==expected_argv and plan['parent']==report['parent']
         and plan['candidate']==report['candidate'],'actual comparator invocation or policy inputs differ')
    # Preserve complete current sources, retained cross-host originals, all
    # normalized/orbit images, and every other actual comparison output.
    for root in (ROOT,ACTUAL,INPUT_ROOT,SOURCE_ROOT):o.tree(root)
    for record in process['input_originals_before'].values():o.descriptor(record['descriptor'])
    for key in ('parent','candidate'):o.descriptor(report[key])
    for row in report['full_av_checks']['runtime_libraries']:o.descriptor(row)
    inv=strict(o.descriptor(plan['tool_inventory']))
    for row in [*inv['package_files'],*inv['readers'].values()]:o.descriptor(row)
    for item in plan['input_original_map']:o.descriptor(item['retained'])
    build_desc=plan['image_build_result'];build=strict(o.descriptor(build_desc))
    need(execution['build']==build_desc and report['sources']['image_build_result']==build_desc,
         'original image build descriptor differs')
    for row in contained_descriptors(build):o.descriptor(row)
    proof={}
    def add(d):
        o.descriptor(d);need(d['path'] not in proof or proof[d['path']]==d,'proof descriptor collision');proof[d['path']]=d
    for d in (report_desc,plan_desc,process_desc,execution_desc,execution['source'],build_desc,collector_source,request_desc):add(d)
    for d in report['sources'].values():add(d)
    for key in ('root_scope_decision','parent_adoption','delta_rule','full_rule','parent_rule','secondary_observation','parent_apex_original',
                'live_provenance_inputs','live_verifier_source','applied_verifier_source'):add(plan[key])
    need(len(plan['parent_av_originals'])==len(plan['parent_set_av_originals'])==11,'exact approved eleven read/set parent rows')
    for d in plan['parent_av_originals']+plan['parent_set_av_originals']:add(d)
    for d in report['retained_originals']:
        if not d['path'].endswith('.all-te-atoms.jsonl.gz'):add(d)
    for key in ('stdout','stderr'):add(process[key])
    add(build['process'])
    for original_process in (build,strict(o.descriptor(build['process']))):
        for key in ('stdout','stderr'):add(original_process[key])
    # Keep both source identities. Each Mac mirror reuses its distinct
    # canonical original: the independent host source and the captured 5cd.
    verifier=plan['live_verifier_source'];applied=plan['applied_verifier_source']
    need(report['sources']['live_provenance_verifier']==verifier
         and report['sources']['applied_verifier_source']==applied
         and {k:applied[k] for k in ('bytes','sha256')}=={'bytes':124306,'sha256':'5cd18af19e1cd4cbe98542996fa41960bc36f697c6687ce201312b8ceda91c00'}
         and verifier['sha256']!=applied['sha256']
         and [d for d in proof.values() if d['sha256']==verifier['sha256']]==[verifier]
         and [d for d in proof.values() if d['sha256']==applied['sha256']]==[applied],
         'one independent host and one actual applied verifier source in the proof subset')
    add(request['controller_status']);add(request['controller_read'])
    need(not OUT.exists() and not OUT.is_symlink() and OUT.parent.resolve(strict=True)==OUT.parent,'new original archive namespace')
    OUT.mkdir(mode=0o700);sync(OUT.parent)
    o.recheck()
    captured={'schema':'hepta.runtime-properties.complete-host-original-archive.v1','source_roots':[str(ROOT),str(ACTUAL),str(INPUT_ROOT),str(SOURCE_ROOT)],
        'report':report_desc,'execution':execution_desc,'originals':[v for k,v in sorted(o.rows.items())],
        'directories':o.directories,'unique_objects':len(o.objects),'raw_unique_bytes':sum(len(b) for b in o.objects.values()),
        'phone_operations':0,'active_policy_writes':0,'all_original_metadata_and_bytes_rechecked':True}
    capture_raw=enc(captured);capture_desc=put(OUT/'FULL-ORIGINALS-MANIFEST.json',capture_raw)
    archive_path=OUT/'COMPLETE-ORIGINALS.tar.gz'
    fd=os.open(archive_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        with gzip.GzipFile(fileobj=stream,mode='wb',mtime=0,compresslevel=6) as gz:
            with tarfile.open(fileobj=gz,mode='w|',format=tarfile.USTAR_FORMAT) as tar:
                for name,body in [('CAPTURE.json',capture_raw),*[('objects/'+key,raw) for key,raw in sorted(o.objects.items())]]:
                    info=tarfile.TarInfo(name);info.size=len(body);info.mode=0o600;info.mtime=0;tar.addfile(info,io.BytesIO(body))
        stream.flush();os.fsync(stream.fileno())
    sync(OUT)
    archive_raw=archive_path.read_bytes();archive_desc={'path':str(archive_path),'bytes':len(archive_raw),'sha256':sha(archive_raw)}
    need(len(archive_raw)<=256*1024*1024,'bounded complete archive bytes')
    with tarfile.open(fileobj=io.BytesIO(archive_raw),mode='r:gz') as tar:
        seen=set()
        for member in tar:
            need(member.isfile() and member.name not in seen,'complete original archive member')
            expected=capture_raw if member.name=='CAPTURE.json' else o.objects[member.name.removeprefix('objects/')]
            need(tar.extractfile(member).read()==expected,'complete original archive readback')
            seen.add(member.name)
        need(seen=={'CAPTURE.json'}|{'objects/'+key for key in o.objects},'complete original archive set')
    o.recheck()
    files=[v for k,v in sorted(proof.items())]
    hashes={d['sha256']:d['bytes'] for d in files}
    index={'schema':'hepta.runtime-properties-r10.adoption-proof-inputs.v1','comparison_kind':'post_live_export',
        'report':report_desc,'plan':plan_desc,'process':process_desc,'execution':execution_desc,'files':files,
        'origin_map':[{'original':d,'retained':d} for d in files],
        'complete_comparison_outputs_retained_elsewhere':True,'all_orbit_images_embedded':False,
        'complete_archive':archive_desc,'complete_archive_manifest':capture_desc,
        'phone_operations':0,'active_policy_writes':0}
    index_desc=put(OUT/'ADOPTION-PROOF-INPUTS.P4.json',index)
    proof_objects={key:base64.b64encode(o.objects[key]).decode() for key in sorted(hashes)}
    packet={'schema':'hepta.runtime-properties.proof-original-transfer-packet.v1','index':index,
        'index_original':{'descriptor':index_desc,'raw_b64':base64.b64encode(enc(index)).decode()},
        'objects':proof_objects}
    packet_raw=enc(packet);compressed=gzip.compress(packet_raw,mtime=0)
    packet_desc=put(OUT/'PROOF-ORIGINALS.packet.json.gz',compressed)
    sizes={'schema':'hepta.runtime-properties.actual-verification-original-capacity.v1','file_descriptors':len(files),
        'unique_sha256_objects':len(hashes),'raw_unique_bytes':sum(hashes.values()),
        'base64_unique_bytes':sum(4*((n+2)//3) for n in hashes.values()),
        'canonical_base64_object_map_bytes':len(json.dumps(proof_objects,sort_keys=True,separators=(',',':')).encode()),
        'index_original_bytes':index_desc['bytes'],'transfer_packet_expanded_bytes':len(packet_raw),
        'transfer_packet_gzip_bytes':len(compressed),'known_historical_union_claimed':False,
        'full_archive_unique_objects':len(o.objects),'full_archive_raw_unique_bytes':captured['raw_unique_bytes'],
        'whole_future_release_bundle_size_claimed':False,'phone_operations':0,'active_policy_writes':0}
    sizes_desc=put(OUT/'VERIFICATION-ORIGINALS-CAPACITY.json',sizes)
    result=put(OUT/'RESULT.json',{'schema':'hepta.runtime-properties.complete-original-preservation.v1','state':'COMPLETE',
        'report':report_desc,'full_archive':archive_desc,'full_archive_manifest':capture_desc,
        'proof_index':index_desc,'proof_packet':packet_desc,'capacity':sizes_desc,
        'source_originals_preserved':True,'original_raw_reports_rewritten':False,
        'phone_operations':0,'active_policy_writes':0,'parser_or_query_executions':0})
    print(json.dumps({'result':result,'proof_packet':packet_desc,'capacity':sizes,
        'independent_verifier_source':verifier,'applied_verifier_source':applied,'phone_operations':0},sort_keys=True));return 0

if __name__=='__main__':raise SystemExit(main())
