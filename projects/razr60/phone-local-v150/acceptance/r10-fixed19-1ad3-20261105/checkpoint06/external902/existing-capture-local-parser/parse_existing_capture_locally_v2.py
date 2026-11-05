#!/usr/bin/env python3
"""Verify retained local wrappers and preserve only bodies returned by 45aff.

This does not read the phone, validate a snapshot archive, or adopt a boundary.
The input controller/tool receipts remain a separately retained provenance anchor.
"""
import argparse
import ast
import base64
import errno
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import shlex
import stat
import tarfile

W=Path('/workspace/scratch/1ad3d6f55439')
ACTUAL=W/'actual_external_902e_7c907661_01/existing-capture-read01'
FROZEN=W/'property_diagnostic/external902_existing_capture_observer_candidate01'
LABEL='root-r10-neg01-7c907661-01'
NONCE='902e851c3ca1f90deab3d880ab993774'
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
TAG='ng-'+NONCE+'-existing-capture-read01'
P4BASE='/home/alex/razr60-local-model-v150'
P4OUT=P4BASE+'/fixed19-root-1ad3-external902-existing-capture-read01'
PHONEBASE='/var/lib/trillionnium/owner-open/phone-local-v150'
CAPTURE=PHONEBASE+'/native-guard-snapshots-r10-r1/'+LABEL+'-capture-01'
BOUNDARY=PHONEBASE+'/native-guard-boundaries-r10-r1/'+NONCE
SOURCE_SHA='45affc6439458dec09e1326c25a0c1be01ac66732d08ad3e754e3773230c0c84'
CALLER_SHA='db1f4a18b37ab6b8c21d338978e28a6993249b7fa987a33ee3d04d0fe5ae996d'
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
NAMES={'CHILD.json','INTENT.json','JOINED.json','PHONE-STDOUT.original',
       'PROBE-SOURCE.original.py','REQUEST.original.json','RESULT.json',
       'actor.stderr.original','actor.stdout.original','phone-baseline.json.original',
       'phone-intent.json.original','phone-result.json.original'}
RULES=(('RESULT.json',65536,65536),('CAPTURE.json',16*1024*1024,1024*1024),
       ('PARTIAL-CAPTURE.json',2*1024*1024,2*1024*1024),('ORIGINALS.tar.gz',64*1024*1024,0))
LOCAL_READS={}

def need(value,message):
    if not value:raise ValueError(message)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def strict(raw):
    def pairs(items):
        obj={}
        for k,v in items:
            need(k not in obj,'duplicate JSON key');obj[k]=v
        return obj
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))

def enc(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()

def meta(s):return [getattr(s,k) for k in META]

def read_local(path,limit):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts,'absolute local input')
    need(path.parent.resolve(strict=True)==path.parent,'local parent alias forbidden')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=limit,
             'bounded single-link local original required')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(before.st_size+1)
        need(len(raw)==before.st_size and meta(before)==meta(os.fstat(fd))==meta(path.lstat()),
             'local original changed during read')
    finally:os.close(fd)
    row={'path':str(path),'bytes':len(raw),'sha256':sha(raw),'local_metadata':meta(before)}
    if str(path) in LOCAL_READS:need(row==LOCAL_READS[str(path)],'local original changed across reads')
    else:LOCAL_READS[str(path)]=row
    return raw

def bare(raw):return {'bytes':len(raw),'sha256':sha(raw)}

def exact_pin(row,raw,path=None):
    need(type(row) is dict and set(row)==({'bytes','sha256'} if path is None else {'path','bytes','sha256'}),
         'exact descriptor fields')
    need(type(row['bytes']) is int and row['bytes']==len(raw) and row['sha256']==sha(raw),'descriptor bytes/SHA differ')
    if path is not None:need(row['path']==path,'original descriptor path differs')

def full9(row,kind,size=None):
    need(type(row) is list and len(row)==9 and all(type(x) is int for x in row),'nine integer metadata fields')
    need(row[0]>=0 and row[1]>0 and row[3]==row[4]==0 and row[5]>=1 and row[6]>=0
         and row[7]>=0 and row[8]>=0,'private full9 shape')
    need((stat.S_ISREG(row[2]) and stat.S_IMODE(row[2])==0o600 and row[5]==1) if kind=='file'
         else (stat.S_ISDIR(row[2]) and stat.S_IMODE(row[2])==0o700),'private metadata mode differs')
    if size is not None:need(row[6]==size,'phone full9 size differs from retained descriptor')

def directory(row,path):
    need(type(row) is dict and row.get('path')==path,'fixed directory path differs')
    full9(row['metadata'],'directory');names=row['names']
    need(type(names) is list and len(names)<=128 and names==sorted(set(names))
         and all(type(n) is str and n not in ('','.','..') and '/' not in n and '\x00' not in n for n in names),
         'complete bounded directory names shape')

def archive_originals():
    manifest_raw=read_local(ACTUAL/'ARCHIVE-MANIFEST.json',65536);mf=strict(manifest_raw)
    need(mf['schema']=='hepta.fixed19.readonly-diagnostic-originals.v1' and mf['source_sha256']==SOURCE_SHA
         and mf['originals_changed'] is False and mf['case_pass'] is False,'caller archive manifest identity')
    rows=mf['files'];need(type(rows) is list and len(rows)==12,'exact twelve originals')
    mapping={}
    for row in rows:
        need(type(row) is dict and set(row)=={'path','bytes','sha256'} and row['path'] in NAMES
             and row['path'] not in mapping and type(row['bytes']) is int and 0<=row['bytes']<=8*1024*1024
             and re.fullmatch('[0-9a-f]{64}',row['sha256']),'bounded unique original descriptor')
        mapping[row['path']]=row
    need(set(mapping)==NAMES and sum(r['bytes'] for r in rows)<=16*1024*1024,'twelve-member aggregate bound')
    compressed=read_local(ACTUAL/'FULL-ORIGINALS.tar.xz',20*1024*1024)
    exact_pin(mf['archive'],compressed,P4OUT+'/FULL-ORIGINALS.tar.xz')
    decoder=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=64*1024*1024)
    plain=decoder.decompress(compressed,max_length=18*1024*1024+1)
    need(len(plain)<=18*1024*1024 and decoder.eof and decoder.unused_data==b'',
         'single complete bounded XZ stream required')
    exact_pin(mf['tar'],plain)
    originals={}
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as tf:
        for member in tf:
            need(member.name in NAMES and member.name not in originals and member.isreg()
                 and not member.pax_headers and member.uid==member.gid==0 and member.mode==0o600
                 and member.mtime==0 and member.size==mapping[member.name]['bytes'],
                 'exact regular USTAR original member required')
            stream=tf.extractfile(member);need(stream is not None,'regular tar body required')
            with stream:raw=stream.read(member.size+1)
            exact_pin(mapping[member.name],raw,member.name);originals[member.name]=raw
    need(set(originals)==NAMES,'archive complete twelve-original closed set')
    local_dir=ACTUAL/'originals'
    if local_dir.exists():
        need(local_dir.is_dir() and not local_dir.is_symlink()
             and {p.name for p in local_dir.iterdir()}==NAMES,'local twelve-original directory closed set')
        for name,raw in originals.items():need(read_local(local_dir/name,8*1024*1024)==raw,'local copy differs from whole archive')
    return originals,mf

def wrappers(originals):
    source=read_local(FROZEN/'delivery-final01/package/source/observe_existing_capture_once.py',49152)
    caller=read_local(FROZEN/'caller-final01/P4-LAUNCHER.py',65536)
    need(len(source)==18736 and sha(source)==SOURCE_SHA and len(caller)==44799 and sha(caller)==CALLER_SHA,
         'frozen source/caller identity')
    tree=ast.parse(caller)
    assignments={n.targets[0].id:n.value for n in tree.body if isinstance(n,ast.Assign)
                 and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
    request=ast.literal_eval(assignments['REQ'])
    need(ast.literal_eval(assignments['PROBE'])==source==originals['PROBE-SOURCE.original.py'],'exact probe source chain')
    request_raw=enc(request);need(request_raw==originals['REQUEST.original.json'],'exact original actor request')
    intent=strict(originals['INTENT.json']);expected_argv=['/usr/bin/python3','-I','-B',P4BASE+'/ops/phone_once.py',TAG,P4BASE+'/requests/'+TAG+'.json']
    need(intent=={'argv':expected_argv,'phone_calls_max':1,'probe_source_sha256':SOURCE_SHA,
        'request_sha256':sha(request_raw),'phone_source_or_case_writes':0,'signals_sent':0,
        'automatic_retry':False,'case_pass':False},'exact launcher intent')
    child=strict(originals['CHILD.json']);joined=strict(originals['JOINED.json'])
    need(type(child['pid']) is int and child['pid']>0 and child=={'pid':child['pid'],'maximum_starts':1,'automatic_retry':False},'single actual actor child')
    need(joined=={'pid':child['pid'],'returncode':joined['returncode'],'wait_returned':True,'signals_sent':0}
         and type(joined['returncode']) is int,'actual joined wrapper identity')
    native_intent=strict(originals['phone-intent.json.original'])
    need(native_intent['schema']=='hepta.phone-local.operator-intent.v150.1' and native_intent['label']==TAG
         and native_intent['request_sha256']==sha(request_raw) and native_intent['request']==request
         and native_intent['automatic_replay'] is False,'actual phone intent exact request')
    operation=strict(originals['phone-result.json.original']);phone=operation['phone']
    need(operation['schema']=='hepta.phone-local.operator-result.v150.1' and operation['label']==TAG
         and operation['model_decision'] is False and operation['native_task_result'] is False,
         'actual operator result binding')
    need(phone['command']=='/debug_ramdisk/su -c '+shlex.quote(request['command'])
         and type(phone['rc']) is int and type(phone['stdout']) is str and type(phone['stderr']) is str,
         'actual root command and outcome shape')
    phone_raw=phone['stdout'].encode('utf-8');need(phone_raw==originals['PHONE-STDOUT.original'],'PHONEOUT original equals actual phone stdout')
    result=strict(originals['RESULT.json']);complete=joined['returncode']==0 and phone['rc']==0
    expected_state='READ_ONLY_FIXED_EXISTING_CAPTURE_AND_BOUNDARY_'+('COMPLETED' if complete else 'FAILED_OR_UNKNOWN')
    need(result['state']==expected_state and result['actor_returncode']==joined['returncode']
         and result['phone_returncode']==phone['rc'] and result['phone_status']==operation['status']
         and result['source_sha256']==SOURCE_SHA and result['case_pass'] is False
         and result['native_boundary_created'] is False and result['signals_sent']==0 and result['automatic_retry'] is False,
         'caller result must preserve real outcomes')
    exact_pin(result['phone_stdout'],phone_raw,P4OUT+'/PHONE-STDOUT.original')
    need(set(result['phone_originals'])=={'baseline.json','intent.json','result.json'},'native original triple')
    for name,row in result['phone_originals'].items():
        exact_pin(row,originals['phone-'+name+'.original'],P4BASE+'/operations/'+TAG+'/'+name)
    baseline=strict(originals['phone-baseline.json.original'])
    need(baseline['rc']==0 and baseline['stdout'].splitlines()[0]==BOOT,'actual baseline boot')
    return phone_raw,{'actor_returncode':joined['returncode'],'phone_returncode':phone['rc'],
        'wrapper_completed_successfully':complete,'native_stderr':phone['stderr'],'actor_stderr_bytes':len(originals['actor.stderr.original'])}

def retained_body(row,maximum):
    need(type(row['bytes']) is int and 0<=row['bytes']<=maximum and re.fullmatch('[0-9a-f]{64}',row['sha256']),
         'bounded exact observed file descriptor')
    full9(row['metadata'],'file',row['bytes'])
    need(row.get('encoding')=='base64' and type(row.get('data_base64')) is str,'complete raw body encoding')
    need(len(row['data_base64'])<=4*((maximum+2)//3),'bounded base64 original')
    raw=base64.b64decode(row['data_base64'],validate=True)
    need(base64.b64encode(raw).decode()==row['data_base64'] and bare(raw)=={'bytes':row['bytes'],'sha256':row['sha256']},
         'retained complete body bytes/SHA mismatch')
    return raw

def observation(raw,wrapper):
    value=strict(raw);need(value['schema']=='hepta.native-guard.existing-capture-and-boundary-observation.v1'
        and value['label']==LABEL and value['nonce']==NONCE,'fixed observer output identity')
    if value['state']=='COMPLETE_OBSERVATION_SERIALIZATION_REFUSED':
        need(value['observation_complete'] is False,'serialization refusal cannot pass')
        return value,{},[],{'state':'SERIALIZATION_REFUSED_NO_COMPLETE_ORIGINAL_SET','complete':False}
    need(value['boot_id']==BOOT,'fixed observer boot')
    complete=value['observation_complete'] is True
    need(value['state']==('EXISTING_FIXED_OUTPUTS_OBSERVED' if complete else 'EXISTING_FIXED_OUTPUT_OBSERVATION_FAILED_OR_PARTIAL'),
         'observer completion state')
    if complete:
        need(wrapper['wrapper_completed_successfully'] and value['failure'] is None
             and value['whole_hash_and_directory_bookends_complete'] is True and value['boot_bookends_complete'] is True
             and value['owned_read_fd_observation']=={'complete':True,'new_read_FDs_remaining':[],
                'closed_unknown_or_foreign_FDs':False},'complete observation requires original bookends and cleanup')
    for k in ('snapshot_entry_rerun','capture_suffix_changed','new_case_or_nonce','existing_capture_contents_validated_or_adopted',
              'boundary_validated_or_adopted','capture_snapshot_subtree_traversed','archive_body_retained','global_clearance_proof',
              'component_qualified','automatic_retry'):need(value[k] is False,'unexpected semantic upgrade: '+k)
    for k in ('phone_case_or_source_writes','phone_evidence_writes','runtime_modules_loaded','runtime_function_calls','process_launches',
              'signals','kernel_signal_zero_queries','model_requests','native_dispatches','socket_connections',
              'runtime_cleanup_calls','boundary_publications'):need(type(value[k]) is int and value[k]==0,'unexpected action claim: '+k)
    need(value['fresh_later_observation_not_existing_snapshot_creation_time'] is True
         and value['result_read_first'] is True and value['output_limit_bytes']==8*1024*1024,'later observation limits')
    bodies={};needed=[];directory_row=value['capture_directory'];leaves=value['capture_leaves'];summary=[]
    if directory_row is not None:directory(directory_row,CAPTURE)
    need(type(leaves) is list and len(leaves)<=4 and (not complete or len(leaves)==4),'four fixed leaf order')
    for row,(name,maximum,retain_limit) in zip(leaves,RULES):
        need(row['path']==CAPTURE+'/'+name and directory_row is not None,'fixed capture leaf path')
        need(row['parent_metadata']==directory_row['metadata'],'capture parent full9 differs')
        if row['state']=='ENOENT':
            need(row['leaf_errno']==errno.ENOENT and row['whole_bytes_retained'] is False
                 and row['whole_file_hash_computed'] is False and name not in directory_row['names'],'positive exact leaf absence')
        else:
            need(row['state']=='REGULAR_ORIGINAL_OBSERVED' and row['kind']=='file' and row['whole_file_hash_computed'] is True
                 and name in directory_row['names'] and row['body_retention_limit_bytes']==retain_limit,
                 'whole-hash observation shape')
            need(type(row['bytes']) is int and 0<=row['bytes']<=maximum and re.fullmatch('[0-9a-f]{64}',row['sha256']),
                 'fixed per-leaf descriptor budget')
            full9(row['metadata'],'file',row['bytes'])
            retain=retain_limit>0 and row['bytes']<=retain_limit
            need(row['whole_bytes_retained'] is retain,'body presence must follow the frozen rule')
            if retain:bodies['capture/'+name]=retained_body(row,retain_limit)
            else:
                need('data_base64' not in row and 'encoding' not in row,'descriptor-only is not a retained body')
                reason='fixed_archive_descriptor_only' if name=='ORIGINALS.tar.gz' else 'CAPTURE_json_exceeds_fixed_one_MiB_body_limit'
                need(row['body_omission_reason']==reason,'explicit descriptor-only reason')
                needed.append({'path':row['path'],'bytes':row['bytes'],'sha256':row['sha256'],'metadata':row['metadata'],
                    'body_present_locally_from_this_observation':False,'purpose':'independent_original_snapshot_validation',
                    'reason':reason,'required_before_any_snapshot_adoption':True})
        summary.append({k:v for k,v in row.items() if k!='data_base64'})
    boundaries=value['boundary_observations'];need(type(boundaries) is list and len(boundaries)<=2
        and (not complete or len(boundaries)==2),'two exact boundary leaves')
    boundary_rows=[]
    for row,path,kind in zip(boundaries,(BOUNDARY+'.json',BOUNDARY),('file','directory')):
        need(row['path']==path,'fixed902 boundary path');full9(row['parent_metadata'],'directory')
        if row['state']=='ENOENT':need(row['leaf_errno']==errno.ENOENT,'positive fixed boundary absence')
        elif kind=='file':
            need(row['state']=='REGULAR_ORIGINAL_RETAINED' and row['kind']=='file','complete fixed boundary file')
            bodies['boundary/'+NONCE+'.json']=retained_body(row,1024*1024)
        else:
            need(row['state']=='DIRECTORY_NAMES_OBSERVED_NO_CHILD_READS' and row['kind']=='directory','boundary directory names only')
            directory(row,path)
        boundary_rows.append({k:v for k,v in row.items() if k!='data_base64'})
    if complete:
        expected_dirs={CAPTURE:directory_row}
        if boundaries[1]['state']!='ENOENT':expected_dirs[BOUNDARY]={k:boundaries[1][k] for k in ('path','metadata','names')}
        dirs=value['all_directory_rows'];need(type(dirs) is list and len(dirs)==len(expected_dirs)
            and {r['path']:r for r in dirs}==expected_dirs,'complete exact directory bookend rows')
        expected_raw=[]
        if boundaries[0]['state']!='ENOENT':expected_raw=[{k:boundaries[0][k] for k in ('path','bytes','sha256','metadata')}]
        need(value['boundary_original_descriptors']==expected_raw,'complete boundary raw readset')
        need(boundaries[0]['parent_metadata']==boundaries[1]['parent_metadata'],'boundary parent identity consistent')
    native_result=None;native_capture=None;boundary_claim=None;links=False
    if 'capture/RESULT.json' in bodies:
        native_result=strict(bodies['capture/RESULT.json'])
        need(native_result['schema']=='hepta.native-guard.snapshot-result.v1'
             and native_result['state']=='ORIGINAL_CAPTURE_ARCHIVED','native result is original snapshot schema')
        by_name={Path(r['path']).name:r for r in leaves}
        links=True
        for field,name in (('capture','CAPTURE.json'),('archive','ORIGINALS.tar.gz')):
            row=by_name.get(name)
            if row is None or row['state']!='REGULAR_ORIGINAL_OBSERVED':
                need(not complete,'complete observation lacks a native-result file');links=False;continue
            need(native_result[field]=={'bytes':row['bytes'],'sha256':row['sha256']}
                and native_result[field+'_path']==CAPTURE+'/'+name,'native snapshot result matches observed whole-file descriptor')
        need(native_result['component_qualified'] is False and native_result['business_qualified'] is False
             and native_result['model_requests']==0 and native_result['automatic_retry'] is False,'snapshot result is not qualification')
    if 'capture/CAPTURE.json' in bodies:
        native_capture=strict(bodies['capture/CAPTURE.json'])
        need(native_capture['schema']=='hepta.native-guard.original-capture.v1'
             and native_capture['nonce']==NONCE and native_capture['boot_id']==BOOT,'captured report fixed identity')
    if 'boundary/'+NONCE+'.json' in bodies:boundary_claim=strict(bodies['boundary/'+NONCE+'.json'])
    result={'state':'COMPLETE_FIXED_OUTPUT_OBSERVATION_PARSED' if complete else 'PARTIAL_FIXED_OUTPUT_OBSERVATION_PARSED',
        'complete':complete,'capture_directory':directory_row,'capture_leaves':summary,'boundary_observations':boundary_rows,
        'native_snapshot_result_reported':native_result,'native_result_descriptor_links_checked':links,
        'native_capture_report_header':None if native_capture is None else {k:v for k,v in native_capture.items() if k not in ('files','directories','native')},
        'boundary_reported_header':None if boundary_claim is None else {k:boundary_claim[k] for k in ('schema','state','nonce','case_id','component_qualified') if k in boundary_claim},
        'boundary_file_body_retained':'boundary/'+NONCE+'.json' in bodies,
        'boundary_directory_children_read':False,'snapshot_archive_body_retained':False,
        'snapshot_archive_contents_validated':False,'existing_boundary_validated_or_adopted':False,
        'native_boundary_published':False,'case_pass':False,'automatic_retry':False}
    return value,bodies,needed,result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True,help='New local derived directory; existing output is rejected')
    a=p.parse_args();out=a.out.absolute()
    need(not out.exists() and out.parent.resolve(strict=True)==out.parent,'new local output only')
    need(out.is_relative_to(W/'property_diagnostic'),'derived output must stay in this agent local namespace')
    originals,mf=archive_originals();raw,wrapper=wrappers(originals)
    value,bodies,needed,summary=observation(raw,wrapper)
    for row in list(LOCAL_READS.values()):read_local(row['path'],max(1,row['bytes']))
    need(not out.exists(),'output appeared before create-only write')
    out.mkdir(mode=0o700)
    saved=[]
    for name,body in sorted(bodies.items()):
        dest=out/'retained-bodies'/name;dest.parent.mkdir(parents=True,exist_ok=True)
        with dest.open('xb') as stream:stream.write(body)
        saved.append({'original_phone_path':CAPTURE+'/'+Path(name).name if name.startswith('capture/') else BOUNDARY+'.json',
            'local_path':str(dest),**bare(body),'full_body_preserved':True})
    result={'schema':'hepta.existing-capture.local-parsed-originals.v1','source_sha256':SOURCE_SHA,
        'phone_stdout':bare(raw),'wrapper':wrapper,'observation':summary,'retained_bodies':saved,
        'readback_needed':needed,'local_input_bookends':list(LOCAL_READS.values()),
        'trusted_retained_controller_tool_receipts_verified_here':False,
        'caller_wrapper_chain_verified_here':True,'phone_calls':0,'remote_calls':0,
        'case_pass':False,'snapshot_or_boundary_adopted':False}
    with (out/'PARSE-RESULT.json').open('xb') as stream:stream.write(enc(result))
    with (out/'READBACK-NEEDED.json').open('xb') as stream:stream.write(enc({'schema':'hepta.fixed-existing-output.readback-needed.v1',
        'state':'FIXED_OBSERVED_DESCRIPTORS_ONLY_NO_RETRIEVAL_EXECUTED','files':needed,
        'actual_observation_complete':summary['complete'],'source_PHONE_STDOUT':bare(raw),
        'boundary_validation_or_publication':False,'phone_calls':0,'remote_calls':0}))
    print(json.dumps({'result':str(out/'PARSE-RESULT.json'),'observation_complete':summary['complete'],
        'retained_bodies':len(saved),'descriptor_only_files_to_read':len(needed),
        'boundary_file_body_retained':summary.get('boundary_file_body_retained',False),'case_pass':False},sort_keys=True))
    return 0 if summary['complete'] else 1

if __name__=='__main__':raise SystemExit(main())
