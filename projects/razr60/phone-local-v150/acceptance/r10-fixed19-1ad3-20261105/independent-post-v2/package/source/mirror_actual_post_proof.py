#!/usr/bin/env python3
"""Mirror the actual post-comparison proof with explicit cross-host identities.

Only the complete small-proof packet is read from P4. The separate full archive
stays at its pinned original path. One already captured Mac verifier is reused
by an explicit descriptor; every other original path receives its own new file.
No original report, plan, full-nine metadata JSON, or process record is rewritten.
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
import types

B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
P=Path('/home/alex/razr60-local-model-v150/policy-runtime-properties-r10-r1')
OUT=B/'policy-runtime-properties-r10-post-live-root02-independent-proof01'
CAPTURED_VERIFIER=B/'policy-runtime-properties-r10-live-02/capture/originals/policy_runtime_properties_verifier.original.py'
INDEPENDENT_VERIFIER=B/'policy-runtime-properties-r10-independent-host-verifier-r1-candidate01/source/policy_runtime_properties_verifier.py'
ACTUAL_PROOF=None
TRANSPORT={'path':str(B/'native-guard-r10-r1-operator-r4/root-chain/source/run_component_root_once.py'),
 'bytes':43438,'sha256':'860aaf747e89411efa993783b950f709b1d8ac5d7b606575065bdff74ef98e22'}
INDEX_KEYS={'schema','comparison_kind','report','plan','process','execution','files','origin_map',
 'complete_comparison_outputs_retained_elsewhere','all_orbit_images_embedded','complete_archive',
 'complete_archive_manifest','phone_operations','active_policy_writes'}
def need(value, message):
    if not value:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)+'\n').encode()

def metadata(s):
    return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]

def descriptor(path, raw):
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}

def exact3(d):
    need(type(d) is dict and set(d)=={'path','bytes','sha256'}, 'exact three-field descriptor')
    need(type(d['path']) is str and Path(d['path']).is_absolute() and '..' not in Path(d['path']).parts, 'absolute original path')
    need(type(d['bytes']) is int and 0 <= d['bytes'] <= 64*1024*1024, 'bounded original size')
    need(type(d['sha256']) is str and re.fullmatch('[0-9a-f]{64}',d['sha256']), 'original SHA256')
    return d

def fsync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)

def mkdir(path):
    need(path.parent.resolve(strict=True)==path.parent, 'canonical parent')
    path.mkdir(mode=0o700)
    fsync_dir(path.parent)

def read_regular(path):
    need(path.resolve(strict=True)==path, 'canonical retained file')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<=before.st_size<=64*1024*1024,'private single-link retained file')
        with os.fdopen(fd,'rb',closefd=False) as f: raw=f.read(before.st_size+1)
        need(len(raw)==before.st_size and metadata(before)==metadata(os.fstat(fd))==metadata(path.lstat()), 'retained file changed')
        return raw,metadata(before)
    finally: os.close(fd)

def put(path, raw):
    need(type(raw) is bytes, 'raw bytes required')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())
    fsync_dir(path.parent)
    actual,meta=read_regular(path)
    need(actual==raw,'retained byte readback')
    return descriptor(path,raw),meta


def strict(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'duplicate JSON key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))

def pinned(row):
    exact3(row);raw,meta=read_regular(Path(row['path']))
    need(descriptor(row['path'],raw)==row,'explicit Mac original bytes changed')
    return raw,meta


def require_actual_proof():
    value=ACTUAL_PROOF
    keys={'packet','original_index','report','collector_result','capacity','verifier_original','verifier_retained','independent_verifier_original','independent_verifier_retained'}
    need(type(value) is dict and set(value)==keys,'actual completed post proof remains unpublished')
    for row in value.values():exact3(row)
    return value

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request',type=Path,required=True)
    parser.add_argument('--request-sha256',required=True)
    parser.add_argument('--execute-host-mirror',action='store_true')
    a=parser.parse_args(argv)
    if not a.execute_host_mirror:
        print(json.dumps({'state':'PREVIEW_NO_REQUEST_READ_NO_REMOTE_READ_NO_MIRROR',
            'phone_operations':0,'policy_writes':0,'comparison_processes':0}));return 0
    actual=require_actual_proof()
    os.umask(0o077);sys.dont_write_bytecode=True
    need(re.fullmatch('[0-9a-f]{64}',a.request_sha256),'explicit original mirror request SHA')
    source_raw,source_meta=read_regular(Path(__file__).resolve());source_desc=descriptor(Path(__file__).resolve(),source_raw)
    request_raw,request_meta=read_regular(a.request)
    need(sha(request_raw)==a.request_sha256,'mirror request original differs');request=strict(request_raw)
    fields={'schema','source','packet','original_index','report','collector_result','capacity',
            'verifier_original','verifier_retained','independent_verifier_original','independent_verifier_retained'}
    need(type(request) is dict and set(request)==fields
         and request['schema']=='hepta.runtime-properties-r10.post-proof-mirror-request.v2'
         and request['source']==source_desc,'explicit current mirror source request')
    need(all(request[k]==actual[k] for k in actual),'actual completed post proof pins differ')
    for key in fields-{'schema'}:exact3(request[key])
    need(request['packet']['path']==str(P/'post-live-root02-independent-evidence01/PROOF-ORIGINALS.packet.json.gz')
         and request['collector_result']['path']==str(P/'post-live-root02-independent-evidence01/RESULT.json')
         and request['capacity']['path']==str(P/'post-live-root02-independent-evidence01/VERIFICATION-ORIGINALS-CAPACITY.json')
         and request['original_index']['path']==str(P/'post-live-root02-independent-evidence01/ADOPTION-PROOF-INPUTS.P4.json')
         and request['report']['path']==str(P/'post-live-root02-actual01/comparison/RESULT.json'),
         'only original Root02 comparison proof paths')
    need(request['verifier_retained']['path']==str(CAPTURED_VERIFIER)
         and {k:request['verifier_retained'][k] for k in ('bytes','sha256')}=={'bytes':124306,'sha256':'5cd18af19e1cd4cbe98542996fa41960bc36f697c6687ce201312b8ceda91c00'}
         and all(request['verifier_original'][k]==request['verifier_retained'][k] for k in ('bytes','sha256')),
         'explicit immutable captured verifier copy required')
    need(request['independent_verifier_retained']['path']==str(INDEPENDENT_VERIFIER)
         and all(request['independent_verifier_original'][k]==request['independent_verifier_retained'][k] for k in ('bytes','sha256'))
         and request['independent_verifier_retained']['sha256']!=request['verifier_retained']['sha256'],
         'separate canonical independently reviewed host verifier required')
    verifier_raw,verifier_meta=pinned(request['verifier_retained'])
    independent_raw,independent_meta=pinned(request['independent_verifier_retained'])
    transport_raw,transport_meta=pinned(TRANSPORT)
    module=types.ModuleType('reviewed_runtime_properties_post_mirror_host_transport')
    module.__file__=TRANSPORT['path'];module.__reviewed_source_sha256__=sha(transport_raw)
    exec(compile(transport_raw,module.__file__,'exec'),module.__dict__)
    need(not OUT.exists() and not OUT.is_symlink(),'new mirror namespace; preserve any previous partial output')
    mkdir(OUT);mkdir(OUT/'originals')
    put(OUT/'REQUEST.original.json',request_raw);put(OUT/'MIRROR-SOURCE.py',source_raw)
    chain=module.Chain.__new__(module.Chain);chain.out=OUT;chain.steps=[];chain.remote_root=str(P)
    try:
        wanted={key:request[key]['path'] for key in ('packet','collector_result','capacity')}
        # Only this frozen read-only SSH method is used; no phone or remote write.
        response=chain.remote_read('read-original-post-proof',wanted)
        need(response['state']=='ORIGINAL_HOST_FILES_READ' and set(response['files'])==set(wanted),'complete three-file original proof read')
        returned={}
        for key,original in response['files'].items():
            raw=base64.b64decode(original['base64'],validate=True)
            need(descriptor(original['path'],raw)==request[key]
                 and original['bytes']==len(raw) and original['sha256']==sha(raw),'remote original proof bytes differ')
            returned[key]=raw
        packet_raw=returned['packet']
        need(len(packet_raw)<=16*1024*1024,'bounded actual proof transfer packet')
        with gzip.GzipFile(fileobj=io.BytesIO(packet_raw),mode='rb') as gz:
            expanded=gz.read(64*1024*1024+1)
            need(len(expanded)<=64*1024*1024 and gz.read(1)==b'','bounded expanded proof transfer packet')
        packet=strict(expanded)
        need(set(packet)=={'schema','index','index_original','objects'}
             and packet['schema']=='hepta.runtime-properties.proof-original-transfer-packet.v1','exact proof packet')
        original_index_raw=base64.b64decode(packet['index_original']['raw_b64'],validate=True)
        need(packet['index_original']['descriptor']==request['original_index']
             and descriptor(request['original_index']['path'],original_index_raw)==request['original_index'],
             'pinned original P4 index bytes differ')
        index=packet['index']
        need(strict(original_index_raw)==index and set(index)==INDEX_KEYS
             and index['schema']=='hepta.runtime-properties-r10.adoption-proof-inputs.v1'
             and index['comparison_kind']=='post_live_export','actual original post proof index')
        need(index['complete_comparison_outputs_retained_elsewhere'] is True
             and index['all_orbit_images_embedded'] is False
             and type(index['phone_operations']) is int and index['phone_operations']==0
             and type(index['active_policy_writes']) is int and index['active_policy_writes']==0,
             'original no-effect proof scope')
        originals=[exact3(d) for d in index['files']]
        need(1<=len(originals)<=512 and len({d['path'] for d in originals})==len(originals)
             and index['origin_map']==[{'original':d,'retained':d} for d in originals],'exact original P4 proof path set')
        for key in ('report','plan','process','execution'):exact3(index[key]);need(index[key] in originals,'top original not in proof files')
        need(index['report']==request['report'],'actual post report identity differs')
        # Complete archive descriptors are explicit external references, not
        # silently embedded/read by this small-proof consumer.
        for key in ('complete_archive','complete_archive_manifest'):
            d=index[key]
            need(type(d) is dict and set(d)=={'path','bytes','sha256'} and type(d['path']) is str
                 and Path(d['path']).is_absolute() and '..' not in Path(d['path']).parts
                 and type(d['bytes']) is int and 0<d['bytes']<=256*1024*1024
                 and re.fullmatch('[0-9a-f]{64}',d['sha256']),'bounded full archive external reference')
        needed={d['sha256'] for d in originals}
        need(type(packet['objects']) is dict and set(packet['objects'])==needed,'closed proof object set')
        objects={key:base64.b64decode(value,validate=True) for key,value in packet['objects'].items()}
        need(all(sha(raw)==key for key,raw in objects.items())
             and all(len(objects[d['sha256']])==d['bytes'] for d in originals)
             and sum(map(len,objects.values()))<=64*1024*1024,'all proof bytes, sizes and aggregate bound')
        verifier_original=request['verifier_original'];verifier_retained=request['verifier_retained']
        independent_original=request['independent_verifier_original'];independent_retained=request['independent_verifier_retained']
        need([d for d in originals if d['sha256']==verifier_original['sha256']]==[verifier_original]
             and objects[verifier_original['sha256']]==verifier_raw,'exactly one captured verifier proof source')
        need([d for d in originals if d['sha256']==independent_original['sha256']]==[independent_original]
             and objects[independent_original['sha256']]==independent_raw,'exactly one independent host verifier proof source')
        actual_report=strict(objects[index['report']['sha256']])
        need(actual_report['comparison_kind']=='post_live_export' and actual_report['check_count']==actual_report['passed_count']==16
             and actual_report['sources']['live_provenance_verifier']==independent_original
             and actual_report['sources']['applied_verifier_source']==verifier_original,'post report dual source identities differ')
        collector=strict(returned['collector_result']);capacity_original=strict(returned['capacity'])
        need(collector['state']=='COMPLETE' and collector['report']==request['report']
             and collector['proof_index']==request['original_index'] and collector['proof_packet']==request['packet']
             and collector['full_archive']==index['complete_archive']
             and collector['full_archive_manifest']==index['complete_archive_manifest'],'actual preservation record linkage')
        need(capacity_original['file_descriptors']==len(originals)
             and capacity_original['unique_sha256_objects']==len(objects)
             and capacity_original['raw_unique_bytes']==sum(map(len,objects.values()))
             and capacity_original['base64_unique_bytes']==sum(4*((len(raw)+2)//3) for raw in objects.values())
             and capacity_original['transfer_packet_gzip_bytes']==len(packet_raw)
             and capacity_original['transfer_packet_expanded_bytes']==len(expanded),'actual P4 capacity record differs')
        saved=[];mapping=[];by_original={};bookends={};created_names=[]
        for i,d in enumerate(originals):
            if d==verifier_original:
                retained=verifier_retained;meta=verifier_meta
                need(pinned(retained)==(verifier_raw,verifier_meta),'captured verifier changed')
            elif d==independent_original:
                retained=independent_retained;meta=independent_meta
                need(pinned(retained)==(independent_raw,independent_meta),'independent host verifier changed')
            else:
                name=Path(d['path']).name;need(re.fullmatch('[A-Za-z0-9_.-]{1,180}',name),'bounded proof filename')
                path=OUT/'originals'/('%03d-%s-%s'%(i,sha(d['path'].encode())[:16],name))
                retained,meta=put(path,objects[d['sha256']]);created_names.append(path.name)
            need(retained['bytes']==d['bytes'] and retained['sha256']==d['sha256'],'retained original identity')
            saved.append(retained);mapping.append({'original':d,'retained':retained});by_original[d['path']]=retained
            bookends[retained['path']]=meta
        need(len({d['path'] for d in saved})==len(saved),'unique retained path for each original')
        mirror=dict(index);mirror['files']=saved;mirror['origin_map']=mapping
        for key in ('report','plan','process','execution'):mirror[key]=by_original[index[key]['path']]
        excluded={'files','origin_map','report','plan','process','execution'}
        need({k:v for k,v in mirror.items() if k not in excluded}=={k:v for k,v in index.items() if k not in excluded},
             'only explicit cross-host descriptors may change')
        index_desc,_=put(OUT/'ADOPTION-PROOF-INPUTS.json',encode(mirror))
        original_index_copy,_=put(OUT/'ADOPTION-PROOF-INPUTS.P4.original.json',original_index_raw)
        packet_desc,_=put(OUT/'PROOF-ORIGINALS.packet.json.gz',packet_raw)
        collector_result,_=put(OUT/'P4-COLLECTOR-RESULT.original.json',returned['collector_result'])
        capacity_copy,_=put(OUT/'P4-CAPACITY.original.json',returned['capacity'])
        for d in saved:
            raw,meta=read_regular(Path(d['path']))
            need(descriptor(d['path'],raw)==d and meta==bookends[d['path']],'final mirror original metadata bookends')
        need(sorted(os.listdir(OUT/'originals'))==sorted(created_names),'closed new retained tree')
        need(read_regular(Path(__file__).resolve())==(source_raw,source_meta)
             and read_regular(a.request)==(request_raw,request_meta)
             and pinned(TRANSPORT)==(transport_raw,transport_meta),'mirror control originals changed')
        capacity={'schema':'hepta.runtime-properties.actual-mac-proof-capacity.v1','original_path_count':len(originals),
            'retained_path_count':len(saved),'new_retained_files':len(created_names),'existing_captured_verifier_files':1,'existing_independent_verifier_files':1,
            'unique_sha256_objects':len(objects),'retained_file_bytes':sum(d['bytes'] for d in saved),
            'raw_unique_bytes':sum(map(len,objects.values())),
            'base64_unique_bytes':sum(4*((len(raw)+2)//3) for raw in objects.values()),
            'canonical_base64_object_map_bytes':len(json.dumps({k:base64.b64encode(v).decode() for k,v in objects.items()},sort_keys=True,separators=(',',':')).encode()),
            'mac_index_bytes':index_desc['bytes'],'known_historical_union_claimed':False,
            'whole_future_release_bundle_size_claimed':False,'all_orbit_images_read_by_consumer':False}
        capacity_desc,_=put(OUT/'CAPACITY.json',encode(capacity))
        result={'schema':'hepta.runtime-properties.actual-proof-mirror.v1','state':'ACTUAL_ORIGINALS_MIRRORED',
            'source':source_desc,'input_packet':request['packet'],'packet_copy':packet_desc,
            'original_index':request['original_index'],'original_index_copy':original_index_copy,
            'index':index_desc,'capacity':capacity_desc,'collector_result':collector_result,
            'capacity_original':capacity_copy,'original_path_count':len(originals),'retained_path_count':len(saved),
            'unique_sha256_objects':len(objects),'existing_captured_verifier':verifier_retained,
            'existing_independent_verifier':independent_retained,
            'all_retained_bytes_and_metadata_rechecked':True,'original_raw_reports_rewritten':False,
            'all_orbit_images_read_by_consumer':False,'complete_archive_retained_on_p4':True,
            'remote_read_steps':chain.steps,'phone_operations':0,'active_policy_writes':0,
            'parser_or_query_executions':0,'policy_adoption_recorded':False}
        result_desc,_=put(OUT/'MIRROR-RESULT.json',encode(result))
        print(json.dumps({'result':result_desc,'index':index_desc,'report':mirror['report'],
            'capacity':capacity,'phone_operations':0},sort_keys=True));return 0
    except BaseException as error:
        put(OUT/'MIRROR-FAILURE.json',encode({'state':'ORIGINAL_PROOF_MIRROR_STOPPED_NO_REPLAY',
            'source':source_desc,'error_type':type(error).__name__,'detail':str(error)[:2048],
            'remote_read_steps':chain.steps,'automatic_retry':False,'phone_operations':0}))
        raise

if __name__=='__main__':raise SystemExit(main())
