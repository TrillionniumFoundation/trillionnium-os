#!/usr/bin/env python3
"""Retain the actual Root runtime-properties transaction on P4 for its separate comparison.

This source only collects pinned host originals through the reviewed pure verifier
and reuses three frozen host SSH methods. It never calls phone, a policy setter,
the comparator, a native sender, or a component lifecycle entry. Default preview
does not read a request or create an output. Unknown transfer is never replayed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
P=Path('/home/alex/razr60-local-model-v150')
LIVE=B/'policy-runtime-properties-r10-live-02'
INDEPENDENT_VERIFIER=B/'policy-runtime-properties-r10-independent-host-verifier-r1-candidate01/source/policy_runtime_properties_verifier.py'
APPLIED_VERIFIER={'bytes':124306,'sha256':'5cd18af19e1cd4cbe98542996fa41960bc36f697c6687ce201312b8ceda91c00'}
OUT=B/'policy-runtime-properties-r10-post-live-root02-retention01'
P4_OUT=P/'policy-runtime-properties-r10-r1/post-live-root02-inputs01'
TRANSPORT={'path':str(B/'native-guard-r10-r1-operator-r4/root-chain/source/run_component_root_once.py'),
    'bytes':43438,'sha256':'860aaf747e89411efa993783b950f709b1d8ac5d7b606575065bdff74ef98e22'}
STATIC_INDEX={'path':str(B/'policy-runtime-properties-r10-offline-proof01/ADOPTION-PROOF-INPUTS.json'),
    'bytes':204360,'sha256':'efb2e2bfc17182f79db6036c4fddb9e06cf16d73e500766a7d8076e243a12390'}
POST_MANIFEST={'path':str(B/'policy-runtime-properties-r10-independent-post-r1-candidate01/COMPARISON-SOURCE-MANIFEST.json'),
    'bytes':3251,'sha256':'314619e8767c3159a6ca767c2147629e65809e3578e656b3138c06d7dff07840'}
IMAGE_BUILD={'path':str(P/'policy-runtime-properties-r10-r1/offline-candidate01/actual-01/BUILD-RESULT.json'),
    'bytes':3954,'sha256':'86b2042d49c971cb9fd6dc507cd0482a4319151cccca34ecd06554ee08b4dde7'}
ROOT_DRIVER_SHA='574e639f52a3b99dc2ea6d6f82a7455d445fdb4d758bc486cf877df316921ebb'
PARENT_SHA='50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
ROOT_DECISION_SHA='5a08041da77eeec9168c869ae76adae0a117a5e34872aa07a1a096bc06a36132'
PARENT_ADOPTION_SHA='a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5'
# Filled only after Root's actual captured provenance and execution exist.
ACTUAL_INPUTS=None
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
HASH=re.compile('[0-9a-f]{64}\\Z')
POST_KEYS={'schema','root_scope_decision','parent_adoption','parent','candidate',
    'image_build_result','live_provenance_inputs','live_verifier_source','applied_verifier_source','input_original_map',
    'delta_rule','full_rule','parent_rule','tool_inventory','image_comparator',
    'image_comparator_source','parent_av_originals','parent_set_av_originals','parent_apex_original','candidate_av_tool',
    'candidate_av_source','secondary_observation'}

def need(value,message):
    if not value:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def strict(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate JSON key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def metadata(s):
    return {k:getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
def descriptor(path,raw):return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}
def descriptor_key(row):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'}
         and type(row['path']) is str and Path(row['path']).is_absolute()
         and '..' not in Path(row['path']).parts and type(row['bytes']) is int
         and 0<=row['bytes']<=64*1024*1024 and type(row['sha256']) is str and HASH.fullmatch(row['sha256']),
         'exact bounded original descriptor required')
    return (row['path'],row['bytes'],row['sha256'])

class Originals:
    def __init__(self):self.rows={};self.raws={};self.total=0;self.reads=[]
    def read(self,row):
        key=descriptor_key(row);path=Path(row['path'])
        need(path.is_relative_to(B) and path!=B and path.resolve(strict=True)==path,'only canonical explicit Mac project originals')
        before=path.lstat()
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==row['bytes'],'regular single-link sized original')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            need(metadata(os.fstat(fd))==metadata(before),'original open identity changed')
            with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(row['bytes']+1)
            need(metadata(os.fstat(fd))==metadata(before)==metadata(path.lstat()),'original metadata changed during read')
        finally:os.close(fd)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'original size or SHA differs')
        record={'descriptor':dict(row),'metadata':metadata(before)}
        if row['path'] in self.rows:
            need(self.rows[row['path']]==record and self.raws[row['path']]==raw,'same original path changed')
        else:
            need(len(self.rows)<512 and self.total+len(raw)<=128*1024*1024,'bounded complete input collection')
            self.rows[row['path']]=record;self.raws[row['path']]=raw;self.total+=len(raw)
        self.reads.append(dict(row))
        return raw
    def known(self,path,expected_sha256=None):
        need(path.is_absolute() and path.resolve(strict=True)==path,'canonical own source or explicit request')
        s=path.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<=s.st_size<=64*1024*1024,'bounded known source')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            need(metadata(os.fstat(fd))==metadata(s),'known source identity changed')
            with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(s.st_size+1)
            need(metadata(os.fstat(fd))==metadata(s)==metadata(path.lstat()),'known source metadata changed')
        finally:os.close(fd)
        row=descriptor(path,raw)
        need(len(raw)==s.st_size and (expected_sha256 is None or row['sha256']==expected_sha256),'explicit known SHA differs')
        self.read(row);return row
    def bookend(self):
        initial=list(self.rows.values())
        for item in initial:self.read(item['descriptor'])
        return {path:self.rows[path] for path in sorted(self.rows)}

def load_exact(raw,path,name):
    module=types.ModuleType(name);module.__file__=path
    module.__reviewed_source_sha256__=sha(raw)
    exec(compile(raw,path,'exec'),module.__dict__)
    return module

def retained_files(originals,p4_out,policy_originals):
    need(p4_out==P4_OUT,'fixed new P4 retention root')
    policy_keys={descriptor_key(row) for row in policy_originals}
    need(len(policy_keys)==2 and all(row['path'] in originals.rows for row in policy_originals),
         'both actual policy originals must be collected')
    mapping=[];files={}
    for index,path in enumerate(sorted(originals.rows)):
        row=originals.rows[path]['descriptor'];raw=originals.raws[path]
        suffix='.bin' if descriptor_key(row) in policy_keys else '.original'
        rel='originals/'+str(index).zfill(3)+'-'+sha(path.encode())[:20]+suffix
        target=descriptor(p4_out/rel,raw)
        mapping.append({'original':dict(row),'retained':target});files[rel]=raw
    need(len({x['original']['path'] for x in mapping})==len(mapping)
         and len({x['retained']['path'] for x in mapping})==len(mapping),'bijective retained paths')
    return mapping,files

def build_post_plan(static,summary,live,live_raw,mapping,p4_out):
    index={descriptor_key(x['original']):x['retained'] for x in mapping}
    def mapped(row):
        key=descriptor_key(row);need(key in index,'actual verifier dependency missing from map');return index[key]
    plan=dict(static);need(plan.pop('schema')=='hepta.runtime-properties-r10.complete-policy-comparison-plan.v1','fixed offline plan schema')
    plan.pop('construction_receipt')
    plan.update({'schema':'hepta.runtime-properties-r10.post-live-complete-policy-comparison-plan.v2',
        'image_build_result':dict(IMAGE_BUILD),'input_original_map':mapping,
        'live_provenance_inputs':descriptor(p4_out/'LIVE-PROVENANCE-INPUTS.original.json',live_raw),
        'live_verifier_source':mapped(summary['independent_verifier_source']),
        'applied_verifier_source':mapped(summary['applied_verifier_source']),
        'parent':mapped(summary['parent']),'candidate':mapped(summary['candidate']),
        'root_scope_decision':mapped(summary['root_scope_decision']),
        'parent_adoption':mapped(summary['parent_adoption_history'])})
    need(set(plan)==POST_KEYS,'exact frozen post comparator plan fields')
    need(plan['parent']['sha256']==PARENT_SHA and plan['parent']['bytes']==2667608
         and plan['root_scope_decision']['sha256']==ROOT_DECISION_SHA
         and plan['parent_adoption']['sha256']==PARENT_ADOPTION_SHA,'approved parent/decision/history mapping differs')
    need(plan['parent']['path'].endswith('.bin') and plan['candidate']['path'].endswith('.bin'),
         'actual AV reader requires explicit regular .bin policy copies')
    need(len(plan['parent_av_originals'])==len(plan['parent_set_av_originals'])==11,
         'all approved original parent read/set rows are preserved')
    return plan

def require_actual_inputs():
    need(type(ACTUAL_INPUTS) is dict
         and set(ACTUAL_INPUTS)=={'live_provenance_inputs','verifier_source','independent_verifier_source','root_execution'},
         'actual live provenance/verifier/Root execution pins remain unpublished')
    for row in ACTUAL_INPUTS.values():descriptor_key(row)
    need(ACTUAL_INPUTS['live_provenance_inputs']['path']==str(LIVE/'LIVE-PROVENANCE-INPUTS.json')
         and ACTUAL_INPUTS['verifier_source']['path']==str(LIVE/'capture/originals/policy_runtime_properties_verifier.original.py')
         and ACTUAL_INPUTS['root_execution']['path']==str(LIVE/'ROOT-EXECUTION.json')
         and ACTUAL_INPUTS['independent_verifier_source']['path']==str(INDEPENDENT_VERIFIER)
         and {k:ACTUAL_INPUTS['verifier_source'][k] for k in ('bytes','sha256')}==APPLIED_VERIFIER
         and ACTUAL_INPUTS['independent_verifier_source']['sha256']!=APPLIED_VERIFIER['sha256'],
         'only this actual transaction may be retained')
    return ACTUAL_INPUTS

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request',type=Path,required=True)
    parser.add_argument('--request-sha256',required=True)
    parser.add_argument('--execute-host-retention',action='store_true')
    a=parser.parse_args(argv)
    if not a.execute_host_retention:
        print(json.dumps({'state':'PREVIEW_NO_REQUEST_READ_NO_TRANSFER_NO_COMPARISON',
            'root_output':str(LIVE),'mac_output':str(OUT),'p4_output':str(P4_OUT),
            'phone_operations':0,'policy_writes':0,'comparison_processes':0}));return 0
    actual=require_actual_inputs()
    os.umask(0o077);sys.dont_write_bytecode=True
    need(HASH.fullmatch(a.request_sha256),'explicit retention request SHA')
    control=Originals();source_desc=control.known(Path(__file__).resolve())
    request_desc=control.known(a.request,a.request_sha256);request_raw=control.read(request_desc);request=strict(request_raw)
    fields={'schema','live_provenance_inputs','verifier_source','independent_verifier_source','collector_source','root_output','out','p4_out'}
    need(type(request) is dict and set(request)==fields
         and request['schema']=='hepta.runtime-properties-r10.post-live-retention-request.v2'
         and request['collector_source']==source_desc
         and request['root_output']==str(LIVE) and request['out']==str(OUT) and request['p4_out']==str(P4_OUT),
         'exact current source and new transaction retention request')
    need(request['live_provenance_inputs']==actual['live_provenance_inputs']
         and request['verifier_source']==actual['verifier_source']
         and request['independent_verifier_source']==actual['independent_verifier_source'],'actual published dual-identity input pins differ')
    live_raw=control.read(request['live_provenance_inputs']);live=strict(live_raw)
    need(live['root_execution']==actual['root_execution'],'actual Root execution pin differs')
    need(live['schema']=='hepta.runtime-properties-r10.live-provenance-inputs.v2','original live inputs schema')
    for field,name in (('root_plan','ROOT-POLICY-PLAN.original.json'),('root_intent','ROOT-LIVE-INTENT.json'),('root_execution','ROOT-EXECUTION.json')):
        need(live[field]['path']==str(LIVE/name),'actual runtime-properties transaction original path differs')
    need(request['verifier_source']==live['originals']['policy_runtime_properties_verifier.original.py']
         and request['independent_verifier_source']==live['independent_verifier_source'],
         'separate actual captured and independent host verifier originals')
    originals=Originals();applied_raw=originals.read(request['verifier_source'])
    need({'bytes':len(applied_raw),'sha256':sha(applied_raw)}==APPLIED_VERIFIER,'immutable actual applied verifier pin')
    verifier_raw=originals.read(request['independent_verifier_source'])
    need(0<len(verifier_raw)<=262144 and sha(verifier_raw)!=APPLIED_VERIFIER['sha256'],'bounded distinct independent verifier')
    verifier=load_exact(verifier_raw,request['independent_verifier_source']['path'],'reviewed_independent_runtime_properties_post_retention_verifier')
    # The callback, rather than a static list of JSON fields, is the authoritative
    # dependency collector. Every actual nested provenance read is included.
    summary=verifier.verify_live_capture(live,read_pinned=originals.read)
    need(summary['comparison_route']=='verified_semantic_export' and summary['expected_live_export'] is None
         and summary['policy_adoption_authorized'] is False and summary['phone_calls']==0,
         'pure complete live provenance verification required')
    root_plan=strict(originals.read(live['root_plan']))
    need(root_plan['schema']=='hepta.root.runtime-properties-live-plan.v2' and root_plan['boot_id']==BOOT
         and root_plan['out']==str(LIVE) and root_plan['driver_source']['sha256']==ROOT_DRIVER_SHA,
         'only the reviewed runtime-properties Root transaction')
    for key in ('parent','candidate','root_scope_decision','parent_adoption_history'):originals.read(summary[key])
    originals.read(live['originals']['policy_runtime_properties_verifier.original.py'])
    need(summary['binding']['verifier_source']==APPLIED_VERIFIER
         and summary['applied_verifier_source']==request['verifier_source']
         and summary['independent_verifier_source']==request['independent_verifier_source'],
         'applied and independently executing verifier source bindings differ')
    static_index=strict(control.read(STATIC_INDEX))
    need(static_index['schema']=='hepta.runtime-properties-r10.adoption-proof-inputs.v1'
         and static_index['comparison_kind']=='offline_candidate'
         and static_index['report']['sha256']=='149c5063d98b3b7674364e34b98465c387d8f187fe1f26d3060ebf0e75c739cf',
         'only the completed offline source plan')
    static_raw=control.read(static_index['plan']);static=strict(static_raw)
    need(sha(static_raw)=='c3d0fba01f4513a3366fed4001a25ea32d5df4b5bdfdd80569fe876607112896',
         'actual completed offline plan raw differs')
    post_raw=control.read(POST_MANIFEST);post_manifest=strict(post_raw)
    need(post_manifest['schema']=='hepta.runtime-properties.final-source-package.v1'
         and len(post_manifest['sources'])==5,'exact frozen five-source package')
    for item in post_manifest['sources']:control.read(item)
    transport_raw=control.read(TRANSPORT);transport=load_exact(transport_raw,TRANSPORT['path'],'reviewed_host_only_retention_transport')
    mapping,files=retained_files(originals,P4_OUT,(summary['parent'],summary['candidate']))
    plan=build_post_plan(static,summary,live,live_raw,mapping,P4_OUT);plan_raw=encoded(plan)
    original_bookends=originals.bookend();control_bookends=control.bookend()
    collection={'schema':'hepta.runtime-properties-r10.actual-live-input-collection.v1',
        'state':'PURE_ACTUAL_VERIFIER_READ_SET_COLLECTED_NO_COMPARISON',
        'source':source_desc,'request':request_desc,'live_provenance_inputs':request['live_provenance_inputs'],
        'verifier_source':request['verifier_source'],'independent_verifier_source':request['independent_verifier_source'],
        'root_output':str(LIVE),'p4_output':str(P4_OUT),
        'post_plan':descriptor(P4_OUT/'POST-PLAN.json',plan_raw),'input_original_map':mapping,
        'original_metadata':original_bookends,'control_originals':control_bookends,
        'raw_bytes':originals.total,'original_path_count':len(mapping),
        'raw_full9_preserved_without_json_reencoding':True,'dynamic_verifier_read_set_complete':True,
        'phone_operations':0,'policy_writes':0,'comparison_processes':0,'automatic_retry':False}
    files.update({'LIVE-PROVENANCE-INPUTS.original.json':live_raw,'POST-PLAN.json':plan_raw,
        'COLLECTION-INDEX.original.json':encoded(collection),'RETENTION-REQUEST.original.json':request_raw,
        'RETENTION-SOURCE.original.py':control.read(source_desc)})
    need(len(files)<=520 and sum(map(len,files.values()))<=132*1024*1024,'bounded actual transfer')
    need(OUT.parent.resolve(strict=True)==OUT.parent and not OUT.exists() and not OUT.is_symlink(),'fresh Mac audit root')
    transport.newdir(OUT)
    transport.put(OUT/'REQUEST.original.json',request_raw)
    transport.put(OUT/'SOURCE.original.py',control.read(source_desc))
    transport.put(OUT/'COLLECTION-INDEX.json',encoded(collection))
    transport.put(OUT/'POST-PLAN.original.json',plan_raw)
    transport.put(OUT/'LIVE-PROVENANCE-INPUTS.original.json',live_raw)
    expected={name:[len(raw),sha(raw)] for name,raw in files.items()}
    transport.put(OUT/'TRANSFER-INTENT.json',encoded({'schema':'hepta.runtime-properties-r10.host-retention-intent.v1',
        'source':source_desc,'request':request_desc,'transport':TRANSPORT,'p4_output':str(P4_OUT),
        'files':expected,'maximum_transfer_attempts':1,'automatic_retry':False,
        'phone_operations':0,'comparison_processes':0}))
    chain=transport.Chain.__new__(transport.Chain);chain.out=OUT;chain.steps=[];chain.remote_root=str(P4_OUT)
    try:
        result=chain.remote_files('runtimeprops2-post-input-retention',files,create_root=True)
        need(result=={'state':'EXACT_NEW_HOST_FILES_WRITTEN','files':expected},'actual full P4 readback result differs')
        originals.bookend();control.bookend()
        completed={'schema':'hepta.runtime-properties-r10.host-retention-result.v1',
            'state':'ACTUAL_P4_INPUTS_RETAINED_COMPARISON_NOT_STARTED',
            'source':source_desc,'request':request_desc,'live_provenance_inputs':request['live_provenance_inputs'],
            'verifier_source':request['verifier_source'],'independent_verifier_source':request['independent_verifier_source'],
            'post_plan':descriptor(P4_OUT/'POST-PLAN.json',plan_raw),
            'collection_index':descriptor(OUT/'COLLECTION-INDEX.json',encoded(collection)),
            'p4_output':str(P4_OUT),'files':expected,'transfer_steps':chain.steps,
            'source_originals_rechecked':True,'raw_json_originals_rewritten':False,
            'phone_operations':0,'policy_writes':0,'comparison_processes':0,'automatic_retry':False,
            'comparison_cli':['/usr/bin/python3','-I','-B',
                str(P/'policy-runtime-properties-r10-r1/independent-post-source01/source/run_post_live_actual.py'),
                '--plan',str(P4_OUT/'POST-PLAN.json'),'--plan-sha256',sha(plan_raw),
                '--out',str(P/'policy-runtime-properties-r10-r1/post-live-root02-actual01'),'--execute-host-only']}
        transport.put(OUT/'RESULT.json',encoded(completed))
        print(json.dumps({'state':completed['state'],'result':descriptor(OUT/'RESULT.json',encoded(completed)),
            'post_plan':completed['post_plan'],'original_paths':len(mapping),'phone_operations':0,
            'comparison_processes':0},sort_keys=True));return 0
    except BaseException as error:
        transport.put(OUT/'FAILURE.json',encoded({'schema':'hepta.runtime-properties-r10.host-retention-failure.v1',
            'state':'ORIGINAL_HOST_RETENTION_STOPPED_NO_REPLAY','error_type':type(error).__name__,
            'detail':str(error)[:2048],'source':source_desc,'request':request_desc,
            'p4_output':str(P4_OUT),'transfer_steps':chain.steps,
            'automatic_retry':False,'phone_operations':0,'comparison_processes':0}))
        raise

if __name__=='__main__':raise SystemExit(main())
