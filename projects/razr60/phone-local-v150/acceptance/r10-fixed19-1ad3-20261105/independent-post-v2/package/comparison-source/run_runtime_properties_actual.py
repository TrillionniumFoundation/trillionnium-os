#!/usr/bin/env python3
"""Once-only host construction and complete comparison of the separately approved runtime-property read delta.

The default is a no-read preview. Execution never contacts a phone and never loads
a policy. It uses the original compiler, libsepol, query binary and table readers.
Every subprocess has an original intent, streams and terminal record. Failure is
preserved; this program contains no retry or in-place repair path.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import types

P=Path('/home/alex/razr60-local-model-v150')
ROOT=P/'policy-runtime-properties-r10-r1/offline-candidate01'
PARENT={'path':str(P/'policy-native5-r10-r1/post-live-root02-bin-plan-01/actual-live-policy-after.bin'),
        'bytes':2667608,'sha256':'50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'}
QUERY={'path':str(P/'sepol-offline-query-r1-20261104/build-01/policy_av_query'),
       'bytes':34976,'sha256':'86f6d18eab7271d9a5688e5f7b03ed5b55740b9679e7dd078661573ad67f0c90'}
COMPARATOR_SHA='d8acacb496fbc1ff1af20a85daa8d03d1552fcbaeed1f837bfa65c1d4cd42871'
COMPARATOR_BYTES=61615
C_SHA='da60ee90209a26216f053064a7ca47ebcb73c4730b4e00378886b5d653de09aa'
C_BYTES=22838
APPROVED_ROW_COUNT=11
APPROVED_ATOM_COUNT=44
RULE_PINS={'delta': (3154, 'fa32d9ae9dfd1f8e9100ebb966a327bf059ed53d307b58be9ed69c8c9b90c1d6'), 'full': (17284, '424e1c680d37583f039c8cc5e2727200b3f9ad8fd29d35616173a5102b0218d1')}
REFERENCE_PINS={
 'ROOT-DECISION.original.json':(24830,'5a08041da77eeec9168c869ae76adae0a117a5e34872aa07a1a096bc06a36132'),
 'PARENT-ADOPTION.original.json':(146368,'a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5'),
 'sepolicy.parent.rule':(14130,'aeda92123f1d043de2c53dd345dd7372b98da7b776299d57bda531dda868e4a1'),
 'EXISTING-PRIVATE-POLICY-TOOLS.original.json':(19446,'b41918ef19a0c00b0ab2295c278f204b8d66c654e8dacad05db0dea232fbd288'),
 'PARENT-BUILD-RESULT.original.json':(3822,'1ca4472eb750cbfad5154c6d65b8d32a69b61292d0019c655b249edbaa604be2'),
 'policy_av_query.original.c':(17720,'262b264c79d12c1cd2af146808ac1c5998f6aa0159515a17796c381e12630a3c'),
 'SECONDARY-DEPENDENCIES.original.json':(30353,'79afdcc1e87e2a13fc9c7276c136cd1937e4cf62d6f8a97d6f3ae162d42e2811'),
}
PARENT_AV=(('runtime-property-remaining-av-matrix-20261105-r1/worker-build_attestation_prop-file.stdout.original', 2188, '5d3c1bc4ef9f799880c530700d7db6065d3c5b3772fbc2b18e02f8940d4f3baf'), ('runtime-property-remaining-av-matrix-20261105-r1/worker-dalvik_config_prop-file.stdout.original', 2184, '8998d0d4797cbc42e3fa6ed347d11ec3bc68c148de7e80300cf0da01bbc13fcd'), ('runtime-property-remaining-av-matrix-20261105-r1/worker-dalvik_dynamic_config_prop-file.stdout.original', 2192, 'b56b37b7cdc39a5b9f12751ada3e379d896365e764502e987fa3a917c2561cc5'), ('runtime-property-remaining-av-matrix-20261105-r1/worker-dalvik_runtime_prop-file.stdout.original', 2185, 'd405f388bdcfd78ecbf9c46e14a1d53f93423d74eb3f069bacc58169a6969a8c'), ('sdk-build-current-policy-av-matrix-20261105-r2/worker-default-file.stdout.original', 2178, 'db3c8b1addf98f370229cc71c37d6bbe09cc67c6c187e13f83d4d46b638c825a'), ('runtime-property-remaining-av-matrix-20261105-r1/worker-odsign_prop-file.stdout.original', 2177, '433c5cd49c3d8e8f2183ed230c30f3064cc408ea8fb21a9a3bb43f744320b4ee'), ('runtime-property-remaining-av-matrix-20261105-r1/worker-persist_debug_prop-file.stdout.original', 2184, '310ee62c1747b6d8e9870f2d397dde04fbe6ddd0f5a4e4cb44b1716d3b34507a'), ('post-sdk-density-current-policy-av-matrix-20261105-r1/worker-qemu-file.stdout.original', 2190, 'c08fa538cc91dc8ed0a15e1550d478694a5269cbc359155971f83f3f847d44d6'), ('runtime-property-remaining-av-matrix-20261105-r1/worker-radio_prop-file.stdout.original', 2176, 'b63d9c430d0ad3c92b60fccc9d0d14d131fb209daf7ece0e434458122901bf0a'), ('runtime-property-remaining-av-matrix-20261105-r1/worker-system_prop-file.stdout.original', 2177, '9ccb9cd491adbdef4e7a32b4ea39744f42081bd829edd03cd689e452cb844593'), ('runtime-property-remaining-av-matrix-20261105-r1/worker-vendor_mot_hw_prop-file.stdout.original', 2184, '7c1be139ba444d9919ce6d3112e50ad788a9121c8721e2adad7d9c57d8b08c3e'))
PARENT_SET_AV=(('runtime-property-remaining-av-matrix-20261105-r1/worker-build_attestation_prop-set.stdout.original', 1715, '7ebd6a8d40ef761f98523dea81c9baddecbf6dedea67b831d6627e02d0b6b2da'), ('runtime-property-remaining-av-matrix-20261105-r1/worker-dalvik_config_prop-set.stdout.original', 1711, '296344c44ebbeb2146cc37cab349efdd5de2e8b7577f16cb12292d35cd94f857'), ('runtime-property-remaining-av-matrix-20261105-r1/worker-dalvik_dynamic_config_prop-set.stdout.original', 1719, '0c0386666b5bd476b93477564be40a520bb4f4d8093bce976780e6ad8a6d932d'), ('runtime-property-remaining-av-matrix-20261105-r1/worker-dalvik_runtime_prop-set.stdout.original', 1712, 'a689fe2461b430b65a2d47ff0938c9801bea7e6619198091e7ee08b0a58bd955'), ('sdk-build-current-policy-av-matrix-20261105-r2/worker-default-set.stdout.original', 1705, '99176f65e11969ba1086eddd5136e5c8e5c1bfcf916ecb79f126a1499292e90a'), ('runtime-property-remaining-av-matrix-20261105-r1/worker-odsign_prop-set.stdout.original', 1704, 'bcfd498d482c8a526f71387d5e57f99d08ceaf26cfa67c5a935e63383c64ee3a'), ('runtime-property-remaining-av-matrix-20261105-r1/worker-persist_debug_prop-set.stdout.original', 1711, 'ccf3e962eb52e488217d30b2b7a09a3d2ded0d482aa8a16f6ea2636d54dd42a2'), ('post-sdk-density-current-policy-av-matrix-20261105-r1/worker-qemu-set.stdout.original', 1717, '319e5dfc5058e7e0d5a4a3577c5679c00ef80fde180c79e16b59f684834168ad'), ('runtime-property-remaining-av-matrix-20261105-r1/worker-radio_prop-set.stdout.original', 1703, '1a767a6edf976157d715450cb2853e4e882208aca338c320ee6c7ab43e954375'), ('runtime-property-remaining-av-matrix-20261105-r1/worker-system_prop-set.stdout.original', 1704, 'a36424018985d2936bfa3d9564d146a1431a4d95980e3ba3affd4f1b25595c28'), ('runtime-property-remaining-av-matrix-20261105-r1/worker-vendor_mot_hw_prop-set.stdout.original', 1711, '964b5b8a36e2eab91df989af00bb669c984ec77c5fcb75b27cfce7e83ecdbaf9'))
APEX={'path':str(P/'policy-native5-r10-r1/post-live-root02-actual-02/comparison/candidate-existing-apex-search.stdout.original'),
      'bytes':2196,'sha256':'34fc5fe1e5278b07ff80b80de8b0cf3c8a4bbaaf5ca3518a9095a2e3ed78d6b7'}

def need(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def strict(raw):
    def pairs(rows):
        value={}
        for k,v in rows:
            need(k not in value,'duplicate JSON key');value[k]=v
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def meta(s):return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def syncdir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def newdir(path):
    need(path.parent.resolve(strict=True)==path.parent,'new output parent canonical')
    path.mkdir(mode=0o700);syncdir(path.parent)
def put(path,raw):
    if not isinstance(raw,bytes):raw=encoded(raw)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    syncdir(path.parent);need(path.read_bytes()==raw,'output readback')
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}

class Inputs:
    def __init__(self):self.rows={}
    def read(self,row):
        need(type(row) is dict and set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int
             and 0<=row['bytes']<=64*1024*1024,'exact bounded input descriptor')
        p=Path(row['path']);need(p.is_absolute() and p.resolve(strict=True)==p,'canonical exact original')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==row['bytes'],'regular original size')
            with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(row['bytes']+1)
            need(meta(a)==meta(os.fstat(fd))==meta(p.lstat()),'original metadata changed')
        finally:os.close(fd)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'original bytes differ: '+str(p))
        record={'descriptor':row,'metadata':meta(a)}
        need(str(p) not in self.rows or self.rows[str(p)]==record,'original generation changed')
        self.rows[str(p)]=record;return raw
    def known(self,path,*,pin=None,size=None):
        p=Path(path);need(p.resolve(strict=True)==p,'canonical descriptor source')
        s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<=s.st_size<=64*1024*1024,'regular bounded descriptor source')
        raw=p.read_bytes();row={'path':str(p),'bytes':len(raw),'sha256':sha(raw)}
        need(size is None or row['bytes']==size,'source size');need(pin is None or row['sha256']==pin,'source SHA')
        self.read(row);return row
    def bookend(self):
        for value in list(self.rows.values()):self.read(value['descriptor'])
        return {p:value for p,value in sorted(self.rows.items())}

def run_original(out,label,argv,timeout,inputs):
    before=inputs.bookend();start=time.time_ns();begin=time.monotonic()
    put(out/(label+'.INTENT.json'),{'schema':'hepta.runtime-properties.host-child-intent.v1','argv':argv,
        'timeout_seconds':timeout,'started_epoch_ns':start,'automatic_retry':False,
        'stdin_bytes':0,'phone_operations':0,'active_policy_writes':0,'input_originals':before})
    try:
        r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=timeout,
            env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
    except subprocess.TimeoutExpired as e:
        op=put(out/(label+'.stdout.original'),e.stdout or b'');ep=put(out/(label+'.stderr.original'),e.stderr or b'')
        put(out/(label+'.PROCESS.json'),{'argv':argv,'returncode':None,'timed_out':True,'captured_streams_complete':False,
            'stdout':op,'stderr':ep,'automatic_retry':False,'started_epoch_ns':start,'ended_epoch_ns':time.time_ns(),
            'elapsed_seconds':time.monotonic()-begin,'input_originals_before':before,
            'input_originals_after':inputs.bookend(),'phone_operations':0,'active_policy_writes':0})
        raise
    op=put(out/(label+'.stdout.original'),r.stdout);ep=put(out/(label+'.stderr.original'),r.stderr)
    process={'argv':argv,'returncode':r.returncode,'timed_out':False,'captured_streams_complete':True,
        'stdout':op,'stderr':ep,'automatic_retry':False,'started_epoch_ns':start,'ended_epoch_ns':time.time_ns(),
        'elapsed_seconds':time.monotonic()-begin,'input_originals_before':before,
        'input_originals_after':inputs.bookend(),'phone_operations':0,'active_policy_writes':0}
    pd=put(out/(label+'.PROCESS.json'),process)
    need(r.returncode==0,'actual '+label+' failed; original terminal preserved')
    return r,pd,process

def require_finalized_inputs():
    need(isinstance(COMPARATOR_SHA,str) and len(COMPARATOR_SHA)==64 and type(COMPARATOR_BYTES) is int and COMPARATOR_BYTES>0
         and isinstance(C_SHA,str) and len(C_SHA)==64 and type(C_BYTES) is int and C_BYTES>0,
         'reviewed comparator and image sources remain unpublished')
    need(type(APPROVED_ROW_COUNT) is int and APPROVED_ROW_COUNT>0 and APPROVED_ATOM_COUNT==4*APPROVED_ROW_COUNT,
         'reviewed scope counts remain unpublished')
    need(all(type(n) is int and n>0 and isinstance(h,str) and len(h)==64 for n,h in REFERENCE_PINS.values()),
         'reviewed original scope references remain unpublished')
    need(type(RULE_PINS) is dict and set(RULE_PINS)=={'delta','full'}
         and all(type(n) is int and n>0 and isinstance(h,str) and len(h)==64 for n,h in RULE_PINS.values()),
         'reviewed exact rule files remain unpublished')
    need(type(PARENT_AV) is tuple and type(PARENT_SET_AV) is tuple
         and len(PARENT_AV)==len(PARENT_SET_AV)==APPROVED_ROW_COUNT,'reviewed original AV inputs remain unpublished')

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-host-only',action='store_true')
    a=parser.parse_args(argv)
    if not a.execute_host_only:
        print(json.dumps({'state':'PREVIEW_NO_INPUT_READ_NO_CHILD','phone_operations':0,'active_policy_writes':0}));return 0
    require_finalized_inputs()
    os.umask(0o077);sys.dont_write_bytecode=True
    need(Path(__file__).resolve()==ROOT/'source/run_runtime_properties_actual.py','exact reviewed runner location')
    need(not os.environ.get('LD_PRELOAD') and not os.environ.get('LD_LIBRARY_PATH'),'injected library environment')
    inp=Inputs();selfdesc=inp.known(Path(__file__).resolve())
    comparator=inp.known(ROOT/'source/full_policy_compare_runtime_properties.py',pin=COMPARATOR_SHA,size=COMPARATOR_BYTES)
    csource=inp.known(ROOT/'source/policy_runtime_properties_image.c',pin=C_SHA,size=C_BYTES)
    refs={name:{'path':str(ROOT/'reference'/name),'bytes':size,'sha256':pin} for name,(size,pin) in REFERENCE_PINS.items()}
    for row in refs.values():inp.read(row)
    delta=inp.known(ROOT/'rules/delta.rule',size=RULE_PINS['delta'][0],pin=RULE_PINS['delta'][1])
    full=inp.known(ROOT/'rules/full.rule',size=RULE_PINS['full'][0],pin=RULE_PINS['full'][1])
    inp.read(PARENT);inp.read(QUERY);inp.read(APEX)
    parent_av=[{'path':str(P/path),'bytes':size,'sha256':pin} for path,size,pin in PARENT_AV]
    parent_set_av=[{'path':str(P/path),'bytes':size,'sha256':pin} for path,size,pin in PARENT_SET_AV]
    for row in parent_av+parent_set_av:inp.read(row)
    parent_build=strict(inp.read(refs['PARENT-BUILD-RESULT.original.json']))
    compiler=parent_build['compiler'];static=parent_build['static_library'];runtime=parent_build['runtime_library'];headers=parent_build['installed_headers']
    for row in [compiler,static,runtime,*headers]:inp.read(row)
    # Invoke only pure, exact-source inventory validation before creating an
    # output or running the compiler. This imports no SETools bytecode/module.
    module=types.ModuleType('runtime_properties_comparison_preflight');module.__file__=comparator['path']
    exec(compile(inp.read(comparator),comparator['path'],'exec'),module.__dict__)
    inventory=strict(inp.read(refs['EXISTING-PRIVATE-POLICY-TOOLS.original.json']))
    r=module.Originals()
    package=Path('/home/alex/razr60-local-runtime-v150/policy-tools-owned-v150-r1/unpack/usr/lib/python3/dist-packages')
    for row in [*inventory['package_files'],*inventory['readers'].values()]:inp.read(row)
    module.require_reviewed_scope()
    need(len(module.APPROVED_ROWS)==APPROVED_ROW_COUNT and len(module.APPROVED_ATOMS)==APPROVED_ATOM_COUNT,'paired approved literal counts')
    preflight={'root_scope_decision':refs['ROOT-DECISION.original.json'],'parent_adoption':refs['PARENT-ADOPTION.original.json'],
        'delta_rule':delta,'full_rule':full,'parent_rule':refs['sepolicy.parent.rule'],
        'parent_av_originals':parent_av,'parent_set_av_originals':parent_set_av}
    module.validate_decision_and_rules(r,preflight);module.validate_parent_av(r,preflight);module.validate_parent_set_av(r,preflight)
    for row in module.APPROVED_ATOMS:need(len(row)==5,'approved atom')
    out=ROOT/'actual-01';newdir(out)
    put(out/'INTENT.json',{'schema':'hepta.runtime-properties.host-execution-intent.v1','source':selfdesc,
        'root_scope_decision':refs['ROOT-DECISION.original.json'],'parent':PARENT,
        'comparator':comparator,'image_source':csource,'maximum_comparison_seconds':780,
        'automatic_retry':False,'phone_operations':0,'active_policy_writes':0})
    put(out/'IMPORT-SOURCE-PREFLIGHT.json',{'source_inventory':refs['EXISTING-PRIVATE-POLICY-TOOLS.original.json'],
        'source_files':inventory['package_files'],'source_file_count':81,
        'original_import_tree_closed_claimed':False,'original_import_path_added_to_sys_path':False})
    binary=out/'policy_runtime_properties_image'
    ccargv=[compiler['path'],'-std=c11','-O2','-fno-common','-Wall','-Wextra','-Werror','-Wformat=2',
        '-Wshadow','-Wconversion','-Wsign-conversion',csource['path'],static['path'],'-Wl,-z,relro,-z,now','-o',str(binary)]
    cc,ccpd,ccproc=run_original(out,'compiler',ccargv,60,inp)
    need(cc.stdout==cc.stderr==b'','compiler original streams must be empty')
    bindesc=inp.known(binary)
    build=put(out/'BUILD-RESULT.json',{'schema':'hepta.runtime-properties.actual-host-build.v1','returncode':0,
        'argv':ccargv,'source':csource,'binary':bindesc,'compiler':compiler,'static_library':static,
        'runtime_library':runtime,'installed_headers':headers,'stdout':ccproc['stdout'],'stderr':ccproc['stderr'],
        'process':ccpd,'phone_operations':0,'active_policy_writes':0})
    constructargv=[str(binary),'--construct-reviewed-runtime-properties',PARENT['path'],str(out/'construction')]
    constructed,cpd,cproc=run_original(out,'construct',constructargv,50,inp)
    need(constructed.stderr==b'','constructor stderr')
    cv=strict(constructed.stdout)
    need(cv['semantic_delta_verified'] is False and cv['approved_permission_atom_count']==APPROVED_ATOM_COUNT,'constructor qualification must be false')
    candidate=inp.known(out/'construction/candidate.bin')
    receipt=put(out/'CONSTRUCTION-RECEIPT.json',{'schema':'hepta.runtime-properties.offline-construction-receipt.v1',
        'state':'COMPLETE_OFFLINE_CANDIDATE_CONSTRUCTION','parent':PARENT,'candidate':candidate,
        'root_scope_decision':refs['ROOT-DECISION.original.json'],'image_constructor':bindesc,
        'image_constructor_source':csource,'build_result':build,'process':cpd,
        'semantic_delta_verified':False,'phone_operations':0,'active_policy_writes':0,'input_originals_unchanged':True})
    plan={'schema':'hepta.runtime-properties-r10.complete-policy-comparison-plan.v1','root_scope_decision':refs['ROOT-DECISION.original.json'],
        'parent_adoption':refs['PARENT-ADOPTION.original.json'],'parent':PARENT,'candidate':candidate,
        'construction_receipt':receipt,'delta_rule':delta,'full_rule':full,'parent_rule':refs['sepolicy.parent.rule'],
        'tool_inventory':refs['EXISTING-PRIVATE-POLICY-TOOLS.original.json'],'image_comparator':bindesc,
        'image_comparator_source':csource,'parent_av_originals':parent_av,'parent_set_av_originals':parent_set_av,'parent_apex_original':APEX,
        'candidate_av_tool':QUERY,'candidate_av_source':refs['policy_av_query.original.c'],
        'secondary_observation':refs['SECONDARY-DEPENDENCIES.original.json']}
    plandesc=put(out/'PLAN.json',plan)
    # The full parser runs once, as a separate child with original streams.
    compareargv=['/usr/bin/python3','-I','-B',comparator['path'],'--plan',plandesc['path'],
        '--plan-sha256',plandesc['sha256'],'--out',str(out/'comparison'),'--execute-host-only']
    compared,process,original=run_original(out,'full-comparison',compareargv,780,inp)
    need(compared.stderr==b'','complete comparison stderr')
    report=inp.known(out/'comparison/RESULT.json');value=strict(inp.read(report))
    need(value['schema']=='hepta.runtime-properties-r10.complete-policy-comparison.v1'
        and value['state']=='EXACT_APPROVED_RUNTIME_PROPERTY_READ_DELTA_VERIFIED'
        and value['comparison_kind']=='offline_candidate'
        and value['parent']==PARENT and value['candidate']==candidate
        and value['check_count']==value['passed_count']==16
        and len(value['checks'])==16 and all(x['passed'] is True for x in value['checks']),
        'actual complete comparison did not pass all sixteen gates')
    pp=value['package_tree_provenance'];mapping=pp['source_to_private_copy_map']
    need([x['original'] for x in mapping]==inventory['package_files'] and len(mapping)==81,'complete source/copy mapping')
    private_package=out/'comparison/owned-import-package'
    for x in mapping:
        want=private_package/Path(x['original']['path']).relative_to(package)
        need(x['retained']['path']==str(want) and all(x['retained'][k]==x['original'][k] for k in ('bytes','sha256')),
            'exact byte-identical retained import original')
    copied_inventory={'package_files':[x['retained'] for x in mapping]}
    need(module.verify_closed_package_tree(r,private_package,copied_inventory)==pp['closed_tree'],
        'complete private import tree differs from actual report')
    need(pp['original_import_tree_closed_claimed'] is False and pp['original_import_path_added_to_sys_path'] is False,
        'unindexed global installation must not be claimed as trusted import tree')
    inp.bookend();r.recheck()
    result=put(out/'EXECUTION.RESULT.json',{'schema':'hepta.runtime-properties.actual-host-execution.v1',
        'state':'ACTUAL_HOST_CONSTRUCTION_AND_COMPLETE_COMPARISON_FINISHED','source':selfdesc,
        'root_scope_decision':refs['ROOT-DECISION.original.json'],'parent':PARENT,'candidate':candidate,
        'plan':plandesc,'build':build,'construction_receipt':receipt,'comparison_process':process,'report':report,
        'returncode':0,'timed_out':False,'captured_streams_complete':True,
        'automatic_retry':False,'all_originals_rechecked':True,'check_count':16,'passed_count':16,
        'phone_operations':0,'active_policy_writes':0,'live_policy_adoption_authorized':False,'business_qualified':False})
    print(json.dumps({'state':'ACTUAL_HOST_ONLY_COMPLETE','execution':result,'report':report,
        'candidate':candidate,'checks':16,'phone_operations':0,'active_policy_writes':0},sort_keys=True));return 0

if __name__=='__main__':raise SystemExit(main())
