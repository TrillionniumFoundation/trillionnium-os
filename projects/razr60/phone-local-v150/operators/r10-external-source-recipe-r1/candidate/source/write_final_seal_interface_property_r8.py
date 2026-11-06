#!/usr/bin/env python3
"""Prepare only a host interface for FC8/C8 after actual R8 source finalization.

Default is a zero-I/O preview. It never invokes the constructor, builder, suite,
phone or policy tools. Empty current cases make its plan template unexecutable.
"""
import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

sys.dont_write_bytecode = True
B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
DELIVERY=None
FC=B/'r10-boundary-consumers-final-r10-epoch-1ad3-01'
C=B/'r10-component-boundary-input-entry-epoch-1ad3-01'
RUNTIME_PARENT=B/'native-guard-r10-r1-operator-r7/runtime'
OLD_RUNTIME=B/'native-guard-r10-r1-operator-r4/runtime'
E=B/'native-guard-attempt03-external-publication-r1/actual-02'
F04=B/'native-guard-root-chains-r10-r1/root-r10-neg01-20261104-04'
F06=B/'native-guard-root-chains-r10-r1/root-r10-neg01-20261105-06'
ENVIRONMENT_PARENT_BOUNDARY_SHA='eca628a18327146b7710a478fc2c2f716f79d55907b2821666828a0795e2060f'
RET=B/'module-r10-r1-retirement-reconciliation-01'
S=B/'r10-boundary-consumers-material-r1/actual-material-01/SHARED-MATERIALS.json'
OUT=None
PRE_POLICY_BOUNDARY_SHA='3216ab18adcafa0dda95e8a93ad35a2070e7aec286d7a518794918068ce31d12'
EXTERNAL_BOUNDARY_SHA='ee008c3b2adec701be4c0bdfd38ca7ac0d650da9b7783f51d3fe4638bfdc5b58'
F08=B/'native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08'
F07=B/'native-guard-root-chains-r10-r1/root-r10-neg01-20261105-07'
PROPERTY_PARENT_BOUNDARY_SHAS=['eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10',
    '46b03cd66426395198b4a3093117659d5cfb128cc981815934fc1ea695c97be0']
POLICY_PARENT_SHA='50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
PARENT_ADOPTION_SHA='a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5'
POLICY_PARENT_COMBINATION_SHA='ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'
SEEN={}


def need(ok, reason):
    if not ok: raise ValueError(reason)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def encode(value): return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()

def combination_encode(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()


def meta(info): return tuple(getattr(info,x) for x in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def read(path, size, digest):
    path=Path(path)
    need(path.is_absolute() and path.resolve(strict=True)==path, 'canonical input required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==size and 0<=size<=16*1024*1024,'input metadata differs')
        with os.fdopen(fd,'rb',closefd=False) as stream: raw=stream.read(size+1)
        need(len(raw)==size and sha(raw)==digest and meta(before)==meta(os.fstat(fd))==meta(path.lstat()),'input original differs')
    finally: os.close(fd)
    entry=dict(path=str(path),bytes=size,sha256=digest)
    need(str(path) not in SEEN or SEEN[str(path)]==(entry,meta(before)),'input changed between reads')
    SEEN[str(path)]=(entry,meta(before))
    return entry,raw


def flags(raw):
    tree=ast.parse(raw)
    return {a.value for n in ast.walk(tree) if isinstance(n,ast.Call)
            and isinstance(n.func,ast.Attribute) and n.func.attr=='add_argument'
            for a in n.args if isinstance(a,ast.Constant) and isinstance(a.value,str)
            and a.value.startswith('--')}


def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def put(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    sync(path.parent)
    need(path.read_bytes()==raw and path.lstat().st_nlink==1,'output readback differs')
    return dict(path=str(path),bytes=len(raw),sha256=sha(raw))


def strict(raw):
    def pairs(rows):
        value = {}
        for key,item in rows:
            need(key not in value, 'duplicate original JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _:need(False, 'nonfinite original JSON'))


def original(row):
    need(isinstance(row, dict) and set(row) == {'path','bytes','sha256'}
         and type(row['bytes']) is int
         and (0 < row['bytes'] <= 16*1024*1024 or row in (
             {'path':str(F06/'phone-late-publish/stderr.original'), 'bytes':0,
              'sha256':'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
             {'path':str(F08/'phone-late-publish/stderr.original'), 'bytes':0,
              'sha256':'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
             {'path':str(F07/'phone-late-publish/stderr.original'), 'bytes':0,
              'sha256':'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}))
         and isinstance(row['sha256'], str) and re.fullmatch('[0-9a-f]{64}',row['sha256']),
         'explicit positive original or one of the exact actual06/08/07 empty publication stderr originals required')
    return read(row['path'],row['bytes'],row['sha256'])




"""Pure exact byte inverses before execution of any current runtime member.

The sole data binding is generated after final source review. It contains no
Python source to execute. Historical bytes are reconstruction outputs only.
Unbound source is an explicit refusal, not a source or capacity qualification.
"""
import base64 as _esi_base64
import hashlib as _esi_hashlib
import json as _esi_json
import re as _esi_re
import zlib as _esi_zlib

EPOCH_SOURCE_RECIPE_DESCRIPTOR = None
_ESI_HASH = _esi_re.compile(r'[0-9a-f]{64}')
_ESI_PROOF_FIELDS = ('schema','state','runtime','combination','shared_materials','source_recipe',
    'parent_runtime','parent_combination','historical_runtime','historical_combination',
    'runtime_source_count','shared_material_count','production_source_count',
    'changed_runtime_members','unchanged_runtime_members','changed_shared_members',
    'inverse_stages','whole_manifest_and_source_inverses_verified',
    'whole_production_service_config_combination_inverses_verified',
    'source_execution_performed','live_originals_read','root02_prelaunch_admission_verified_here',
    'current_head_admission_verified_here','epoch_resource_admission_verified_here',
    'phone_calls','nonces_generated','component_qualified','business_qualified')


def _esi_need(value, reason):
    if not value:raise ValueError(reason)


def _esi_json_bytes(value):
    return (_esi_json.dumps(value,sort_keys=True,separators=(',',':'),
                            ensure_ascii=False,allow_nan=False)+'\n').encode()


def _esi_strict(raw):
    def pairs(items):
        result={}
        for key,value in items:
            _esi_need(key not in result,'duplicate source-proof JSON key');result[key]=value
        return result
    return _esi_json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite source-proof JSON')))


def _esi_bare(raw):
    _esi_need(type(raw) is bytes,'complete immutable source bytes required')
    return {'bytes':len(raw),'sha256':_esi_hashlib.sha256(raw).hexdigest()}


def _esi_same(left,right):
    return _esi_json_bytes(left)==_esi_json_bytes(right)


def _esi_exact(value,fields,reason):
    _esi_need(type(value) is dict and set(value)==set(fields),reason)


def _esi_pin(raw,pin,maximum=16*1024*1024):
    _esi_exact(pin,('bytes','sha256'),'exact source data pin required')
    _esi_need(type(pin['bytes']) is int and 0<=pin['bytes']<=maximum
        and type(pin['sha256']) is str and _ESI_HASH.fullmatch(pin['sha256'])
        and _esi_same(_esi_bare(raw),pin),'complete source data size or digest differs')
    return raw


def _esi_recipe_descriptor():
    row=EPOCH_SOURCE_RECIPE_DESCRIPTOR
    _esi_exact(row,('path','bytes','sha256'),'final source recipe descriptor is not frozen')
    path=row['path']
    _esi_need(type(path) is str and path.startswith('/') and '\0' not in path
        and all(part not in ('','.','..') for part in path.split('/')[1:])
        and type(row['bytes']) is int and 0<row['bytes']<=65536
        and type(row['sha256']) is str and _ESI_HASH.fullmatch(row['sha256']),
        'canonical absolute bounded source-frozen recipe descriptor required')
    return dict(row)


def _esi_recipe_match(row):
    fixed=_esi_recipe_descriptor()
    _esi_need(_esi_same(row,fixed),'caller cannot substitute source recipe authority')
    return fixed


def epoch_recipe_original(frozen, read_original):
    """Use the enclosing original reader and its unchanged bookend/budget."""
    _esi_need(type(frozen) is dict and 'source_recipe' in frozen and callable(read_original),
              'explicit source recipe field and original reader required')
    row=_esi_recipe_match(frozen['source_recipe'])
    raw=read_original(row)
    _esi_data(raw)
    return raw


def _esi_data(recipe_raw):
    row=_esi_recipe_descriptor()
    _esi_pin(recipe_raw,{key:row[key] for key in ('bytes','sha256')},65536)
    packet=_esi_strict(recipe_raw)
    _esi_need(_esi_json_bytes(packet)==recipe_raw,'source recipe packet canonical JSON differs')
    _esi_exact(packet,('schema','compressed','decoded','base85'),
               'final exact source recipe is not frozen')
    _esi_need(packet['schema']=='hepta.native-guard.epoch-source-data-capsule.v1'
        and type(packet['base85']) is str and len(packet['base85'])<=65536,
        'bounded data-only source recipe required')
    encoded=packet['base85'].encode('ascii','strict')
    compressed=_esi_base64.b85decode(encoded)
    _esi_need(_esi_base64.b85encode(compressed)==encoded,'noncanonical data capsule encoding')
    _esi_pin(compressed,packet['compressed'],52428)
    _esi_exact(packet['decoded'],('bytes','sha256'),'bounded decoded data pin required')
    size=packet['decoded']['bytes']
    _esi_need(type(size) is int and 0<size<=262144,'decoded source recipe exceeds fixed bound')
    stream=_esi_zlib.decompressobj()
    raw=stream.decompress(compressed,size+1)
    _esi_need(stream.eof and not stream.unused_data and not stream.unconsumed_tail
        and len(raw)==size,'source recipe must be one exact bounded complete stream')
    _esi_pin(raw,packet['decoded'],262144)
    value=_esi_strict(raw)
    _esi_need(_esi_json_bytes(value)==raw,'source recipe canonical JSON differs')
    _esi_exact(value,('schema','current','stages','historical'),
               'source recipe complete finite fields differ')
    _esi_need(value['schema']=='hepta.native-guard.epoch-whole-byte-inverse.v2'
        and type(value['stages']) is list and len(value['stages'])==2,
        'final-to-reviewed-codec and reviewed-codec-to-actual902 stages required')
    return value


def _esi_source_name(name):
    _esi_need(type(name) is str and name.startswith(('source/','reference/'))
        and len(name.split('/'))==2 and name.split('/')[1] not in ('','.','..')
        and '\0' not in name and name.endswith(('.py','.json')),
        'exact two-level runtime member name required')


def _esi_dataset(runtime_raw,source_files,combination_raw,shared_files,expected,*,recipe_bytes=0):
    # The complete original manifest and COMBO are themselves fixed authority.
    # Their exact rows are checked again; a duplicate copy of all pins is not
    # needed in the inverse recipe and is never accepted from a caller instead.
    _esi_exact(expected,('runtime','combination'),'fixed whole source-generation pins required')
    _esi_pin(runtime_raw,expected['runtime'],262144)
    _esi_pin(combination_raw,expected['combination'],262144)
    manifest=_esi_strict(runtime_raw);rows=manifest.get('files')
    combination=_esi_strict(combination_raw)
    _esi_exact(combination,('schema','state','source_seal','configuration','service_inputs',
        'production_files','artifacts','live_policy_sha256'),'exact fixed COMBO fields differ')
    _esi_need(combination['schema']=='hepta.native-guard.component-combination.v150.r10.1'
        and combination['state']=='REVIEWED_COMPONENT_BYTES_NOT_FOUR_ROLE_READY'
        and manifest.get('schema')=='hepta.native-guard.adapter-package.v1'
        and manifest.get('state')=='HOST_REVIEWED_NOT_PHONE_QUALIFIED'
        and type(rows) is list and len(rows)==32
        and type(source_files) is dict and len(source_files)==32
        and type(shared_files) is dict and len(shared_files)==17,
        'exact32 runtime and exact17 shared bodies required')
    names=[];total=len(runtime_raw)+len(combination_raw)+recipe_bytes
    for row in rows:
        _esi_exact(row,('path','bytes','sha256'),'runtime member row fields differ')
        name=row['path'];_esi_source_name(name);names.append(name)
        _esi_need(name in source_files,'fixed runtime member body is missing')
        raw=source_files[name]
        _esi_pin(raw,{k:row[k] for k in ('bytes','sha256')},
                 131072 if name.endswith('.py') else 16*1024*1024)
        total+=len(raw)
    _esi_need(len(set(names))==32 and set(names)==set(source_files),
              'runtime has an omitted, duplicate or extra original member')
    production=combination['production_files']
    _esi_need(type(production) is list and len(production)==15,'fixed production15 rows required')
    shared={}
    for row in production:
        _esi_exact(row,('path','bytes','sha256'),'fixed production row fields differ')
        name=row['path']
        _esi_need(type(name) is str and name.startswith('production/') and len(name.split('/'))==2
            and name.split('/')[1] not in ('','.','..') and name.endswith('.py') and '\0' not in name,
            'exact production member name differs')
        key='provider/source/'+name.split('/')[1]
        _esi_need(key not in shared,'duplicate fixed production member')
        shared[key]={k:row[k] for k in ('bytes','sha256')}
    shared['local-config-r10-r1.json']=combination['configuration']
    shared['PHONE-SERVICE-INPUTS-v150-r10-r1.json']=combination['service_inputs']
    _esi_need(len(shared)==17 and set(shared)==set(shared_files),'complete fixed shared names differ')
    for name,pin in shared.items():
        _esi_pin(shared_files[name],pin);total+=len(shared_files[name])
    _esi_need(total<=32*1024*1024,'source gate actual decoded inputs exceed the original whole pool')
    return manifest


def _esi_inverse(raw,recipe):
    _esi_exact(recipe,('input','output','operations'),'exact finite byte inverse required')
    _esi_pin(raw,recipe['input'])
    operations=recipe['operations']
    _esi_need(type(operations) is list and 0<len(operations)<=1024,
              'finite continuous whole-source inverse required')
    cursor=0;result=bytearray()
    for operation in operations:
        _esi_need(type(operation) is dict and operation.get('kind') in ('copy','replace'),
                  'unreviewed inverse operation')
        fields=('kind','start','bytes') if operation['kind']=='copy' else (
            'kind','start','bytes','removed_sha256','literal_utf8')
        _esi_exact(operation,fields,'exact inverse operation fields required')
        size=operation['bytes']
        _esi_need(type(operation['start']) is int and operation['start']==cursor
            and type(size) is int and 0<=size<=len(raw)-cursor,
            'inverse ranges overlap, omit, reorder or exceed complete input')
        part=raw[cursor:cursor+size]
        if operation['kind']=='copy':
            _esi_need(size>0,'empty inverse copy range')
        else:
            _esi_need(type(operation['removed_sha256']) is str
                and _ESI_HASH.fullmatch(operation['removed_sha256'])
                and _esi_bare(part)['sha256']==operation['removed_sha256']
                and type(operation['literal_utf8']) is str
                and len(operation['literal_utf8'])<=131072,
                'removed full source span or bounded old literal differs')
            part=operation['literal_utf8'].encode('utf-8','strict')
            _esi_need(len(part)<=131072,'complete old literal exceeds the fixed source bound')
        _esi_need(len(result)+len(part)<=16*1024*1024,'reconstructed parent exceeds original read bound')
        result.extend(part);cursor+=size
    _esi_need(cursor==len(raw),'whole inverse did not consume the complete original input')
    return _esi_pin(bytes(result),recipe['output'])


def _esi_stage(data,stage):
    _esi_exact(stage,('name','expected','runtime','sources','combination','shared'),
               'exact manifest/source/shared inverse stage required')
    runtime,sources,combo,shared=data
    _esi_need(type(stage['name']) is str and type(stage['sources']) is dict
        and set(stage['sources'])<=set(sources) and type(stage['shared']) is dict
        and set(stage['shared'])<=set(shared),'inverse stage names or changed member set differ')
    result_sources=dict(sources);result_shared=dict(shared)
    for name,recipe in stage['sources'].items():result_sources[name]=_esi_inverse(sources[name],recipe)
    for name,recipe in stage['shared'].items():result_shared[name]=_esi_inverse(shared[name],recipe)
    result_runtime=_esi_inverse(runtime,stage['runtime'])
    result_combo=_esi_inverse(combo,stage['combination'])
    _esi_dataset(result_runtime,result_sources,result_combo,result_shared,stage['expected'])
    return result_runtime,result_sources,result_combo,result_shared


def _esi_checked(runtime_raw,source_files,combination_raw,shared_files,*,recipe_raw):
    recipe=_esi_data(recipe_raw)
    _esi_dataset(runtime_raw,source_files,combination_raw,shared_files,recipe['current'],
                 recipe_bytes=len(recipe_raw))
    current=(runtime_raw,source_files,combination_raw,shared_files);data=current;checked=[]
    for stage in recipe['stages']:
        data=_esi_stage(data,stage)
        checked.append({'name':stage['name'],'runtime':_esi_bare(data[0]),
                        'combination':_esi_bare(data[2])})
    _esi_need(checked[0]['name']=='exact_pre_epoch_codec_source'
        and checked[1]['name']=='actual_closed902_runtime'
        and checked[1]['runtime']=={'bytes':16808,'sha256':
          '31da1d92d2d9c833cd053db15b0cc40824e750705d315a320206a2f7a52a6bfb'},
        'source inverse does not terminate at the fixed actual902 runtime')
    historical=recipe['historical']
    _esi_exact(historical,('runtime','late','expected'),'exact historical67 proof inverse required')
    base_files=dict(data[1]);base_files['source/late_boundary.py']=_esi_inverse(
        base_files['source/late_boundary.py'],historical['late'])
    base_raw=_esi_inverse(data[0],historical['runtime'])
    base_value=_esi_dataset(base_raw,base_files,data[2],data[3],historical['expected'])
    _esi_need(_esi_bare(base_raw)=={'bytes':16808,'sha256':
        '67dc40470b8ecb1e10cb57f8953a3d0b6db309b45079216eb24cd65f0760107c'}
        and _esi_bare(base_files['source/late_boundary.py'])=={'bytes':66996,'sha256':
        'c50a219efd992ce1353494ace2656af20c932cbc32530b0085e38a79975d8add'}
        and _esi_bare(data[2])=={'bytes':4702,'sha256':
        '54b1d9aef4c16ebc0989b3e13345238bfbd4e400e5bfc9a97e27648a2385057e'},
        'historical proof view must be exact67dc/c50a/54b1 bytes')
    return recipe,data,checked,(base_raw,base_value,base_files,data[2],data[3])


def verify_epoch_runtime_increment(runtime_raw,source_files,combination_raw,shared_files,*,recipe_raw):
    recipe,parent,stages,history=_esi_checked(runtime_raw,source_files,combination_raw,shared_files,recipe_raw=recipe_raw)
    changed=sorted(name for name in source_files if source_files[name]!=parent[1][name])
    changed_shared=sorted(name for name in shared_files if shared_files[name]!=parent[3][name])
    value={'schema':'hepta.native-guard.epoch-runtime-increment-verification.v2',
        'state':'EXACT_SOURCE_INCREMENT_VERIFIED_NO_CASE_OR_LIVE_ADMISSION',
        'runtime':_esi_bare(runtime_raw),'combination':_esi_bare(combination_raw),
        'shared_materials':{name:_esi_bare(raw) for name,raw in sorted(shared_files.items())},
        'source_recipe':_esi_recipe_descriptor(),
        'parent_runtime':_esi_bare(parent[0]),'parent_combination':_esi_bare(parent[2]),
        'historical_runtime':_esi_bare(history[0]),'historical_combination':_esi_bare(history[3]),
        'runtime_source_count':32,'shared_material_count':17,'production_source_count':15,
        'changed_runtime_members':changed,'unchanged_runtime_members':32-len(changed),
        'changed_shared_members':changed_shared,'inverse_stages':stages,
        'whole_manifest_and_source_inverses_verified':True,
        'whole_production_service_config_combination_inverses_verified':True,
        'source_execution_performed':False,'live_originals_read':False,
        'root02_prelaunch_admission_verified_here':False,'current_head_admission_verified_here':False,
        'epoch_resource_admission_verified_here':False,'phone_calls':0,'nonces_generated':0,
        'component_qualified':False,'business_qualified':False}
    _esi_exact(value,_ESI_PROOF_FIELDS,'source proof output fields differ')
    return value


def epoch_historical_runtime_view(runtime_raw,source_files,combination_raw,shared_files,*,recipe_raw):
    return _esi_checked(runtime_raw,source_files,combination_raw,shared_files,recipe_raw=recipe_raw)[3]


# Current-source and historical-proof domains remain separate throughout.
REVIEWED_CODEC_PARENT_HOST_ORIGINALS = {'boundary': {'bytes': 9686, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/epoch-legacy902-1ad3-boundary.original.json', 'sha256': '6e1d4a343fface7ebf36392e129a0f08ad91c8fc0d9216816502f90074b98831'}, 'closure': {'bytes': 55124, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/epoch-legacy902-1ad3-closure.original.json', 'sha256': 'ffe4cc50c4a89d20cc7ccc284fa781604a31be2a8107a5fabdc3c50f87305719'}, 'inventory': {'bytes': 923078, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/epoch-legacy902-1ad3-inventory.original.json', 'sha256': 'b9da7fdf1e8e110f9cb5cb253627c7a9bdad98a7660fddca16653bab1b93e94d'}}


REVIEWED_EPOCH_MODULE_INPUT_REPLACEMENT = {'path':str(B/'epoch-output600000-1ad3-MODULE-INPUT-REPLACEMENT.json'), 'bytes':16034, 'sha256':'15ad0a87035ba2a469440a4cecf82c003f0c648af4c092f34b6858c4a5f40384'}


def epoch_module_source_rows(read_original, combination_raw):
    """Verify the three actual host sources and their exact path/hash inverses."""
    need(callable(read_original) and type(combination_raw) is bytes,
         'complete current combination and fixed original reader required')
    row = REVIEWED_EPOCH_MODULE_INPUT_REPLACEMENT
    raw = read_original(row)
    need(type(raw) is bytes and len(raw) == row['bytes'] and sha(raw) == row['sha256'],
         'source-frozen epoch module increment original differs')
    value = strict(raw)
    need(value['schema'] == 'hepta.epoch.module-native-artifact-input-replacement.v1'
         and value['state'] == 'SOURCE_DERIVED_NOT_DEPLOYED'
         and value['r7_history_preserved'] == {
             'path':str(B/'module-sidecar-android-environment-r7-candidate01/MODULE-INPUT-REPLACEMENT.json'),
             'bytes':5897,'sha256':'223801205cfaba915c88b76fb291f888043c0f75fe0ae22be10ff13b19931374'}
         and value['old_artifact_path_preserved'] is True
         and value['production_still_checks_actual_proc_exe_path_and_hash'] is True
         and all(value[key] is False for key in ('actual_focus_or_native_execution_proved',
             'phone_deployment_performed','native_source_limit_runtime_proved','case_pass'))
         and type(value['phone_calls']) is int and value['phone_calls'] == 0,
         'module source history cannot supply phone or business qualification')
    old_path = '/data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-sidecar-r6'
    new_path = old_path+'-output600000-1ad3-01'
    old_sha = '8595f99cf8d0f39ec2a45f85f1250745c158ea504d2d0520cd83791f28bdb976'
    new_sha = '21b59e78c19f992d605ba9346febeeeb4161a8044580bf67441a04e785d9c2b2'
    need(value['old_sidecar'] == {'path':old_path,'bytes':965824,'sha256':old_sha}
         and value['new_sidecar'] == {'path':new_path,'bytes':965952,'sha256':new_sha},
         'fixed old and independently built new native artifacts differ')
    current_sidecar = strict(combination_raw)['artifacts']['sidecar']
    need(current_sidecar == dict(value['new_sidecar'],mode=493,uid=0,gid=0,
             selinux='u:object_r:trillionnium_owner_open_phone_executor_exec:s0'),
         'production startup and actual current combination must bind the same new sidecar')
    expected = {
        'launch-sidecar.sh':[(old_path,new_path)],
        'role-expectations.tsv':[(old_path,new_path),(old_sha,new_sha)],
        'role_identity_probe.sh':[(old_path,new_path)]}
    old_rows = value['parent_module_sources']; new_rows = value['candidate_module_sources']
    maps = []
    for rows in (old_rows,new_rows):
        need(type(rows) is list and len(rows) == 14,
             'exact original fourteen module members required')
        by_name = {}
        for member in rows:
            need(type(member) is dict and set(member) == {'name','path','bytes','sha256'}
                 and type(member['name']) is str and Path(member['name']).name == member['name']
                 and member['name'] not in by_name
                 and type(member['path']) is str and Path(member['path']).is_absolute()
                 and type(member['bytes']) is int and 0 <= member['bytes'] <= 131072
                 and type(member['sha256']) is str and re.fullmatch('[0-9a-f]{64}',member['sha256']),
                 'module source row is not a complete unique descriptor')
            by_name[member['name']] = member
        maps.append(by_name)
    parent,candidate = maps
    need(set(parent) == set(candidate) and set(expected) <= set(parent)
         and value['changed_names'] == sorted(expected)
         and value['unchanged_names'] == sorted(set(parent)-set(expected))
         and len(value['unchanged_names']) == 11,
         'epoch module increment must retain its exact original fourteen names')
    observed = value['observed_formal_parent']
    need(observed == {'path':str(B/'r10-boundary-consumers-final-r8-inventory-prefix-1ad3-01/inputs/FINAL-INTEGRATION-INPUTS.json'),
             'bytes':28304,'sha256':'3d9704eee561eebbd1b9bc6c6043d7e896e9010175617caf651c50a1fccca804'}
         and strict(read_original(observed))['module_sources'] == old_rows,
         'actual observed formal original does not contain the retained parent14')
    need(type(value['source_changes']) is list and len(value['source_changes']) == 3
         and {entry['name'] for entry in value['source_changes']} == set(expected),
         'three complete independently reviewable source increments required')
    for name in sorted(parent):
        if name not in expected:
            need(candidate[name] == parent[name], 'unchanged module member was replaced: '+name)
            continue
        oldrow,newrow = parent[name],candidate[name]
        need(newrow['path'] == str(B/('epoch-output600000-1ad3-'+name)),
             'new module source must use its independently published exact leaf')
        before = read_original({key:oldrow[key] for key in ('path','bytes','sha256')})
        after = read_original({key:newrow[key] for key in ('path','bytes','sha256')})
        need(type(before) is bytes and type(after) is bytes
             and len(before) == oldrow['bytes'] and sha(before) == oldrow['sha256']
             and len(after) == newrow['bytes'] and sha(after) == newrow['sha256'],
             'module source full bodies differ')
        step = next(entry for entry in value['source_changes'] if entry['name'] == name)
        need(step['parent'] == oldrow and step['candidate'] == newrow
             and step['whole_byte_inverse_verified'] is True
             and [(x['before_utf8'],x['after_utf8']) for x in step['replacements']] == expected[name],
             'module source increment changed beyond fixed native path and hash')
        actual = before
        for record,(one,two) in zip(step['replacements'],expected[name]):
            one=one.encode();two=two.encode()
            need(actual.count(one) == 1 and actual.index(one) == record['offset_in_step_input'],
                 'module source old span is not exact and unique')
            actual=actual.replace(one,two,1)
        need(actual == after, 'entire module source differs after the exact permitted replacements')
        restored=after
        for one,two in reversed(expected[name]):
            one=one.encode();two=two.encode()
            need(restored.count(two) == 1, 'module source new span is not unique')
            restored=restored.replace(two,one,1)
        need(restored == before, 'module source whole-byte inverse failed')
    proof = {'schema':'hepta.epoch.verified-module-source-input-increment.v1',
        'history':row,'new_sidecar':value['new_sidecar'],
        'changed_members':[candidate[name] for name in sorted(expected)],
        'unchanged_member_count':11,'whole_source_inverses_verified':True,
        'original_r7_history_retained':True,'host_source_originals_read':True,
        'phone_deployment_or_case_authority':False}
    return raw,value,proof


REVIEWED_EPOCH_MATERIAL_INPUT = {'path':str(B/'epoch-output600000-1ad3-MATERIAL-INTEGRATION-INPUTS-02.json'),
    'bytes':28292,'sha256':'83cdcc4738ce8a04219cc460554e3852dd67922f8e1a5f5d849b5d7cd47e3b6a'}
REVIEWED_EPOCH_MATERIAL_FORMAL_PARENT = {'path':str(B/'r10-boundary-consumers-final-r8-inventory-prefix-1ad3-01/inputs/FINAL-INTEGRATION-INPUTS.json'),
    'bytes':28304,'sha256':'3d9704eee561eebbd1b9bc6c6043d7e896e9010175617caf651c50a1fccca804'}
REVIEWED_EPOCH_GENERATED_SHARED = {'path':str(B/'r10-shared-materials-epoch-1ad3-01/SHARED-MATERIALS.json'),
    'bytes':3519,'sha256':'cbf97ec916db1b5594be40a261045be8feb4155a2153ecb8312b07432aa3d600'}


def epoch_production_source_rows(read_original, epoch_sources):
    """Bind the four actual new production rows to the already verified shared17."""
    need(callable(read_original), 'explicit original reader required for production input increment')
    def fixed(row):
        raw=read_original(row)
        need(type(raw) is bytes and len(raw)==row['bytes'] and sha(raw)==row['sha256'],
             'complete production input original differs')
        return raw
    raw=fixed(REVIEWED_EPOCH_MATERIAL_INPUT)
    parent_raw=fixed(REVIEWED_EPOCH_MATERIAL_FORMAL_PARENT)
    value,parent=strict(raw),strict(parent_raw)
    old_rows,new_rows=parent['production_sources'],value['production_sources']
    restored=dict(value);restored['production_sources']=old_rows
    need(restored==parent, 'material input changed beyond its exact production source rows')
    def index(rows):
        need(type(rows) is list and len(rows)==15, 'exact fifteen production rows required')
        out={}
        for row in rows:
            need(type(row) is dict and set(row)=={'name','path','bytes','sha256'}
                 and type(row['name']) is str and Path(row['name']).name==row['name']
                 and row['name'].endswith('.py') and row['name'] not in out
                 and Path(row['path']).name==row['name'] and type(row['bytes']) is int
                 and 0<row['bytes']<=131072 and type(row['sha256']) is str
                 and re.fullmatch('[0-9a-f]{64}',row['sha256']),
                 'closed production row identity or original basename differs')
            out[row['name']]=row
        return out
    old,new=index(old_rows),index(new_rows)
    need(set(old)==set(new), 'production member names changed')
    changed={'daily_phone_local.py','phone_observation_tools.py','phone_task_guards.py','retirement_recovery.py'}
    need({name for name in old if old[name]!=new[name]}==changed,
         'material input must change exactly the four reviewed production members')
    shared_raw=epoch_sources['shared_manifest_raw'];shared=epoch_sources['shared_files']
    need(type(shared_raw) is bytes and len(shared_raw)==REVIEWED_EPOCH_GENERATED_SHARED['bytes']
         and sha(shared_raw)==REVIEWED_EPOCH_GENERATED_SHARED['sha256']
         and strict(shared_raw)['source_input_sha256']==sha(raw),
         'actual generated shared17 does not bind this complete material input')
    for name in sorted(new):
        row=new[name];body=fixed({k:row[k] for k in ('path','bytes','sha256')})
        need(shared.get('provider/source/'+name)==body,
             'formal production input does not reproduce the admitted actual shared material')
        if name in changed:
            need(row['path']==str(B/'epoch-output600000-1ad3-production/source'/name),
                 'changed production member is not its exact independently staged original name')
            prior=old[name];fixed({k:prior[k] for k in ('path','bytes','sha256')})
    proof={'schema':'hepta.epoch.verified-production-source-input-increment.v1',
        'material_input':REVIEWED_EPOCH_MATERIAL_INPUT,'formal_parent':REVIEWED_EPOCH_MATERIAL_FORMAL_PARENT,
        'actual_shared_manifest':REVIEWED_EPOCH_GENERATED_SHARED,
        'changed_members':[new[name] for name in sorted(changed)],'unchanged_member_count':11,
        'all15_actual_source_bodies_equal_admitted_shared':True,
        'original_four_parent_source_bodies_retained_and_read':True,
        'material_input_restored_wholly_to_actual_formal_parent':True,
        'phone_deployment_or_case_authority':False}
    return raw,{'parent_production_sources':old_rows,'candidate_production_sources':new_rows},proof


def epoch_policy_history_source_input(frozen, runtime_raw, read_original):
    """Bind the small new input and preserve the opaque original adoption."""
    row=frozen['policy_history_input'];runtime=strict(runtime_raw)
    need(type(row) is dict and set(row)=={'path','bytes','sha256'}
         and type(row['path']) is str and Path(row['path']).is_absolute()
         and type(row['bytes']) is int and 0<row['bytes']<=65536
         and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256'])
         and encode(runtime.get('epoch_policy_history_input'))==encode(row),
         'runtime and source-frozen policy history input differ')
    raw=read_original(row);value=strict(raw)
    need(type(raw) is bytes and len(raw)==row['bytes'] and sha(raw)==row['sha256']
         and type(value) is dict and set(value)=={'schema','epoch_id','original_adoption',
             'actual_export','full_rule','root_scope_decision','reconciliation','authority','originals'}
         and value['schema']=='hepta.native-guard.epoch-policy-history-input.v1'
         and value['epoch_id']=='legacy902-active01', 'complete explicit policy history input required')
    adopted=value['original_adoption']
    need(type(adopted) is dict and set(adopted)=={'path','bytes','sha256'}
         and type(adopted['path']) is str and Path(adopted['path']).is_absolute()
         and type(adopted['bytes']) is int and adopted['bytes']==208226
         and adopted['sha256']=='527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a'
         and ('policy_adoption' not in frozen or encode(frozen['policy_adoption'])==encode(adopted)),
         'the original policy adoption is a separate unchanged descriptor')
    original=read_original(adopted)
    need(type(original) is bytes and len(original)==adopted['bytes'] and sha(original)==adopted['sha256'],
         'complete actual historical adoption bytes differ')
    old=strict(original)
    need(old['schema']=='hepta.runtime-properties-r10.policy-adoption.v1'
         and all(encode(value[name])==encode(old[name]) for name in
             ('actual_export','full_rule','root_scope_decision')),
         'current policy materials differ from the original adoption')
    return raw,value


def epoch_cascade_source_inputs(frozen, runtime_raw, runtime_files, read_original):
    """Read a fixed shared17, then verify all four pure inputs before runtime exec."""
    need(callable(read_original), 'fixed original byte reader required')
    recipe_raw=epoch_recipe_original(frozen,read_original)
    history_input_raw,history_input=epoch_policy_history_source_input(frozen,runtime_raw,read_original)
    shared_row = frozen['shared_material_manifest']
    need(shared_row==REVIEWED_EPOCH_GENERATED_SHARED,
         'final cascade must use the actual complete generated shared17 manifest')
    need(type(shared_row) is dict and set(shared_row) == {'path','bytes','sha256'}
         and type(shared_row['bytes']) is int and 0 < shared_row['bytes'] <= 65536,
         'fixed complete shared material manifest descriptor required')
    shared_raw = read_original(shared_row); shared_manifest = strict(shared_raw)
    reviewed = strict(runtime_files['reference/REVIEWED-PRODUCTION-PINS.json'])
    need(type(reviewed) is dict and len(reviewed) == 15
         and all(type(name) is str and Path(name).name == name and name.endswith('.py') for name in reviewed),
         'actual runtime must bind exactly fifteen production names')
    expected = {'provider/source/'+name for name in reviewed}
    expected.update({'local-config-r10-r1.json','PHONE-SERVICE-INPUTS-v150-r10-r1.json'})
    need(type(shared_manifest) is dict
         and shared_manifest.get('schema') == 'hepta.r10.shared-production-materials.v1'
         and type(shared_manifest.get('files')) is list and len(shared_manifest['files']) == 17,
         'actual closed shared17 manifest required')
    shared = {}; root = Path(shared_row['path']).parent
    for row in shared_manifest['files']:
        need(type(row) is dict and set(row) == {'path','bytes','sha256'}
             and type(row['path']) is str and row['path'] in expected and row['path'] not in shared
             and type(row['bytes']) is int and 0 < row['bytes'] <= 16*1024*1024
             and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
             'complete unique shared material row required')
        body = read_original(dict(path=str(root/row['path']), **{k:row[k] for k in ('bytes','sha256')}))
        need(type(body) is bytes and len(body) == row['bytes'] and sha(body) == row['sha256'],
             'actual shared material bytes differ')
        if row['path'].startswith('provider/source/'):
            need(reviewed[Path(row['path']).name] == row['sha256'], 'shared production differs from actual runtime pins')
        shared[row['path']] = body
    need(set(shared) == expected, 'actual shared17 omitted or added a member')
    combo_raw = read_original(frozen['component_combination'])
    gate = globals().get('verify_epoch_runtime_increment'); history_gate = globals().get('epoch_historical_runtime_view')
    need(callable(gate) and callable(history_gate), 'the reviewed pure four-input source gates are not installed')
    proof = gate(runtime_raw,runtime_files,combo_raw,shared,recipe_raw=recipe_raw)
    history = history_gate(runtime_raw,runtime_files,combo_raw,shared,recipe_raw=recipe_raw)
    fields = {'schema','state','runtime','combination','shared_materials','source_recipe','parent_runtime','parent_combination',
              'historical_runtime','historical_combination','runtime_source_count','shared_material_count',
              'production_source_count','changed_runtime_members','unchanged_runtime_members','changed_shared_members',
              'inverse_stages','whole_manifest_and_source_inverses_verified',
              'whole_production_service_config_combination_inverses_verified','source_execution_performed',
              'live_originals_read','root02_prelaunch_admission_verified_here','current_head_admission_verified_here',
              'epoch_resource_admission_verified_here','phone_calls','nonces_generated','component_qualified','business_qualified'}
    def bare(raw):return {'bytes':len(raw),'sha256':sha(raw)}
    need(type(proof) is dict and set(proof) == fields
         and proof['schema'] == 'hepta.native-guard.epoch-runtime-increment-verification.v2'
         and proof['state'] == 'EXACT_SOURCE_INCREMENT_VERIFIED_NO_CASE_OR_LIVE_ADMISSION'
         and proof['runtime'] == bare(runtime_raw) and proof['combination'] == bare(combo_raw)
         and proof['source_recipe'] == _esi_recipe_descriptor()
         and proof['shared_materials'] == {name:bare(body) for name,body in sorted(shared.items())}
         and proof['runtime_source_count'] == 32 and proof['shared_material_count'] == 17
         and proof['production_source_count'] == 15
         and proof['whole_manifest_and_source_inverses_verified'] is True
         and proof['whole_production_service_config_combination_inverses_verified'] is True,
         'complete pure source proof does not bind the actual four input domains')
    need(all(proof[key] is False for key in ('source_execution_performed','live_originals_read',
             'root02_prelaunch_admission_verified_here','current_head_admission_verified_here',
             'epoch_resource_admission_verified_here','component_qualified','business_qualified'))
         and type(proof['phone_calls']) is int and proof['phone_calls'] == 0
         and type(proof['nonces_generated']) is int and proof['nonces_generated'] == 0,
         'a pure byte inverse cannot grant live or case authority')
    need(type(history) is tuple and len(history) == 5, 'complete five-value historical proof view required')
    old_raw,old_value,old_files,old_combo,old_shared = history
    need(type(old_raw) is bytes and type(old_files) is dict and len(old_files) == 32
         and encode(strict(old_raw)) == old_raw and strict(old_raw) == old_value
         and bare(old_raw) == proof['historical_runtime'] == {'bytes':16808,
             'sha256':'67dc40470b8ecb1e10cb57f8953a3d0b6db309b45079216eb24cd65f0760107c'}
         and bare(old_combo) == proof['historical_combination'] == {'bytes':4702,
             'sha256':'54b1d9aef4c16ebc0989b3e13345238bfbd4e400e5bfc9a97e27648a2385057e'}
         and type(old_shared) is dict and set(old_shared) == expected,
         'historical proof view is not the exact verified67/54b1 source domain')
    return {'proof':proof,'combination_raw':combo_raw,'shared_manifest_raw':shared_raw,
            'source_recipe_raw':recipe_raw,
            'policy_history_input_raw':history_input_raw,'policy_history_input':history_input,
            'shared_manifest':shared_manifest,'shared_files':shared,'historical_runtime_raw':old_raw,
            'historical_runtime':old_value,'historical_files':old_files,
            'historical_combination_raw':old_combo,'historical_shared_files':old_shared}


def epoch_codec_parent_host_originals(late, read_original):
    """Use actual new Mac carriers without replacing the fixed phone identities."""
    hosts = REVIEWED_CODEC_PARENT_HOST_ORIGINALS
    need(type(hosts) is dict and set(hosts) == {'boundary','inventory','closure'},
         'actual verified Mac carriers for the fixed902 originals are not frozen')
    phones = late.reviewed_codec_parent_ancestor(); raw = {}
    for name in ('boundary','inventory','closure'):
        row = hosts[name]; phone = phones[name]
        need(type(row) is dict and set(row) == {'path','bytes','sha256'}
             and type(row['path']) is str and Path(row['path']).is_absolute()
             and {k:row[k] for k in ('bytes','sha256')} == {k:phone[k] for k in ('bytes','sha256')},
             'the new host carrier must retain exact902 bytes and a distinct host identity')
        raw[name] = read_original(row)
        need(type(raw[name]) is bytes and len(raw[name]) == row['bytes'] and sha(raw[name]) == row['sha256'],
             'the actual complete host carrier differs from its fixed phone original')
    reader = late.codec_parent_reader()
    head,inventory,closure = reader.closed_boundary_originals(raw['boundary'],raw['inventory'],raw['closure'],
        original_descriptor=phones['boundary'],combination_sha256=late.CODEC_PARENT_COMBINATION_SHA256,
        package_sha256=late.CODEC_PARENT_PACKAGE_SHA256)
    source_observation = reader.recheck_actual_sources()
    need(source_observation['context'] == 'mac'
         and source_observation['source_full9_is_actual_context_not_phone_substitution'] is True
         and source_observation['historical_main_called'] is False
         and head['nonce'] == '902e851c3ca1f90deab3d880ab993774'
         and head['native_status'] == 'provider_failed' and head['component_qualified'] is False
         and closure['component_qualified'] is False,
         'fixed902 must retain its actual source context and failed qualification')
    return head,inventory,closure,{'schema':'hepta.fixed902-host-carrier-and-semantic-proof.v1',
        'actual_context':'mac','host_originals':hosts,'phone_originals':phones,
        'source_observation':source_observation,'component_qualified':False,'business_qualified':False,
        'phone_metadata_used_as_host_metadata':False,'current_case_credit':False}


def epoch_historical_role_union(values, sidebranch, read_original):
    """Recheck historical retirement raw bodies; this is not a current census."""
    need(type(values) is list and len(values) == 6, 'exact six-member historical domain required')
    retirement = values[0]['retirement']; need(set(retirement) == {'proof','preflight','probe','bound_inputs','disabled_flag'},
                                             'all five historical retirement originals required')
    need(all(value['retirement'] == retirement for value in values), 'historical retirement identity changed')
    root = B/'module-r10-r1-retirement-reconciliation-01'
    declared = strict(read_original({'path':str(root/'ACTUAL-RETIREMENT-INPUTS.json'),'bytes':2220,
        'sha256':'e3c8411f3d85440018392597d4f9f8795cfd7a60c44fc1680068a60949d20999'}))['files']
    need(declared == retirement, 'actual retirement descriptor and six legacy boundaries differ')
    raws = {name:read_original({'path':str(root/'retirement-originals'/(name+'.original')),
                               **{k:row[k] for k in ('bytes','sha256')}}) for name,row in retirement.items()}
    proof = strict(raws['proof']); preflight = strict(raws['preflight']); bound = strict(raws['bound_inputs'])
    need(proof['schema'] == 'hepta.r9-r2-retirement-observation.v1'
         and proof['state'] == 'ORIGINAL_FOUR_GROUPS_ABSENT_STATE_PRESERVED'
         and proof['boot_id'] == values[0]['boot_id'] and proof['global_pending_clear'] is True
         and proof['server_lock_now_unheld'] is True and proof['old_claims_deleted'] is False
         and proof['old_task_terminal_rewritten'] is False and proof['automatic_replay'] is False,
         'complete historical retirement terminal differs')
    need(preflight['schema'] == 'hepta.r9-r2-retirement-preflight.v1'
         and preflight['state'] == 'READY_FOR_DISABLE_AND_ONE_SUPERVISOR_TERM'
         and preflight['groups'] == proof['original_role_identities']
         and preflight['preserved_state'] == proof['preserved_state']
         and bound['complete_current_accepted_case_union_verified'] is True and raws['disabled_flag'] == b'',
         'all historical retirement source originals and lineage are required')
    component = [tuple(role) for value in values for role in value['component_role_identities'].values()]
    component.extend(tuple(role) for role in sidebranch['component_role_identities'].values())
    retired = [tuple(role) for role in preflight['groups'].values()]; roles = retired + component
    need(len(component) == len(set(component)) == 21 and len(retired) == len(set(retired)) == 4
         and len(roles) == len(set(roles)) == 25 and len(roles) <= 64
         and all(len(role) == 4 and all(type(n) is int and n > 0 for n in role) for role in roles),
         'exact historical21 plus retired4 distinct complete role identities required')
    return {'schema':'hepta.fixed-six-legacy-and-retirement-role-union.v1','retirement':retirement,
            'component_roles':[list(role) for role in component],'retirement_roles':[list(role) for role in retired],
            'complete_role_union':[list(role) for role in roles],'distinct_role_count':25,
            'historical_observation_only':True,'current_process_absence_proved':False,
            'component_qualified':False,'business_qualified':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-host-interface-once',action='store_true')
    args=parser.parse_args()
    if not args.execute_host_interface_once:
        print(json.dumps({'state':'PROPERTY_POLICY_SEAL_INTERFACE_PREVIEW_NO_IO',
            'phone_calls':0,'host_reads':0,'host_writes':0,'qualification_granted':False},sort_keys=True))
        return 0
    need(isinstance(DELIVERY,dict) and set(DELIVERY)=={'path','bytes','sha256'},
         'actual reviewed final cascade delivery is not frozen')
    need(isinstance(OUT,Path) and OUT == B/'property-policy-final-seal-interface-r8-r1-inventory-prefix-1ad3-01',
         'the explicit create-only R8 host-interface output has not been frozen')
    os.umask(0o077)
    need(not OUT.exists() and not OUT.is_symlink() and OUT.parent.resolve(strict=True)==OUT.parent,
         'new interface output required')
    delivery,draw=original(DELIVERY);d=strict(draw)
    need(d['schema']=='hepta.property-policy.final-boundary-cascade-delivery.v1'
         and d['state']=='HOST_ONLY_PUBLISHED' and d['phone_calls']==0
         and d['nonce_generated'] is False and d['final_release_generated'] is False
         and d['new_component_qualification'] is False
         and d['pre_policy_ancestor_sha256']==PRE_POLICY_BOUNDARY_SHA
         and d['external_ancestor_sha256']==EXTERNAL_BOUNDARY_SHA
         and d['environment_parent_ancestor_sha256']==ENVIRONMENT_PARENT_BOUNDARY_SHA
         and d['property_parent_boundary_sha256']==PROPERTY_PARENT_BOUNDARY_SHAS[0]
         and d['property_parent_failed_ancestor_count']==2
         and d['historical_native_failed_case_count']==6
         and d['policy_parent_sha256']==POLICY_PARENT_SHA
         and d['parent_adoption_sha256']==PARENT_ADOPTION_SHA
         and d['module_replacement_reapplied'] is False,
         'actual source cascade delivery differs')
    frozen=d['reviewed_finalization']
    need(frozen['schema']=='hepta.property-policy.final-pin-freeze.v4'
         and set(frozen)=={'schema','runtime_manifest','component_combination',
                         'policy_adoption','policy_verifier','actual_policy','scope_decision','full_rule',
                         'shared_material_manifest','policy_history_input','source_recipe'},
         'reviewed future pin record differs')
    manifest,mraw=original(frozen['runtime_manifest']);runtime=strict(mraw)
    need(runtime['schema']=='hepta.native-guard.adapter-package.v1'
         and len(runtime['files'])==32 and len({r['path'] for r in runtime['files']})==32,
         'actual new runtime manifest differs')
    old_manifest,oldraw=read(OLD_RUNTIME/'MANIFEST.json',5284,
        '1cd57949621b36e46dc72d3df55e6ec3814fa76fb046c15ae71524463e3e8996')
    oldpaths={r['path'] for r in strict(oldraw)['files']}
    parent_manifest,parent_raw=read(RUNTIME_PARENT/'MANIFEST.json',13446,
        '683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c')
    parentpaths={r['path'] for r in strict(parent_raw)['files']}
    sidebranch_added={'reference/component_common_r5.py','reference/non_native_attempt05.py',
           'reference/attempt05-SIDE-PROOF.original.json',
           'reference/attempt05-CLOSURE.original.json',
           'reference/attempt05-AFTER-INVENTORY.original.json'}
    added={'reference/property_parent_late_boundary_r7.py'}
    need(len(oldpaths)==24 and len(parentpaths)==31
         and parentpaths==oldpaths|{'reference/policy_parent_late_boundary_r4.py',
                                  'reference/environment_parent_late_boundary_r6.py'}|sidebranch_added
         and not (parentpaths & added)
         and {r['path'] for r in runtime['files']}==parentpaths|added,
         'exact R8 path set or immutable historical24 versus parent31 distinction differs')
    runtime_files={}
    for row in runtime['files']:
        need(set(row)=={'path','bytes','sha256'} and row['path'] not in runtime_files,
             'runtime original source row differs')
        name=Path(row['path'])
        need(not name.is_absolute() and '..' not in name.parts and str(name)==row['path'],
             'runtime original source path differs')
        _,runtime_files[row['path']]=read(Path(manifest['path']).parent/name,row['bytes'],row['sha256'])
    epoch_sources=epoch_cascade_source_inputs(frozen,mraw,runtime_files,lambda row:original(row)[1])
    increment_proof=epoch_sources['proof']
    historical_rows={r['path']:r for r in epoch_sources['historical_runtime']['files']}
    parent_rows={r['path']:r for r in strict(parent_raw)['files']}
    need(all(historical_rows[name]==parent_rows[name] for name in parentpaths
             if name!='source/late_boundary.py')
         and {k:historical_rows['reference/property_parent_late_boundary_r7.py'][k] for k in ('bytes','sha256')}==
             {k:parent_rows['source/late_boundary.py'][k] for k in ('bytes','sha256')},
         'the verified historical view must retain all30 R7 bodies and the exact original reader reference')
    runtime_state={'actual_context':'mac','package_sources':runtime_files,'package_manifest_raw':mraw,
        'component_combination_raw':epoch_sources['combination_raw'],
        'shared_runtime_originals':epoch_sources['shared_files'],
        'epoch_source_recipe_raw':epoch_sources['source_recipe_raw']}
    need(encode(d.get('runtime_source_increment_proof'))==encode(increment_proof),
         'actual delivery did not retain the exact32 source increment proof')
    fc_manifest,fcraw=original(d['consumer']);fc=strict(fcraw)
    c_manifest,ccraw=original(d['constructor']);cc=strict(ccraw)
    need(d['consumer']['path']==str(FC/'MANIFEST.json')
         and d['constructor']['path']==str(C/'MANIFEST.json')
         and fc['schema']=='hepta.r10.final-boundary-consumers.v8'
         and cc['schema']=='hepta.r10.component-boundary-input-entry.v8'
         and fc['component_package_sha256']==cc['component_package_sha256']==manifest['sha256'],
         'actual FC8/C8 identity differs')
    def source(root,value,name):
        rows=[r for r in value['files'] if r['path']==name]
        need(len(rows)==1 and set(rows[0])=={'path','bytes','sha256'}, 'one exact source row required')
        row=rows[0]
        return read(root/name,row['bytes'],row['sha256'])
    constructor,craw=source(C,cc,'source/make_component_boundary_inputs.py')
    builder,braw=source(FC,fc,'source/build_release_r10.py')
    helper,hraw=source(FC,fc,'source/release_boundaries.py')
    need({k:constructor[k] for k in ('bytes','sha256')}==d['constructor_source']
         and {k:builder[k] for k in ('bytes','sha256')}==d['runtime_sources']['build_release_r10.py']
         and {k:helper[k] for k in ('bytes','sha256')}==d['runtime_sources']['release_boundaries.py'],
         'delivered source descriptors differ')
    need(flags(craw)=={'--plan','--plan-sha256','--out','--execute-host-inputs'},
         'constructor actual CLI differs')
    required={'--inputs','--inputs-sha256','--output','--retirement-inputs',
        '--retirement-inputs-sha256','--component-boundary-inputs','--component-boundary-inputs-sha256',
        '--policy-history-inputs','--policy-history-inputs-sha256','--shared-materials','--shared-materials-sha256'}
    need(required<=flags(braw) and '--out' not in flags(braw),'builder actual CLI differs')
    assignments={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(hraw).body
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)
        and n.targets[0].id in {'PACKAGE_SHA','PACKAGE_FILE_COUNT','CURRENT_COMBINATION_SHA','SHARED_MATERIALS_SHA',
                              'POLICY_VERIFIER_SHA','POLICY_VERIFIER_BYTES','CURRENT_POLICY_SHA',
                               'CURRENT_POLICY_ADOPTION_SHA','CURRENT_SCOPE_DECISION_SHA','EPOCH_SOURCE_RECIPE_DESCRIPTOR'}}
    bound_nodes=[n.value for n in ast.parse(hraw).body
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)
        and n.targets[0].id=='MAX_BUNDLE']
    need(len(bound_nodes)==1 and ast.dump(bound_nodes[0])==ast.dump(ast.parse('32 * 1024 * 1024',mode='eval').body),
         'exact aggregate boundary capacity expression changed')
    need(assignments=={'PACKAGE_SHA':manifest['sha256'],'PACKAGE_FILE_COUNT':32,
        'CURRENT_COMBINATION_SHA':frozen['component_combination']['sha256'],
        'SHARED_MATERIALS_SHA':frozen['shared_material_manifest']['sha256'],
        'POLICY_VERIFIER_SHA':frozen['policy_verifier']['sha256'],
        'POLICY_VERIFIER_BYTES':frozen['policy_verifier']['bytes'],
         'CURRENT_POLICY_SHA':frozen['actual_policy']['sha256'],
         'CURRENT_POLICY_ADOPTION_SHA':frozen['policy_adoption']['sha256'],
         'CURRENT_SCOPE_DECISION_SHA':frozen['scope_decision']['sha256'],
         'EPOCH_SOURCE_RECIPE_DESCRIPTOR':_esi_recipe_match(frozen['source_recipe'])},
        'final helper does not contain the independently reviewed new pins and unchanged capacity')
    need(b"SCHEMA = 'hepta.r10.component-boundary-construction-plan.v9'" in craw
         and b"schema='hepta.r10.component-boundary-inputs.v8'" in craw,
         'current component constructor must separate the old failed tail')
    need(b"component_package_sha256=state['component_input']['component_package_manifest']['sha256']" in braw,
         'builder activation must use the consumer-verified actual current package')
    module=types.ModuleType('reviewed_r8_interface_boundary_consumer')
    module.__file__=helper['path']
    exec(compile(hraw,module.__file__,'exec',optimize=0),module.__dict__)
    need(encode(module.verify_epoch_runtime_increment(mraw,runtime_files,
             epoch_sources['combination_raw'],epoch_sources['shared_files'],
             recipe_raw=epoch_sources['source_recipe_raw']))==encode(increment_proof),
         'delivered consumer pure four-input runtime increment gate differs')
    with module.component_modules(runtime_state, actual_context='mac') as modules:
        late=modules['late_boundary']
        proof=d['environment_parent_ancestor'];reviewed=late.reviewed_environment_parent_ancestor()
        need(proof['boundary']==reviewed['boundary']
             and proof['boundary']['sha256']==ENVIRONMENT_PARENT_BOUNDARY_SHA,
             'delivered exact environment-parent proof differs')
        pool={}
        def collect_environment(row):
            _descriptor,body=original(row)
            item={'bytes':len(body),'raw_b64':base64.b64encode(body).decode('ascii')}
            need(row['sha256'] not in pool or pool[row['sha256']]==item,'environment original collision')
            pool[row['sha256']]=item
            return body
        for key,row in proof.items():
            if key not in ('schema','boundary'):collect_environment(row)
        raw06={}
        for key,name in [('boundary','LATE-BOUNDARY.original.json'),
                         ('closure','CLOSURE.json'),('inventory','INVENTORY.json')]:
            row=reviewed[key]
            raw06[key]=collect_environment(dict(path=str(F06/name),
                **{k:row[k] for k in ('bytes','sha256')}))
        head06,inventory06,closure06=late.closed_boundary_originals(
            raw06['boundary'],raw06['inventory'],raw06['closure'],
            original_descriptor=reviewed['boundary'],
            combination_sha256=frozen['component_combination']['sha256'],
            package_sha256=manifest['sha256'])
        module.validate_environment_parent_ancestor({'originals':pool},proof,
            runtime_state,head06,late)
        environment_input={'root_result':proof['root_result'],'package_manifest':proof['package_manifest']}
        property_proofs=d['property_parent_ancestors']
        reviewed_properties=late.reviewed_property_parent_ancestors()
        need(isinstance(property_proofs,list) and len(property_proofs)==2
             and property_proofs==fc['property_parent_ancestors']
             and [r['boundary']['sha256'] for r in property_proofs]==PROPERTY_PARENT_BOUNDARY_SHAS,
             'delivered property ancestors must remain exact08 then07')
        property_values=[];property_inventories=[];property_inputs=[]
        for index,(home,attempt) in enumerate(((F08,'attempt08'),(F07,'attempt07'))):
            property_proof=property_proofs[index]
            need(property_proof['attempt']==attempt
                 and property_proof['boundary']==reviewed_properties[index]['boundary'],
                 'historical property ancestor identity or order differs')
            for key,row in property_proof.items():
                if key not in ('schema','attempt','boundary'):collect_environment(row)
            raw_property={}
            for key,name in [('boundary','LATE-BOUNDARY.original.json'),
                             ('closure','CLOSURE.json'),('inventory','INVENTORY.json')]:
                row=reviewed_properties[index][key]
                raw_property[key]=collect_environment(dict(path=str(home/name),
                    **{k:row[k] for k in ('bytes','sha256')}))
            old_value,old_inventory,_=late.closed_boundary_originals(
                raw_property['boundary'],raw_property['inventory'],raw_property['closure'],
                original_descriptor=reviewed_properties[index]['boundary'],
                combination_sha256=frozen['component_combination']['sha256'],
                package_sha256=manifest['sha256'])
            property_values.append(old_value);property_inventories.append(old_inventory)
            property_inputs.append({key:property_proof[key] for key in ('root_result','package_manifest')})
        module.validate_property_parent_ancestors({'originals':pool},property_proofs,
            runtime_state,property_values,late)
        older_values=[]
        all_records=late.property_parent_records()
        for index,(home,names) in enumerate(((F04,('LATE-BOUNDARY.original.json','INVENTORY.json','CLOSURE.json')),
                (E/'originals',('BOUNDARY.original.json','AFTER-INVENTORY.original.json','CLOSURE.original.json'))),start=3):
            record=all_records[index];raw_old={}
            for key,name in zip(('boundary','inventory','closure'),names):
                row=record[key]
                _,raw_old[key]=original(dict(path=str(home/name),
                    **{k:row[k] for k in ('bytes','sha256')}))
            old_value,_,_=late.closed_boundary_originals(raw_old['boundary'],raw_old['inventory'],
                raw_old['closure'],original_descriptor=record['boundary'],
                combination_sha256=frozen['component_combination']['sha256'],
                package_sha256=manifest['sha256'])
            older_values.append(old_value)
        codec_value,codec_inventory,codec_closure,codec_proof=epoch_codec_parent_host_originals(
            late,lambda row:original(row)[1])
        need(encode(codec_proof)==encode(d['codec_parent_ancestor'])
             and encode(codec_proof)==encode(fc['codec_parent_ancestor']),
             'source delivery and actual fixed902 host/source proof differ')
        all_values=[codec_value]+property_values+[head06]+older_values
        late.require_failed_ancestor_tail(all_values)
        sidebranch=late.non_native_sidebranch()
        late.preserve_non_native_private(sidebranch['inventory'],sidebranch)
        binding=sidebranch['binding']
        need(binding==d['non_native_sidebranch']==fc['non_native_sidebranch']
             and binding['native_case_count']==0 and binding['component_qualified'] is False
             and binding['native_predecessor']['sha256']==PRE_POLICY_BOUNDARY_SHA
             and d['non_native_attempt_count']==1 and d['non_native_case_count']==0,
             'actual R8 source delivery lost or reinterpreted the independent non-native sidebranch')
        late.preserve_non_native_private(property_inventories[0],sidebranch)
        need(late.effective_prior_inventory(property_values[0],property_inventories[0],sidebranch)
             is property_inventories[0], 'actual08 must retain its own cumulative inventory')
        roles=[tuple(row) for value in all_values for row in value['component_role_identities'].values()]
        roles.extend(tuple(row) for row in binding['component_role_identities'].values())
        need(len(roles)==len(set(roles))==21 and len(roles)<=24,
             'the actual six native failures and separate05 role set differs')
        historical_role_union=epoch_historical_role_union(all_values,binding,lambda row:original(row)[1])
        need(encode(historical_role_union)==encode(d['historical_role_union'])
             and encode(historical_role_union)==encode(fc['historical_role_union'])
             and historical_role_union['component_roles']==[list(row) for row in roles],
             'the exact historical21 and retired4 roles were not retained as one distinct union')
        sidebranch_sources={name:{'bytes':len(runtime_files[name]),'sha256':sha(runtime_files[name])}
            for name in ('reference/non_native_attempt05.py',
                         'reference/attempt05-SIDE-PROOF.original.json',
                         'reference/attempt05-CLOSURE.original.json',
                         'reference/attempt05-AFTER-INVENTORY.original.json')}
    formal,fraw=original(d['formal_input'])
    need(formal['path']==str(FC/'inputs/FINAL-INTEGRATION-INPUTS.json'), 'formal original path differs')
    module_replacement,module_raw=original(d['module_input_replacement']);replacement=strict(module_raw)
    epoch_module_raw,epoch_module_value,epoch_module_proof=epoch_module_source_rows(
        lambda row:original(row)[1],epoch_sources['combination_raw'])
    need(d['epoch_module_input_replacement']==REVIEWED_EPOCH_MODULE_INPUT_REPLACEMENT
         and encode(d['epoch_module_source_proof'])==encode(epoch_module_proof)
         and encode(fc['epoch_module_source_proof'])==encode(epoch_module_proof)
         and strict(fraw)['module_sources']==epoch_module_value['candidate_module_sources'],
         'final formal module14 does not bind the exact verified new native startup sources')
    epoch_production_raw,epoch_production_value,epoch_production_proof=epoch_production_source_rows(
        lambda row:original(row)[1],epoch_sources)
    need(encode(d['epoch_production_source_proof'])==encode(epoch_production_proof)
         and encode(fc['epoch_production_source_proof'])==encode(epoch_production_proof)
         and strict(fraw)['production_sources']==epoch_production_value['candidate_production_sources'],
         'final formal production15 does not reproduce the actual four-source input increment')
    module_rows=epoch_module_value['parent_module_sources']
    need(len(module_rows)==14 and len({r['name'] for r in module_rows})==14
         and [r for r in module_rows if r['name']=='launch-sidecar.sh']==[replacement['candidate_module_source']]
         and [r for r in module_rows if r['name']!='launch-sidecar.sh']==
             replacement['other_thirteen_module_source_rows_unchanged'],
         'historical module parent is not the already adopted original R7 sidecar increment')
    original({k:replacement['candidate_module_source'][k] for k in ('path','bytes','sha256')})
    shared,shared_raw=original(frozen['shared_material_manifest'])
    need(shared_raw==epoch_sources['shared_manifest_raw'],
         'actual final shared17 manifest changed after the pure source gate')
    adoption,araw=original(frozen['policy_adoption']);adopted=strict(araw)
    history_input,hiraw=original(frozen['policy_history_input'])
    need(hiraw==epoch_sources['policy_history_input_raw']
         and encode(epoch_sources['policy_history_input']['original_adoption'])==encode(adoption),
         'actual history input or its original adoption changed after the source gate')
    combo,coraw=original(frozen['component_combination']);combination=strict(coraw)
    verifier,vraw=original(frozen['policy_verifier'])
    scope,sraw=original(frozen['scope_decision']);full_rule,frraw=original(frozen['full_rule'])
    _,actual_raw=original(adopted['actual_export'])
    policy_verifier=types.ModuleType('reviewed_r8_interface_policy_verifier')
    policy_verifier.__file__=verifier['path'];policy_verifier.__reviewed_source_sha256__=sha(vraw)
    exec(compile(vraw,verifier['path'],'exec',optimize=0),policy_verifier.__dict__)
    policy_summary=policy_verifier.verify_adoption(araw,read_pinned=lambda row:original(row)[1])
    need(policy_summary['current_adoption_sha256']==adoption['sha256']
         and policy_summary['runtime_policy']==frozen['actual_policy']==
             {'bytes':len(actual_raw),'sha256':sha(actual_raw)}
         and policy_summary['parent_policy']=={'bytes':2667608,'sha256':POLICY_PARENT_SHA}
         and policy_summary['parent_adoption_sha256']==PARENT_ADOPTION_SHA
         and policy_summary['prior_boundary_sha256']==PROPERTY_PARENT_BOUNDARY_SHAS[0]
         and policy_summary['root_scope_decision_sha256']==scope['sha256']
         and policy_summary['full_rule']==adopted['full_rule']==full_rule
         and policy_summary['retirement_sha256']==property_values[0]['retirement']['proof']['sha256']
         and frozen['actual_policy']['sha256']!=POLICY_PARENT_SHA
         and adoption['sha256']!=PARENT_ADOPTION_SHA,
         'new policy evidence must retain exact50f/a5f/08 and the separately reviewed scope/full rule')
    verifier_rows=[row for row in adopted['verification_originals']
        if row.get('bytes')==len(vraw) and row.get('sha256')==sha(vraw)]
    need(len(verifier_rows)==1 and original(verifier_rows[0])[1]==vraw
         and original(adopted['full_rule'])[1]==frraw,
         'new adoption must retain the same exact reviewed verifier and complete rule')
    _,parent_combo_raw=read(RUNTIME_PARENT.parent/'COMBINATION.json',4702,POLICY_PARENT_COMBINATION_SHA)
    need(combination_encode(strict(parent_combo_raw))==parent_combo_raw and combination_encode(combination)==coraw
         and combination['live_policy_sha256']==frozen['actual_policy']['sha256'],
         'actual canonical property-policy combination differs')
    historical_combination=strict(epoch_sources['historical_combination_raw'])
    reversed_combo=dict(historical_combination);reversed_combo['live_policy_sha256']=POLICY_PARENT_SHA
    need(combination_encode(reversed_combo)==parent_combo_raw
         and coraw==epoch_sources['combination_raw'] and sha(coraw)!=POLICY_PARENT_COMBINATION_SHA
         and historical_combination['live_policy_sha256']==frozen['actual_policy']['sha256'],
         'current source changes require the exact four-input inverse and historical54b1 retains the original R7 policy transition')
    retirement,rraw=read(RET/'ACTUAL-RETIREMENT-INPUTS.json',2220,
        'e3c8411f3d85440018392597d4f9f8795cfd7a60c44fc1680068a60949d20999')
    retired=strict(rraw)['files'];retirement_originals={}
    for name,phone in retired.items():
        retirement_originals[name],_=read(RET/'retirement-originals'/(name+'.original'),phone['bytes'],phone['sha256'])
    builder_retirement,_=read(B/'r10-final-seal-preparation-r1/ACTUAL-BUILDER-RETIREMENT-INPUTS.json',2414,
        '1cd133d03c687d671aa87b3a813379020e0779941ebdd638de2b5b79652cdf4f')
    publication,praw=read(E/'PUBLICATION-RESULT.json',13450,
        '5799fac9fcc837c61e2990b56d0feab9140affd97b988f80419feeefeb7167ce')
    published=strict(praw)
    descriptor,raw=read(E/'BOUNDARY-DESCRIPTOR.json',302,
        '48be797e4413795ba332114124121d23c8fb1968462c93f432d29c7d0e4c89ae')
    need(strict(raw)==published['boundary'] and published['boundary']['sha256']==EXTERNAL_BOUNDARY_SHA,
         'actual published full9 external descriptor differs')
    legacy={'boundary_descriptor':descriptor}
    for name,key in [('boundary','boundary_original'),('closure','closure_original'),('inventory','inventory_original')]:
        legacy[key],_=original(published['originals'][name]['host'])
    _,hraw=original(published['publication_host_result']);host=strict(hraw)
    need(host['state']=='ORIGINAL_HOST_CHILD_JOINED' and host['phase']=='phone-external-publish'
         and type(host['returncode']) is int and host['returncode']==0,
         'actual external publication terminal differs')
    legacy['publication_operation'],operation=original(host['stdout'])
    need(Path(host['stdout']['path'])==E/'phone-external-publish/stdout.original',
         'actual original publication stdout path differs')
    alias,alias_raw=original(published['publication_operation'])
    need(operation==alias_raw and legacy['publication_operation']['path']!=alias['path'],
         'publication stdout and alias must have the same bytes and separate identity')
    transport=strict(operation)
    need(type(transport['actor_rc']) is int and transport['actor_rc']==0
         and type(transport['wrapper']['phone']['rc']) is int and transport['wrapper']['phone']['rc']==0,
         'original publication did not complete')
    pre_root,pre_raw=read(F04/'ROOT-RESULT.json',10980,
        'c92382e0841375fc0a1fb19ff0271381ac044f1dad01427342fca4e4f6e9c638')
    pre=strict(pre_raw)
    need(pre['late_boundary']['sha256']==PRE_POLICY_BOUNDARY_SHA
         and pre['component_qualified'] is False and pre['native_status']=='provider_failed',
         'fixed old04 Root result was changed or upgraded')
    pre_policy={'root_result':pre_root,'package_manifest':old_manifest}
    template=dict(schema='hepta.r10.component-boundary-construction-plan.v9',package_manifest=manifest,
        combination=combo,source_recipe=_esi_recipe_descriptor(),
        retirement_descriptor=retirement,retirement_originals=retirement_originals,
        shared_materials=shared,policy_adoption=adoption,policy_history_input=history_input,cases=[],
        epoch_publication_inputs=None,epoch_publication_originals=[],
        legacy_ancestor=legacy,pre_policy_ancestor=pre_policy,
        environment_parent_ancestor=environment_input,property_parent_ancestors=property_inputs)
    preview=['/usr/bin/python3','-I','-B',constructor['path'],'--plan','<ACTUAL_PLAN_PATH>',
        '--plan-sha256','<ACTUAL_PLAN_SHA256>','--out','<FRESH_COMPONENT_INPUT_OUTPUT>']
    build=['/usr/bin/python3','-I','-B',builder['path'],'--inputs',formal['path'],
        '--inputs-sha256',formal['sha256'],'--output','<FRESH_FINAL_SEALED_OUTPUT>',
        '--retirement-inputs',builder_retirement['path'],'--retirement-inputs-sha256',builder_retirement['sha256'],
        '--component-boundary-inputs','<ACTUAL_COMPONENT_BOUNDARY_INPUT_PATH>',
        '--component-boundary-inputs-sha256','<ACTUAL_COMPONENT_BOUNDARY_INPUT_SHA256>',
        '--policy-history-inputs',history_input['path'],'--policy-history-inputs-sha256',history_input['sha256'],
        '--shared-materials',shared['path'],'--shared-materials-sha256',shared['sha256']]
    interface=dict(schema='hepta.property-policy.final-seal-interface.v1',
        state='WAITING_FOR_ACTUAL_CURRENT_COMPONENT_CASE_ORIGINALS',actual_source_delivery=delivery,
        actual_runtime_manifest=manifest,actual_runtime_parent_manifest=parent_manifest,
        consumer_manifest=fc_manifest,constructor_manifest=c_manifest,
        property_parent_ancestors=property_proofs,property_parent_failed_ancestor_count=2,
        exact_retained_component_roles=[list(row) for row in roles],
        historical_native_failed_case_count=6,environment_parent_ancestor=proof,
        codec_parent_ancestor=codec_proof,historical_role_union=historical_role_union,
        runtime_source_increment_proof=increment_proof,
        module_input_replacement=module_replacement,
        epoch_module_input_replacement=REVIEWED_EPOCH_MODULE_INPUT_REPLACEMENT,
        epoch_module_source_proof=epoch_module_proof,
        epoch_production_source_proof=epoch_production_proof,
        non_native_sidebranch=binding,non_native_original_references=sidebranch_sources,
        non_native_attempt_count=1,non_native_case_count=0,
        non_native_role_identities_in_activation=True,
        constructor=constructor,builder=builder,formal_input=formal,builder_retirement_input=builder_retirement,
        policy_adoption=adoption,policy_history_input=history_input,component_combination=combo,policy_verifier=verifier,
        root_scope_decision=scope,full_rule=full_rule,
        policy_parent_sha256=POLICY_PARENT_SHA,parent_adoption_sha256=PARENT_ADOPTION_SHA,
        component_plan_template_filename='COMPONENT-PLAN.template.json',template_is_executable=False,
        missing_actual_inputs=['Latest-first actual ROOT-RESULT descriptors for the complete active epoch prefix',
            'Actual sealed global EPOCH-PUBLICATION-INPUTS packet and every charged source/action/carrier original',
            'Every current closed case must use the same actual new package and combination',
            'Fixed failed08 and07 retain their original R7 package, policy, recovery and publication proof outside cases',
             'Exact failed06 remains a separately verified original R6 ancestor before fixed04 and external03',
            'Every current boundary/closure retains the separately verified ended05 sidebranch and private roots',
            'True NEG-01 and NEG-02 qualification in their own original closed results',
            'Actual complete component/policy evidence-union byte count within the unchanged 32MiB bound',
            'Explicit fresh host output paths; no generated nonce or lease'],
        required_case_files=['ROOT-RESULT.json','EPOCH-PUBLICATION-INPUTS.json',
            'LATE-BOUNDARY.original.json','CLOSURE.json','INVENTORY.json',
            'material/tree/inputs/COMBINATION.json','phone-late-publish/stdout.original','phone-late-publish/stderr.original'],
        case_order='Latest-first active epoch records; separate fixed legacy902,08,07,06,04,external03 domain; ended05 remains non-native',
        old_tail_separate_from_current_cases=True,old_tail_qualification=False,
        constructor_preview_argv=preview,constructor_execute_argv=preview+['--execute-host-inputs'],
        constructor_outputs=['PUBLISH-RESULT.original.json','COMPONENT-BOUNDARY-INPUTS.json','PREPARATION-RESULT.json'],
        component_input_schema='hepta.r10.component-boundary-inputs.v8',
        pre_seal_checks=['Actual active qualified_component_cases must include NEG-01 and NEG-02',
            'Six fixed failed native ancestors and their21 roles plus retired4 preserve historical identity without current credit',
            'Actual release_bundle_preview bytes <= 33554432, only the exact aggregate evidence member',
            'Actual shared17 must remain the exact source/config/service materials used by current components',
            'Three ended05 role identities join the existing bounded activation absence set; 05 never supplies native-case credit',
            'Fixed06 is outside current cases and retains its original failure, recovery, package, scope and one tool call',
            'New policy must retain actual50f/a5f/08 and its separately reviewed scope/full rule; old296b/7899/04 are never current'],
        actual_complete_component_and_policy_union_bytes=None,exact_boundary_member_maximum_bytes=33554432,
        final_builder_argv=build,expected_builder_state='SEALED_ACTUAL_RETIREMENT_BOUND',
        final_expected_outputs=['BUILD-RESULT.json','release.json','module/SEALED','phone-release-v150-r10-r1.tar.gz'],
        downstream='Root alone reviews/stages/starts and obtains actual four-role readiness; only that release feeds host six/UI/fault.',
        automatic_execution=False,case_or_nonce_created=False,qualification_granted=False,release_created=False,
        phone_calls=0,policy_operations=0,production_signals=0,automatic_retry=False)
    for row,identity in tuple(SEEN.values()):
        read(row['path'],row['bytes'],row['sha256'])
        need(SEEN[row['path']][1]==identity,'input changed before interface publication')
    OUT.mkdir(mode=0o700);sync(OUT.parent)
    rows=[put(OUT/'COMPONENT-PLAN.template.json',encode(template)),put(OUT/'INTERFACE.json',encode(interface))]
    report=dict(schema='hepta.property-policy.final-seal-interface-preparation.v1',
        state='STATIC_ORIGINALS_AND_ACTUAL_CLI_VERIFIED_CURRENT_CASE_INPUTS_PENDING',
        files=rows,static_original_count=len(SEEN),originals=[row for row,_ in SEEN.values()],
        constructor_run=False,builder_run=False,phone_calls=0,nonce_created=False,qualification_granted=False)
    result=put(OUT/'RESULT.json',encode(report));print(json.dumps(result,sort_keys=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
