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

EPOCH_SOURCE_RECIPE = None
_ESI_HASH = _esi_re.compile(r'[0-9a-f]{64}')
_ESI_PROOF_FIELDS = ('schema','state','runtime','combination','shared_materials',
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


def _esi_data():
    packet=EPOCH_SOURCE_RECIPE
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


def _esi_dataset(runtime_raw,source_files,combination_raw,shared_files,expected):
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
    names=[];total=len(runtime_raw)+len(combination_raw)
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


def _esi_checked(runtime_raw,source_files,combination_raw,shared_files):
    recipe=_esi_data();_esi_dataset(runtime_raw,source_files,combination_raw,shared_files,recipe['current'])
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


def verify_epoch_runtime_increment(runtime_raw,source_files,combination_raw,shared_files):
    recipe,parent,stages,history=_esi_checked(runtime_raw,source_files,combination_raw,shared_files)
    changed=sorted(name for name in source_files if source_files[name]!=parent[1][name])
    changed_shared=sorted(name for name in shared_files if shared_files[name]!=parent[3][name])
    value={'schema':'hepta.native-guard.epoch-runtime-increment-verification.v1',
        'state':'EXACT_SOURCE_INCREMENT_VERIFIED_NO_CASE_OR_LIVE_ADMISSION',
        'runtime':_esi_bare(runtime_raw),'combination':_esi_bare(combination_raw),
        'shared_materials':{name:_esi_bare(raw) for name,raw in sorted(shared_files.items())},
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


def epoch_historical_runtime_view(runtime_raw,source_files,combination_raw,shared_files):
    return _esi_checked(runtime_raw,source_files,combination_raw,shared_files)[3]
