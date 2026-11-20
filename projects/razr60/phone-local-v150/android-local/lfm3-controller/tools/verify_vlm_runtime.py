"""Pin the separate current-frame VLM worker without replacing any existing runtime."""
import hashlib,json,re
from pathlib import Path
from verify_mobimind_runtime import _read_regular

def _sha(raw):return hashlib.sha256(raw).hexdigest()
def _need(value,message):
    if not value:raise RuntimeError(message)

def _same_json(actual,expected):
    if type(actual) is not type(expected):return False
    if isinstance(expected,dict):
        return actual.keys()==expected.keys() and all(_same_json(actual[k],v) for k,v in expected.items())
    if isinstance(expected,list):
        return len(actual)==len(expected) and all(_same_json(a,b) for a,b in zip(actual,expected))
    return actual==expected

def load_pins(root):
    root=Path(root)
    pins=json.loads(_read_regular(root/'native/local-vlm-runtime-pins.json',65536))
    _need(pins.get('schema')=='hepta.local-vlm.worker-packaging.v1' and pins.get('worker_build_qualified') is True,
          'VLM independent build pin missing')
    member=pins['worker']
    _need(member['apk_name']==member['source_name']=='libhepta_local_vlm_runner.so','VLM runner name differs')
    _need(type(member['bytes']) is int and member['bytes']>0 and re.fullmatch('[0-9a-f]{64}',member['sha256']),
          'VLM full artifact pin missing')
    _need(member.get('runpath')=='$ORIGIN','VLM runpath differs')
    java=_read_regular(root/'src/org/trillionnium/hepta/local/VlmPins.java',131072).decode('utf-8')
    _need(re.findall(r'\bWORKER\s*=\s*"([^"]+)"',java)==[member['apk_name']]
          and re.findall(r'\bWORKER_SHA\s*=\s*"([0-9a-f]{64})"',java)==[member['sha256']]
          and re.findall(r'\bWORKER_BYTES\s*=\s*(\d+)L',java)==[str(member['bytes'])],
          'VLM Java/native artifact pins differ')
    source=root/'native/vlm-worker'
    raw=_read_regular(source/'SOURCE.json',131072)
    _need(_sha(raw)==pins['source_manifest_sha256'],'VLM frozen source manifest differs')
    recipe=json.loads(raw)
    _need(recipe['schema']=='hepta.vlm.source.v1' and recipe['runtime']==pins['runtime']
          and recipe['llama_source_commit']==pins['llama_source_commit']
          and recipe['geniex_source_commit']==pins['geniex_source_commit'],'VLM source/runtime identity differs')
    names=set()
    for row in recipe['files']:
        rel=Path(row['path'])
        _need(not rel.is_absolute() and '..' not in rel.parts and str(rel) not in names,'VLM unsafe or duplicate source member')
        names.add(str(rel));path=source/rel
        _need(path.resolve(strict=True)==path,'VLM source alias rejected')
        data=_read_regular(path,max(1,row['bytes']))
        _need(len(data)==row['bytes'] and _sha(data)==row['sha256'],'VLM source differs: '+str(rel))
    _need(_read_regular(source/'native/owned-generation.inc',131072)==
          _read_regular(root/'native/owned-generation.inc',131072),'VLM must preserve the ordinary generation cleanup core')
    reference=_read_regular(source/'provenance/ANDROID-BUILD-R6.json',131072)
    _need(_sha(reference)==pins['reference_build_receipt_sha256'],'VLM reference build receipt differs')
    reference_data=json.loads(reference)
    host_raw=_read_regular(source/'provenance/LINKED-BACKENDS-HOST-R6.json',131072)
    _need(_sha(host_raw)==reference_data.get('linked_backend_host_receipt_sha256'),
          'VLM reference linked backend regression receipt differs')
    host=json.loads(host_raw)
    _need(host.get('schema')=='hepta.vlm.linked-backend-host-run.v1' and host.get('passed') is True
          and host.get('sources_unchanged') is True and host.get('phone_contacted') is False
          and host.get('model_inference_performed') is False
          and _same_json(host.get('result'),{'schema':'hepta.vlm.linked-backend-host.v1','checks':23,
              'rejection_cases':13,'passed':True,'plugin_init_absent':True,
              'phone_contacted':False,'model_inference_performed':False}),
          'VLM reference linked backend regression scope differs')
    host_sources={'native/linked-backends.h','native/vlm-worker.cpp','tests/linked-backends-fixture.cpp',
        'tests/linked-backends-test.cpp','vendor/llama/ggml-backend.h','tools/test_linked_backends.py'}
    _need(type(host.get('sources')) is dict and set(host['sources'])==host_sources,
          'VLM linked backend regression input membership differs')
    recipe_sources={row['path']:row for row in recipe['files']}
    _need(all(_same_json({k:host['sources'][name].get(k) for k in ('bytes','sha256')},
                        {k:recipe_sources[name][k] for k in ('bytes','sha256')}) for name in host_sources),
          'VLM linked backend regression source identity differs')
    order_raw=_read_regular(source/'provenance/VISION-INIT-ORDER-HOST-R6.json',131072)
    _need(_sha(order_raw)==reference_data.get('vision_init_order_host_receipt_sha256'),
          'VLM reference vision initialization regression receipt differs')
    order=json.loads(order_raw)
    _need(order.get('schema')=='hepta.vlm.vision-init-order-host-run.v1' and order.get('passed') is True
          and order.get('sources_unchanged') is True and order.get('phone_contacted') is False
          and order.get('model_inference_performed') is False and order.get('opencl_backend_executed') is False
          and _same_json(order.get('result'),{'schema':'hepta.vlm.vision-init-order-host.v1',
              'passed':True,'cases':5,'checks':23,'production_statements_executed':True,
              'early_metric_control_rejected':True,'phone_contacted':False,'model_inference_performed':False})
          and _same_json(order.get('extraction',{}).get('actual_source_order'),['init','guard','metric']),
          'VLM reference vision initialization regression scope differs')
    order_sources={'native/vlm-worker.cpp','tests/vision-init-order-fixture.cpp','tools/test_vision_init_order.py'}
    order_sources.update(name for name in recipe_sources if name.startswith('vendor/llama/')
                         and name.count('/')==2 and name.endswith('.h'))
    _need(type(order.get('sources')) is dict and set(order['sources'])==order_sources,
          'VLM vision initialization regression input membership differs')
    _need(all(type(order['sources'][name]) is dict and
              _same_json({k:order['sources'][name].get(k) for k in ('bytes','sha256')},
                         {k:recipe_sources[name][k] for k in ('bytes','sha256')}) for name in order_sources),
          'VLM vision initialization regression source identity differs')
    sdk=json.loads(_read_regular(root/'provenance/ui-venus-app-r1/sdk-runtime-pins.json',65536))
    expected={row['name']:row for row in sdk['files']}
    _need(all(expected.get(row['name'])==row for row in pins['runtime']),
          'VLM SDK pins differ from preserved GenieX closure')
    return pins

def verify_vlm_worker_dynamic(dynamic,member):
    tags=re.findall(r'\((RUNPATH|RPATH)\)',dynamic)
    paths=re.findall(r'\((RUNPATH|RPATH)\).*?\[([^]]*)\]',dynamic)
    needed=re.findall(r'\(NEEDED\).*?\[([^]]+)\]',dynamic)
    _need(tags==['RUNPATH'] and paths==[('RUNPATH','$ORIGIN')],
          'VLM runner requires only nontransitive ORIGIN RUNPATH')
    _need(needed==member['needed'] and 'libc++_shared.so' not in needed,'VLM actual ELF imports differ')
    return {'worker_runpath':'$ORIGIN','needed':needed,'extra_cpp_runtime_added':False,
            'runtime_maps_proven':False,'vendor_opencl_namespace_verified':False}

def verify_vlm_runtime(root,runtime_dir):
    root,runtime=Path(root),Path(runtime_dir)
    pins=load_pins(root);member=pins['worker']
    raw=_read_regular(runtime/'BUILD-RECEIPT.json',131072);receipt=json.loads(raw)
    expected={'schema':'hepta.vlm.android-build.v1','source_manifest_sha256':pins['source_manifest_sha256'],
        'dt_needed':member['needed'],'runpath':['$ORIGIN'],'sdk_cpp_undefined_closure_complete':True,
        'new_cpp_runtime_added':False,'vendor_needed':pins['vendor_needed'],
        'vendor_versioned_symbols':pins['vendor_versioned_symbols'],'vendor_opencl_verification_pending':True,
        'strong_undefined_closure_complete':False,'android_executed':False,'model_inference_performed':False,
        'ordinary_app_qualified':False,'dispatcher_connected':False,'phone_contacted':False,
        'linked_backend_abi':{'registration':'linked_GGML_BACKEND_DL_OFF',
            'libraries':{'libggml-cpu.so':'ggml_backend_cpu_reg',
                'libggml-hexagon.so':'ggml_backend_hexagon_reg','libggml-opencl.so':'ggml_backend_opencl_reg'},
            'generic_plugin_entry_absent':True,'phone_registration_executed':False},
        'linked_backend_host_checks':23,'vision_init_order_host_cases':5,'vision_init_order_host_checks':23}
    _need(all(_same_json(receipt.get(k),v) for k,v in expected.items()),
          'VLM build/source/ABI scope differs')
    host_proof=receipt.get('linked_backend_host_receipt_sha256')
    _need(type(host_proof) is str and re.fullmatch('[0-9a-f]{64}',host_proof),
          'VLM linked backend host regression receipt pin missing')
    order_proof=receipt.get('vision_init_order_host_receipt_sha256')
    _need(type(order_proof) is str and re.fullmatch('[0-9a-f]{64}',order_proof),
          'VLM vision initialization host regression receipt pin missing')
    actual=receipt['worker']
    _need(Path(actual['path']).name==member['source_name'] and actual['bytes']==member['bytes']
          and actual['sha256']==member['sha256'],'VLM built artifact identity differs')
    rows=[{k:row[k] for k in ('name','bytes','sha256')} for row in receipt['runtime']]
    _need(rows==pins['runtime'],'VLM build used different SDK bytes')
    owners=receipt.get('sha2_instruction_owners',{})
    _need(owners and sum(owners.values())>=4 and all(x.startswith('hepta_sha256_armv8_blocks') for x in owners),
          'VLM SHA2 instruction guard proof missing')
    path=runtime/member['source_name'];data=_read_regular(path,member['bytes'])
    _need(len(data)==member['bytes'] and _sha(data)==member['sha256'],'VLM worker bytes differ')
    return {member['apk_name']:{**member,'path':path,'provenance':'independent_current_frame_vlm_android_build',
            'build_receipt_sha256':_sha(raw),'source_manifest_sha256':pins['source_manifest_sha256']}}
