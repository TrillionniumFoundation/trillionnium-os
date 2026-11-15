"""Pin the separate current-frame VLM worker without replacing any existing runtime."""
import hashlib,json,re
from pathlib import Path
from verify_mobimind_runtime import _read_regular

def _sha(raw):return hashlib.sha256(raw).hexdigest()
def _need(value,message):
    if not value:raise RuntimeError(message)

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
    reference=_read_regular(source/'provenance/ANDROID-BUILD-R4.json',131072)
    _need(_sha(reference)==pins['reference_build_receipt_sha256'],'VLM reference build receipt differs')
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
        'ordinary_app_qualified':False,'dispatcher_connected':False,'phone_contacted':False}
    _need(all(type(receipt.get(k)) is type(v) and receipt[k]==v for k,v in expected.items()),
          'VLM build/source/ABI scope differs')
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
