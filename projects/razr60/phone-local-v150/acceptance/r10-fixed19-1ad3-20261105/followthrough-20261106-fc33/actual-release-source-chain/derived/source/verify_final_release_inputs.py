#!/usr/bin/env python3
"""Pure final release original reader; no phone, process, or filesystem actions.

The caller supplies a stable pinned-byte reader. Success requires an actual
original builder job and the original installer load_release projection, which
runs all complete boundary/adoption/archive checks. No source-only build or
boolean qualification assertion can enable this API.
"""
import ast,hashlib,io,json,re,tarfile,types
from pathlib import PurePosixPath
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
POLICY='69aa6433a11ac4cffb2f1d349cc9f36ec2349a601911c173ebe7d92fff9e0c5b'
PARENT_POLICY='f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'
RUNTIME = '990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a'
FIXED = {'ADOPTION': {'bytes': 32638, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/art-source-a1055-parent-getattr-resume01/actual_adoption_candidate03/actual01/POLICY-ADOPTION.json', 'sha256': '98b5db3d2c9680fff13e50bf64b18ddf9822689641427d204fded84f690d04c7'}, 'BUILDER': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-release-source-chain-r5-derived01/source/build_release_r10.py', 'bytes': 65767, 'sha256': 'd69cb02bead77625f5930922a99faf705a0d239849210f528a5b0a048b2238a1'}, 'COMBINATION': {'bytes': 4695, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-20261106-fc33-shared-material-v3-01/COMBINATION.json', 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'CONSUMER': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-release-source-chain-r5-derived01/source/release_boundaries.py', 'bytes': 249860, 'sha256': 'd65923a2323f4590d41291f3606e4b7bc550eaf800826f819c8f4bb1a102f479'}, 'FORMAL': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-release-source-chain-r5-derived01/contracts/FINAL-INTEGRATION-INPUTS.json', 'bytes': 28952, 'sha256': '7dd91169507d30d803357a8b4ac3688a206a4bcdeed2dd63973a023f312ce9e8'}, 'INSTALLER': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-release-source-chain-r5-derived01/source/install_phone_release_r10.py', 'bytes': 34100, 'sha256': '22a04f452d86a1d02e66b227acfc12e3e119fe4fdc9b0d39b5656a415bc9d40b'}, 'READINESS': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-release-source-chain-r5-derived01/source/collect_r10_readiness.py', 'bytes': 16407, 'sha256': '8fcf151ebeeeeaa38f0d8e057b4340f7c681f402d6a5a9670ca95f79737935e5'}, 'SHARED': {'bytes': 3519, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-20261106-fc33-shared-material-v3-01/shared/SHARED-MATERIALS.json', 'sha256': 'cc7eb624333216e510b540c3af8277e948aa689a108950fa78e8d01c2177e5b1'}}
CURRENT_COMPONENT_CHAIN_LENGTH = 12
SCHEMA='hepta.r10.actual-final-release-original-inputs.v1'
A='/data/trillionnium/owner-open/state/phone-local-v150'
MODULE='/data/adb/modules/trillionnium_hepta_phone_local_v150_r10_r1'
FIELDS={'schema','boot_id','release_id','builder_source','installer_source','formal_inputs',
 'combination','shared_materials','shared_originals','component_boundary_inputs','policy_adoption',
 'retirement_inputs','build_result','release_archive','release_manifest','production_source_seal',
 'module_manifest','module_binding','build_process'}
HASH=re.compile('[0-9a-f]{64}')
MAX_ARCHIVE=64*1024*1024
MAX_OTHER=16*1024*1024
MAX_INPUT_POOL=80*1024*1024
PROJECT_FUNCTIONS=('need','digest','strict','android','beneath','directory_profile','load_release')
PROJECT_CONSTANTS=('ANDROID','ANDROID_BASE','BOOT','PARENT_POLICY','BOUNDARY_CONSUMER_SHA256',
 'MODULE','HELPER','MODEL_RUNTIME','HISTORY','EXECUTOR_HISTORY','ROOTS','HELPER_LABEL','EXECUTOR_LABEL','LABELS')

def need(ok,why):
    if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def encoded(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,allow_nan=False,separators=(',',':'))+'\n').encode()
def strict(raw):
    def pairs(items):
        out={}
        for k,v in items:
            need(k not in out,'duplicate JSON key');out[k]=v
        return out
    need(type(raw) is bytes,'raw original bytes required')
    return json.loads(raw.decode('utf-8','strict'),object_pairs_hook=pairs,
        parse_constant=lambda _:need(False,'nonfinite JSON'))
def descriptor(row,maximum=MAX_OTHER):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact retained descriptor required')
    p=PurePosixPath(row['path'])
    need(type(row['path']) is str and p.is_absolute() and str(p)==row['path']
         and '..' not in p.parts and '\0' not in row['path']
         and type(row['bytes']) is int and 0<=row['bytes']<=maximum
         and type(row['sha256']) is str and HASH.fullmatch(row['sha256']),
         'canonical finite retained descriptor required')
    return p

class Originals:
    def __init__(self,callback):
        need(callable(callback),'pinned original reader required')
        self.callback=callback;self.rows={};self.total=0
    def read(self,row,maximum=MAX_OTHER):
        descriptor(row,maximum)
        b=self.callback(row)
        need(type(b) is bytes and len(b)==row['bytes'] and sha(b)==row['sha256'],
             'retained original byte identity differs')
        prior=self.rows.get(row['path'])
        if prior is None:
            need(len(self.rows)<256 and self.total+len(b)<=MAX_INPUT_POOL,'finite final-release original pool exceeded')
            self.rows[row['path']]=(dict(row),b);self.total+=len(b)
        else:need(prior==(row,b),'retained original changed between reads')
        return b
    def json(self,row,maximum=MAX_OTHER):return strict(self.read(row,maximum))
    def recheck(self):
        for row,b in self.rows.values():need(self.callback(row)==b,'original changed during final-release verification')

def _tool(raw):
    value=strict(raw)
    need(type(value) is dict and value.get('isError') is False,'original tool result failed or lacks its envelope')
    texts=[x['text'] for x in value.get('content',[]) if type(x) is dict and x.get('type')=='text']
    need(len(texts)==1,'one original controller tool payload required')
    return strict(texts[0].encode())

def expected_build_command(value):
    """Finite future builder recipe, not an execution or qualification action."""
    need(type(value) is dict and set(value)==FIELDS and value['schema']==SCHEMA,'final original input schema differs')
    output=str(descriptor(value['build_result']).parent)
    args=['-I',FIXED['BUILDER']['path'],'--inputs',FIXED['FORMAL']['path'],
      '--inputs-sha256',FIXED['FORMAL']['sha256'],'--output',output,
      '--retirement-inputs',value['retirement_inputs']['path'],
      '--retirement-inputs-sha256',value['retirement_inputs']['sha256'],
      '--component-boundary-inputs',value['component_boundary_inputs']['path'],
      '--component-boundary-inputs-sha256',value['component_boundary_inputs']['sha256'],
      '--policy-adoption-inputs',FIXED['ADOPTION']['path'],
      '--policy-adoption-inputs-sha256',FIXED['ADOPTION']['sha256'],
      '--shared-materials',FIXED['SHARED']['path'],'--shared-materials-sha256',FIXED['SHARED']['sha256']]
    return {'executable':'/opt/homebrew/bin/python3','args':args,'phone_calls':0}

def verify_build_process(value,build,pool):
    records=value['build_process']
    need(type(records) is dict and set(records)=={'start','status','read'},'three original builder process tool receipts required')
    started=_tool(pool.read(records['start'],1024*1024))
    status=_tool(pool.read(records['status'],1024*1024))
    streams=_tool(pool.read(records['read'],1024*1024))
    job=started['job'];expected=expected_build_command(value)
    args=list(job['args'])
    if args[:2]==['-I','-B']:args.pop(1)
    need(job['host']=='mac' and job['executable'] in ('/opt/homebrew/bin/python3','/usr/bin/python3')
         and args==expected['args'] and job['launch_state']=='launched'
         and job['launch_error'] is None and started['reused'] is False,
         'actual original builder invocation differs or was replayed')
    need(status['job_id']==job['id']==streams['job_id'] and status['state']=='succeeded'
         and type(status['exit_code']) is int and status['exit_code']==0
         and status['output_complete'] is True and status['output_durable'] is True
         and status['terminal_publication_confirmed'] is True and status['timed_out'] is False
         and status['cancelled'] is False and status['log_errors']=={'stderr':None,'stdout':None}
         and type(status['log_truncated'])is dict and set(status['log_truncated'])=={'stderr','stdout'}
          and all(status['log_truncated'][n]is False for n in ('stderr','stdout')),
         'original builder terminal, output or publication is unknown')
    outputs={}
    for name in ('stdout','stderr'):
        row=streams[name]
        b=bytes.fromhex(row['bytes_hex'])
        need(type(row['offset'])is int and row['offset']==0 and row['eof'] is True
              and type(row['next_offset'])is int and type(row['size'])is int and row['next_offset']==row['size']==len(b)
              and row['text'].encode()==b and type(status['log_bytes'][name])is dict
              and set(status['log_bytes'][name])=={'seen','stored'}
              and all(type(status['log_bytes'][name][k])is int and status['log_bytes'][name][k]==len(b)for k in ('seen','stored'))
             and status['log_synced'][name] is True,'complete original builder output bytes required')
        outputs[name]=b
    need(outputs['stderr']==b'' and canonical(strict(outputs['stdout']))==canonical(build),
         'actual builder stdout does not equal its retained BUILD-RESULT')
    return {'job_id':job['id'],'exit_code':0,'stdout_sha256':sha(outputs['stdout']),
            'stderr_sha256':sha(outputs['stderr']),'original_terminal_and_complete_outputs_verified':True}

def project_installer(raw,archive_row,archive_raw):
    """Exact original function ASTs, with only the pinned archive byte source supplied."""
    need(len(raw)==FIXED['INSTALLER']['bytes'] and sha(raw)==FIXED['INSTALLER']['sha256'],
         'reviewed actual installer source differs')
    tree=ast.parse(raw);chosen=[];fnames=set();constants=set()
    for node in tree.body:
        if isinstance(node,ast.FunctionDef) and node.name in PROJECT_FUNCTIONS:
            need(node.name not in fnames,'duplicate projected function');fnames.add(node.name);chosen.append(node)
        elif isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in PROJECT_CONSTANTS:
            name=node.targets[0].id;need(name not in constants,'duplicate projected constant');constants.add(name);chosen.append(node)
    need(fnames==set(PROJECT_FUNCTIONS) and constants==set(PROJECT_CONSTANTS),'complete original archive-validator projection required')
    namespace={'__name__':'exact_readonly_installer_projection','Path':PurePosixPath,
        'PurePosixPath':PurePosixPath,'hashlib':hashlib,'io':io,'json':json,'re':re,'tarfile':tarfile}
    def stable(path,maximum):
        need(str(path)==archive_row['path'] and maximum==MAX_ARCHIVE and len(archive_raw)<=maximum,
             'projected reader attempted an undeclared original')
        return archive_raw
    namespace['stable']=stable
    projected=ast.Module(body=chosen,type_ignores=[])
    exec(compile(projected,'<exact-original-installer-readonly-projection>','exec'),namespace)
    need(namespace['PARENT_POLICY']==PARENT_POLICY and namespace['BOUNDARY_CONSUMER_SHA256']==FIXED['CONSUMER']['sha256'],
         'projected actual direct parent or consumer pin differs')
    return namespace

OWNER_MODULE_FILES = {'RESIDENT-OWNER-FINALIZER.json': {'bytes': 3354, 'sha256': '199a83e1b8e4ab7b1cf92050a450e04cf5f4eda133a97730a3ba4f46319a50ac'}, 'resident_owner_terminal.py': {'bytes': 32701, 'sha256': '958d796590cbd4f1d8440f76fdd95a1b273237c3c78aa1db8696728a697ad55a'}, 'service.sh': {'bytes': 21310, 'sha256': '72bc91083db2827fafa8aef11ed1e09c764f87b02ef8623a8106c7399bd49620'}}
OWNER_MODULE_PROVENANCE = {'additional_resident_roles': 0, 'child_wait_owner': 'ORIGINAL_SERVICE_SHELL_MEMORY', 'cleanup_audit2_outside_component_inventory_required': True, 'exact_eight_stream_caller_required': True, 'fixed19_credit': 0, 'formal_build_qualification_from_this_record': False, 'helper_phase_total_seconds': 2, 'helper_source': {'bytes': 32701, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/fivefault-source-reconstruction-a1055-r2/source/resident_owner_terminal_candidate05.py', 'sha256': '958d796590cbd4f1d8440f76fdd95a1b273237c3c78aa1db8696728a697ad55a'}, 'installer_initial_stream_identity_proven': False, 'new_stop_observation_window_seconds': 36, 'new_window_limits_only_observation_and_wait_qualification': True, 'observer_deployed_as_module_member': False, 'original_terminate_role_bytes_preserved': True, 'original_three_role_stop_calls_always_attempted': True, 'parent_builder': {'bytes': 45121, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-release-reader-reconstruction-a1055-r4/source/build_release_r10.py', 'sha256': '26bbd6dafa353badc6ef6be5e4e43a25ae1fecc48def321e883caafe7b48ddb0'}, 'parent_formal_inputs_sha256': '8443393552d1b322b0bf3f86d9e91474ece860e1efd708c80ad15ba8c539df9f', 'parent_module_service': {'bytes': 11975, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-r10-preparation-01/module-base-02/module-root/service.sh', 'sha256': '2dde5460ad8ea2e33075634f62ff67c7cae34e39d5e07a2329c20365803c7114'}, 'parent_stream_origin': 'ACTUAL_OPEN_PARENT_FD_AT_CHILD_BIND_ONLY', 'phone_execution': False, 'prewire_service': {'bytes': 17999, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/fivefault-source-reconstruction-a1055-r2/source/service_owner_finalizer_candidate04.sh', 'sha256': 'f7104166cf935940832cca67e98c218a4cee2cece4a35148b3a6a8aaa07b0a24'}, 'regular_file_pipe_eof_claimed': False, 'regular_output_observer_candidate': {'bytes': 28570, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/fivefault-source-reconstruction-a1055-r2/source/observe_resident_regular_outputs_UNBOUND08.py', 'sha256': 'e48a4e1cd905643a7de060b49536d508aa31ba4535ea0a71708e6ccb71abd9bf'}, 'resident_roles': ['supervisor', 'model', 'sidecar', 'provider'], 'schema': 'hepta.module-r10-r1.resident-owner-finalizer.v1', 'service_lifetime_foreground_helper_invocations_maximum': 10, 'service_transform_count': 19, 'service_transforms_sha256': 'e41a1392d2003c0c8e8879dcd4a6393adade6c5bdcdada0b57be0d9a0754fa47', 'status_127': 'AMBIGUOUS_UNQUALIFIED', 'supervisor_original_parent_wait': 'NOT_RETAINED', 'supervisor_terminal_type': 'SELF_TERMINAL_PLUS_REQUIRED_INDEPENDENT_ABSENCE', 'task_endpoint_lock_latest_family_closure_separate': True, 'wired_configuration_sha256': '5ff00467e8432d7119ba72a700ce07cb20f16555d3dc0c90de7cbfc388103f48', 'wired_service': {'bytes': 21310, 'sha256': '72bc91083db2827fafa8aef11ed1e09c764f87b02ef8623a8106c7399bd49620'}}

def verify_owner_finalizer_module(module_files):
    need(type(module_files) is dict, 'complete actual module files required')
    for name,pin in OWNER_MODULE_FILES.items():
        need(name in module_files and type(module_files[name]) is bytes
             and len(module_files[name])==pin['bytes'] and sha(module_files[name])==pin['sha256'],
             'actual owner-finalizer module member differs: '+name)
    value=strict(module_files['RESIDENT-OWNER-FINALIZER.json'])
    need(value==OWNER_MODULE_PROVENANCE,'actual typed owner-finalizer provenance differs')
    return {'schema':'hepta.module-r10-r1.resident-owner-source-verdict.v1',
            'module_files':OWNER_MODULE_FILES,'source_provenance_sha256':sha(module_files['RESIDENT-OWNER-FINALIZER.json']),
            'additional_resident_roles':0,'supervisor_original_parent_wait':'NOT_RETAINED',
            'exact_eight_stream_caller_required':True,'resident_terminal_qualified':False,
            'phone_execution_proven_by_this_source_gate':False}


def verify_final_release_inputs(inputs_raw, *, read_pinned):
    need(type(inputs_raw) is bytes and 0<len(inputs_raw)<=1024*1024,'bounded final input bytes required')
    value=strict(inputs_raw)
    need(type(value) is dict and set(value)==FIELDS and value['schema']==SCHEMA
         and value['boot_id']==BOOT and value['release_id']=='v150-r10-r1','exact selected final release inputs required')
    for key,fixed in [('builder_source','BUILDER'),('installer_source','INSTALLER'),('formal_inputs','FORMAL'),
                      ('combination','COMBINATION'),('shared_materials','SHARED'),('policy_adoption','ADOPTION')]:
        need(value[key]==FIXED[fixed],'source selected final release binding differs: '+key)
    pool=Originals(read_pinned)
    builder_raw=pool.read(value['builder_source'],262144)
    installer_raw=pool.read(value['installer_source'],262144)
    formal_raw=pool.read(value['formal_inputs'],262144);formal=strict(formal_raw)
    combination_raw=pool.read(value['combination'],65536);combination=strict(combination_raw)
    shared_raw=pool.read(value['shared_materials'],65536);shared=strict(shared_raw)
    policy_raw=pool.read(value['policy_adoption'],1024*1024)
    component_raw=pool.read(value['component_boundary_inputs'],4*1024*1024)
    pool.read(value['retirement_inputs'],4*1024*1024)
    build_raw=pool.read(value['build_result'],1024*1024);build=strict(build_raw)
    need(build.get('schema')=='hepta.r10.integration-build.v1'
         and build.get('state')=='SEALED_ACTUAL_RETIREMENT_BOUND'
         and build.get('input_sha256')==sha(formal_raw) and build.get('policy_sha256')==POLICY
         and build.get('parent_policy_sha256')==PARENT_POLICY and build.get('production_source_count')==15
         and build.get('phone_calls')==build.get('model_requests')==0,
         'source-only, unrelated or unsealed build cannot qualify')
    root=descriptor(value['build_result']).parent
    need(descriptor(value['build_result']).name=='BUILD-RESULT.json'
         and value['release_archive']==build['archive']
         and descriptor(value['release_archive'],MAX_ARCHIVE)==root/'phone-release-v150-r10-r1.tar.gz'
         and descriptor(value['release_manifest'])==root/'release.json'
         and descriptor(value['production_source_seal'])==root/'provider/SOURCE-SEAL-v150-r10.json'
         and descriptor(value['module_manifest'])==root/'module/MODULE-MANIFEST-v150-r10-r1.json'
         and descriptor(value['module_binding'])==root/'module/seal-binding.json',
         'actual output namespace or artifact identity differs')
    process=verify_build_process(value,build,pool)
    archive_raw=pool.read(value['release_archive'],MAX_ARCHIVE)
    namespace=project_installer(installer_raw,value['release_archive'],archive_raw)
    release,blobs=namespace['load_release'](PurePosixPath(value['release_archive']['path']),
        value['release_archive']['sha256'],sha(component_raw),sha(policy_raw))
    release_raw=pool.read(value['release_manifest'],1024*1024)
    need(release_raw==blobs['release.json'],'separate actual release manifest differs from archive')
    boundary=release['_boundary']
    need(boundary['component_input']['component_package_manifest']['sha256']==RUNTIME
         and boundary['component_combination']==combination
         and sha(encoded(combination))==FIXED['COMBINATION']['sha256']
         and boundary['runtime_policy']=={'bytes':2667752,'sha256':POLICY}
         and boundary['policy_adoption_sha256']==FIXED['ADOPTION']['sha256']
         and boundary['component_input_sha256']==sha(component_raw)
         and len(boundary['chain'])==CURRENT_COMPONENT_CHAIN_LENGTH
         and [row[0]['case_id'] for row in boundary['chain'][:2]]==['NEG-02','NEG-01'],
         'archive is not the exact final closed tuple and successful two-case prefix')
    writes={row['target']:row for row in release['writes']}
    def payload(target):
        need(target in writes,'complete final target omitted: '+target)
        return blobs[writes[target]['member']]
    shared_rows=value['shared_originals']
    need(type(shared_rows) is list and len(shared_rows)==17,'complete17 shared originals required')
    expected={row['path']:row for row in shared['files']}
    need(len(expected)==17,'original shared manifest member set differs')
    actual={};shared_root=PurePosixPath(FIXED['SHARED']['path']).parent
    for item in shared_rows:
        need(type(item) is dict and set(item)=={'name','copy'} and item['name'] in expected
             and item['name'] not in actual,'shared original omitted or repeated')
        row=expected[item['name']]
        need(item['copy']==dict(path=str(shared_root/item['name']),bytes=row['bytes'],sha256=row['sha256']),
             'shared original path or pin differs')
        body=pool.read(item['copy'],262144)
        target=A+'/provider-r10-r1/source/'+PurePosixPath(item['name']).name if item['name'].startswith('provider/source/') else A+'/'+item['name']
        need(payload(target)==body,'final archive changed a selected shared byte')
        actual[item['name']]=body
    need(set(actual)==set(expected),'complete shared17 comparison required')
    seal_raw=pool.read(value['production_source_seal'],1024*1024)
    module_raw=pool.read(value['module_manifest'],1024*1024)
    binding_raw=pool.read(value['module_binding'],1024*1024)
    need(payload(A+'/provider-r10-r1/SOURCE-SEAL-v150-r10.json')==seal_raw
         and payload(MODULE+'/MODULE-MANIFEST-v150-r10-r1.json')==module_raw
         and payload(MODULE+'/seal-binding.json')==binding_raw,
         'actual separate seals/manifests differ from archive')
    seal=strict(seal_raw);module=strict(module_raw);binding=strict(binding_raw)
    production={PurePosixPath(n).name:b for n,b in actual.items() if n.startswith('provider/source/')}
    config=actual['local-config-r10-r1.json'];service=actual['PHONE-SERVICE-INPUTS-v150-r10-r1.json']
    need(seal['schema']=='hepta.provider-r10.actual-integration-seal.v1'
         and seal['state']=='HOST_FROZEN_PHONE_NOT_STARTED' and seal['module_release']=='v150-r10-r1'
         and seal['production_files']==[dict(path='source/'+n,bytes=len(b),sha256=sha(b)) for n,b in sorted(production.items())]
         and seal['configuration']=={'bytes':len(config),'sha256':sha(config)}
         and seal['phone_service_inputs_sha256']==sha(service) and seal['source_inputs_sha256']==sha(formal_raw)
         and seal['model']==strict(config)['model'] and seal['parent_sources_preserved'] is True
         and seal['phone_calls']==seal['model_requests']==0 and seal['phone_business_qualified'] is False,
         'component-only seal or changed production seal cannot be a formal release')
    helpers={}
    for row in formal['provider_helpers']:
        need(set(row)=={'name','path','bytes','sha256'} and row['name'] not in helpers,'formal helper inventory differs')
        helpers[row['name']]=pool.read({k:row[k] for k in ('path','bytes','sha256')},262144)
    helpers['release_boundaries.py']=pool.read(FIXED['CONSUMER'],262144)
    need(sha(helpers['collect_r10_readiness.py'])==FIXED['READINESS']['sha256']
         and seal['operator_helpers']==[dict(path=n,bytes=len(b),sha256=sha(b)) for n,b in sorted(helpers.items())]
         and all(payload(A+'/provider-r10-r1/'+n)==b for n,b in helpers.items()),
         'complete production operator helper/source pins differ')
    module_files={target[len(MODULE)+1:]:payload(target) for target in writes if target.startswith(MODULE+'/')}
    owner_module=verify_owner_finalizer_module(module_files)
    need(module['schema']=='hepta.module-r10-r1.file-manifest.v1' and module['release_id']=='v150-r10-r1'
         and module['binding_sha256']==sha(binding_raw) and module['phone_qualification'] is False
         and type(module['files']) is list and len(module['files'])==len({r['path'] for r in module['files']}),
         'complete production module manifest differs')
    listed={row['path']:row for row in module['files']}
    need(set(module_files)==set(listed)|{'MODULE-MANIFEST-v150-r10-r1.json','module-inputs.sha256','SEALED'}
         and all(listed[n]==dict(path=n,bytes=len(module_files[n]),sha256=sha(module_files[n])) for n in listed)
         and module_files['SEALED']==b'HEPTA_PHONE_LOCAL_V150_R10_R1_REVIEWED_INPUTS_BOUND\n',
         'module seal or complete module source census differs')
    checksum=''.join(sha(b)+'  '+n+'\n' for n,b in sorted(module_files.items()) if n not in ('module-inputs.sha256','SEALED')).encode()
    need(module_files['module-inputs.sha256']==checksum,'full module checksum manifest differs')
    need(binding['schema']=='hepta.module-r10-r1.exact-integration.v1'
         and binding['release_id']=='v150-r10-r1' and binding['migration_boot']==BOOT
         and binding['policy_sha256']==POLICY and binding['parent_policy_sha256']==PARENT_POLICY
         and binding['provider_source_seal_sha256']==sha(seal_raw)
         and binding['configuration_sha256']==sha(config) and binding['service_inputs_sha256']==sha(service)
         and binding['component_boundary_inputs_sha256']==sha(component_raw)
         and binding['policy_adoption_inputs_sha256']==sha(policy_raw)
         and binding['component_boundary_sha256']==boundary['component_boundary_sha256']
         and binding['release_boundary_bundle_sha256']==release['release_boundary_bundle']['sha256']
         and binding['shared_materials_sha256']==sha(shared_raw)
         and binding['retirement_sha256']==boundary['retirement_sha256']
         and binding['original_retirement_required'] is False and binding['old_claims_and_actions_preserved'] is True
         and binding['phone_installed'] is False and binding['phone_ready'] is False
         and binding['final_19_qualification'] is False and binding['cold_boot_qualified'] is False,
         'module binding cannot grant phone or final19 qualification')
    need(module['payload_files']==binding['payloads'] and module['retirement_sha256']==binding['retirement_sha256']
         and build['module_manifest_sha256']==sha(module_raw) and build['source_seal_sha256']==sha(seal_raw)
         and build['configuration_sha256']==sha(config) and build['service_inputs_sha256']==sha(service)
         and build['payload_write_count']==len(writes) and build['existing_input_count']==len(release['verify_existing'])
         and build['retirement_sha256']==binding['retirement_sha256']
         and build['component_boundary_inputs_sha256']==sha(component_raw)
         and build['policy_adoption_inputs_sha256']==sha(policy_raw)
         and build['component_boundary_sha256']==boundary['component_boundary_sha256']
         and build['release_boundary_bundle_sha256']==release['release_boundary_bundle']['sha256']
         and build['shared_materials_sha256']==sha(shared_raw),
         'actual BUILD cannot disagree with complete archive and module originals')
    pool.recheck()
    return {'schema':'hepta.r10.actual-final-release-original-verdict.v1',
       'state':'ACTUAL_HOST_RELEASE_ORIGINALS_VERIFIED_PHONE_READINESS_SEPARATE',
       'actual_build_result_sha256':sha(build_raw),'combination_sha256':sha(combination_raw),
       'runtime_combination_sha256':sha(combination_raw),
       'production_combination_sha256':sha(canonical(binding)),
       'production_combination_manifest_sha256':sha(binding_raw),
       'all_17_shared_bytes_equal':True,'component_package_sha256':RUNTIME,
       'policy_adoption_sha256':sha(policy_raw),'policy_sha256':POLICY,
       'release_pins':{'source_seal_sha256':sha(seal_raw),'configuration_sha256':sha(config),
         'module_manifest_sha256':sha(module_raw),'service_inputs_sha256':sha(service),
         'component_boundary_inputs_sha256':sha(component_raw),'policy_adoption_inputs_sha256':sha(policy_raw)},
       'module_owner_finalizer':owner_module,
       'actual_builder_process':process,'original_paths_verified':len(pool.rows),'original_raw_bytes_read':pool.total,
       'all_originals_bookended':True,'projected_original_installer_functions':list(PROJECT_FUNCTIONS),
       'phone_ready':False,'business_qualified':False,'whole_case_pass':False,'fixed19_credit':0,
       'phone_calls':0,'model_calls':0,'native_submissions':0}
