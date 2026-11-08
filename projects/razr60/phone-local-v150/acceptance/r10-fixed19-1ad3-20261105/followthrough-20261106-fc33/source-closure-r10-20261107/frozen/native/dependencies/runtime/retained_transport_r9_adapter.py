"""Fixed R10 runtime adapter for the independently retained R9 transport failure.

This uncompressed frozen source is a runtime dependency. It is not an R9 failure
original and is never added to the three-file R9 proof publication directory.
"""
from pathlib import Path
import base64
import types

PROOF_SCHEMA='hepta.r9.retained-transport-failure-manifest.v1'
RESULT_SCHEMA='hepta.r9.retained-transport-failure-verification.v1'
RESULT_STATE='EXACT_FAILED_R9_FIRST_PUSH_ORIGINALS_RECONCILED_UNKNOWN_RETAINED'
OBSERVATION_SCHEMA='hepta.r10.retained-transport-observation.v1'
NONCE='299483481a678cbd589aeba54ed8b68f'
PHONE_ROOT='/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/'+NONCE
ADAPTER_PATH='/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-runtime-dependencies-r10-r1/fc33-r10-01/retained_transport_r9_adapter.py'
FROZEN_PROOF_INPUTS={'proof': {'phone': {'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/299483481a678cbd589aeba54ed8b68f/RETENTION-INPUTS.json', 'bytes': 421, 'sha256': 'fb0c324e3bc994b56732fc6c6385ed686b73e138fd47e1e538e32c1a535b945b'}, 'archive': {'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/299483481a678cbd589aeba54ed8b68f/ORIGINALS.zlib', 'bytes': 2174339, 'sha256': '18da9626e5ae687adb4087b5a5484d9d2a8dc8885fdaabfd57b829ec02d20fd3'}, 'reader': {'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/299483481a678cbd589aeba54ed8b68f/READER.py', 'bytes': 34650, 'sha256': '919d508899f405a5942766ad5d9adf0bfa0600aa0bc2e51552a835b5a8c7fbd3'}, 'host': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/retained-transport-r9-failed01/RETENTION-INPUTS.json', 'bytes': 431, 'sha256': 'a49f04c7e6be09e9d46b00176b9a0baf4489b12d764abbfe4482f5c839fee01d'}, 'host_archive': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/retained-transport-r9-failed01/ORIGINALS.zlib', 'bytes': 2174339, 'sha256': '18da9626e5ae687adb4087b5a5484d9d2a8dc8885fdaabfd57b829ec02d20fd3'}, 'host_reader': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/retained-transport-r9-failed01/verify_retained_transport_r9.py', 'bytes': 34650, 'sha256': '919d508899f405a5942766ad5d9adf0bfa0600aa0bc2e51552a835b5a8c7fbd3'}, 'phone_manifest_base64': 'eyJhcmNoaXZlIjp7ImJ5dGVzIjoyMTc0MzM5LCJwYXRoIjoiL3Zhci9saWIvdHJpbGxpb25uaXVtL293bmVyLW9wZW4vcGhvbmUtbG9jYWwtdjE1MC9uYXRpdmUtZ3VhcmQtbm9ubmF0aXZlLWJvdW5kYXJpZXMtcjEwLXIxLzI5OTQ4MzQ4MWE2NzhjYmQ1ODlhZWJhNTRlZDhiNjhmL09SSUdJTkFMUy56bGliIiwic2hhMjU2IjoiMThkYTk2MjZlNWFlNjg3YWRiNDA4N2I1YTU0ODRkOWQyYThkYzg4ODVmZGFhYmZkNTdiODI5ZWMwMmQyMGZkMyJ9LCJyYXdfYXJjaGl2ZSI6eyJieXRlcyI6Mzc4ODgwMCwic2hhMjU2IjoiY2E3NmUwODU0YmUxMmNiMDA0YmVmMDU3ZGY2NjgzNzRiODUxYzBhMmE5MDYwNGYxYWU3YzhlYTQyMmIzNjhkNiJ9LCJzY2hlbWEiOiJoZXB0YS5yOS5yZXRhaW5lZC10cmFuc3BvcnQtZmFpbHVyZS1tYW5pZmVzdC52MSJ9Cg=='}, 'binding': {'schema': 'hepta.r9.retained-transport-failure-binding.v1', 'label': 'root-r10-neg01-fc33-r9-bound01', 'nonce': '299483481a678cbd589aeba54ed8b68f', 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'package': {'bytes': 73225, 'sha256': 'bcabd6171f84738300b1a1e1bbac5263356339f9d9c5e9ee3079db16ca820734'}, 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'lease': {'bytes': 2506, 'sha256': 'c56261e8a905de9a3e12d81d16c2a9fb15e90103a4fc0324d6f93c74ec5a6c17'}, 'evidence_archive': {'archive': {'bytes': 2174339, 'sha256': '18da9626e5ae687adb4087b5a5484d9d2a8dc8885fdaabfd57b829ec02d20fd3'}, 'raw_archive': {'bytes': 3788800, 'sha256': 'ca76e0854be12cb004bef057df668374b851c0a2a90604f1ae7c8ea422b368d6'}}, 'inventory': {'bytes': 1403290, 'sha256': 'bb8cfb6dd2f108046e8296956e514f7b3eec0ea5aaac5794ad86c70174478609'}, 'private_roots': [], 'component_role_identities': {}, 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'original_root_namespace_anchor': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-fc33-r9-bound01/ROOT-FAILURE.json', 'bytes': 3274, 'sha256': '29b5b67cc99280b36c3250d87aaf3ecfeec8a19a79d22e715338447bd6095763'}, 'retained_preaccept_binding': {'schema': 'hepta.r7.retained-preaccept-binding.v1', 'label': 'root-r10-neg01-fc33-r7-bound01', 'nonce': '4808fbf1e81fd1542e7ffb60d7f57ca6', 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'package': {'bytes': 61701, 'sha256': '643d4e17475293532aa02489194c01175d263f54d8a5979ae96ff802d4f5150a'}, 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'lease': {'bytes': 2506, 'sha256': '03f1d2a383384e74743e3331adf39a50bdd8e3d4c9a8d4e618bd8b6012557a5c'}, 'evidence_archive': {'archive': {'bytes': 3000200, 'sha256': '4010779b9a3810dc7d0d51072dc76dd52be2327301b857df2b04ddb004a5edca'}, 'raw_archive': {'bytes': 11427840, 'sha256': 'a50abed2fea44393468bd058c9c97d72330e9bf0b98e36aa196f0a0d05affcdd'}}, 'inventory': {'bytes': 1378036, 'sha256': 'dfdadedaded0eced586cc680f39d8ab58c336db2d25d75daf7460fc32ae74f7f'}, 'component_role_identities': {'supervisor': [12513, 12513, 12513, 39102689], 'sidecar': [14026, 14026, 14026, 39106597]}, 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01/executor', '/proc/1/root/data/local/tmp/hepta-native-guard-4808fbf1e81fd1542e7ffb60d7f57ca6'], 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'native_case_credit': 0, 'component_qualified': False}, 'retained_failed_staged_binding': {'schema': 'hepta.r8.retained-staged-failure-binding.v1', 'label': 'root-r10-neg01-fc33-r8-bound01', 'nonce': 'aa06c3b8d035dcd0c0047105f620b3bf', 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'package': {'bytes': 65655, 'sha256': '654f8b0ad50a4d930d7beff9421b5e9f988ecb74b55badc70cec9efeaa63130c'}, 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'lease': {'bytes': 2506, 'sha256': 'f05ee53a7609972c18f6bab2263008a4c3de3b49b12b8654df94790b25c30a44'}, 'evidence_archive': {'archive': {'bytes': 2066079, 'sha256': 'd66d286bfb7890e0b32358326b669ac4a47d5f4ba43c524bc3f129f5bf631e93'}, 'raw_archive': {'bytes': 6389760, 'sha256': '2f0e98f48f0f1449cf1fe588ffe6b5a30f69f252fae67e5fd1682a25b713a213'}}, 'inventory': {'bytes': 1403291, 'sha256': '2008db913728ff0c3836cb6edb361e37f427d7663f2832163fe93b2adb18f432'}, 'component_role_identities': {}, 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r8-bound01', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r8-bound01/executor'], 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'original_root_namespace_anchor': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-fc33-r8-bound01/ROOT-FAILURE.json', 'bytes': 12992, 'sha256': 'ab8c85f7d403c6427931db66acfecb12137143cf3b78573a654346584dab7a31'}, 'retained_preaccept_binding': {'schema': 'hepta.r7.retained-preaccept-binding.v1', 'label': 'root-r10-neg01-fc33-r7-bound01', 'nonce': '4808fbf1e81fd1542e7ffb60d7f57ca6', 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'package': {'bytes': 61701, 'sha256': '643d4e17475293532aa02489194c01175d263f54d8a5979ae96ff802d4f5150a'}, 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'lease': {'bytes': 2506, 'sha256': '03f1d2a383384e74743e3331adf39a50bdd8e3d4c9a8d4e618bd8b6012557a5c'}, 'evidence_archive': {'archive': {'bytes': 3000200, 'sha256': '4010779b9a3810dc7d0d51072dc76dd52be2327301b857df2b04ddb004a5edca'}, 'raw_archive': {'bytes': 11427840, 'sha256': 'a50abed2fea44393468bd058c9c97d72330e9bf0b98e36aa196f0a0d05affcdd'}}, 'inventory': {'bytes': 1378036, 'sha256': 'dfdadedaded0eced586cc680f39d8ab58c336db2d25d75daf7460fc32ae74f7f'}, 'component_role_identities': {'supervisor': [12513, 12513, 12513, 39102689], 'sidecar': [14026, 14026, 14026, 39106597]}, 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01/executor', '/proc/1/root/data/local/tmp/hepta-native-guard-4808fbf1e81fd1542e7ffb60d7f57ca6'], 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'native_case_credit': 0, 'component_qualified': False}, 'absent_fixture_path': '/proc/1/root/data/local/tmp/hepta-native-guard-aa06c3b8d035dcd0c0047105f620b3bf', 'fixture_is_inventory_root': False, 'original_nonce_consumed': True, 'original_remote_cleanup_boolean': False, 'global_unknown_effect_count': None, 'native_terminal': None, 'native_case_credit': 0, 'component_qualified': False, 'standalone_execution_authorized': False}, 'first_launch_receipt_gap': True, 'original_start_reused': True, 'original_retried_launch': False, 'original_wrapper_status': 'failed_or_unknown_no_retry', 'historical_failed_route_callsite': None, 'historical_failed_listener_identity': None, 'baseline_device_shell_wire_dispatched': None, 'global_unknown_effect_count': None, 'native_terminal': None, 'native_case_credit': 0, 'component_qualified': False, 'business_qualified': False, 'standalone_execution_authorized': False, 'original_nonce_consumed': True, 'replay_authorized': False, 'new_nonce_authorized': False, 'remote_cleanup_proven': False, 'same_boot_complete_scope_original': {'bytes': 11658275, 'sha256': '7323e266eed8e2e0413f4a04e4368b703953103c214a569a0fe175bcc76b2ddd'}, 'first_push_scope_only': True, 'current_kernel_ESRCH_asserted': False}}
FAILURE_SEMANTICS={'first_launch_receipt_gap':True,'original_start_reused':True,
 'original_retried_launch':False,'original_wrapper_status':'failed_or_unknown_no_retry',
 'historical_failed_route_callsite':None,'historical_failed_listener_identity':None,
 'global_unknown_effect_count':None,'native_terminal':None,'native_case_credit':0,
 'component_qualified':False,'business_qualified':False,'standalone_execution_authorized':False,
 'original_nonce_consumed':True,'replay_authorized':False,'new_nonce_authorized':False,
 'remote_cleanup_proven':False}

class Adapter:
    def __init__(self,*,common,expected_inputs_sha256,adapter_source,prior,old_read_pinned,
                 inventory_reader,supplied=None):
        C=common;inputs=FROZEN_PROOF_INPUTS
        C.need(type(inputs)is dict and set(inputs)=={'proof','binding'}
               and type(expected_inputs_sha256)is str and C.HASH.fullmatch(expected_inputs_sha256)
               and C.sha(C.encoded(inputs))==expected_inputs_sha256,
               'fully bound exact immutable R9 proof inputs before any proof read')
        proof=inputs['proof'];binding=inputs['binding']
        self.C=C;self.proof=proof;self.binding=binding;self.adapter_source=adapter_source
        self.prior=prior;self.old_read_pinned=old_read_pinned
        self.inventory_reader=inventory_reader;self.supplied=supplied
        C.need(type(proof)is dict and set(proof)=={'phone','archive','reader','host',
               'host_archive','host_reader','phone_manifest_base64'}
               and type(binding)is dict and type(prior)is dict and
               set(prior)=={'preaccept_archive','staged_phone','staged_archive','staged_reader',
                            'preaccept_binding','staged_binding'},
               'complete explicit fixed R9 proof and unchanged old proof context')
        C.need(callable(old_read_pinned) and callable(inventory_reader)
               and (supplied is None or callable(supplied)),
               'explicit unchanged old reader, inventory parser and bounded R9 reader')
        for key in ('phone','archive','reader','host','host_archive','host_reader'):
            self.descriptor(proof[key],4*1024*1024)
        for key in ('preaccept_archive','staged_phone','staged_archive','staged_reader'):
            self.descriptor(prior[key],4*1024*1024)
        self.descriptor(adapter_source,32768)
        C.need(adapter_source['path']==ADAPTER_PATH
               and proof['phone']['path']==PHONE_ROOT+'/RETENTION-INPUTS.json'
               and proof['archive']['path']==PHONE_ROOT+'/ORIGINALS.zlib'
               and proof['reader']['path']==PHONE_ROOT+'/READER.py'
               and type(proof['phone_manifest_base64'])is str
               and len(proof['phone_manifest_base64'])<=65536
               and all(type(prior[k])is dict for k in ('preaccept_binding','staged_binding')),
               'fixed R9 three-file proof and separate R10 source namespace')
        for a,b in (('archive','host_archive'),('reader','host_reader')):
            C.need({k:proof[a][k]for k in ('bytes','sha256')}==
                   {k:proof[b][k]for k in ('bytes','sha256')},
                   'same complete source/archive bytes across explicit host path mapping')

    def descriptor(self,row,maximum):
        C=self.C
        C.need(type(row)is dict and set(row)=={'path','bytes','sha256'}
               and type(row['path'])is str and Path(row['path']).is_absolute()
               and str(Path(row['path']))==row['path']and '..'not in Path(row['path']).parts
               and type(row['bytes'])is int and 0<row['bytes']<=maximum
               and type(row['sha256'])is str and C.HASH.fullmatch(row['sha256']),
               'fixed absolute bounded exact source/proof descriptor')
        return row

    def same(self,row,raw):
        C=self.C
        C.need(type(raw)is bytes and C.descriptor(raw)=={k:row[k]for k in ('bytes','sha256')},
               'complete fixed original/source bytes differ')
        return raw

    def read_pinned(self,row):
        C=self.C;p=self.proof;old=self.prior
        if row in (old['preaccept_archive'],old['staged_phone'],old['staged_archive'],old['staged_reader']):
            return self.same(row,self.old_read_pinned(row))
        C.need(row in (p['phone'],p['archive'],p['reader']),
               'only three R9 originals and four separately verified historical originals')
        if self.supplied is not None:
            raw=self.supplied(row)
        else:
            path=Path(row['path']);before=C.metadata(path.lstat())
            raw=C.read(path,4*1024*1024)
            C.need(before==C.metadata(path.lstat()),'same R9 original full9 bookends')
        return self.same(row,raw)

    def host_reader(self,read_pinned):
        C=self.C;p=self.proof
        C.need(callable(read_pinned),'bounded bookended Mac original reader')
        phone_raw=base64.b64decode(p['phone_manifest_base64'],validate=True)
        self.same(p['phone'],phone_raw);phone=C.strict(phone_raw)
        def manifest():
            raw=self.same(p['host'],read_pinned(p['host']));value=C.strict(raw)
            C.need(set(value)==set(phone)=={'schema','archive','raw_archive'}
                   and value['schema']==phone['schema']==PROOF_SCHEMA
                   and value['raw_archive']==phone['raw_archive']
                   and value['archive']==p['host_archive']
                   and phone['archive']==p['archive'],
                   'consume actual Mac R9 manifest before exact phone path representation')
        manifest()
        def supplied(row):
            if row==p['phone']:
                manifest();return phone_raw
            if row==p['archive']:target=p['host_archive']
            elif row==p['reader']:target=p['host_reader']
            else:raise ValueError('host R9 hook left the exact three proof originals')
            return self.same(row,read_pinned(target))
        return supplied

    def reader(self):
        raw=self.read_pinned(self.proof['reader'])
        self.C.need(len(raw)<=128*1024,'unchanged external reader source bound')
        mod=types.ModuleType('fixed_failed_transport_r9')
        mod.__file__=self.proof['reader']['path']
        exec(compile(raw,mod.__file__,'exec'),mod.__dict__)
        return mod

    def verify(self):
        C=self.C;p=self.proof;old=self.prior
        r=self.reader()
        manifest=C.strict(self.read_pinned(p['phone']))
        C.need(manifest=={'schema':r.MANIFEST_SCHEMA,'archive':r.ARCHIVE,'raw_archive':r.RAW_ARCHIVE}
               and r.MANIFEST_SCHEMA==PROOF_SCHEMA and r.ARCHIVE==p['archive']
               and type(r.RAW_ARCHIVE)is dict and set(r.RAW_ARCHIVE)=={'bytes','sha256'},
               'consume the entire exact R9 manifest before the archive reader')
        v=r.verify_retained_transport_archive(p['archive'],read_pinned=self.read_pinned)
        C.need(v['schema']==RESULT_SCHEMA and v['state']==r.RESULT_STATE==RESULT_STATE
               and all(type(v.get(k))is type(x)and v[k]==x for k,x in FAILURE_SEMANTICS.items()),
               'all original R9 failure, receipt gap and unknown semantics remain unchanged')
        C.need(v['retained_failed_transport_binding']==self.binding and v['nonce']==NONCE
               and v['private_roots']==[] and v['component_role_identities']=={}
               and v['retained_preaccept_binding']==old['preaccept_binding']
               and v['retained_failed_staged_binding']==old['staged_binding']
               and v['original_native_predecessor']==old['staged_binding']['original_native_predecessor'],
               'only the fully proved zero-added-root/role R9 family; never a native predecessor')
        self.inventory_reader(v['inventory_value'])
        C.need(len(v['inventory_roots'])==49 and v['inventory_roots']==v['inventory_value']['roots']
               and v['inventory']==C.descriptor(C.encoded(v['inventory_value'])),
               'complete retained49 inventory identity')
        return v

    def current_binding(self,value,*,retained_failed_transport_value=None):
        C=self.C
        v=self.verify()if retained_failed_transport_value is None else retained_failed_transport_value
        C.need(type(value)is dict and v['retained_failed_transport_binding']==self.binding
               and value.get('retained_failed_transport_binding')==self.binding
               and value.get('nonce')!=v['nonce'],'same independently retained R9 failure and consumed nonce')
        return v

    def preserve(self,inventory,*,retained_failed_transport_value=None):
        v=self.verify()if retained_failed_transport_value is None else retained_failed_transport_value
        self.C.need(v['retained_failed_transport_binding']==self.binding,'same fixed R9 family')
        return self.reader().validate_private_preservation(v,inventory,inventory_reader=self.inventory_reader)

    def fresh_absence(self,*,deadline):
        return self.reader().observe_current_absence(common_module=self.C,deadline=deadline)

    def validate_absence(self,observations,*,retained_failed_transport_value=None):
        v=self.verify()if retained_failed_transport_value is None else retained_failed_transport_value
        self.C.need(v['retained_failed_transport_binding']==self.binding,'same R9 absence family')
        return self.reader().validate_absence_observations(observations,expected_boot_id=v['boot_id'])

    def validate_observation(self,value,*,retained_failed_transport_value=None):
        C=self.C;p=self.proof
        v=self.verify()if retained_failed_transport_value is None else retained_failed_transport_value
        C.need(type(value)is dict and set(value)=={'schema','binding','proof_originals',
               'runtime_adapter','absence_observations','failure_semantics'}
               and value['schema']==OBSERVATION_SCHEMA and value['binding']==v['retained_failed_transport_binding']
               and value['proof_originals']==[p['phone'],p['archive'],p['reader']]
               and value['runtime_adapter']==self.adapter_source
               and value['failure_semantics']==FAILURE_SEMANTICS
               and all(type(value['failure_semantics'][k])is type(x)for k,x in FAILURE_SEMANTICS.items()),
               'exact captured R9 proof, separate runtime source and unchanged unknown semantics')
        self.validate_absence(value['absence_observations'],retained_failed_transport_value=v)
        return value

    def external_originals(self):
        C=self.C;rows=[]
        for row in (self.proof['phone'],self.proof['archive'],self.proof['reader']):
            path=Path(row['path']);before=C.metadata(path.lstat());self.read_pinned(row)
            C.need(before==C.metadata(path.lstat()),'R9 proof source generation changed')
            rows.append(dict(row,metadata=before))
        return rows

    def validate_manifest(self,manifest):
        C=self.C;p=self.proof
        expected={'retained_failed_transport_binding':self.binding,
            'retained_failed_transport_phone_originals':[p['phone'],p['archive'],p['reader']],
            'retained_failed_transport_runtime_adapter':self.adapter_source,
            'retained_failed_transport_role_count':0,'retained_failed_transport_private_root_count':0,
            'retained_failed_transport_original_start_reused':True}
        C.need(type(manifest)is dict and all(type(manifest.get(k))is type(v)and manifest[k]==v
               for k,v in expected.items()),'exact retained R9 proof and separate runtime source manifest fields')
        return manifest

    def source_parent_inventory(self,r7,r8):
        C=self.C;v=self.verify()
        C.need(r7['retained_preaccept_binding']==self.prior['preaccept_binding']
               and r8['retained_failed_staged_binding']==self.prior['staged_binding']
               and v['original_native_predecessor']==r8['original_native_predecessor']
               and v['inventory_roots']==r8['inventory_roots']
               and self.inventory_reader(v['inventory_value'])==self.inventory_reader(r8['inventory_value']),
               'only actual R9 retained49 with every original R8 topology/full9/hash preserved')
        self.preserve(v['inventory_value'],retained_failed_transport_value=v)
        return v['inventory_value'],v['inventory'],'exact_source_parent44_plus_retained_failed_r7_r8_r9_49'
