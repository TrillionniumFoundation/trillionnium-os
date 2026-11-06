#!/usr/bin/env python3
"""Explicit r10 preservation and policy inputs; imports perform no phone work.

The builder embeds exact reviewed originals in a bounded bundle. Runtime readers
verify that same bundle and compare observations with its adopted values. No
function discovers an acceptable policy hash, changes policy, publishes a late
boundary, sends a signal, starts a service or supplies a component qualification.
"""
import ast
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types
import zlib
BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
RELEASE = 'v150-r10-r1'
PARENT_POLICY = 'bfe7acc92ba8c5b7a3a1c2360d6faf53f804a19c3e25e20aad336e3220fa0e38'
CANDIDATE_POLICY = '1b1513ced8c62f4ac592ae955fe1eaf385b98db06a4e30add741255e24e9be16'
PARENT_RULE = '30f3963d10aa4c4eea70c31c8f80278490be3c16986fb029853b5bc217a4b6f8'
DELTA_RULE = 'ecf74e374f1e34dea958e9ce7298358dbf2e0fd1e1a988994da16f776411d120'
FULL_RULE = 'dd9303a46c0016c98cce26b8a2fa199e045038f70148817d72fa6034e86dd0e3'
ATOM = ['allow', 'trillionnium_owner_open_phone_worker', 'hal_graphics_allocator_default', 'fd', 'use']
BASE = '/var/lib/trillionnium/owner-open/phone-local-v150'
ANDROID_BASE = '/data/trillionnium/owner-open/state/phone-local-v150'
MODULE = '/data/adb/modules/trillionnium_hepta_phone_local_v150_r10_r1'
INSTALL_DIRECTORY = BASE + '/executor-r6/module-history-r10-r1'
INSTALL_LABEL = 'u:object_r:trillionnium_owner_open_phone_executor_data_file:s0'
PACKAGE_SHA = None
PACKAGE_FILE_COUNT = 32
CURRENT_COMBINATION_SHA = None
SHARED_MATERIALS_SHA = None
POLICY_VERIFIER_SHA = None
POLICY_VERIFIER_BYTES = None
MAX_ORIGINAL = 16 * 1024 * 1024
MAX_BUNDLE = 32 * 1024 * 1024
HASH = re.compile(r'[0-9a-f]{64}\Z')
COMPONENT_FIELDS = {'schema', 'release_id', 'boot_id', 'component_package_manifest',
'component_package_files', 'component_combination', 'latest_boundary',
'component_shared_material_manifest', 'component_shared_material_files',
'publish_result', 'retirement', 'originals', 'pre_policy_ancestor', 'non_native_sidebranch',
'environment_parent_ancestor', 'property_parent_ancestors',
'epoch_publication_inputs', 'epoch_publication_originals', 'source_recipe'}
POLICY_FIELDS = {'schema', 'release_id', 'boot_id', 'comparison_route', 'parent',
'candidate', 'actual_export', 'parent_rule', 'delta_rule', 'full_rule',
'offline_result', 'offline_comparison', 'pre_live_expectation',
'live_operation', 'live_originals', 'post_live_comparison', 'retirement_sha256',
'prior_boundary_sha256', 'root_decision'}
LIVE_GUARD_SHA = '2f657aea0712db933ffe3a2e3c86fdc488fdad98576289defb4c79dfa320d67d'
LIVE_OPERATION_DIRECTORY = BASE + '/policy-fd-use-r10-live-01'
LIVE_ARGV = ['/data/adb/magisk/magiskpolicy', '--live', '--apply',
ANDROID_BASE + '/policy-fd-use-r10-live-01/fd-use.delta.rule']
def _property_parent_host_originals():
 encoded = 'c-rllPjeeZ5XJ9&44t#l{GXoOOfXfhN^Hupsp917p6QN7WUW}O41vmbr&qz065#-+pcFpX>s?7Z^V{y%@9DQ0jw9c#N0VpIew)?)jutB%7yWAbm)?%NnLP{HxF@qUj<>UCv-$Oght2$_1+IQt%)jaD_KsKMX8ycy{L9=KmpW@Y3-fhf-|!f^0e>Bm>9&jc&;9Ubz8UqrP2DZ8N9>k;#btM=?_GA6eLr^hHkxj*^Jx+H+`Zo7(7Iu|Qg3mw+UT|2_1&rIc*U=c?WX%$Yhq{e{0>JR7Py>`1M_^bT5qT2UA+AI?EK{F?Be|Cj~m_IliB7LT}-+q!dPQ5kPK0d#uaOl%?zOx<6S{pY>ikfC#-r_C<}0iWHH7BKF{7gnf1fswUS%jObfdaTr9T(?=iH-#CSvyFE1{xx^GX;UR+<E9st9PzM}CVI}AQn_OZn3F#(8pUnpltXrNjWYEl0*h|!5pMR|#tfUU8<!Pk6qhpUC~X544xLr9;O)s9csuX(_+AG#sWhwW-y-0}S7$@$s0r?0LKpy<v5=uRm`Pc2s}nVQy-ZHa7<#1$n-DFL{-q$QOp*WipWMqyufPzJtV^xMrojNssi>gMG6)%D4X?z_v=@6Rr-Uv+2a-(4TFLhlnQi)@-eVazd8us%X`X6nKMtS1vT;X-VU$A;(%DZ<>eHFvDGv|QAkR^7aRP#>z6b0HrQxb<zn;%=$h)$Mk+xz(Gtemg#Wkd}Rb-YXK<j5e77Rd1DGVdJ#foFOJ7lUzY#2dH(Ki46g^6oY^kWcV1M-in7|kDfVtbh@9vM8}>?4Z#(VYO4(eg(OrcB?%Q5Tt*I-Lkfk84;4d+rC7>ZoTM@~p&PjN_dLA4S*%8dvBwScQIuoS`P1hY-=ALoppANUdVbicK&tAYI#9{?yD}0REcr?%B$Y2;6B!%5i^gl)7A}FD;$=w^IO7Mj2HtF!`?Oq+{up6hp1!(%aR@87C=msVcUEVCanVa9t3OVfID~4d@}rn+sNzIFHehMlS3?$R{s7jd-wt)(Lik|8epXt4dd2QxmEHSQPOp4_G@qXF9q$|vw;MH-Yi-VzzUS%s?LI5rHlndCMq&v@5mnI!BOQ=bp*CZYGD+hMIZB9`Yq2G{>M5`(ZpUi!T8BlYc+0U_tw$=V#VDyXw9racm*uIN;8mKELH*r4k|!uOCF5I5NZN+RsmQmKTGH})r<fid8+;)aA3n3iuecu7-9Nbeo1T={{l`crH)D>7=^wl59=5sZjGe!_e);m`@`nSS5s*Y;^HRXN<UmqpQX$KXwl)t<s)1%=5mCF#)}mNJ-`H@D;Uk{CTI<#Jy%RZ%P5?O_5y$l{Zn)du(**LdC<VrO!$Doh<ko7bSOJ0>joLC*au}f~$_mXnZd$)qyFGH`Qh^<%f08|mv-yYselmJ8rP}N?Av7=)btS5G$ec7@+T4U<R;`T1WsRa%G=bUZvRaYgT*P4Q|Izacjh^riqi3<+vx_Q7DIpk*mnkSQAPR-OW&s~9xY#Ia1c;J#2B=drlv-(8Q{jt?p71ZDXUNtvs$&g7Jh?1L#;8PRH6BsNDi+DEnpC4m4VZ&C^(cCsU5fhpFDQD#e=2%v3QPW&T-@Jf&)ihKt4K>h2O}||SFJZ*T?U0_bJZze69;v{m3#?FM}hMs05(Gb|LN@MV>n7!k0b>XeerqnwwW}A`k1Iz>l>(p6?P@GAPTLbVq^tawEkS!eb;8F#P;dz8MD^pe<FLrVfJ)?mp$R5>?uT5F$e;<3NEvT_NJ4d1t(C@)DnuRHkT%;`J$FWm{_ww$e>9gJf1zhH~#3n)?*cwvnr8S_vA>jN|H4>f~HXQS*l(!qK`6tU2CQ2AqGehbf`*5Iva{s)Vp_I{SKy#UxN'
 compressed_size = 1478
 compressed_sha = '81514f487b2e109e5a1104b3815a49ff369bc62b58db9a470b6d0cd746bb1ff4'
 decoded_size = 6753
 decoded_sha = '071097b0906a891bbc1087b1b371582dce44e2a44da4514ce65afbb320cee1f7'
 if len(encoded) != 1848 or not 0 < decoded_size <= 16384:
  raise ValueError('fixed property table data bound differs')
 packed = base64.b85decode(encoded.encode('ascii'))
 if (len(packed) != compressed_size or hashlib.sha256(packed).hexdigest() != compressed_sha
 or base64.b85encode(packed).decode('ascii') != encoded):
  raise ValueError('fixed property table compressed original differs')
 stream = zlib.decompressobj()
 original = stream.decompress(packed, decoded_size + 1)
 if (not stream.eof or stream.unused_data or stream.unconsumed_tail
 or len(original) != decoded_size or hashlib.sha256(original).hexdigest() != decoded_sha):
  raise ValueError('property table is not its one complete bounded data stream')
 def pairs(items):
  result = {}
  for key, item in items:
   if key in result:
    raise ValueError('duplicate property table JSON key')
   result[key] = item
  return result
 def nonfinite(_):
  raise ValueError('nonfinite property table JSON value')
 result = json.loads(original, object_pairs_hook=pairs, parse_constant=nonfinite)
 canonical = (json.dumps(result, sort_keys=True, separators=(',', ':'),
 ensure_ascii=False, allow_nan=False) + '\n').encode()
 if canonical != original:
  raise ValueError('fixed property table canonical bytes differ')
 return result
PROPERTY_PARENT_HOST_ORIGINALS = _property_parent_host_originals()
CURRENT_POLICY_SHA = None
CURRENT_POLICY_ADOPTION_SHA = None
CURRENT_SCOPE_DECISION_SHA = None
def need(value, reason):
 if not value:
  raise ValueError(reason)
def sha(raw):
 return hashlib.sha256(raw).hexdigest()
def encode(value):
 return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
 allow_nan=False) + '\n').encode()
def strict(raw):
 def pairs(rows):
  result = {}
  for key, value in rows:
   need(key not in result, 'duplicate JSON field')
   result[key] = value
  return result
 return json.loads(raw, object_pairs_hook=pairs,
 parse_constant=lambda _v: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
def descriptor(raw):
 return {'bytes': len(raw), 'sha256': sha(raw)}
def meta(value):
 return [getattr(value, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]
def file_descriptor(row):
 need(isinstance(row, dict) and set(row) == {'path', 'bytes', 'sha256'},
 'exact host original descriptor required')
 p = Path(row['path'])
 need(p.is_absolute() and str(p) == row['path'] and '..' not in p.parts,
 'canonical original path required')
 need(type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_ORIGINAL
 and isinstance(row['sha256'], str) and HASH.fullmatch(row['sha256']),
 'bounded original bytes/hash required')
 return row
def read_pinned(row):
 file_descriptor(row)
 p = Path(row['path'])
 need(p.resolve(strict=True) == p, 'host original path is not canonical')
 fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
 try:
  before = os.fstat(fd)
  need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
  and before.st_size == row['bytes'], 'host original metadata differs')
  with os.fdopen(fd, 'rb', closefd=False) as stream:
   raw = stream.read(row['bytes'] + 1)
  need(meta(before) == meta(os.fstat(fd)) == meta(p.lstat())
  and descriptor(raw) == {k: row[k] for k in ('bytes', 'sha256')},
  'host original changed or differs')
  return raw, meta(before)
 finally:
  os.close(fd)
def descriptors(value):
 """Walk only the separately pinned input descriptor, not arbitrary reports."""
 if isinstance(value, dict):
  if set(value) == {'path', 'bytes', 'sha256'}:
   yield file_descriptor(value)
  else:
   for child in value.values():
    yield from descriptors(child)
 elif isinstance(value, list):
  for child in value:
   yield from descriptors(child)
def pack_original(raw):
 """Lossless host encoding; raw byte identity and all size bounds stay explicit."""
 need(type(raw) is bytes and len(raw) <= MAX_ORIGINAL, 'bounded original bytes required')
 compressed = zlib.compress(raw, 9)
 smaller = 4 * ((len(compressed) + 2) // 3) + 1 < 4 * ((len(raw) + 2) // 3)
 field, body = ('zlib_b64', compressed) if smaller else ('raw_b64', raw)
 return {'bytes': len(raw), field: base64.b64encode(body).decode()}
def original_from(bundle, row):
 file_descriptor(row)
 item = bundle['originals'].get(row['sha256'])
 need(type(item) is dict and set(item) in ({'bytes', 'raw_b64'}, {'bytes', 'zlib_b64'}),
 'original is missing or its encoding fields differ')
 need(type(item['bytes']) is int and item['bytes'] == row['bytes'],
 'bundled original declared byte count differs')
 field = 'zlib_b64' if 'zlib_b64' in item else 'raw_b64'
 encoded = item[field]
 need(type(encoded) is str and len(encoded) <= 4 * ((row['bytes'] + 2) // 3),
 'original encoding exceeds its declared raw byte bound')
 body = base64.b64decode(encoded, validate=True)
 need(base64.b64encode(body).decode() == encoded, 'noncanonical original encoding')
 if field == 'zlib_b64':
  need(0 < len(body) < row['bytes'], 'compressed original must be smaller than its raw bytes')
  decoder = zlib.decompressobj()
  raw = decoder.decompress(body, row['bytes'] + 1)
  need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
  'compressed original must be one complete stream without extra data')
 else:
  raw = body
 need(item['bytes'] == len(raw) == row['bytes'] and sha(raw) == row['sha256'],
 'bundled original bytes/hash differ')
 return raw
def checked_actual_context(value):
 need(type(value) is str and value in ('phone', 'mac', 'p4'),
 'explicit actual phone/mac/p4 execution context required')
 return value
def decoded_bundle_budget(bundle):
 """Charge all decoded payloads before any body decode or source execution."""
 need(type(bundle['originals']) is dict, 'exact original byte pool required')
 total = 0
 for name in ('component', 'policy'):
  row = bundle['inputs'][name]
  need(type(row) is dict and set(row) == {'descriptor', 'raw_b64'},
  'input payload fields differ')
  descriptor = file_descriptor(row['descriptor'])
  need(type(row['raw_b64']) is str
  and len(row['raw_b64']) <= 4 * ((descriptor['bytes'] + 2) // 3),
  'input payload exceeds its exact decoded bound')
  total += descriptor['bytes']
 need(total <= MAX_BUNDLE, 'decoded input payloads exceed fixed shared bundle budget')
 for digest, item in bundle['originals'].items():
  need(type(digest) is str and HASH.fullmatch(digest)
  and type(item) is dict
  and set(item) in ({'bytes', 'raw_b64'}, {'bytes', 'zlib_b64'})
  and type(item['bytes']) is int and 0 <= item['bytes'] <= MAX_ORIGINAL,
  'bounded decoded original pool entry required')
  total += item['bytes']
  need(total <= MAX_BUNDLE, 'decoded originals exceed one fixed shared bundle budget')
 return total
def prepare_bundle(component_input, policy_input, *, actual_context):
 """Host-only: collect exact originals, then run the shared pure checks."""
 actual_context = checked_actual_context(actual_context)
 budget_check = epoch_component_budget()
 need(actual_context == 'mac', 'this fixed host constructor requires actual Mac context')
 inputs = {}; originals = {}; observed = {}; declared = {}
 decoded_total = sum(file_descriptor(row)['bytes'] for row in (component_input, policy_input))
 need(decoded_total <= MAX_BUNDLE, 'input originals exceed fixed shared decoded budget')
 for name, row in (('component', component_input), ('policy', policy_input)):
  budget_check()
  raw, metadata = read_pinned(row)
  observed[row['path']] = (row, metadata)
  value = strict(raw)
  if name == 'component':
   _esi_recipe_match(value.get('source_recipe'))
  inputs[name] = {'descriptor': row, 'raw_b64': base64.b64encode(raw).decode()}
  for source in descriptors(value):
   budget_check()
   previous_size = declared.get(source['sha256'])
   need(previous_size is None or previous_size == source['bytes'],
   'same original digest has different declared size')
   if previous_size is None:
    decoded_total += source['bytes']
    need(decoded_total <= MAX_BUNDLE, 'originals exceed one shared decoded budget before reading')
    declared[source['sha256']] = source['bytes']
   body, identity = read_pinned(source)
   previous = observed.get(source['path'])
   need(previous is None or previous == (source, identity), 'input path changed between references')
   observed[source['path']] = (source, identity)
   item = pack_original(body)
   need(source['sha256'] not in originals or originals[source['sha256']] == item,
   'duplicate digest has different original bytes')
   originals[source['sha256']] = item
 value = {'schema': 'hepta.r10.release-boundary-bundle.v2',
 'inputs': inputs, 'originals': originals}
 raw = encode(value)
 need(len(raw) <= MAX_BUNDLE, 'reviewed release evidence bundle exceeds fixed bound')
 state = validate_bundle(raw, sha(raw), actual_context=actual_context, budget_check=budget_check)
 for row, identity in observed.values():
  _body, after = read_pinned(row)
  need(identity == after, 'host original changed while preparing bundle')
  budget_check()
 return raw, state
def input_value(bundle, name):
 row = bundle['inputs'][name]
 need(set(row) == {'descriptor', 'raw_b64'}, 'input bundle fields differ')
 file_descriptor(row['descriptor'])
 raw = base64.b64decode(row['raw_b64'], validate=True)
 need(base64.b64encode(raw).decode() == row['raw_b64']
 and descriptor(raw) == {k: row['descriptor'][k] for k in ('bytes', 'sha256')},
 'explicit input original bytes differ')
 return strict(raw)
@contextmanager
def component_modules(state, *, actual_context, runtime=False):
 """Evaluate only reviewed package originals; restore import state on exit."""
 actual_context = checked_actual_context(actual_context)
 need('actual_context' not in state or state['actual_context'] == actual_context,
 'actual execution context changed between validation and module loading')
 need(not runtime or actual_context == 'phone', 'live runtime modules require actual phone context')
 names = ['component_common', 'native_proc_profile', 'component_lifecycle',
 'prepare_component', 'late_boundary', 'component_snapshot']
 manifest_raw = state.get('package_manifest_raw')
 need(type(manifest_raw) is bytes and sha(manifest_raw) == PACKAGE_SHA,
 'actual already-admitted runtime manifest original is required before module execution')
 manifest = strict(manifest_raw); source = state['package_sources']
 need(type(manifest) is dict and type(manifest.get('files')) is list
 and type(source) is dict and len(manifest['files']) == len(source) == PACKAGE_FILE_COUNT == 32,
 'complete manifest/source32 required at every module-loader boundary')
 pins = {}
 for row in manifest['files']:
  need(type(row) is dict and set(row) == {'path','bytes','sha256'}
  and type(row['path']) is str and row['path'] not in pins
  and type(row['bytes']) is int and 0 < row['bytes']
  and ((row['path'].endswith('.py') and row['bytes'] <= 131072)
  or (row['path'].endswith('.json') and row['bytes'] <= MAX_ORIGINAL))
  and type(row['sha256']) is str and HASH.fullmatch(row['sha256']),
  'exact unique reviewed source row required before module execution')
  path = Path(row['path'])
  need('\0' not in row['path'] and not path.is_absolute()
  and '..' not in path.parts and str(path) == row['path'],
  'canonical relative reviewed source name required')
  pins[row['path']] = row
 need(set(pins) == set(source), 'runtime source map omitted or added a manifest member')
 for name,row in pins.items():
  need(type(source[name]) is bytes
  and descriptor(source[name]) == {key:row[key] for key in ('bytes','sha256')},
  'runtime source bytes changed before the first module exec: '+name)
 verify_epoch_runtime_increment(manifest_raw, source, state.get('component_combination_raw'),
 state.get('shared_runtime_originals'), recipe_raw=state.get('epoch_source_recipe_raw'))
 prior = {name: sys.modules.get(name) for name in names}
 path_before = sys.path[:]
 modules = {}
 try:
  for name in names:
   raw = state['package_sources']['source/' + name + '.py']
   module = types.ModuleType(name)
   module.__file__ = '/reviewed-r10-component-package/source/' + name + '.py'
   module.__actual_context__ = actual_context
   module.__reviewed_source_sha256__ = sha(raw)
   module.__reviewed_package_sources__ = state['package_sources']
   module.__reviewed_package_manifest_raw__ = manifest_raw
   modules[name] = module
   sys.modules[name] = module
   exec(compile(raw, module.__file__, 'exec', optimize=0), module.__dict__)
  yield modules
 finally:
  sys.path[:] = path_before
  for name, old in prior.items():
   if old is None:
    sys.modules.pop(name, None)
   else:
    sys.modules[name] = old
def validate_pre_policy_ancestor(bundle, proof, state, boundary, late):
 fields={'schema','boundary','root_result','package_manifest','combination',
 'previous','publication_operation','publication_stderr'}
 need(isinstance(proof,dict) and set(proof)==fields
 and proof['schema']=='hepta.r10.fixed-pre-policy-component-ancestor.v1',
 'explicit fixed pre-policy ancestor proof is required')
 reviewed=late.reviewed_pre_policy_ancestor()
 need(proof['boundary']==reviewed['boundary'] and late.is_pre_policy_ancestor(boundary),
 'pre-policy proof is not the exact retained actual04 original')
 home='/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261104-04'
 need(proof['root_result']=={'path':home+'/ROOT-RESULT.json','bytes':10980,
 'sha256':'c92382e0841375fc0a1fb19ff0271381ac044f1dad01427342fca4e4f6e9c638'},
 'fixed actual04 Root original differs')
 result=strict(original_from(bundle,proof['root_result']))
 manifest_raw=original_from(bundle,proof['package_manifest']);manifest=strict(manifest_raw)
 need(descriptor(manifest_raw)=={'bytes':5284,
 'sha256':'1cd57949621b36e46dc72d3df55e6ec3814fa76fb046c15ae71524463e3e8996'}
 and manifest['schema']=='hepta.native-guard.adapter-package.v1'
 and len(manifest['files'])==24,'exact historical actual04 package is required')
 need(result['late_boundary']==reviewed['boundary']
 and result['scope']==boundary['scope']
 and result['state']=='ORIGINAL_COMPONENT_CLOSED_AND_LATE_BOUNDARY_PUBLISHED'
 and result['component_qualified'] is False and result['native_status']=='provider_failed'
 and result['automatic_retry'] is False and result['business_qualified'] is False
 and type(result['model_requests']) is int and result['model_requests']==0
 and result['four_role_qualification'] is False,
 'historical failed result was changed or upgraded')
 need(proof['combination']=={'path':home+'/material/tree/inputs/COMBINATION.json','bytes':4702,
 'sha256':late.LEGACY_COMBINATION_SHA256},'fixed historical combination original differs')
 combo_raw=original_from(bundle,proof['combination']);oldcombo=strict(combo_raw)
 need(boundary['combination_sha256']==sha(combo_raw)
 and oldcombo['schema']=='hepta.native-guard.component-combination.v150.r10.1'
 and oldcombo['live_policy_sha256']=='296b09d9c844d2916b0dbdb0765c71cbcb8411790b58f5823798aa872205b659'
 and sha(combo_raw)!=CURRENT_COMBINATION_SHA,
 'historical policy identity must remain separate from the current combination')
 need(proof['previous']=={'path':home+'/ACTUAL-PREVIOUS-INPUT.json','bytes':1428,
 'sha256':'7ed4ccc75cc4ebc999af0da37e10e3d10173c2bf93e66f01b01042b890a4d9a4'},
 'exact actual04 native predecessor original differs')
 previous=strict(original_from(bundle,proof['previous']))
 need(previous['identity']==boundary['scope'] and previous['late_boundary']==reviewed['boundary']
 and previous['component_qualified'] is False and previous['terminal']['status']=='provider_failed'
 and previous['known_all_dispatched_tools_confirmed_terminal'] is True
 and previous['automatic_replay'] is False,
 'historical terminal scope or closure semantics differs')
 steps=[row for row in result['steps'] if row.get('phase')=='phone-late-publish']
 need(len(steps)==1 and type(steps[0]['returncode']) is int and steps[0]['returncode']==0,
 'actual04 original publication terminal is absent')
 step=steps[0]
 need(proof['publication_operation']==step['stdout']
 and proof['publication_stderr']==step['stderr']
 and step['stdout']['path']==home+'/phone-late-publish/stdout.original'
 and step['stderr']['path']==home+'/phone-late-publish/stderr.original',
 'fixed actual04 publication original paths differ')
 operation=strict(original_from(bundle,proof['publication_operation']))
 need(original_from(bundle,proof['publication_stderr'])==b''
 and type(operation['actor_rc']) is int and operation['actor_rc']==0
 and type(operation['wrapper']['phone']['rc']) is int
 and operation['wrapper']['phone']['rc']==0,
 'actual04 publication was not fully successful')
 raw=operation['wrapper']['phone']['stdout'];need(isinstance(raw,str),'actual04 publication stdout missing')
 published=strict(raw.encode('utf-8'))
 need(published['schema']=='hepta.native-guard.boundary-publish-result.v1'
 and published['state']=='CREATE_ONLY_CLOSED_LATE_BOUNDARY_PUBLISHED'
 and published['boundary']==reviewed['boundary']
 and published['original_retirement_rewritten'] is False,
 'retained actual04 publication does not match its original boundary')
 return proof
def validate_environment_parent_ancestor(bundle, proof, state, boundary, late):
 """Retain the one actually closed R6 failure; it is never a current case."""
 fields = {'schema', 'boundary', 'root_result', 'package_manifest', 'combination',
 'previous', 'publication_operation', 'publication_stderr',
 'recovery_result', 'recovery_source', 'recovery_intent', 'original_root_failure'}
 need(isinstance(proof, dict) and set(proof) == fields
 and proof['schema'] == 'hepta.r10.fixed-environment-parent-component-ancestor.v1',
 'explicit fixed environment-parent ancestor proof is required')
 reviewed = late.reviewed_environment_parent_ancestor()
 need(proof['boundary'] == reviewed['boundary']
 and late.is_environment_parent_ancestor(boundary),
 'environment-parent proof is not the exact retained actual06 original')
 home = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-20261105-06'
 root = {'path':home+'/ROOT-RESULT.json', 'bytes':32600,
 'sha256':'ed2e22f27b72951621802add6a1d68950ea94721d052b25dd5d59ebc95be5c93'}
 need(proof['root_result'] == root, 'fixed actual06 Root result differs')
 result = strict(original_from(bundle, proof['root_result']))
 manifest_raw = original_from(bundle, proof['package_manifest'])
 manifest = strict(manifest_raw)
 need(descriptor(manifest_raw) == {'bytes':11495,
 'sha256':'4dd75caa1d77f4698fba5084689b84c99a91c388219fd546d84906d869f23f8e'}
 and manifest['schema'] == 'hepta.native-guard.adapter-package.v1'
 and manifest['state'] == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED'
 and len(manifest['files']) == 30,
 'actual06 must retain its exact original 30-file R6 package')
 pins = {row['path']:row for row in manifest['files']}
 need(len(pins) == 30, 'historical R6 package duplicates a source')
 for name, size, digest in (
 ('source/late_boundary.py',53502,late.ENVIRONMENT_PARENT_READER_SHA256),
 ('source/component_common.py',19138,late.ENVIRONMENT_PARENT_COMMON_SHA256),
 ('source/close_component.py',99120,late.ENVIRONMENT_PARENT_CLOSURE_SHA256)):
  need(pins[name] == {'path':name,'bytes':size,'sha256':digest},
  'actual06 executed source identity differs')
 need(result['late_boundary'] == reviewed['boundary']
 and result['scope'] == boundary['scope']
 and result['state'] == 'ORIGINAL_COMPONENT_CLOSED_AND_LATE_BOUNDARY_PUBLISHED'
 and result['component_qualified'] is False and result['native_status'] == 'provider_failed'
 and result['automatic_retry'] is False and result['business_qualified'] is False
 and type(result['model_requests']) is int and result['model_requests'] == 0
 and result['four_role_qualification'] is False
 and boundary['package_sha256'] == late.ENVIRONMENT_PARENT_PACKAGE_SHA256
 and boundary['publisher_source_sha256'] == late.ENVIRONMENT_PARENT_READER_SHA256
 and boundary['prior_boundary'] == late.reviewed_pre_policy_ancestor()['boundary']
 and type(boundary['actual_native_calls']) is int and boundary['actual_native_calls'] == 1,
 'actual06 failure was reinterpreted as a current or qualified case')
 need(proof['combination'] == {'path':home+'/material/tree/inputs/COMBINATION.json',
 'bytes':4702,'sha256':'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'},
 'actual06 original combination descriptor differs')
 combo_raw = original_from(bundle, proof['combination']); combo = strict(combo_raw)
 need(boundary['combination_sha256'] == sha(combo_raw) == late.PROPERTY_PARENT_COMBINATION_SHA256
 and combo['schema'] == 'hepta.native-guard.component-combination.v150.r10.1'
 and combo['live_policy_sha256'] == '50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7',
 'historical actual06 retains its original policy combination independently of current')
 need(proof['previous'] == {'path':home+'/ACTUAL-PREVIOUS-INPUT.json','bytes':1428,
 'sha256':'5ef37523f24a78dbce66da496c7f61897d989630a18739945279b8d0383415e9'},
 'fixed actual06 latest native predecessor differs')
 previous = strict(original_from(bundle, proof['previous']))
 closure_copy = {'path':home+'/CLOSURE.json', **{k:reviewed['closure'][k] for k in ('bytes','sha256')}}
 boundary_copy = {'path':home+'/LATE-BOUNDARY.original.json',
 **{k:reviewed['boundary'][k] for k in ('bytes','sha256')}}
 need(previous['identity'] == boundary['scope'] and previous['late_boundary'] == reviewed['boundary']
 and previous['closed_component'] == closure_copy and result['previous'] == proof['previous']
 and previous['component_qualified'] is False and previous['terminal']['status'] == 'provider_failed'
 and previous['known_all_dispatched_tools_confirmed_terminal'] is True
 and previous['complete_business_success'] is False
 and previous['automatic_replay'] is False and HASH.fullmatch(previous['request_sha256']),
 'actual06 native predecessor semantics or original scope changed')
 steps = [row for row in result['steps'] if row.get('phase') == 'phone-late-publish']
 need(len(steps) == 1 and steps[0]['state'] == 'ORIGINAL_HOST_CHILD_JOINED'
 and type(steps[0]['returncode']) is int and steps[0]['returncode'] == 0
 and steps[0]['automatic_retry'] is False,
 'actual06 original publication terminal is absent')
 step = steps[0]
 need(proof['publication_operation'] == step['stdout'] and proof['publication_stderr'] == step['stderr']
 and step['stdout']['path'] == home+'/phone-late-publish/stdout.original'
 and step['stderr']['path'] == home+'/phone-late-publish/stderr.original',
 'actual06 publication original paths differ')
 operation = strict(original_from(bundle, proof['publication_operation']))
 need(original_from(bundle, proof['publication_stderr']) == b''
 and type(operation['actor_rc']) is int and operation['actor_rc'] == 0
 and type(operation['wrapper']['phone']['rc']) is int and operation['wrapper']['phone']['rc'] == 0,
 'actual06 publication was not fully successful')
 stdout = operation['wrapper']['phone']['stdout']
 need(isinstance(stdout,str), 'actual06 original publication stdout missing')
 pub = strict(stdout.encode('utf-8'))
 need(pub['schema'] == 'hepta.native-guard.boundary-publish-result.v1'
 and pub['state'] == 'CREATE_ONLY_CLOSED_LATE_BOUNDARY_PUBLISHED'
 and pub['boundary'] == reviewed['boundary'] and pub['original_retirement_rewritten'] is False,
 'actual06 original publication names another boundary')
 fixed = {
 'recovery_result':{'path':home+'/RECOVERY-RESULT.json','bytes':2724,
 'sha256':'ea74dc212a1edf1c9f4395ce72a8be8ec7a7f184b9f28321d68ece270fc4aa12'},
 'recovery_source':{'path':'/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-attempt06-recovery-source-r1/source/resume_failed_component06.py',
 'bytes':26606,'sha256':'50a4e759486632d0fc129bb08e0101f526542a8a577b47d3474497da3d9b6237'},
 'recovery_intent':{'path':home+'/RECOVERY-INTENT.json','bytes':90530,
 'sha256':'2db02625a51939dfbcaa1127d10976f253aa12e8ee9fa8c8c95c196f73ceefa2'},
 'original_root_failure':{'path':home+'/ROOT-FAILURE.json','bytes':17357,
 'sha256':'4db667e2036cfcfee95f48ee3a58ed7f930cd0807402433afc7ad220da83fc7d'}}
 for key, row in fixed.items():
  need(proof[key] == row, 'actual06 original recovery provenance differs: '+key)
  original_from(bundle, row)
 recovery = strict(original_from(bundle, proof['recovery_result']))
 need(recovery['schema'] == 'hepta.native-guard.attempt06-recovery-result.v1'
 and recovery['state'] == 'ORIGINAL_FAILED_COMPONENT_NORMAL_TAIL_CLOSED_AND_PUBLISHED'
 and recovery['source'] == proof['recovery_source']
 and recovery['original_root_failure'] == proof['original_root_failure']
 and recovery['recovery_intent'] == proof['recovery_intent']
 and recovery['root_result'] == root and recovery['closure'] == closure_copy
 and recovery['boundary'] == boundary_copy and recovery['previous'] == proof['previous']
 and recovery['malformed_original_preserved'] is True
 and recovery['original_sender_wait_fabricated'] is False
 and recovery['original_lease_expiry_unchanged'] is True
 and all(recovery[key] is False for key in ('component_qualified','business_qualified',
 'new_nonce','new_send','new_fixture','new_launch','automatic_retry'))
 and type(recovery['model_requests']) is int and recovery['model_requests'] == 0,
 'actual06 recovery provenance was dropped, replayed or upgraded')
 return proof
def property_parent_proof_spec(attempt):
 """Exact retained host provenance; it does not read or admit a new case."""
 need(attempt in ('attempt08', 'attempt07'), 'only the two fixed R7 property parents exist')
 need(isinstance(PROPERTY_PARENT_HOST_ORIGINALS, dict)
 and set(PROPERTY_PARENT_HOST_ORIGINALS) == {'attempt08','attempt07'},
 'actual R7 property-parent host originals are not reviewed')
 return strict(encode(PROPERTY_PARENT_HOST_ORIGINALS[attempt]))
def validate_property_parent_ancestors(bundle, proofs, state, boundaries, late):
 """Recheck actual08/07 with their original R7 package, reader and policy."""
 need(isinstance(proofs, list) and len(proofs) == 2
 and isinstance(boundaries, list) and len(boundaries) == 2,
 'the two fixed property-parent proofs must appear latest first')
 reviewed = late.reviewed_property_parent_ancestors()
 old_reader = late.property_parent_reader()
 for index, (attempt, proof, boundary) in enumerate(zip(
 ('attempt08','attempt07'), proofs, boundaries)):
  spec = property_parent_proof_spec(attempt)
  need(isinstance(proof, dict)
  and set(proof) == set(spec) | {'schema','attempt','boundary'}
  and proof['schema'] == 'hepta.r10.fixed-property-parent-component-ancestor.v1'
  and proof['attempt'] == attempt
  and proof['boundary'] == reviewed[index]['boundary']
  and all(proof[key] == row for key,row in spec.items()),
  'fixed property-parent host proof fields or generation differ')
  originals = {key:original_from(bundle,row) for key,row in spec.items()}
  result = strict(originals['root_result'])
  canonical = old_reader.C.encoded(boundary)
  need(late.is_property_parent_ancestor(boundary)
  and descriptor(canonical) == {k:reviewed[index]['boundary'][k]
  for k in ('bytes','sha256')}
  and boundary['nonce'] == late.PROPERTY_PARENT_NONCES[index]
  and boundary['package_sha256'] == late.PROPERTY_PARENT_PACKAGE_SHA256
  and boundary['combination_sha256'] == late.PROPERTY_PARENT_COMBINATION_SHA256
  and boundary['publisher_source_sha256'] == late.PROPERTY_PARENT_READER_SHA256
  and boundary['component_qualified'] is False
  and boundary['native_status'] == 'provider_failed'
  and type(boundary['actual_native_calls']) is int
  and boundary['actual_native_calls'] == late.PROPERTY_PARENT_CALL_COUNTS[index],
  'retained R7 failure was changed or credited to the new generation')
  need(boundary['prior_boundary'] == (reviewed[1]['boundary'] if index == 0
  else late.reviewed_environment_parent_ancestor()['boundary']),
  'fixed actual08-to-07-to-06 suffix is not continuous')
  manifest = strict(originals['package_manifest'])
  need(descriptor(originals['package_manifest']) == {'bytes':13446,
  'sha256':late.PROPERTY_PARENT_PACKAGE_SHA256}
  and manifest['schema'] == 'hepta.native-guard.adapter-package.v1'
  and manifest['state'] == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED'
  and len(manifest['files']) == 31,
  'actual08/07 must retain the exact original 31-file R7 package')
  pins = {row['path']:row for row in manifest['files']}
  need(len(pins) == 31, 'historical R7 manifest duplicates a member')
  for name,size,digest in (
  ('source/late_boundary.py',62434,late.PROPERTY_PARENT_READER_SHA256),
  ('source/component_common.py',19138,late.PROPERTY_PARENT_COMMON_SHA256),
  ('source/close_component.py',99120,late.PROPERTY_PARENT_CLOSURE_SHA256)):
   need(pins[name] == {'path':name,'bytes':size,'sha256':digest},
   'historical R7 executed source differs')
  combo = strict(originals['combination'])
  need(sha(originals['combination']) == late.PROPERTY_PARENT_COMBINATION_SHA256
  and combo['live_policy_sha256'] == late.PROPERTY_PARENT_POLICY_SHA256
  and combo['schema'] == 'hepta.native-guard.component-combination.v150.r10.1',
  'historical R7 combination must use its old adopted policy')
  need(result['late_boundary'] == reviewed[index]['boundary']
  and result['scope'] == boundary['scope']
  and result['state'] == 'ORIGINAL_COMPONENT_CLOSED_AND_LATE_BOUNDARY_PUBLISHED'
  and result['component_qualified'] is False and result['native_status'] == 'provider_failed'
  and result['automatic_retry'] is False and result['business_qualified'] is False
  and type(result['model_requests']) is int and result['model_requests'] == 0
  and result['four_role_qualification'] is False,
  'actual R7 Root result changed its terminal or qualification')
  home = Path(spec['root_result']['path']).parent
  closure_copy = {'path':str(home/'CLOSURE.json'),
  **{k:reviewed[index]['closure'][k] for k in ('bytes','sha256')}}
  boundary_copy = {'path':str(home/'LATE-BOUNDARY.original.json'),
  **{k:reviewed[index]['boundary'][k] for k in ('bytes','sha256')}}
  previous = strict(originals['previous'])
  need(previous['identity'] == boundary['scope']
  and previous['late_boundary'] == reviewed[index]['boundary']
  and previous['closed_component'] == closure_copy
  and result['previous'] == spec['previous']
  and previous['component_qualified'] is False
  and previous['terminal']['status'] == 'provider_failed'
  and previous['known_all_dispatched_tools_confirmed_terminal'] is True
  and previous['complete_business_success'] is False
  and previous['automatic_replay'] is False and HASH.fullmatch(previous['request_sha256']),
  'actual R7 previous input changed its original native scope')
  steps = [row for row in result['steps'] if row.get('phase') == 'phone-late-publish']
  need(len(steps) == 1 and steps[0]['state'] == 'ORIGINAL_HOST_CHILD_JOINED'
  and type(steps[0]['returncode']) is int and steps[0]['returncode'] == 0
  and steps[0]['automatic_retry'] is False
  and steps[0]['stdout'] == spec['publication_operation']
  and steps[0]['stderr'] == spec['publication_stderr'],
  'actual R7 publication terminal or original stream differs')
  operation = strict(originals['publication_operation'])
  need(originals['publication_stderr'] == b''
  and type(operation['actor_rc']) is int and operation['actor_rc'] == 0
  and type(operation['wrapper']['phone']['rc']) is int
  and operation['wrapper']['phone']['rc'] == 0,
  'actual R7 publication actor/phone did not both succeed')
  text = operation['wrapper']['phone']['stdout']
  need(isinstance(text,str), 'actual R7 publication stdout is absent')
  published = strict(text.encode('utf-8'))
  need(published == {'schema':'hepta.native-guard.boundary-publish-result.v1',
  'state':'CREATE_ONLY_CLOSED_LATE_BOUNDARY_PUBLISHED',
  'boundary':reviewed[index]['boundary'], 'old_retirement_current_equality_claimed':False,
  'original_retirement_rewritten':False, 'phone_tool_calls':0,
  'model_requests':0, 'signals':0, 'automatic_retry':False},
  'actual R7 original publication named another boundary')
  recovery = strict(originals['recovery_result'])
  need(recovery['schema'] == 'hepta.native-guard.'+attempt+'-recovery-result.v1'
  and recovery['state'] == 'ORIGINAL_FAILED_COMPONENT_NORMAL_TAIL_CLOSED_AND_PUBLISHED'
  and recovery['source'] == spec['recovery_source']
  and recovery['root_result'] == spec['root_result']
  and recovery['closure'] == closure_copy and recovery['boundary'] == boundary_copy
  and recovery['previous'] == spec['previous']
  and recovery['recovery_intent'] == spec['recovery_intent']
  and recovery['original_root_failure'] == spec['original_root_failure']
  and recovery['original_sender_wait_fabricated'] is False
  and recovery['original_lease_expiry_unchanged'] is True
  and all(recovery[key] is False for key in ('component_qualified','business_qualified',
  'new_nonce','new_send','new_fixture','new_launch','automatic_retry'))
  and type(recovery['model_requests']) is int and recovery['model_requests'] == 0,
  'actual R7 recovery provenance was dropped, replayed or upgraded')
  if attempt == 'attempt08':
   need(recovery['original_continuation_failure'] == spec['original_continuation_failure']
   and recovery['original_capture_failure_observation'] == spec['original_capture_failure_observation']
   and recovery['original_launch_timeout_and_continuation_failure_preserved'] is True
   and type(recovery['original_setup_attempt_count']) is int
   and recovery['original_setup_attempt_count'] == 1
   and type(recovery['original_capture_call_count']) is int
   and recovery['original_capture_call_count'] == 1,
   'actual08 launch timeout, one setup or failed capture provenance differs')
  else:
   need(recovery['original_setup_wait_failure_and_unconsumed_plan_preserved'] is True,
   'actual07 setup wait failure provenance was discarded')
  old_reader.boundary_from_original(canonical,
  original_descriptor=reviewed[index]['boundary'],
  combination_sha256=late.PROPERTY_PARENT_COMBINATION_SHA256,
  package_sha256=late.PROPERTY_PARENT_PACKAGE_SHA256)
 return proofs
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
def verify_shared_runtime_originals(manifest_raw, files, reviewed_production):
 """Pure closed shared17 byte verification before loading any runtime source."""
 need(type(manifest_raw) is bytes and 0 < len(manifest_raw) <= 65536
 and sha(manifest_raw) == SHARED_MATERIALS_SHA,
 'the fixed complete shared material manifest is required')
 manifest = strict(manifest_raw)
 need(type(reviewed_production) is dict and len(reviewed_production) == 15
 and all(type(name) is str and Path(name).name == name and name.endswith('.py')
 for name in reviewed_production), 'exact reviewed production names required')
 expected = {'provider/source/' + name for name in reviewed_production}
 expected.update({'local-config-r10-r1.json', 'PHONE-SERVICE-INPUTS-v150-r10-r1.json'})
 need(type(manifest) is dict
 and manifest['schema'] == 'hepta.r10.shared-production-materials.v1'
 and type(manifest['files']) is list and len(manifest['files']) == 17
 and type(files) is dict and set(files) == expected,
 'all seventeen exact shared originals are required before runtime loading')
 pins = {}
 for row in manifest['files']:
  need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
  and type(row['path']) is str and row['path'] in expected
  and row['path'] not in pins and type(row['bytes']) is int
  and 0 < row['bytes'] <= MAX_ORIGINAL
  and type(row['sha256']) is str and HASH.fullmatch(row['sha256']),
  'closed shared material manifest member differs')
  pins[row['path']] = row
 need(set(pins) == expected, 'shared material manifest path set differs')
 for name, raw in files.items():
  need(type(raw) is bytes and descriptor(raw) == {k: pins[name][k] for k in ('bytes', 'sha256')},
  'complete shared original bytes or hash differ')
  if name.startswith('provider/source/'):
   need(pins[name]['sha256'] == reviewed_production[Path(name).name],
   'shared production original differs from the runtime reviewed source pin')
 return manifest
def shared_runtime_originals(bundle, value, source):
 manifest_raw = original_from(bundle, value['component_shared_material_manifest'])
 rows = value['component_shared_material_files']
 need(type(rows) is list and len(rows) == 17, 'exact shared17 host-copy descriptors required')
 files = {}
 for row in rows:
  need(type(row) is dict and set(row) == {'name', 'copy'}
  and type(row['name']) is str and row['name'] not in files,
  'unique named shared material host copies required')
  files[row['name']] = original_from(bundle, row['copy'])
 reviewed = strict(source['reference/REVIEWED-PRODUCTION-PINS.json'])
 verify_shared_runtime_originals(manifest_raw, files, reviewed)
 return files
EPOCH_COMPONENT_VERIFY_SECONDS = 150
EPOCH_PUBLICATION_SOURCE_AUTHORITY = None
def epoch_component_budget():
 started = time.monotonic()
 def check():
  need(time.monotonic() - started < EPOCH_COMPONENT_VERIFY_SECONDS,
  'complete component evidence verification deadline exceeded')
 check()
 return check
def epoch_publication_context(bundle, value, common, late, action_module, *, budget_check):
 """Read one explicit host dependency closure from the precharged raw pool."""
 need(callable(budget_check), 'one enclosing component verification budget is required')
 budget_check()
 need(type(EPOCH_PUBLICATION_SOURCE_AUTHORITY) is dict
 and set(EPOCH_PUBLICATION_SOURCE_AUTHORITY)=={
 'root_source_manifest','root_coordinator','root_bridge','root_reference','actor','sdk'},
 'source-frozen outer publication authority remains unbound')
 rows = value['epoch_publication_originals']
 need(type(rows) is list and 1 <= len(rows) <= 4096,
 'complete bounded publication host original list required')
 declared = {}
 for row in rows:
  budget_check(); file_descriptor(row)
  need(row['path'] not in declared, 'publication host original paths repeat')
  declared[row['path']] = row
 need(list(declared) == sorted(declared), 'publication host original list must use canonical path order')
 used = {}; fetched = {}
 def get(row):
  budget_check(); file_descriptor(row)
  need(row['path'] in declared and encode(row) == encode(declared[row['path']]),
  'publication dependency is absent from the one explicit precharged original pool')
  if row['path'] not in fetched:
   fetched[row['path']] = original_from(bundle, row)
  used[row['path']] = row
  budget_check()
  return fetched[row['path']]
 packet_original = value['epoch_publication_inputs']
 packet_raw = get(packet_original)
 parser = getattr(common, 'publication_inputs_from_original', None)
 need(action_module is sys.modules.get('component_snapshot')
 and getattr(action_module,'__actual_context__',None) == getattr(common,'__actual_context__',None)
 and getattr(action_module,'__reviewed_package_manifest_raw__',None)
 == getattr(common,'__reviewed_package_manifest_raw__',None)
 and type(getattr(action_module,'__reviewed_package_manifest_raw__',None)) is bytes
 and sha(action_module.__reviewed_package_manifest_raw__) == PACKAGE_SHA
 and getattr(action_module,'__reviewed_package_sources__',None)
 is getattr(common,'__reviewed_package_sources__',None)
 and getattr(action_module,'__reviewed_source_sha256__',None)
 == sha(common.__reviewed_package_sources__['source/component_snapshot.py']),
 'publication action gate must come from the exact already-admitted snapshot member and context')
 action_gate = getattr(action_module,'verify_publication_action_receipts',None)
 action_sources = getattr(action_module,'publication_action_needed_source_descriptors',None)
 need(callable(parser) and callable(action_gate) and callable(action_sources),
 'the final actual publication carrier and source/action gates are not installed')
 parsed = parser(packet_raw, original_from=get)
 need(type(parsed) is dict and set(parsed) == {
 'manifest', 'originals_by_path', 'publication_observation', 'source_action_originals',
 'source_action_original_bytes', 'action_verification_required',
 'source_or_action_authority_verified_here'}
 and parsed['action_verification_required'] is True
 and parsed['source_or_action_authority_verified_here'] is False,
 'the carrier parser cannot substitute for actual action verification')
 needed_sources = action_sources(source_authority=EPOCH_PUBLICATION_SOURCE_AUTHORITY)
 need(type(needed_sources) is list and needed_sources,
 'the publication action source authority remains unbound')
 action_used = {}
 def action_get(row):
  raw = get(row)
  action_used[row['path']] = row
  return raw
 action = action_gate(packet_original, parsed,
 source_authority=EPOCH_PUBLICATION_SOURCE_AUTHORITY,
 original_from=action_get, budget_check=budget_check)
 need(type(action) is dict and set(action) == {'schema','state','packet_original',
 'needed_source_descriptors','used_original_descriptors','proof'}
 and action['schema'] == 'hepta.native-guard.epoch-publication-action-verification.v1'
 and action['state'] == 'OWNED_HOST_AND_ACTUAL_PHONE_PUBLICATION_READ_VERIFIED'
 and encode(action['packet_original']) == encode(packet_original)
 and encode(action['needed_source_descriptors']) == encode(needed_sources)
 and encode(action['used_original_descriptors']) == encode(
 [action_used[path] for path in sorted(action_used)]),
 'publication action proof does not reproduce its actual original reads and trusted sources')
 for source in needed_sources:
  file_descriptor(source)
  need(source['path'] in action_used and encode(source) == encode(action_used[source['path']]),
  'a required publication source bypassed the one enclosing original lookup')
 need(set(used) == set(declared), 'unused or hidden publication host dependency')
 budget_check()
 verified = late.verify_epoch_publication_inputs(parsed['manifest'], parsed['originals_by_path'])
 need(type(verified) is dict and set(verified) == {
 'legacy','active','registry','anchor','failure_inputs','retained_roots','control_roots'},
 'postpublication replay must retain both complete native domains')
 budget_check()
 return {'manifest':parsed['manifest'], 'originals_by_path':parsed['originals_by_path'],
 'verified':verified, 'observation':parsed['publication_observation'],
 'action':action, 'host_originals':[used[path] for path in sorted(used)]}
def epoch_phone_body(publication, row, common, *, budget_check):
 budget_check(); common._ep_pin(row, original=True)
 matches = [entry for entry in publication['manifest']['files'] if entry['path'] == row['path']]
 need(len(matches) == 1 and encode(matches[0]) == encode(row),
 'exact immutable phone original is missing or changed in the postpublication manifest')
 raw = publication['originals_by_path'].get(row['path'])
 need(type(raw) is bytes and descriptor(raw) == {k:row[k] for k in ('bytes','sha256')},
 'postpublication body differs from its actual complete phone identity')
 budget_check()
 return raw
def epoch_retained_failed_native_records(bundle, publication, common, *, budget_check):
 """Check the complete extra failed-native domain without extending the chain."""
 budget_check();failure=publication['verified']['failure_inputs']
 need(type(failure) is dict and set(failure)=={'footprint','host_origins','carriers',
 'retained_failed_fixture_absences','unresolved_namespace_members','retained_failed_native_branches'},
 'the complete explicit failure-input domain is required')
 rows=failure['retained_failed_native_branches']
 need(type(rows) is list and len(rows)==1, 'the fixed failed-native branch cannot be omitted or flattened')
 row=rows[0]
 fields={'schema','label','nonce','boot_id','originals','prior_boundary','scope',
 'component_role_identities','history_reconciliation','current_observation',
 'actual_native_calls','native_status','canonical_chain_member','active_slot_count_contribution',
 'nonce_reuse_forbidden','component_qualified','business_qualified'}
 need(type(row) is dict and set(row)==fields
 and row['schema']=='hepta.native-guard.retained-failed-native-branch.v1'
 and row['label']=='root-r10-neg01-7c907661-diag01'
 and row['nonce']=='6077fc8f045572edc4acfb13ed7e09a8' and row['boot_id']==BOOT
 and type(row['actual_native_calls']) is int and row['actual_native_calls']==1
 and row['native_status']=='provider_failed' and row['canonical_chain_member'] is False
 and type(row['active_slot_count_contribution']) is int and row['active_slot_count_contribution']==0
 and row['nonce_reuse_forbidden'] is True and row['component_qualified'] is False
 and row['business_qualified'] is False, 'fixed failed6077 identity or classification differs')
 need(type(row['scope']) is dict and set(row['scope'])==set(common.SCOPE)
 and all(type(value) is str and value for value in row['scope'].values()),
 'complete original failed-native scope required')
 roles=row['component_role_identities']
 need(type(roles) is dict and set(roles)=={'provider','sidecar','supervisor'}
 and all(type(role) is list and len(role)==4
 and all(type(n) is int and n>0 for n in role) for role in roles.values())
 and len({tuple(role) for role in roles.values()})==3,
 'three distinct complete failed-native role generations required')
 originals=row['originals']
 need(type(originals) is dict and set(originals)=={
 'lease','runtime','combination','boundary','inventory','closure','publish_intent'},
 'all seven original failed-native inputs required')
 raw={name:epoch_phone_body(publication,item,common,budget_check=budget_check)
 for name,item in originals.items()}
 prior=publication['verified']['legacy']['native_chain'][0]['boundary']
 need(encode(row['prior_boundary'])==encode(prior), 'failed6077 changed its separate fixed902 predecessor')
 epoch_phone_body(publication,row['prior_boundary'],common,budget_check=budget_check)
 boundary=strict(raw['boundary']);closure=strict(raw['closure'])
 need(boundary['nonce']==row['nonce'] and boundary['boot_id']==BOOT
 and encode(boundary['scope'])==encode(row['scope'])
 and encode(boundary['component_role_identities'])==encode(roles)
 and encode(boundary['prior_boundary'])==encode(prior)
 and boundary['native_status']=='provider_failed'
 and boundary['component_qualified'] is False and closure['component_qualified'] is False,
 'failed-native outer record differs from its actual original boundary and closure')
 host_rows={item['path']:item for item in publication['host_originals']}
 for name in ('history_reconciliation','current_observation'):
  pair=row[name];need(type(pair) is dict and set(pair)=={'origin','carrier'},
  'separate host original and actual phone carrier required')
  origin=pair['origin'];file_descriptor(origin)
  need(origin['path'] in host_rows and encode(host_rows[origin['path']])==encode(origin),
  'failed-native authority original bypassed the declared complete host pool')
  host_raw=original_from(bundle,origin)
  carrier_raw=epoch_phone_body(publication,pair['carrier'],common,budget_check=budget_check)
  need(host_raw==carrier_raw, 'failed-native authority host/carrier bytes differ')
 budget_check();return rows
def epoch_saved_capture(publication, boundary, common, late, *, budget_check):
 """Replay the saved preclose view without rewriting the later registry."""
 epoch = boundary['epoch']
 def body(row):
  return epoch_phone_body(publication, row, common, budget_check=budget_check)
 lease_raw = body(epoch['lease']); lease = strict(lease_raw)
 capture_raw = body(epoch['capture']); capture = strict(capture_raw)
 manifest_raw = body(epoch['capture_manifest']); manifest = strict(manifest_raw)
 legacy_raw = body(epoch['legacy_semantic']); phone_legacy = strict(legacy_raw)
 active_raw = body(epoch['active_semantic']); phone_active = strict(active_raw)
 observation_raw = body(epoch['capture_epoch_observation'])
 need(type(capture) is dict and capture['schema'] == 'hepta.native-guard.epoch-original-capture.v1'
 and capture['state'] == 'ORIGINAL_BYTES_CAPTURED_FOR_INDEPENDENT_AUDIT'
 and capture['lease_sha256'] == sha(lease_raw)
 and capture['nonce'] == boundary['nonce'] == lease['nonce']
 and capture['case_id'] == boundary['case_id'] == lease['case_id']
 and encode(capture['scope']) == encode(boundary['scope'])
 and capture['boot_id'] == boundary['boot_id'] == BOOT
 and capture['package_sha256'] == boundary['package_sha256'] == PACKAGE_SHA
 and capture['combination_sha256'] == boundary['combination_sha256'] == CURRENT_COMBINATION_SHA,
 'the saved capture is not the original capture for this native boundary')
 need(type(manifest) is dict and set(manifest) == {'schema','files','directories'}
 and manifest['schema'] == 'hepta.native-guard.epoch-capture-inputs.v1'
 and common.encoded(manifest) == manifest_raw,
 'the actual saved preclose manifest is not canonical and complete')
 raw_by_path = {}; expected_capture_names = {'epoch-inputs/MANIFEST.json',
 'epoch-inputs/LEGACY-SEMANTIC.json',
 'epoch-inputs/ACTIVE-SEMANTIC.json'}
 for row in manifest['files']:
  budget_check(); common._ep_pin(row, original=True)
  need(row['path'] not in raw_by_path, 'saved preclose phone originals repeat')
  raw = body(row)
  name = 'epoch-inputs/files/'+sha(row['path'].encode('utf-8'))+'.original'
  need(name in capture['files'] and name not in expected_capture_names,
  'saved capture omitted or repeated a complete protocol original')
  retained = capture['files'][name]
  need(retained['kind'] == 'original_file_bytes'
  and retained['source_path'] == row['path']
  and encode(retained['source_metadata']) == encode(row['metadata'])
  and {k:retained[k] for k in ('bytes','sha256')} == descriptor(raw),
  'saved preclose file bytes or original phone metadata differ')
  expected_capture_names.add(name); raw_by_path[row['path']] = raw
 need({name for name in capture['files'] if name.startswith('epoch-inputs/')} == expected_capture_names,
 'saved capture has an omitted or unaccounted epoch input')
 for name, raw, key in (
 ('epoch-inputs/MANIFEST.json', manifest_raw, 'inputs_manifest'),
 ('epoch-inputs/LEGACY-SEMANTIC.json', legacy_raw, 'legacy_semantic'),
 ('epoch-inputs/ACTIVE-SEMANTIC.json', active_raw, 'active_semantic'),
 ('after/EPOCH-INVENTORY-OBSERVATION.json', observation_raw, 'inventory_observation')):
  row = capture['files'][name]
  need(row['kind'] == 'derived_read_observation' and row['source_path'] is None
  and row['source_metadata'] is None
  and {k:row[k] for k in ('bytes','sha256')} == descriptor(raw)
  and capture['epoch'][key] == descriptor(raw),
  'saved derived capture output was relabeled as an earlier input or changed bytes')
 need(capture['epoch']['native_chain_domains_flattened'] is False
 and capture['epoch']['case_or_lease_authorized'] is False,
 'capture cannot flatten domains or grant case authority')
 verified = late.verify_epoch_capture_inputs(lease, manifest, raw_by_path)
 need(encode(verified['legacy']) == encode(publication['verified']['legacy'])
 and verified['registry']['mode'] == 'preclose'
 and verified['active']['current_ordinal'] == epoch['ordinal']
 and encode(verified['active']['current_identity']) == encode(epoch['identity'])
 and encode(verified['active']['current_scope_binding']) == encode(epoch['scope_binding']),
 'saved capture replay is not the one actual uncommitted ordinal')
 records = publication['verified']['active']['closed_native_records']
 need(encode(verified['active']['closed_native_records']) == encode(records[:epoch['ordinal']-1]),
 'preclose active history differs from the complete actual terminal prefix')
 need(type(phone_legacy) is dict and set(phone_legacy) == {
 'schema','semantic','actual_context','source_observation'}
 and phone_legacy['schema'] == 'hepta.native-guard.epoch-legacy-semantic-proof.v1'
 and phone_legacy['actual_context'] == 'phone',
 'captured actual phone legacy proof is absent or relabeled')
 checked = late.verify_epoch_phone_legacy_source_observation(
 phone_legacy['source_observation'], manifest, raw_by_path, verified)
 need(encode(checked) == encode(phone_legacy['source_observation']),
 'phone legacy source observation does not reproduce its actual fixed source authority')
 host_legacy = late.epoch_verified_legacy_context(
 lease, manifest, raw_by_path, verified, budget_check=budget_check)
 need(type(host_legacy) is dict and set(host_legacy) == set(phone_legacy)
 and host_legacy['schema'] == phone_legacy['schema']
 and host_legacy['actual_context'] == common.epoch_actual_context(common.__dict__)
 and encode(host_legacy['semantic']) == encode(phone_legacy['semantic']),
 'actual consumer context and captured phone legacy semantics differ')
 need(type(phone_active) is dict and set(phone_active) == {
 'schema','semantic','actual_context','source_observation'}
 and phone_active['schema'] == 'hepta.native-guard.epoch-active-semantic-proof.v1'
 and phone_active['actual_context'] == 'phone',
 'the original capture omitted its actual phone active semantic proof')
 phone_active_gate = getattr(late, 'verify_epoch_phone_active_source_observation', None)
 need(callable(phone_active_gate), 'mandatory actual phone active source-binding gate is not installed')
 checked_active = phone_active_gate(phone_active['source_observation'], manifest, raw_by_path, verified)
 need(encode(checked_active) == encode(phone_active['source_observation']),
 'phone active source binding differs from the complete actual source originals')
 active_gate = getattr(late, 'epoch_verified_active_context', None)
 need(callable(active_gate), 'mandatory independent active semantic gate is not installed')
 active = active_gate(lease, manifest, raw_by_path, verified, budget_check=budget_check)
 need(type(active) is dict and set(active) == {'schema','actual_context','source_observation','semantic'}
 and active['schema'] == 'hepta.native-guard.epoch-active-semantic-proof.v1'
 and active['actual_context'] == common.epoch_actual_context(common.__dict__),
 'mandatory active proof schema or actual consumer context differs')
 need(encode(active['semantic']) == encode(phone_active['semantic']),
 'actual consumer and captured phone active semantics differ')
 semantic = active['semantic']; source_observation = active['source_observation']
 semantic_fields = getattr(common, 'EPOCH_ACTIVE_SEMANTIC_FIELDS', None)
 source_fields = getattr(common, 'EPOCH_ACTIVE_SOURCE_OBSERVATION_FIELDS', None)
 need(type(semantic_fields) is tuple and len(semantic_fields) == 29
 and type(source_fields) is tuple and len(source_fields) == 6
 and type(semantic) is dict and set(semantic) == set(semantic_fields)
 and type(source_observation) is dict and set(source_observation) == set(source_fields),
 'final exact active semantic and reviewed-source contracts are not installed')
 need(semantic['schema'] == 'hepta.native-guard.epoch-active-semantics.v1'
 and semantic['epoch_id'] == epoch['epoch_id'] and semantic['boot_id'] == BOOT
 and type(semantic['current_ordinal']) is int and semantic['current_ordinal'] == epoch['ordinal']
 and encode(semantic['epoch_anchor']) == encode(epoch['anchor'])
 and encode(semantic['current_identity']) == encode(epoch['identity'])
 and encode(semantic['current_scope_binding']) == encode(epoch['scope_binding'])
 and encode(semantic['current_generation']) == encode(epoch['generation'])
 and encode(semantic['closed_records']) == encode(records[:epoch['ordinal']-1])
 and type(semantic['previous_native_components']) is int
 and semantic['previous_native_components'] == epoch['ordinal']-1
 and type(semantic['consumed_slots_before_current']) is int
 and semantic['consumed_slots_before_current'] == epoch['ordinal']-1
 and encode(semantic['previous_active_boundary']) == encode(epoch['previous_active_boundary'])
 and encode(semantic['predecessor_terminal']) == encode(epoch['predecessor_terminal'])
 and encode(semantic['preservation_inventory_original']) == encode(epoch['preservation_inventory'])
 and semantic['all_previous_native_records_verified'] is True
 and all(semantic[key] is False for key in ('legacy_domains_flattened','legacy_semantics_verified_here',
 'live_inventory_verified_here','role_absence_verified_here','endpoints_verified_here',
 'component_qualified','business_qualified','native_boundary_created')),
 'active semantic proof changed the actual prefix, predecessor or authority boundary')
 need(source_observation['schema'] == 'hepta.native-guard.epoch-active-source-binding.v1'
 and source_observation['context'] == active['actual_context']
 and encode(source_observation['current_generation']) == encode(epoch['generation'])
 and source_observation['physical_full9_observation_claimed'] is False,
 'reviewed active module bindings cannot become fictional physical source observations')
 preservation = late.epoch_capture_preservation_context(
 lease, verified, manifest=manifest, originals_by_path=raw_by_path)
 need(encode(preservation['preservation_inventory_original']) == encode(epoch['preservation_inventory'])
 and encode(preservation['lease_prior_boundary']) == encode(lease['prior_boundary'])
 and preservation['closed_components'] == epoch['ordinal']-1
 and preservation['consumed_slots_before_current'] == epoch['ordinal']-1,
 'saved capture preservation predecessor does not match its exact active ordinal')
 budget_check()
 return {'lease':lease, 'capture':capture, 'manifest':manifest, 'originals_by_path':raw_by_path,
 'verified':verified, 'phone_legacy':phone_legacy, 'host_legacy':host_legacy,
 'active_semantic':active, 'phone_active':phone_active, 'preservation':preservation}
def epoch_publish_result(raw, boundary, record, common):
 value = strict(raw)
 need(type(value) is dict and set(value) == {'schema','state','epoch_id','ordinal','nonce',
 'case_id','boundary','inventory','closure','terminal','initialization','generation',
 'scope_binding','predecessor_terminal','component_qualified','business_qualified',
 'native_boundary_created','automatic_replay'}, 'complete actual epoch publication result required')
 expected = {'schema':'hepta.native-guard.epoch-boundary-publish-result.v1',
 'state':'ORIGINAL_EPOCH_NATIVE_BOUNDARY_AND_TERMINAL_PUBLISHED',
 'epoch_id':boundary['epoch']['epoch_id'], 'ordinal':record['ordinal'],
 'nonce':boundary['nonce'], 'case_id':boundary['case_id'],
 'boundary':record['boundary'], 'inventory':record['inventory'], 'closure':record['closure'],
 'terminal':record['terminal'], 'initialization':boundary['epoch']['initialization'],
 'generation':record['generation'], 'scope_binding':record['scope_binding'],
 'predecessor_terminal':boundary['epoch']['predecessor_terminal'],
 'component_qualified':boundary['component_qualified'], 'business_qualified':False,
 'native_boundary_created':True, 'automatic_replay':False}
 need(encode(value) == encode(expected),
 'actual publication result differs from its closed boundary and final COMMIT')
 return value
def validate_component(bundle, value, *, actual_context, budget_check):
 actual_context = checked_actual_context(actual_context)
 need(callable(budget_check), 'one enclosing verification budget required')
 budget_check()
 decoded_bundle_budget(bundle)
 need(isinstance(PACKAGE_SHA,str) and HASH.fullmatch(PACKAGE_SHA)
 and type(PACKAGE_FILE_COUNT) is int and 24<PACKAGE_FILE_COUNT<=32
 and isinstance(CURRENT_COMBINATION_SHA,str) and HASH.fullmatch(CURRENT_COMBINATION_SHA),
 'current policy component runtime has not been frozen and reviewed')
 need(isinstance(value, dict) and set(value) == COMPONENT_FIELDS
 and value['schema'] == 'hepta.r10.component-boundary-inputs.v8'
 and value['release_id'] == RELEASE and value['boot_id'] == BOOT,
 'explicit component input schema/identity differs')
 manifest_raw = original_from(bundle, value['component_package_manifest'])
 need(sha(manifest_raw) == PACKAGE_SHA, 'component package is not the reviewed frozen runtime')
 manifest = strict(manifest_raw)
 need(manifest['schema'] == 'hepta.native-guard.adapter-package.v1'
 and manifest['state'] == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED',
 'component package schema differs')
 files = value['component_package_files']
 need(isinstance(files, list) and len(files) == len(manifest['files']) == PACKAGE_FILE_COUNT,
 'complete frozen component package required')
 source = {}
 pins = {row['path']: row for row in manifest['files']}
 for item in files:
  need(set(item) == {'name', 'copy'} and item['name'] in pins
  and item['name'] not in source, 'component package file set differs')
  raw = original_from(bundle, item['copy'])
  need(descriptor(raw) == {k: pins[item['name']][k] for k in ('bytes', 'sha256')},
  'component package original differs')
  source[item['name']] = raw
 need(set(source) == set(pins), 'component package omitted a file')
 combination_raw = original_from(bundle, value['component_combination'])
 need(sha(combination_raw)==CURRENT_COMBINATION_SHA,'current reviewed policy combination differs')
 shared_files = shared_runtime_originals(bundle, value, source)
 recipe_raw = original_from(bundle, _esi_recipe_match(value['source_recipe']))
 verify_epoch_runtime_increment(manifest_raw, source, combination_raw, shared_files, recipe_raw=recipe_raw)
 combination = strict(combination_raw)
 need(set(combination) == {'schema', 'state', 'source_seal', 'configuration',
 'service_inputs', 'production_files', 'artifacts', 'live_policy_sha256'}
 and combination.get('schema') == 'hepta.native-guard.component-combination.v150.r10.1'
 and combination.get('state') == 'REVIEWED_COMPONENT_BYTES_NOT_FOUR_ROLE_READY',
 'component combination is not an explicit component source set')
 reviewed_production = strict(source['reference/REVIEWED-PRODUCTION-PINS.json'])
 production = combination['production_files']
 need(len(reviewed_production) == len(production) == 15
 and len({row['path'] for row in production}) == 15
 and {row['path'] for row in production} == {'production/' + name for name in reviewed_production},
 'component combination omitted a reviewed production source')
 for row in production:
  name = Path(row['path']).name
  need(set(row) == {'path', 'bytes', 'sha256'}
  and type(row['bytes']) is int and 0 < row['bytes'] <= 262144
  and row['sha256'] == reviewed_production[name],
  'component combination production pin differs')
 need(set(combination['artifacts']) == {'client', 'sidecar', 'worker', 'screen_helper',
 'focus_helper', 'unicode_helper', 'busybox', 'python'}
 and isinstance(combination['live_policy_sha256'], str)
 and HASH.fullmatch(combination['live_policy_sha256']),
 'component combination artifact or explicit policy identity differs')
 copies = {}
 for item in value['originals']:
  need(set(item) == {'phone', 'copy'}, 'component original transport entry differs')
  phone = item['phone']; raw = original_from(bundle, item['copy'])
  need(phone['path'] not in copies and descriptor(raw) == {k: phone[k] for k in ('bytes', 'sha256')},
  'phone original duplicate or host copy differs')
  copies[phone['path']] = (phone, raw)
 state = {'actual_context': actual_context, 'package_sources': source,
 'package_manifest_raw': manifest_raw, 'component_input': value,
 'component_combination': combination, 'component_originals': copies,
 'shared_runtime_originals': shared_files, 'component_combination_raw': combination_raw,
 'epoch_source_recipe_raw': recipe_raw}
 used = set(); chain = []; legacy_chain = []; captures = []
 with component_modules(state, actual_context=state['actual_context']) as modules:
  late = modules['late_boundary']; common = modules['component_common']
  sidebranch = late.non_native_sidebranch()
  need(encode(value['non_native_sidebranch']) == encode(sidebranch['binding']),
  'component input omitted or changed the exact non-native attempt05 binding')
  publication = epoch_publication_context(bundle, value, common, late,
  modules['component_snapshot'], budget_check=budget_check)
  retained_failed = epoch_retained_failed_native_records(bundle,publication,common,
  budget_check=budget_check)
  verified = publication['verified']; active = verified['active']; legacy = verified['legacy']
  need(verified['registry']['mode'] == 'published'
  and type(active['closed_native_records']) is list
  and 1 <= len(active['closed_native_records']) <= 8
  and type(active['current_ordinal']) is int
  and active['current_ordinal'] == len(active['closed_native_records'])
  and len(active['consumed_reservations']) == active['current_ordinal']
  and active['current_identity'] is None and active['current_scope_binding'] is None,
  'every consumed active slot must have one actual native terminal before release')
  need(legacy['native_components'] == 6 and legacy['fixture_roots'] == 7
  and len(legacy['native_chain']) == 6
  and encode(legacy['retirement']) == encode(value['retirement']),
  'six fixed historical native failures and their separate fixture domain are mandatory')
  records = active['closed_native_records']
  need([record['ordinal'] for record in records] == list(range(1,len(records)+1))
  and encode(value['latest_boundary']) == encode(records[-1]['boundary']),
  'current head must be the last actual contiguous active native terminal')
  def body(row):
   budget_check(); common._ep_pin(row, original=True)
   need(row['path'] in copies and encode(copies[row['path']][0]) == encode(row),
   'exact boundary, closure, inventory or retirement host copy is absent')
   raw = epoch_phone_body(publication, row, common, budget_check=budget_check)
   need(copies[row['path']][1] == raw,
   'component host copy differs from the independently observed published original')
   used.add(row['path'])
   return raw
  for record in legacy['native_chain']:
   legacy_chain.append(tuple(strict(body(record[key]))
   for key in ('boundary','inventory','closure')))
  seen_nonce = set(); seen_scope = set()
  for boundary, _inventory, closure in legacy_chain:
   scope = tuple(boundary['scope'][field] for field in common.SCOPE)
   need(boundary['nonce'] not in seen_nonce and scope not in seen_scope
   and boundary['component_qualified'] is False
   and closure['component_qualified'] is False,
   'historical native failures repeat identity or claim current qualification')
   seen_nonce.add(boundary['nonce']); seen_scope.add(scope)
  need(sidebranch['binding']['nonce'] not in seen_nonce,
  'non-native historical identity repeats a native identity')
  seen_nonce.add(sidebranch['binding']['nonce'])
  fixed = common.epoch_binding_value()
  need(set(fixed['legacy_nonces']) == seen_nonce,
  'the complete permanently forbidden historical nonce domain differs')
  need(fixed['retained_failed_native_nonces']==['6077fc8f045572edc4acfb13ed7e09a8']
  and fixed['additional_retained_prelaunch_nonces']==['13ed8d3d16807322fb50923a8c1e8b42'],
  'the two additional permanently forbidden nonce domains are not source-bound')
  for failed in retained_failed:
   failed_scope=tuple(failed['scope'][field] for field in common.SCOPE)
   need(failed['nonce'] in fixed['retained_failed_native_nonces']
   and failed['nonce'] not in seen_nonce and failed_scope not in seen_scope,
   'the separate failed-native nonce and scope must join the permanent reuse denial')
   seen_nonce.add(failed['nonce']);seen_scope.add(failed_scope)
  prelaunch=set(fixed['failed_nonces'])|set(fixed['additional_retained_prelaunch_nonces'])
  need(len(fixed['failed_nonces'])==len(set(fixed['failed_nonces']))==3
  and len(prelaunch)==4 and not prelaunch.intersection(seen_nonce),
  'old failed-prelaunch3 and additional retained-prelaunch1 must remain distinct')
  seen_nonce.update(prelaunch)
  for record in reversed(records):
   budget_check()
   boundary_raw = body(record['boundary'])
   inventory_raw = body(record['inventory']); closure_raw = body(record['closure'])
   untrusted = strict(boundary_raw)
   need(untrusted['schema'] == 'hepta.native-guard.epoch-boundary.v1'
   and untrusted['epoch']['ordinal'] == record['ordinal'],
   'an active record cannot be substituted by an old flat boundary')
   capture = epoch_saved_capture(publication, untrusted, common, late,
   budget_check=budget_check)
   gate = getattr(late, 'closed_epoch_boundary_originals', None)
   need(callable(gate), 'independent epoch closure and final terminal gate is not installed')
   boundary, inventory, closure = gate(boundary_raw, inventory_raw, closure_raw,
   original_descriptor=record['boundary'],
   registry_originals={'manifest':publication['manifest'],
   'originals_by_path':publication['originals_by_path']},
   combination_sha256=CURRENT_COMBINATION_SHA, package_sha256=PACKAGE_SHA,
   budget_check=budget_check)
   need(encode(boundary) == encode(untrusted)
   and boundary['boot_id'] == BOOT
   and encode(boundary['retirement']) == encode(value['retirement'])
   and encode(boundary['inventory']) == encode(record['inventory'])
   and encode(boundary['closure']) == encode(record['closure'])
   and encode(boundary['epoch']['generation']) == encode(record['generation'])
   and encode(boundary['epoch']['identity']) == encode(record['identity'])
   and encode(boundary['epoch']['scope_binding']) == encode(record['scope_binding'])
   and boundary['package_sha256'] == PACKAGE_SHA
   and boundary['combination_sha256'] == CURRENT_COMBINATION_SHA
   and closure['closure_source_sha256'] == sha(source['source/close_component.py']),
   'active native closure, actual source generation or final terminal identity differs')
   scope = tuple(boundary['scope'][field] for field in common.SCOPE)
   need(boundary['nonce'] not in seen_nonce and scope not in seen_scope,
   'an active native record reuses an old, failed or concurrent identity')
   seen_nonce.add(boundary['nonce']); seen_scope.add(scope)
   expected_prior = legacy['native_chain'][0]['boundary'] if record['ordinal'] == 1 else records[record['ordinal']-2]['boundary']
   expected_terminal = None if record['ordinal'] == 1 else records[record['ordinal']-2]['terminal']
   expected_active_prior = None if record['ordinal'] == 1 else expected_prior
   need(encode(boundary['prior_boundary']) == encode(expected_prior)
   and encode(boundary['epoch']['previous_active_boundary']) == encode(expected_active_prior)
   and encode(boundary['epoch']['predecessor_terminal']) == encode(expected_terminal),
   'the independent active predecessor and legacy anchor domains are discontinuous')
   need(encode(boundary.get('non_native_sidebranch')) == encode(sidebranch['binding'])
   and encode(closure.get('non_native_sidebranch')) == encode(sidebranch['binding']),
   'active native closure changed its separate non-native preservation binding')
   late.preserve_non_native_private(inventory, sidebranch)
   need(set(legacy_chain[0][0]['roots']) <= set(boundary['roots']),
   'active native preservation omitted a historical cumulative root')
   chain.append((boundary,inventory,closure)); captures.append(capture)
  for later, earlier in zip(chain, chain[1:]):
   need(set(earlier[0]['roots']) <= set(later[0]['roots']),
   'an active boundary dropped an earlier active preservation root')
  property_parents = validate_property_parent_ancestors(
  bundle, value['property_parent_ancestors'], state,
  [row[0] for row in legacy_chain[1:3]], late)
  budget_check()
  environment_parent = validate_environment_parent_ancestor(
  bundle, value['environment_parent_ancestor'], state, legacy_chain[3][0], late)
  pre_policy = validate_pre_policy_ancestor(
  bundle, value['pre_policy_ancestor'], state, legacy_chain[4][0], late)
  budget_check()
  retirement = value['retirement']
  need(set(retirement) == {'proof','preflight','probe','bound_inputs','disabled_flag'},
  'all five original retirement identities are required')
  retired_raw = {key:body(row) for key,row in retirement.items()}
  retired = strict(retired_raw['proof']); before = strict(retired_raw['preflight'])
  bound = strict(retired_raw['bound_inputs'])
  need(retired['schema'] == 'hepta.r9-r2-retirement-observation.v1'
  and retired['state'] == 'ORIGINAL_FOUR_GROUPS_ABSENT_STATE_PRESERVED'
  and retired['boot_id'] == BOOT and retired['global_pending_clear'] is True
  and retired['server_lock_now_unheld'] is True and retired['old_claims_deleted'] is False
  and retired['old_task_terminal_rewritten'] is False and retired['automatic_replay'] is False,
  'actual original retirement is not closed')
  need(before['schema'] == 'hepta.r9-r2-retirement-preflight.v1'
  and before['state'] == 'READY_FOR_DISABLE_AND_ONE_SUPERVISOR_TERM'
  and before['groups'] == retired['original_role_identities']
  and before['preserved_state'] == retired['preserved_state']
  and bound['complete_current_accepted_case_union_verified'] is True
  and retired_raw['disabled_flag'] == b'', 'original retirement lineage differs')
  need(used == set(copies), 'unused or missing closed original in component boundary input')
  published = epoch_publish_result(original_from(bundle,value['publish_result']),
  chain[0][0], records[-1], common)
  roles = list(before['groups'].values()); component_roles = []
  for boundary, _inventory, _closure in legacy_chain + chain:
   component_roles.extend(boundary['component_role_identities'].values())
  component_roles.extend(sidebranch['binding']['component_role_identities'].values())
  for failed in retained_failed:
   component_roles.extend(failed['component_role_identities'].values())
  roles.extend(component_roles)
  need(len(retained_failed)==1 and len(roles) == 28 + 3*len(chain) and len(roles) <= 64
  and len({tuple(row) for row in roles}) == len(roles),
  'separate legacy and active role generations repeat or exceed the original bound')
  budget_check()
 state.update(chain=chain, legacy_chain=legacy_chain, epoch_captures=captures,
 epoch_publication=publication, epoch_published_result=published,
 retained_failed_native_branches=retained_failed,
 current_inventory=chain[0][1], retired=retired,
 retirement_sha256=retirement['proof']['sha256'], roles=roles,
 component_roles=component_roles, component_boundary_sha256=value['latest_boundary']['sha256'],
 pre_policy_ancestor=pre_policy, non_native_sidebranch=sidebranch['binding'],
 environment_parent_ancestor=environment_parent, property_parent_ancestors=property_parents,
 native_chain_domains_flattened=False, legacy_native_count=6,
 active_native_count=len(chain), semantic_verification_mode='actual_capture')
 return state
def validate_shared_materials(state, sources, config_raw, service_raw):
 """Bind the actual closed component to the final 17 computed byte strings."""
 combination = state['component_combination']
 need(isinstance(sources, dict) and len(sources) == 15
 and all(isinstance(raw, bytes) for raw in sources.values()),
 'exact final production byte set required')
 production = [dict(path='production/' + name, **descriptor(raw))
 for name, raw in sorted(sources.items())]
 config = strict(config_raw)
 need(combination['production_files'] == production
 and combination['configuration'] == descriptor(config_raw)
 and combination['service_inputs'] == descriptor(service_raw)
 and config['service_manifest_sha256'] == sha(service_raw),
 'closed component and final source/config/service bytes differ')
 source_seal = dict(schema='hepta.native-guard.component-source-seal.v150.r10.1',
 state='REVIEWED_COMPONENT_BYTES_NOT_FINAL_RELEASE', intended_module_release=RELEASE,
 configuration=descriptor(config_raw), phone_service_inputs_sha256=sha(service_raw),
 production_files=[dict(path='source/' + name, **descriptor(raw))
 for name, raw in sorted(sources.items())])
 with component_modules(state, actual_context=state['actual_context']) as modules:
  source_seal_raw = modules['component_common'].encoded(source_seal)
 need(combination['source_seal'] == descriptor(source_seal_raw)
 and combination['live_policy_sha256'] == state['runtime_policy']['sha256'],
 'closed component seal or explicitly adopted runtime policy differs')
 return {'production_source_count': 15, 'configuration': descriptor(config_raw),
 'service_inputs': descriptor(service_raw),
 'component_source_seal': descriptor(source_seal_raw)}
def external_artifact_bindings(state, sources, service_raw):
 """Bind eight component dependencies to the final service and source bytes.

    This is a pure comparison. Metadata comes from the explicitly closed
    component combination; runtime consumers independently re-read it. The
    Python and BusyBox pins are the already observed stock dependencies.
    """
 service = strict(service_raw)
 need(service['schema'] == 'hepta.phone-local.service-inputs.v150.r10.1',
 'final r10 service inputs required for external dependencies')
 artifacts = state['component_combination']['artifacts']
 names = {'client', 'sidecar', 'worker', 'screen_helper', 'focus_helper',
 'unicode_helper', 'busybox', 'python'}
 need(set(artifacts) == names, 'exact eight component dependencies required')
 expected = {}
 with component_modules(state, actual_context=state['actual_context']) as modules:
  common = modules['component_common']
  client = service['executor']['client']
  need(client['gnu_path'] == str(common.CLIENT)
  and client['host_state_path'] == ANDROID_BASE + '/tool_client_r6.py'
  and client['sha256'] == common.CLIENT_SHA, 'final native client binding differs')
  expected['client'] = (str(common.CLIENT), client['bytes'], common.CLIENT_SHA,
  client['host_state_path'])
  for name, field, path, pin in (
  ('sidecar', 'binary', common.SIDECAR, common.SIDECAR_SHA),
  ('worker', 'worker', common.WORKER, common.WORKER_SHA)):
   row = service['executor'][field]
   need(row['path'] == path and row['sha256'] == pin,
   'final native executor binding differs: ' + name)
   expected[name] = (path, row['bytes'], pin, path)
 wanted = {'SCREEN_JAR', 'SCREEN_JAR_SHA256', 'FOCUS_INPUT_JAR',
 'FOCUS_INPUT_JAR_SHA256', 'INPUT_JAR', 'INPUT_JAR_SHA256'}
 constants = {}
 for node in ast.parse(sources['phone_observation_tools.py']).body:
  if isinstance(node, ast.Assign) and len(node.targets) == 1 \
  and isinstance(node.targets[0], ast.Name) and node.targets[0].id in wanted:
   name = node.targets[0].id
   need(name not in constants, 'duplicate typed helper constant')
   constants[name] = ast.literal_eval(node.value)
 need(set(constants) == wanted, 'complete typed helper source constants required')
 helper_rows = {row['path']: row for row in service['helpers']}
 need(len(helper_rows) == len(service['helpers']) == 3, 'final helper inventory differs')
 for name, stem in (('screen_helper', 'SCREEN_JAR'), ('focus_helper', 'FOCUS_INPUT_JAR'),
 ('unicode_helper', 'INPUT_JAR')):
  path, pin = constants[stem], constants[stem + '_SHA256']
  need(path in helper_rows and helper_rows[path]['sha256'] == pin,
  'final service and typed helper source differ: ' + name)
  expected[name] = (path, helper_rows[path]['bytes'], pin, path)
 expected['python'] = ('/usr/bin/python3', 7843560,
 'f7ad87c414fc6a5126571b2ecca19351119ac10e54d0539de6a0a9300d81087f',
 '/data/trillionnium/owner-open/root/usr/bin/python3')
 expected['busybox'] = ('/data/adb/magisk/busybox', 1710600,
 '4d60ab3f5a59ebb2ca863f2f514e6924401b581e9b64f602665c008177626651',
 '/data/adb/magisk/busybox')
 result = []
 for name in sorted(names):
  row = artifacts[name]; path, size, pin, target = expected[name]
  need(set(row) == {'path', 'bytes', 'sha256', 'uid', 'gid', 'mode', 'selinux'}
  and type(row['bytes']) is int and row['bytes'] == size > 0
  and row['path'] == path and row['sha256'] == pin,
  'closed component and final external artifact differ: ' + name)
  need(type(row['uid']) is int and type(row['gid']) is int
  and 0 <= row['uid'] < 2**32 and 0 <= row['gid'] < 2**32
  and type(row['mode']) is int and 0 <= row['mode'] <= 0o777
  and isinstance(row['selinux'], str)
  and re.fullmatch(r'u:object_r:[a-zA-Z0-9_]+:s0', row['selinux']),
  'explicit external artifact metadata required: ' + name)
  result.append(dict(name=name, target=target, **row))
 need(len({row['target'] for row in result}) == 8, 'external target mapping is not unique')
 return result
def validate_external_inventory(bindings, inventory, *, path_key):
 need(path_key in ('path', 'target') and isinstance(inventory, list),
 'explicit installed dependency inventory required')
 rows = {row[path_key]: row for row in inventory}
 need(len(rows) == len(inventory), 'duplicate dependency inventory path')
 for binding in bindings:
  row = rows.get(binding['target'])
  need(row is not None and all(row[k] == binding[k] for k in ('bytes', 'sha256')),
  'component dependency omitted or changed in final payload: ' + binding['name'])
 return True
def current_external_artifacts(state):
 """Read-only exact eight bytes/metadata and explicitly adopted policy."""
 need(checked_actual_context(state['actual_context']) == 'phone',
 'current external artifacts require actual phone context')
 with component_modules(state, actual_context=state['actual_context']) as modules:
  return modules['component_common'].verify_external(state['component_combination'])
def image_descriptor(value, expected=None):
 file_descriptor(value)
 need(0 < value['bytes'] <= 8 * 1024 * 1024
 and (expected is None or value['sha256'] == expected), 'policy image descriptor differs')
 return {k: value[k] for k in ('bytes', 'sha256')}
def complete_comparison(report, parent, candidate, *, kind):
 need(report.get('schema') == 'hepta.fd-use-r10.complete-policy-comparison.v1'
 and report.get('state') == 'EXACT_ONE_APPROVED_PERMISSION_DELTA_VERIFIED'
 and report.get('comparison_kind') == kind
 and image_descriptor(report['parent']) == image_descriptor(parent)
 and image_descriptor(report['candidate']) == image_descriptor(candidate)
 and report.get('approved_rule_atoms') == [ATOM], 'complete policy comparison identity differs')
 delta = report['semantic_delta']; coverage = report['coverage']
 need(delta['added_atoms'] == [ATOM] and delta['removed_atoms'] == []
 and delta['all_raw_TE_counter_delta_bound'] is True and delta['unconditional_only'] is True,
 'policy comparison is not exactly the approved atom')
 for name in ('all_TE_rules_enumerated', 'multiplicity_preserved',
 'conditional_expression_and_branch_preserved', 'explicit_xperm_type_and_all_integers'):
  need(coverage.get(name) is True, 'incomplete semantic comparison: ' + name)
 need(coverage['unsupported_rule_kinds'] == [] and coverage['errors'] == []
 and coverage['actual_conditional_list_empty'] is True
 and type(coverage['actual_conditional_avtab_count']) is int
 and coverage['actual_conditional_avtab_count'] == 0,
 'policy comparison has unsupported or incomplete coverage')
 expected_tables = {'categories', 'commons', 'classes', 'constraints', 'defaults', 'bounds',
 'ibendportcons', 'ibpkeycons', 'levels', 'mlsrules', 'netifcons', 'nodecons',
 'polcaps', 'portcons', 'rbacrules', 'sensitivities'}
 extra_tables = {'types', 'type_attributes', 'booleans', 'classes_with_common',
 'common_permissions', 'conditionals', 'roles', 'users', 'initialsids',
 'fs_uses', 'unlabeled_filesystems', 'genfs'}
 need(set(coverage['non_TE_tables']) == expected_tables
 and len(coverage['non_TE_tables']) == len(expected_tables)
 and set(coverage['additional_complete_tables']) == extra_tables
 and len(coverage['additional_complete_tables']) == len(extra_tables),
 'complete policy tables differ')
 image = report['full_image_comparison']
 need(image['all_enumerated_roundtrip_semantics_preserved'] is True
 and image['all_orbit_members_structurally_and_semantically_verified'] is True,
 'original-to-normalized semantic preservation missing')
 for name in ('complete_input_consumption', 'baseline_conditional_list_empty',
 'candidate_conditional_list_empty', 'all_cycles_close_at_first_image',
 'all_cycle_representatives_stable',
 'only_approved_delta_full_image_equal', 'negative_missing_atom_rejected',
 'negative_unapproved_binder_change_rejected', 'negative_unknown_handling_rejected'):
  need(image['result'].get(name) is True, 'complete policy image gate missing: ' + name)
 result = image['result']
 need(result['schema'] == 'hepta.official-libsepol-one-atom-full-image-comparison.v2'
 and type(result['cycle_bound']) is int and result['cycle_bound'] == 4
 and result['normalization'] == 'lexicographic-minimum-complete-official-serialization-cycle',
 'complete official serializer normalization differs')
 names = ['parent', 'candidate', 'expected', 'negative-handle-unknown', 'negative-binder-change']
 orbits = result['serialization_orbits']
 need(isinstance(orbits, list) and [row.get('name') for row in orbits] == names,
 'complete exact official serializer orbit set differs')
 for row in orbits:
  need(set(row) == {'name', 'length', 'selected_index'}
  and type(row['length']) is int and 1 <= row['length'] <= 4
  and type(row['selected_index']) is int and 1 <= row['selected_index'] <= row['length'],
  'official serializer orbit exceeded reviewed bound')
 need(type(result['raw_serializer_idempotent']) is bool
 and result['raw_serializer_idempotent'] == all(row['length'] == 1 for row in orbits),
 'actual serializer non-idempotence was hidden')
 members = image['serialization_orbits']
 need(isinstance(members, list) and [row.get('name') for row in members] == names,
 'retained whole-orbit semantic evidence missing')
 for orbit, row in zip(orbits, members):
  need(row['length'] == orbit['length'] and row['selected_index'] == orbit['selected_index']
  and row['all_members_complete_tables_and_supplemental_readers_equal'] is True
  and len(row['original_images']) == orbit['length']
  and len({x['sha256'] for x in row['original_images']}) == orbit['length']
  and HASH.fullmatch(row['complete_table_semantics_sha256']),
  'retained orbit semantics or image inventory differs')
  for original in row['original_images']:
   image_descriptor(original)
 checks = report['checks']
 need(isinstance(checks, list) and len(checks) >= 10
 and report['check_count'] == report['passed_count'] == len(checks)
 and all(row.get('passed') is True for row in checks), 'a complete comparison check failed')
 av = report['full_av_checks']
 need(av['all_compiled_AV_nodes_validated'] is True
 and av['all_symbolic_AV_permission_atoms_compared'] is True
 and av['candidate_complete_compute_av_verified'] is True
 and av['candidate_effective_expanded_fd_permissions'] == ['use'],
 'full AV proof missing')
 effective = av['candidate_complete_compute_av']
 need(effective['policy']['sha256'] == candidate['sha256']
 and effective['policy']['bytes'] == candidate['bytes']
 and effective['policy']['input_unchanged'] is True
 and effective['requested'] == effective['allowed'] == '0x00000001'
 and effective['denied_requested'] == '0x00000000'
 and effective['denial_reason_mask'] == 0, 'actual complete AV result differs')
 need(report['phone_operations'] == 0 and report['active_policy_writes'] == 0
 and report['live_policy_adoption_authorized'] is False,
 'comparison cannot itself authorize runtime adoption')
def _validate_policy_direct(bundle, value, component):
 need(isinstance(POLICY_VERIFIER_SHA,str) and HASH.fullmatch(POLICY_VERIFIER_SHA)
 and type(POLICY_VERIFIER_BYTES) is int and 0<POLICY_VERIFIER_BYTES<=131072
 and all(isinstance(pin,str) and HASH.fullmatch(pin) for pin in
 (CURRENT_POLICY_SHA,CURRENT_POLICY_ADOPTION_SHA,CURRENT_SCOPE_DECISION_SHA))
 and CURRENT_POLICY_SHA != '50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
 and CURRENT_POLICY_ADOPTION_SHA != 'a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5',
 'new property-policy adoption, scope and verifier have not been frozen and reviewed')
 need(isinstance(value,dict) and isinstance(value.get('verification_originals'),list),
 'explicit new property-policy adoption original inventory required')
 verifier_rows=[row for row in value['verification_originals']
 if isinstance(row,dict) and row.get('sha256')==POLICY_VERIFIER_SHA
 and row.get('bytes')==POLICY_VERIFIER_BYTES]
 need(len(verifier_rows)==1,'one exact reviewed property-policy verifier original required')
 verifier_raw=original_from(bundle,verifier_rows[0])
 verifier=types.ModuleType('reviewed_property_policy_adoption')
 verifier.__file__='/reviewed-property-adoption/policy_native5_verifier.py'
 verifier.__reviewed_source_sha256__=sha(verifier_raw)
 exec(compile(verifier_raw,verifier.__file__,'exec',optimize=0),verifier.__dict__)
 raw=base64.b64decode(bundle['inputs']['policy']['raw_b64'],validate=True)
 summary=verifier.verify_adoption(raw,read_pinned=lambda row:original_from(bundle,row))
 need(summary['current_adoption_sha256']==sha(raw)==bundle['inputs']['policy']['descriptor']['sha256']
 == CURRENT_POLICY_ADOPTION_SHA,
 'actual property-policy adoption is not the explicitly reviewed original')
 need(summary['retirement_sha256']==component['retirement_sha256']
 and summary['prior_boundary_sha256']==component['property_parent_ancestors'][0]['boundary']['sha256']
 and summary['prior_boundary_sha256']=='eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10',
 'property-policy transition is outside the exact retained actual08 lineage')
 need(summary['root_scope_decision_sha256']==CURRENT_SCOPE_DECISION_SHA
 and summary['parent_adoption_sha256']=='a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5',
 'property-policy transition changed its exact reviewed parent or new scope')
 actual=original_from(bundle,value['actual_export']);full=original_from(bundle,value['full_rule'])
 need(summary['runtime_policy']==descriptor(actual) and summary['full_rule']==value['full_rule']
 and component['component_combination']['live_policy_sha256']==sha(actual)==CURRENT_POLICY_SHA,
 'current component policy and complete adopted property-policy rules differ')
 return {'runtime_policy':descriptor(actual),'full_rule':full,
 'policy_adoption_sha256':summary['current_adoption_sha256'],
 'policy_transition':summary}
def validate_policy(bundle, value, component, *, budget_check=None):
 """Use the explicit epoch audit contract; preserve the original direct verifier."""
 if type(value) is not dict or value.get('schema') != 'hepta.native-guard.epoch-policy-history-input.v1':
  need('epoch_policy_history_input' not in strict(component['package_manifest_raw']),
  'current epoch requires its explicit source-bound history audit input')
  return _validate_policy_direct(bundle, value, component)
 need(callable(budget_check), 'policy history must share the enclosing verification deadline')
 budget_check()
 fields={'schema','epoch_id','original_adoption','actual_export','full_rule',
 'root_scope_decision','reconciliation','authority','originals'}
 need(set(value)==fields and value['epoch_id']=='legacy902-active01',
 'exact policy history input and source epoch required')
 rows=value['originals']
 need(type(rows) is list and 1<=len(rows)<=4096,
 'complete bounded history authority dependency list required')
 declared={};sizes={}
 def declare(row):
  file_descriptor(row)
  need(type(row['bytes']) is int, 'strict original byte count required')
  previous=declared.get(row['path']);size=sizes.get(row['sha256'])
  need(previous is None or encode(previous)==encode(row),
  'history dependency path has conflicting identities')
  need(size is None or size==row['bytes'], 'equal history SHA has conflicting sizes')
  declared[row['path']]=row;sizes[row['sha256']]=row['bytes']
 for row in rows:
  need(type(row) is dict and row.get('path') not in declared,
  'history dependency paths repeat')
  declare(row)
 need(list(declared)==sorted(declared), 'history dependency list is not path-sorted')
 for name in ('original_adoption','actual_export','full_rule','root_scope_decision','reconciliation','authority'):
  declare(value[name])
 used={}
 def get(row):
  budget_check();file_descriptor(row)
  need(row['path'] in declared and encode(row)==encode(declared[row['path']]),
  'history verifier requested an undeclared or changed original')
  raw=original_from(bundle,row);used[row['path']]=row;budget_check();return raw
 need(encode(strict(component['package_manifest_raw']).get('epoch_policy_history_input'))
 ==encode(bundle['inputs']['policy']['descriptor']),
 'policy history input differs from the actual whole32 runtime manifest')
 input_raw=base64.b64decode(bundle['inputs']['policy']['raw_b64'],validate=True)
 need(sha(input_raw)==bundle['inputs']['policy']['descriptor']['sha256']
 and encode(strict(input_raw))==encode(value), 'policy wrapper original differs')
 with component_modules(component,actual_context=component['actual_context']) as modules:
  profile=modules['native_proc_profile'];common=modules['component_common']
  need(profile is sys.modules.get('native_proc_profile')
  and profile.__actual_context__==component['actual_context']==common.__actual_context__
  and profile.__reviewed_package_sources__ is component['package_sources']
  and common.__reviewed_package_sources__ is component['package_sources']
  and profile.__reviewed_package_manifest_raw__==component['package_manifest_raw']
  and common.__reviewed_package_manifest_raw__==component['package_manifest_raw']
  and profile.__reviewed_source_sha256__==sha(component['package_sources']['source/native_proc_profile.py']),
  'history verifier must be the current whole32 member in the same actual context')
  gate=getattr(profile,'verify_epoch_policy_history',None)
  need(callable(gate), 'reviewed policy history source/action gate is not installed')
  proof=gate(input_raw,read_pinned=get,budget_check=budget_check)
 need(type(proof) is dict and set(proof)=={'schema','state','input','original_adoption',
 'policy_transition','authority','used_originals'}
 and proof['schema']=='hepta.native-guard.epoch-policy-history-verification.v1'
 and proof['state']=='ORIGINAL_POLICY_ADOPTION_REVERIFIED_BY_OWNED_HOST_AUDIT'
 and proof['input']==descriptor(input_raw)
 and encode(proof['original_adoption'])==encode(value['original_adoption']),
 'history result does not bind the exact new wrapper and original adoption separately')
 authority=proof['authority']
 need(type(authority) is dict and set(authority)=={'schema','state','packet','reconciliation','sources','readset'}
 and authority['schema']=='hepta.native-guard.epoch-policy-history-source-action-verification.v1'
 and authority['state']=='FIXED_SOURCE_INPUTS_OWNED_EXECUTION_AND_RESULT_VERIFIED'
 and encode(authority['packet'])==encode(value['authority'])
 and encode(authority['reconciliation'])==encode(value['reconciliation']),
 'complete fixed source/action authority is missing or inconsistent')
 sources=authority['sources']
 need(type(sources) is list and 1<=len(sources)<=64,
 'bounded complete fixed history source set required')
 for row in sources+[authority['readset']]:
  file_descriptor(row)
  need(row['path'] in used and encode(used[row['path']])==encode(row),
  'history source or audit readset bypassed the actual complete reader')
 names=[row['path'] for row in sources]
 need(names==sorted(set(names)), 'history sources are not unique and path-sorted')
 need(set(used)==set(declared)
 and encode(proof['used_originals'])==encode([used[path] for path in sorted(used)]),
 'history proof omitted, invented or hid an original read')
 original_raw=get(value['original_adoption']);original=strict(original_raw)
 need(len(original_raw)==208226
 and sha(original_raw)==CURRENT_POLICY_ADOPTION_SHA
 == '527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a'
 and original.get('schema')=='hepta.runtime-properties-r10.policy-adoption.v1',
 'unchanged complete historical policy adoption required')
 for name in ('actual_export','full_rule','root_scope_decision'):
  need(encode(value[name])==encode(original[name]),
  'current policy material differs from its actual original adoption')
 summary=proof['policy_transition']
 need(type(summary) is dict and summary['current_adoption_sha256']==sha(original_raw),
 'the complete actual old-verifier summary must retain the original adoption identity')
 need(summary['retirement_sha256']==component['retirement_sha256']
 and summary['prior_boundary_sha256']==component['property_parent_ancestors'][0]['boundary']['sha256']
 and summary['prior_boundary_sha256']=='eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10',
 'property-policy transition is outside the exact retained actual08 lineage')
 need(summary['root_scope_decision_sha256']==CURRENT_SCOPE_DECISION_SHA
 and summary['parent_adoption_sha256']=='a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5',
 'property-policy transition changed its exact reviewed parent or new scope')
 actual=get(value['actual_export']);full=get(value['full_rule'])
 scope=get(value['root_scope_decision'])
 need(sha(scope)==CURRENT_SCOPE_DECISION_SHA
 and summary['runtime_policy']==descriptor(actual) and summary['full_rule']==value['full_rule']
 and component['component_combination']['live_policy_sha256']==sha(actual)==CURRENT_POLICY_SHA,
 'current component policy and complete adopted property-policy rules differ')
 budget_check()
 return {'runtime_policy':descriptor(actual),'full_rule':full,
 'policy_adoption_sha256':summary['current_adoption_sha256'],
 'policy_transition':summary,'epoch_policy_history':proof}
def validate_bundle(raw, expected_sha256, *, actual_context, budget_check=None):
 actual_context = checked_actual_context(actual_context)
 if budget_check is None:
  budget_check = epoch_component_budget()
 need(callable(budget_check), 'one enclosing verification deadline is required')
 budget_check()
 need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_BUNDLE and sha(raw) == expected_sha256,
 'explicit release-boundary bundle pin differs')
 bundle = strict(raw)
 need(set(bundle) == {'schema', 'inputs', 'originals'}
 and bundle['schema'] == 'hepta.r10.release-boundary-bundle.v2'
 and set(bundle['inputs']) == {'component', 'policy'}, 'release-boundary bundle schema differs')
 decoded_bundle_budget(bundle)
 component_value = input_value(bundle, 'component'); policy_value = input_value(bundle, 'policy')
 wanted = {row['sha256'] for value in (component_value, policy_value) for row in descriptors(value)}
 need(set(bundle['originals']) == wanted, 'bundled original inventory differs')
 state = validate_component(bundle, component_value, actual_context=actual_context,
 budget_check=budget_check)
 budget_check()
 state.update(validate_policy(bundle, policy_value, state, budget_check=budget_check))
 budget_check()
 state.update(bundle_sha256=expected_sha256,
 component_input_sha256=bundle['inputs']['component']['descriptor']['sha256'])
 return state
def inventory_value(state, inventory):
 with component_modules(state, actual_context=state['actual_context']) as modules:
  return modules['late_boundary'].inventory_value(inventory)
def current_preservation(state):
 """Phone-only fresh complete preservation of a sealed two-domain epoch."""
 need(state['actual_context'] == 'phone' and state['native_chain_domains_flattened'] is False,
 'live preservation requires explicit phone context and separate native domains')
 budget_check = epoch_component_budget()
 with component_modules(state, runtime=True, actual_context=state['actual_context']) as modules:
  late = modules['late_boundary']; common = modules['component_common']
  gate = getattr(late, 'current_epoch_preservation', None)
  need(callable(gate), 'the mandatory sealed epoch live-preservation gate is not installed')
  publication = state['epoch_publication']
  seal = publication['verified']['registry']['sealed']
  need(type(seal) is dict and set(seal) == {'original','value'},
  'installation requires an actual immutable seal in the postpublication originals')
  proof = gate(publication['manifest'], publication['originals_by_path'], budget_check=budget_check)
  need(type(proof) is dict and set(proof) == {
  'schema','state','epoch_id','boot_id','publication_manifest','latest_boundary',
  'epoch_seal','source_generation','inventory_spec','business_inventory','control_inventory',
  'inventory_observation','role_absence','endpoints','external_artifacts',
  'immutable_original_rechecks','original_retirement_current_equality_claimed',
  'component_qualified','business_qualified','native_boundary_created'}
  and proof['schema'] == 'hepta.native-guard.epoch-current-preservation.v1'
  and proof['state'] == 'SEALED_EPOCH_CURRENT_ORIGINALS_INVENTORY_ROLES_ENDPOINTS_VERIFIED'
  and proof['epoch_id'] == publication['verified']['active']['epoch_id']
  and proof['boot_id'] == BOOT
  and proof['publication_manifest'] == descriptor(common.encoded(publication['manifest']))
  and encode(proof['latest_boundary']) == encode(state['component_input']['latest_boundary'])
  and encode(proof['epoch_seal']) == encode(seal['original'])
  and encode(proof['source_generation']) == encode(state['chain'][0][0]['epoch']['generation'])
  and proof['original_retirement_current_equality_claimed'] is False
  and proof['component_qualified'] is False and proof['business_qualified'] is False
  and proof['native_boundary_created'] is False,
  'live preservation proof does not belong to the exact sealed generation and original set')
  need(type(proof['role_absence']) is list and len(proof['role_absence']) == 2,
  'two actual complete union-role absence observations are required')
  modules['component_lifecycle'].verify_epoch_inventory_observation(
  proof['inventory_spec'], proof['business_inventory'], proof['control_inventory'],
  proof['inventory_observation'])
  budget_check()
  return proof['business_inventory'], {
  'role_absence':proof['role_absence'], 'endpoints':proof['endpoints'],
  'external_artifacts':proof['external_artifacts'],
  'component_boundary_sha256':state['component_boundary_sha256'],
  'retirement_sha256':state['retirement_sha256'],
  'old_retirement_current_equality_claimed':False,
  'epoch_current_preservation':proof}
def inventory_path(android_path):
 p = Path(android_path)
 need(p.is_absolute() and str(p) == android_path and '..' not in p.parts,
 'canonical release target required')
 if android_path == ANDROID_BASE or android_path.startswith(ANDROID_BASE + '/'):
  return BASE + android_path[len(ANDROID_BASE):]
 return '/proc/1/root' + android_path
def validate_install_layout(state, manifest):
 roots = list(map(Path, state['current_inventory']['roots']))
 observed = []
 for row in manifest['writes']:
  p = Path(inventory_path(row['target']))
  need(not any(p == root or root in p.parents or p in root.parents for root in roots),
  'release file write overlaps preserved component inventory')
 for row in manifest['runtime_directories']:
  p = Path(inventory_path(row['path']))
  if any(p == root or root in p.parents or p in root.parents for root in roots):
   need(str(p) == INSTALL_DIRECTORY and row.get('selinux') == INSTALL_LABEL,
   'unreviewed runtime directory overlaps preserved originals')
   observed.append(str(p))
 need(observed == [INSTALL_DIRECTORY], 'one exact installation-owned empty directory required')
 need(INSTALL_DIRECTORY not in state['current_inventory']['entries']
 and str(Path(INSTALL_DIRECTORY).parent) in state['current_inventory']['entries'],
 'new installation directory already exists or its preserved parent is absent')
def validate_install_delta(before, after):
 """Only the actual stage source's mkdir/chown/chmod/label/fsync is admitted.

    No stage source opens a file under this directory. Its per-boot child and
    sidecar log files are created later by service.sh, after the start boundary.
    """
 need(before['schema'] == after['schema'] == 'hepta.native-guard.complete-inventory.v1'
 and before['roots'] == after['roots']
 and before['file_bytes_hashed'] == after['file_bytes_hashed']
 and before['inventory_is_closure_or_retirement'] is False
 and after['inventory_is_closure_or_retirement'] is False, 'stage inventory envelope changed')
 b, a = before['entries'], after['entries']
 parent = str(Path(INSTALL_DIRECTORY).parent); name = Path(INSTALL_DIRECTORY).name
 need(INSTALL_DIRECTORY not in b and set(a) == set(b) | {INSTALL_DIRECTORY}
 and parent in b, 'stage changed an unreviewed inventory path')
 new = a[INSTALL_DIRECTORY]
 need(set(new) == {'kind', 'metadata', 'names'} and new['kind'] == 'directory'
 and new['names'] == [], 'installation-owned directory is not exactly empty')
 bm, am, nm = b[parent]['metadata'], a[parent]['metadata'], new['metadata']
 need(len(bm) == len(am) == len(nm) == 9
 and all(type(v) is int for v in bm + am + nm), 'stage metadata shape differs')
 need(nm[0] == bm[0] and nm[1] > 0 and nm[2] == stat.S_IFDIR | 0o700
 and nm[3:6] == [0, 0, 2] and nm[6] >= 0,
 'installation-owned empty directory metadata differs')
 need(set(b[parent]) == set(a[parent]) == {'kind', 'metadata', 'names'}
 and b[parent]['kind'] == a[parent]['kind'] == 'directory'
 and a[parent]['names'] == sorted(b[parent]['names'] + [name])
 and name not in b[parent]['names'], 'preserved parent gained a different name')
 need(am[:5] == bm[:5] and am[5] == bm[5] + 1 and am[6] >= bm[6]
 and am[7] >= bm[7] and am[8] >= bm[8]
 and nm[7] >= bm[7] and nm[8] >= bm[8],
 'preserved parent identity or mkdir-attributable metadata differs')
 for path in b:
  if path != parent:
   need(a[path] == b[path], 'pre-existing original changed during install: ' + path)
 return {'added_directory': INSTALL_DIRECTORY, 'added_directory_metadata': nm,
 'parent': parent, 'parent_before_metadata': bm, 'parent_after_metadata': am,
 'parent_added_name': name, 'all_old_file_bytes_and_identities_unchanged': True,
 'other_directory_entries_unchanged': True,
 'old_retirement_current_equality_claimed': False}
