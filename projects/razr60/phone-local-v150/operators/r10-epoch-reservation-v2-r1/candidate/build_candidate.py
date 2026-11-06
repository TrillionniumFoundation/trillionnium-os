#!/usr/bin/env python3
"""Derive the complete preparer from fixed inputs using reversible exact edits."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path('/workspace/scratch/2438ae2c67d8')
OUT = Path(__file__).parent
SOURCE = ROOT / 'acceptance-audit/full19-dependency-r1/inputs/final32-source-snapshot02/publication-producer/source/prepare_component.py'
COMMON = ROOT / 'acceptance-audit/full19-dependency-r1/inputs/final32-source-snapshot02/common05/source/component_common.py'
ADMISSION = ROOT / 'acceptance-audit/full19-dependency-r1/inputs/final32-entry-fragments04/source/epoch_admission_values.fragment.py'
STAGE = ROOT / 'acceptance-audit/full19-dependency-r1/inputs/final32-entry-fragments04/source/epoch_stage_operations.fragment.py'
raw = SOURCE.read_bytes()
assert len(raw) == 130768
assert hashlib.sha256(ADMISSION.read_bytes()).hexdigest() == '6d3b3d1ab5fd10e23b125f99c216141d4d341dc116c4eb5387571f6fffb5959d'
source = raw.decode()
edits = []


def replace(old, new, kind='semantic'):
    global source
    assert source.count(old) == 1, ('unique exact edit', old)
    source = source.replace(old, new)
    edits.append({'kind':kind, 'before':old, 'after':new})


replace(" binding=epoch_binding_value();index=epoch_manifest_value(manifest,originals,binding=binding)\n",
" import component_common as common\n api=common._epoch_stage_api();source_binding=api._est_binding(common)\n binding=epoch_binding_value();index=epoch_manifest_value(manifest,originals,binding=binding)\n")
replace(" slots=[];closed=[];nonce_set=set(binding['legacy_nonces']+binding['failed_nonces'])\n",
" slots=[];closed=[];nonce_set=set(common.epoch_forbidden_nonces(binding))\n")
replace("  for key in ('authorization_request','resource_reservation'):\n   _ep_manifest_raw(reservation[key],index,originals)\n",
"  resource=reservation['resource_reservation'];authorization=reservation['authorization_request']\n  _ep_need(_ep_same(resource['generation'],reservation['generation'])\n  and _ep_same(authorization['origin'],source_binding['authorization_requests'][resource['case_id']])\n  and '\\0' not in authorization['utf8'],'reservation source or authorization differs')\n")
replace("  records={key:_ep_optional_record(index,originals,prefix+filename) for key,filename in (\n  ('identity','IDENTITY.json'),('admission','ADMISSION.json'),('stage','STAGE.json'),\n  ('scope_binding','SCOPE-BINDING.json'),('launch','LAUNCH.json'),('terminal','COMMIT.json'))}\n  names={'DIRECTORY-BINDING.json'}|{filename for key,filename in (\n  ('identity','IDENTITY.json'),('admission','ADMISSION.json'),('stage','STAGE.json'),\n  ('scope_binding','SCOPE-BINDING.json'),('launch','LAUNCH.json'),('terminal','COMMIT.json'))\n  if records[key] is not None}\n",
"  record_files=(('identity','IDENTITY.json'),('allocation','ALLOCATION-ADMISSION.json'),\n  ('role_launch','ROLE-LAUNCH-INTENT.json'),('admission','ADMISSION.json'),('stage','STAGE.json'),\n  ('scope_binding','SCOPE-BINDING.json'),('launch','LAUNCH.json'),('terminal','COMMIT.json'))\n  records={key:_ep_optional_record(index,originals,prefix+filename) for key,filename in record_files}\n  names={'DIRECTORY-BINDING.json'}|{filename for key,filename in record_files if records[key] is not None}\n")
replace("   _ep_manifest_raw(identity['owner_request'],index,originals)\n",
"   owner=_ep_manifest_raw(identity['owner_request'],index,originals)\n   _ep_need(identity['case_id']==resource['case_id']\n   and owner==authorization['utf8'].replace('{{EPOCH_NONCE}}',identity['nonce']).encode('utf-8'),\n   'owner bytes differ from reserved authorization')\n")
replace("   stage=records['stage']\n   if stage is not None:\n",
"   allocation=records['allocation']\n   if allocation is not None:\n    api.epoch_allocation_admission_value(allocation['value'],identity=identity,\n    identity_pin=identity_record['original'],reservation=reservation,reservation_pin=claim['original'],\n    initialization=initialization,index=index,originals=originals)\n   else:\n    _ep_need(all(records[k] is None for k in ('stage','role_launch','admission','scope_binding','launch','terminal')),\n    'later phase lacks allocation admission')\n   stage=records['stage']\n   if stage is not None:\n")
replace("    _ep_need(all(records[k] is None for k in ('admission','scope_binding','launch','terminal')),\n    'later actual phases cannot be inferred before private stage completion')\n",
"    _ep_need(all(records[k] is None for k in ('role_launch','admission','scope_binding','launch','terminal')),\n    'later phase lacks stage completion')\n")
replace("   if records['admission'] is not None:\n    _ep_retired_admission(records['admission'],identity,index,originals,observation_verifier)\n",
"   role=records['role_launch']\n   if role is not None:\n    api.epoch_role_launch_intent_value(role['value'],identity=identity,\n    identity_pin=identity_record['original'],lease_pin=stage['value']['lease'],\n    generation=generation['original'],index=index,originals=originals)\n   else:\n    _ep_need(all(records[k] is None for k in ('admission','scope_binding','launch','terminal')),\n    'later phase lacks role launch intent')\n   if records['admission'] is not None:\n    _ep_retired_admission(records['admission'],identity,index,originals,observation_verifier)\n")
semantic = source

# Preserve conditions and control flow; shorten only diagnostics in this local
# replay section and three documentation strings. No source-wide reformatting.
messages = {
 'native scope must come from the original accepted file in this actual home':'accepted scope path differs',
 'actual accepted original fields differ':'accepted fields differ',
 'scope binding cannot fabricate a prior dispatch':'unexpected prior dispatch',
 'scope lacks its actual original bound component contract':'bound contract missing',
 'actual accepted native scope changed its one-use identity or owner contract':'accepted identity/contract differs',
 'actual native claim is not the original once-only zero-model claim':'native claim differs',
 'original native run acceptance differs from the home scope binding':'run acceptance differs',
 'explicit original accepted-scope fixture authorization required':'fixture authorization fields differ',
 'fixture phase permission changed its actual scope, ordinal or fixed namespace':'fixture scope/ordinal/path differs',
 'fixture permission is not the actual native setup original':'fixture setup original differs',
 'fixture original belongs to another native scope or bound contract':'fixture scope/contract differs',
 'complete immutable lifecycle admission binding required':'lifecycle binding fields differ',
 'lifecycle admission is not this actual original home observation':'lifecycle home differs',
 'actual lifecycle did not record a complete new-domain current verification':'current verification missing',
 'current admission invented a native result or model request':'unexpected native/model result',
 'explicit protocol mode and complete inventory gates required':'protocol mode/gates differ',
 'actual immutable epoch anchor is missing':'epoch anchor missing',
 'initialization has an unreviewed source catalog':'initial catalog unreviewed',
 'source authority must retain its one actual create-only namespace':'authority path differs',
 'complete actual slot namespace is missing':'slot namespace missing',
 'partial, unknown, duplicate or noncontiguous slot allocation blocks replay':'slot sequence incomplete',
 'postpublication replay cannot substitute a current preclose lease':'published lease forbidden',
 'capture is not the sole highest unsealed ordinal':'capture ordinal/seal differs',
 'slot selected a catalog outside the finite reviewed generation set':'slot catalog unreviewed',
 'actual exclusively claimed slot directory is missing':'claimed directory missing',
 'an empty or active epoch cannot claim a sealed production boundary':'empty/active epoch cannot seal',
 'complete explicit epoch seal required':'seal fields differ',
 'epoch seal changed its actual terminal frontier':'seal terminal differs',
 'a later phase cannot exist before the actual durable identity':'phase lacks identity',
 'unknown preidentity claim cannot become a terminal or authorize a next ordinal':'unidentified claim blocks advance',
 'slot repeats a label or skips the actual previous native boundary':'label/prior boundary differs',
 'owner request must already be an actual create-only slot original':'owner original path differs',
 'new transport contains an unreviewed phase filename':'transport phase unreviewed',
 'native accepted scope omitted actual lifecycle admission':'accepted scope lacks admission',
 'active slots repeat a native scope':'native scope repeated',
 'fixture phase precedes actual accepted scope':'fixture lacks accepted scope',
 'native terminal lacks its actual fixture phase':'terminal lacks fixture',
 'a consumed unknown slot forbids further allocation/publication':'unknown slot blocks advance',
 'capture lease does not belong to this current uncommitted identity':'capture lease identity differs',
}
for before, after in messages.items():
    replace(repr(before), repr(after), 'diagnostic_only')
docs = {
 '<module>':'"""Host-only preparation; no nonce, phone action or qualification."""',
 '_epoch_collect_saved_inventory_inputs':'"""Retain both actual bodies under saved CAPTURE pins and phone full9."""',
 'epoch_verify_phone_active_source_observation':'"""Bind phone proof to whole32; independent active verification remains mandatory."""',
}
for name, replacement in docs.items():
    tree = ast.parse(source)
    node = tree if name == '<module>' else next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    expr = node.body[0]
    assert isinstance(expr, ast.Expr) and isinstance(expr.value, ast.Constant) and isinstance(expr.value.value, str)
    replace(ast.get_source_segment(source, expr), replacement, 'documentation_only')

reverse = source
for edit in reversed(edits):
    assert reverse.count(edit['after']) == 1
    reverse = reverse.replace(edit['after'], edit['before'])
assert reverse.encode() == raw
candidate = source.encode()
assert len(candidate) <= 131072, len(candidate)
compile(candidate, 'prepare_component.py', 'exec')
for folder in ('source','reference','validation'):
    (OUT/folder).mkdir(exist_ok=True)
(OUT/'source/prepare_component.py').write_bytes(candidate)
reference = {'prepare_component.parent.py':SOURCE, 'component_common.py':COMMON,
             'epoch_admission_values.fragment.py':ADMISSION, 'epoch_stage_operations.fragment.py':STAGE}
for name,path in reference.items():
    data=path.read_bytes();(OUT/'reference'/name).write_bytes(data)
diff=''.join(difflib.unified_diff(raw.decode().splitlines(True), source.splitlines(True),
    fromfile='prepare_component.parent.py',tofile='prepare_component.py'))
(OUT/'validation/prepare_component.patch').write_text(diff)
report = {'schema':'hepta.prepare-epoch-v2.source-derivation.v1',
    'parent':{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},
    'candidate':{'bytes':len(candidate),'sha256':hashlib.sha256(candidate).hexdigest()},
    'semantic_candidate_bytes_before_local_diagnostic_shrink':len(semantic.encode()),
    'source_limit':131072,'remaining_bytes':131072-len(candidate),
    'whole_byte_inverse_equal':True,'phone_calls':0,'case_credit':0,
    'diagnostic_only_replacements':len(messages),'documentation_only_replacements':len(docs),
    'edits':edits,
    'references':{name:{'source':str(path),'bytes':len(path.read_bytes()),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()} for name,path in reference.items()}}
(OUT/'validation/SOURCE-DERIVATION.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ('edits','references')},sort_keys=True))
