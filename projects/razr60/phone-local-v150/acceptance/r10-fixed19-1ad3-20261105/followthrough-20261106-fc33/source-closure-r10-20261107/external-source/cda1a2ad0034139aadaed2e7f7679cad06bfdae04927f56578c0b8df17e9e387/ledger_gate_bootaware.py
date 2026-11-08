import base64,fcntl,hashlib,json,os,re,stat
from pathlib import Path
BINDING={'action_id': 'fc7bd6d939fb740a6403a04521fbb057', 'intent_sha256': '37f047bc0f06ad65eb5c20673e45eba4b257df864d5482ae454f553eba7cb417', 'command_sha256': '7976b489740b138a22fb8d724f953af92b7a1e3a1c15b5b60941482ab497487f', 'proof_sha256': '2bdd6c33c42359f1b27567b99627f7223d40a0c37f6af0158b8dc010e899943e', 'artifact_sha256': {'after': '740e70772a71a3b12bcddb4488452d497960781a7aa2ea021e7e379183d1457e', 'before': 'ee698fc195b52360b87b9196163d0bd32b3455daa6769b91dfd67a93e8c26744', 'native_records': '3acdcdbde2ce5673816751664a706c11a07b3fc1976f7a598af398cdc4f4f806', 'native_report': 'd94e0ca4b809073abe1bd8750837e1107ca7837eb9c44a85ce7325bd6f229818'}, 'resolution_sha256': '7e06216823c49ec8b3949efa334e61b6731ca3f9bd4a039edbea771fb849a433', 'resolution': {'action_id': 'fc7bd6d939fb740a6403a04521fbb057', 'automatic_replay': False, 'business_verified': False, 'future_executor_binding': {'client_path': '/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6.py', 'client_sha256': '500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f', 'endpoint': 'hepta_phone_executor_v150_r6', 'revision': 6}, 'intent_sha256': '37f047bc0f06ad65eb5c20673e45eba4b257df864d5482ae454f553eba7cb417', 'observed_utc': '2026-11-03T18:17:10.103595+00:00', 'old_effect_replay_forbidden': True, 'original_task_terminal_unchanged': True, 'retired_executor': {'actions_dev': 65086, 'actions_ino': 136105, 'binary_sha256': '30a495061ec8370e15391fd579a254ce35818c7b019725538e0a34755a36ccaa', 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'endpoint': 'hepta_phone_local_v150', 'pid': 31206, 'server_instance': 'ec17ea0567048b7094ac702fa4321d7d', 'source_sha256': 'beedc3a1a178d4b75887773e8ea1feae508cef89a692b35a03da3134893cafb4', 'start_ticks': 6437072}, 'retirement_proof_sha256': '2bdd6c33c42359f1b27567b99627f7223d40a0c37f6af0158b8dc010e899943e', 'schema': 'hepta.action-resolution.v150.2', 'state': 'confirmed_not_executed_after_executor_retirement', 'verifier_sha256': '6645922db85d02d71b1b8a9542af19ef6b343d5c599c91c0c4f9bb96757fe981'}, 'scope': {'profile_id': 'owner-open', 'session_id': 'session-ee897738-8fc2-4d3e-a916-5fe368b340ef', 'task_id': 'task-d3f61033-5b61-40e4-b8c6-7ea00d6b2d56', 'turn_id': 'turn-7a71e2ea-dd79-4eef-8310-2c986aa2701f', 'turn_stream_id': 'r5-stream-de6066d574abdf08ebba4677b633cb6e9926cdb634030410e87c9a58b95217ed'}, 'native_request_sha256': '860acef29450013940ddedf8ed50d1d826d7ce02352dcf0155f4aab7bbd2f57a', 'native_record_sha256': ['90c2da102dca1e0f16f2f948af684c401a77c2774ede113ef4317866aa145503', '1af982a955ecbfc0a80fbf197cdf88893c45a1fff06e7a6936ba298bc9fd42d9', 'e4685cfd3dd3a6fe556726ae919b5f0b0bb855d9dd041b9e6b45bfd35efce115', '022bafcb2f0facb9d6539abd2736cb868db943f4275b752ddda6ba4b284deea1', 'a608869dff90f36b6a250e36719ed14b68f2c560a4ae77744e6cb7e8486c269b', 'fc1331255a90b2d1046c06d3c1175c12640b74b7845c2a91a8cf4837eb5c6018', 'f4914c84cfdcda4d749c92ef35ceb895c6e9da6017c653a657349c7fc5741072'], 'original_client_files': {'fc7bd6d939fb740a6403a04521fbb057.claim.json': '78541235ce196d823f10486d3c99dbad097ba3ce7dff12ecc133719a62751179', 'fc7bd6d939fb740a6403a04521fbb057.result.json': '4849c26693888db4cdae9f4ac89ff3fc868b0b86162a0ce64a9403cf367eab09'}, 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d'}
AUDIT_SOURCE='"""Read-only verification of the pinned native event-store v1 record format.\n\nSource: frozen source7/crates/trillionnium-owner-open-event-store/src/lib.rs,\nSHA256 99b2f280ba4798cd8ee3f74fa9e9c901893c3a4949800dc13083d5842ac38018.\nRecordPreimage field order is a Rust struct; payload Value maps are sorted.\nFloats are deliberately unsupported: Python formatting is not Rust serde/ryu.\nA filtered turn proves no unobserved global predecessor or whole-store chain.\n"""\nimport hashlib\nimport json\n\nSCOPE_FIELDS = ("session_id", "profile_id", "task_id", "turn_id", "turn_stream_id")\nRECORD_FIELDS = ("schema", "store_seq", "turn_seq", "scope", "event_id", "kind",\n                 "payload", "payload_sha256", "previous_record_sha256")\n\ndef sha(raw):\n    return hashlib.sha256(raw).hexdigest()\n\ndef strict_loads(raw):\n    def unique(pairs):\n        result = {}\n        for key, value in pairs:\n            if key in result:\n                raise ValueError("duplicate JSON key")\n            result[key] = value\n        return result\n    def invalid(value):\n        raise ValueError("nonfinite JSON number: " + value)\n    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)\n\ndef canonical_value(value):\n    if value is None or type(value) in (str, bool):\n        return value\n    if type(value) is int:\n        if not -(2**63) <= value <= 2**64-1:\n            raise ValueError("integer outside serde_json i64/u64")\n        return value\n    if type(value) is float:\n        raise ValueError("float serialization requires original Rust/ryu verifier")\n    if isinstance(value, list):\n        return [canonical_value(item) for item in value]\n    if isinstance(value, dict):\n        return {key: canonical_value(value[key]) for key in sorted(value)}\n    raise ValueError("unsupported JSON value")\n\ndef encode(value):\n    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")\n\ndef record_hashes(row):\n    if set(row) != set(RECORD_FIELDS) | {"record_sha256"}:\n        raise ValueError("native event record fields differ")\n    if row["schema"] != "trillionnium.owner-open.event-record.v1":\n        raise ValueError("native event record schema differs")\n    scope = row["scope"]\n    if set(scope) != set(SCOPE_FIELDS) or any(not isinstance(scope[k],str) or not scope[k]\n                                            for k in SCOPE_FIELDS):\n        raise ValueError("native record scope differs")\n    payload = canonical_value(row["payload"])\n    payload_hash = sha(encode(payload))\n    preimage = {key: row[key] for key in RECORD_FIELDS}\n    preimage["scope"] = {key: scope[key] for key in SCOPE_FIELDS}\n    preimage["payload"] = payload\n    return payload_hash, sha(encode(preimage))\n\ndef verify_records(records, scope):\n    checks, errors, unsupported = [], [], []\n    seen = {}\n    for index, row in enumerate(records):\n        try:\n            store_seq = row["store_seq"]\n            if type(store_seq) is not int or store_seq < 0:\n                raise ValueError("invalid store sequence")\n            if store_seq in seen:\n                raise ValueError("duplicate store sequence in supplied evidence")\n            seen[store_seq] = row\n            payload_hash, record_hash = record_hashes(row)\n            if payload_hash != row["payload_sha256"] or record_hash != row["record_sha256"]:\n                raise ValueError("native record payload/preimage hash differs")\n            checks.append(store_seq)\n        except (KeyError, TypeError, ValueError, UnicodeError) as error:\n            issue = {"input_index": index, "store_seq": row.get("store_seq") if isinstance(row,dict) else None,\n                     "error": str(error)}\n            (unsupported if "float serialization" in str(error) else errors).append(issue)\n    ordered = sorted(seen.values(), key=lambda row: row["store_seq"])\n    adjacent, gaps = [], []\n    for previous, current in zip(ordered, ordered[1:]):\n        if current["store_seq"] == previous["store_seq"] + 1:\n            if current["previous_record_sha256"] != previous["record_sha256"]:\n                errors.append({"store_seq": current["store_seq"], "error": "global predecessor hash differs"})\n            else:\n                adjacent.append([previous["store_seq"], current["store_seq"]])\n        else:\n            gaps.append([previous["store_seq"], current["store_seq"]])\n    selected = [row for row in ordered if row.get("scope") == scope]\n    if not selected:\n        errors.append({"error": "selected scope has no original native records"})\n    elif [row["turn_seq"] for row in selected] != list(range(len(selected))):\n        errors.append({"error": "selected scope turn_seq is incomplete, duplicated or unordered"})\n    frames = []\n    for row in selected:\n        try:\n            frame = row["payload"]["frame"]\n            if any(frame.get(key) != scope[key] for key in SCOPE_FIELDS):\n                raise ValueError("native frame scope differs")\n            if frame.get("kind") != row["kind"] or frame.get("event_id") != row["event_id"]:\n                raise ValueError("native frame event identity differs")\n            frames.append(frame)\n        except (KeyError, TypeError, ValueError) as error:\n            errors.append({"store_seq":row["store_seq"],"error":str(error)})\n    if frames:\n        if [frame.get("host_seq") for frame in frames] != list(range(len(frames))):\n            errors.append({"error":"native frame host sequence incomplete"})\n        if frames[0].get("kind") != "turn.accepted" or frames[-1].get("kind") != "turn.end":\n            errors.append({"error":"selected native turn lacks accepted/end boundary"})\n        digests = [row["payload"].get("request_sha256") for row in selected]\n        if not isinstance(digests[0],str) or len(set(digests)) != 1:\n            errors.append({"error":"native turn request binding differs across records"})\n        elif any(frame.get("payload",{}).get("turn_request_sha256") != digests[0] for frame in frames):\n            errors.append({"error":"native frame request binding differs"})\n    return {\n        "status": "PASS" if not errors and not unsupported else "UNVERIFIED" if unsupported and not errors else "FAIL",\n        "record_count":len(records), "record_hashes_verified":len(checks),\n        "selected_scope_record_count":len(selected),\n        "adjacent_global_predecessor_links_verified":len(adjacent),\n        "unobserved_global_sequence_gaps":gaps,\n        "global_chain_complete":False,\n        "global_chain_limit":"Only supplied adjacent records checked; no unseen predecessor/genesis attested.",\n        "errors":errors,"unsupported":unsupported,\n        "selected_records":selected,"frames":frames,\n    }\n'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def strict(raw):
 def pairs(items):
  value={}
  for key,item in items:
   assert key not in value,'duplicate key';value[key]=item
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda value:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def read(path,limit=262144):
 path=Path(path)
 assert path.parent.resolve(strict=True)==path.parent,'noncanonical parent'
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd)
  assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.getuid() and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=limit,'private file bound/type'
  with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(limit+1)
  after=os.fstat(fd);named=path.lstat()
  assert len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k)==getattr(named,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink')),'file changed'
 finally:os.close(fd)
 return raw
BASE=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
LEDGER=BASE/'provider-state/evidence/action-ledger'
# Explicit r9 derivative: the old immutable proof binds its original epoch.
# A reviewed outer gate supplies a current native-proc epoch after census.
# All original intent/proof/resolution/native-record checks below are unchanged.
if not __debug__:
 raise ValueError('optimized_python_is_not_accepted')
epoch=globals().get('__activation_epoch__')
if epoch is None or dict(epoch).keys() != {'schema','original_boot_id','current_boot_id','mode','original_source_sha256'}:
 raise ValueError('verified_activation_epoch_required')
if epoch['schema']!='hepta.module-r10-r1.verified-epoch.v1' or epoch['original_boot_id']!=BINDING['boot_id']:
 raise ValueError('original_retirement_epoch_mismatch')
if epoch['original_source_sha256']!='23ec1ee206635c0ce0b2dc28ca8281d4e5523d6245eac453b58531c708e1d68e':
 raise ValueError('original_retirement_source_mismatch')
current_boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
if current_boot!=epoch['current_boot_id'] or re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',current_boot) is None:
 raise ValueError('current_activation_epoch_mismatch')
expected_mode='same_boot_exact_retirement' if current_boot==BINDING['boot_id'] else 'new_boot_process_epoch'
if epoch['mode']!=expected_mode:
 raise ValueError('activation_epoch_mode_mismatch')
assert LEDGER.resolve()==LEDGER
lock=os.open(LEDGER/'ledger.lock',os.O_RDONLY|os.O_NOFOLLOW)
try:
 info=os.fstat(lock)
 assert stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1
 fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
 action=BINDING['action_id']
 intent_raw=read(LEDGER/(action+'.intent.json'))
 proof_raw=read(LEDGER/(action+'.retirement-proof.json'))
 resolution_raw=read(LEDGER/(action+'.resolution.json'),16384)
 assert sha(intent_raw)==BINDING['intent_sha256'] and sha(proof_raw)==BINDING['proof_sha256']
 assert len(resolution_raw)==1237 and sha(resolution_raw)==BINDING['resolution_sha256']=='7e06216823c49ec8b3949efa334e61b6731ca3f9bd4a039edbea771fb849a433','actual retained resolution differs'
 intent,proof,resolution=map(strict,(intent_raw,proof_raw,resolution_raw))
 assert resolution==BINDING['resolution'] and resolution['intent_sha256']==sha(intent_raw)
 assert proof['eligible_for_new_version_resolution'] is True and proof['external_review_verified'] is True
 assert proof['artifact_sha256']==BINDING['artifact_sha256'] and proof['details']['original_request_scope']==BINDING['scope']
 assert intent['action_id']==action and intent['command_sha256']==BINDING['command_sha256']
 for name,pin in BINDING['original_client_files'].items():
  assert sha(read(BASE/'client-receipts'/name,16384))==pin,'old client original changed'
 names=sorted(p.name for p in LEDGER.glob('*.intent.json'));assert len(names)<=1024
 for name in names:
  raw=read(LEDGER/name,16384);item=strict(raw)
  assert item['schema'] in ('hepta.action-intent.v150.1','hepta.action-intent.v150.2') and name==item['action_id']+'.intent.json'
  resolved=strict(read(LEDGER/(item['action_id']+'.resolution.json'),16384))
  assert resolved['action_id']==item['action_id'] and resolved['intent_sha256']==sha(raw)
  assert resolved['automatic_replay'] is False and resolved['business_verified'] is False
  if item['action_id']==action:assert resolved==resolution
  else:
   assert resolved['schema']=='hepta.action-resolution.v150.1'
   assert resolved['state'] in ('known_not_dispatched','original_native_result_independently_validated','original_sidecar_terminal_independently_inspected')
 assert names==sorted(p.name for p in LEDGER.glob('*.intent.json'))
finally:os.close(lock)
assert sha(AUDIT_SOURCE.encode())=='da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf'
audit_namespace={'__name__':'bound_native_read_only_audit'}
exec(compile(AUDIT_SOURCE,'frozen_native_audit','exec'),audit_namespace)
scope=BINDING['scope'];selected=[];scanned=0
J=Path('/var/lib/trillionnium/owner-open/turn-events.jsonl.segments')
files=sorted(J.glob('*.jsonl'));assert len(files)<=1024 and J.resolve()==J
for path in files:
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  info=os.fstat(fd);assert stat.S_ISREG(info.st_mode) and info.st_nlink==1
  scanned+=info.st_size;assert scanned<=64*1024*1024
  with os.fdopen(fd,'rb',closefd=False) as stream:
   while True:
    line=stream.readline(4*1024*1024+1)
    if not line:break
    assert len(line)<=4*1024*1024
    if not line.endswith(b'\n') or scope['turn_id'].encode() not in line:continue
    row=strict(line)
    if row.get('scope')==scope:selected.append(row)
 finally:os.close(fd)
selected.sort(key=lambda row:row['turn_seq'])
assert [row['record_sha256'] for row in selected]==BINDING['native_record_sha256'],'original native records changed'
audited=audit_namespace['verify_records'](selected,scope)
assert audited['status']=='PASS' and audited['frames'][-1]['payload']['status']=='provider_failed'
assert all(row['payload']['request_sha256']==BINDING['native_request_sha256'] for row in selected)
print(json.dumps({'schema':'hepta.sender-retirement-gate.v150.r4','state':'original_retirement_verified',
'original_scope':scope,'original_native_request_sha256':BINDING['native_request_sha256'],
'original_action_id':action,'proof_sha256':sha(proof_raw),'resolution_sha256':sha(resolution_raw),
'original_native_status':'provider_failed','native_record_hashes_verified':len(selected),
'global_action_gate_clear':True,'live_intent_count':len(names),'phone_writes':0,'effects_dispatched':0,
'old_request_replay_authorized':False},separators=(',',':')))
