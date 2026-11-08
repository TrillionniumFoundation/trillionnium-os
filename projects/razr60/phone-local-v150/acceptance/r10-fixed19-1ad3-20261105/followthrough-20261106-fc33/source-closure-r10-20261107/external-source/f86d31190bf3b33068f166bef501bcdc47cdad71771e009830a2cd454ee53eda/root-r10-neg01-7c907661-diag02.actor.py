from pathlib import Path
import hashlib,json,os,re,shlex,time,types,xml.etree.ElementTree as ET
m=Path('/home/alex/codex-preserved-ui-root12-materials-20261101-01');p=m/'preserved_ui_package_phase_r7.py';b=p.read_bytes();assert hashlib.sha256(b).hexdigest()=='6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b'
f=types.ModuleType('actual_app_fixed_turn');f.__file__=str(p);exec(compile(b,str(p),'exec'),f.__dict__);c=json.loads((m/'preserved-ui-package-config.json').read_text());t=f.route(c)
assert f.read('cat /proc/sys/kernel/random/boot_id',c,t)=='f8019f83-20a7-4f18-bea1-51c980621e4d'
assert f.read('getprop sys.usb.config',c,t)=='adb'
assert f.read('getenforce',c,t)=='Enforcing'
root=lambda q:f.shell('/debug_ramdisk/su -c '+shlex.quote(q),c,t)
assert root('getprop trillionnium.owner_open.ready')['stdout'].strip()=='1'
label='root-r10-neg01-7c907661-diag02'
reset_probe=False
preserved_draft=' 你好'
retirement_binding={'action_id': 'fc7bd6d939fb740a6403a04521fbb057', 'intent_sha256': '37f047bc0f06ad65eb5c20673e45eba4b257df864d5482ae454f553eba7cb417', 'command_sha256': '7976b489740b138a22fb8d724f953af92b7a1e3a1c15b5b60941482ab497487f', 'proof_sha256': '2bdd6c33c42359f1b27567b99627f7223d40a0c37f6af0158b8dc010e899943e', 'artifact_sha256': {'after': '740e70772a71a3b12bcddb4488452d497960781a7aa2ea021e7e379183d1457e', 'before': 'ee698fc195b52360b87b9196163d0bd32b3455daa6769b91dfd67a93e8c26744', 'native_records': '3acdcdbde2ce5673816751664a706c11a07b3fc1976f7a598af398cdc4f4f806', 'native_report': 'd94e0ca4b809073abe1bd8750837e1107ca7837eb9c44a85ce7325bd6f229818'}, 'resolution_sha256': '7e06216823c49ec8b3949efa334e61b6731ca3f9bd4a039edbea771fb849a433', 'resolution': {'action_id': 'fc7bd6d939fb740a6403a04521fbb057', 'automatic_replay': False, 'business_verified': False, 'future_executor_binding': {'client_path': '/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6.py', 'client_sha256': '500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f', 'endpoint': 'hepta_phone_executor_v150_r6', 'revision': 6}, 'intent_sha256': '37f047bc0f06ad65eb5c20673e45eba4b257df864d5482ae454f553eba7cb417', 'observed_utc': '2026-11-03T18:17:10.103595+00:00', 'old_effect_replay_forbidden': True, 'original_task_terminal_unchanged': True, 'retired_executor': {'actions_dev': 65086, 'actions_ino': 136105, 'binary_sha256': '30a495061ec8370e15391fd579a254ce35818c7b019725538e0a34755a36ccaa', 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'endpoint': 'hepta_phone_local_v150', 'pid': 31206, 'server_instance': 'ec17ea0567048b7094ac702fa4321d7d', 'source_sha256': 'beedc3a1a178d4b75887773e8ea1feae508cef89a692b35a03da3134893cafb4', 'start_ticks': 6437072}, 'retirement_proof_sha256': '2bdd6c33c42359f1b27567b99627f7223d40a0c37f6af0158b8dc010e899943e', 'schema': 'hepta.action-resolution.v150.2', 'state': 'confirmed_not_executed_after_executor_retirement', 'verifier_sha256': '6645922db85d02d71b1b8a9542af19ef6b343d5c599c91c0c4f9bb96757fe981'}, 'scope': {'profile_id': 'owner-open', 'session_id': 'session-ee897738-8fc2-4d3e-a916-5fe368b340ef', 'task_id': 'task-d3f61033-5b61-40e4-b8c6-7ea00d6b2d56', 'turn_id': 'turn-7a71e2ea-dd79-4eef-8310-2c986aa2701f', 'turn_stream_id': 'r5-stream-de6066d574abdf08ebba4677b633cb6e9926cdb634030410e87c9a58b95217ed'}, 'native_request_sha256': '860acef29450013940ddedf8ed50d1d826d7ce02352dcf0155f4aab7bbd2f57a', 'native_record_sha256': ['90c2da102dca1e0f16f2f948af684c401a77c2774ede113ef4317866aa145503', '1af982a955ecbfc0a80fbf197cdf88893c45a1fff06e7a6936ba298bc9fd42d9', 'e4685cfd3dd3a6fe556726ae919b5f0b0bb855d9dd041b9e6b45bfd35efce115', '022bafcb2f0facb9d6539abd2736cb868db943f4275b752ddda6ba4b284deea1', 'a608869dff90f36b6a250e36719ed14b68f2c560a4ae77744e6cb7e8486c269b', 'fc1331255a90b2d1046c06d3c1175c12640b74b7845c2a91a8cf4837eb5c6018', 'f4914c84cfdcda4d749c92ef35ceb895c6e9da6017c653a657349c7fc5741072'], 'original_client_files': {'fc7bd6d939fb740a6403a04521fbb057.claim.json': '78541235ce196d823f10486d3c99dbad097ba3ce7dff12ecc133719a62751179', 'fc7bd6d939fb740a6403a04521fbb057.result.json': '4849c26693888db4cdae9f4ac89ff3fc868b0b86162a0ce64a9403cf367eab09'}, 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d'}
retirement_prior=False
evidence_mode='component'
RETIREMENT_READ_GUARD_SOURCE='import base64,fcntl,hashlib,json,os,re,stat\nfrom pathlib import Path\nBINDING={\'action_id\': \'fc7bd6d939fb740a6403a04521fbb057\', \'intent_sha256\': \'37f047bc0f06ad65eb5c20673e45eba4b257df864d5482ae454f553eba7cb417\', \'command_sha256\': \'7976b489740b138a22fb8d724f953af92b7a1e3a1c15b5b60941482ab497487f\', \'proof_sha256\': \'2bdd6c33c42359f1b27567b99627f7223d40a0c37f6af0158b8dc010e899943e\', \'artifact_sha256\': {\'after\': \'740e70772a71a3b12bcddb4488452d497960781a7aa2ea021e7e379183d1457e\', \'before\': \'ee698fc195b52360b87b9196163d0bd32b3455daa6769b91dfd67a93e8c26744\', \'native_records\': \'3acdcdbde2ce5673816751664a706c11a07b3fc1976f7a598af398cdc4f4f806\', \'native_report\': \'d94e0ca4b809073abe1bd8750837e1107ca7837eb9c44a85ce7325bd6f229818\'}, \'resolution_sha256\': \'7e06216823c49ec8b3949efa334e61b6731ca3f9bd4a039edbea771fb849a433\', \'resolution\': {\'action_id\': \'fc7bd6d939fb740a6403a04521fbb057\', \'automatic_replay\': False, \'business_verified\': False, \'future_executor_binding\': {\'client_path\': \'/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6.py\', \'client_sha256\': \'500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f\', \'endpoint\': \'hepta_phone_executor_v150_r6\', \'revision\': 6}, \'intent_sha256\': \'37f047bc0f06ad65eb5c20673e45eba4b257df864d5482ae454f553eba7cb417\', \'observed_utc\': \'2026-11-03T18:17:10.103595+00:00\', \'old_effect_replay_forbidden\': True, \'original_task_terminal_unchanged\': True, \'retired_executor\': {\'actions_dev\': 65086, \'actions_ino\': 136105, \'binary_sha256\': \'30a495061ec8370e15391fd579a254ce35818c7b019725538e0a34755a36ccaa\', \'boot_id\': \'f8019f83-20a7-4f18-bea1-51c980621e4d\', \'endpoint\': \'hepta_phone_local_v150\', \'pid\': 31206, \'server_instance\': \'ec17ea0567048b7094ac702fa4321d7d\', \'source_sha256\': \'beedc3a1a178d4b75887773e8ea1feae508cef89a692b35a03da3134893cafb4\', \'start_ticks\': 6437072}, \'retirement_proof_sha256\': \'2bdd6c33c42359f1b27567b99627f7223d40a0c37f6af0158b8dc010e899943e\', \'schema\': \'hepta.action-resolution.v150.2\', \'state\': \'confirmed_not_executed_after_executor_retirement\', \'verifier_sha256\': \'6645922db85d02d71b1b8a9542af19ef6b343d5c599c91c0c4f9bb96757fe981\'}, \'scope\': {\'profile_id\': \'owner-open\', \'session_id\': \'session-ee897738-8fc2-4d3e-a916-5fe368b340ef\', \'task_id\': \'task-d3f61033-5b61-40e4-b8c6-7ea00d6b2d56\', \'turn_id\': \'turn-7a71e2ea-dd79-4eef-8310-2c986aa2701f\', \'turn_stream_id\': \'r5-stream-de6066d574abdf08ebba4677b633cb6e9926cdb634030410e87c9a58b95217ed\'}, \'native_request_sha256\': \'860acef29450013940ddedf8ed50d1d826d7ce02352dcf0155f4aab7bbd2f57a\', \'native_record_sha256\': [\'90c2da102dca1e0f16f2f948af684c401a77c2774ede113ef4317866aa145503\', \'1af982a955ecbfc0a80fbf197cdf88893c45a1fff06e7a6936ba298bc9fd42d9\', \'e4685cfd3dd3a6fe556726ae919b5f0b0bb855d9dd041b9e6b45bfd35efce115\', \'022bafcb2f0facb9d6539abd2736cb868db943f4275b752ddda6ba4b284deea1\', \'a608869dff90f36b6a250e36719ed14b68f2c560a4ae77744e6cb7e8486c269b\', \'fc1331255a90b2d1046c06d3c1175c12640b74b7845c2a91a8cf4837eb5c6018\', \'f4914c84cfdcda4d749c92ef35ceb895c6e9da6017c653a657349c7fc5741072\'], \'original_client_files\': {\'fc7bd6d939fb740a6403a04521fbb057.claim.json\': \'78541235ce196d823f10486d3c99dbad097ba3ce7dff12ecc133719a62751179\', \'fc7bd6d939fb740a6403a04521fbb057.result.json\': \'4849c26693888db4cdae9f4ac89ff3fc868b0b86162a0ce64a9403cf367eab09\'}, \'boot_id\': \'f8019f83-20a7-4f18-bea1-51c980621e4d\'}\nAUDIT_SOURCE=\'"""Read-only verification of the pinned native event-store v1 record format.\\n\\nSource: frozen source7/crates/trillionnium-owner-open-event-store/src/lib.rs,\\nSHA256 99b2f280ba4798cd8ee3f74fa9e9c901893c3a4949800dc13083d5842ac38018.\\nRecordPreimage field order is a Rust struct; payload Value maps are sorted.\\nFloats are deliberately unsupported: Python formatting is not Rust serde/ryu.\\nA filtered turn proves no unobserved global predecessor or whole-store chain.\\n"""\\nimport hashlib\\nimport json\\n\\nSCOPE_FIELDS = ("session_id", "profile_id", "task_id", "turn_id", "turn_stream_id")\\nRECORD_FIELDS = ("schema", "store_seq", "turn_seq", "scope", "event_id", "kind",\\n                 "payload", "payload_sha256", "previous_record_sha256")\\n\\ndef sha(raw):\\n    return hashlib.sha256(raw).hexdigest()\\n\\ndef strict_loads(raw):\\n    def unique(pairs):\\n        result = {}\\n        for key, value in pairs:\\n            if key in result:\\n                raise ValueError("duplicate JSON key")\\n            result[key] = value\\n        return result\\n    def invalid(value):\\n        raise ValueError("nonfinite JSON number: " + value)\\n    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)\\n\\ndef canonical_value(value):\\n    if value is None or type(value) in (str, bool):\\n        return value\\n    if type(value) is int:\\n        if not -(2**63) <= value <= 2**64-1:\\n            raise ValueError("integer outside serde_json i64/u64")\\n        return value\\n    if type(value) is float:\\n        raise ValueError("float serialization requires original Rust/ryu verifier")\\n    if isinstance(value, list):\\n        return [canonical_value(item) for item in value]\\n    if isinstance(value, dict):\\n        return {key: canonical_value(value[key]) for key in sorted(value)}\\n    raise ValueError("unsupported JSON value")\\n\\ndef encode(value):\\n    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")\\n\\ndef record_hashes(row):\\n    if set(row) != set(RECORD_FIELDS) | {"record_sha256"}:\\n        raise ValueError("native event record fields differ")\\n    if row["schema"] != "trillionnium.owner-open.event-record.v1":\\n        raise ValueError("native event record schema differs")\\n    scope = row["scope"]\\n    if set(scope) != set(SCOPE_FIELDS) or any(not isinstance(scope[k],str) or not scope[k]\\n                                            for k in SCOPE_FIELDS):\\n        raise ValueError("native record scope differs")\\n    payload = canonical_value(row["payload"])\\n    payload_hash = sha(encode(payload))\\n    preimage = {key: row[key] for key in RECORD_FIELDS}\\n    preimage["scope"] = {key: scope[key] for key in SCOPE_FIELDS}\\n    preimage["payload"] = payload\\n    return payload_hash, sha(encode(preimage))\\n\\ndef verify_records(records, scope):\\n    checks, errors, unsupported = [], [], []\\n    seen = {}\\n    for index, row in enumerate(records):\\n        try:\\n            store_seq = row["store_seq"]\\n            if type(store_seq) is not int or store_seq < 0:\\n                raise ValueError("invalid store sequence")\\n            if store_seq in seen:\\n                raise ValueError("duplicate store sequence in supplied evidence")\\n            seen[store_seq] = row\\n            payload_hash, record_hash = record_hashes(row)\\n            if payload_hash != row["payload_sha256"] or record_hash != row["record_sha256"]:\\n                raise ValueError("native record payload/preimage hash differs")\\n            checks.append(store_seq)\\n        except (KeyError, TypeError, ValueError, UnicodeError) as error:\\n            issue = {"input_index": index, "store_seq": row.get("store_seq") if isinstance(row,dict) else None,\\n                     "error": str(error)}\\n            (unsupported if "float serialization" in str(error) else errors).append(issue)\\n    ordered = sorted(seen.values(), key=lambda row: row["store_seq"])\\n    adjacent, gaps = [], []\\n    for previous, current in zip(ordered, ordered[1:]):\\n        if current["store_seq"] == previous["store_seq"] + 1:\\n            if current["previous_record_sha256"] != previous["record_sha256"]:\\n                errors.append({"store_seq": current["store_seq"], "error": "global predecessor hash differs"})\\n            else:\\n                adjacent.append([previous["store_seq"], current["store_seq"]])\\n        else:\\n            gaps.append([previous["store_seq"], current["store_seq"]])\\n    selected = [row for row in ordered if row.get("scope") == scope]\\n    if not selected:\\n        errors.append({"error": "selected scope has no original native records"})\\n    elif [row["turn_seq"] for row in selected] != list(range(len(selected))):\\n        errors.append({"error": "selected scope turn_seq is incomplete, duplicated or unordered"})\\n    frames = []\\n    for row in selected:\\n        try:\\n            frame = row["payload"]["frame"]\\n            if any(frame.get(key) != scope[key] for key in SCOPE_FIELDS):\\n                raise ValueError("native frame scope differs")\\n            if frame.get("kind") != row["kind"] or frame.get("event_id") != row["event_id"]:\\n                raise ValueError("native frame event identity differs")\\n            frames.append(frame)\\n        except (KeyError, TypeError, ValueError) as error:\\n            errors.append({"store_seq":row["store_seq"],"error":str(error)})\\n    if frames:\\n        if [frame.get("host_seq") for frame in frames] != list(range(len(frames))):\\n            errors.append({"error":"native frame host sequence incomplete"})\\n        if frames[0].get("kind") != "turn.accepted" or frames[-1].get("kind") != "turn.end":\\n            errors.append({"error":"selected native turn lacks accepted/end boundary"})\\n        digests = [row["payload"].get("request_sha256") for row in selected]\\n        if not isinstance(digests[0],str) or len(set(digests)) != 1:\\n            errors.append({"error":"native turn request binding differs across records"})\\n        elif any(frame.get("payload",{}).get("turn_request_sha256") != digests[0] for frame in frames):\\n            errors.append({"error":"native frame request binding differs"})\\n    return {\\n        "status": "PASS" if not errors and not unsupported else "UNVERIFIED" if unsupported and not errors else "FAIL",\\n        "record_count":len(records), "record_hashes_verified":len(checks),\\n        "selected_scope_record_count":len(selected),\\n        "adjacent_global_predecessor_links_verified":len(adjacent),\\n        "unobserved_global_sequence_gaps":gaps,\\n        "global_chain_complete":False,\\n        "global_chain_limit":"Only supplied adjacent records checked; no unseen predecessor/genesis attested.",\\n        "errors":errors,"unsupported":unsupported,\\n        "selected_records":selected,"frames":frames,\\n    }\\n\'\ndef sha(raw):return hashlib.sha256(raw).hexdigest()\ndef strict(raw):\n def pairs(items):\n  value={}\n  for key,item in items:\n   assert key not in value,\'duplicate key\';value[key]=item\n  return value\n return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda value:(_ for _ in ()).throw(ValueError(\'nonfinite JSON\')))\ndef read(path,limit=262144):\n path=Path(path)\n assert path.parent.resolve(strict=True)==path.parent,\'noncanonical parent\'\n fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)\n try:\n  before=os.fstat(fd)\n  assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.getuid() and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=limit,\'private file bound/type\'\n  with os.fdopen(fd,\'rb\',closefd=False) as stream:raw=stream.read(limit+1)\n  after=os.fstat(fd);named=path.lstat()\n  assert len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k)==getattr(named,k) for k in (\'st_dev\',\'st_ino\',\'st_size\',\'st_mtime_ns\',\'st_ctime_ns\',\'st_nlink\')),\'file changed\'\n finally:os.close(fd)\n return raw\nBASE=Path(\'/var/lib/trillionnium/owner-open/phone-local-v150\')\nLEDGER=BASE/\'provider-state/evidence/action-ledger\'\nassert Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip()==BINDING[\'boot_id\'],\'wrong boot\'\nassert LEDGER.resolve()==LEDGER\nlock=os.open(LEDGER/\'ledger.lock\',os.O_RDONLY|os.O_NOFOLLOW)\ntry:\n info=os.fstat(lock)\n assert stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1\n fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)\n action=BINDING[\'action_id\']\n intent_raw=read(LEDGER/(action+\'.intent.json\'))\n proof_raw=read(LEDGER/(action+\'.retirement-proof.json\'))\n resolution_raw=read(LEDGER/(action+\'.resolution.json\'),16384)\n assert sha(intent_raw)==BINDING[\'intent_sha256\'] and sha(proof_raw)==BINDING[\'proof_sha256\']\n assert len(resolution_raw)==1237 and sha(resolution_raw)==BINDING[\'resolution_sha256\']==\'7e06216823c49ec8b3949efa334e61b6731ca3f9bd4a039edbea771fb849a433\',\'actual retained resolution differs\'\n intent,proof,resolution=map(strict,(intent_raw,proof_raw,resolution_raw))\n assert resolution==BINDING[\'resolution\'] and resolution[\'intent_sha256\']==sha(intent_raw)\n assert proof[\'eligible_for_new_version_resolution\'] is True and proof[\'external_review_verified\'] is True\n assert proof[\'artifact_sha256\']==BINDING[\'artifact_sha256\'] and proof[\'details\'][\'original_request_scope\']==BINDING[\'scope\']\n assert intent[\'action_id\']==action and intent[\'command_sha256\']==BINDING[\'command_sha256\']\n for name,pin in BINDING[\'original_client_files\'].items():\n  assert sha(read(BASE/\'client-receipts\'/name,16384))==pin,\'old client original changed\'\n names=sorted(p.name for p in LEDGER.glob(\'*.intent.json\'));assert len(names)<=1024\n for name in names:\n  raw=read(LEDGER/name,16384);item=strict(raw)\n  assert item[\'schema\'] in (\'hepta.action-intent.v150.1\',\'hepta.action-intent.v150.2\') and name==item[\'action_id\']+\'.intent.json\'\n  resolved=strict(read(LEDGER/(item[\'action_id\']+\'.resolution.json\'),16384))\n  assert resolved[\'action_id\']==item[\'action_id\'] and resolved[\'intent_sha256\']==sha(raw)\n  assert resolved[\'automatic_replay\'] is False and resolved[\'business_verified\'] is False\n  if item[\'action_id\']==action:assert resolved==resolution\n  else:\n   assert resolved[\'schema\']==\'hepta.action-resolution.v150.1\'\n   assert resolved[\'state\'] in (\'known_not_dispatched\',\'original_native_result_independently_validated\',\'original_sidecar_terminal_independently_inspected\')\n assert names==sorted(p.name for p in LEDGER.glob(\'*.intent.json\'))\nfinally:os.close(lock)\nassert sha(AUDIT_SOURCE.encode())==\'da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf\'\naudit_namespace={\'__name__\':\'bound_native_read_only_audit\'}\nexec(compile(AUDIT_SOURCE,\'frozen_native_audit\',\'exec\'),audit_namespace)\nscope=BINDING[\'scope\'];selected=[];scanned=0\nJ=Path(\'/var/lib/trillionnium/owner-open/turn-events.jsonl.segments\')\nfiles=sorted(J.glob(\'*.jsonl\'));assert len(files)<=1024 and J.resolve()==J\nfor path in files:\n fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)\n try:\n  info=os.fstat(fd);assert stat.S_ISREG(info.st_mode) and info.st_nlink==1\n  scanned+=info.st_size;assert scanned<=64*1024*1024\n  with os.fdopen(fd,\'rb\',closefd=False) as stream:\n   while True:\n    line=stream.readline(4*1024*1024+1)\n    if not line:break\n    assert len(line)<=4*1024*1024\n    if not line.endswith(b\'\\n\') or scope[\'turn_id\'].encode() not in line:continue\n    row=strict(line)\n    if row.get(\'scope\')==scope:selected.append(row)\n finally:os.close(fd)\nselected.sort(key=lambda row:row[\'turn_seq\'])\nassert [row[\'record_sha256\'] for row in selected]==BINDING[\'native_record_sha256\'],\'original native records changed\'\naudited=audit_namespace[\'verify_records\'](selected,scope)\nassert audited[\'status\']==\'PASS\' and audited[\'frames\'][-1][\'payload\'][\'status\']==\'provider_failed\'\nassert all(row[\'payload\'][\'request_sha256\']==BINDING[\'native_request_sha256\'] for row in selected)\nprint(json.dumps({\'schema\':\'hepta.sender-retirement-gate.v150.r4\',\'state\':\'original_retirement_verified\',\n\'original_scope\':scope,\'original_native_request_sha256\':BINDING[\'native_request_sha256\'],\n\'original_action_id\':action,\'proof_sha256\':sha(proof_raw),\'resolution_sha256\':sha(resolution_raw),\n\'original_native_status\':\'provider_failed\',\'native_record_hashes_verified\':len(selected),\n\'global_action_gate_clear\':True,\'live_intent_count\':len(names),\'phone_writes\':0,\'effects_dispatched\':0,\n\'old_request_replay_authorized\':False},separators=(\',\',\':\')))\n'
component_binding={'schema': 'hepta.native-guard.sender-binding.v1', 'contract': {'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'case_id': 'NEG-01', 'combination_sha256': '765e66acedee58e41de0ef45b6ea8061709e5b63a7aef43437876349289e86ec', 'expires_unix_ms': 1793904925714, 'label': 'root-r10-neg01-7c907661-diag02', 'lease_sha256': '9c420ebd9b1e7b24847fab5e2851921c3857f80c9281514e806a8bbe8ac790e3', 'nonce': '8daaaad6a322963e87973613c1fac762', 'owner_request_sha256': 'caa9a5091e758975ef1b94903f0cd06705f88ef8c9fe94cc8a17e773240a777f', 'package_sha256': '8e5ba081f1780da2ec73a3c103e7a27f6a0ba4e6e15ceab502fa8221ed410863', 'schema': 'hepta.native-guard.sender-contract.v1', 'selected_profile_id': 'owner-open', 'selected_session_id': 'session-ee897738-8fc2-4d3e-a916-5fe368b340ef'}, 'contract_sha256': '7a6c72fa309e79fc8de182e9177a6556371dafffd82e918eb29dda6e8ec5d2fb', 'contract_bytes': 683, 'contract_original_b64': 'eyJib290X2lkIjoiZjgwMTlmODMtMjBhNy00ZjE4LWJlYTEtNTFjOTgwNjIxZTRkIiwiY2FzZV9pZCI6Ik5FRy0wMSIsImNvbWJpbmF0aW9uX3NoYTI1NiI6Ijc2NWU2NmFjZWRlZTU4ZTQxZGUwZWY0NWI2ZWE4MDYxNzA5ZTViNjNhN2FlZjQzNDM3ODc2MzQ5Mjg5ZTg2ZWMiLCJleHBpcmVzX3VuaXhfbXMiOjE3OTM5MDQ5MjU3MTQsImxhYmVsIjoicm9vdC1yMTAtbmVnMDEtN2M5MDc2NjEtZGlhZzAyIiwibGVhc2Vfc2hhMjU2IjoiOWM0MjBlYmQ5YjFlN2IyNDg0N2ZhYjVlMjg1MTkyMWMzODU3ZjgwYzkyODE1MTRlODA2YThiYmU4YWM3OTBlMyIsIm5vbmNlIjoiOGRhYWFhZDZhMzIyOTYzZTg3OTczNjEzYzFmYWM3NjIiLCJvd25lcl9yZXF1ZXN0X3NoYTI1NiI6ImNhYTlhNTA5MWU3NTg5NzVlZjFiOTQ5MDNmMGNkMDY3MDVmODhlZjhjOWZlOTRjYzhhMTdlNzczMjQwYTc3N2YiLCJwYWNrYWdlX3NoYTI1NiI6IjhlNWJhMDgxZjE3ODBkYTJlYzczYTNjMTAzZTdhMjdmNmEwYmE0ZTZlMTVjZWFiNTAyZmE4MjIxZWQ0MTA4NjMiLCJzY2hlbWEiOiJoZXB0YS5uYXRpdmUtZ3VhcmQuc2VuZGVyLWNvbnRyYWN0LnYxIiwic2VsZWN0ZWRfcHJvZmlsZV9pZCI6Im93bmVyLW9wZW4iLCJzZWxlY3RlZF9zZXNzaW9uX2lkIjoic2Vzc2lvbi1lZTg5NzczOC04ZmMyLTRkM2UtYTkxNi01ZmUzNjhiMzQwZWYifQo=', 'source_sha256': 'ad345c0080cbfd89f1378bb6e8583f43e1fa4af0a5928d7ecbf4ccc8d4f04c52', 'common_pin': {'bytes': 19138, 'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}, 'lifecycle_pin': {'bytes': 40261, 'sha256': '144836347482b8871703b882283ffac63d5df480e3333a9bd631409f890fc1c2'}, 'phone_home': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02', 'phone_contract_path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02/sender-contract.json', 'phone_ready_path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02/READY.json', 'phone_source_path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02/package/source/component_listener.py'}
COMPONENT_READY_PROBE_SOURCE="\nimport base64,hashlib,json,os,stat,sys,time,types\nfrom pathlib import Path\nsys.dont_write_bytecode=True\nB={'schema': 'hepta.native-guard.sender-binding.v1', 'contract': {'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'case_id': 'NEG-01', 'combination_sha256': '765e66acedee58e41de0ef45b6ea8061709e5b63a7aef43437876349289e86ec', 'expires_unix_ms': 1793904925714, 'label': 'root-r10-neg01-7c907661-diag02', 'lease_sha256': '9c420ebd9b1e7b24847fab5e2851921c3857f80c9281514e806a8bbe8ac790e3', 'nonce': '8daaaad6a322963e87973613c1fac762', 'owner_request_sha256': 'caa9a5091e758975ef1b94903f0cd06705f88ef8c9fe94cc8a17e773240a777f', 'package_sha256': '8e5ba081f1780da2ec73a3c103e7a27f6a0ba4e6e15ceab502fa8221ed410863', 'schema': 'hepta.native-guard.sender-contract.v1', 'selected_profile_id': 'owner-open', 'selected_session_id': 'session-ee897738-8fc2-4d3e-a916-5fe368b340ef'}, 'contract_sha256': '7a6c72fa309e79fc8de182e9177a6556371dafffd82e918eb29dda6e8ec5d2fb', 'contract_bytes': 683, 'contract_original_b64': 'eyJib290X2lkIjoiZjgwMTlmODMtMjBhNy00ZjE4LWJlYTEtNTFjOTgwNjIxZTRkIiwiY2FzZV9pZCI6Ik5FRy0wMSIsImNvbWJpbmF0aW9uX3NoYTI1NiI6Ijc2NWU2NmFjZWRlZTU4ZTQxZGUwZWY0NWI2ZWE4MDYxNzA5ZTViNjNhN2FlZjQzNDM3ODc2MzQ5Mjg5ZTg2ZWMiLCJleHBpcmVzX3VuaXhfbXMiOjE3OTM5MDQ5MjU3MTQsImxhYmVsIjoicm9vdC1yMTAtbmVnMDEtN2M5MDc2NjEtZGlhZzAyIiwibGVhc2Vfc2hhMjU2IjoiOWM0MjBlYmQ5YjFlN2IyNDg0N2ZhYjVlMjg1MTkyMWMzODU3ZjgwYzkyODE1MTRlODA2YThiYmU4YWM3OTBlMyIsIm5vbmNlIjoiOGRhYWFhZDZhMzIyOTYzZTg3OTczNjEzYzFmYWM3NjIiLCJvd25lcl9yZXF1ZXN0X3NoYTI1NiI6ImNhYTlhNTA5MWU3NTg5NzVlZjFiOTQ5MDNmMGNkMDY3MDVmODhlZjhjOWZlOTRjYzhhMTdlNzczMjQwYTc3N2YiLCJwYWNrYWdlX3NoYTI1NiI6IjhlNWJhMDgxZjE3ODBkYTJlYzczYTNjMTAzZTdhMjdmNmEwYmE0ZTZlMTVjZWFiNTAyZmE4MjIxZWQ0MTA4NjMiLCJzY2hlbWEiOiJoZXB0YS5uYXRpdmUtZ3VhcmQuc2VuZGVyLWNvbnRyYWN0LnYxIiwic2VsZWN0ZWRfcHJvZmlsZV9pZCI6Im93bmVyLW9wZW4iLCJzZWxlY3RlZF9zZXNzaW9uX2lkIjoic2Vzc2lvbi1lZTg5NzczOC04ZmMyLTRkM2UtYTkxNi01ZmUzNjhiMzQwZWYifQo=', 'source_sha256': 'ad345c0080cbfd89f1378bb6e8583f43e1fa4af0a5928d7ecbf4ccc8d4f04c52', 'common_pin': {'bytes': 19138, 'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}, 'lifecycle_pin': {'bytes': 40261, 'sha256': '144836347482b8871703b882283ffac63d5df480e3333a9bd631409f890fc1c2'}, 'phone_home': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02', 'phone_contract_path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02/sender-contract.json', 'phone_ready_path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02/READY.json', 'phone_source_path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02/package/source/component_listener.py'}\ndef need(ok,why):\n if not ok:raise ValueError(why)\ndef initial_read(path,maximum):\n path=Path(path)\n need(path.is_absolute() and path.parent.resolve()==path.parent,'canonical GNU package parent')\n fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)\n try:\n  before=os.fstat(fd)\n  need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==0 and stat.S_IMODE(before.st_mode)==0o600 and before.st_size<=maximum,'private bootstrap source identity')\n  with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(maximum+1)\n  after=os.fstat(fd);named=path.lstat()\n  names=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')\n  need(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k)==getattr(named,k) for k in names),'bootstrap source changed')\n  return raw\n finally:os.close(fd)\nhome=Path(B['phone_home']);c=B['contract'];cp=home/'package/source/component_common.py'\nraw=initial_read(cp,262144)\nneed(len(raw)==B['common_pin']['bytes'] and hashlib.sha256(raw).hexdigest()==B['common_pin']['sha256'],'pinned common source differs')\nC=types.ModuleType('component_common');C.__file__=str(cp);sys.modules['component_common']=C\nexec(compile(raw,str(cp),'exec'),C.__dict__)\nmanifest=C.verify_package(home/'package/MANIFEST.json',c['package_sha256'])\nprofile_path=home/'package/source/native_proc_profile.py'\nprofile_rows=[row for row in manifest['files'] if row['path']=='source/native_proc_profile.py']\nneed(len(profile_rows)==1 and 'native_proc_profile' not in sys.modules,'one fresh pinned native proc profile required')\nprofile_raw=C.pinned(profile_path,{key:profile_rows[0][key] for key in ('bytes','sha256')})\nprofile=types.ModuleType('native_proc_profile');profile.__file__=str(profile_path)\nsys.modules['native_proc_profile']=profile\nexec(compile(profile_raw,str(profile_path),'exec'),profile.__dict__)\nL=C.import_pinned(home/'package/source/component_lifecycle.py',B['lifecycle_pin'],'sender_readonly_lifecycle')\nlease,lease_raw=L.load_lease(home,c['lease_sha256']);L.native_root(c['boot_id'])\nneed(all(lease[k]==c[k] for k in ('label','nonce','case_id','boot_id','owner_request_sha256','selected_session_id','selected_profile_id','expires_unix_ms','package_sha256')) and lease['combination']['sha256']==c['combination_sha256'],'phone lease differs from selected Root contract')\nneed(C.read(home/'sender-contract.json')==base64.b64decode(B['contract_original_b64'],validate=True),'original sender contract differs')\ncombo_raw=C.pinned(home/'inputs/COMBINATION.json',lease['combination'])\ncombo,_=C.load_combination(home/'inputs',combo_raw,C.strict(C.read(home/'package/reference/REVIEWED-PRODUCTION-PINS.json')))\nC.verify_external(combo)\nfor name,pin in lease['retirement'].items():\n path=Path(pin['path']);C.pinned(path,{k:pin[k] for k in ('bytes','sha256')},16*1024*1024)\n need(C.metadata(path.lstat())==pin['metadata'],'original retirement identity differs')\nproof=C.strict(C.read(Path(lease['retirement']['proof']['path']),16*1024*1024))\nneed(proof['state']=='ORIGINAL_FOUR_GROUPS_ABSENT_STATE_PRESERVED','original retirement state differs')\nC.absent_groups(list(proof['original_role_identities'].values()))\nneed(not list(C.private_dir(home/'claims').iterdir()),'component one-use claim already exists')\nfor name in ('CONNECTION-ACCEPTED.json','ACCEPTED.json','PROVIDER-ENDED.json','LIFECYCLE-ENDED.json','LIFECYCLE-FAILURE.json'):\n try:(home/name).lstat()\n except FileNotFoundError:pass\n else:need(False,'component already consumed or ended')\ntry:ready_raw=C.read(home/'READY.json',65536)\nexcept FileNotFoundError:\n print(json.dumps({'state':'waiting_for_ready','contract_sha256':B['contract_sha256'],'nonce':c['nonce'],'owner_request_sha256':c['owner_request_sha256'],'claim_absent':True,'ended_absent':True},separators=(',',':')))\n raise SystemExit(0)\nready=C.strict(ready_raw);bound_raw=C.read(home/'BOUND-CONTRACT.json',65536);bound=C.strict(bound_raw)\nsupervisor_raw=C.read(home/'SUPERVISOR.json',16384);supervisor=C.strict(supervisor_raw)\nroles={name:C.target_identity(row['identity'][0],row['identity']) for name,row in [('provider',ready['identity']),('sidecar',bound['sidecar_identity']),('supervisor',supervisor)]}\npython=combo['artifacts']['python']['path']\nsuper_argv=[python,'-I','-B',str(home/'package/source/component_lifecycle.py'),'--lease',str(home),'--lease-sha256',c['lease_sha256'],'--package',str(home/'package/MANIFEST.json'),'--package-sha256',c['package_sha256'],'--execute-component-lifecycle-once']\nspawn=C.strict(C.read(home/'provider.SPAWNED.json',65536));argv=spawn['argv'];need(argv[-2]=='--listener-fd' and argv[-1].isdigit(),'original provider listener fd absent')\nprovider_argv=[python,'-I','-B',str(home/'package/source/component_listener.py'),'--package',str(home/'package/MANIFEST.json'),'--package-sha256',c['package_sha256'],'--lease',str(home),'--lease-sha256',c['lease_sha256'],'--listener-fd',argv[-1],'--execute-native-listener-once']\nsidecar_argv=[C.SIDECAR,'--state-dir',lease['android_journal']]\nfor name,wanted in [('supervisor',super_argv),('provider',provider_argv),('sidecar',sidecar_argv)]:\n actual=base64.b64decode(roles[name]['argv_b64'],validate=True)\n need(actual==b'\\0'.join(x.encode() for x in wanted)+b'\\0' and roles[name]['argv_sha256']==C.sha(actual),'actual owned role argv differs')\n need(roles[name]['exe']==(C.SIDECAR if name=='sidecar' else python),'actual owned role executable differs')\nnow=time.monotonic_ns();wall=time.time_ns()//1000000\nvalue={'schema':'hepta.native-guard.readiness-observation.v1','state':'ready_observed','contract_sha256':B['contract_sha256'],'provider_source_sha256':B['source_sha256'],'package_sha256':c['package_sha256'],'boot_id':c['boot_id'],'ready':ready,'ready_sha256':C.sha(ready_raw),'ready_original_b64':base64.b64encode(ready_raw).decode(),'bound':bound,'bound_sha256':C.sha(bound_raw),'bound_original_b64':base64.b64encode(bound_raw).decode(),'supervisor':supervisor,'supervisor_sha256':C.sha(supervisor_raw),'supervisor_original_b64':base64.b64encode(supervisor_raw).decode(),'current_roles':roles,'combination':combo,'combination_sha256':C.sha(combo_raw),'combination_original_b64':base64.b64encode(combo_raw).decode(),'claim_absent':True,'connection_absent':True,'ended_absent':True,'retirement_originals_bound':True,'old_groups_absent':True,'socket_connections':0,'phone_monotonic_ns':now,'phone_unix_ms':wall,'remaining_accept_ns':ready['accept_deadline_monotonic_ns']-now}\ndef validate_ready_observation(value, binding, previous=None, minimum_remaining_ns=15000000000):\n    import base64,hashlib,json,re\n    def check(ok, why):\n        if not ok:\n            raise ValueError(why)\n    def digest(raw):\n        return hashlib.sha256(raw).hexdigest()\n    def original(key, parsed):\n        raw = base64.b64decode(value[key+'_original_b64'],validate=True)\n        check(digest(raw) == value[key+'_sha256'] and json.loads(raw) == parsed, 'original readiness bytes differ')\n        return raw\n    c = binding['contract']; r = value.get('ready',{}); b = value.get('bound',{}); roles = value.get('current_roles',{})\n    check(value.get('schema') == 'hepta.native-guard.readiness-observation.v1'\n          and value.get('state') == 'ready_observed', 'component readiness not observed')\n    check(value.get('contract_sha256') == binding['contract_sha256']\n          and value.get('provider_source_sha256') == binding['source_sha256']\n          and value.get('package_sha256') == c['package_sha256'] and value.get('boot_id') == c['boot_id'],\n          'component input pins or boot differ')\n    original('ready',r);original('bound',b)\n    combo = value.get('combination',{})\n    original('combination',combo)\n    check(value['combination_sha256'] == c['combination_sha256']\n          and combo.get('schema') == 'hepta.native-guard.component-combination.v150.r10.1'\n          and combo.get('state') == 'REVIEWED_COMPONENT_BYTES_NOT_FOUR_ROLE_READY',\n          'original component combination differs')\n    check(r.get('schema') == 'hepta.native-guard.ready.v1'\n          and r.get('lease_sha256') == c['lease_sha256'] and r.get('combination_sha256') == c['combination_sha256']\n          and r.get('provider_source_sha256') == binding['source_sha256'] and r.get('port') == 18080\n          and r.get('accepting_one_session') is True and r.get('model_requests') == 0\n          and r.get('readiness_scope') == 'isolated_component_transport_only' and r.get('four_role_ready') is False,\n          'component ready original contract differs')\n    bc = b.get('contract',{})\n    check(b.get('schema') == 'hepta.native-guard.bound-contract.v1' and b.get('lease_sha256') == c['lease_sha256']\n          and b.get('provider_source_sha256') == binding['source_sha256']\n          and set(bc) == {'schema','case_id','nonce','owner_request_sha256','selected_session_id','selected_profile_id',\n                         'source_seal_sha256','configuration_sha256','executor_server_instance'}\n          and bc.get('schema') == 'hepta.native-guard-component.contract.v150.r10.1'\n          and bc.get('source_seal_sha256') == combo.get('source_seal',{}).get('sha256')\n          and bc.get('configuration_sha256') == combo.get('configuration',{}).get('sha256')\n          and all(bc.get(k) == c[k] for k in ('case_id','nonce','owner_request_sha256','selected_session_id','selected_profile_id')),\n          'actual native component contract differs')\n    canonical = (json.dumps(bc,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)+'\\n').encode()\n    check(digest(canonical) == r['contract_sha256'] and re.fullmatch('[0-9a-f]{32}',bc.get('executor_server_instance','')),\n          'actual bound kernel contract bytes or executor instance differ')\n    check(set(roles) == {'supervisor','provider','sidecar'} and roles['provider'] == r['identity']\n          and roles['sidecar'] == b['sidecar_identity'] and roles['supervisor'] == value.get('supervisor'),\n          'actual live process identity differs')\n    original('supervisor',value['supervisor'])\n    for name,row in roles.items():\n        ident = row.get('identity',[])\n        check(len(ident) == 4 and all(type(x) is int and x > 1 for x in ident)\n              and ident[:3] == [ident[0]]*3 and row.get('uid') == row.get('gid') == [0]*4 and row.get('nnp') == 0,\n              'owned role process identity/credentials differ')\n        domain = 'u:r:trillionnium_owner_open_phone_executor:s0' if name == 'sidecar' else 'u:r:magisk:s0'\n        check(row.get('domain') == domain, 'owned role security domain differs')\n    check(roles['provider']['ppid'] == roles['sidecar']['ppid'] == roles['supervisor']['identity'][0],\n          'owned component parent changed')\n    health = b.get('sidecar_health',{})\n    check(health.get('executor_revision') == 6 and health.get('state') == 'ready'\n          and health.get('server_instance') == bc['executor_server_instance']\n          and health.get('execute_authorized') is False and health.get('inference_endpoint') is False,\n          'component parent readiness is not read-only')\n    check(value.get('claim_absent') is True and value.get('connection_absent') is True\n          and value.get('ended_absent') is True and value.get('retirement_originals_bound') is True\n          and value.get('old_groups_absent') is True and value.get('socket_connections') == 0,\n          'component consumed, ended or original retirement not verified')\n    times = [r.get(k) for k in ('ready_monotonic_ns','accept_deadline_monotonic_ns','service_deadline_monotonic_ns')]\n    now,wall = value.get('phone_monotonic_ns'),value.get('phone_unix_ms')\n    check(all(type(x) is int and x > 0 for x in times+[now,wall]), 'phone clock shape differs')\n    ready,accept,service = times\n    check(ready <= now < accept < service and accept-ready == 120000000000\n          and service-ready == 420000000000, 'component windows changed')\n    check(accept-now >= minimum_remaining_ns and value.get('remaining_accept_ns') == accept-now\n          and c['expires_unix_ms']-wall >= minimum_remaining_ns//1000000, 'component acceptance margin expired')\n    if previous is not None:\n        check(value['ready_sha256'] == previous['ready_sha256']\n              and value['bound_sha256'] == previous['bound_sha256']\n              and value['current_roles'] == previous['current_roles'], 'component readiness generation changed')\n    return value\n\nvalidate_ready_observation(value,B)\nneed(C.read(home/'READY.json',65536)==ready_raw and C.read(home/'BOUND-CONTRACT.json',65536)==bound_raw,'ready originals changed after process read')\nprint(json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False))\n"
import re
def validate_ready_observation(value, binding, previous=None, minimum_remaining_ns=15000000000):
    import base64,hashlib,json,re
    def check(ok, why):
        if not ok:
            raise ValueError(why)
    def digest(raw):
        return hashlib.sha256(raw).hexdigest()
    def original(key, parsed):
        raw = base64.b64decode(value[key+'_original_b64'],validate=True)
        check(digest(raw) == value[key+'_sha256'] and json.loads(raw) == parsed, 'original readiness bytes differ')
        return raw
    c = binding['contract']; r = value.get('ready',{}); b = value.get('bound',{}); roles = value.get('current_roles',{})
    check(value.get('schema') == 'hepta.native-guard.readiness-observation.v1'
          and value.get('state') == 'ready_observed', 'component readiness not observed')
    check(value.get('contract_sha256') == binding['contract_sha256']
          and value.get('provider_source_sha256') == binding['source_sha256']
          and value.get('package_sha256') == c['package_sha256'] and value.get('boot_id') == c['boot_id'],
          'component input pins or boot differ')
    original('ready',r);original('bound',b)
    combo = value.get('combination',{})
    original('combination',combo)
    check(value['combination_sha256'] == c['combination_sha256']
          and combo.get('schema') == 'hepta.native-guard.component-combination.v150.r10.1'
          and combo.get('state') == 'REVIEWED_COMPONENT_BYTES_NOT_FOUR_ROLE_READY',
          'original component combination differs')
    check(r.get('schema') == 'hepta.native-guard.ready.v1'
          and r.get('lease_sha256') == c['lease_sha256'] and r.get('combination_sha256') == c['combination_sha256']
          and r.get('provider_source_sha256') == binding['source_sha256'] and r.get('port') == 18080
          and r.get('accepting_one_session') is True and r.get('model_requests') == 0
          and r.get('readiness_scope') == 'isolated_component_transport_only' and r.get('four_role_ready') is False,
          'component ready original contract differs')
    bc = b.get('contract',{})
    check(b.get('schema') == 'hepta.native-guard.bound-contract.v1' and b.get('lease_sha256') == c['lease_sha256']
          and b.get('provider_source_sha256') == binding['source_sha256']
          and set(bc) == {'schema','case_id','nonce','owner_request_sha256','selected_session_id','selected_profile_id',
                         'source_seal_sha256','configuration_sha256','executor_server_instance'}
          and bc.get('schema') == 'hepta.native-guard-component.contract.v150.r10.1'
          and bc.get('source_seal_sha256') == combo.get('source_seal',{}).get('sha256')
          and bc.get('configuration_sha256') == combo.get('configuration',{}).get('sha256')
          and all(bc.get(k) == c[k] for k in ('case_id','nonce','owner_request_sha256','selected_session_id','selected_profile_id')),
          'actual native component contract differs')
    canonical = (json.dumps(bc,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
    check(digest(canonical) == r['contract_sha256'] and re.fullmatch('[0-9a-f]{32}',bc.get('executor_server_instance','')),
          'actual bound kernel contract bytes or executor instance differ')
    check(set(roles) == {'supervisor','provider','sidecar'} and roles['provider'] == r['identity']
          and roles['sidecar'] == b['sidecar_identity'] and roles['supervisor'] == value.get('supervisor'),
          'actual live process identity differs')
    original('supervisor',value['supervisor'])
    for name,row in roles.items():
        ident = row.get('identity',[])
        check(len(ident) == 4 and all(type(x) is int and x > 1 for x in ident)
              and ident[:3] == [ident[0]]*3 and row.get('uid') == row.get('gid') == [0]*4 and row.get('nnp') == 0,
              'owned role process identity/credentials differ')
        domain = 'u:r:trillionnium_owner_open_phone_executor:s0' if name == 'sidecar' else 'u:r:magisk:s0'
        check(row.get('domain') == domain, 'owned role security domain differs')
    check(roles['provider']['ppid'] == roles['sidecar']['ppid'] == roles['supervisor']['identity'][0],
          'owned component parent changed')
    health = b.get('sidecar_health',{})
    check(health.get('executor_revision') == 6 and health.get('state') == 'ready'
          and health.get('server_instance') == bc['executor_server_instance']
          and health.get('execute_authorized') is False and health.get('inference_endpoint') is False,
          'component parent readiness is not read-only')
    check(value.get('claim_absent') is True and value.get('connection_absent') is True
          and value.get('ended_absent') is True and value.get('retirement_originals_bound') is True
          and value.get('old_groups_absent') is True and value.get('socket_connections') == 0,
          'component consumed, ended or original retirement not verified')
    times = [r.get(k) for k in ('ready_monotonic_ns','accept_deadline_monotonic_ns','service_deadline_monotonic_ns')]
    now,wall = value.get('phone_monotonic_ns'),value.get('phone_unix_ms')
    check(all(type(x) is int and x > 0 for x in times+[now,wall]), 'phone clock shape differs')
    ready,accept,service = times
    check(ready <= now < accept < service and accept-ready == 120000000000
          and service-ready == 420000000000, 'component windows changed')
    check(accept-now >= minimum_remaining_ns and value.get('remaining_accept_ns') == accept-now
          and c['expires_unix_ms']-wall >= minimum_remaining_ns//1000000, 'component acceptance margin expired')
    if previous is not None:
        check(value['ready_sha256'] == previous['ready_sha256']
              and value['bound_sha256'] == previous['bound_sha256']
              and value['current_roles'] == previous['current_roles'], 'component readiness generation changed')
    return value

expected='在当前 owner-open 会话执行 NEG-01 前台切换保护组件验收。仅按已审查的隔离协议取得一次新屏幕观察并检查保护拒绝结果；测试前台由独立 Root 夹具切换，过时观察不得驱动输入，不做模型业务成功声明。验收标识：8daaaad6a322963e87973613c1fac762\n'
previous_identity={'profile_id': 'owner-open', 'session_id': 'session-ee897738-8fc2-4d3e-a916-5fe368b340ef', 'task_id': 'task-d3f61033-5b61-40e4-b8c6-7ea00d6b2d56', 'turn_id': 'turn-bcfba897-cbed-467a-9cc7-cff01d517593', 'turn_stream_id': 'r5-stream-2ff6e9edc32479c304c09e97d26f0b8569b292d64a89fd6602124681c12cec13'}
previous_digest='5792e441794e7da4f1f80f77f6ee4dffa74f46cd12b2da909e0cea8d8fac4431'
previous_status='provider_failed'
known_all_prior_tools_confirmed=True
"""Pure, offline decoder of HEPTA49's non-secret committed identity record.

No phone operations, app-state writes, locks, transport or effect authority.
The caller supplies bytes captured read-only after the real app's Inspect.
"""
import base64
import hashlib
import hmac
import json
import re
import struct
import sys

UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
DOMAINS = ('transport_event', 'job_runtime_event', 'job_journal_record')


def decode_client_state(encoded: bytes) -> dict:
    if not isinstance(encoded, bytes) or not 52 < len(encoded) <= 512:
        raise ValueError('invalid record length')
    payload, checksum = encoded[:-32], encoded[-32:]
    if not hmac.compare_digest(hashlib.sha256(payload).digest(), checksum):
        raise ValueError('record checksum mismatch')
    offset = 0

    def take(count):
        nonlocal offset
        if offset + count > len(payload):
            raise ValueError('truncated state field')
        value = payload[offset:offset + count]
        offset += count
        return value

    def byte():
        return take(1)[0]

    def ascii_string():
        count = byte()
        if not 1 <= count <= 64:
            raise ValueError('invalid state string length')
        raw = take(count)
        if any(not 0x21 <= value <= 0x7e for value in raw):
            raise ValueError('noncanonical state string bytes')
        return raw.decode('ascii')

    def identity(prefix):
        value = ascii_string()
        if not re.fullmatch(re.escape(prefix) + UUID, value):
            raise ValueError('invalid local client identity')
        return value

    def optional(reader):
        present = byte()
        if present not in (0, 1):
            raise ValueError('invalid state presence flag')
        return reader() if present else None

    if take(8) != b'OOCLST01' or struct.unpack('>i', take(4))[0] != 2:
        raise ValueError('unsupported state schema')
    revision = struct.unpack('>q', take(8))[0]
    if revision < 1:
        raise ValueError('invalid snapshot revision')
    session = identity('session-')
    task = identity('task-')
    turn = optional(lambda: identity('turn-'))
    request_digest = optional(ascii_string)
    if request_digest is not None and (turn is None or not HEX64.fullmatch(request_digest)):
        raise ValueError('invalid turn request digest')
    count = byte()
    if count > len(DOMAINS) or (turn is None and count):
        raise ValueError('invalid cursor count/selected turn')
    cursors = {}
    previous = -1
    for _ in range(count):
        ordinal = byte()
        if ordinal >= len(DOMAINS) or ordinal <= previous:
            raise ValueError('duplicate/unknown/noncanonical cursor domain')
        previous = ordinal
        epoch = ascii_string()
        cursor = struct.unpack('>q', take(8))[0]
        if not HEX64.fullmatch(epoch) or cursor < 0:
            raise ValueError('invalid cursor producer/cursor')
        cursors[DOMAINS[ordinal]] = {'producer_epoch_sha256': epoch, 'inclusive_cursor': cursor}
    if offset != len(payload):
        raise ValueError('unknown/trailing state fields')
    return {'schema': 'org.trillionnium.owneropen.client-session.v2',
            'revision': revision, 'session_id': session, 'task_id': task,
            'turn_id': turn, 'turn_request_sha256': request_digest, 'cursors': cursors,
            'record_bytes': len(encoded), 'record_sha256': hashlib.sha256(encoded).hexdigest(),
            'payload_sha256': checksum.hex(), 'checksum_valid': True,
            'scope': 'Non-secret identity observation only; no effect/replay authority. Profile and stream are not stored.'}



out=Path('/home/alex/codex-hepta-natural-root-r10-neg01-7c907661-diag02-root-v150');os.umask(0o077);out.mkdir(mode=0o700,exist_ok=False)
def save(n,v):
 with (out/n).open('x') as s:json.dump(v,s,ensure_ascii=False,indent=2);s.write('\n');s.flush();os.fsync(s.fileno())
 fd=os.open(out,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def sh(q):
 r=f.shell(q,c,t,timeout=25);assert r['rc']==0,r;return r
counter=0
def dump(tag):
 global counter
 counter+=1;path='/data/local/tmp/hepta-natural-root-r10-neg01-7c907661-diag02-v150-'+str(counter)+'.xml';r=sh('test ! -e '+path+' && uiautomator dump '+path+' && cat '+path);save(tag+'.json',r);tree=ET.fromstring(r['stdout'][r['stdout'].index('<?xml'):]);assert any(n.attrib.get('package')=='org.trillionnium.owneropen' for n in tree.iter('node'));return list(tree.iter('node'))
def node(nodes,rid):
 hits=[n for n in nodes if n.attrib.get('resource-id')==rid];assert len(hits)==1,(rid,len(hits));return hits[0]
def tap(n):
 assert n.attrib.get('enabled')=='true';a=list(map(int,re.findall(r'\d+',n.attrib['bounds'])));return sh('input tap '+str((a[0]+a[2])//2)+' '+str((a[1]+a[3])//2))
READ_ONLY_PROBE_SOURCE="import base64,hashlib,json,os,re,stat,sys\nfrom pathlib import Path\nWANTED=sys.argv[1]\nHINT=json.loads(base64.b64decode(sys.argv[2])) if len(sys.argv)>2 and sys.argv[2]!='-' else None\nassert re.fullmatch('[0-9a-f]{64}',WANTED)\nROOTS={'production':'/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/evidence',\n       'component':'/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6/evidence'}\nMODE=sys.argv[3] if len(sys.argv)>3 else 'production'\nassert MODE in ROOTS,'unapproved evidence root'\nE=Path(ROOTS[MODE])\nJ=Path('/var/lib/trillionnium/owner-open/turn-events.jsonl.segments')\nKEYS=('session_id','profile_id','task_id','turn_id','turn_stream_id')\ndef sha(b): return hashlib.sha256(b).hexdigest()\ndef strict(b):\n def pairs(xs):\n  result={}\n  for k,v in xs:\n   if k in result: raise ValueError('duplicate_json_key')\n   result[k]=v\n  return result\n return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite_json')))\ndef canonical_directory(p):\n assert p.is_dir() and not p.is_symlink() and p.resolve()==p,'noncanonical_evidence_directory'\ncanonical_directory(E);canonical_directory(J)\ndirs=[];modes={}\nfor mode,root_name in ROOTS.items():\n root=Path(root_name)\n try:root.lstat()\n except FileNotFoundError:continue\n canonical_directory(root)\n for path in root.iterdir():\n  if re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',path.name):\n   dirs.append(path);modes[str(path)]=mode\ndirs.sort()\nassert len(dirs)<=512,'provider_directory_bound'\nmatches=[]\nfor d in dirs:\n canonical_directory(d)\n p=d/'provider-in.jsonl'\n try: fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)\n except FileNotFoundError: continue\n try:\n  before=os.fstat(fd)\n  assert stat.S_ISREG(before.st_mode) and before.st_nlink==1,'provider_file_type'\n  raw=os.read(fd,131072)\n  after=os.fstat(fd)\n  assert (before.st_dev,before.st_ino)==(after.st_dev,after.st_ino) and after.st_size>=before.st_size,'provider_file_identity'\n finally: os.close(fd)\n for line in raw.splitlines(keepends=True):\n  if not line.endswith(b'\\n'): continue\n  frame=strict(line)\n  if frame.get('kind')!='turn.start': continue\n  turn=frame.get('turn',{})\n  if not isinstance(turn.get('user_input'),str) or sha(turn['user_input'].encode('utf-8'))!=WANTED: continue\n  scope={k:turn.get(k) for k in KEYS}\n  assert all(isinstance(v,str) and 0<len(v.encode())<=256 and '\\0' not in v for v in scope.values()),'provider_scope'\n  matches.append({'evidence_root_mode':modes[str(d)],'run_dir':str(d),'provider_input_file':str(p),'scope':scope,'owner_utf8_sha256':WANTED,\n                  'provider_start_original_b64':base64.b64encode(line).decode(),\n                  'provider_start_original_sha256':sha(line),'provider_start_original_bytes':len(line)})\nanswer={'schema':'hepta.read-only-new-turn-observation.v150.r4','owner_utf8_sha256':WANTED,\n        'provider_match_count':len(matches),'phone_writes':False,'model_requests':0,'tool_dispatches':0,\n        'native_hash_chain_verified':False,'business_qualified':False}\nif not matches:\n answer['state']='no_matching_provider_start'\nelif len(matches)!=1:\n answer.update(state='ambiguous_matching_provider_starts',matches=matches)\nelse:\n match=matches[0];scope=match['scope'];answer['match']=match\n if match['evidence_root_mode']!=MODE or (HINT is not None and HINT!=scope):\n  answer['state']='scope_changed'\n else:\n  files=sorted(J.glob('*.jsonl'));assert len(files)<=1024,'native_segment_count_bound'\n  total=0;selected=[];terminal=[]\n  needle=scope['turn_id'].encode('utf-8')\n  for p in files:\n   fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)\n   try:\n    info=os.fstat(fd)\n    assert stat.S_ISREG(info.st_mode) and info.st_nlink==1,'native_file_type'\n    total+=info.st_size;assert total<=64*1024*1024,'native_scan_bytes_bound'\n    with os.fdopen(fd,'rb',closefd=False) as stream:\n     while True:\n      raw=stream.readline(4*1024*1024+1)\n      if not raw: break\n      assert len(raw)<=4*1024*1024,'native_record_bytes_bound'\n      if not raw.endswith(b'\\n'): continue\n      if needle not in raw: continue\n      row=strict(raw)\n      if row.get('scope')!=scope: continue\n      payload=row.get('payload',{});frame=payload.get('frame',{})\n      assert isinstance(frame,dict),'native_frame_type'\n      selected.append({'file':str(p),'store_seq':row.get('store_seq'),'turn_seq':row.get('turn_seq'),\n                       'kind':frame.get('kind'),'row_kind':row.get('kind'),'request_sha256':payload.get('request_sha256'),\n                       'record_sha256':row.get('record_sha256'),'raw_line_sha256':sha(raw),'raw_line_bytes':len(raw)})\n      if frame.get('kind')=='turn.end':\n       terminal.append({'frame':frame,'record':row,'raw_line_b64':base64.b64encode(raw).decode(),\n                        'raw_line_sha256':sha(raw),'raw_line_bytes':len(raw),'source':str(p)})\n   finally: os.close(fd)\n  selected.sort(key=lambda r:r['turn_seq'] if type(r['turn_seq']) is int else -1)\n  assert [r['turn_seq'] for r in selected]==list(range(len(selected))),'native_turn_sequence_gap_or_duplicate'\n  hashes={r['request_sha256'] for r in selected}\n  assert len(hashes)<=1 and all(isinstance(x,str) and re.fullmatch('[0-9a-f]{64}',x) for x in hashes),'native_request_hash_binding'\n  answer.update(native_records=selected,native_record_count=len(selected),native_scanned_bytes=total,\n                native_request_sha256=next(iter(hashes)) if hashes else None)\n  assert len(terminal)<=1,'duplicate_native_terminal'\n  if terminal:\n   assert selected and selected[-1]['kind']=='turn.end' and terminal[0]['record']['turn_seq']==selected[-1]['turn_seq'],'native_terminal_order'\n   assert terminal[0]['frame'].get('payload',{}).get('status') in ('completed','provider_failed','cancelled'),'native_terminal_status'\n   answer.update(state='native_terminal_observed',native_terminal=terminal[0])\n  else: answer['state']='native_pending'\nprint(json.dumps(answer,ensure_ascii=False,separators=(',',':'),allow_nan=False))\n"
import signal
class OriginalReadDeadline(RuntimeError): pass
def latency_read_original(scope=None):
 # Entire host route discovery plus wire read has an 8-second alarm.
 # Remote process is read-only and separately bounded by BusyBox 6s + 1s kill.
 def alarm(_signum,_frame): raise OriginalReadDeadline('read_only_probe_total_deadline')
 previous_handler=signal.getsignal(signal.SIGALRM)
 previous_timer=signal.getitimer(signal.ITIMER_REAL)
 assert previous_timer==(0.0,0.0),'preexisting observer alarm; no read'
 signal.signal(signal.SIGALRM,alarm)
 start=time.monotonic_ns()
 result=None
 try:
  signal.setitimer(signal.ITIMER_REAL,8.0)
  hint=base64.b64encode(json.dumps(scope,separators=(',',':')).encode()).decode() if scope else '-'
  command='/data/adb/magisk/busybox timeout -s TERM -k 1 6 /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -c '+shlex.quote(READ_ONLY_PROBE_SOURCE)+' '+shlex.quote(hashlib.sha256(expected.encode()).hexdigest())+' '+shlex.quote(hint)+' '+shlex.quote(evidence_mode)
  result=f.shell('/debug_ramdisk/su -c '+shlex.quote(command),c,t,timeout=6)
  assert result['rc']==0,'read-only probe nonzero exit'
  value=json.loads(result['stdout'])
  assert value['owner_utf8_sha256']==hashlib.sha256(expected.encode()).hexdigest(),'probe request binding'
  return {'read_start_monotonic_ns':start,'read_end_monotonic_ns':time.monotonic_ns(),
          'read_deadline_seconds':8,'original_wire_receipt':result,'observation':value}
 except Exception as error:
  return {'read_start_monotonic_ns':start,'read_end_monotonic_ns':time.monotonic_ns(),
          'read_deadline_seconds':8,'original_wire_receipt':result,
          'read_error_type':type(error).__name__,'read_error':str(error),'automatic_send_retry':False}
 finally:
  signal.setitimer(signal.ITIMER_REAL,0)
  signal.signal(signal.SIGALRM,previous_handler)
def observe_original_terminal(send_started_monotonic_ns,send_returned_monotonic_ns,send_status):
 deadline=send_started_monotonic_ns+335_000_000_000
 scope=None;count=0;reads=[];last_negative_start=None;result=None
 while time.monotonic_ns()+8_000_000_000<=deadline:
  count+=1
  reading=latency_read_original(scope)
  save('LATENCY-%04d.original-read.json'%count,reading)
  observation=reading.get('observation')
  reads.append({'start':reading['read_start_monotonic_ns'],'end':reading['read_end_monotonic_ns'],
                'state':observation.get('state') if observation else 'read_unknown'})
  if observation:
   state=observation['state']
   if state in ('ambiguous_matching_provider_starts','scope_changed'):
    result={'state':'UNKNOWN_SCOPE_BINDING','original_observation':observation};break
   if 'match' in observation:
    observed_scope=observation['match']['scope']
    assert observed_scope!=previous_identity,'old scope cannot be the fresh task'
    if scope is None: scope=observed_scope
    assert scope==observed_scope,'observation changed scope'
   if state=='native_terminal_observed':
    end=reading['read_end_monotonic_ns']
    lower=max(send_started_monotonic_ns,last_negative_start or send_started_monotonic_ns)
    result={'state':'ORIGINAL_NATIVE_TERMINAL_OBSERVED','native_status':observation['native_terminal']['frame']['payload']['status'],
            'terminal_observation_end_monotonic_ns':end,
            'send_to_terminal_observed_seconds':(end-send_started_monotonic_ns)/1e9,
            'terminal_persistence_latency_interval_seconds':[(lower-send_started_monotonic_ns)/1e9,(end-send_started_monotonic_ns)/1e9],
            'observation_uncertainty_interval_seconds':(end-lower)/1e9,
            'original_observation':observation}
    break
   if state=='native_pending':
    last_negative_start=reading['read_start_monotonic_ns']
  pause=min(0.75,max(0,(deadline-time.monotonic_ns())/1e9-8))
  if pause: time.sleep(pause)
 if result is None: result={'state':'UNKNOWN_MONITOR_BOUND_REACHED','next':'Read the same original request/scope only; never Send again'}
 ends=[r['end']-r['start'] for r in reads]
 gaps=[reads[i]['start']-reads[i-1]['start'] for i in range(1,len(reads))]
 result.update(schema='hepta.p4-send-native-terminal-latency.v150.r3',
   owner_request_utf8_sha256=hashlib.sha256(expected.encode()).hexdigest(),scope=scope,
   send_call_started_monotonic_ns=send_started_monotonic_ns,
   send_call_returned_monotonic_ns=send_returned_monotonic_ns,send_wire_state=send_status,
   clock='Pocket4 time.monotonic_ns, one actor process',monitor_budget_seconds=335,
   read_deadline_seconds=8,poll_pause_seconds=0.75,
   nominal_poll_start_interval_upper_seconds=8.75,
   maximum_observed_poll_start_interval_seconds=max(gaps,default=0)/1e9,
   maximum_observed_read_seconds=max(ends,default=0)/1e9,
   observer_elapsed_seconds=(time.monotonic_ns()-send_started_monotonic_ns)/1e9,
   read_count=count,automatic_send_retry=False,send_attempt_count=1,
   native_hash_chain_verified=False,business_success_verified=False,
   qualification='Observed native terminal latency upper bound; independent collector still required',
   original_receipts_preserved=True)
 save('SEND-NATIVE-LATENCY.json',result)
 return result

def component_send_margin(reading,minimum_remaining_ns=15000000000):
 elapsed=time.monotonic_ns()-reading['read_start_monotonic_ns']
 assert elapsed>=0,'Pocket4 monotonic clock changed'
 value=reading['observation']
 assert value['remaining_accept_ns']-elapsed>=minimum_remaining_ns,'Component accept margin elapsed; no Send'
 assert component_binding['contract']['expires_unix_ms']-value['phone_unix_ms']-elapsed//1000000>=minimum_remaining_ns//1000000,'Component contract margin elapsed; no Send'
 assert time.monotonic_ns()<=pre_send_deadline_ns,'Original pre-Send deadline elapsed; no Send'

def read_component_ready(tag,previous=None,minimum_remaining_ns=15000000000):
 import signal
 assert component_binding is not None and evidence_mode=='component','Fixed component mode required'
 assert time.monotonic_ns()+8_000_000_000<=pre_send_deadline_ns,'Insufficient original pre-Send read budget'
 def expired(_number,_frame):raise RuntimeError('component ready read deadline')
 previous_handler=signal.getsignal(signal.SIGALRM)
 assert signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'Existing deadline must not be cleared'
 signal.signal(signal.SIGALRM,expired)
 result=None;value=None;started=time.monotonic_ns()
 try:
  signal.setitimer(signal.ITIMER_REAL,8.0)
  command='/data/adb/magisk/busybox timeout -s TERM -k 1 6 /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -B -c '+shlex.quote(COMPONENT_READY_PROBE_SOURCE)
  result=f.shell('/debug_ramdisk/su -c '+shlex.quote(command),c,t,timeout=6)
  assert result['rc']==0,'Fixed component ready observation failed; no Send'
  value=json.loads(result['stdout'])
  if value.get('state')=='waiting_for_ready':
   assert previous is None,'Component ready vanished after observation'
   assert value['contract_sha256']==component_binding['contract_sha256'] and value['nonce']==component_binding['contract']['nonce'] and value['owner_request_sha256']==component_binding['contract']['owner_request_sha256']
   assert value['claim_absent'] is True and value['ended_absent'] is True
  else:
   validate_ready_observation(value,component_binding,previous,minimum_remaining_ns)
 finally:
  signal.setitimer(signal.ITIMER_REAL,0)
  signal.signal(signal.SIGALRM,previous_handler)
  reading={'read_start_monotonic_ns':started,'read_end_monotonic_ns':time.monotonic_ns(),
           'original_wire_receipt':result,'observation':value,'read_only':True,
           'socket_connections':0,'service_launches':0}
  save(tag+'.original-read.json',reading)
 if value['state']=='ready_observed':component_send_margin(reading,minimum_remaining_ns)
 return reading

def wait_component_rendezvous():
 assert component_binding is not None and evidence_mode=='component','Fixed component rendezvous only'
 now=time.monotonic_ns()
 assert now+30_000_000_000<=pre_send_deadline_ns,'Insufficient original pre-Send budget for rendezvous'
 save('COMPONENT-PREPARED-NO-SEND.json',{
  'schema':'hepta.native-guard.sender-prepared.v1','state':'PREPARED_NO_SEND',
  'nonce':component_binding['contract']['nonce'],
  'owner_request_sha256':component_binding['contract']['owner_request_sha256'],
  'contract_sha256':component_binding['contract_sha256'],
  'provider_source_sha256':component_binding['source_sha256'],
  'ready_path':component_binding['phone_ready_path'],
  'clock':'Pocket4 time.monotonic_ns, one actor process',
  'prepared_monotonic_ns':now,'pre_send_deadline_monotonic_ns':pre_send_deadline_ns,
  'pre_send_budget_remaining_seconds':(pre_send_deadline_ns-now)/1e9,
  'same_phone_accept_minimum_remaining_seconds':15,
  'provider_started_by_sender':False,'socket_connections':0,'send_attempt_count':0,
  'root_action':'Root may launch the separately reviewed isolated native-guard lifecycle once; sender only reads its pinned ready file'})
 count=0
 while time.monotonic_ns()+25_000_000_000<=pre_send_deadline_ns:
  count+=1
  reading=read_component_ready('COMPONENT-READY-%04d'%count,minimum_remaining_ns=25000000000)
  if reading['observation']['state']=='ready_observed':return reading
  pause=min(.25,max(0,(pre_send_deadline_ns-time.monotonic_ns()-25_000_000_000)/1e9))
  if pause:time.sleep(pause)
 raise RuntimeError('Component rendezvous deadline elapsed; zero Send, no provider restart')

def read_selected_identity(tag,wanted_identity,wanted_digest):
 directory='/data/user/0/org.trillionnium.owneropen/files/'
 command='test ! -e '+directory+'owner-client-session-v1.pending && base64 '+directory+'owner-client-session-v1.bin && test ! -e '+directory+'owner-client-session-v1.pending'
 result=f.shell('/debug_ramdisk/su -c '+shlex.quote(command),c,t,timeout=8)
 save(tag+'.original-read.json',result)
 assert result['rc']==0,'Selected task state unreadable'
 raw=base64.b64decode(''.join(result['stdout'].split()),validate=True)
 selected=decode_client_state(raw)
 assert all(selected[k]==wanted_identity[k] for k in ('session_id','task_id','turn_id')) and selected['turn_request_sha256']==wanted_digest,'Selected task changed; no Send or draft replacement'
 return selected

def read_retirement_gate(tag):
 import signal
 def expired(_number,_frame):raise RuntimeError('retirement read deadline')
 previous_handler=signal.getsignal(signal.SIGALRM)
 assert signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'existing deadline must not be cleared'
 signal.signal(signal.SIGALRM,expired)
 result=None
 try:
  signal.setitimer(signal.ITIMER_REAL,8.0)
  command='/data/adb/magisk/busybox timeout -s TERM -k 1 6 /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -c '+shlex.quote(RETIREMENT_READ_GUARD_SOURCE)
  result=f.shell('/debug_ramdisk/su -c '+shlex.quote(command),c,t,timeout=6)
  assert result['rc']==0,'Original retirement or global action gate unverified'
  value=json.loads(result['stdout'])
  assert value['state']=='original_retirement_verified' and value['global_action_gate_clear'] is True
  assert value['resolution_sha256']==retirement_binding['resolution_sha256'] and value['proof_sha256']==retirement_binding['proof_sha256']
 finally:
  signal.setitimer(signal.ITIMER_REAL,0)
  signal.signal(signal.SIGALRM,previous_handler)
  save(tag+'.original-read.json',{'original_wire_receipt':result,'read_only':True,'no_retry':True})
 return value

def restore_preserved_draft(timing,send_attempted,draft_input_confirmed):
 if not draft_input_confirmed:
  value={'state':'RESTORE_NOT_AUTOMATED_INPUT_OUTCOME_UNCONFIRMED','original_draft_preserved_privately':True,'automatic_retry':False}
  save('DRAFT-RESTORE-PENDING.json',value);return value
 if send_attempted:
  if not timing or timing.get('state')!='ORIGINAL_NATIVE_TERMINAL_OBSERVED':
   value={'state':'RESTORE_DEFERRED_ORIGINAL_TASK_NOT_TERMINAL','original_draft_preserved_privately':True,'automatic_retry':False}
   save('DRAFT-RESTORE-PENDING.json',value);return value
  restore_identity=timing['scope']
  restore_digest=timing['original_observation']['native_request_sha256']
 else:
  restore_identity,restore_digest=previous_identity,previous_digest
 read_retirement_gate('RESTORE-GLOBAL-GATE')
 read_selected_identity('RESTORE-SELECTED',restore_identity,restore_digest)
 # This is operator cleanup after the original task terminal, never a model
 # return receipt or business postcondition. Preserve the actual pre-cleanup UI.
 foreground=f.shell('dumpsys activity activities | grep topResumedActivity',c,t,timeout=8)
 save('PRE-RESTORE-FOREGROUND.json',{'original_wire_receipt':foreground,'model_business_credit':False})
 sh('am start -W -n org.trillionnium.owneropen/.OwnerOpenShellActivity')
 nodes=dump('RESTORE-INITIAL')
 for index in range(4):
  if any(n.attrib.get('resource-id')=='org.trillionnium.owneropen:id/ui_prompt' for n in nodes):break
  dismiss=[n for n in nodes if n.attrib.get('package')=='org.trillionnium.owneropen' and n.attrib.get('resource-id')=='android:id/button2' and n.attrib.get('text') in ('关闭','返回','完成') and n.attrib.get('clickable')=='true']
  assert len(dismiss)==1,'Unknown modal retained; draft restore deferred'
  tap(dismiss[0]);nodes=dump('RESTORE-DISMISS-'+str(index))
 editor=node(nodes,'org.trillionnium.owneropen:id/ui_prompt')
 visible=editor.attrib.get('text','')
 if visible in ('',editor.attrib.get('hint',''),'发消息或交代任务…','发消息或交代任务...'):
  expected_before=''
 elif visible in (expected,preserved_draft):
  expected_before=visible
 else:
  raise RuntimeError('Draft changed after submission; preserved without replacement')
 # A hint is treated as empty only for the helper's exact effectiveText CAS.
 # A real user-entered hint string fails that CAS, so it is never overwritten.
 read_selected_identity('RESTORE-SELECTED-FINAL',restore_identity,restore_digest)
 tap(editor)
 command='CLASSPATH=/data/local/tmp/hepta-unicode-v148-r2/input.jar app_process /system/bin org.trillionnium.hepta.input.UnicodeInput set-text --operation-id root-restore-' + label + ' --display 0 --package org.trillionnium.owneropen --view-id org.trillionnium.owneropen:id/ui_prompt --expected-text-b64 '+shlex.quote(base64.b64encode(expected_before.encode()).decode() or '-')+' --text-b64 '+shlex.quote(base64.b64encode(preserved_draft.encode()).decode() or '-')
 result=sh(command);save('PRESERVED-DRAFT-RESTORE.original.json',result)
 answer=json.loads(result['stdout'])
 assert answer['status'] in ('set_verified','already_exact') and answer['own_automation_disconnected'] is True
 readback=base64.b64decode(answer['readback_text_b64'],validate=True).decode('utf-8')
 assert readback==preserved_draft,'Original preserved draft not exactly restored'
 value={'state':'ORIGINAL_DRAFT_RESTORED','utf8_sha256':hashlib.sha256(readback.encode()).hexdigest(),
        'original_draft_submitted':False,'model_business_credit':False,'restore_attempts':1}
 save('DRAFT-RESTORE-RESULT.json',value)
 return value

pre_send_deadline_ns=time.monotonic_ns()+150_000_000_000
draft_input_confirmed=False
send_attempted=False
timing=None
actor_error=None
exit_code=0
restore={'state':'NOT_ATTEMPTED'}
try:
 
 retirement_before=read_retirement_gate('PRE-MUTATION-RETIREMENT')
 if reset_probe:sh('am force-stop org.trillionnium.hepta.controlprobe')
 sh('input keyevent 224; wm dismiss-keyguard; cmd statusbar collapse; am start -W -n org.trillionnium.owneropen/.OwnerOpenShellActivity')
 nodes=dump('INITIAL')
 for index in range(4):
  if any(n.attrib.get('resource-id')=='org.trillionnium.owneropen:id/ui_prompt' for n in nodes):break
  dismiss=[n for n in nodes if n.attrib.get('package')=='org.trillionnium.owneropen' and n.attrib.get('resource-id')=='android:id/button2' and n.attrib.get('text') in ('关闭','返回','完成') and n.attrib.get('clickable')=='true']
  assert len(dismiss)==1,'Unknown modal retained; no task sent'
  tap(dismiss[0]);nodes=dump('DISMISS-INFO-'+str(index))
 assert any(n.attrib.get('resource-id')=='org.trillionnium.owneropen:id/ui_prompt' for n in nodes)
 status=node(nodes,'org.trillionnium.owneropen:id/ui_control_status').attrib.get('text','')
 assert '暂停' not in status,'Task arming is paused; no task sent'
 editor=node(nodes,'org.trillionnium.owneropen:id/ui_prompt');existing=editor.attrib.get('text','')
 # A preserved-empty draft is independently confirmed with the frozen helper.
 # Its CAS still compares effectiveText==empty before the only new input action.
 if preserved_draft=='' and editor.attrib.get('hint') and existing==editor.attrib.get('hint'):
  existing=''
 assert existing == preserved_draft, 'Draft changed since immutable preservation; no task sent'
 save('PRESERVED-USER-DRAFT.json',{'exact_text':existing,'utf8_sha256':hashlib.sha256(existing.encode()).hexdigest(),'restore_required':True,'submitted_original_draft':False})
 if existing!=expected:
  tap(editor)
  helper='CLASSPATH=/data/local/tmp/hepta-unicode-v148-r2/input.jar app_process /system/bin org.trillionnium.hepta.input.UnicodeInput set-text --operation-id root-prompt-' + label + ' --display 0 --package org.trillionnium.owneropen --view-id org.trillionnium.owneropen:id/ui_prompt --expected-text-b64 '+shlex.quote(base64.b64encode(existing.encode()).decode() or '-')+' --text-b64 '+shlex.quote(base64.b64encode(expected.encode()).decode())
  result=sh(helper);save('OPERATOR-CHINESE-PROMPT-INPUT.json',result);answer=json.loads(result['stdout']);assert answer['status'] in ('set_verified','already_exact') and answer['own_automation_disconnected'] is True and base64.b64decode(answer['readback_text_b64']).decode()==expected
 
 draft_input_confirmed=True
 nodes=dump('DRAFT');assert node(nodes,'org.trillionnium.owneropen:id/ui_prompt').attrib['text']==expected
 tap(node(nodes,'org.trillionnium.owneropen:id/ui_tools'));nodes=dump('CONNECT-MENU');tap(node(nodes,'org.trillionnium.owneropen:id/ui_reconnect'));time.sleep(.5)
 nodes=dump('CURRENT-CONNECTION');tap(node(nodes,'org.trillionnium.owneropen:id/ui_task_summary'));nodes=dump('TASK-CONTROLS');tap(node(nodes,'org.trillionnium.owneropen:id/ui_inspect'));time.sleep(.5)
 nodes=dump('READBACK');tap(node(nodes,'org.trillionnium.owneropen:id/ui_tools'));nodes=dump('DETAILS-MENU');tap(node(nodes,'org.trillionnium.owneropen:id/ui_details'));nodes=dump('RAW-DETAILS')
 records=[]
 for line in node(nodes,'org.trillionnium.owneropen:id/ui_log').attrib['text'].splitlines():
  try:records.append(json.loads(line))
  except (ValueError,TypeError):pass
 save('PREVIOUS-ORIGINAL-READBACK.json',records)
 hellos=[i for i,r in enumerate(records) if r.get('kind')=='broker.hello.ack']
 inspections=[r['frame'] for r in records[(hellos[-1]+1 if hellos else 0):] if r.get('frame',{}).get('kind')=='turn.inspect.result' and all(r['frame'].get(k)==v for k,v in previous_identity.items())]
 if inspections and hellos:
  hello=records[hellos[-1]];assert hello['host_hello_ack']['payload']['runtime_ready'] is True
  proof=inspections[-1]['payload'];assert proof['request_sha256']==previous_digest and proof['complete'] is True and proof['has_more'] is False
  assert proof['frames'][-1]['kind']=='turn.end' and proof['frames'][-1]['payload']['status']==previous_status
  qualified={'method':'same_connection_real_app_original_inspect','hello':hello,'previous_original_readback':inspections[-1]}
 else:
  # Accessibility exposes only the first100000 characters of this diagnostic
  # TextView. Its prefix is not authority for selecting or completing a task.
  # The app still processes its full native response and owns its Send fence.
  # The app's view cache also drops a prefix at131072 characters, so even a
  # shorter exposed suffix can lack a complete JSON response. Observe the
  # committed selection and full native records instead of treating the view
  # cache as the execution record. The app's original Inspect/Send fence stays.
  diagnostic_chars=len(node(nodes,'org.trillionnium.owneropen:id/ui_log').attrib['text'])
  directory='/data/user/0/org.trillionnium.owneropen/files/'
  state_read=root('test ! -e '+directory+'owner-client-session-v1.pending && base64 '+directory+'owner-client-session-v1.bin && test ! -e '+directory+'owner-client-session-v1.pending');assert state_read['rc']==0
  raw=base64.b64decode(''.join(state_read['stdout'].split()),validate=True);selected=decode_client_state(raw)
  assert all(selected[k]==previous_identity[k] for k in ('session_id','task_id','turn_id')) and selected['turn_request_sha256']==previous_digest,'Selected app identity differs; no Send'
  journal=root('grep -h -F '+shlex.quote(previous_identity['turn_id'])+' /data/trillionnium/owner-open/state/turn-events.jsonl.segments/*.jsonl');assert journal['rc']==0
  original=[json.loads(line) for line in journal['stdout'].splitlines()];assert original and all(row['scope']==previous_identity for row in original)
  assert [row['turn_seq'] for row in original]==list(range(len(original)))
  assert all(row['payload']['request_sha256']==previous_digest for row in original)
  last=original[-1]['payload']['frame'];assert last['kind']=='turn.end' and last['payload']['status']==previous_status
  if previous_status!='completed' and not (known_all_prior_tools_confirmed or retirement_prior):assert not any(row['kind'].startswith('tool.') for row in original),'Failed task has effects without confirmed outcomes; no fresh test'
  qualified={'method':'real_app_inspect_then_read_only_selected_identity_and_original_journal','app_diagnostic_not_complete_record':True,'diagnostic_chars':diagnostic_chars,'selected_identity':selected,'original_records':original,'app_state_writes':False,'app_guard_bypassed':False}
 qualified['retirement_prior_admission']=retirement_prior
 qualified['retirement_gate']=retirement_before
 qualified['prompt_sha256']=hashlib.sha256(expected.encode()).hexdigest();save('PRE-SEND-QUALIFIED.json',qualified)
 for index in range(2):
  done=node(nodes,'android:id/button2');assert done.attrib['text'] in ('关闭','完成');tap(done);nodes=dump('CLOSE-DETAILS-'+str(index))
 assert node(nodes,'org.trillionnium.owneropen:id/ui_prompt').attrib['text']==expected
 assert f.read('cat /proc/sys/kernel/random/boot_id',c,t)=='f8019f83-20a7-4f18-bea1-51c980621e4d'
 send=node(nodes,'org.trillionnium.owneropen:id/ui_send')
 # Additional read-only freshness guard: identical old text cannot bind this timing.
 pre=latency_read_original()
 save('LATENCY-PRE-SEND.original-read.json',pre)
 assert pre.get('observation',{}).get('state')=='no_matching_provider_start','New exact request already present or read unknown; no Send'
 retirement_final=read_retirement_gate('FINAL-PRE-SEND-RETIREMENT')
 read_selected_identity('FINAL-PRE-SEND-SELECTED',previous_identity,previous_digest)
 nodes=dump('FINAL-PRE-SEND-UI')
 assert node(nodes,'org.trillionnium.owneropen:id/ui_prompt').attrib.get('text','')==expected,'Fresh owner draft changed; no Send'
 send=node(nodes,'org.trillionnium.owneropen:id/ui_send')
 component_final=None
 if component_binding is not None:
  component_first=wait_component_rendezvous()
  retirement_final=read_retirement_gate('COMPONENT-FINAL-PRE-SEND-RETIREMENT')
  read_selected_identity('COMPONENT-FINAL-PRE-SEND-SELECTED',previous_identity,previous_digest)
  nodes=dump('COMPONENT-FINAL-PRE-SEND-UI')
  assert node(nodes,'org.trillionnium.owneropen:id/ui_prompt').attrib.get('text','')==expected,'Fresh component draft changed; no Send'
  send=node(nodes,'org.trillionnium.owneropen:id/ui_send')
  component_final=read_component_ready('COMPONENT-FINAL-PRE-SEND-READY',component_first['observation'])
 assert time.monotonic_ns()<=pre_send_deadline_ns,'Pre-Send budget elapsed; no late Send'
 save('SEND.once.json',{'prompt':expected,'prompt_sha256':hashlib.sha256(expected.encode()).hexdigest(),'bounds':send.attrib['bounds'],'supplied_app_commands':False,'supplied_app_coordinates':False,'automatic_replay':False})
 save('SEND.MONOTONIC-INTENT.json',{'p4_pre_send_monotonic_ns':time.monotonic_ns(),'send_attempt_count':1,'automatic_replay':False})
 assert time.monotonic_ns()<=pre_send_deadline_ns,'Pre-Send budget elapsed after intent persistence; no late Send'
 if component_final is not None:component_send_margin(component_final)
 send_started_monotonic_ns=time.monotonic_ns()
 send_status='unknown'
 send_attempted=True
 try:
  result=tap(send);send_status='tap_returned';save('SEND.result.json',result)
 except Exception as error:
  save('SEND.unknown.json',{'error':str(error),'automatic_replay':False,'next':'Only read original request/scope'})
 send_returned_monotonic_ns=time.monotonic_ns()
 save('SEND.MONOTONIC-WINDOW.json',{'send_started_monotonic_ns':send_started_monotonic_ns,'send_returned_monotonic_ns':send_returned_monotonic_ns,'clock':'Pocket4 time.monotonic_ns','send_status':send_status,'automatic_replay':False})
 timing=observe_original_terminal(send_started_monotonic_ns,send_returned_monotonic_ns,send_status)
 # Final output is emitted only after the separately recorded draft cleanup.
 if timing['state']!='ORIGINAL_NATIVE_TERMINAL_OBSERVED': raise SystemExit(2)
except BaseException as error:
 actor_error={'error_type':type(error).__name__,'error':str(error),'automatic_send_retry':False}
 save('ACTOR-FAILURE.json',actor_error)
 exit_code=2
finally:
 try:
  restore=restore_preserved_draft(timing,send_attempted,draft_input_confirmed)
 except BaseException as error:
  restore={'state':'RESTORE_UNCONFIRMED_RETAIN_PRIVATE_ORIGINAL','error_type':type(error).__name__,
           'automatic_retry':False,'original_draft_preserved_privately':True}
  save('DRAFT-RESTORE-UNCONFIRMED.json',restore)
 if restore.get('state')!='ORIGINAL_DRAFT_RESTORED':exit_code=2
print(json.dumps({'state':timing.get('state') if timing else 'PRE_SEND_OR_ACTOR_FAILURE',
 'native_status':timing.get('native_status') if timing else None,
 'out':str(out),'route':t,'prompt_sha256':hashlib.sha256(expected.encode()).hexdigest(),
 'draft_restore':{'state':restore.get('state'),'restore_attempts':restore.get('restore_attempts',0),'original_draft_submitted':False},'send_attempt_count':int(send_attempted),'automatic_replay':False,
 'business_success_verified':False,'independent_collector_required':True,
 'retirement_resolution_sha256':retirement_binding['resolution_sha256']}))
if exit_code:raise SystemExit(exit_code)

