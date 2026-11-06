#!/usr/bin/env python3
"""Build an isolated native v2 consumer candidate from pinned full15 sources.

No installed file, historical candidate, seal, or executor is modified.
"""
import argparse,ast,difflib,hashlib,json,os,stat
from pathlib import Path
BASE_PINS_SHA="ccdb924f7b8e1556008a443f8412b4d35604e884dc171c9e7d855299f40b1fb4"
V1_OBS="22580b8aa22d5c0ab4040888872e642a5176042023dd7bcf50e67efe51248409"
V1_DAILY="689db3908014940a1e39689b966d30ab16ac6f9c0d7892becf1718b9840c824f"
LOCAL="0302a8bac9dac18234c9493aa512e1efcf43d7cc5eaab884882dad42c2182c54"
TRANSFORM=json.loads("{\"old_native_streams\":\"def native_streams(reply, call_id, expected_tool='adb.exec'):\\n    require(expected_tool in {'adb.exec', 'shell.exec'}, 'unqualified phone result wire tool')\\n    require(reply.get('call_id') == call_id and reply.get('status') == 'terminal',\\n            'phone result lacks matching terminal identity')\\n    terminal = reply.get('terminal')\\n    require(isinstance(terminal, dict) and terminal.get('kind') == 'exited'\\n            and type(terminal.get('exit_code')) is int\\n            and terminal.get('exit_code') == 0 and terminal.get('error') is None\\n            and terminal.get('output_truncated') is False,\\n            'phone semantic tool is not confirmed successful and complete')\\n    streams = {'stdout': bytearray(), 'stderr': bytearray()}\\n    events = reply.get('events')\\n    require(isinstance(events, list), 'phone result events are missing')\\n    for index, record in enumerate(events):\\n        require(isinstance(record, dict) and record.get('call_id') == call_id and record.get('tool') == expected_tool\\n                and type(record.get('seq')) is int and record['seq'] == index,\\n                'phone result event scope or sequence differs')\\n        event = record.get('event')\\n        require(isinstance(event, dict), 'phone result event is malformed')\\n        require(type(event.get('kind')) is str\\n                and event['kind'] in {'accepted', 'started', 'output', 'terminal'},\\n                'phone result contains an unqualified event kind')\\n        if event['kind'] != 'output':\\n            continue\\n        name = event.get('stream')\\n        require(name in streams and event.get('encoding') == 'base64'\\n                and isinstance(event.get('data'), str), 'phone output stream differs')\\n        try:\\n            raw = base64.b64decode(event['data'], validate=True)\\n        except (ValueError, TypeError) as error:\\n            raise ProviderError('phone output base64 is invalid') from error\\n        require(type(event.get('byte_count')) is int and event['byte_count'] == len(raw),\\n                'phone output byte count differs')\\n        streams[name].extend(raw)\\n    kinds = [record['event']['kind'] for record in events]\\n    require(len(kinds) >= 3 and kinds[:2] == ['accepted', 'started']\\n            and kinds[-1] == 'terminal' and all(kind == 'output' for kind in kinds[2:-1]),\\n            'phone result does not contain its original accepted/start/terminal events')\\n    observed_terminal = events[-1]['event'].get('terminal')\\n    require(isinstance(observed_terminal, dict) and observed_terminal == terminal\\n            and all(type(observed_terminal[key]) is type(value)\\n                    for key, value in terminal.items()),\\n            'phone terminal event differs in value or field type')\\n    for name, raw in streams.items():\\n        require(type(terminal.get(name + '_bytes')) is int\\n                and terminal[name + '_bytes'] == len(raw), 'phone terminal count differs')\\n    require(not streams['stderr'], 'phone semantic tool reported stderr')\\n    return bytes(streams['stdout'])\\n\\n\",\"new_native_streams\":\"def native_streams(reply, call_id, expected_tool='adb.exec', *, expected_call):\\n    # Bind returned routing metadata to the trusted mapped call, never to the\\n    # result's own (possibly self-consistent) target assertions.\\n    require(type(expected_tool) is str and expected_tool in {'adb.exec', 'shell.exec'},\\n            'unqualified phone result wire tool')\\n    require(isinstance(expected_call, dict) and type(call_id) is str\\n            and expected_call.get('call_id') == call_id\\n            and expected_call.get('tool') == expected_tool,\\n            'phone result lacks its trusted mapped wire call')\\n    target_alias, target_id = expected_call.get('target'), expected_call.get('target_id')\\n    require((target_alias is None or type(target_alias) is str)\\n            and (target_id is None or type(target_id) is str)\\n            and (target_alias is None or target_id is None or target_alias == target_id),\\n            'phone mapped target aliases or types differ')\\n    expected_target = target_id if target_id is not None else target_alias\\n    require(isinstance(reply, dict) and reply.get('call_id') == call_id\\n            and reply.get('status') == 'terminal',\\n            'phone result lacks matching terminal identity')\\n    registry = reply.get('registry')\\n    require(isinstance(registry, dict) and registry.get('call_id') == call_id\\n            and registry.get('tool') == expected_tool and 'target_id' in registry\\n            and type(registry['target_id']) is type(expected_target)\\n            and registry['target_id'] == expected_target,\\n            'phone registry identity differs from the mapped wire call')\\n    terminal = reply.get('terminal')\\n    require(isinstance(terminal, dict) and set(terminal) == {\\n                'kind', 'exit_code', 'signal', 'stdout_bytes', 'stderr_bytes',\\n                'output_truncated', 'elapsed_ms', 'error'}\\n            and terminal.get('kind') == 'exited'\\n            and type(terminal.get('exit_code')) is int and terminal['exit_code'] == 0\\n            and terminal['signal'] is None and terminal['error'] is None\\n            and terminal['output_truncated'] is False\\n            and type(terminal['elapsed_ms']) is int\\n            and 0 <= terminal['elapsed_ms'] <= 18446744073709551615,\\n            'phone semantic tool is not confirmed successful in the qualified terminal schema')\\n    streams = {'stdout': bytearray(), 'stderr': bytearray()}\\n    events = reply.get('events')\\n    require(isinstance(events, list), 'phone result events are missing')\\n    for index, record in enumerate(events):\\n        require(isinstance(record, dict) and set(record) == {\\n                    'call_id', 'target_id', 'tool', 'seq', 'elapsed_ms', 'event'}\\n                and record['call_id'] == call_id and record['tool'] == expected_tool\\n                and type(record['target_id']) is type(expected_target)\\n                and record['target_id'] == expected_target\\n                and type(record['seq']) is int and record['seq'] == index\\n                and type(record['elapsed_ms']) is int\\n                and 0 <= record['elapsed_ms'] <= 18446744073709551615,\\n                'phone result event schema, scope, target, sequence or elapsed time differs')\\n        event = record['event']\\n        require(isinstance(event, dict) and type(event.get('kind')) is str\\n                and event['kind'] in {'accepted', 'started', 'output', 'terminal'},\\n                'phone result contains an unqualified event kind')\\n        fields = {'accepted': {'kind'}, 'started': {'kind', 'pid'},\\n                  'output': {'kind', 'stream', 'encoding', 'data', 'byte_count'},\\n                  'terminal': {'kind', 'terminal'}}\\n        require(set(event) == fields[event['kind']], 'phone result event fields differ')\\n        if event['kind'] == 'started':\\n            require(type(event['pid']) is int and 1 <= event['pid'] <= 4294967295,\\n                    'phone started event lacks a qualified process ID')\\n        if event['kind'] != 'output':\\n            continue\\n        name = event['stream']\\n        require(type(name) is str and name in streams and event['encoding'] == 'base64'\\n                and type(event['data']) is str, 'phone output stream differs')\\n        try:\\n            raw = base64.b64decode(event['data'], validate=True)\\n        except (ValueError, TypeError) as error:\\n            raise ProviderError('phone output base64 is invalid') from error\\n        require(base64.b64encode(raw).decode() == event['data']\\n                and type(event['byte_count']) is int and event['byte_count'] == len(raw),\\n                'phone output encoding or byte count differs')\\n        streams[name].extend(raw)\\n    kinds = [record['event']['kind'] for record in events]\\n    require(len(kinds) >= 3 and kinds[:2] == ['accepted', 'started']\\n            and kinds[-1] == 'terminal' and all(kind == 'output' for kind in kinds[2:-1]),\\n            'phone result does not contain its original accepted/start/terminal events')\\n    observed_terminal = events[-1]['event']['terminal']\\n    require(isinstance(observed_terminal, dict) and observed_terminal == terminal\\n            and all(type(observed_terminal[key]) is type(value)\\n                    for key, value in terminal.items()),\\n            'phone terminal event differs in value or field type')\\n    for name, raw in streams.items():\\n        require(type(terminal[name + '_bytes']) is int\\n                and terminal[name + '_bytes'] == len(raw), 'phone terminal count differs')\\n    require(not streams['stderr'], 'phone semantic tool reported stderr')\\n    return bytes(streams['stdout'])\\n\",\"callsite_old\":\"native_streams(actual, call_id, call.get('wire_tool', 'adb.exec'))\",\"callsite_new\":\"native_streams(actual, call_id, call.get('wire_tool', 'adb.exec'), expected_call=call['wire_call'])\"}")
def sha(b):return hashlib.sha256(b).hexdigest()
def meta(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def pinned(path,length,digest):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd);assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==length
  chunks=[];count=0
  while True:
   b=os.read(fd,min(65536,length+1-count))
   if not b:break
   chunks.append(b);count+=len(b);assert count<=length
  raw=b"".join(chunks)
  assert meta(before)==meta(os.fstat(fd))==meta(path.lstat())
  assert len(raw)==length and sha(raw)==digest
  return raw
 finally:os.close(fd)
def write(path,raw):
 path.parent.mkdir(parents=True,exist_ok=True)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,"wb")as f:f.write(raw);f.flush();os.fsync(f.fileno())
 assert path.read_bytes()==raw
 return {"path":str(path),"bytes":len(raw),"sha256":sha(raw),"git_blob_sha1":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()}
def js(value):return (json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+"\n").encode()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument("--base-package",type=Path,required=True);ap.add_argument("--out",type=Path,required=True)
 args=ap.parse_args();base=args.base_package.resolve();out=args.out.resolve();os.umask(0o077)
 pins_raw=(base/"CANDIDATE-PINS.json").read_bytes();assert sha(pins_raw)==BASE_PINS_SHA
 pins=json.loads(pins_raw);old={}
 for row in pins["files"]:old[row["path"]]=pinned(base/row["path"],row["bytes"],row["sha256"])
 original={Path(k).name:v for k,v in old.items() if k.startswith("reference/production/")}
 prior={Path(k).name:v for k,v in old.items() if k.startswith("candidate/source/")}
 assert len(original)==len(prior)==15 and set(original)==set(prior)
 assert sha(prior["phone_observation_tools.py"])==V1_OBS and sha(prior["daily_phone_local.py"])==V1_DAILY
 assert sha(prior["phone_local_tools.py"])==LOCAL
 candidate=dict(prior);obs=prior["phone_observation_tools.py"].decode()
 oldfn=TRANSFORM["old_native_streams"];newfn=TRANSFORM["new_native_streams"]
 assert obs.count(oldfn)==1
 obs=obs.replace(oldfn,newfn)
 invocation_counts={}
 for variable,expected in (("reply",1),("actual",6)):
  oldcall="native_streams("+variable+", call_id, call.get('wire_tool', 'adb.exec'))"
  newcall=oldcall[:-1]+", expected_call=call['wire_call'])"
  assert obs.count(oldcall)==expected;invocation_counts[variable]=expected;obs=obs.replace(oldcall,newcall)
 local=prior["phone_local_tools.py"].decode()
 assert local.count(TRANSFORM["callsite_old"])==1
 local=local.replace(TRANSFORM["callsite_old"],TRANSFORM["callsite_new"])
 candidate["phone_observation_tools.py"]=obs.encode();candidate["phone_local_tools.py"]=local.encode()
 daily=prior["daily_phone_local.py"].decode()
 for oldhash,name in ((V1_OBS,"phone_observation_tools.py"),(LOCAL,"phone_local_tools.py")):
  assert daily.count(oldhash)==1;daily=daily.replace(oldhash,sha(candidate[name]))
 candidate["daily_phone_local.py"]=daily.encode()
 changed=sorted(n for n in prior if candidate[n]!=prior[n]);assert changed==["daily_phone_local.py","phone_local_tools.py","phone_observation_tools.py"]
 for name,raw in candidate.items():ast.parse(raw,filename=name)
 tree=ast.parse(candidate["daily_phone_local.py"]);parents=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=="PARENTS"for t in n.targets))
 assert set(parents)==set(candidate)-{"daily_phone_local.py"}
 assert all(sha(candidate[n])==digest for n,digest in parents.items())
 rows=[]
 for folder,files in (("reference/production",original),("candidate/source",candidate)):
  for name,raw in sorted(files.items()):
   row=write(out/folder/name,raw);row["path"]=str(Path(folder)/name);rows.append(row)
 for name in ("phone_observation_tools.py","daily_phone_local.py"):
  write(out/"reference/native-v1"/name,prior[name])
 comb=pins["current_combination"];raw=pinned(base/comb["archived_path"],comb["bytes"],comb["sha256"]);write(out/comb["archived_path"],raw)
 legacy=pins["reference_runner"];raw=pinned(base/legacy["path"],legacy["bytes"],legacy["sha256"]);write(out/legacy["path"],raw)
 write(out/"reference/BASE-CANDIDATE-PINS.original.json",pins_raw)
 patches={}
 for name in changed:
  diff="".join(difflib.unified_diff(prior[name].decode().splitlines(keepends=True),candidate[name].decode().splitlines(keepends=True),fromfile="native-v1/"+name,tofile="native-v2/"+name))
  patches[name]=write(out/"patches"/(name+".patch"),diff.encode())
 manifest={"schema":"razr60-native-streams-v2-full15-source-pins/v1","base_candidate_pins_sha256":BASE_PINS_SHA,
  "production_source_count":15,"candidate_source_count":15,"changed_source_files":changed,"files":rows,
  "current_combination":comb,"reference_runner":legacy,"adopted":False,"whole_NEG11_qualified":False,"whole_NEG12_qualified":False,"whole_NEG13_qualified":False,
  "candidate_scope":"Host-only consumer candidate; current NEG01 full six-field records and eight-field terminal, explicit trusted mapped target binding",
  "phone_calls":0,"model_requests":0,"native_dispatches":0}
 pin=write(out/"CANDIDATE-PINS.json",js(manifest))
 derivation={"schema":"razr60-native-streams-v2-derivation/v1","base_pins_sha256":BASE_PINS_SHA,"candidate_pins":pin,"changed_files":changed,
  "observation_function_replacement":"native_streams only","existing_callsite_updates":8,"observation_callsite_counts":invocation_counts,"phone_local_callsite_count":1,
  "semantic_record_fields_added":False,"wire_call_already_persisted_by_original_map":True,"phone_local_adapter_existing_exact_dispatch_gate_unchanged":True,
  "daily_edits":"Exactly two PARENTS SHA256 strings","other_twelve_sources_unchanged":True,"all_fifteen_parse":True,"all_fourteen_daily_parent_pins_match":True,
  "historical_native_v1_preserved":True,"legacy_minimal_terminal_rejected_only_by_new_v2":True,"patches":patches,
  "limitations":["No installed schema claim beyond current archived NEG01 originals and reviewed matching producer sources.","No phone/model/native dispatch or runtime adoption.","Registry routing identity is checked; generation, request canonical digest and configuration fingerprint are not reconstructed by this consumer."]}
 write(out/"DERIVATION.json",js(derivation))
 assert all(pinned(base/row["path"],row["bytes"],row["sha256"])==old[row["path"]] for row in pins["files"])
 print(json.dumps({"state":"BUILT_NOT_ADOPTED","candidate_pins":pin,"changed_files":[row for row in rows if row["path"].startswith("candidate/")and Path(row["path"]).name in changed],"source_count":15,"original_sources_unchanged":True,"native_dispatches":0,"phone_calls":0},sort_keys=True))
if __name__=="__main__":main()
