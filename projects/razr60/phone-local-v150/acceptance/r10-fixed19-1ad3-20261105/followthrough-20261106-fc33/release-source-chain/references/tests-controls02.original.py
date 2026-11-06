"""Source-only controls. Private fixtures never become actual BUILD/READY inputs."""
import ast,copy,hashlib,json,os,stat,subprocess,sys,types
from pathlib import Path
root=Path(__file__).resolve().parent.parent
source=root/"source/derive_reviewed_release_sources_UNBOUND.py"
out=Path(sys.argv[1]);out.mkdir(mode=0o700)
M=types.ModuleType("source_chain");M.__file__=str(source);exec(compile(source.read_bytes(),str(source),"exec"),M.__dict__)
baseline=json.loads((root/"references/ORIGINALS.json").read_bytes())
raws={}
for r in baseline["files"]:
 raw=(root/r["copy"]).read_bytes()
 assert len(raw)==r["original"]["bytes"] and hashlib.sha256(raw).hexdigest()==r["original"]["sha256"]
 raws[r["original"]["path"]]=raw
originals=lambda r:raws[r["path"]]
actual=json.loads((root/"references/MATERIAL-V2-DESCRIPTORS.json").read_bytes())
cases=[]
def check(v,why="control"):
 if not v:raise AssertionError(why)
def test(name,fn):
 fn();cases.append(dict(name=name,passed=True))
def rejects(name,fn,text=None):
 try:fn()
 except ValueError as e:
  if text is not None:check(text in str(e),str(e))
  cases.append(dict(name=name,passed=True,rejection=str(e)))
 else:raise AssertionError("accepted "+name)
calls=[]
def forbidden(*a,**k):calls.append((a,k));raise AssertionError("unexpected original read")
rejects("public_unbound_rejects_before_malformed_input_or_callback",lambda:M.derive_reviewed_source_chain(None,read_pinned=forbidden),"UNBOUND")
test("unbound_has_zero_reads",lambda:check(calls==[]))
for value in (False,0.0,-1):
 row=dict(path="/HOST_SOURCE_CONTROL/input",bytes=value,sha256="0"*64)
 rejects("descriptor_rejects_"+repr(value),lambda r=row:M.descriptor(r),"typed bounded")
rejects("duplicate_JSON_rejected",lambda:M.strict(b'{"x":0,"x":0}\n'),"duplicate")
rejects("CRLF_not_original_serializer",lambda:M.styled(b'{"x":0}\r\n'),"serializer")
rejects("duplicate_source_assignment_rejected",lambda:M.literal(b"X=1\nX=2\n","X"),"one reviewed")
c=M.Changes(b"X = None\n");c.rhs("X",{"typed":False,"count":0});changed,proof=c.finish()
test("whole_source_forward_inverse",lambda:check(proof["complete_inverse"]and M.literal(changed,"X")=={"typed":False,"count":0}))
historical=M._material(actual,M.Originals(originals),require_five=False)
test("actual_three_source_material_complete_graph_and_daily_checked",lambda:check(len(historical["sources"])==15 and len(historical["changed"])==3))
rejects("historical_three_source_not_final_five_source",lambda:M._material(actual,M.Originals(originals)),"all five")
# Fully synthetic five-source graph, isolated in memory and explicitly named HOST_SOURCE_CONTROL.
# It exercises the source constructor and its graph inverses; it is never saved as an actual material manifest.
def fixture():
 memory=dict(raws);base="/HOST_SOURCE_CONTROL/material";old=historical["old_raw"]
 new=dict(historical["sources"])
 for n in ("provider_codex_host.py","provider_phone_local.py"):new[n]+=b"\n# HOST_SOURCE_CONTROL_ONLY\n"
 daily=historical["old_sources"]["daily_phone_local.py"]
 for n in sorted(M.FIVE-{"daily_phone_local.py"}):daily=daily.replace(M.pin(historical["old_sources"][n])["sha256"].encode(),M.pin(new[n])["sha256"].encode(),1)
 new["daily_phone_local.py"]=daily
 def save(name,body):memory[name]=body;return M.located(name,body)
 source_rows={n:save(base+"/shared/provider/source/"+n,b)for n,b in new.items()}
 producer=save("/HOST_SOURCE_CONTROL/material_producer.py",b"# HOST_SOURCE_CONTROL_ONLY\n")
 sin=dict(schema="hepta.reviewed-source-material-derivation-input.v1",state="HOST_SOURCE_ONLY_NOT_RUNTIME_ADOPTION",
  original_component=M.R4["combination"],builder=producer,original_request_sha256="1"*64,
  reviewed_replacements={n:source_rows[n]for n in sorted(M.FIVE)},changed_sources=sorted(M.FIVE),
  phone_calls=0,actual_cleanup_closure_bound=False)
 graph={"source_inputs":M.enc(sin)}
 def changed_rows(rows):return[dict(path=r["path"],**M.pin(new[Path(r["path"]).name]))for r in rows]
 v,pretty=M.styled(old["service"]);v["provider_sources"]=changed_rows(v["provider_sources"]);v["parent_service_inputs_sha256"]=M.pin(old["service"])["sha256"];graph["service"]=M.enc(v,pretty)
 v,pretty=M.styled(old["configuration"]);v["service_manifest_sha256"]=M.pin(graph["service"])["sha256"];graph["configuration"]=M.enc(v,pretty)
 v,pretty=M.styled(old["source_seal"]);v.update(configuration=M.pin(graph["configuration"]),phone_service_inputs_sha256=M.pin(graph["service"])["sha256"],production_files=changed_rows(v["production_files"]));graph["source_seal"]=M.enc(v,pretty)
 v,pretty=M.styled(old["combination"]);v.update(configuration=M.pin(graph["configuration"]),service_inputs=M.pin(graph["service"]),source_seal=M.pin(graph["source_seal"]),production_files=changed_rows(v["production_files"]));graph["combination"]=M.enc(v,pretty)
 members={"local-config-r10-r1.json":graph["configuration"],"PHONE-SERVICE-INPUTS-v150-r10-r1.json":graph["service"]}
 members.update({"provider/source/"+n:b for n,b in new.items()})
 v,pretty=M.styled(old["shared"]);v.update(files=[dict(path=r["path"],**M.pin(members[r["path"]]))for r in v["files"]],
  parent_configuration_sha256=M.pin(old["configuration"])["sha256"],parent_service_inputs_sha256=M.pin(old["service"])["sha256"],
  source_input_sha256=M.pin(graph["source_inputs"])["sha256"]);graph["shared"]=M.enc(v,pretty)
 material={k:save(base+"/"+M.MATERIAL_NAMES[k],b)for k,b in graph.items()}
 material["producer"]=producer
 files={M.MATERIAL_NAMES[k]:b for k,b in graph.items()}
 files.update({"shared/"+n:b for n,b in members.items()})
 files.update({"reference/"+M.MATERIAL_NAMES[k].replace("/","__"):b for k,b in old.items()})
 d=dict(schema="hepta.reviewed-source-material-derivation.v1",state="DERIVED_SHARED_SOURCE_MATERIAL_ONLY",
  changed_sources=sorted(M.FIVE),builder=M.pin(memory[producer["path"]]),source_count=15,daily_dependency_count=14,shared_member_count=17,
  combination=M.pin(graph["combination"]),source_seal=M.pin(graph["source_seal"]),configuration=M.pin(graph["configuration"]),
  service_inputs=M.pin(graph["service"]),shared_manifest=M.pin(graph["shared"]),files=[dict(path=n,**M.pin(b))for n,b in sorted(files.items())],
  actual_BUILD=False,actual_READY=False,actual_install=False,actual_cleanup_closure_bound=False,runtime_freeze=False,
  root_plan_generated=False,native_history_rebased=False,phone_calls=0,new_nonces=0,fixed19_credit=0)
 material["derivation"]=save(base+"/DERIVATION.json",M.enc(d))
 manifest=M.enc(dict(schema="hepta.native-guard.adapter-package.v1",state="HOST_REVIEWED_NOT_PHONE_QUALIFIED",
  files=[dict(path="source/HOST_SOURCE_CONTROL.py",bytes=1,sha256="2"*64)]))
 runtime=save("/HOST_SOURCE_CONTROL/RUNTIME-PACKAGE.json",manifest)
 consumer_parent=raws[baseline["consumer_original"]["path"]]
 c=M.Changes(consumer_parent);c.rhs("PACKAGE_SHA",M.pin(manifest)["sha256"]);c.rhs("PACKAGE_FILE_COUNT",1)
 c.rhs("CURRENT_COMBINATION_SHA",M.pin(graph["combination"])["sha256"])
 # The literal is deliberately a fixture value. Actual chain/root counts are absent from this package.
 c.once("def need(value, reason):","CURRENT_COMPONENT_CHAIN_LENGTH = 13\n\ndef need(value, reason):")
 consumer_raw,_=c.finish()
 consumer=save("/HOST_SOURCE_CONTROL/release_boundaries.py",consumer_raw)
 value=dict(schema=M.INPUT_SCHEMA,material=material,consumer=dict(source=consumer,runtime_package=runtime),output_root="/HOST_SOURCE_CONTROL/source_chain")
 return memory,value
memory,value=fixture()
result=M._derive(value,M.Originals(lambda r:memory[r["path"]]))
test("five_source_fixture_derives_only_source_candidates",lambda:check(result["report"]["actual_execution_slots_unbound"]and result["report"]["BUILD"]is False and result["report"]["phone_calls"]==0))
test("all_eight_changed_sources_have_full_inverse",lambda:check(len(result["changes"])==8 and all(r["complete_inverse"]for r in result["changes"].values())))
def loaded(name):
 module=types.ModuleType("fixture_"+Path(name).stem);module.__file__=value["output_root"]+"/"+name
 exec(compile(result["files"][name],module.__file__,"exec"),module.__dict__);return module
reader=loaded("source/verify_final_release_inputs.py");builder=loaded("source/build_release_r10.py")
installer=loaded("source/install_phone_release_r10.py");ready=types.SimpleNamespace(BOUNDARY_CONSUMER_SHA256=M.literal(result["files"]["source/collect_r10_readiness.py"],"BOUNDARY_CONSUMER_SHA256"))
proto=loaded("source/install_ready_execution_protocol.py");install=loaded("source/verify_install_start_ready_UNBOUND.py")
retain=loaded("source/verify_install_retention_UNBOUND.py");exact8=loaded("source/verify_resident_output_bindings.py")
test("consumer_pin_reaches_builder_installer_readiness",lambda:check(builder.BOUNDARY_CONSUMER_SHA256==installer.BOUNDARY_CONSUMER_SHA256==ready.BOUNDARY_CONSUMER_SHA256==M.pin(result["files"]["source/release_boundaries.py"])["sha256"]))
test("source_reader_descriptor_chain_complete",lambda:check(proto.INSTALLER_PIN==M.pin(result["files"]["source/install_phone_release_r10.py"])and proto.READY_PIN==exact8.READY_PIN==M.pin(result["files"]["source/collect_r10_readiness.py"])and exact8.RELEASE_READER==install.SOURCES["release"]and retain.INSTALL_READER["sha256"]==M.pin(result["files"]["source/verify_install_start_ready_UNBOUND.py"])["sha256"]))
test("runtime_count_from_consumer_not_old_literal",lambda:check(reader.RUNTIME==exact8.RUNTIME==M.pin(memory[value["consumer"]["runtime_package"]["path"]])["sha256"]and reader.CURRENT_COMPONENT_CHAIN_LENGTH==13 and result["consumer_runtime"]["package_file_count"]==1))
rejects("derived_install_reader_still_unbound_before_IO",lambda:install.verify_install_start_ready_originals(None,read_pinned=forbidden),"UNBOUND")
rejects("derived_retention_reader_still_unbound_before_IO",lambda:retain.derive_scope_from_actual_phase(None,read_pinned=forbidden),"UNBOUND")
test("all_execution_slots_remain_None",lambda:check(install.FROZEN_INPUTS is None and install.FROZEN_EXECUTION_PLAN is None and retain.FROZEN_PHASE_AUTHORITY is None and retain.FROZEN_RETENTION_INPUTS is None))
formal_raw=result["files"]["contracts/FINAL-INTEGRATION-INPUTS.json"]
all_bytes=dict(memory);all_bytes.update({value["output_root"]+"/"+n:b for n,b in result["files"].items()})
builder.read=lambda r:all_bytes[r["path"]]
test("derived_formal_whole_inverse_gate_accepts_only_five_plus_readiness",lambda:check(builder.verify_current_formal_parent(formal_raw,json.loads(formal_raw),result["files"]["source/collect_r10_readiness.py"])==value["material"]["source_inputs"]["sha256"]))
bad=json.loads(formal_raw);bad["configuration"]["bytes"]+=1
rejects("formal_unrelated_parent_change_rejected",lambda:builder.verify_current_formal_parent(M.enc(bad),bad,result["files"]["source/collect_r10_readiness.py"]),"beyond five")
# Execute only the actual pure host module-wiring function with original module inputs and /bin/sh -n checks.
builder.read_owner_finalizer_source=lambda r:raws[r["path"]]
formal_parent=json.loads(raws[M.REFS["formal"]["path"]])
module={r["name"]:raws[r["path"]]for r in formal_parent["module_sources"]}
wired=builder.wire_module(module,M.pin(memory[value["material"]["configuration"]["path"]])["sha256"])
test("actual_wire_function_matches_derived_owner_service_full_bytes",lambda:check(wired["service.sh"]==result["files"]["preview-module/service.sh"]and wired["RESIDENT-OWNER-FINALIZER.json"]==result["files"]["preview-module/RESIDENT-OWNER-FINALIZER.json"]))
test("release_reader_uses_exact_derived_owner_module_pins",lambda:check(reader.verify_owner_finalizer_module(wired)["resident_terminal_qualified"]is False))
for key,new,expected in (("source_count",15.0,"typed source derivation"),("phone_calls",False,"typed source derivation"),("actual_READY",0,"cannot grant")):
 mem,v=fixture();row=v["material"]["derivation"];d=json.loads(mem[row["path"]]);d[key]=new;raw=M.enc(d);mem[row["path"]]=raw;v["material"]["derivation"]=M.located(row["path"],raw)
 rejects("material_rejects_typed_alias_"+key,lambda m=mem,x=v:M._material(x["material"],M.Originals(lambda r:m[r["path"]])),text=expected)
mem,v=fixture();row=v["material"]["configuration"];d=json.loads(mem[row["path"]]);d["model"]="UNREVIEWED";raw=M.enc(d);mem[row["path"]]=raw;v["material"]["configuration"]=M.located(row["path"],raw)
rejects("coherent_pin_wrong_configuration_rejected",lambda:M._material(v["material"],M.Originals(lambda r:mem[r["path"]])),"whole new configuration")
mem,v=fixture();row=v["consumer"]["source"];text=mem[row["path"]].decode().replace("CURRENT_COMPONENT_CHAIN_LENGTH = 13","CURRENT_COMPONENT_CHAIN_LENGTH = True");mem[row["path"]]=text.encode();v["consumer"]["source"]=M.located(row["path"],text.encode())
mat=M._material(v["material"],M.Originals(lambda r:mem[r["path"]]))
rejects("consumer_boolean_history_count_rejected",lambda:M._consumer(v["consumer"],mat,M.Originals(lambda r:mem[r["path"]])),"history chain length")
# Self-consistent original-process-shaped fixtures test only verify_build_process, never the actual BUILD gate.
def process_fixture(mutate=None):
 build={"schema":"HOST_SOURCE_CONTROL_ONLY","phone_calls":0}
 supplied={k:None for k in reader.FIELDS};supplied["schema"]=reader.SCHEMA
 for key in ("build_result","retirement_inputs","component_boundary_inputs"):
  supplied[key]=dict(path="/HOST_SOURCE_CONTROL/"+("BUILD-RESULT.json"if key=="build_result"else key+".json"),bytes=0,sha256="0"*64)
 command=reader.expected_build_command(supplied)
 started=dict(job=dict(id="HOST_SOURCE_CONTROL_JOB",host="mac",executable=command["executable"],args=command["args"],launch_state="launched",launch_error=None),reused=False)
 stdout=(json.dumps(build,sort_keys=True)+"\n").encode()
 status=dict(job_id="HOST_SOURCE_CONTROL_JOB",state="succeeded",exit_code=0,output_complete=True,output_durable=True,terminal_publication_confirmed=True,
  timed_out=False,cancelled=False,log_errors={"stderr":None,"stdout":None},log_truncated={"stderr":False,"stdout":False},
  log_synced={"stderr":True,"stdout":True},log_bytes={"stderr":{"seen":0,"stored":0},"stdout":{"seen":len(stdout),"stored":len(stdout)}})
 def stream(raw):return dict(offset=0,eof=True,next_offset=len(raw),size=len(raw),text=raw.decode(),bytes_hex=raw.hex())
 streams=dict(job_id="HOST_SOURCE_CONTROL_JOB",stdout=stream(stdout),stderr=stream(b""))
 if mutate:mutate(build,status,streams)
 def tool(v):return M.enc(dict(isError=False,content=[dict(type="text",text=json.dumps(v))]))
 pool_data={};records={}
 for key,data in (("start",started),("status",status),("read",streams)):
  raw=tool(data);row=M.located("/HOST_SOURCE_CONTROL/"+key+".json",raw);records[key]=row;pool_data[row["path"]]=raw
 supplied["build_process"]=records
 return reader.verify_build_process(supplied,build,reader.Originals(lambda r:pool_data[r["path"]]))
test("complete_process_source_fixture_baseline",lambda:check(process_fixture()["exit_code"]==0))
mutations=[
 ("stdout_offset_bool",lambda b,s,r:r["stdout"].update(offset=False)),
 ("stdout_offset_float",lambda b,s,r:r["stdout"].update(offset=0.0)),
 ("stderr_next_bool",lambda b,s,r:r["stderr"].update(next_offset=False)),
 ("stdout_next_float",lambda b,s,r:r["stdout"].update(next_offset=float(r["stdout"]["next_offset"]))),
 ("stderr_size_bool",lambda b,s,r:r["stderr"].update(size=False)),
 ("stdout_size_float",lambda b,s,r:r["stdout"].update(size=float(r["stdout"]["size"]))),
 ("stderr_seen_bool",lambda b,s,r:s["log_bytes"]["stderr"].update(seen=False)),
 ("stdout_stored_float",lambda b,s,r:s["log_bytes"]["stdout"].update(stored=float(s["log_bytes"]["stdout"]["stored"]))),
 ("stdout_truncated_zero",lambda b,s,r:s["log_truncated"].update(stdout=0)),
 ("stderr_truncated_float",lambda b,s,r:s["log_truncated"].update(stderr=0.0)),
 ("terminal_exit_bool",lambda b,s,r:s.update(exit_code=False)),
 ("retained_BUILD_counter_bool_alias",lambda b,s,r:b.update(phone_calls=False))
]
for name,mutate in mutations:rejects("release_process_rejects_"+name,lambda f=mutate:process_fixture(f))
test("phase_stdout_serializer_LF_preserved",lambda:check(install.original_entry_stdout({"text":"中文\n😀"})==(json.dumps({"text":"中文\n😀"},sort_keys=True)+"\n").encode()))
report=dict(schema="hepta.release-source-chain.host-controls.v1",state="PASS_SOURCE_CONSTRUCTOR_ONLY",passed=len(cases),tests=cases,
 source=M.pin(source.read_bytes()),actual_three_source_material_read=True,three_source_material_final_binding=False,
 synthetic_five_source_fixture_only=True,actual_five_source_material_bound=False,actual_runtime_or_cleanup_bound=False,
 source_chain_kept_in_memory=True,actual_BUILD=False,actual_install=False,actual_READY=False,phone_calls=0,generated_acceptance_nonces=0,fixed19_credit=0)
(out/"RESULT.json").write_bytes(M.enc(report))
print(json.dumps(report,sort_keys=True))
