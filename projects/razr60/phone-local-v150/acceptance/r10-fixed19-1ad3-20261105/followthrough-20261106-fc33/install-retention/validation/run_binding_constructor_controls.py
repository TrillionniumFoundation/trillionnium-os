"""In-memory source constructor controls. Descriptors are explicitly synthetic."""
import ast,hashlib,json,runpy,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1];ns=runpy.run_path(str(root/"build_reader_binding.py"))
raw=(root/"source/verify_install_retention_UNBOUND.py").read_bytes();cases=[]
def check(v):
 if not v:raise AssertionError("source constructor control")
def test(name,fn):fn();cases.append(dict(name=name,passed=True))
def rejects(name,fn):
 try:fn()
 except ValueError as e:cases.append(dict(name=name,passed=True,rejection=str(e)))
 else:raise AssertionError(name)
a=dict(path="/HOST_SOURCE_CONTROL/actual-authority.json",bytes=17,sha256="a"*64)
b=dict(path="/HOST_SOURCE_CONTROL/retention-originals.json",bytes=18,sha256="b"*64)
test("no_descriptor_leaves_both_slots_unbound",lambda:check(ns["derive"](raw)[0]==raw))
one,facts=ns["derive"](raw,a)
test("phase_only_exact_single_rhs_and_inverse",lambda:check(facts["exact_forward_inverse"]and b"FROZEN_RETENTION_INPUTS = None\n"in one))
two,facts=ns["derive"](raw,a,b)
test("two_actual_descriptor_slots_exact_inverse",lambda:check(facts["exact_forward_inverse"]and facts["selected"]==ns["pin"](two)))
test("constructor_does_not_claim_actual_success",lambda:check(facts["actual_inputs_verifier_executed"]is False and facts["qualification_granted"]is False))
rejects("retention_cannot_omit_phase_authority",lambda:ns["derive"](raw,None,b))
rejects("changed_source_bytes_refused",lambda:ns["derive"](raw+b"\n",a))
rejects("already_bound_source_not_rebound",lambda:ns["derive"](one,a))
rejects("boolean_descriptor_bytes_refused",lambda:ns["derive"](raw,dict(a,bytes=True)))
rejects("relative_descriptor_path_refused",lambda:ns["derive"](raw,dict(a,path="relative")))
rejects("duplicate_descriptor_json_refused",lambda:ns["strict"](b'{"bytes":1,"bytes":2}'))
report=dict(schema="hepta.install-retention.binding-constructor-controls.v1",state="PASS_SOURCE_ONLY",
 passed=len(cases),tests=cases,parent_source=ns["pin"](raw),synthetic_descriptors_only=True,
 source_candidates_compiled_in_memory_only=True,actual_manifest_generated=False,
 actual_scopes_bound=0,phone_calls=0,actual_install=0,actual_READY=0,fixed19_credit=0)
out=Path(sys.argv[1]);out.mkdir(mode=0o700)
with(out/"RESULT.json").open("xb")as f:f.write((json.dumps(report,sort_keys=True,indent=2)+"\n").encode())
print(json.dumps(report,sort_keys=True))
