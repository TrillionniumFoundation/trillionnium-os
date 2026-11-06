#!/usr/bin/env python3
"""Run retained offline controls against the merged unbound install reader."""
import contextlib,hashlib,io,json,os,runpy,shlex,sys,types
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
E=ROOT/"evidence";E.mkdir(mode=0o700)
def save(name,raw):
    with(E/name).open("xb")as f:f.write(raw);f.flush();os.fsync(f.fileno())
def check(v):
    if not v:raise AssertionError("merge control")
sys.argv=[str(ROOT/"validation/run_install_ready_candidate_controls.py"),str(E/"mac-merged-controls01")]
capture=io.TextIOWrapper(io.BytesIO())
with contextlib.redirect_stdout(capture):r=runpy.run_path(sys.argv[0])
save("portable.stdout",capture.buffer.getvalue())
sys.argv=[str(ROOT/"validation/run_controller_phone_rc_controls.py")]
capture2=io.TextIOWrapper(io.BytesIO())
with contextlib.redirect_stdout(capture2):runpy.run_path(sys.argv[0])
save("phone-rc.stdout",capture2.buffer.getvalue())
R,P,ns=r["R"],r["P"],r["ns"]
P1=types.ModuleType("original_protocol")
exec(compile((ROOT/"references/install_ready_execution_protocol.v1.py").read_bytes(),"original_protocol","exec"),P1.__dict__)
cases=[]
def test(name,fn):fn();cases.append(dict(name=name,passed=True))
test("exact_unmodified_v2_protocol_guard",lambda:check(P.GUARD==P1.GUARD))
facts=json.loads((ROOT/"CANDIDATE-MANIFEST.json").read_bytes())
test("exact_actual_prefix_in_source",lambda:check(P.GNU_EXEC_PREFIX==facts["actual_prefix"]))
for phase in P.PHASES:
    old=P1.expected_phase(ns["plan"],phase,ns["release"],ns["release_inputs"],"3"*64)
    new=P.expected_phase(ns["plan"],phase,ns["release"],ns["release_inputs"],"3"*64)
    def verify(old=old,new=new):
        check(old["spec"]==new["spec"] and old["dispatch"]==new["dispatch"] and old["actor_operation_dir"]==new["actor_operation_dir"])
        check(shlex.split(new["request"]["command"])[:-1]==P.GNU_EXEC_PREFIX)
        check(shlex.split(new["request"]["command"])[-1]==shlex.split(old["request"]["command"])[-1])
        check(new["request"]["timeout_seconds"]==old["request"]["timeout_seconds"] and new["wire_bytes"]<65536)
        check(new["request_raw"]==P.request_bytes(new["request"]) and new["request_raw"].endswith(b"\n"))
    test(phase+"_only_environment_command_prefix_differs",verify)
portable=json.loads((E/"mac-merged-controls01/RESULT.json").read_bytes())
phone=json.loads((ROOT/"validation/CONTROLLER-PHONE-RC-RESULT.json").read_bytes())
report=dict(schema="razr60-install-ready-merged-offline-controls/v1",state="PASS_SOURCE_ONLY",
            source_pins=facts["selected"],portable_controls=portable["passed"],phone_rc_controls=phone["passed"],
            environment_controls=len(cases),passed=portable["passed"]+phone["passed"]+len(cases),
            tests=cases,linux_guard_execution=portable["host_guard_execution_skip"],
            actual_slots_bound=False,actual_builds=0,phone_calls=0,actual_installs=0,actual_READY=0,
            formal_role_identities_generated=0,fixed19_credit=0)
save("RESULT.json",(json.dumps(report,sort_keys=True,indent=2)+"\n").encode())
print(json.dumps(report,sort_keys=True))
