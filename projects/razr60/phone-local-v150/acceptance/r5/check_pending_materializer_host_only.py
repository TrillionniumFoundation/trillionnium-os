#!/usr/bin/env python3
"""One bounded host check: pending combination must not materialize request bytes."""
import ast,json,subprocess,sys
from pathlib import Path
import aggregate_protocol_r5 as b
base=Path(__file__).resolve().parent
for name in ("aggregate_protocol_r5.py","materialize_case_r5.py"):
 ast.parse(b.read(base/name).decode("utf-8"),filename=name)
target=base/"validation"/"PENDING-MUST-NOT-MATERIALIZE"
assert not target.exists() and not target.is_symlink()
args=[sys.executable,"-B",str(base/"materialize_case_r5.py"),"health",
 "--combination",str(base/"COMBINATION-PENDING.json"),
 "--combination-sha256","f5f778e908e46f2c291da06a08dc9546ac803350e6ec9989582564d1ca3de086",
 "--out",str(target)]
p=subprocess.run(args,cwd=base,capture_output=True,timeout=10,check=False)
expected="No materialization against pending module/policy/native-App inputs"
assert p.returncode!=0 and expected in p.stderr.decode("utf-8") and not p.stdout
assert not target.exists() and not target.is_symlink()
value={"schema":"hepta.acceptance-r5.materializer-pending-rejection.v150.1","state":"PASS",
 "scope":"Host process only; intentional rejection is expected.",
 "materializer_sha256":b.sha(b.read(base/"materialize_case_r5.py")),
 "wrapper_sha256":b.sha(b.read(base/"aggregate_protocol_r5.py")),
 "actual_process_return_code":p.returncode,"stdout_bytes":len(p.stdout),"stderr_bytes":len(p.stderr),
 "stderr_sha256":b.sha(p.stderr),"expected_rejection_label_present":True,
 "new_request_output_directory_absent":True,"phone_calls":0,"model_requests":0,
 "request_materials_created":0,"fixture_is_not_a_fixed19_sample":True}
r=b.write_new(base/"validation/MATERIALIZER-PENDING-REJECTION.json",
 (json.dumps(value,sort_keys=True,indent=2)+"\n").encode())
print(json.dumps({"result":r,"expected_child_returncode":p.returncode,"phone_calls":0,"request_materials_created":0}))
