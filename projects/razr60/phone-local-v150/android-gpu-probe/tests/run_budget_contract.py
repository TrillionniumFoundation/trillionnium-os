#!/usr/bin/env python3
"""Host-only contract check with mocked ABI calls; no SDK binary, model or phone."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,subprocess
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--out',type=Path,required=True,help='New output directory; an existing directory is refused')
a=p.parse_args()
root=Path(__file__).resolve().parents[1]
out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
compiler=os.environ.get('CC') or shutil.which('cc')
if not compiler:raise RuntimeError('Set CC or install a host C compiler')
command=[compiler,'-std=c11','-Wall','-Wextra','-Werror','-I'+str(root/'native'),'-I'+str(root/'native/vendor'),str(root/'tests/budget_contract.c'),'-o',str(out/'budget-contract')]
with (out/'compile.stdout').open('wb') as stdout,(out/'compile.stderr').open('wb') as stderr:
 subprocess.run(command,stdout=stdout,stderr=stderr,check=True,timeout=60)
with (out/'runtime.stdout').open('wb') as stdout,(out/'runtime.stderr').open('wb') as stderr:
 subprocess.run([str(out/'budget-contract')],stdout=stdout,stderr=stderr,check=True,timeout=30)
result=json.loads((out/'runtime.stdout').read_text())
result.update(boundary_scenarios=16,source_under_test_sha256=hashlib.sha256((root/'native/gpu-budget.inc').read_bytes()).hexdigest(),test_source_sha256=hashlib.sha256((root/'tests/budget_contract.c').read_bytes()).hexdigest())
(out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
