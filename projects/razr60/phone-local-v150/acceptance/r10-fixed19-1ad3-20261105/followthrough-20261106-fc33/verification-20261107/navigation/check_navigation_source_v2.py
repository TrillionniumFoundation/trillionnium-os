#!/usr/bin/env python3
"""Repeatable offline navigation controls for exact pinned source bytes.

No phone, socket, sender actor or native dispatch is used. All four source files
are verified before either executed module is compiled from those same bytes.
The original v1 script and its result remain separate, unchanged evidence.
"""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import types

REFERENCE_COMMIT = "ca3f26100c57579bcb740488e4a7f9ec8b912e4d"
SOURCE_REL = Path("projects/razr60/phone-local-v150/acceptance/r10-fixed19-1ad3-20261105/followthrough-20261106-fc33/actual-e2e-bound-source/actual/shared/provider/source")
SOURCE_PINS = {
    "phone_local_tools.py": (13927, "2d0c9cc8f1ff0c643aab3daeef07c12e84541f1c2f0bfd13c8043c5c8fa58930"),
    "phone_observation_tools.py": (55981, "4f95178996a2d7a604ae56eecd0f7725657222783f5cab5a7ff868f85a8cd086"),
    "phone_task_guards.py": (22825, "87d88e0e9f93b31cf69bf0e4cdb9c62fd20e03c2192a0ffec621eb84c26bba86"),
    "provider_openai_compatible.py": (17730, "337c83284fece94c0dd477a30029c63017b7eb00aab55a747b89b193823820bc"),
}


def load_verified_modules(repo_root):
    source = repo_root / SOURCE_REL
    verified = {}
    pins = {}
    for name, (size, digest) in SOURCE_PINS.items():
        path = source / name
        raw = path.read_bytes()
        actual = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        if actual != {"bytes": size, "sha256": digest}:
            raise RuntimeError("source_pin_mismatch_before_import: " + str(SOURCE_REL / name))
        verified[name] = raw
        pins[str(SOURCE_REL / name)] = actual
    # Never re-read source during import after the hash check. The two remaining
    # pinned files document the exact reviewed caller context, without execution.
    modules = {}
    for name in ("provider_openai_compatible", "phone_task_guards"):
        if name in sys.modules:
            raise RuntimeError("unexpected_preloaded_module: " + name)
        module = types.ModuleType(name)
        module.__file__ = str(source / (name + ".py"))
        module.__package__ = ""
        sys.modules[name] = module
        exec(compile(verified[name + ".py"], module.__file__, "exec"), module.__dict__)
        modules[name] = module
    return modules, pins


def run_controls(g, ProviderError):
    B64=lambda s:base64.b64encode(s.encode()).decode()
    TOKEN='a'*32
    page='\n'.join(['Display: mDisplayId=0','mTopFocusedDisplayId=0','mCurrentFocus=Window{a u0 '+g.HEPTA_COMPONENT+'}', 'mFocusedApp=ActivityRecord{b u0 '+g.HEPTA_COMPONENT+' t1}', 'isKeyguardShowing=false','topResumedActivity=ActivityRecord{b u0 '+g.HEPTA_COMPONENT+' t1}'])
    launch='Status: ok\nActivity: '+g.HEPTA_COMPONENT+'\n'
    receipt={'schema':'hepta.return-receipt.v149.1','operation_id':TOKEN,'launch_exit_code':0,'launch_b64':B64(launch),'page_b64':B64(page),'viewport_b64':B64('fixture viewport separately checked by caller')}
    results=[]
    def rejection(name, mutate):
     value=copy.deepcopy(receipt);mutate(value)
     try:g.verify_return(value,TOKEN)
     except ProviderError as e:results.append({'name':name,'passed':True,'rejection':str(e)})
     else:raise AssertionError(name+' accepted invalid receipt')
    assert g.verify_return(receipt,TOKEN)[0]['component']==g.HEPTA_FULL_COMPONENT
    results.append({'name':'complete exact launch/focus/resumed accepted','passed':True})
    rejection('nonzero launch',lambda r:r.update(launch_exit_code=137))
    rejection('boolean launch exit',lambda r:r.update(launch_exit_code=False))
    rejection('wrong operation',lambda r:r.update(operation_id='b'*32))
    rejection('missing launch Activity',lambda r:r.update(launch_b64=B64('Status: ok\n')))
    rejection('duplicate launch status',lambda r:r.update(launch_b64=B64(launch+'Status: ok\n')))
    rejection('wrong Activity same package',lambda r:r.update(launch_b64=B64(launch.replace('OwnerOpenShellActivity','OtherActivity'))))
    rejection('launch error alongside ok',lambda r:r.update(launch_b64=B64(launch+'Error: refused\n')))
    rejection('top resumed disagreement',lambda r:r.update(page_b64=B64(page.replace('topResumedActivity=ActivityRecord{b u0 '+g.HEPTA_COMPONENT,'topResumedActivity=ActivityRecord{b u0 other.app/.Main'))))
    rejection('current window disagreement',lambda r:r.update(page_b64=B64(page.replace('mCurrentFocus=Window{a u0 '+g.HEPTA_COMPONENT,'mCurrentFocus=Window{a u0 other.app/.Main'))))
    rejection('focused app disagreement',lambda r:r.update(page_b64=B64(page.replace('mFocusedApp=ActivityRecord{b u0 '+g.HEPTA_COMPONENT,'mFocusedApp=ActivityRecord{b u0 other.app/.Main'))))
    rejection('external focused display',lambda r:r.update(page_b64=B64(page.replace('mTopFocusedDisplayId=0','mTopFocusedDisplayId=1'))))
    rejection('keyguard active',lambda r:r.update(page_b64=B64(page.replace('isKeyguardShowing=false','isKeyguardShowing=true'))))
    rejection('missing actual resumed',lambda r:r.update(page_b64=B64('\n'.join(x for x in page.splitlines() if not x.startswith('topResumedActivity=')))))
    rejection('extra receipt field',lambda r:r.update(unverified=True))
    # Execute only local shell function mocks. A nonzero dump must not read partial XML.
    with tempfile.TemporaryDirectory(prefix='navigation-review-') as td:
     td=Path(td);xml=td/'capture.xml';attempt=td/'attempt';calls=td/'calls'
     shell='dumpsys() { return 0; }; uiautomator() { printf x >> '+shlex.quote(str(calls))+'; printf partial > "$2"; printf "Killed\\n" >&2; return 137; }; '
     shell+=g.public_text_command('',TOKEN,'test.app',str(xml))
     proc=subprocess.run(['/bin/sh','-c',shell],capture_output=True,timeout=5)
     assert proc.returncode==73 and calls.read_bytes()==b'x' and not xml.exists() and not proc.stdout and b'Killed' in proc.stderr
     results.append({'name':'public collector dump137 single attempt no receipt own XML removed','passed':True,'exit_code':proc.returncode})
    # Return launch is exactly one effect; a failed launch remains nonzero after read-only observations.
    with tempfile.TemporaryDirectory(prefix='navigation-review-') as td:
     td=Path(td);calls=td/'calls'
     shell='am() { printf x >> '+shlex.quote(str(calls))+'; printf "Error: refused\\n"; return 17; }; dumpsys() { return 0; }; '
     proc=subprocess.run(['/bin/sh','-c',shell+g.return_command('',TOKEN)],capture_output=True,timeout=5)
     payload=json.loads(proc.stdout)
     assert proc.returncode==17 and calls.read_bytes()==b'x' and payload['launch_exit_code']==17
     results.append({'name':'failed return launch remains nonzero and is not retried','passed':True,'exit_code':proc.returncode})
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True,
                        help="Checkout or retained source root containing projects/razr60")
    parser.add_argument("--out", type=Path, required=True,
                        help="New result JSON file; existing evidence is never overwritten")
    args = parser.parse_args(argv)
    if sys.flags.optimize:
        raise RuntimeError("control_assertions_require_unoptimized_python")
    repo_root = args.repo_root.resolve(strict=True)
    if args.out.exists():
        raise RuntimeError("output_already_exists; choose a new evidence path")
    modules, pins = load_verified_modules(repo_root)
    results = run_controls(modules["phone_task_guards"], modules["provider_openai_compatible"].ProviderError)
    report = {
        "schema": "hepta.navigation-readonly-source-review.v2",
        "source_reference_commit": REFERENCE_COMMIT,
        "source_files_verified_before_import": True,
        "executed_module_source": "compiled from the same verified in-memory bytes",
        "checkout_head_asserted": False,
        "repo_root": str(repo_root),
        "source_files": pins,
        "source_modules_executed": ["provider_openai_compatible.py", "phone_task_guards.py"],
        "phone_calls": 0, "native_dispatches": 0, "sender_actor_constructions": 0,
        "production_source_changes": 0, "physical_qualification": False,
        "fixed19_credit": 0, "passed": len(results), "total": len(results),
        "controls": results,
    }
    data = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("xb") as stream:
        stream.write(data)
    print(json.dumps({key: report[key] for key in (
        "passed", "total", "source_files_verified_before_import", "phone_calls", "fixed19_credit")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"error_type": type(error).__name__, "error": str(error),
                          "physical_qualification": False, "fixed19_credit": 0}), file=sys.stderr)
        raise SystemExit(2)
