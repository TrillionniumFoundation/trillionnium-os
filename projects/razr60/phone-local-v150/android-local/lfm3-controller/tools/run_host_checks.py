#!/usr/bin/env python3
"""Compile and exercise the controller's real host-testable code; no phone/network.

All outputs go to a new directory. Host passes establish neither Android
compilation nor model inference, acceleration, phone effects, or release status.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
PURE_CLASSES=['LastModelDecisionProjection', 'BackgroundPermissionPreparation', 'TaskAuthorization', 'QualificationScope', 'ActionDecision', 'ActionPolicy', 'ObservedTargetLabels', 'ObservedAppLabels', 'ObservedScrollActions', 'ObservedImeEnter', 'SubmitAttemptGuard', 'ObservationStabilityGate', 'RecentActionProjection', 'PersistentActionPolicy', 'ImeVisibility', 'ObservationState', 'ObservedWindowMetadata', 'ObservedChildText', 'RepeatActionGuard', 'SameStateNoEffectGuard', 'DecisionGrammar', 'ModelProfile', 'NativeBudgetVerifier', 'LocalRuntimeConfig', 'ModelFileVerifier', 'ConservativeTokenBudget', 'MemoryAvailability', 'AppCatalogueRanker', 'SessionRecovery', 'MobiMindPins', 'MobiMindContract', 'MobiMindSessionContract', 'UiVenusPins', 'UiVenusInputContract', 'UiVenusRequestContract', 'UiVenusContract', 'UiVenusProcessContract', 'UiVenusSessionContract', 'DiagnosticStartupGate', 'ObservedTextProjection', 'ObservedTransitionProjection', 'CompactTaskHistory', 'PromptActionDomain', 'RecoveryQuiescence', 'RecoveryDispatch', 'RecoveryJournalTransaction', 'RecoverySlotHandoff', 'WarmProcessSession']


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",required=True,type=Path)
    args=parser.parse_args()
    out=args.out.expanduser().resolve()
    out.mkdir(parents=True,exist_ok=False)
    java=shutil.which("java"); cc=shutil.which("cc")
    if not java or not cc: raise RuntimeError("Existing JDK and C compiler required; no installation attempted")
    compiler=[shutil.which("javac")] if shutil.which("javac") else [java,"-m","jdk.compiler/com.sun.tools.javac.Main"]
    report={"schema":"hepta.host-checks.v3","scope":"host_only","all_pass":False,
            "android_compiled":False,"phone_tested":False,"native_grammar_model_tested":False,
            "external_model_used":False,"started_host_wall_ms":int(time.time()*1000),"checks":[]}
    source_dir=ROOT/"src/org/trillionnium/hepta/local"
    sources=[source_dir/(name+".java") for name in PURE_CLASSES]
    tests=sorted((ROOT/"tests").glob("*HostTest.java"))+[
        ROOT/"tests/action-parser/ActionDecisionHostTest.java",
        ROOT/"tests/action-grammar/DecisionGrammarHostTest.java"]
    def all_inputs():
        paths=set(ROOT.glob("*.py"))
        for directory, extensions in (("src",("*.java",)),("tests",("*.java","*.py")),
                                      ("native",("*.c","*.h","*.inc","*.py")),("tools",("*.py",))):
            for extension in extensions: paths.update((ROOT/directory).rglob(extension))
        if any(p.is_symlink() for p in paths): raise RuntimeError("Host inputs must not be symbolic links")
        return [{"path":str(p.relative_to(ROOT)),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
                for p in sorted(paths)]
    report["source_inputs"]=all_inputs()

    def run(name,command,timeout=180):
        started=time.monotonic()
        result=subprocess.run([str(x) for x in command],cwd=ROOT,capture_output=True,timeout=timeout,check=False)
        (out/(name+".stdout")).write_bytes(result.stdout)
        (out/(name+".stderr")).write_bytes(result.stderr)
        row={"name":name,"exit_code":result.returncode,"elapsed_s":time.monotonic()-started,
             "stdout_sha256":hashlib.sha256(result.stdout).hexdigest(),"stderr_sha256":hashlib.sha256(result.stderr).hexdigest()}
        report["checks"].append(row)
        if result.returncode:
            raise RuntimeError(name+" failed: "+result.stderr.decode("utf-8","replace")[-4000:])
        return result

    try:
        classes=out/"classes"; classes.mkdir()
        fixtures=out/"grammar"; fixtures.mkdir()
        run("java-compile",compiler+["--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-d",classes,*sources,*tests])
        for test in tests:
            name=test.stem
            command=[java,"-cp",classes,name]
            if name in ("DecisionGrammarHostTest","AppCatalogueHostTest","RepeatActionGuardHostTest","ScrollGrammarHostTest","SameStateNoEffectGuardHostTest","ObservedAppLabelsHostTest"):command.append(fixtures)
            if name=="LastModelDecisionProjectionHostTest":command.append(ROOT/"tests/last-model-decision")
            run(name,command)
        run("grammar-recognition",[sys.executable,ROOT/"tests/action-grammar/test_decision_grammar.py",fixtures])
        run("app-label-grammar-recognition",[sys.executable,ROOT/"tests/action-grammar/test_app_label_grammar.py",fixtures])
        run("scroll-grammar-recognition",[sys.executable,ROOT/"tests/action-grammar/test_scroll_grammar.py",fixtures])
        run("completion-protocol",[sys.executable,ROOT/"tests/action-grammar/test_completion_protocol.py",fixtures])
        run("same-state-no-effect-grammar",[sys.executable,ROOT/"tests/action-grammar/test_same_state_no_effect_grammar.py",fixtures])
        run("background-client",[sys.executable,"-B",ROOT/"tests/background-session/run_host_tests.py",
            "--source",ROOT,"--output",out/"background-client","--release8"])
        run("qualification-scope",[sys.executable,ROOT/"tests/qualification-scope/run_host_tests.py",
            "--source",ROOT,"--output",out/"qualification-scope","--release8"])
        run("owner-authorization",[sys.executable,"-B",ROOT/"tests/owner-authorization/run_host_tests.py",
            "--source",ROOT,"--output",out/"owner-authorization","--release8"])
        run("owner-grammar",[sys.executable,"-B",ROOT/"tests/owner-grammar/run_host_tests.py",
            "--source",ROOT,"--output",out/"owner-grammar","--release8"])
        run("ime-submit",[sys.executable,"-B",ROOT/"tests/ime-submit/run_host_tests.py",
            "--source",ROOT,"--output",out/"ime-submit","--release8"])
        run("background-permission",[sys.executable,"-B",ROOT/"tests/background-permission/run_host_tests.py",
            "--source",ROOT,"--output",out/"background-permission","--release8"])
        run("background-permission-session",[sys.executable,"-B",ROOT/"tests/background-permission/run_session_tests.py",
            "--source",ROOT,"--output",out/"background-permission-session","--release8"])
        run("background-broker",[sys.executable,"-B",ROOT/"tests/background-broker/run_host_checks.py",
            "--java",java,"--javac",shutil.which("javac"),"--out",out/"background-broker"])
        run("python-tools",[sys.executable,"-m","unittest","discover","-s","tools","-p","test_*.py","-v"])
        run("mobimind-private-staging",[sys.executable,"-m","unittest","discover","-s",
            ROOT/"provenance/mobimind-app-only-r1/tests","-p","test_*.py","-v"])
        run("ui-venus-q4_0-provenance",[sys.executable,ROOT/"tests/test_ui_venus_q4_0_runtime.py"])
        for source in sorted((ROOT/"native/tests").glob("*.c")):
            binary=out/source.stem
            run(source.stem+"-compile",[cc,"-std=c11","-Wall","-Wextra","-Werror","-O2","-I"+str(ROOT/"native"),source,"-o",binary])
            arguments=["--self-test"] if source.stem=="sha256_probe" else []
            run(source.stem,[binary,*arguments],timeout=30)
            if source.stem=="sha256_probe":
                run("sha256-hashlib-differential",[sys.executable,ROOT/"native/tests/test_sha256.py","--probe",binary])
        sys.path.insert(0,str(ROOT/"native"))
        from generate_adapter import generate
        generated=out/"native-generated"; generated.mkdir()
        report["native_adapter"]=generate(ROOT,generated)
        run("native-adapter-syntax",[cc,"-std=c11","-Wall","-Wextra","-Werror","-fsyntax-only",
            "-I"+str(ROOT/"native/vendor"),"-I"+str(ROOT/"native"),"-I"+str(generated),ROOT/"native/probe-worker.c"])
        run("private-prompt-evidence",[sys.executable,ROOT/"native/tests/test_prompt_evidence.py"])
        run("task-worker-native-lifecycle",[sys.executable,ROOT/"native/tests/test_warm_runtime.py"])
        run("profile-sampler",[sys.executable,"-B",ROOT/"native/tests/test_profile_sampler.py",
            "--source",ROOT,"--output",out/"profile-sampler"])
        if all_inputs()!=report["source_inputs"]: raise RuntimeError("Source changed during host checks")
        report["all_pass"]=True
    except Exception as error:
        report["error"]=str(error)
    finally:
        report["finished_host_wall_ms"]=int(time.time()*1000)
        (out/"HOST-CHECKS.json").write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps({k:report.get(k) for k in ("scope","all_pass","android_compiled","phone_tested","error")},ensure_ascii=False))
    return 0 if report["all_pass"] else 1


if __name__=="__main__":sys.exit(main())
