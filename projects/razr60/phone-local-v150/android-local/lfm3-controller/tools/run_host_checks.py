#!/usr/bin/env python3
"""Compile and exercise the controller's real host-testable code; no phone/network.

All outputs go to a new directory. Host passes establish neither Android
compilation nor model inference, acceleration, phone effects, or release status.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
PURE_CLASSES=['NativeCtripFormObservation', 'NativeSearchDecision', 'ObservationCaptureEvidence', 'NativeXiaomiSearchInputObservation', 'NativeActionSnapshotCheck', 'NativeAppEvidence', 'NativeAppDomain', 'NativeCtripFlightPage', 'NativeXiaomiProductPage', 'BackgroundTaskTarget', 'NativeAppGoal', 'NotesCreateWorkflow', 'NotesOwnerIntent', 'CalculatorTaskInputGuard', 'CalculatorGoalContract', 'CalculatorCompletionEvidence', 'NotesTaskPhaseGuard', 'TaskCompletionGate', 'NotesCompletionEvidence', 'FixedIntentAttemptGuard', 'LastModelDecisionProjection', 'BackgroundPermissionPreparation', 'TaskAuthorization', 'QualificationScope', 'ActionDecision', 'ActionPolicy', 'ObservedTargetLabels', 'ObservedAppLabels', 'ObservedScrollActions', 'ObservedImeEnter', 'SubmitAttemptGuard', 'ObservationStabilityGate', 'RecentActionProjection', 'PersistentActionPolicy', 'ImeVisibility', 'ObservationState', 'ObservedWindowMetadata', 'ObservedChildText', 'RepeatActionGuard', 'SameStateNoEffectGuard', 'DecisionGrammar', 'ModelProfile', 'NativeBudgetVerifier', 'LocalRuntimeConfig', 'ModelFileVerifier', 'ConservativeTokenBudget', 'MemoryAvailability', 'AppCatalogueRanker', 'SessionRecovery', 'MobiMindPins', 'MobiMindContract', 'MobiMindSessionContract', 'UiVenusPins', 'UiVenusInputContract', 'UiVenusRequestContract', 'UiVenusContract', 'UiVenusProcessContract', 'UiVenusSessionContract', 'DiagnosticStartupGate', 'ObservedTextProjection', 'ObservedTransitionProjection', 'CompactTaskHistory', 'PromptActionDomain', 'RecoveryQuiescence', 'RecoveryDispatch', 'RecoveryJournalTransaction', 'RecoverySlotHandoff', 'WarmProcessSession', 'OwnedWorkerCancellation']


def legacy_session_parent_proof(raw):
    """Proof copy only; actual compilation retains the current refusing type port."""
    parent_sha="3fff6e7e892adca8a9e895a852447f55237124e6545c1fb3aa2c9b047a0e3ddd"
    current_sha="8ee6f4d05dc3f71ed646215947e10c9d34b12b4354ed6920ca49b06112dd5203"
    digest=hashlib.sha256(raw).hexdigest()
    if digest==parent_sha:return raw
    if digest!=current_sha:raise RuntimeError("unknown legacy Session type-port source")
    added=(b"        // Type-only final-use projection; this guard still cannot be constructed.\n"
           b"        final NativeAppEvidence.Frame frame=null;\n")
    if raw.count(added)!=1:raise RuntimeError("unique exact Frame type-port addition required")
    proof=raw.replace(added,b"",1)
    if hashlib.sha256(proof).hexdigest()!=parent_sha:
        raise RuntimeError("complete original refusing Session proof differs")
    return proof


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",required=True,type=Path)
    parser.add_argument("--json-jar",required=True,type=Path,
                        help="Existing fixed org.json 20240303 JAR; this runner never downloads dependencies")
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
    sources += [source_dir/"web/WebFlightGoal.java",source_dir/"web/WebShoppingGoal.java",
                ROOT/"tests/web-flight/legacy-boundary/WebFlightDomain.java",
                ROOT/"tests/web-flight/legacy-boundary/WebShoppingQuote.java",
                ROOT/"tests/native-app/legacy-boundary/NativeAppSession.java",
                ROOT/"tests/native-app/legacy-boundary/NativeSearchPlanning.java",
                ROOT/"tests/native-app/legacy-boundary/NativeSearchSession.java"]
    report["web_fixture_boundary"]="Legacy non-Web tests use a type-only WebTaskDomain whose methods throw; actual Web classes have an independent gate"
    report["native_fixture_boundary"]="Legacy non-native tests compile the real pure NativeAppEvidence/Domain and an unconstructible all-throw NativeAppSession; native session execution has an independent mandatory gate"
    sources += [ROOT/"src/org/trillionnium/hepta/background"/(name+".java") for name in ("FixedIntentTools","FixedIntentTarget","BrokerProtocol","PublicPermissionControllerUi","PublicOwnGroupPolicy","BackgroundOwnedTaskPolicy","ProfileIdentity","ProfileTarget","WindowOwnership")]
    automatic_helper=ROOT/"tests/native-app/legacy-boundary/prepare_search_pure.py"
    automatic_spec=importlib.util.spec_from_file_location("old_pure_automatic_boundary",automatic_helper)
    automatic_boundary=importlib.util.module_from_spec(automatic_spec);automatic_spec.loader.exec_module(automatic_boundary)
    sources=automatic_boundary.add_auto_boundary(ROOT,sources)
    report["automatic_fixture_boundary"]={
        "helper_path":str(automatic_helper),
        "compiler_path":str(ROOT/"tests/native-app/legacy-boundary/BackgroundAutoTargetResolver.java"),
        "constructors_private_and_throwing":True,"authority_endpoints_always_refuse":True,
        "automatic_selection_executed":False,"actual_target_compiled":True}
    tests=sorted((ROOT/"tests").glob("*HostTest.java"))+[
        ROOT/"tests/action-parser/ActionDecisionHostTest.java",
        ROOT/"tests/action-grammar/DecisionGrammarHostTest.java"]
    def all_inputs():
        paths=set(ROOT.glob("*.py"))
        paths.add(ROOT/"tests/vlm-contract/requirements.txt")
        paths.update(ROOT/"tests/local-model-settings"/name for name in ("CASE-CONTRACT.json","PRODUCTION-SOURCES.json","README.md"))
        paths.update(ROOT/"tests/local-model-settings-visual"/name for name in ("CASE-CONTRACT.json","OBSERVE-CASE-CONTRACT.json","README.md"))
        paths.add(ROOT/"tests/notes-task-info-reader/synthetic-notes-census.json")
        paths.add(ROOT/"tests/profile-cleanup-sampling/fixtures-synthetic/before-recents.txt")
        paths.add(ROOT/"tests/background-broker/535-close-reply.json")
        for directory, extensions in (("src",("*.java",)),("tests",("*.java","*.py","*.template","*.inc")),
                                      ("native",("*.c","*.cpp","*.h","*.inc","*.py")),("tools",("*.py",))):
            for extension in extensions: paths.update((ROOT/directory).rglob(extension))
        paths.update(p for p in (ROOT/"tests/completion/fixtures").rglob("*") if p.is_file())
        paths.update(p for p in (ROOT/"tests/text-only-click/fixtures").rglob("*") if p.is_file())
        paths.update(p for p in (ROOT/"tests/notes-task-phase/fixtures").rglob("*") if p.is_file())
        paths.update(p for p in (ROOT/"tests/calculator-completion/fixtures").rglob("*") if p.is_file())
        paths.update(p for p in (ROOT/"tests/calculator-input/fixtures").rglob("*") if p.is_file())
        paths.update(p for p in (ROOT/"tests/notes-editor-phase/fixtures").rglob("*") if p.is_file())
        paths.update(p for p in (ROOT/"tests/completion-status/fixtures").rglob("*") if p.is_file())
        paths.update(p for p in (ROOT/"tests/observation-collection/fixtures").rglob("*") if p.is_file())
        paths.update(p for p in (ROOT/"tests/notes-create-workflow/fixtures").rglob("*") if p.is_file())
        paths.update(p for p in (ROOT/"tests/profile-permission-transient/fixtures").rglob("*") if p.is_file())
        paths.add(ROOT/"tests/profile-permission-transient/README.md")
        paths.add(ROOT/"tests/native-app-provider/fixtures/ctrip-startup-promotion-native-ax.json")
        paths.add(ROOT/"tests/native-search-producer/2a5063-navigation-censuses.json")
        paths.add(ROOT/"tests/native-search-producer/1d0e0e-navigation-censuses.json")
        paths.add(ROOT/"tests/native-search-producer/0b742-execution-censuses.json")
        paths.add(ROOT/"tests/native-search-producer/dcc738-progress-censuses.json")
        paths.add(ROOT/"tests/native-search-producer/r38-planning-captures.json")
        paths.add(ROOT/"tests/native-form-history-actions/d1e685-query-refusals.json")
        paths.add(ROOT/"tests/native-form-history-actions/86b343-departure-year-refusals.json")
        paths.add(ROOT/"tests/native-search-producer/99c24-retired-search.json")
        paths.add(ROOT/"tests/native-search-producer/6bea-search-icon-censuses.json")
        paths.add(ROOT/"tests/native-search-session/8436-retained-login.json")
        paths.add(ROOT/"tests/native-search-producer/SearchIconCases.fragment")
        paths.update((ROOT/"tests/native-search-producer").glob("*.fragment"))
        paths.add(ROOT/"tests/native-ctrip-login-form-terminal/40c65-calendar-fare.json")
        paths.add(ROOT/"tests/native-auto-target/fixtures/legacy-ctrip-gui.json")
        for fixture_root in ("tests/sdk-exception-failure-audit/fixtures",
                             "tests/owned-generation-cleanup/fixtures",
                             "tests/vlm-contract/fixtures"):
            paths.update(p for p in (ROOT/fixture_root).rglob("*") if p.is_file())
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
        json_jar=args.json_jar.expanduser().absolute()
        if json_jar.is_symlink() or not json_jar.is_file():
            raise RuntimeError("Existing regular pinned host JSON JAR required")
        json_bytes=json_jar.read_bytes()
        json_digest=hashlib.sha256(json_bytes).hexdigest()
        if len(json_bytes)!=78332 or json_digest!="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed":
            raise RuntimeError("Pinned org.json 20240303 host dependency differs")
        java_home=Path(java).resolve().parent.parent
        run("profile-cleanup-sampling",[sys.executable,"-B",ROOT/"tests/profile-cleanup-sampling/run_candidate.py",
            "--source",ROOT,"--output",out/"profile-cleanup-sampling","--java-home",java_home,"--json-jar",json_jar])
        cleanup_sampling_raw=(out/"profile-cleanup-sampling/RESULT.json").read_bytes()
        cleanup_sampling=json.loads(cleanup_sampling_raw)
        if (cleanup_sampling.get("all_pass") is not True or cleanup_sampling.get("source_inputs_unchanged") is not True
                or cleanup_sampling.get("fixture_kind")!="synthetic_complete_public_recents"
                or cleanup_sampling.get("original_task_fixture_used") is not False
                or cleanup_sampling.get("phone_operations")!=0
                or cleanup_sampling.get("sampling",{}).get("assertions")!=55
                or cleanup_sampling.get("diagnostics",{}).get("assertions")!=14):
            raise RuntimeError("profile cleanup candidate regression contract differs")
        report["profile_cleanup_sampling_gate"]={"bytes":len(cleanup_sampling_raw),
            "sha256":hashlib.sha256(cleanup_sampling_raw).hexdigest(),
            "sampling":cleanup_sampling["sampling"],"diagnostics":cleanup_sampling["diagnostics"]}
        if not (java_home/"bin/javac").is_file():
            raise RuntimeError("The selected Java runtime must have its full JDK javac for the mandatory audit gates")
        report["host_json_dependency"]={"path":str(json_jar),"bytes":len(json_bytes),"sha256":json_digest,
                                       "downloaded_by_canonical_runner":False}
        report["additional_gate_java_home"]=str(java_home)
        classes=out/"classes"; classes.mkdir()
        fixtures=out/"grammar"; fixtures.mkdir()
        web_fixture_source=ROOT/"tests/web-flight/legacy-boundary/WebFlightDomain.java"
        web_fixture_raw=web_fixture_source.read_bytes()
        web_fixture_compile=out/"WebTaskDomain.java"
        if sources.count(web_fixture_source)!=1 or hashlib.sha256(web_fixture_raw).hexdigest()!=next(
                r["sha256"] for r in report["source_inputs"] if r["path"]==str(web_fixture_source.relative_to(ROOT))):
            raise RuntimeError("Exact original Web type-boundary source required")
        web_fixture_compile.write_bytes(web_fixture_raw)
        if web_fixture_compile.read_bytes()!=web_fixture_raw:
            raise RuntimeError("Web type-boundary compiler copy changed")
        compile_sources=[web_fixture_compile if p==web_fixture_source else p for p in sources]
        report["web_fixture_compiler_copy"]={"source_path":str(web_fixture_source.relative_to(ROOT)),
            "compiler_path":str(web_fixture_compile),"bytes":len(web_fixture_raw),
            "sha256":hashlib.sha256(web_fixture_raw).hexdigest(),"byte_identical":True}
        # Local type-only compiler copies for this legacy pure gate. Actual
        # calendar producers and capabilities are exercised by separate gates.
        native_fixture_source=ROOT/"tests/native-app/legacy-boundary/NativeAppSession.java"
        native_fixture_raw=native_fixture_source.read_bytes()
        if (compile_sources.count(native_fixture_source)!=1
                or hashlib.sha256(legacy_session_parent_proof(native_fixture_raw)).hexdigest()!="3fff6e7e892adca8a9e895a852447f55237124e6545c1fb3aa2c9b047a0e3ddd"
                or b"class CalendarOffer" in native_fixture_raw):
            raise RuntimeError("Exact original refusing NativeAppSession boundary required")
        calendar_offer_port=b"""
    /** Type-only calendar grammar shape; no Offer or grammar can be created. */
    static final class CalendarOffer {
        final NativeCalendarDateEnvelope source=null;
        final CalendarGrammar protocol=null;
        private CalendarOffer(){throw unavailable();}
        void claimGrammar(TaskAuthorization.Frame owner)throws Exception{throw unavailable();}
        void close(){throw unavailable();}
    }
    static final class CalendarGrammar {
        final String grammar=null,grammarSha256=null;
        private CalendarGrammar(){throw unavailable();}
    }
"""
        final_class_end=native_fixture_raw.rfind(b"\n}")
        if final_class_end<0 or native_fixture_raw[final_class_end:].strip()!=b"}":
            raise RuntimeError("Exact final NativeAppSession class boundary required")
        native_fixture_compile_raw=(native_fixture_raw[:final_class_end]
            +calendar_offer_port+native_fixture_raw[final_class_end:])
        if native_fixture_compile_raw.replace(calendar_offer_port,b"",1)!=native_fixture_raw:
            raise RuntimeError("Calendar shape must preserve the original session byte-for-byte")
        intent_source=source_dir/"NativeCalendarDateIntent.java"
        intent_original=intent_source.read_bytes()
        intent_constants=b'    static final String SCHEMA="hepta.native-calendar-select-date.v1",ACTION="calendar.select_date";'
        if intent_original.splitlines().count(intent_constants)!=1:
            raise RuntimeError("Actual calendar schema/action constants differ")
        calendar_ports=out/"calendar-legacy-types";calendar_ports.mkdir()
        generated_calendar=[
            (calendar_ports/"NativeAppSession.java",native_fixture_compile_raw),
            (calendar_ports/"NativeCalendarDateEnvelope.java",b"""package org.trillionnium.hepta.local;
final class NativeCalendarDateEnvelope {
    final NativeAppEvidence.Frame facts=null;
    private NativeCalendarDateEnvelope(){throw new UnsupportedOperationException("No calendar envelope in legacy pure gate");}
}
"""),
            (calendar_ports/"NativeCalendarDateIntent.java",b"""package org.trillionnium.hepta.local;
final class NativeCalendarDateIntent {
"""+intent_constants+b"""
    private NativeCalendarDateIntent(){throw new UnsupportedOperationException("No calendar intent in legacy pure gate");}
}
""")]
        for generated_path,generated_raw in generated_calendar:
            with generated_path.open("xb") as stream:stream.write(generated_raw)
        if any(source_dir/name in compile_sources for name in
                ("NativeCalendarDateIntent.java","NativeCalendarDateEnvelope.java")):
            raise RuntimeError("Actual and type-only calendar sources cannot coexist in this gate")
        compile_sources=[generated_calendar[0][0] if p==native_fixture_source else p for p in compile_sources]
        compile_sources += [p for p,_ in generated_calendar[1:]]
        def calendar_ref(path,raw):
            return {"path":str(path),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
        report["calendar_fixture_compiler_copy"]={
            "original_session":calendar_ref(native_fixture_source,native_fixture_raw),
            "constant_source":calendar_ref(intent_source,intent_original),
            "constant_declaration_sha256":hashlib.sha256(intent_constants).hexdigest(),
            "inserted_session_shape_sha256":hashlib.sha256(calendar_offer_port).hexdigest(),
            "original_session_bytes_reversible":True,
            "generated":[calendar_ref(p,raw) for p,raw in generated_calendar],
            "constructors_private_and_throwing":True,"calendar_methods_always_throw":True,
            "model_request_created":False,"calendar_offer_created":False,
            "calendar_permit_created":False,"calendar_behavior_executed":False}
        run("java-compile",compiler+["--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-d",classes,*compile_sources,*tests])
        if web_fixture_compile.read_bytes()!=web_fixture_raw:
            raise RuntimeError("Web type-boundary compiler copy changed during javac")
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
        run("background-launch-isolation",[sys.executable,"-B",ROOT/"tests/background-launch-isolation/run_host_tests.py",
            "--source",ROOT,"--output",out/"background-launch-isolation","--release8"])
        run("qualification-scope",[sys.executable,ROOT/"tests/qualification-scope/run_host_tests.py",
            "--source",ROOT,"--output",out/"qualification-scope","--release8"])
        run("observation-pipeline",[sys.executable,"-B",ROOT/"tests/observation-pipeline/run_host_tests.py",
            "--source",ROOT,"--output",out/"observation-pipeline","--release8"])
        run("owner-authorization",[sys.executable,"-B",ROOT/"tests/owner-authorization/run_host_tests.py",
            "--source",ROOT,"--output",out/"owner-authorization","--release8"])
        run("owner-grammar",[sys.executable,"-B",ROOT/"tests/owner-grammar/run_host_tests.py",
            "--source",ROOT,"--output",out/"owner-grammar","--release8"])
        run("ime-submit",[sys.executable,"-B",ROOT/"tests/ime-submit/run_host_tests.py",
            "--source",ROOT,"--output",out/"ime-submit","--release8"])
        run("fixed-intent-tools",[sys.executable,"-B",ROOT/"tests/fixed-intent-tools/run_host_tests.py",
            "--source",ROOT/"src/org/trillionnium/hepta/background/FixedIntentTools.java","--out",out/"fixed-intent-tools","--release8"])
        run("fixed-intent-integration",[sys.executable,"-B",ROOT/"tests/fixed-intent-tools/run_integration_tests.py",
            "--source",ROOT,"--output",out/"fixed-intent-integration","--release8"])
        run("background-permission",[sys.executable,"-B",ROOT/"tests/background-permission/run_host_tests.py",
            "--source",ROOT,"--output",out/"background-permission","--release8"])
        run("background-permission-session",[sys.executable,"-B",ROOT/"tests/background-permission/run_session_tests.py",
            "--source",ROOT,"--output",out/"background-permission-session","--release8"])
        run("runtime-config-ui",[sys.executable,"-B",ROOT/"tests/runtime-config-ui/run_host_tests.py",
            "--source",ROOT,"--output",out/"runtime-config-ui","--release8"])
        run("local-model-settings",[sys.executable,"-B",ROOT/"tests/local-model-settings/run_host.py",
            "--source",ROOT,"--output",out/"local-model-settings","--java-home",java_home,"--json-jar",json_jar])
        settings_raw=(out/"local-model-settings/RESULT.json").read_bytes()
        settings_gate=json.loads(settings_raw)
        if (settings_gate.get("schema")!="hepta.local-model-settings-host-gate.v1"
                or settings_gate.get("all_pass") is not True or settings_gate.get("inputs_unchanged") is not True
                or settings_gate.get("java_release_api_check") is not True
                or settings_gate.get("full_production_engine_and_transaction") is not True
                or settings_gate.get("phone_operations")!=0 or settings_gate.get("native_model_executed") is not False):
            raise RuntimeError("Local model settings host gate receipt differs")
        if set(settings_gate.get("cases",{}))!={"transaction","generation","context_files"}:
            raise RuntimeError("Local model settings case groups differ")
        for name,count,assertions in (("transaction",43,196),("generation",15,100),("context_files",8,36)):
            actual=settings_gate.get("cases",{}).get(name,{})
            original=json.loads((out/"local-model-settings"/(name+"-cases")/"RESULT.json").read_bytes())
            if (actual!=original or actual.get("passed") is not True
                    or type(actual.get("cases")) is not int or actual["cases"]!=count
                    or type(actual.get("assertions")) is not int or actual["assertions"]!=assertions):
                raise RuntimeError("Local model settings original cases differ: "+name)
        report["local_model_settings_gate"]={"bytes":len(settings_raw),"sha256":hashlib.sha256(settings_raw).hexdigest(),
            "cases":settings_gate["cases"]}
        run("local-model-settings-visual",[sys.executable,"-B",ROOT/"tests/local-model-settings-visual/run_host.py",
            "--source",ROOT,"--output",out/"local-model-settings-visual","--java-home",java_home,"--json-jar",json_jar],timeout=360)
        visual_raw=(out/"local-model-settings-visual/RESULT.json").read_bytes()
        visual_gate=json.loads(visual_raw)
        if (visual_gate.get("schema")!="hepta.local-model-settings-visual-host-gate.v1"
                or visual_gate.get("all_pass") is not True or visual_gate.get("inputs_unchanged") is not True
                or visual_gate.get("original_settings_cases_retained") is not True
                or visual_gate.get("actual_settings_and_runtime_router") is not True
                or visual_gate.get("view_inventory_and_positive_model_loading_are_host_ports") is not True
                or type(visual_gate.get("phone_operations")) is not int or visual_gate["phone_operations"]!=0
                or visual_gate.get("native_model_executed") is not False
                or visual_gate.get("positive_backend_qualified") is not False):
            raise RuntimeError("Visual settings and runtime routing host scope or receipt differs")
        if ([row.get("name") for row in visual_gate.get("stages",[])]!=["javac-version","original-settings","compile","visual-settings"]
                or any(type(row.get("exit_code")) is not int or row["exit_code"]!=0 for row in visual_gate["stages"])):
            raise RuntimeError("Visual settings mandatory compile/run stages differ")
        visual_cases=visual_gate.get("cases",{})
        visual_rows=visual_cases.get("case_results")
        if (visual_cases.get("schema")!="hepta.local-model-settings-visual-cases.v1"
                or visual_cases.get("passed") is not True
                or type(visual_cases.get("cases")) is not int or visual_cases["cases"]!=30
                or type(visual_cases.get("assertions")) is not int or visual_cases["assertions"]!=243
                or type(visual_rows) is not list or len(visual_rows)!=30
                or any(type(row) is not dict or row.get("passed") is not True
                    or type(row.get("name")) is not str or type(row.get("assertions")) is not int
                    or row["assertions"]<1 for row in visual_rows)
                or sum(row["assertions"] for row in visual_rows)!=243):
            raise RuntimeError("Visual settings exact original/new case assertions differ")
        visual_names=[row["name"] for row in visual_rows]
        visual_names_sha=hashlib.sha256(json.dumps(visual_names,ensure_ascii=False,separators=(",",":")).encode()).hexdigest()
        visual_contract=json.loads((ROOT/"tests/local-model-settings-visual/CASE-CONTRACT.json").read_bytes())
        if (len(set(visual_names))!=30 or visual_names_sha!="e5d32582f6bfa5797dedb933949b69f87d37719e03c49d088588bffde850362a"
                or visual_gate.get("case_names_sha256")!=visual_names_sha
                or visual_contract.get("schema")!="hepta.local-model-settings-visual-case-contract.v1"
                or visual_contract.get("case_schema")!=visual_cases["schema"]
                or visual_contract.get("cases")!=22 or visual_contract.get("assertions")!=169
                or visual_contract.get("names")!=visual_names[:22]
                or json.loads((out/"local-model-settings-visual/cases/RESULT.json").read_bytes())!=visual_cases
                or json.loads((out/"local-model-settings-visual/visual-settings.stdout").read_bytes())!=visual_cases):
            raise RuntimeError("Visual settings case identity or actual Java output differs")
        visual_extension=json.loads((ROOT/"tests/local-model-settings-visual/OBSERVE-CASE-CONTRACT.json").read_bytes())
        if (sum(row["assertions"] for row in visual_rows[:22])!=169
                or hashlib.sha256(json.dumps(visual_names[:22],ensure_ascii=False,separators=(",",":")).encode()).hexdigest()!=
                    "7afd16285a00eb25340ef178f2b9c11b2e036e8bde8bd810e5c3d1ddc31adf73"
                or visual_extension.get("schema")!="hepta.local-model-settings-lfm3-observe-case-contract.v1"
                or visual_extension.get("cases")!=8 or visual_extension.get("assertions")!=74
                or visual_extension.get("names")!=visual_names[22:]
                or sum(row["assertions"] for row in visual_rows[22:])!=74
                or visual_gate.get("original_visual_cases_retained")!={"cases":22,"assertions":169}
                or visual_gate.get("lfm3_observation_extension")!={"cases":8,"assertions":74}):
            raise RuntimeError("Original GUI or LFM3 observation case/assertion boundaries differ")
        if (type(visual_cases.get("phone_operations")) is not int or visual_cases["phone_operations"]!=0
                or visual_cases.get("native_model_executed") is not False or visual_cases.get("positive_backend_qualified") is not False
                or any(visual_cases.get(key) is not True for key in ("actual_owner_button_methods",
                    "actual_application_idle_methods","actual_service_controller_factory","actual_settings_transaction_and_engine",
                    "actual_runtime_generation_binding","same_service_and_controller_roundtrip",
                    "positive_weight_verification_is_host_boundary","vlm_model_loading_is_host_boundary",
                    "actual_negative_asset_and_hash_checks","android_view_and_inventory_are_host_boundaries"))):
            raise RuntimeError("Visual settings actual methods or explicit host boundary differs")
        engine_boundary=visual_gate.get("engine_host_type_boundary",{})
        if (any(engine_boundary.get(key) is not True for key in ("only_class_final_removed",
                "all_fields_and_method_bodies_unchanged","unmodified_final_engine_executed_in_original_gate"))
                or engine_boundary.get("original_sha256")!=hashlib.sha256((ROOT/"src/org/trillionnium/hepta/local/LocalModelEngine.java").read_bytes()).hexdigest()):
            raise RuntimeError("Visual settings unmodified production Engine identity differs")
        original_visual_settings=json.loads((out/"local-model-settings-visual/original-settings/RESULT.json").read_bytes())
        if (original_visual_settings.get("all_pass") is not True or original_visual_settings.get("inputs_unchanged") is not True
                or set(original_visual_settings.get("cases",{}))!={"transaction","generation","context_files"}):
            raise RuntimeError("Visual routing gate did not retain the complete original settings gate")
        for name,count,assertions in (("transaction",43,196),("generation",15,100),("context_files",8,36)):
            original_case=original_visual_settings["cases"][name]
            if (original_case.get("passed") is not True or type(original_case.get("cases")) is not int
                    or original_case["cases"]!=count or type(original_case.get("assertions")) is not int
                    or original_case["assertions"]!=assertions):
                raise RuntimeError("Visual routing gate original settings case contract differs: "+name)
        visual_inputs=visual_gate.get("source_inputs")
        if type(visual_inputs) is not list or not visual_inputs:
            raise RuntimeError("Visual settings actual source and tool pins missing")
        visual_input_paths=set()
        for item in visual_inputs:
            path=Path(item["path"])
            if not path.is_absolute() or path.is_symlink() or str(path) in visual_input_paths:
                raise RuntimeError("Visual settings duplicate or aliased input")
            visual_input_paths.add(str(path));data=path.read_bytes()
            if len(data)!=item["bytes"] or hashlib.sha256(data).hexdigest()!=item["sha256"]:
                raise RuntimeError("Visual settings source or tool changed after its gate")
        report["local_model_settings_visual_gate"]={"bytes":len(visual_raw),
            "sha256":hashlib.sha256(visual_raw).hexdigest(),"cases":visual_cases,
            "case_names_sha256":visual_names_sha,"original_settings_cases_retained":True}
        run("background-broker",[sys.executable,"-B",ROOT/"tests/background-broker/run_host_checks.py",
            "--java",java,"--javac",shutil.which("javac"),"--out",out/"background-broker"])
        run("public-screen-lease",[sys.executable,"-B",ROOT/"tests/public-screen-lease/run_host.py",
            "--source",ROOT,"--output",out/"public-screen-lease","--java-home",java_home])
        screen_raw=(out/"public-screen-lease/RESULT.json").read_bytes()
        screen=json.loads(screen_raw);screen_test=screen.get("test",{})
        if (screen.get("schema")!="hepta.public-screen-lease-host-run.v1" or screen.get("passed") is not True
                or screen.get("phone_operations")!=0 or screen.get("android_power_api_executed") is not False
                or screen.get("inputs_before")!=screen.get("inputs_after")
                or [row.get("name") for row in screen.get("stages",[])]!=["compile","screen-lease","initial-readiness"]
                or any(type(row.get("exit_code")) is not int or row["exit_code"]!=0 for row in screen.get("stages",[]))
                or screen_test.get("schema")!="hepta.public-screen-lease-host.v1" or screen_test.get("all_pass") is not True
                or type(screen_test.get("cases")) is not int or screen_test["cases"]!=42
                or type(screen_test.get("assertions")) is not int or screen_test["assertions"]!=85
                or screen_test.get("phone_operations")!=0 or screen_test.get("android_power_api_executed") is not False):
            raise RuntimeError("Actual isolated screen-lease host contract differs")
        screen_names=screen_test.get("case_names")
        if (type(screen_names) is not list or len(screen_names)!=42 or len(set(screen_names))!=42
                or any(type(name) is not str or not name for name in screen_names)
                or hashlib.sha256("\n".join(screen_names).encode()).hexdigest()!=
                    "65e0331d44e95ad29dbdf4e533dd64bd68e6567e82439a5b29371a02528318af"
                or json.loads((out/"public-screen-lease/screen-lease.stdout").read_bytes())!=screen_test):
            raise RuntimeError("Screen-lease original case names or raw receipt differ")
        initial=screen.get("initial_readiness_test",{});initial_names=initial.get("case_names")
        if (initial.get("schema")!="hepta.public-screen-initial-readiness-host.v1" or initial.get("all_pass") is not True
                or type(initial.get("cases")) is not int or initial["cases"]!=25
                or type(initial.get("assertions")) is not int or initial["assertions"]!=68
                or initial.get("phone_operations")!=0 or initial.get("android_power_api_executed") is not False
                or type(initial_names) is not list or len(initial_names)!=25 or len(set(initial_names))!=25
                or any(type(name) is not str or not name for name in initial_names)
                or hashlib.sha256("\n".join(initial_names).encode()).hexdigest()!=
                    "24f9b3dc06329b6af33eec47640a51491564e6ef13770100cd40348e37e2964b"
                or json.loads((out/"public-screen-lease/initial-readiness.stdout").read_bytes())!=initial):
            raise RuntimeError("Initial screen readiness case names or raw receipt differ")
        report["public_screen_lease_gate"]={"bytes":len(screen_raw),"sha256":hashlib.sha256(screen_raw).hexdigest(),
            "test":screen_test,"initial_readiness_test":initial}
        run("main-ui-permission",[sys.executable,"-B",ROOT/"tests/main-ui-permission/run_host.py",
            "--source",ROOT,"--output",out/"main-ui-permission","--java-home",java_home,"--json-jar",json_jar])
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
        run("sdk-generate-exception-boundary",[sys.executable,ROOT/"native/tests/test_sdk_exception_boundary.py"])
        run("profile-sampler",[sys.executable,"-B",ROOT/"native/tests/test_profile_sampler.py",
            "--source",ROOT,"--output",out/"profile-sampler"])
        run("notes-completion-evidence",[sys.executable,"-B",ROOT/"tests/completion/test_notes_completion.py",
            "--java",java,"--report",out/"notes-completion-evidence"/"VALIDATION.json","--release8"])
        run("task-completion",[sys.executable,"-B",ROOT/"tests/completion/run_host_tests.py",
            "--source",ROOT,"--output",out/"task-completion","--release8"])
        run("calculator-completion-pure",[sys.executable,"-B",ROOT/"tests/calculator-completion/run_host_tests.py",
            "--source",ROOT,"--output",out/"calculator-completion-pure","--release8"])
        run("observation-collection",[sys.executable,"-B",ROOT/"tests/observation-collection/run_host_tests.py",
            "--source",ROOT,"--output",out/"observation-collection","--release8"])
        run("notes-owner-intent",[sys.executable,"-B",ROOT/"tests/notes-owner-intent/run_host_tests.py",
            "--source",ROOT,"--output",out/"notes-owner-intent","--release8"])
        run("notes-task-info-reader",[sys.executable,"-B",ROOT/"tests/notes-task-info-reader/run_host.py",
            "--source",ROOT,"--output",out/"notes-task-info-reader","--java-home",java_home,"--json-jar",json_jar])
        notes_raw=(out/"notes-task-info-reader/RESULT.json").read_bytes()
        notes_gate=json.loads(notes_raw)
        notes_fixture={"path":str(ROOT/"tests/notes-task-info-reader/synthetic-notes-census.json"),
            "bytes":18714,"sha256":"8b44610ab210e5882d5de0cb61583992ccb626ed021b63af277f47407c3af201"}
        if (notes_gate.get("schema")!="hepta.notes-task-info-reader-gate.v2"
                or notes_gate.get("all_pass") is not True or notes_gate.get("inputs_unchanged") is not True
                or notes_gate.get("framework_and_binder_fixtures_synthetic") is not True
                or notes_gate.get("android_runtime") is not False or notes_gate.get("hardware_qualification_claimed") is not False
                or type(notes_gate.get("phone_operations")) is not int or notes_gate["phone_operations"]!=0
                or notes_gate.get("input_mode")!="synthetic_derived_fixture"
                or notes_gate.get("archived_capture_replayed") is not False or notes_gate.get("input_fixture")!=notes_fixture):
            raise RuntimeError("Notes TaskInfo gate requires the exact bundled synthetic input and v2 provenance")
        if (notes_gate.get("inputs_before")!=notes_gate.get("inputs_after")
                or type(notes_gate.get("inputs_before")) is not list or notes_fixture not in notes_gate["inputs_before"]
                or not any(row["path"]=="tests/notes-task-info-reader/synthetic-notes-census.json"
                    and row["sha256"]==notes_fixture["sha256"] for row in report["source_inputs"])):
            raise RuntimeError("Notes synthetic fixture is missing from complete fixed before/after inputs")
        notes_cases=notes_gate.get("reflection_cases",{})
        if (notes_cases.get("schema")!="hepta.notes-task-info-reader-host.v2" or notes_cases.get("all_pass") is not True
                or notes_cases.get("input_mode")!="synthetic_derived_fixture"
                or notes_cases.get("input_sha256")!=notes_fixture["sha256"]
                or notes_cases.get("archived_capture_replayed") is not False
                or "actual_capture_sha256" not in notes_cases or notes_cases["actual_capture_sha256"] is not None
                or notes_cases.get("input_values_rehydrated") is not True
                or notes_cases.get("synthetic_binder_tokens") is not True
                or notes_cases.get("framework_and_clock_fixtures_synthetic") is not True
                or notes_cases.get("complete_production_reflection_adapters") is not True
                or notes_cases.get("hardware_qualification_claimed") is not False
                or any(type(notes_cases.get(k)) is not int or notes_cases[k]!=0
                    for k in ("phone_operations","get_child_tasks_calls","mutation_calls"))
                or type(notes_cases.get("cases")) is not int or notes_cases["cases"]!=71
                or type(notes_cases.get("assertions")) is not int or notes_cases["assertions"]!=238):
            raise RuntimeError("Notes TaskInfo case receipt or original 71 cases and bounded-sampling assertion contract differs")
        notes_names=notes_cases.get("case_names")
        if (type(notes_names) is not list or len(notes_names)!=71
                or any(type(name) is not str or not name for name in notes_names) or len(set(notes_names))!=71):
            raise RuntimeError("Notes TaskInfo case names are incomplete or duplicated")
        notes_empty=notes_cases.get("empty_activity",{})
        if (notes_empty.get("schema")!="hepta.notes-empty-activity-host.v1" or notes_empty.get("all_pass") is not True
                or type(notes_empty.get("cases")) is not int or notes_empty["cases"]!=14
                or type(notes_empty.get("assertions")) is not int or notes_empty["assertions"]!=59
                or type(notes_empty.get("case_names")) is not list or len(notes_empty["case_names"])!=14
                or any(type(name) is not str or not name for name in notes_empty["case_names"])
                or len(set(notes_empty["case_names"]))!=14
                or notes_empty.get("framework_and_binder_fixtures_synthetic") is not True
                or type(notes_empty.get("phone_operations")) is not int or notes_empty["phone_operations"]!=0):
            raise RuntimeError("Notes empty-activity and actual-field diagnostic cases differ")
        first_root=notes_cases.get("first_root_bootstrap",{})
        if (first_root.get("cases")!=22 or first_root.get("assertions")!=116
                or len(set(first_root.get("case_names",[])))!=22 or first_root.get("phone_operations")!=0
                or first_root.get("framework_and_binder_fixtures_synthetic") is not True):
            raise RuntimeError("Complete bound first-root read and refusal cases required")
        notes_stability=notes_cases.get("taskinfo_stability",{})
        if (notes_stability.get("schema")!="hepta.notes-taskinfo-stability-host.v1" or notes_stability.get("all_pass") is not True
                or type(notes_stability.get("cases")) is not int or notes_stability["cases"]!=12
                or type(notes_stability.get("assertions")) is not int or notes_stability["assertions"]!=60
                or type(notes_stability.get("case_names")) is not list or len(notes_stability["case_names"])!=12
                or any(type(name) is not str or not name for name in notes_stability["case_names"])
                or len(set(notes_stability["case_names"]))!=12
                or notes_stability.get("framework_and_binder_fixtures_synthetic") is not True
                or type(notes_stability.get("phone_operations")) is not int or notes_stability["phone_operations"]!=0
                or type(notes_stability.get("intent_redispatches")) is not int or notes_stability["intent_redispatches"]!=0
                or notes_stability.get("maximum_complete_samples")!=3 or notes_stability.get("maximum_frame_ms")!=1500):
            raise RuntimeError("Notes bounded read-only stability and immutable identity cases differ")
        notes_private=notes_gate.get("original_private_cases",{})
        if (notes_private.get("schema")!="hepta.profile-broker-host-tests.v1" or notes_private.get("passed") is not True
                or type(notes_private.get("cases")) is not int or notes_private["cases"]!=47
                or type(notes_private.get("assertions")) is not int or notes_private["assertions"]!=449
                or notes_private.get("framework_fixtures_synthetic") is not True or notes_private.get("phone_contacted") is not False):
            raise RuntimeError("Notes gate changed the original private 47/449 contract")
        notes_stages=notes_gate.get("stages")
        if (type(notes_stages) is not list or [row.get("name") for row in notes_stages]!=
                ["compile-reflection","reflection-cases","compile-original-private","original-private-cases"]
                or any(type(row.get("exit_code")) is not int or row["exit_code"]!=0 for row in notes_stages)):
            raise RuntimeError("Notes gate lacks its four actual compile/run stages")
        report["notes_task_info_reader_gate"]={"bytes":len(notes_raw),
            "sha256":hashlib.sha256(notes_raw).hexdigest(),"input_fixture":notes_fixture,
            "cases":notes_cases,"original_private_cases":notes_private}
        run("personal-notes-absence",[sys.executable,"-B",ROOT/"tests/personal-notes-absence/run_host.py",
            "--source",ROOT,"--output",out/"personal-notes-absence","--java-home",java_home,"--json-jar",json_jar])
        notes_absence_raw=(out/"personal-notes-absence/RESULT.json").read_bytes()
        notes_absence=json.loads(notes_absence_raw)
        if (notes_absence.get("schema")!="hepta.personal-notes-absence-host-validation.v1"
                or notes_absence.get("all_pass") is not True or notes_absence.get("strict_release8") is not True
                or notes_absence.get("inputs_unchanged") is not True
                or notes_absence.get("all_task_values_synthetic") is not True
                or notes_absence.get("framework_samples_synthetic") is not True
                or notes_absence.get("current_installation_pm_fixture_synthetic") is not True
                or notes_absence.get("owned_process_factory_replacements_only") is not True
                or notes_absence.get("android_runtime") is not False
                or notes_absence.get("business_success_claimed") is not False
                or type(notes_absence.get("phone_operations")) is not int or notes_absence["phone_operations"]!=0
                or notes_absence.get("json_jar_sha256")!="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"):
            raise RuntimeError("Notes absence requires strict Java 8 compilation and unchanged synthetic host provenance")
        notes_absence_contracts={
            "policy":("hepta.personal-notes-absence-host.v1","cases",91,109,"case_names",
                "945275de9519682a14a8fbda5b914bb8098349bcb66b854d924ea713d75d9560"),
            "client":("hepta.personal-notes-recovery-client-host-tests.v1","checks",27,247,"cases",
                "a3bc86072c411a9ed2cd791ce832e690812b6fc333248be4ac0e1af823188c9a"),
            "post-model":("hepta.personal-notes-post-model-host.v1","cases",51,89,"case_names",
                "6069172caafbc3746974a84016abc18409b16ccd4cb9635dc5c90f5ea7a3ddb9")}
        for key,(schema,metric,count,assertions,names_metric,names_hash) in notes_absence_contracts.items():
            cases=notes_absence.get(key,{})
            if (cases.get("schema")!=schema or cases.get("all_pass",cases.get("passed")) is not True
                    or type(cases.get(metric)) is not int or cases[metric]!=count
                    or type(cases.get("assertions")) is not int or cases["assertions"]!=assertions):
                raise RuntimeError("Notes absence case contract changed: "+key)
            names=cases.get(names_metric)
            if (type(names) is not list or len(names)!=count or len(set(names))!=count
                    or any(type(name) is not str or not name for name in names)
                    or hashlib.sha256(json.dumps(names,ensure_ascii=True,separators=(",",":")).encode()).hexdigest()!=names_hash):
                raise RuntimeError("Notes absence case identities changed: "+key)
            original=json.loads((out/"personal-notes-absence"/(key+".stdout")).read_bytes())
            if original!=cases:
                raise RuntimeError("Notes absence aggregate differs from actual Java stdout: "+key)
        census=notes_absence.get("display-census")
        if (type(census) is not dict or type(census.get("cases")) is not int or census["cases"]!=15
                or type(census.get("assertions")) is not int or census["assertions"]!=16
                or census.get("failed")!=[]
                or type(census.get("phone_operations")) is not int or census["phone_operations"]!=0):
            raise RuntimeError("Notes display census case contract changed")
        census_names=census.get("passed")
        if (type(census_names) is not list or len(census_names)!=15 or len(set(census_names))!=15
                or any(type(name) is not str or not name for name in census_names)
                or hashlib.sha256(json.dumps(census_names,ensure_ascii=True,separators=(",",":")).encode()).hexdigest()!="950c6a97ac544edd3d18116a03a42612aff33ed110c17ab85fa359e6cfaf4a90"):
            raise RuntimeError("Notes display census case identities changed")
        if json.loads((out/"personal-notes-absence/display-census.stdout").read_bytes())!=census:
            raise RuntimeError("Notes display census aggregate differs from actual Java stdout")
        notes_absence_stages=notes_absence.get("stages")
        if (type(notes_absence_stages) is not list or [row.get("stage") for row in notes_absence_stages]!=
                ["policy-compile","policy","display-census","client-compile","client","post-model"]
                or any(type(row.get("exit_code")) is not int or row["exit_code"]!=0 for row in notes_absence_stages)):
            raise RuntimeError("Notes absence lacks all six real compile/run stages")
        report["personal_notes_absence_gate"]={"bytes":len(notes_absence_raw),
            "sha256":hashlib.sha256(notes_absence_raw).hexdigest(),
            "policy":notes_absence["policy"],"display-census":census,"client":notes_absence["client"],"post-model":notes_absence["post-model"]}
        run("native-auto-target",[sys.executable,"-B",ROOT/"tests/native-auto-target/run_host.py",
            "--source",ROOT,"--output",out/"native-auto-target","--java-home",java_home,"--json-jar",json_jar])
        run("native-xiaomi-budget-preview",[sys.executable,"-B",ROOT/"tests/native-xiaomi-budget-preview/run_host.py",
            "--source",ROOT,"--output",out/"native-xiaomi-budget-preview","--java-home",java_home,"--json-jar",json_jar])
        run("native-search-login-handoff",[sys.executable,"-B",ROOT/"tests/native-search-session/run_host.py",
            "--source",ROOT,"--output",out/"native-search-login-handoff","--java-home",java_home,"--json-jar",json_jar])
        run("native-search-producer",[sys.executable,"-B",ROOT/"tests/native-search-producer/run_producer.py",
            "--source",ROOT,"--output",out/"native-search-producer","--java-home",java_home,"--json-jar",json_jar])
        census_source=ROOT/"src/org/trillionnium/hepta/background/ProfileRecoveryProcesses.java"
        run("profile-recovery-census",[sys.executable,"-B",ROOT/"tests/profile-recovery-census/run_host.py",
            "--source-root",ROOT,"--expected-processes",hashlib.sha256(census_source.read_bytes()).hexdigest(),
            "--jdk-bin",java_home/"bin","--json-jar",json_jar,"--output",out/"profile-recovery-census"])
        run("foreground-concurrency",[sys.executable,"-B",ROOT/"tests/public-profile-history/run_concurrency_host.py",
            "--source",ROOT,"--output",out/"foreground-concurrency","--java-home",java_home,"--json-jar",json_jar])
        concurrency_raw=(out/"foreground-concurrency/RESULT.json").read_bytes()
        concurrency=json.loads(concurrency_raw)
        if (concurrency.get("schema")!="hepta.foreground-concurrency-host.v1"
                or concurrency.get("all_pass") is not True or concurrency.get("strict_release8") is not True
                or concurrency.get("source_inputs_unchanged") is not True or concurrency.get("json_jar_unchanged") is not True
                or concurrency.get("framework_and_user_activity_synthetic") is not True
                or concurrency.get("actual_production_custody_and_receipt_readers") is not True
                or concurrency.get("android_runtime") is not False or concurrency.get("native_model_executed") is not False
                or type(concurrency.get("phone_operations")) is not int or concurrency["phone_operations"]!=0):
            raise RuntimeError("Foreground concurrency host receipt differs")
        concurrency_contracts={
            "custody":(23,44,"1634b5644fbb6accc3c4e9dce37d6c10203fa9954d0b0cbe26079c256c1fcdc6"),
            "receipts":(25,30,"c503a5913d9899568542aa784d996a8822fc25302eee3b962d6d5730477fbe8b"),
            "recovery_entry":(6,8,"02d4d12aead56f784df256a64a920dce313d364ee0edcf71e54aeb6023384fa0")}
        if set(concurrency.get("cases",{}))!=set(concurrency_contracts):
            raise RuntimeError("Foreground concurrency case groups differ")
        for name,(count,assertions,names_sha) in concurrency_contracts.items():
            cases=concurrency["cases"][name]
            names=cases.get("case_names")
            if (cases.get("passed") is not True or type(cases.get("cases")) is not int or cases["cases"]!=count
                    or type(cases.get("assertions")) is not int or cases["assertions"]!=assertions
                    or type(names) is not list or len(names)!=count or len(set(names))!=count
                    or cases.get("case_names_sha256")!=names_sha
                    or hashlib.sha256(json.dumps(names,ensure_ascii=False,separators=(",",":")).encode()).hexdigest()!=names_sha):
                raise RuntimeError("Foreground concurrency case contract differs: "+name)
        if ([row.get("name") for row in concurrency.get("stages",[])]!=["compile","custody","receipts","recovery_entry"]
                or any(row.get("exit_code")!=0 for row in concurrency["stages"])):
            raise RuntimeError("Foreground concurrency compile/run stages incomplete")
        report["foreground_concurrency_gate"]={"bytes":len(concurrency_raw),
            "sha256":hashlib.sha256(concurrency_raw).hexdigest(),"cases":concurrency["cases"]}
        run("ctrip-form-observation",[sys.executable,"-B",ROOT/"tests/native-ctrip-form-observation/run_host.py",
            "--source",ROOT,"--output",out/"ctrip-form-observation","--java-home",java_home,"--json-jar",json_jar])
        run("native-form-history-actions",[sys.executable,"-B",ROOT/"tests/native-form-history-actions/run_host.py",
            "--source",ROOT,"--output",out/"native-form-history-actions","--java-home",java_home])
        run("ctrip-startup-promotion",[sys.executable,"-B",ROOT/"tests/native-ctrip-promotion/run_host.py",
            "--out",out/"ctrip-startup-promotion","--java-home",java_home,"--json-jar",json_jar])
        run("ctrip-login-return-calendar-minimum",[sys.executable,"-B",ROOT/"tests/native-ctrip-login-form-terminal/run_host.py",
            "--source",ROOT,"--output",out/"ctrip-login-return-calendar-minimum","--java-home",java_home,"--json-jar",json_jar])
        run("public-profile-terminal-bridge",[sys.executable,"-B",ROOT/"tests/public-profile-terminal-bridge/run_host.py",
            "--source",ROOT,"--output",out/"public-profile-terminal-bridge","--java-home",java_home,"--json-jar",json_jar])
        bridge_raw=(out/"public-profile-terminal-bridge/RESULT.json").read_bytes()
        bridge=json.loads(bridge_raw)
        if (bridge.get("schema")!="hepta.public-profile-terminal-bridge-host.v1" or bridge.get("all_pass") is not True
                or bridge.get("strict_release8") is not True or bridge.get("source_inputs_unchanged") is not True
                or bridge.get("tools_unchanged") is not True or bridge.get("android_runtime") is not False
                or bridge.get("native_model_executed") is not False or bridge.get("full_android_controller_compiled_or_executed") is not False
                or bridge.get("controller_bridge_verbatim_extraction") is not True
                or bridge.get("actual_profile_owned_task_producer") is not True or bridge.get("actual_background_session_consumer") is not True
                or bridge.get("actual_native_session_terminal") is not True or bridge.get("framework_model_installed_and_worker_io_synthetic") is not True
                or type(bridge.get("phone_operations")) is not int or bridge["phone_operations"]!=0):
            raise RuntimeError("Public profile terminal bridge receipt differs")
        bridge_contracts={'legacy': (1, 28, 'ad7777f8f55f49c6fdf31b255460e7526ce4449eaec94a2378ce3e7f6ebdf864', 0, 1), 'candidate': (33, 412, '5f2b560320c45a07a342a67ef1e8e703b2cf390494ca1406ebe549814322312d', 11, 17)}
        if set(bridge.get("cases",{}))!=set(bridge_contracts):
            raise RuntimeError("Public profile terminal bridge case groups differ")
        bridge_summary={}
        for name,(count,assertions,names_sha,refusals,terminals) in bridge_contracts.items():
            cases=bridge["cases"][name];names=cases.get("case_names")
            if (cases.get("schema")!="hepta.public-profile-terminal-bridge-cases.v1" or cases.get("all_pass") is not True
                    or type(cases.get("cases")) is not int or cases["cases"]!=count
                    or type(cases.get("assertions")) is not int or cases["assertions"]!=assertions
                    or type(names) is not list or len(names)!=count or len(set(names))!=count
                    or cases.get("case_names_sha256")!=names_sha
                    or hashlib.sha256(json.dumps(names,ensure_ascii=False,separators=(",",":")).encode()).hexdigest()!=names_sha
                    or type(cases.get("real_nested_consumer_refusals")) is not int or cases["real_nested_consumer_refusals"]!=refusals
                    or type(cases.get("full_native_terminal_calls")) is not int or cases["full_native_terminal_calls"]!=terminals
                    or cases.get("old_bridge_full_terminal_reproduced") is not (name=="legacy")):
                raise RuntimeError("Public profile terminal bridge exact case contract differs: "+name)
            actual=json.loads((out/"public-profile-terminal-bridge"/(name+"-CASES.json")).read_bytes())
            aggregate=dict(cases);aggregate.pop("case_names_sha256")
            lines=(out/"public-profile-terminal-bridge"/(name+".stdout")).read_text().splitlines()
            emitted=[line for line in lines if line.startswith("{")]
            if (aggregate!=actual or len(emitted)!=1 or json.loads(emitted[0])!=actual
                    or [line[5:] for line in lines if line.startswith("PASS ")]!=names):
                raise RuntimeError("Public profile terminal bridge cases differ from actual Java output: "+name)
            bridge_summary[name]={key:cases[key] for key in ("cases","assertions","case_names_sha256",
                "real_nested_consumer_refusals","full_native_terminal_calls","old_bridge_full_terminal_reproduced")}
        if ([row.get("name") for row in bridge.get("stages",[])]!=["compile","legacy","candidate"]
                or any(type(row.get("exit_code")) is not int or row["exit_code"]!=0 for row in bridge["stages"])
                or bridge.get("controller_bridge",{}).get("verbatim_method_and_helpers") is not True
                or bridge["controller_bridge"].get("source",{}).get("sha256")!=hashlib.sha256((ROOT/"src/org/trillionnium/hepta/local/LocalTaskController.java").read_bytes()).hexdigest()):
            raise RuntimeError("Public profile terminal bridge actual source or compile/run stages differ")
        report["public_profile_terminal_bridge_gate"]={"bytes":len(bridge_raw),
            "sha256":hashlib.sha256(bridge_raw).hexdigest(),"cases":bridge_summary}
        run("owned-worker-cancellation",[sys.executable,"-B",ROOT/"tests/owned-worker-cancellation/run_host_tests.py",
            "--source",ROOT,"--output",out/"owned-worker-cancellation"])
        run("background-owned-task-policy",[sys.executable,"-B",ROOT/"tests/background-owned-task/run_host_tests.py",
            "--out",out/"background-owned-task-policy","--java",java])
        run("sdk-exception-failure-audit",[sys.executable,"-B",ROOT/"tests/sdk-exception-failure-audit/run_host.py",
            "--source",ROOT,"--output",out/"sdk-exception-failure-audit","--java-home",java_home,
            "--json-jar",json_jar,"--python",Path(sys.executable).resolve()])
        run("owned-generation-cleanup",[sys.executable,"-B",ROOT/"tests/owned-generation-cleanup/run_host.py",
            "--source",ROOT,"--output",out/"owned-generation-cleanup","--java-home",java_home,
            "--json-jar",json_jar,"--python",Path(sys.executable).resolve(),"--cc",Path(cc).resolve()])
        additional_contracts={"owned-generation-cleanup":{"schema":"hepta.owned-generation-cleanup-gate.v1","case_schema":"hepta.owned-generation-cleanup-host.v1","cases":87,"metric":"checks","count":267,"case_names_sha256":"2f63e71ea898341d5818b437c2977d8eb9023c207484a0a6587f73b23239180f"},"sdk-exception-failure-audit":{"schema":"hepta.sdk-exception-failure-audit-gate.v1","case_schema":"hepta.sdk-exception-failure-audit-host.v1","cases":43,"metric":"assertions","count":99,"case_names_sha256":"317c235ce467904c60ad8fe000f412adf3a96d5253a29581f92dff025da84188"}}
        report["mandatory_additional_gate_receipts"]={}
        for name in ("sdk-exception-failure-audit","owned-generation-cleanup"):
            contract=additional_contracts[name]
            gate_path=out/name/"RESULT.json"
            gate_raw=gate_path.read_bytes()
            gate=json.loads(gate_raw)
            if gate.get("schema")!=contract["schema"] or gate.get("all_pass") is not True or gate.get("inputs_unchanged") is not True:
                raise RuntimeError("Mandatory additional gate lacks its successful unchanged-input receipt: "+name)
            cases=gate.get("cases")
            if type(cases) is not dict or cases.get("schema")!=contract["case_schema"] or cases.get("all_pass") is not True:
                raise RuntimeError("Mandatory additional gate has no typed case receipt: "+name)
            if type(cases.get("cases")) is not int or cases["cases"]!=contract["cases"] or type(cases.get(contract["metric"])) is not int or cases[contract["metric"]]!=contract["count"]:
                raise RuntimeError("Mandatory additional gate has incomplete cases/assertions: "+name)
            names=cases.get("case_names")
            if type(names) is not list or any(type(x) is not str for x in names) or len(names)!=contract["cases"] or len(set(names))!=len(names):
                raise RuntimeError("Mandatory additional gate case identities are missing or duplicated: "+name)
            names_hash=hashlib.sha256(json.dumps(names,ensure_ascii=True,separators=(",",":")).encode()).hexdigest()
            if names_hash!=contract["case_names_sha256"]:
                raise RuntimeError("Mandatory additional gate case identities changed: "+name)
            cases_original=json.loads((out/name/"CASES.json").read_bytes())
            if json.dumps(cases_original,sort_keys=True,separators=(",",":"))!=json.dumps(cases,sort_keys=True,separators=(",",":")):
                raise RuntimeError("Mandatory additional gate RESULT/CASES originals differ: "+name)
            report["mandatory_additional_gate_receipts"][name]={
                "path":str(gate_path),"bytes":len(gate_raw),"sha256":hashlib.sha256(gate_raw).hexdigest(),
                "schema":gate["schema"],"cases":cases}
        run("profile-permission-transient",[sys.executable,"-B",ROOT/"tests/profile-permission-transient/run_host.py",
            "--source",ROOT,"--output",out/"profile-permission-transient","--java-home",java_home])
        permission_raw=(out/"profile-permission-transient/RESULT.json").read_bytes()
        permission_gate=json.loads(permission_raw)
        permission_cases=permission_gate.get("synthetic_summary",{})
        if (permission_gate.get("schema")!="hepta.profile-permission-transient-canonical-host.v1"
                or permission_gate.get("all_pass") is not True or permission_gate.get("source_inputs_unchanged") is not True
                or permission_gate.get("real_dump_requested") is not False
                or permission_cases.get("passed") is not True or permission_cases.get("cases")!=16
                or permission_cases.get("fixture_kind")!="synthetic"):
            raise RuntimeError("Mandatory permission transient gate receipt differs")
        report["permission_transient_gate"]={"bytes":len(permission_raw),
            "sha256":hashlib.sha256(permission_raw).hexdigest(),"cases":permission_cases}
        # The new preparation route does not change any ordinary ownership gate.
        # Execute its core and actual worker separately; Android IO remains explicit.
        permission_contracts={
            "profile-permission-initialization":("hepta.permission-init-core-host.v1",{
                "new_policy_cases":(81,330),"physical_fence_cases":(26,40)}),
            "profile-permission-ui":("hepta.permission-ui-host.v1",{"checks":(23,104),"late_ready_broker":(11,22)})}
        report["permission_initialization_gates"]={}
        for name,(schema,case_contracts) in permission_contracts.items():
            run(name,[sys.executable,"-B",ROOT/"tests"/name/"run_host.py",
                "--source",ROOT,"--output",out/name,"--java-home",java_home])
            receipt_raw=(out/name/"RESULT.json").read_bytes()
            receipt=json.loads(receipt_raw)
            if (receipt.get("schema")!=schema or receipt.get("all_pass") is not True
                    or receipt.get("source_inputs_unchanged") is not True
                    or receipt.get("java_release_api_check") is not True
                    or receipt.get("phone_contacted") is not False
                    or receipt.get("android_adapters_compiled") is not False):
                raise RuntimeError("Permission initialization gate receipt differs: "+name)
            for key,(cases,assertions) in case_contracts.items():
                actual=receipt.get(key,{})
                if (actual.get("all_pass") is not True or type(actual.get("cases")) is not int
                        or actual["cases"]!=cases or type(actual.get("assertions")) is not int
                        or actual["assertions"]!=assertions or actual.get("android_adapter_executed") is not False
                        or actual.get("phone_contacted") is not False):
                    raise RuntimeError("Permission initialization cases differ: "+name+"/"+key)
            report["permission_initialization_gates"][name]={"bytes":len(receipt_raw),
                "sha256":hashlib.sha256(receipt_raw).hexdigest(),
                "cases":{key:receipt[key] for key in case_contracts}}
        run("visual-prompt-projection",[sys.executable,"-B",ROOT/"tests/visual-prompt-projection/run_host_tests.py",
            "--source",ROOT,"--out",out/"visual-prompt-projection","--json-jar",json_jar,"--release8"])
        run("vlm-result-contract",[sys.executable,"-B",ROOT/"tests/vlm-contract/run_host_tests.py",
            "--source",ROOT,"--output",out/"vlm-result-contract","--java-home",java_home])
        run("vlm-template-render",[sys.executable,"-B",ROOT/"tests/vlm-contract/check_template.py",
            "--template",ROOT/"tests/vlm-contract/fixtures/gui-owl-chat-template.jinja",
            "--output",out/"vlm-template-render"])
        run("vlm-adapter-lifecycle",[sys.executable,"-B",ROOT/"tests/vlm-adapter/run_host.py",
            "--source",ROOT,"--output",out/"vlm-adapter-lifecycle","--java-home",java_home,
            "--json-jar",json_jar,"--template",ROOT/"tests/vlm-contract/fixtures/gui-owl-chat-template.jinja"])
        if json_jar.read_bytes()!=json_bytes: raise RuntimeError("Host JSON dependency changed during checks")
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
