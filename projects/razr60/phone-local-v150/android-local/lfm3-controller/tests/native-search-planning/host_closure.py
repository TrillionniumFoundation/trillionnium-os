"""Shared host compile closure: real Session/Offer/Role, explicit Android IO ports.

No phone command is available here.  Existing profile/background host ports are
reused exactly; actual full production classes remain the compiled consumers.
"""
from pathlib import Path
import hashlib
import importlib.util

JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def record(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def prepare(source, output, extra_tests=()):
    """Return (actual compile paths, provenance) in a fresh output directory.

    `extra_tests` are explicit Path values.  Both old complete fixture classes
    are always included, so callers can reuse their synthetic setup without
    manufacturing permission-bearing Session, Offer, or Attempt objects.
    """
    source, output = Path(source).resolve(), Path(output).resolve()
    if output.exists():
        raise RuntimeError("host closure output must be fresh")
    output.mkdir(parents=True, mode=0o700)
    query_path = source / "tests/web-flight/run_query_host_tests.py"
    background_path = source / "tests/background-session/prepare_fixture.py"
    query = module(query_path, "native_search_query_closure")
    background = module(background_path, "native_search_background_closure")
    bgfiles, extraction = background.prepare(source, output / "ports", include_terminal=False)
    # The original Android ports are retained; JSON semantics come from the
    # independently pinned actual org.json jar, not a capability-shaped stub.
    bgfiles = [p for p in bgfiles if not (p.parent.name == "json" and p.parent.parent.name == "org")]
    config_path = output / "ports/org/trillionnium/hepta/local/QualificationScopeConfig.java"
    config_source = source / "src/org/trillionnium/hepta/local/QualificationScopeConfig.java"
    actual_completion = query.java_block(config_source.read_bytes(), "static final class CompletionInstalledIdentity {")
    config = config_path.read_text()
    if not config.endswith("}\n") or "CompletionInstalledIdentity" in config:
        raise RuntimeError("nonunique original complete identity fixture")
    # Same refusing ordinary-PackageManager endpoints as run_native_host.py.
    ports = '''
    private static final class Installed {
        String packageName,apkSetSha256;int uid;long version;
        Map<String,Apk> apks;
        static Installed capture(Context c,String pkg){throw new AssertionError("ordinary PackageManager fallback forbidden in profile gate");}
        void verify(Context c){throw new AssertionError("ordinary installation verifier forbidden in profile gate");}
    }
    private static final class Apk {String sha256;}
'''
    config_path.write_text(config[:-2].replace("import java.io.File;", "import java.io.File;import java.util.*;")
                           + actual_completion + "\n" + ports + "}\n")
    calculator = output / "ports/org/trillionnium/hepta/local/CalculatorGoalContract.java"
    calculator.write_text('package org.trillionnium.hepta.local;final class CalculatorGoalContract {static final String PACKAGE="com.google.android.calculator";}\n')
    bgfiles.append(calculator)
    fixture_source = source / "tests/background-session/BackgroundSessionHostTest.java"
    signatures = ("static Object invoke(", "static JSONObject decode(", "static byte[] frame(",
                  "static JSONObject policy(", "static byte[] response(")
    fixture_methods = [query.java_block(fixture_source.read_bytes(), s) for s in signatures]
    client = output / "ports/org/trillionnium/hepta/local/ProfileClientPort.java"
    client.write_text("package org.trillionnium.hepta.local;\nimport java.io.*;import java.lang.reflect.*;"
                      "import java.nio.charset.StandardCharsets;import java.util.*;import org.json.*;"
                      "import android.os.SystemClock;\nfinal class ProfileClientPort {\n"
                      + "\n".join(fixture_methods) + "\n}\n")
    bgfiles.append(client)
    # Session.acceptOutcome consumes the entire actual production result type.
    # Only its containing Android service is absent from this pure consumer gate.
    service_source = source / "src/org/trillionnium/hepta/local/HeptaAccessibilityService.java"
    outcome = query.java_block(service_source.read_bytes(), "public static final class ActionOutcome {")
    service_path = output / "ports/org/trillionnium/hepta/local/HeptaAccessibilityService.java"
    service = service_path.read_text()
    if not service.endswith("}") or "class ActionOutcome" in service:
        raise RuntimeError("nonunique original service IO port")
    service_path.write_text(service[:-1].replace("package org.trillionnium.hepta.local;",
                            "package org.trillionnium.hepta.local;import org.json.JSONObject;")
                            + "\n" + outcome + "\n"
                            + "static final class NativeSearchReadRetryProof { private NativeSearchReadRetryProof(){throw new AssertionError(\"Android initial-read proof is unavailable in this pure consumer gate\");} }\n}\n")
    excluded = {"tests/web-flight/WebFlightQueryHostTest.java", "tests/native-app/legacy-boundary/NativeAppSession.java"}
    paths = [source / p for p in query.PURE_PATHS if p not in excluded] + bgfiles
    paths += [source / ("src/org/trillionnium/hepta/local/" + name + ".java") for name in (
        "ObservationCaptureEvidence", "PromptActionDomain", "NativeAppEvidence", "NativeAppDomain", "NativeAppSession",
        "NativeActionSnapshotCheck", "NativeAppObservation", "NativeCtripFlightPage", "NativeXiaomiProductPage",
        "ActionExecutionState", "NativeSearchRole", "NativeSearchPlanning", "NativeSearchDecision", "NativeSearchSession")]
    paths += [source / "tests/xiaomi-profile/NativeProfileIdentityHostTest.java",
              source / "tests/native-action-integration/NativeActionSnapshotCheckHostTest.java"]
    paths += list(map(Path, extra_tests))
    paths = list(dict.fromkeys(p.resolve() for p in paths))
    originals = [p for p in paths if source in p.parents] + [
        config_source, fixture_source, service_source, query_path, background_path, Path(__file__).resolve()]
    originals = list(dict.fromkeys(p.resolve() for p in originals))
    provenance = {
        "schema": "hepta.native-search-shared-host-closure.v1",
        "source": str(source), "production_inputs": [record(p) for p in originals],
        "compile_inputs": [record(p) for p in paths], "background_fixture": extraction,
        "exact_completion_installed_identity_sha256": sha(actual_completion.encode()),
        "exact_actual_action_outcome_sha256": sha(outcome.encode()),
        "client_port_methods": [{"signature": s, "sha256": sha(v.encode())} for s, v in zip(signatures, fixture_methods)],
        "boundary": "Full actual Session, Offer, Attempt, Role, Planning, authorization, selection and provider classes. Existing Android socket/display/clock ports are synthetic; ordinary PM/root recovery ports refuse. Actual ActionOutcome is copied byte-for-byte. This is not an Android producer, phone effect or business-success proof.",
        "phone_actions": 0, "device_qualified": False, "business_verified": False}
    return paths, provenance
