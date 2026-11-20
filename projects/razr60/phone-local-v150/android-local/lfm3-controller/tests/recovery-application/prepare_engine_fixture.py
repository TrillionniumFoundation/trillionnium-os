"""Build only an explicit host fixture around exact production Engine recovery members."""
import hashlib
import json
from pathlib import Path

def _section(text,start,end):
    if text.count(start)!=1 or text.count(end)!=1:
        raise RuntimeError("production extraction anchors are not unique")
    i=text.index(start);j=text.index(end,i)
    return text[i:j]

def prepare(source,output):
    source=Path(source);output=Path(output);output.mkdir(parents=True,exist_ok=True)
    package=source/"src/org/trillionnium/hepta/local"
    engine=(package/"LocalModelEngine.java").read_text(encoding="utf-8")
    parts={
        "RunHandle":_section(engine,"    public static final class RunHandle {","    /** Retains the existing process-wide slot"),
        "external_path":_section(engine,"    /** Shares the existing single-model slot","    /** An aggregate startup barrier"),
        "recovery_path":_section(engine,"    /** An aggregate startup barrier","    public RunHandle start("),
        "process_admission":_section(engine,"    private void claimProcess(","    public Result lastResult()"),
        "runtime_generation":_section(engine,"    static final class RuntimeGeneration {","    private volatile RuntimeGeneration runtime;"),
        "captured_cancellation":_section(engine,"    public void cancelActive() {","    JSONObject cancellationEvidence()"),
    }
    declarations=[]
    for prefix in (
        "    private static final AtomicReference<RunHandle> PROCESS_ACTIVE",
        "    private static final TaskCancellationQueue ACTIVE_CANCELLATION",
        "    private static final Object PROCESS_ADMISSION",
        "    private final AtomicReference<RunHandle> active",
        "    private final AtomicBoolean closed",
        "    private volatile TaskCancellationQueue.Ticket lastCancellation",
        "    private final Context context;",
        "    private volatile RuntimeGeneration runtime;",
        "    private volatile boolean settingsBlocked;",
    ):
        matches=[line for line in engine.splitlines() if line.startswith(prefix)]
        if len(matches)!=1:
            raise RuntimeError("production declaration is not unique: "+prefix)
        declarations.append(matches[0])
    # Only construction, normal model IO and executor shutdown are fixture code.
    # Every recovery ownership/cancellation/close member below is copied verbatim from production.
    rendered=(
        "package org.trillionnium.hepta.local;\n"
        "import android.content.Context;\nimport java.util.UUID;\nimport java.util.concurrent.atomic.*;\n"
        "public final class LocalModelEngine implements AutoCloseable {\n"
        +"\n".join(declarations)+"\n"
        +"public LocalModelEngine(Context context){this.context=context.getApplicationContext();runtime=new RuntimeGeneration(LocalRuntimeConfig.defaults(),null,new ModelFileVerifier(),null);}\n"
        +"private static final class RuntimeConfigTransaction {static final class Snapshot{}}\n"
        +"boolean settingsAdmissionAvailable(boolean restoring){throw new AssertionError(\"settings admission is outside the legacy recovery fixture\");}\n"
        +parts["runtime_generation"]
        +parts["RunHandle"]+parts["external_path"]+parts["recovery_path"]
        +parts["process_admission"]+parts["captured_cancellation"]
        +"@Override public void close(){closed.set(true);cancelActive();}\n}\n"
    )
    engine_file=output/"LocalModelEngine.java";engine_file.write_text(rendered,encoding="utf-8")
    names=["LocalProbeApplication.java","RecoverySlotHandoff.java","RecoveryDispatch.java",
           "RecoveryQuiescence.java","RecoveryJournalTransaction.java","DiagnosticStartupGate.java","OwnedWorkerCancellation.java",
           "TaskCancellationQueue.java","LocalRuntimeConfig.java","ModelProfile.java","ModelFileVerifier.java"]
    actual=[package/name for name in names]
    fixtures=sorted((source/"tests/recovery-application").rglob("*.java"))
    if len(fixtures)!=11:
        raise RuntimeError("unexpected Application host fixture closure")
    # The new Application owns this service, but these original recovery cases never enter settings.
    # Calls into settings-specific policy fail loudly; the full production Engine/settings gate is separate.
    settings_file=output/"LocalModelSettings.java"
    settings_file.write_text("""package org.trillionnium.hepta.local;
final class LocalModelSettings implements AutoCloseable {
 LocalModelSettings(LocalProbeApplication app,LocalModelEngine engine){}
 boolean isBusy(){throw new AssertionError("settings UI is outside the legacy recovery fixture");}
 boolean restoreAvailable(){throw new AssertionError("settings UI is outside the legacy recovery fixture");}
 public void close(){}
}
""",encoding="utf-8")
    service_file=output/"HeptaAccessibilityService.java"
    service_file.write_text("""package org.trillionnium.hepta.local;
final class HeptaAccessibilityService {
 static HeptaAccessibilityService connected(){throw new AssertionError("settings UI is outside the legacy recovery fixture");}
 boolean modelSettingsIdle(){throw new AssertionError("settings UI is outside the legacy recovery fixture");}
}
""",encoding="utf-8")
    all_sources=actual+[engine_file,settings_file,service_file]+fixtures
    digest=lambda b:hashlib.sha256(b).hexdigest()
    record={
        "scope":"actual Application and exact Engine external/recovery members; Android/normal IO/Session/permission Session/diagnostic fixtures",
        "production_engine_sha256":digest(engine.encode()),
        "cancellation_boundary":"Unchanged process-wide TaskCancellationQueue, captured cancelActive, process admission and recovery ownership; host tests drain the exact ticket and close the host executor after all cases",
        "extracted_parts":{name:{"bytes":len(value.encode()),"sha256":digest(value.encode())}
                           for name,value in parts.items()},
        "production_declaration_sha256":digest(("\n".join(declarations)+"\n").encode()),
        "generated_engine_fixture_sha256":digest(rendered.encode()),
        "java_inputs":[{"path":str(path),"sha256":digest(path.read_bytes())} for path in all_sources],
        "not_android_runtime":True,"not_session_filesystem_durability":True,
        "runtime_boundary":"Exact RuntimeGeneration class and actual config/profile/verifier types; snapshot IO is opaque, default construction is a fixture; new settings UI throws if entered. Original recovery assertions are unchanged.",
    }
    (output/"EXTRACTION.json").write_text(json.dumps(record,indent=2)+"\n",encoding="utf-8")
    return all_sources
