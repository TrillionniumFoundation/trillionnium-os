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
        "RunHandle":_section(engine,"    public static final class RunHandle {","    /** Shares the existing single-model slot"),
        "recovery_path":_section(engine,"    /** An aggregate startup barrier","    public RunHandle start("),
    }
    declarations=[]
    for prefix in (
        "    private static final AtomicReference<RunHandle> PROCESS_ACTIVE",
        "    private final AtomicReference<RunHandle> active",
        "    private final AtomicBoolean closed",
        "    public boolean isBusy()",
        "    public void cancelActive()",
    ):
        matches=[line for line in engine.splitlines() if line.startswith(prefix)]
        if len(matches)!=1:
            raise RuntimeError("production declaration is not unique: "+prefix)
        declarations.append(matches[0])
    # Only construction, normal model IO and executor shutdown are fixture code.
    # Every recovery ownership/cancellation/close member below is copied verbatim from production.
    rendered=(
        "package org.trillionnium.hepta.local;\n"
        "import java.util.UUID;\nimport java.util.concurrent.atomic.*;\n"
        "public final class LocalModelEngine implements AutoCloseable {\n"
        +"\n".join(declarations)+"\n"
        +"public LocalModelEngine(android.content.Context ignored){}\n"
        +parts["RunHandle"]+parts["recovery_path"]
        +"@Override public void close(){closed.set(true);cancelActive();}\n}\n"
    )
    engine_file=output/"LocalModelEngine.java";engine_file.write_text(rendered,encoding="utf-8")
    names=["LocalProbeApplication.java","RecoverySlotHandoff.java","RecoveryDispatch.java",
           "RecoveryQuiescence.java","RecoveryJournalTransaction.java","DiagnosticStartupGate.java"]
    actual=[package/name for name in names]
    fixtures=sorted((source/"tests/recovery-application").rglob("*.java"))
    if len(fixtures)!=10:
        raise RuntimeError("unexpected Application host fixture closure")
    all_sources=actual+[engine_file]+fixtures
    digest=lambda b:hashlib.sha256(b).hexdigest()
    record={
        "scope":"actual Application and exact Engine recovery members; Android/normal IO/Session/diagnostic fixtures",
        "production_engine_sha256":digest(engine.encode()),
        "extracted_parts":{name:{"bytes":len(value.encode()),"sha256":digest(value.encode())}
                           for name,value in parts.items()},
        "production_declaration_sha256":digest(("\n".join(declarations)+"\n").encode()),
        "generated_engine_fixture_sha256":digest(rendered.encode()),
        "java_inputs":[{"path":str(path),"sha256":digest(path.read_bytes())} for path in all_sources],
        "not_android_runtime":True,"not_session_filesystem_durability":True,
    }
    (output/"EXTRACTION.json").write_text(json.dumps(record,indent=2)+"\n",encoding="utf-8")
    return all_sources
