"""Actual permission session/storage and exact ExternalRunLease; Android/process IO are fakes."""
import hashlib
import importlib.util
import json
from pathlib import Path


def section(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise RuntimeError("nonunique production extraction anchor")
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def prepare(source, output):
    source, output = Path(source), Path(output)
    helper = source / "tests/background-session/prepare_fixture.py"
    spec = importlib.util.spec_from_file_location("permission_android_fixture", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    files, _ = module.prepare(source, output)
    package = source / "src/org/trillionnium/hepta/local"
    context = output / "android/content/Context.java"
    text = context.read_text().replace("private final java.io.File files;", "public int installedUid=10123;private final java.io.File files;")
    text = text.replace("a.sourceDir=", "a.uid=installedUid;a.sourceDir=")
    text = text.replace("public Context getApplicationContext()", 'public String getPackageName(){return "org.trillionnium.hepta.local";}public Context getApplicationContext()')
    context.write_text(text)
    (output / "android/os/Process.java").write_text("package android.os;public final class Process {public static int uid=10123;public static int myUid(){return uid;}public static int myPid(){return 123;}}\n")
    os = output / "android/system/Os.java"
    os.write_text(os.read_text().replace('r.st_uid=((Number)a.get("uid")).intValue();', "r.st_uid=10123;"))
    settings = output / "android/provider/Settings.java"
    settings.write_text(settings.read_text().replace("public static int getInt(Object resolver,String key)", "public static int getInt(Object resolver,String key,int fallback){return boot;}public static int getInt(Object resolver,String key)"))
    handler = output / "android/os/Handler.java"
    handler.write_text("package android.os;public final class Handler {public Handler(Looper looper){}public boolean post(Runnable value){value.run();return true;}}\n")
    files.append(handler)
    app = output / "org/trillionnium/hepta/local/LocalProbeApplication.java"
    app.write_text('''package org.trillionnium.hepta.local;
final class LocalProbeApplication {
 static BackgroundPermissionSession permission;
 static boolean permissionPreparationBlocks(android.content.Context ignored){return permission!=null&&permission.blocksOtherWork();}
 static void requirePermissionPreparationIdle(android.content.Context context){if(permissionPreparationBlocks(context))throw new IllegalStateException("preparation owns the process slot");}
}
''')
    engine = (package / "LocalModelEngine.java").read_text()
    pieces = {
        "run_handle": section(engine, "    public static final class RunHandle {", "    /** Retains the existing process-wide slot"),
        "external_lease": section(engine, "    /** Shares the existing single-model slot", "    /** An aggregate startup barrier"),
        "process_admission": section(engine, "    private static void claimProcess(", "    public Result lastResult()"),
        "captured_cancellation": section(engine, "    public void cancelActive() {", "    JSONObject cancellationEvidence()"),
    }
    declarations = []
    for prefix in ("    private static final AtomicReference<RunHandle> PROCESS_ACTIVE", "    private static final TaskCancellationQueue ACTIVE_CANCELLATION", "    private static final Object PROCESS_ADMISSION", "    private final AtomicReference<RunHandle> active", "    private final AtomicBoolean closed", "    private volatile TaskCancellationQueue.Ticket lastCancellation"):
        matches = [line for line in engine.splitlines() if line.startswith(prefix)]
        if len(matches) != 1:
            raise RuntimeError("nonunique declaration: " + prefix)
        declarations.append(matches[0])
    rendered = '''package org.trillionnium.hepta.local;
import java.util.UUID;import java.util.concurrent.atomic.*;
final class LocalModelEngine implements AutoCloseable {
 private final android.content.Context context;
 LocalModelEngine(android.content.Context context){this.context=context;}
''' + "\n".join(declarations) + "\n" + "\n".join(pieces.values()) + '''
 static void fixtureReset(){if(ACTIVE_CANCELLATION.pending())throw new AssertionError("real cancellation worker still active");PROCESS_ACTIVE.set(null);}
 public void close(){closed.set(true);cancelActive();}
}
'''
    generated = output / "org/trillionnium/hepta/local/LocalModelEngine.java"
    generated.write_text(rendered)
    files += [generated, *[package / (name + ".java") for name in ("BackgroundPermissionPreparation", "BackgroundPermissionSession", "MobiMindContract", "MobiMindPins", "OwnedWorkerCancellation")]]
    cancellation = package / "TaskCancellationQueue.java"
    if cancellation not in files:
        files.append(cancellation)
    record = {"schema": "hepta.permission-session-host-extraction.v1", "actual_classes": ["BackgroundPermissionSession", "BackgroundPermissionPreparation", "MobiMindPrivateFiles"],
              "actual_engine_parts": {name: hashlib.sha256(value.encode()).hexdigest() for name, value in pieces.items()},
              "production_engine_sha256": hashlib.sha256(engine.encode()).hexdigest(),
              "production_declaration_sha256": hashlib.sha256(("\n".join(declarations) + "\n").encode()).hexdigest(),
              "task_cancellation_queue_sha256": hashlib.sha256(cancellation.read_bytes()).hexdigest(),
              "cancellation_boundary": "Unchanged process-wide TaskCancellationQueue with exact Engine admission and captured cancellation; host tests await real ticket drain before resetting their process fixture",
              "android_io_fake": True, "process_launch_fake": True, "phone_tested": False, "real_fsync_or_magisk_tested": False}
    (output / "PERMISSION-EXTRACTION.json").write_text(json.dumps(record, indent=2) + "\n")
    return files, record
