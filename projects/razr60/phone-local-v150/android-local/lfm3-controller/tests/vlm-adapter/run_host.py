#!/usr/bin/env python3
"""Exercise actual VLM adapter/lease lifecycle with explicit host platform fixtures.

The adapter, receipt verifier, private-file checks, cancellation clock and engine
ownership members are production source. Android services, model launch and the
generation-cleanup helper are fixtures. No phone, model or accelerator is run.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time


def section(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError("nonunique production extraction anchor")
    at = text.index(start)
    return text[at:text.index(end, at)]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prepare(source, output):
    package = source / "src/org/trillionnium/hepta/local"
    fixture = output / "fixture"
    fixture.mkdir()
    generated = []

    def write(name, text):
        path = fixture / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        generated.append(path)

    android = source / "tests/qualification-scope/fixtures/android/system"
    for name in ["Os.java", "OsConstants.java", "StructStat.java", "ErrnoException.java"]:
        code = (android / name).read_text()
        if name == "Os.java":
            code = code.replace('public static String failFsyncPath;',
                                'public static String failFsyncPath;public static String foreignOwnerPath;')
            code = code.replace('r.st_uid=((Number)a.get("uid")).intValue();',
                                'r.st_uid=s.equals(foreignOwnerPath)?10482:android.os.Process.myUid();')
        write("android/system/" + name, code)
    write("android/os/Process.java", """package android.os;
public final class Process {
 public static int myUid(){return 10481;}
 public static int myPid(){return Integer.parseInt(java.lang.management.ManagementFactory.getRuntimeMXBean().getName().split("@")[0]);}
 public static boolean isApplicationUid(int uid){return uid>=10000;}
}
""")
    write("android/os/Looper.java", """package android.os;
public final class Looper {private static final Looper MAIN=new Looper();
 public static Looper myLooper(){return MAIN;}public static Looper getMainLooper(){return MAIN;}}
""")
    write("android/app/ActivityManager.java", """package android.app;
public final class ActivityManager {
 public static final class MemoryInfo {public long availMem=8L<<30,totalMem=12L<<30;public boolean lowMemory;}
 public void getMemoryInfo(MemoryInfo out){}
}
""")
    write("android/graphics/Bitmap.java", """package android.graphics;
public final class Bitmap {
 public enum Config {ARGB_8888}
 final java.awt.image.BufferedImage image;public boolean recycled;
 Bitmap(java.awt.image.BufferedImage image){this.image=image;}
 public int getWidth(){return image.getWidth();}public int getHeight(){return image.getHeight();}
 public void getPixels(int[] pixels,int offset,int stride,int x,int y,int width,int height){
  if(recycled)throw new IllegalStateException("recycled fixture bitmap");image.getRGB(x,y,width,height,pixels,offset,stride);}
 public void recycle(){recycled=true;BitmapFactory.recycled++;}
}
""")
    write("android/graphics/BitmapFactory.java", """package android.graphics;
public final class BitmapFactory {
 public static int decoded,recycled;
 public static final class Options {public Bitmap.Config inPreferredConfig;public boolean inScaled,inPremultiplied;}
 public static Bitmap decodeByteArray(byte[] bytes,int start,int length,Options options){
  if(options.inScaled||options.inPremultiplied||options.inPreferredConfig!=Bitmap.Config.ARGB_8888)
   throw new AssertionError("original pixel inspection options differ");
  try{java.awt.image.BufferedImage image=javax.imageio.ImageIO.read(new java.io.ByteArrayInputStream(bytes,start,length));
   if(image==null)return null;decoded++;return new Bitmap(image);}
  catch(java.io.IOException invalid){return null;}}
}
""")
    write("android/content/pm/ApplicationInfo.java", """package android.content.pm;
public final class ApplicationInfo {public String nativeLibraryDir="/host-fixture-not-an-installed-apk";}
""")
    write("android/content/pm/PackageInfo.java", """package android.content.pm;
public final class PackageInfo {public String[] requestedPermissions=new String[0];}
""")
    write("android/content/pm/PackageManager.java", """package android.content.pm;
public final class PackageManager {public static final int GET_PERMISSIONS=4096;public final PackageInfo info=new PackageInfo();
 public PackageInfo getPackageInfo(String name,int flags){return info;}}
""")
    write("android/content/Context.java", """package android.content;
public final class Context {
 public static final String ACTIVITY_SERVICE="activity";
 private final java.io.File files;public final android.content.pm.PackageManager manager=new android.content.pm.PackageManager();
 public String packageName="org.trillionnium.hepta.local";public java.io.File cacheDirectory;
 public Context(java.io.File files){this.files=files;cacheDirectory=new java.io.File(files.getParentFile(),"cache");}
 public Context getApplicationContext(){return this;}public java.io.File getFilesDir(){return files;}
 public java.io.File getCacheDir(){return cacheDirectory;}
 public String getPackageName(){return packageName;}public android.content.pm.PackageManager getPackageManager(){return manager;}
 public android.content.pm.ApplicationInfo getApplicationInfo(){return new android.content.pm.ApplicationInfo();}
 public Object getSystemService(String name){return new android.app.ActivityManager();}
}
""")
    write("org/trillionnium/hepta/local/LocalProbeApplication.java", """package org.trillionnium.hepta.local;
final class LocalProbeApplication {
 static boolean permissionBusy;
 static boolean permissionPreparationBlocks(android.content.Context context){return permissionBusy;}
 static void requirePermissionPreparationIdle(android.content.Context context){
  if(permissionBusy)throw new IllegalStateException("host permission fixture busy");}
}
""")
    # Grammar/policy semantics have separate production gates. This fixture only
    # supplies the immutable public projection consumed by the real adapter.
    write("org/trillionnium/hepta/local/DecisionGrammar.java", """package org.trillionnium.hepta.local;
import java.nio.charset.StandardCharsets;
public final class DecisionGrammar {
 public final String text,sha256,observationId,currentPackage;public final AuthorizationFrame authorization;
 public DecisionGrammar(String task,String owner,String observation,String packageName){
  text="root ::= \\"{}\\"\\n";sha256=MobiMindContract.sha(text.getBytes(StandardCharsets.UTF_8));
  observationId=observation;currentPackage=packageName;authorization=new AuthorizationFrame(task,owner);}
 public static final class AuthorizationFrame {public final String taskId;public final Authorization authorization;
  AuthorizationFrame(String task,String owner){taskId=task;authorization=new Authorization(owner);}}
 public static final class Authorization {public final String instructionSha256;
  Authorization(String owner){instructionSha256=MobiMindContract.sha(owner.getBytes(StandardCharsets.UTF_8));}
  public void requireOwner(String owner){if(!instructionSha256.equals(MobiMindContract.sha(owner.getBytes(StandardCharsets.UTF_8))))
   throw new IllegalArgumentException("host OWNER differs");}}
}
""")
    engine = (package / "LocalModelEngine.java").read_text()
    parts = {
        "run_handle": section(engine, "    public static final class RunHandle {",
                              "    /** Retains the existing process-wide slot"),
        "task_lease": section(engine, "    /** Retains the ordinary task's process slot",
                              "    /** Shares the existing single-model slot"),
        "external_lease": section(engine, "    /** Shares the existing single-model slot",
                                  "    /** An aggregate startup barrier"),
        "admission": section(engine, "    private void claimProcess(",
                             "    public Result lastResult()"),
        "runtime_generation": section(engine, "    static final class RuntimeGeneration {",
                                      "    private volatile RuntimeGeneration runtime;"),
        "captured_stop": section(engine, "    public void cancelActive() {",
                                 "    JSONObject cancellationEvidence()"),
    }
    declarations = []
    for prefix in (
            "    private static final AtomicReference<RunHandle> PROCESS_ACTIVE",
            "    private static final TaskCancellationQueue ACTIVE_CANCELLATION",
            "    private static final Object PROCESS_ADMISSION",
            "    private final AtomicReference<RunHandle> active",
            "    private final AtomicBoolean closed",
            "    private volatile TaskCancellationQueue.Ticket lastCancellation",
            "    private volatile RuntimeGeneration runtime;",
            "    private volatile boolean settingsBlocked;"):
        matches = [line for line in engine.splitlines() if line.startswith(prefix)]
        if len(matches) != 1:
            raise ValueError("nonunique engine field: " + prefix)
        declarations += matches
    write("org/trillionnium/hepta/local/LocalModelEngine.java", """package org.trillionnium.hepta.local;
import android.content.Context;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;
public final class LocalModelEngine implements AutoCloseable {
 private final Context context;private final ExecutorService executor;private final LocalRuntimeConfig config;
 public LocalModelEngine(Context context,LocalRuntimeConfig config,ExecutorService executor){
  this.context=context;this.config=config;this.executor=executor;
  runtime=new RuntimeGeneration(config,null,new ModelFileVerifier(),null);}
 private static final class RuntimeConfigTransaction {static final class Snapshot{}}
 public LocalRuntimeConfig configuration(){return config;}
""" + "\n".join(declarations) + "\n" + "\n".join(parts.values()) + """
 static void fixtureReset(){if(ACTIVE_CANCELLATION.pending())throw new AssertionError("actual cancellation queue still running");
  PROCESS_ACTIVE.set(null);}
 public void fixtureAwaitCancel()throws Exception{
  TaskCancellationQueue.Ticket value=lastCancellation;if(value!=null&&!value.awaitDrain(5000))throw new AssertionError("cancellation did not drain");}
 static void fixtureShutdownCancellation()throws Exception{
  java.lang.reflect.Field field=TaskCancellationQueue.class.getDeclaredField("executor");field.setAccessible(true);
  java.util.concurrent.ExecutorService service=(java.util.concurrent.ExecutorService)field.get(ACTIVE_CANCELLATION);
  service.shutdown();if(!service.awaitTermination(5,TimeUnit.SECONDS))throw new AssertionError("cancellation executor still active");}
 public void close(){closed.set(true);executor.shutdown();}
}
""")
    write("org/trillionnium/hepta/local/OwnedGenerationScope.java",
          (source / "tests/vlm-adapter/GenerationScopeFixture.java.inc").read_text())

    controller = (package / "LocalTaskController.java").read_text()
    start = "                    if(!inference.modelOutputDispatchAllowed()){"
    end = "                    try{\n                        action=ActionDecision.parse("
    gate = section(controller, start, end)
    template = (source / "tests/vlm-adapter/ObservationModeFixture.java.inc").read_text()
    write("org/trillionnium/hepta/local/ObservationModeHostTest.java", template.replace("/* EXACT_OBSERVE_GATE */", gate))
    actual_names = [
        "VlmInferenceAdapter", "VlmResultContract", "VlmPins", "UiVenusPins",
        "LocalInference", "LocalRuntimeConfig", "ModelProfile", "ModelFileVerifier", "MobiMindContract",
        "MobiMindPins", "MobiMindPrivateFiles", "WorkerGenerationProof",
        "OwnedWorkerCancellation", "WarmProcessSession", "TaskCancellationQueue", "MemoryAvailability",
    ]
    actual = [package / (name + ".java") for name in actual_names]
    extraction = {
        "schema": "hepta.vlm-adapter-host-extraction.v1",
        "actual_full_classes": actual_names,
        "engine_source_sha256": sha(engine.encode()),
        "engine_exact_members": {key: sha(value.encode()) for key, value in parts.items()},
        "controller_observe_gate_sha256": sha(gate.encode()),
        "controller_source_sha256": sha(controller.encode()),
        "fixtures": "Android services/UID/fsync surrogate, model launch and generation helper simulated; grammar public projection fixture",
        "settings_boundary": "Exact generation type and actual verifier; snapshot IO and passed immutable config are fixture inputs. No settings transaction or native model is executed.",
        "adapter_code_rewritten": False,
        "native_inference_executed": False,
        "generation_cleanup_kernel_proven": False,
        "generated_files": {str(path.relative_to(output)): sha(path.read_bytes()) for path in generated},
    }
    (output / "EXTRACTION.json").write_text(json.dumps(extraction, indent=2) + "\n")
    return actual + generated + [source / "tests/vlm-adapter/VlmAdapterLifecycleHostTest.java"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--json-jar", required=True, type=Path)
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--java-home", type=Path)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if output.is_relative_to(source):
        raise ValueError("host output must be outside source")
    output.mkdir(parents=True, exist_ok=False)
    if sha(args.json_jar.read_bytes()) != "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed":
        raise ValueError("original org.json dependency pin differs")
    if sha(args.template.read_bytes()) != "3636d0f0bd6bef02654cdffdc447b79cb2cef8ab02cc75267345946291a489e4":
        raise ValueError("original pinned GUI-Owl template differs")
    sources = prepare(source, output)
    # This standalone legacy gate never requests a calendar proof. Keep prepare()
    # byte-identical for the separate actual-calendar consumers which import it.
    grammar_port = output / "fixture/org/trillionnium/hepta/local/DecisionGrammar.java"
    grammar_before = grammar_port.read_text()
    if sha(grammar_before.encode()) != "0bd4df6eb843f301ac2f6c2236b96c746d2e274601040d37a3efb22380c21d15":
        raise ValueError("original legacy VLM grammar port differs")
    marker = "public final class DecisionGrammar {\n"
    fields = (" public final String schema=null;\n"
              " public final java.util.List<String> actions=java.util.Collections.emptyList();\n"
              " public final java.util.List<String> doneStatuses=java.util.Collections.emptyList();\n"
              " public final boolean successAllowed=false;\n")
    if grammar_before.count(marker) != 1:
        raise ValueError("nonunique legacy VLM grammar type")
    grammar_after = grammar_before.replace(marker, marker + fields)
    if grammar_after.replace(marker + fields, marker) != grammar_before:
        raise ValueError("legacy VLM grammar inverse differs")
    grammar_port.write_text(grammar_after)
    intent_source = source / "src/org/trillionnium/hepta/local/NativeCalendarDateIntent.java"
    constants = [line for line in intent_source.read_text().splitlines()
                 if line.startswith("    static final String SCHEMA=")]
    expected = '    static final String SCHEMA="hepta.native-calendar-select-date.v1",ACTION="calendar.select_date";'
    if constants != [expected]:
        raise ValueError("actual calendar intent constants differ")
    intent_port = output / "fixture/org/trillionnium/hepta/local/NativeCalendarDateIntent.java"
    intent_port.write_text("package org.trillionnium.hepta.local;\n"
                          "final class NativeCalendarDateIntent {\n" + constants[0] + "\n"
                          " private NativeCalendarDateIntent(){throw new UnsupportedOperationException(\"calendar intent unavailable in legacy VLM gate\");}\n"
                          "}\n")
    sources.append(intent_port)
    extraction_path = output / "EXTRACTION.json"
    extraction = json.loads(extraction_path.read_text())
    extraction["standalone_calendar_type_boundary"] = {
        "prepared_grammar_sha256": sha(grammar_before.encode()),
        "grammar_inverse_byte_equal": True,
        "calendar_grammar_schema_is_null": True,
        "calendar_action_and_done_lists_are_empty": True,
        "calendar_success_allowed": False,
        "actual_intent_source_sha256": sha(intent_source.read_bytes()),
        "actual_constants_copied_verbatim": True,
        "calendar_intent_constructor_always_throws": True,
        "calendar_receipt_or_dispatch_authority_produced": False,
        "shared_prepare_function_changed": False,
    }
    for path in (grammar_port, intent_port):
        extraction["generated_files"][str(path.relative_to(output))] = sha(path.read_bytes())
    extraction_path.write_text(json.dumps(extraction, indent=2) + "\n")
    before = {str(p): sha(p.read_bytes()) for p in sources}
    input_paths = [Path(__file__).resolve(), args.json_jar.resolve(), args.template.resolve(),
                   source / "src/org/trillionnium/hepta/local/LocalModelEngine.java",
                   source / "src/org/trillionnium/hepta/local/LocalTaskController.java"]
    input_paths += sorted((source / "tests/vlm-adapter").glob("*.java.inc"))
    input_paths += sorted((source / "tests/qualification-scope/fixtures/android/system").glob("*.java"))
    input_paths.append(intent_source)
    before.update({str(path): sha(path.read_bytes()) for path in input_paths})
    classes = output / "classes"
    classes.mkdir()
    javac = str(args.java_home / "bin/javac") if args.java_home else shutil.which("javac")
    java = str(args.java_home / "bin/java") if args.java_home else shutil.which("java")
    cp = str(classes) + ":" + str(args.json_jar.resolve())
    commands = [
        ("compile", [javac, "--release", "8", "-encoding", "UTF-8", "-Xlint:all", "-Werror",
                     "-cp", str(args.json_jar.resolve()), "-d", str(classes)] + [str(p) for p in sources]),
        ("lifecycle", [java, "-cp", cp, "org.trillionnium.hepta.local.VlmAdapterLifecycleHostTest",
                       str(output / "data"), str(args.template.resolve()), str(output / "CASES.json")]),
        ("observe", [java, "-cp", cp, "org.trillionnium.hepta.local.ObservationModeHostTest"]),
    ]
    report = {"schema": "hepta.vlm-adapter-lifecycle-host.v1", "all_pass": False,
              "java_release": 8, "input_sha256": before, "stages": [],
              "phone_operations": 0, "android_runtime": False, "model_inference": False,
              "generation_cleanup_kernel_proven": False}
    for name, argv in commands:
        start = time.monotonic()
        run = subprocess.run(argv, capture_output=True, timeout=90)
        (output / (name + ".stdout")).write_bytes(run.stdout)
        (output / (name + ".stderr")).write_bytes(run.stderr)
        report["stages"].append({"name": name, "argv": argv, "exit_code": run.returncode,
                                  "elapsed_s": time.monotonic() - start})
        if run.returncode:
            break
    report["inputs_unchanged"] = all(sha(Path(path).read_bytes()) == digest for path, digest in before.items())
    report["all_pass"] = len(report["stages"]) == 3 and all(row["exit_code"] == 0 for row in report["stages"]) and report["inputs_unchanged"]
    if (output / "CASES.json").is_file():
        report["cases"] = json.loads((output / "CASES.json").read_text())
    (output / "RESULT.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"all_pass": report["all_pass"], "stages": [(r["name"], r["exit_code"]) for r in report["stages"]]}))
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
