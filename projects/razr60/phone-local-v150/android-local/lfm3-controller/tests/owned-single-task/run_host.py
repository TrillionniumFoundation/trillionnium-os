#!/usr/bin/env python3
"""Compile the coordinator and verbatim broker snapshot; framework IO is a host double."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

INPUTS = (
    "src/org/trillionnium/hepta/background/BackgroundDisplayBroker.java",
    "src/org/trillionnium/hepta/background/BackgroundOwnedTaskPolicy.java",
    "src/org/trillionnium/hepta/background/BackgroundOwnedSingleTask.java",
    "src/org/trillionnium/hepta/background/BackgroundTaskOrganizer.java",
    "tests/owned-single-task/OwnedSingleTaskHostTest.java",
    "tests/owned-single-task/run_host.py",
    "tests/owned-single-task/fixtures/activities-shape.txt",
    "tests/owned-single-task/fixtures/recents-shape.txt",
    "tests/owned-single-task/fixtures/PROVENANCE.json",
    "src/org/trillionnium/hepta/local/BackgroundSession.java",
    "src/org/trillionnium/hepta/local/MobiMindPrivateFiles.java",
)
JSON_BYTES = 78332
JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"


def pin(path):
    path = Path(path)
    stat = path.stat()
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "mode": stat.st_mode & 0o777}


def write(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--json-jar", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.absolute()
    java_home = args.java_home.resolve(strict=True)
    jar = args.json_jar.resolve(strict=True)
    if output.exists():
        raise RuntimeError("fresh output directory required")
    if output == source or source in output.parents:
        raise RuntimeError("output must be outside the source tree")
    output.mkdir(parents=True, exist_ok=False)
    classes = output / "classes"
    classes.mkdir()
    before = {name: pin(source / name) for name in INPUTS}
    tools = [java_home / "bin/javac", java_home / "bin/java", java_home / "lib/modules",
             java_home / "lib/ct.sym", jar]
    tool_before = {str(path): pin(path) for path in tools}
    if tool_before[str(jar)]["bytes"] != JSON_BYTES or tool_before[str(jar)]["sha256"] != JSON_SHA:
        raise RuntimeError("org.json dependency does not match the required pin")
    env = dict(os.environ, JAVA_HOME=str(java_home), LC_ALL="C.UTF-8")
    env["PATH"] = str(java_home / "bin") + os.pathsep + env.get("PATH", "")
    stages = []
    error = None
    cases = None
    session = (source / INPUTS[9]).read_text(encoding="utf-8")
    helper_start = "    private static boolean ownedTaskRetirementRequired(JSONObject journal)throws Exception{"
    helper_end = "    private static JSONObject readJournal(File file)throws Exception{"
    condition_start = "        boolean ownedTaskRetirement=ownedTaskRetirementRequired(old);"
    condition_end = "        JSONObject evidence=new JSONObject().put(\"schema\",\"hepta.background-reconcile.v1\")"
    for marker in (helper_start, helper_end, condition_start, condition_end):
        if session.count(marker) != 1:
            raise RuntimeError("actual reconciliation source boundary changed: " + marker)
    helper = session[session.index(helper_start):session.index(helper_end)]
    condition = session[session.index(condition_start):session.index(condition_end)]
    marker = '.put("owned_task_retirement_required",selection.allowedPackages.contains("com.xiaomi.shop"));}'
    if session.count(marker) != 1:
        raise RuntimeError("durable whole-scope retirement marker missing")
    write_call = 'MobiMindPrivateFiles.writeNew(journal,baseJournal().toString().getBytes(StandardCharsets.UTF_8));'
    spawn_call = 'brokerProcess=new ProcessBuilder("su","-c",command).redirectErrorStream(true).start();'
    if session.count(write_call) != 1 or session.count(spawn_call) != 1 or session.index(write_call) >= session.index(spawn_call):
        raise RuntimeError("durable journal must precede broker spawn")
    projection = output / "OwnedTaskReconcileProjection.java"
    projection.write_text('package org.trillionnium.hepta.background;\nimport java.io.*;import org.json.JSONObject;\n'
        'final class OwnedTaskReconcileProjection {\n'
        ' private final boolean absent; OwnedTaskReconcileProjection(boolean absent){this.absent=absent;}\n'
        ' boolean known(JSONObject old,boolean released,boolean noLateCreate)throws Exception{\n'
        '  Object context=null;int id=7;String name="synthetic-owned-display";\n' + condition
        + '  return known;\n }\n'
        + ' private boolean displayAbsent(Object context,int id,String name){return absent;}\n'
        + helper + '}\n', encoding="utf-8")
    broker = (source / INPUTS[0]).read_text(encoding="utf-8")
    snapshot_start = "    /** Requires the privileged whole-root list,"
    snapshot_end = "    private void startWatchdog()"
    if broker.count(snapshot_start) != 1 or broker.count(snapshot_end) != 1:
        raise RuntimeError("actual broker snapshot source boundary changed")
    snapshot = broker[broker.index(snapshot_start):broker.index(snapshot_end)]
    snapshot_projection = output / "OwnedTaskSnapshotProjection.java"
    snapshot_projection.write_text('''package org.trillionnium.hepta.background;
import java.util.*;import java.lang.reflect.Method;
/** Complete production snapshot and TaskSnapshot methods; Android IO fields alone are doubles. */
public final class OwnedTaskSnapshotProjection {
    final BackgroundOwnedSingleTask ownedSingleTask;final Object activityTasks;final Method allRootTasks;
    OwnedTaskSnapshotProjection(BackgroundOwnedSingleTask owned,RootInfo... roots)throws Exception{
        ownedSingleTask=owned;activityTasks=new TaskService(roots);
        allRootTasks=TaskService.class.getMethod("getAllRootTaskInfos");
    }
    public static final class RootInfo {
        public int taskId,displayId,numActivities;public boolean visible;
        public ComponentName baseActivity,topActivity;
        public int[] childTaskIds;public String[] childTaskNames;
        RootInfo(int root,int display,int[] ids,String[] names,String top,int count,boolean shown){
            taskId=root;displayId=display;childTaskIds=ids;childTaskNames=names;numActivities=count;visible=shown;
            topActivity=ComponentName.unflattenFromString(top);baseActivity=topActivity;
        }
    }
    public static final class TaskService {
        private final List<RootInfo> roots;TaskService(RootInfo[] roots){this.roots=Arrays.asList(roots);}
        public List<RootInfo> getAllRootTaskInfos(){return roots;}
    }
    String top(int display)throws Exception{return snapshot().singleVisibleTop(display);}
    void requireNoOtherDisplay(String pkg,int display)throws Exception{snapshot().requireNoOtherDisplay(pkg,display);}
''' + snapshot + '}\n', encoding="utf-8")
    component_projection = output / "ComponentName.java"
    component_projection.write_text('''package org.trillionnium.hepta.background;
/** Explicit Android ComponentName boundary; no framework execution. */
final class ComponentName {
    final String pkg,cls;ComponentName(String pkg,String cls){this.pkg=pkg;this.cls=cls;}
    String getPackageName(){return pkg;}
    static ComponentName unflattenFromString(String value){if(value==null)return null;int i=value.indexOf('/');return i<=0||i==value.length()-1?null:new ComponentName(value.substring(0,i),value.substring(i+1));}
}
''', encoding="utf-8")
    protocol_projection = output / "BrokerProtocol.java"
    protocol_projection.write_text('''package org.trillionnium.hepta.background;
/** Explicit existing package-name/refusal boundary; no broker socket or Android execution. */
final class BrokerProtocol {
    static final class Refusal extends Exception {private static final long serialVersionUID=1L;final String code;Refusal(String code){super(code);this.code=code;}}
    static boolean packageName(String value){return value!=null&&value.matches("[A-Za-z][A-Za-z0-9_]*(?:\\\\.[A-Za-z][A-Za-z0-9_]*)+");}
}
''', encoding="utf-8")
    extraction = {"schema": "hepta.owned-task-reconciliation-extraction.v1",
                  "source_path": INPUTS[9], "source_sha256": before[INPUTS[9]]["sha256"],
                  "actual_condition": condition, "actual_helper": helper,
                  "condition_sha256": hashlib.sha256(condition.encode()).hexdigest(),
                  "helper_sha256": hashlib.sha256(helper.encode()).hexdigest(),
                  "projection": {"path": projection.name, **pin(projection)},
                  "durable_marker_covers_all_allowed_packages": True,
                  "write_new_call_precedes_process_start": True,
                  "display_absence_is_explicit_host_double": True,
                  "broker_snapshot": {"source_path": INPUTS[0], "source_sha256": before[INPUTS[0]]["sha256"],
                                      "actual_snapshot_and_task_rows": snapshot,
                                      "snapshot_sha256": hashlib.sha256(snapshot.encode()).hexdigest(),
                                      "projection": {"path": str(snapshot_projection), **pin(snapshot_projection)},
                                      "root_task_info_and_component_io_synthetic": True,
                                      "coordinator_fresh_read_predicate_compiled_unmodified": True}}
    write(output / "EXTRACTION.json", extraction)
    commands = [
        ("compile", [str(java_home / "bin/javac"), "--release", "8", "-encoding", "UTF-8",
                     "-Xlint:all", "-Werror", "-cp", str(jar), "-d", str(classes),
                     str(source / INPUTS[1]), str(source / INPUTS[2]), str(source / INPUTS[4]), str(projection),
                     str(snapshot_projection), str(component_projection), str(protocol_projection)]),
        ("owned-single-task-cases", [str(java_home / "bin/java"), "-ea", "-cp",
                                    str(classes) + os.pathsep + str(jar),
                                    "org.trillionnium.hepta.background.OwnedSingleTaskHostTest",
                                    str(source / "tests/owned-single-task/fixtures"), str(output)]),
    ]
    try:
        for name, command in commands:
            stdout, stderr = output / (name + ".stdout"), output / (name + ".stderr")
            started = time.monotonic()
            with stdout.open("xb") as out, stderr.open("xb") as err:
                process = subprocess.run(command, cwd=source, env=env, stdout=out, stderr=err,
                                         timeout=120, check=False)
            stages.append({"name": name, "argv": command, "exit_code": process.returncode,
                           "elapsed_seconds": time.monotonic() - started,
                           "stdout": {"path": str(stdout), **pin(stdout)},
                           "stderr": {"path": str(stderr), **pin(stderr)}})
            if process.returncode:
                raise RuntimeError(name + " failed with exit " + str(process.returncode))
        cases = json.loads((output / "CASES.json").read_text(encoding="utf-8"))
        if cases.get("schema") != "hepta.owned-single-task-host.v1" or cases.get("all_pass") is not True:
            raise RuntimeError("invalid case receipt")
        names = cases.get("case_names")
        if not isinstance(names, list) or len(names) != cases.get("cases") or len(set(names)) != len(names):
            raise RuntimeError("invalid case names")
        if cases.get("framework_io_synthetic") is not True or cases.get("android_capability_verified") is not False:
            raise RuntimeError("host boundary declaration missing")
    except Exception as exc:
        error = type(exc).__name__ + ": " + str(exc)
    after = {name: pin(source / name) for name in INPUTS}
    tool_after = {str(path): pin(path) for path in tools}
    unchanged = before == after
    tools_unchanged = tool_before == tool_after
    passed = error is None and unchanged and tools_unchanged
    inputs_before = [{"path": str(source / name), **value} for name, value in before.items()]
    inputs_before += [{"path": path, **value} for path, value in tool_before.items()]
    inputs_after = [{"path": str(source / name), **value} for name, value in after.items()]
    inputs_after += [{"path": path, **value} for path, value in tool_after.items()]
    result = {"schema": "hepta.owned-single-task-host-gate.v1", "all_pass": passed,
              "source": str(source), "output": str(output), "error": error,
              "inputs_before": inputs_before, "inputs_after": inputs_after, "inputs_unchanged": unchanged and tools_unchanged,
              "tools_before": tool_before, "tools_after": tool_after, "tools_unchanged": tools_unchanged,
              "stages": stages, "cases": cases,
              "case_record": None if cases is None else {"path": str(output / "CASES.json"), **pin(output / "CASES.json")},
              "cases_file": None if cases is None else {"path": str(output / "CASES.json"), **pin(output / "CASES.json")},
              "extraction": {"path": "EXTRACTION.json", **pin(output / "EXTRACTION.json")},
              "actual_production_coordinator_compiled": bool(stages and stages[0]["exit_code"] == 0),
              "actual_broker_snapshot_compiled_verbatim": bool(stages and stages[0]["exit_code"] == 0),
              "android_framework_adapter_compiled_by_this_gate": False,
              "framework_io_synthetic": True, "android_capability_verified": False,
              "phone_operations": 0, "business_result_verified": False}
    write(output / "RESULT.json", result)
    print(json.dumps({"all_pass": passed, "result": str(output / "RESULT.json"),
                      "sha256": pin(output / "RESULT.json")["sha256"]}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
