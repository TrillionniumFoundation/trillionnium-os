#!/usr/bin/env python3
"""Actual method extraction, synthetic Android/Binder/clock ports; no phone IO."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import time

JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
BASE_BROKER_SHA = "1ba8ffb027d7ef8f84985853ab1482bc26bdd52989c3ef17fa07594515ec3fd4"
ACK_METHOD_SHA = "533b218335afd212b136d9ebd3ab5c2812fe747e97df162d682a5fc10a12d805"
RAW_SHA = "41dc7715aa7e7516a56bac7737dbb6c9a4a2ef621bfc5414e00c57c311d14b9f"
BG = "src/org/trillionnium/hepta/background"
PKG = "org.trillionnium.hepta.background."

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def ref(path):
    p = Path(path).resolve(strict=True)
    st = p.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or Path(path).is_symlink():
        raise RuntimeError("regular single-link input required: " + str(p))
    return dict(path=str(p), bytes=st.st_size, sha256=sha(p), mode=stat.S_IMODE(st.st_mode))

def require(value, message):
    if not value:
        raise AssertionError(message)

def write_json(path, value):
    with Path(path).open("x") as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write("\n")

def generate(a, upstream, mode, broker, output, report):
    template = a.template.read_text()
    sources = {"broker": broker, "platform": a.source / BG / "ProfileTaskPlatform.java",
               "organizer": a.source / BG / "BackgroundTaskOrganizer.java", "session": a.session}
    ports = [
        ("ORGANIZER_REMOVE", "organizer", "    void removeOwnedLeaf(Object token,Check finalCheck) throws Exception {"),
        ("ORGANIZER_DELETE", "organizer", "    boolean deleteOwnedContainer(Object token,Check finalCheck) throws Exception {"),
        ("PLATFORM_REMOVE", "platform", "    @Override public void removeLeaf(Object token,ProfileOwnedTask.CleanupEffectCheck check)throws Exception{"),
        ("PLATFORM_DELETE", "platform", "    @Override public boolean deleteRoot(Object token,ProfileOwnedTask.CleanupEffectCheck check)throws Exception{"),
        ("CLOSE_BRANCH", "broker", '            if ("close".equals(r.operation)) {'),
        ("READ_DEADLINE", "broker", "    private long cleanupReadDeadline(){"),
        ("WATCHDOG_DEADLINE", "broker", "    private long cleanupWatchdogDeadline(){"),
        ("PROFILE_DEADLINE", "broker", "    private long profileDeadline(){"),
        ("CLOSE_REPLY_PENDING", "broker", "    private boolean profileCloseReplyPending(long now){"),
        ("CLOSE_REPLY_FLUSH", "broker", "    private boolean releasedProfileReplyMayFlush(long now){"),
        ("BEGIN_CLEANUP", "broker", "    private void beginCleanup(String reason) {"),
        ("BEGIN_PROFILE_CLEANUP", "broker", "    private void beginProfileCleanup(){"),
        ("REFRESH_EVIDENCE", "broker", "    private void refreshProfileTaskEvidence("),
        ("EMPTY_EVIDENCE", "broker", "    private java.util.Map<String,Object> emptyProfileCleanup(boolean known){"),
        ("QUARANTINE", "broker", "    private void quarantineProfile(String reason){"),
        ("FAILURE_AUDIT", "broker", "    static final class ProfileCleanupFailureAudit {"),
        ("RELEASED_STATE", "broker", "    private String releasedState() {"),
        ("HALT_AFTER_BOOT_READ", "broker", "    private void haltAfterBootRead(int exit) {"),
        ("CLOSE_SOCKETS", "broker", "    private void closeSockets() {"),
        ("PRINT_TERMINAL", "broker", "    private void printTerminal() {"),
        ("NOTES_DIAGNOSTIC", "broker", "    static void appendNotesHistoryDiagnostic("),
        ("WATCHDOG_CLEANUP", "broker", "                if (cleanupStarted.get() && now >= cleanupWatchdogDeadline() && !releasedProfileReplyMayFlush(now)) {"),
        ("MAIN_FINALLY", "broker", "            if (broker != null) {"),
    ]
    new_ports = [
        ("CLOSE_RESPONSE_BINDING", "broker", '        if(r!=null&&"close".equals(r.operation)){'),
        ("TERMINAL_RECORD", "broker", "    private JSONObject terminalRecord()throws Exception {"),
        ("FAILURE_SCOPE", "broker", "    private boolean retainedProfileFailureScope(){"),
        ("FAILURE_TERMINAL", "broker", "    private String retainedProfileFailureTerminal()throws Exception{"),
        ("LATE_DIAGNOSTIC", "broker", "    private JSONObject retainedProfileLateDiagnostic(){"),
        ("RETAINED_REPLY", "broker", "    private byte[] retainedCleanupReply(JSONObject original,JSONObject diagnostic)throws Exception{"),
    ]
    if mode == "candidate":
        ports += new_ports
    extraction = []
    def slot(name, block, source, start, kind="complete_production_block"):
        nonlocal template
        marker = "@@" + name + "@@"
        require(template.count(marker) == 1, "unique template slot: " + name)
        template = template.replace(marker, block)
        extraction.append(dict(slot=name, source=ref(source), start_line=source.read_text()[:start].count("\n")+1,
            bytes=len(block.encode()), sha256=hashlib.sha256(block.encode()).hexdigest(), kind=kind,
            source_bytes_unchanged=True))
    for name, source, anchor in ports:
        path = sources[source]
        block, start, _ = upstream.extract(path.read_text(), anchor)
        slot(name, block, path, start)
    broker_text = broker.read_text()
    budget = "    private static final long STARTUP_MS = 8000, SOCKET_MS = 3000, CLEANUP_MS = 1500;"
    require(broker_text.count(budget) == 1, "actual broker budget declaration")
    slot("BUDGET_FIELDS", budget, broker, broker_text.index(budget), "complete_production_budget_declaration")
    for key, anchor in [("DECISION_GATE_FIELD", "    private final Object profileTerminalDecisionGate=new Object();"),
                        ("FROZEN_FIELD", "    private volatile String frozenRetainedProfileTerminal;")]:
        if mode == "candidate":
            require(broker_text.count(anchor) == 1, "unique field")
            slot(key, anchor, broker, broker_text.index(anchor), "complete_production_field")
        else:
            template = template.replace("@@"+key+"@@", anchor)
    retained = '                profileCustody.retainedObservedAbsent(tasks);refreshProfileTaskEvidence();\n                retainedRecheckOutcome="RELEASED_AFTER_ORIGINAL_UNKNOWN";state=releasedState();printTerminal();'
    require(broker_text.count(retained) == 1, "actual retained success commit unique")
    slot("RETAINED_SUCCESS_COMMIT", retained, broker, broker_text.index(retained), "complete_original_success_commit_slice")
    if mode == "baseline":
        for key, _, _ in new_ports:
            template = template.replace("@@"+key+"@@", "")
        template = template.replace("JSONObject lateDiagnostic(){return retainedProfileLateDiagnostic();}",
            'JSONObject lateDiagnostic(){throw new AssertionError("new diagnostic not executed in old-producer control");}')
        template = template.replace("byte[] retainedReply(JSONObject base,JSONObject diagnostic)throws Exception{return retainedCleanupReply(base,diagnostic);}",
            'byte[] retainedReply(JSONObject base,JSONObject diagnostic)throws Exception{throw new AssertionError("new reply not executed in old-producer control");}')
    require("@@" not in template, "unresolved extraction marker")
    output.mkdir()
    expanded = output / "complete-expanded-template.txt"
    expanded.write_text(template)
    header = template[:template.index("final class BackgroundTaskOrganizer {")]
    generated = []
    for name in ("BackgroundTaskOrganizer", "ProfileTaskPlatform", "SystemClock", "ProfileCleanupBrokerHost"):
        anchor = "final class " + name + (" extends ProfileCleanupSettleFixtures.Platform" if name == "ProfileTaskPlatform" else "") + " {"
        block, _, _ = upstream.extract(template, anchor)
        p = output / (name + ".java");p.write_text(header + block + "\n");generated.append(p)
    ack, start, _ = upstream.extract(a.session.read_text(), "        synchronized boolean retainedClosePair(int id,String scope)throws Exception{")
    require(hashlib.sha256(ack.encode()).hexdigest()==ACK_METHOD_SHA, "original exact ACK parser changed")
    ack_source = '''package org.trillionnium.hepta.background;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.json.JSONObject;
final class RetainedPairHost {
    static final int LIMIT=65536;
    File directory;String name,generation;JSONObject captured;
    static boolean accepts(byte[] raw,JSONObject terminal)throws Exception{
        RetainedPairHost f=new RetainedPairHost();
        Path root=java.nio.file.Paths.get(System.getProperty("hepta.fixture.root"));
        f.directory=Files.createTempDirectory(root,"pair-").toFile();f.name="captured";
        f.generation=terminal.getString("generation");
        Files.write(new File(f.directory,f.name+".bin").toPath(),raw);
        f.captured=new JSONObject().put("stored_sha256",ProfileIdentity.sha(raw));
        return f.retainedClosePair(terminal.getInt("display_id"),terminal.getString("display_scope_sha256"));
    }
    static final class MobiMindPrivateFiles {
        static final class Read {final byte[] bytes;Read(byte[] value){bytes=value;}}
        static Read read(File p,int limit,boolean ignored)throws Exception{
            byte[] data=Files.readAllBytes(p.toPath());if(data.length>limit)throw new IllegalArgumentException("fixture limit");return new Read(data);
        }
    }
    static final class HeptaAccessibilityService {static String sha(byte[] bytes){return ProfileIdentity.sha(bytes);}}
''' + ack + "\n}\n"
    ack_path = output / "RetainedPairHost.java";ack_path.write_text(ack_source);generated.append(ack_path)
    extraction.append(dict(slot="ORIGINAL_ACK_PAIR_CONSUMER",source=ref(a.session),start_line=a.session.read_text()[:start].count("\n")+1,
        bytes=len(ack.encode()),sha256=hashlib.sha256(ack.encode()).hexdigest(),source_bytes_unchanged=True,
        kind="complete_production_method_with_explicit_private_file_io_port"))
    report[mode+"_extraction"] = extraction
    report[mode+"_expanded_template"] = ref(expanded)
    report[mode+"_generated_units"] = [ref(p) for p in generated]
    report[mode+"_boundary"] = dict(full_android_broker_compiled=False, framework_binder_clock_and_pipe_ports_synthetic=True,
        baseline_new_method_ports_fail_if_executed=mode=="baseline", original_print_terminal_executed=True,
        original_watchdog_cleanup_branch_executed=True, original_main_finally_block_executed=True)
    return generated

def main():
    p = argparse.ArgumentParser()
    for name in ("source", "java-home", "json-jar", "output"):
        p.add_argument("--"+name, type=Path, required=True)
    for name in ("baseline-broker", "candidate-broker", "session", "template", "test", "upstream-runner", "actual-broker-bin"):
        p.add_argument("--"+name, type=Path)
    a = p.parse_args()
    defaults={
        "baseline_broker":a.source/"tests/profile-failure-snapshot/before-failure-snapshot-broker.inc",
        "candidate_broker":a.source/BG/"BackgroundDisplayBroker.java",
        "session":a.source/"src/org/trillionnium/hepta/local/BackgroundSession.java",
        "template":a.source/"tests/profile-failure-snapshot/ProfileFailureSnapshotBrokerHost.template",
        "test":a.source/"tests/profile-failure-snapshot/ProfileFailureSnapshotHostTest.java",
        "upstream_runner":a.source/"tests/profile-cleanup-settle/run_host.py"}
    for name,value in defaults.items():
        if getattr(a,name) is None:setattr(a,name,value)
    for name, value in vars(a).items():
        if isinstance(value, Path):
            setattr(a, name, value.resolve())
    require(not a.output.exists() and a.source not in a.output.parents, "fresh output outside source")
    require(sha(a.baseline_broker)==BASE_BROKER_SHA, "actual baseline source changed")
    if a.actual_broker_bin is not None:
        require(sha(a.actual_broker_bin)==RAW_SHA and a.actual_broker_bin.stat().st_size==11334, "actual original broker bin changed")
    require(sha(a.json_jar)==JSON_SHA, "JSON dependency changed")
    spec = importlib.util.spec_from_file_location("upstream_settle_source_reader", a.upstream_runner)
    upstream = importlib.util.module_from_spec(spec);spec.loader.exec_module(upstream)
    a.output.mkdir()
    tests = a.source / "tests/profile-cleanup-settle"
    common = tests / "ProfileCleanupSettleFixtures.java"
    old_test = tests / "ProfileCleanupSettleHostTest.java"
    old_broker = a.source / "tests/profile-broker/ProfileBrokerHostTest.java"
    fixture = a.source / "tests/profile-cleanup-sampling/fixtures-synthetic/before-recents.txt"
    pure = [a.source / BG / (n+".java") for n in upstream.NAMES]
    sources = set(pure + [a.source / BG / "ProfileTaskPlatform.java", a.source / BG / "BackgroundTaskOrganizer.java",
        common, old_test, old_broker, fixture, a.baseline_broker, a.candidate_broker, a.session,
        a.template, a.test, a.upstream_runner, Path(__file__).resolve(),
        a.java_home / "bin/java", a.java_home / "bin/javac", a.java_home / "lib/modules", a.json_jar])
    if a.actual_broker_bin is not None:sources.add(a.actual_broker_bin)
    before = [ref(x) for x in sorted(sources)]
    report = dict(schema="hepta.profile-failure-snapshot-targeted.v1", all_pass=False, stages=[],
        source_inputs_before=before, android_runtime=False, phone_operations=0, device_qualified=False,
        original_stage_timeout_seconds=120, original_cleanup_ms=1500, original_normal_read_bound_ms=3000,
        original_close_request_ms=3500, original_effect_freshness_ms=1500, historical_raw_rewritten=False,
        archived_original_supplied=a.actual_broker_bin is not None)
    def run(name, argv, result_key=None):
        began=time.monotonic();stdout=b"";stderr=b"";code=None;error=None
        try:
            result=subprocess.run([str(x) for x in argv],cwd=a.output,capture_output=True,timeout=120)
            code,stdout,stderr=result.returncode,result.stdout,result.stderr
        except subprocess.TimeoutExpired as e:
            stdout=e.stdout or b"";stderr=e.stderr or b"";error="original 120-second stage timeout"
        for suffix,data in (("stdout",stdout),("stderr",stderr)):
            with (a.output/(name+"."+suffix)).open("xb") as f:f.write(data)
        report["stages"].append(dict(name=name,argv=[str(x) for x in argv],exit_code=code,
            elapsed_seconds=time.monotonic()-began,error=error,stdout=ref(a.output/(name+".stdout")),stderr=ref(a.output/(name+".stderr"))))
        print(json.dumps(dict(stage=name,exit_code=code)),flush=True)
        require(code==0,name+" failed: "+stderr.decode("utf-8","replace")[-5000:])
        if result_key:
            value=json.loads(stdout);require(value.get("all_pass") is True,name+" missing positive result")
            report[result_key]=value
    try:
        for mode,broker in (("baseline",a.baseline_broker),("candidate",a.candidate_broker)):
            generated=generate(a,upstream,mode,broker,a.output/(mode+"-generated"),report)
            classes=a.output/(mode+"-classes");classes.mkdir()
            inputs=pure+[old_broker,common,old_test,a.test]+generated
            run(mode+"-compile",[a.java_home/"bin/javac","--release","8","-proc:none","-Xlint:all,-options","-Werror",
                "-encoding","UTF-8","-cp",a.json_jar,"-d",classes,*inputs])
            cp=str(classes)+os.pathsep+str(a.json_jar)
            argv=[a.java_home/"bin/java","-Dhepta.fixture.root="+str(a.output),"-cp",cp,
                PKG+"ProfileFailureSnapshotHostTest",fixture,a.actual_broker_bin if a.actual_broker_bin is not None else ""]
            if mode=="baseline":
                run("old-producer-negative",argv+["baseline-red"],"old_producer_negative")
            else:
                run("unchanged-normal-cleanup-regression",[a.java_home/"bin/java","-cp",cp,
                    PKG+"ProfileCleanupSettleHostTest",fixture],"unchanged_normal_cleanup_regression")
                require(report["unchanged_normal_cleanup_regression"]["case_count"]==35,"old 35 cases changed")
                run("new-producer-snapshot-regression",argv,"new_producer_snapshot_regression")
                require(report["new_producer_snapshot_regression"]["case_count"]==12+(1 if a.actual_broker_bin is not None else 0),
                        "complete new snapshot case contract changed")
        report["all_pass"]=True
    except Exception as error:
        report["error"]=str(error)
    finally:
        report["source_inputs_after"]=[ref(x) for x in sorted(sources)]
        report["source_inputs_unchanged"]=report["source_inputs_before"]==report["source_inputs_after"]
        report["all_pass"]=report["all_pass"] and report["source_inputs_unchanged"]
        write_json(a.output/"RESULT.json",report)
        print(json.dumps(dict(all_pass=report["all_pass"],result=ref(a.output/"RESULT.json"),phone_operations=0)),flush=True)
    return 0 if report["all_pass"] else 1

if __name__=="__main__":
    raise SystemExit(main())
