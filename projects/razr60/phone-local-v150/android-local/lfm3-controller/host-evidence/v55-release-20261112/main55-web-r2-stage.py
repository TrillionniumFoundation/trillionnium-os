#!/usr/bin/env python3
"""Run the existing80/43/13 Web host gates against the unchanged current594 source.
The explicit v4 fixture successors live only in this independent output root.
No SDK, Android build, core101 pass, signing, phone or model call is required here.
"""
import gzip,hashlib,json,os,signal,stat,subprocess,sys,time,traceback
from pathlib import Path,PurePosixPath

CONFIG=json.loads("{\"schema\":\"hepta.main55-existing-web-regression-stage-config.v1\",\"root\":\"/home/alex/hepta-local-007f-20261111/v55-main-web-regression-host-r2\",\"source_root\":\"/home/alex/hepta-local-007f-20261111/v55-main-core101-materialized-host-r3/source\",\"materialized_root\":\"/home/alex/hepta-local-007f-20261111/v55-main-core101-materialized-host-r3\",\"input_path\":\"/home/alex/hepta-local-007f-20261111/v55-main-web-regression-host-r1.input.json.gz\",\"input\":{\"bytes\":41889,\"sha256\":\"ee29ce3d337980234ae584d7fe89a985dea7a111ec74f20ecafa38215d18f94c\"},\"decoded_input\":{\"bytes\":161563,\"sha256\":\"6b2c8f192b00e95feae521e657e2bc9552b1cbf251510ef75818f5884c0cf9e3\",\"git_blob_sha\":\"7c98d42f3ea3babad09e7a47eb5121cec9a1cc7c\"},\"aggregate\":{\"git\":\"d3bf59d91e5681fd5991c4bfef8587ba9a7b2a2d\",\"bytes\":1320157,\"sha256\":\"66ac069a14b64db51d9f2d09bf52acc6a8d9dc93484f8c21e3c3276ac31c2f06\"},\"inventory\":{\"bytes\":103607,\"sha256\":\"65bf7934d82692f45c10aedb947613043453b30bc7d55c4dc8b7e44e4ca0bed1\"},\"java\":{\"path\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/java\",\"bytes\":14544,\"sha256\":\"bb70208200cb6538b877d80478141194a716edb591f4910ec106589291e99196\"},\"javac\":{\"path\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/javac\",\"bytes\":14592,\"sha256\":\"2aaf03d13aeb80b8269696f2dcd9f4937d7366bbc68f91fdc703cf157e8f39c4\"},\"json\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-public-inputs-r1/host-json/json-20240303.jar\",\"bytes\":78332,\"sha256\":\"3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed\"},\"orgjson_ready\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-public-inputs-r1/ORGJSON-READY.json\",\"bytes\":1289,\"sha256\":\"37f3b1790fce237f6339cab159015da7937e6517cc4a97f4dc16443c74e01d7b\"},\"base_mac_stage\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/release-evidence-r1/MAC-STAGE-ORIGINAL.json\",\"bytes\":28841,\"sha256\":\"a037b49f05ea48caccb2902b95bbb2314a5f767e230138dd14ae3a16851ee4b2\"},\"old_regression_root\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/release-evidence-r1/regressions\",\"expected_gates\":[{\"name\":\"evidence80\",\"class_name\":\"org.trillionnium.hepta.local.WebFlightEvidenceHostTest\",\"prior_file\":\"WEB-RESULT.json\",\"cases\":80,\"assertions\":92,\"schema\":\"hepta.web-flight-evidence-host-cases.v1\"},{\"name\":\"composition43\",\"class_name\":\"org.trillionnium.hepta.local.WebTaskCompositionHostTest\",\"prior_file\":\"COMPOSITION-RESULT.json\",\"cases\":43,\"assertions\":59,\"schema\":\"hepta.v55-web-task-composition-host.v1\"},{\"name\":\"calendar13\",\"class_name\":\"org.trillionnium.hepta.local.WebCalendarNativeHostTest\",\"prior_file\":\"CALENDAR-NATIVE-RESULT.json\",\"cases\":13,\"assertions\":1001,\"schema\":\"hepta.csair-calendar-native-host.v1\"}],\"case_name_mapping\":{\"v3_receipt_and_real_composition\":\"v4_receipt_and_real_composition\",\"duplicate_native_resource_id_blocks_even_disabled\":\"duplicate_native_card_description_blocks_even_disabled\",\"duplicate_dom_id_blocks_product_link\":\"ambiguous_observed_region_blocks_product_link\"},\"key\":\"007f-v55-main-existing-web-regression-host-r2-mi-guard\",\"prior_packet\":{\"bytes\":161563,\"sha256\":\"f5cb32866930dbb6ccd70ad93074325d52270325522d79770dae6e13107d0b5d\",\"git_blob_sha\":\"52a2f3612afee45d6f7ead12b238a585e9554e59\"},\"prior_packet_aggregate\":{\"git\":\"012cf1a8457828d9d0d7867bfc8b2951c5d9e3e7\",\"bytes\":1280583,\"sha256\":\"217148644ec56e545bf55c3e38c3b00ede43a4458108a19d96da57ac5f88b0ee\",\"inventory_sha256\":\"de3d08609b656923b80c97316452b2e9da881cc90b20b18de0aa463323caa1dc\"},\"prior_mi_input\":{\"path\":\"src/org/trillionnium/hepta/local/MiPublicProductPage.java\",\"bytes\":17276,\"sha256\":\"cdc85225d7f938d47a8aeb62b6d7d4ccc439b420c698dd86a10841f543771f50\",\"git_blob_sha\":\"31da0b4abaa16116fe504dfe61df9b988f05ec59\",\"mode\":\"100644\"},\"current_mi_input\":{\"path\":\"src/org/trillionnium/hepta/local/MiPublicProductPage.java\",\"bytes\":17440,\"sha256\":\"aaddee9837555083ec1d796b67a2cfc37a280b023b12b2dbd4e474d47586ac8b\",\"git_blob_sha\":\"4d38f27e602302f71ecbf1c4e2e4fcb367fa9fe0\",\"mode\":\"100644\"},\"prior_web\":{\"root\":\"/home/alex/hepta-local-007f-20261111/v55-main-web-regression-host-r1\",\"result\":{\"bytes\":28342,\"sha256\":\"2829b933cb305cf2c940bf7d86e6c98479c257b9ad72a85e8f62be196f3d0187\",\"git_blob_sha\":\"c3538df42438869158be5f4e34c665e77fb7e603\"},\"stage\":{\"bytes\":31909,\"sha256\":\"033cc515c8f02bad19e1b5ddd7de038ba886ab827f9ed7d5ee0cd4a71e67582e\",\"git_blob_sha\":\"d88c3294d34f78a4c7a47023f52b6cb8a0d91214\"},\"composition_stderr\":{\"bytes\":487,\"sha256\":\"09aa7132f588bb627caf24a32f5721e38f69fb0fac9e42e8029941240a170d8f\",\"git_blob_sha\":\"624cc8b8ed8806d8d467d3a2f940dece2a7bd139\"}},\"current_packet_inventory_sha256\":\"5e445cbdd8ef7322e98ed97174b39b42d89cc757369e4ac5bd79d308faaf70c4\"}")

def need(value, why):
    if not value:
        raise RuntimeError(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def blob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode("ascii")+b"\0"+raw).hexdigest()

def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)+"\n").encode("utf-8")

def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def no_constant(value):
        raise ValueError("non-finite JSON")
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_constant=no_constant)

def identity(st):
    return [st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns]

def read_regular(path, expected=None, limit=64<<20):
    path = Path(path)
    need(path.is_absolute(), "absolute input path")
    for parent in path.parents:
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "ordinary input ancestors")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
         "bounded single-link ordinary input")
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        need(identity(os.fstat(fd)) == identity(before), "input replaced before open")
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit+1-size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            need(size <= limit, "input byte limit")
        raw = b"".join(chunks)
        need(identity(os.fstat(fd)) == identity(before), "input changed while open")
    finally:
        os.close(fd)
    need(identity(path.lstat()) == identity(before) and len(raw) == before.st_size, "input changed across read")
    facts = {"path": str(path), "bytes": len(raw), "sha256": sha(raw), "identity": identity(before)}
    if expected is not None:
        need(type(expected["bytes"]) is int and facts["bytes"] == expected["bytes"]
             and facts["sha256"] == expected["sha256"], "exact input bytes/SHA: "+str(path))
    return raw, facts

def unchanged(facts):
    raw, current = read_regular(facts["path"], facts)
    need(current == facts, "input identity changed: "+facts["path"])
    return raw

def checked(raw, pin, message):
    need(type(raw) is bytes and type(pin["bytes"]) is int and len(raw) == pin["bytes"]
         and sha(raw) == pin["sha256"], message)
    if "git_blob_sha" in pin:
        need(blob(raw) == pin["git_blob_sha"], message+" Git blob")
    return raw

def relative(name):
    need(type(name) is str and "\\" not in name and name not in ("", "."), "relative member")
    path = PurePosixPath(name)
    need(not path.is_absolute() and ".." not in path.parts and str(path) == name, "safe member")
    return name

def rows(values):
    return [{"path": name, "bytes": len(raw), "sha256": sha(raw)}
            for name, raw in sorted(values.items(), key=lambda item: Path(item[0]))]

def snapshot(root):
    need(root.is_dir() and not root.is_symlink(), "existing ordinary source root")
    values, facts = {}, {}
    for path in sorted(root.rglob("*")):
        need(not path.is_symlink(), "no source symlink")
        if path.is_dir():
            continue
        name = relative(path.relative_to(root).as_posix())
        values[name], facts[name] = read_regular(path, limit=4<<20)
    return values, facts

def validate_map(values, expected, with_git):
    need(len(expected) == len(values) and len({r["path"] for r in expected}) == len(expected),
         "exact source map membership")
    need(set(values) == {relative(r["path"]) for r in expected}, "source map path set")
    for item in expected:
        raw = values[item["path"]]
        checked(raw, item, "source map member "+item["path"])
        if with_git:
            need(blob(raw) == item["git_blob_sha"], "source map Git identity")

def write_new(path, raw, mode=0o600):
    need(ROOT in path.parents and type(raw) is bytes, "owned new output")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for parent in path.parents:
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "ordinary output ancestors")
    fd = os.open(str(path), os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        raise
    os.chmod(path, mode)
    actual, facts = read_regular(path, {"bytes": len(raw), "sha256": sha(raw)})
    need(actual == raw, "new output readback")
    return facts

def load_bound(path, pin, original_facts):
    raw, facts = read_regular(path, pin)
    original_facts.append(facts)
    return raw


def run_step(name, argv, timeout, cwd, env):
    begin = time.monotonic()
    process, code, timed_out, forced = None, None, False, False
    group_cleanup_attempted, group_absent_observed, group_cleanup_error = False, None, None
    stdout_path, stderr_path = ROOT/(name+".stdout"), ROOT/(name+".stderr")
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        process = subprocess.Popen([str(x) for x in argv], cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                code = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                forced = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                code = process.wait(timeout=5)
        finally:
            # A failed leader may already have exited while its compiler
            # descendants still belong to the new process group. Clean that
            # owned group on every failure, not just a still-running leader.
            if code != 0 or timed_out or process.poll() is None:
                group_cleanup_attempted = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                except OSError as cleanup_error:
                    group_cleanup_error = str(cleanup_error)
                if process.poll() is None:
                    try:
                        code = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                # The group may still exist after its leader is reaped.
                # This failure-only signal never targets another job/root.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    forced = True
                except ProcessLookupError:
                    pass
                except OSError as cleanup_error:
                    group_cleanup_error = str(cleanup_error)
                if process.poll() is None:
                    try:
                        code = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        group_cleanup_error = "owned leader exit not observed after bounded cleanup"
                try:
                    os.killpg(process.pid, 0)
                    group_absent_observed = False
                except ProcessLookupError:
                    group_absent_observed = True
                except OSError as cleanup_error:
                    group_absent_observed = None
                    group_cleanup_error = str(cleanup_error)
    _, stdout_facts = read_regular(stdout_path)
    _, stderr_facts = read_regular(stderr_path)
    step = {"name": name, "argv": [str(x) for x in argv], "cwd": str(cwd), "pid": process.pid,
            "exit_code": code, "timed_out": timed_out, "forced_kill": forced, "exit_observed": process.poll() is not None,
            "elapsed_seconds": time.monotonic()-begin, "stdout": stdout_facts, "stderr": stderr_facts,
            "owned_group_cleanup_attempted": group_cleanup_attempted,
            "owned_group_absent_observed_after_failure": group_absent_observed,
            "owned_group_cleanup_error": group_cleanup_error}
    steps.append(step)
    need(type(code) is int and code == 0 and not timed_out and not forced and process.poll() is not None,
         "each original Web regression process must exit normally")


def source_rows(values):
    return [{"path":name,"bytes":len(raw),"sha256":sha(raw)}
            for name,raw in sorted(values.items(),key=lambda item:Path(item[0]))]

def read_bound(path,pin):
    raw,facts=read_regular(path,pin)
    originals.append(facts)
    return raw,facts

def exact_changes(base,changes,successor):
    value=base.decode("utf-8","strict")
    for change in changes:
        need(type(change["count"]) is int and change["count"]>0
             and value.count(change["before"])==change["count"],"exact fixture predecessor occurrence")
        value=value.replace(change["before"],change["after"])
    need(value.encode("utf-8")==successor,"exact forward fixture reconstruction")
    for change in reversed(changes):
        need(value.count(change["after"])==change["count"],"exact fixture reverse occurrence")
        value=value.replace(change["after"],change["before"])
    need(value.encode("utf-8")==base,"byte-identical original fixture reverse proof")

def validate_report(report,spec,old_names):
    need(type(report) is dict and report["schema"]==spec["schema"] and report["all_pass"] is True
         and type(report["cases"]) is int and report["cases"]==spec["cases"]
         and type(report["assertions"]) is int and report["assertions"]==spec["assertions"],
         "all unchanged-count existing Web cases must actually pass")
    names=report["case_names"]
    need(type(names) is list and len(names)==spec["cases"]
         and len(set(names))==spec["cases"] and all(type(n) is str for n in names),
         "unique complete actual Web case names")
    expected=old_names
    if spec["name"]=="composition43":
        expected=[CONFIG["case_name_mapping"].get(name,name) for name in old_names]
        need(report["prior_case_count"]==43 and report["legacy_dom_id_bridge_assertions_replaced"]==2
             and report["full_native_action_service_or_binder_executed"] is False
             and report["synthetic_profile_assignment_not_actual_webview"] is True
             and report["actual_mi_dom_seen"] is False and report["actual_model_run_executed"] is False
             and report["binder_authenticated"] is False
             and type(report["phone_commands_executed"]) is int and report["phone_commands_executed"]==0
             and report["actual_shopping_or_flight_result_verified"] is False
             and report["final_native_and_cleanup_gates_verified"] is False,
             "explicit synthetic composition successor scope")
    elif spec["name"]=="evidence80":
        need(report["production_pure_classes_executed"] is True
             and report["android_rect_and_ax_fixture"] is True
             and report["binder_transport_authenticated"] is False
             and report["native_geometry_is_synthetic"] is True
             and type(report["phone_commands_executed"]) is int and report["phone_commands_executed"]==0
             and report["query_executed"] is False,"original pure receipt scope")
    elif spec["name"]=="calendar13":
        need(report["actual_fixture_dom_nodes"]==987
             and report["lease_and_native_ref_signatures_synthetic"] is True
             and report["original_dom_values_preserved"] is True
             and report["source_dom_schema"]=="hepta.fixed-top-document-dom.v2"
             and report["unit_envelope_schema"]=="hepta.fixed-top-document-dom.v4"
             and type(report["phone_actions"]) is int and report["phone_actions"]==0
             and report["binder_authenticated"] is False,"real calendar original within a synthetic v4 envelope")
    else:
        raise RuntimeError("unknown fixed regression")
    need(names==expected,"original case order with only the declared three composition names mapped")
    need(report["business_verified"] is False,"host cases cannot assert real business completion")

stage_raw=globals().get("__stage_source__")
need(type(stage_raw) is bytes and len(stage_raw)>0,"exact loader-verified source bytes")
ROOT=Path(CONFIG["root"])
SOURCE=Path(CONFIG["source_root"])
MATERIALIZED=Path(CONFIG["materialized_root"])
need(sys.platform=="linux" and ROOT.is_absolute() and SOURCE==MATERIALIZED/"source"
     and not ROOT.exists() and not ROOT.is_symlink()
     and ROOT not in MATERIALIZED.parents and MATERIALIZED not in ROOT.parents,
     "independent new Pocket4 output root")
originals=[]
# Preserve the actually failed prior output and derive only two metadata fields
# from its already published input. No old fixture/assertion byte is rewritten.
PRIOR=Path(CONFIG["prior_web"]["root"])
need(PRIOR.is_absolute() and ROOT!=PRIOR and ROOT not in PRIOR.parents
     and PRIOR not in ROOT.parents,"independent prior failed Web output")
prior_output,prior_output_facts=snapshot(PRIOR)
originals.extend(prior_output_facts.values())
prior_failure_raw=checked(prior_output["RESULT.json"],CONFIG["prior_web"]["result"],
                          "actual failed Web result")
prior_failure=strict(prior_failure_raw)
checked(prior_output["stage.py"],CONFIG["prior_web"]["stage"],"actual prior coordinator")
need(prior_failure["schema"]=="hepta.main55-existing-web-regressions-host-stage.v1"
     and prior_failure["all_pass"] is False and prior_failure["exit_code"]==1
     and prior_failure["root"]==str(PRIOR)
     and prior_failure["stage_sha256"]==CONFIG["prior_web"]["stage"]["sha256"]
     and prior_failure["originals_unchanged"] is True
     and prior_failure["written_files_unchanged"] is True
     and prior_failure["source_unchanged"] is True
     and prior_failure["error"]=="RuntimeError: each original Web regression process must exit normally",
     "preserve actual failed composition gate and its original scope")
need([x["name"] for x in prior_failure["steps"]]==["compile","evidence80","composition43"]
     and [x["exit_code"] for x in prior_failure["steps"]]==[0,0,1],
     "prior compile and80 passed; composition process failed; calendar not run")
for step in prior_failure["steps"]:
    for stream in ("stdout","stderr"):
        name=step["name"]+"."+stream
        need(step[stream]["path"]==str(PRIOR/name),"prior stream is the exact owned file")
        checked(prior_output[name],step[stream],"prior actual stream")
prior_stderr=checked(prior_output["composition43.stderr"],CONFIG["prior_web"]["composition_stderr"],
                     "actual transaction-label assertion failure")
need(b"AssertionError: no purchase path" in prior_stderr,"specific retained transaction failure")
need(list(prior_failure["reports"])==["evidence80"],"only prior actually completed report")
prior80=prior_failure["reports"]["evidence80"]
prior80_raw=checked(prior_output["evidence80-RESULT.json"],prior80["original"],"prior80 original")
need(strict(prior80_raw)==prior80["report"] and prior80["report"]["all_pass"] is True
     and prior80["report"]["cases"]==80 and prior80["report"]["assertions"]==92,
     "retain the real prior80 positive report without promoting the failed run")
packed,_=read_bound(CONFIG["input_path"],CONFIG["input"])
prior_packet_raw=gzip.decompress(packed)
checked(prior_packet_raw,CONFIG["prior_packet"],"exact original already published fixture input")
need(prior_output["FIXTURE-PACKET.json"]==prior_packet_raw,"actual prior input unchanged")
packet=strict(prior_packet_raw)
need(packet["current_aggregate"]==CONFIG["prior_packet_aggregate"],"exact prior candidate metadata")
mi_indices=[i for i,item in enumerate(packet["production_inputs"])
            if item["path"]==CONFIG["prior_mi_input"]["path"]]
need(len(mi_indices)==1 and packet["production_inputs"][mi_indices[0]]==CONFIG["prior_mi_input"],
     "one exact old compiled Mi source record")
packet["current_aggregate"]=dict(CONFIG["aggregate"],
    inventory_sha256=CONFIG["current_packet_inventory_sha256"])
packet["production_inputs"][mi_indices[0]]=CONFIG["current_mi_input"]
packet_raw=encoded(packet)
checked(packet_raw,CONFIG["decoded_input"],"only aggregate metadata and actual Mi record changed")
reverse=strict(packet_raw)
reverse["current_aggregate"]=CONFIG["prior_packet_aggregate"]
reverse["production_inputs"][mi_indices[0]]=CONFIG["prior_mi_input"]
need(encoded(reverse)==prior_packet_raw,"complete packet reverse; all five fixtures and assertions identical")
need(packet["schema"]=="hepta.main55-web-regression-v4-fixture-successor.v1"
     and packet["status"]=="source_only_not_executed","reviewed fixture successor packet")
aggregate_raw,_=read_bound(MATERIALIZED/"AGGREGATE.json",CONFIG["aggregate"])
need(blob(aggregate_raw)==CONFIG["aggregate"]["git"],"complete current594 aggregate Git identity")
aggregate=strict(aggregate_raw)
inventory_raw,_=read_bound(MATERIALIZED/"SOURCE-INVENTORY.json",CONFIG["inventory"])
before,before_facts=snapshot(SOURCE)
need(len(before)==594 and len(aggregate["inventory"]["files"])==594,"complete current source tree")
validate_map(before,aggregate["inventory"]["files"],True)
need(inventory_raw==encoded(source_rows(before)),"complete current594 runtime source inventory")
need(packet["current_aggregate"]["git"]==CONFIG["aggregate"]["git"]
     and packet["current_aggregate"]["bytes"]==CONFIG["aggregate"]["bytes"]
     and packet["current_aggregate"]["sha256"]==CONFIG["aggregate"]["sha256"]
     and packet["current_aggregate"]["inventory_sha256"]==aggregate["inventory"]["sha256"],
     "fixture packet bound to the same full Git-bearing candidate map")
originals.extend(before_facts.values())
for flag in ("evidence80_original_main_byte_identical","calendar13_asserted_body_byte_identical",
             "composition43_explicit_fixture_successor","original_three_java_sources_not_overwritten",
             "gate_counts_are_separate_not_a_sum_with_core101"):
    need(packet["scope"][flag] is True,"explicit fixture migration scope")
for flag in ("compiled","host_executed","production_sources_modified","actual_Mi_detail_seen",
             "actual_popup_or_profile_callback","actual_business_verified"):
    need(packet["scope"][flag] is False,"no prior fixture execution or business claim")
need(type(packet["scope"]["phone_commands"]) is int and packet["scope"]["phone_commands"]==0,
     "source-only packet")
expected_fixture_names=[
    "tests/web-flight/WebFlightEvidenceHostTest.java",
    "tests/web-flight/WebTaskCompositionHostTest.java",
    "tests/web-flight/WebCalendarNativeHostTest.java",
    "tests/web-flight/WebV4RegressionFixtures.java",
    "tests/web-flight/WebWire4SyntheticFactory.java"]
need([item["path"] for item in packet["files"]]==expected_fixture_names,"fixed exact five fixture members")
fixture_bytes={}
for index,item in enumerate(packet["files"]):
    name=relative(item["path"])
    raw=checked(item["raw_utf8"].encode("utf-8","strict"),item,"exact fixture successor member")
    need(blob(raw)==item["git_blob_sha"],"fixture successor Git identity")
    if index<3:
        need(name in before,"unchanged current original Java fixture")
        checked(before[name],item["base"],"original Java predecessor")
        need(blob(before[name])==item["base"]["git_blob_sha"],"original Java Git identity")
        exact_changes(before[name],item["ordered_replacements"],raw)
    else:
        need(name not in before,"new fixtures do not shadow any current source file")
    fixture_bytes[name]=raw
need([len(item["ordered_replacements"]) for item in packet["files"][:3]]==[3,24,3],
     "only reviewed exact migration hunks")
need(packet["files"][0]["proof"]["main_byte_identical"] is True
     and packet["files"][2]["proof"]["main_asserted_body_byte_identical"] is True
     and packet["files"][1]["proof"]["assertion_blocks_not_claimed_wholly_byte_identical"] is True,
     "accurate original assertion boundaries")
production=packet["production_inputs"]
extra=packet["unchanged_extra_inputs"]
need(type(production) is list and len(production)==43
     and len({item["path"] for item in production})==43
     and all(item["path"].startswith("src/") and item["path"].endswith(".java") for item in production),
     "fixed43 actual production compilation units")
need([item["path"] for item in extra]==[
    "tests/qualification-scope/fixtures/android/graphics/Rect.java",
    "tests/web-flight/WebUnstartedRetirementHostTest.java"],"two unchanged auxiliary compilation units")
for item in production+extra:
    name=relative(item["path"])
    need(name in before,"actual compilation input exists")
    checked(before[name],item,"actual complete compilation unit")
    need(blob(before[name])==item["git_blob_sha"],"actual compilation unit Git identity")
need(extra[1]["only_initial_and_confirmation_factories_called_here"] is True
     and extra[1]["old_36_main_run_here"] is False,"old36 not represented as rerun")
java_names=[item["path"] for item in production+extra]+expected_fixture_names
need(len(java_names)==50 and len(set(java_names))==50,"complete unique50 Java closure")
calendar_specs=packet["actual_calendar_fixtures"]
need([Path(item["path"]).name for item in calendar_specs]==[
    "calendar-pending.json","calendar-stable.json","calendar-stable.xml"],
    "actual pending/stable calendar and native AX")
calendar_facts=[]
for item in calendar_specs:
    _,facts=read_bound(item["path"],item);calendar_facts.append(facts)
mac_raw,_=read_bound(CONFIG["base_mac_stage"]["path"],CONFIG["base_mac_stage"])
mac=strict(mac_raw)
old_rows=mac["host_gate_results"]
need(type(old_rows) is list and len(old_rows)==4
     and len({item["path"] for item in old_rows})==4,"actual54 query plus three Web regression originals")
old_reports={}
for spec in CONFIG["expected_gates"]:
    matches=[item for item in old_rows if Path(item["path"]).name==spec["prior_file"]]
    need(len(matches)==1,"one exact original report for each existing gate")
    raw,facts=read_bound(Path(CONFIG["old_regression_root"])/spec["prior_file"],matches[0])
    report=strict(raw)
    need(report["all_pass"] is True and type(report["cases"]) is int and report["cases"]==spec["cases"]
         and type(report["assertions"]) is int and report["assertions"]==spec["assertions"]
         and type(report["case_names"]) is list and len(report["case_names"])==spec["cases"]
         and len(set(report["case_names"]))==spec["cases"],"actual old gate names/counts/assertions")
    old_reports[spec["name"]]={"raw":raw,"facts":facts,"report":report}
need(set(CONFIG["case_name_mapping"]).issubset(set(old_reports["composition43"]["report"]["case_names"])),
     "all explicit composition case migrations map real old cases")
tools={}
for name in ("java","javac","json"):
    _,facts=read_bound(CONFIG[name]["path"],CONFIG[name])
    tools[name]=facts
for name in ("java","javac"):
    need(os.access(tools[name]["path"],os.X_OK),"actual executable JDK")
ready_raw,_=read_bound(CONFIG["orgjson_ready"]["path"],CONFIG["orgjson_ready"])
ready=strict(ready_raw)
# The exact actual READY bytes are pinned; the JAR itself is independently read/hash checked.
need(type(ready) is dict,"actual JSON dependency READY object")
python_path=Path(sys.executable).resolve(strict=True)
_,python_facts=read_regular(python_path)
originals.append(python_facts);tools["python"]=python_facts
env=dict(os.environ)
for name in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH","SOURCE_HEAD_SHA"):
    env.pop(name,None)
env["PYTHONDONTWRITEBYTECODE"]="1"
started=time.time()
ROOT.mkdir(mode=0o700)  # FIRST MUTATION; outside the handler, never share a previous result root.
steps,written=[],[]
reports={}
result={"schema":"hepta.main55-existing-web-regressions-host-stage.v1",
        "all_pass":False,"exit_code":1,"root":str(ROOT),"source_root":str(SOURCE),
        "source_candidate_git":CONFIG["aggregate"]["git"],"source_file_count":594,
        "source_inventory_sha256":CONFIG["inventory"]["sha256"],
        "candidate_git_bearing_inventory_sha256":aggregate["inventory"]["sha256"],
        "fixture_packet":CONFIG["decoded_input"],"fixture_count":5,
        "production_java_count":43,"compilation_unit_count":50,"steps":steps,"reports":reports,
        "prior_reports":{name:value["facts"] for name,value in old_reports.items()},
        "actual_calendar_originals":calendar_facts,"tools":tools,
        "core101_pass_prerequisite_required":False,"android_build_prerequisite_required":False,
        "evidence80_original_main_byte_identical":True,"calendar13_asserted_body_byte_identical":True,
        "composition43_explicit_fixture_successor":True,"composition_case_name_mapping":CONFIG["case_name_mapping"],
        "old_unstarted36_main_executed_here":False,"focused39_rerun":False,"identity10_rerun":False,
        "query40_rerun":False,"core101_rerun":False,
        "android_compiled":False,"binder_transport_executed":False,"native_accessibility_executed":False,
        "external_model_used":False,"phone_actions":0,"business_verified":False,
        "actual_Mi_detail_or_popup_verified":False,"signed":False,"published":False,
        "started_epoch":started,"originals_unchanged":False,"error":None,
        "prior_failed_web_result":dict(CONFIG["prior_web"]["result"],path=str(PRIOR/"RESULT.json")),
        "prior_failed_output_count":len(prior_output),
        "prior_failed_output_inventory_sha256":sha(encoded(source_rows(prior_output))),
        "prior_failed_output_preserved":False,
        "fixture_packet_derived_from_existing_input":True,
        "old_compressed_input":CONFIG["input"],
        "old_fixture_packet":CONFIG["prior_packet"],
        "fixture_assertions_changed_here":False,
        "changed_production_input_paths":[CONFIG["current_mi_input"]["path"]]}
class_before=None
classes=ROOT/"classes"
try:
    written.append(write_new(ROOT/"stage.py",stage_raw))
    written.append(write_new(ROOT/"CONFIG.json",encoded(CONFIG)))
    written.append(write_new(ROOT/"FIXTURE-PACKET.json",packet_raw))
    written.append(write_new(ROOT/"SOURCE-INVENTORY.json",inventory_raw))
    written.append(write_new(ROOT/"prior-failure/RESULT.json",prior_failure_raw))
    written.append(write_new(ROOT/"prior-failure/composition43.stderr",prior_stderr))
    written.append(write_new(ROOT/"PRIOR-OUTPUT-INVENTORY.json",encoded(source_rows(prior_output))))
    written.append(write_new(ROOT/"COMPILATION-INPUTS.json",encoded([
        {"role":"actual_production" if item in production else "unchanged_fixture",**item}
        for item in production+extra]+[
        {"role":"explicit_fixture_successor","path":item["path"],"bytes":item["bytes"],
         "sha256":item["sha256"],"git_blob_sha":item["git_blob_sha"]} for item in packet["files"]])))
    for name,raw in fixture_bytes.items():
        written.append(write_new(ROOT/"fixtures"/name,raw))
    for name,value in old_reports.items():
        written.append(write_new(ROOT/"prior"/(name+".json"),value["raw"]))
    classes.mkdir(mode=0o700)
    (ROOT/"tmp").mkdir(mode=0o700);env["TMPDIR"]=str(ROOT/"tmp")
    sources=[SOURCE/item["path"] for item in production+extra]+[
        ROOT/"fixtures"/name for name in expected_fixture_names]
    compile_argv=[tools["javac"]["path"],"--release","8","-encoding","UTF-8",
                  "-Xlint:all","-Werror","-cp",tools["json"]["path"],"-d",classes]+sources
    written.append(write_new(ROOT/"START-ARGS.json",encoded({
        "key":CONFIG["key"],"compile_argv":[str(x) for x in compile_argv],
        "test_classes":[item["class_name"] for item in CONFIG["expected_gates"]],
        "synthetic_fixture_scope":packet["scope"],"source_modified":False,"phone_actions":0})))
    run_step("compile",compile_argv,120,ROOT,env)
    class_bytes,class_facts=snapshot(classes)
    need(len(class_bytes)>0 and all(name.endswith(".class") for name in class_bytes),
         "actual nonempty compiled Java class set")
    class_before=(class_bytes,class_facts)
    result["compiled_class_count"]=len(class_bytes)
    written.append(write_new(ROOT/"COMPILED-CLASSES.json",encoded(source_rows(class_bytes))))
    cp=str(classes)+os.pathsep+tools["json"]["path"]
    for spec in CONFIG["expected_gates"]:
        out=ROOT/(spec["name"]+"-RESULT.json")
        args=[tools["java"]["path"],"-cp",cp,spec["class_name"]]
        if spec["name"]=="calendar13":
            args.extend([item["path"] for item in calendar_specs])
        args.append(out)
        run_step(spec["name"],args,120,ROOT,env)
        raw,facts=read_regular(out);report=strict(raw)
        written.append(facts)
        validate_report(report,spec,old_reports[spec["name"]]["report"]["case_names"])
        reports[spec["name"]]={"original":facts,"report":report}
    need(len(steps)==4 and len(reports)==3,"compile and all three original gates completed")
    result["all_pass"]=True;result["exit_code"]=0
except BaseException as failure:
    result["all_pass"]=False;result["exit_code"]=1
    result["error"]=type(failure).__name__+": "+str(failure)
    try:write_new(ROOT/"ERROR.txt",traceback.format_exc().encode("utf-8"))
    except BaseException as logging_failure:
        result["error_record_failure"]=type(logging_failure).__name__+": "+str(logging_failure)
finally:
    # Retain any real partial output after a failed process; never synthesize a pass.
    partial={}
    for spec in CONFIG["expected_gates"]:
        path=ROOT/(spec["name"]+"-RESULT.json")
        try:
            if path.exists():
                raw,facts=read_regular(path)
                partial[spec["name"]]={"original":facts,"report":strict(raw)}
        except BaseException as partial_failure:
            result["all_pass"]=False;result["exit_code"]=1
            partial[spec["name"]]={"read_error":type(partial_failure).__name__+": "+str(partial_failure)}
    result["actual_report_files"]=partial
    try:
        for facts in originals:unchanged(facts)
        for facts in written:unchanged(facts)
        for step in steps:
            unchanged(step["stdout"]);unchanged(step["stderr"])
        after,after_facts=snapshot(SOURCE)
        need(after==before and after_facts==before_facts,"whole594 source bytes and identities unchanged")
        need(snapshot(PRIOR)==(prior_output,prior_output_facts),
             "all prior failed Web output bytes and identities unchanged")
        result["prior_failed_output_preserved"]=True
        if class_before is not None:
            class_after=snapshot(classes)
            need(class_after==class_before,"compiled class bytes and identities unchanged across all gates")
        result["originals_unchanged"]=True
        result["written_files_unchanged"]=True
        result["source_unchanged"]=True
    except BaseException as integrity_failure:
        result["all_pass"]=False;result["exit_code"]=1
        result["integrity_error"]=type(integrity_failure).__name__+": "+str(integrity_failure)
    result["finished_epoch"]=time.time()
    result["elapsed_seconds"]=result["finished_epoch"]-started
    result["stage_sha256"]=sha(stage_raw)
    result["original_guard_count"]=len(originals)
    result["written_guard_count"]=len(written)
    result["all_pass"]=bool(result["all_pass"] and result["originals_unchanged"])
    result["exit_code"]=0 if result["all_pass"] else 1
    result_facts=write_new(ROOT/"RESULT.json",encoded(result))
    summary={"schema":"hepta.main55-existing-web-regressions-host-summary.v1",
        "all_pass":result["all_pass"],"exit_code":result["exit_code"],"result":result_facts,
        "error":result.get("error"),"source_file_count":594,
        "source_inventory_sha256":CONFIG["inventory"]["sha256"],
        "reports":{name:{"cases":value["report"]["cases"],"assertions":value["report"]["assertions"],
                         "all_pass":value["report"]["all_pass"]} for name,value in reports.items()},
        "android_compiled":False,"phone_actions":0,"business_verified":False,
        "core101_rerun":False,"query40_rerun":False,"focused39_rerun":False}
    write_new(ROOT/"SUMMARY.json",encoded(summary))
    print(json.dumps(summary,sort_keys=True,ensure_ascii=False,allow_nan=False),flush=True)
raise SystemExit(result["exit_code"])
