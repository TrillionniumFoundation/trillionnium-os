#!/usr/bin/env python3
"""Selected NEG10/14 guards against the complete native v3 source tuple.

Only four image-map refusals and eight filesystem cases are exercised, with one
resource baseline check. No phone, model, installed daemon, capacity exhaustion,
or process-group cleanup qualification is asserted.
"""
import argparse,ast,copy,errno,hashlib,importlib,importlib.util,json,os,signal,sys,tempfile,time,traceback
from pathlib import Path
PINS_SHA="168cbbb9c49e86613622dfe6ce682516847cc856086b3369909e923ae8007d68"
HELPER_SHA="dbbfece5877955b68a98770af41a9010365990b3fdbe29a8c9c37e648ec6756a"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def expect_error(kind,call,error_number=None,message=None):
    try:call()
    except kind as error:
        if error_number is not None:assert error.errno==error_number
        if message is not None:assert message in str(error)
        return{"error_type":type(error).__name__,"errno":getattr(error,"errno",None),"message":str(error)}
    raise AssertionError("expected controlled rejection "+kind.__name__)
def function_bytes(raw,name):
    tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name)
    return b"".join(raw.splitlines(keepends=True)[node.lineno-1:node.end_lineno])
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument("--package-root",type=Path,default=Path(__file__).resolve().parent)
    ap.add_argument("--out",type=Path,required=True);args=ap.parse_args();package=args.package_root.resolve();out=args.out
    assert out.is_absolute()and out.parent.resolve()==out.parent;os.umask(0o077);out.mkdir(mode=0o700);sys.dont_write_bytecode=True
    helper=package/"test_shared_business_admission_v3.py";assert sha(helper.read_bytes())==HELPER_SHA
    spec=importlib.util.spec_from_file_location("v3_guard_fixture_helper",helper);H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)
    pins,initial=H.verify_sources(package);assert sha((package/"CANDIDATE-PINS.json").read_bytes())==PINS_SHA
    H.OUT=out;sys.addaudithook(H.audit);sys.path.insert(0,str(package/"candidate/source"))
    DAILY=importlib.import_module("daily_phone_local");OBS=importlib.import_module("phone_observation_tools")
    imported=[]
    for row in pins["files"]:
        if row["path"].startswith("candidate/source/"):
            module=importlib.import_module(Path(row["path"]).stem);assert Path(module.__file__).resolve()==package/row["path"]
            assert sha(Path(module.__file__).read_bytes())==row["sha256"];imported.append(row)
    assert len(imported)==15
    original=initial["reference/production/daily_phone_local.py"];candidate=initial["candidate/source/daily_phone_local.py"]
    names=("expected_evidence_temporary","evidence_item_size","raise_evidence_scan_error")
    assert all(function_bytes(original,n)==function_bytes(candidate,n)for n in names)
    before=H.resources();start=time.monotonic();rows=[];fatal=None;temp_path=None
    old_signal=signal.getsignal(signal.SIGALRM);assert signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0)
    def expired(_sig,_frame):raise TimeoutError("selected v3 guard regression 25-second deadline")
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,25)
    def case(name,scope,fn):
        details=fn();rows.append({"name":name,"scope":scope,"passed":True,"details":details})
    try:
        temp_path=Path(tempfile.mkdtemp(prefix="owned-v3-guards-",dir=out))
        for kind in ("budget","expired","foreign_image","old_round"):
            def image_guard(kind=kind):
                run=temp_path/("guard-"+kind);run.mkdir(mode=0o700);writes=[]
                tools=OBS.PhoneTools(run,lambda *items:writes.append(items));tools.bind(H.identity());tools.round=3
                if kind=="budget":
                    tools.encoded_bytes_used=OBS.MAX_TURN_IMAGE_BYTES-65535
                    decision={"call_id":"guard_budget","tool":"phone.screenshot","argv":["0"],"command":""}
                    reason="turn screenshot byte budget exhausted"
                else:
                    tools.latest={"call_id":"image-current","attached_round":3,"received_monotonic":time.monotonic()}
                    if kind=="expired":tools.latest["received_monotonic"]-=121
                    elif kind=="old_round":tools.latest["attached_round"]=2
                    image_id="foreign-image"if kind=="foreign_image"else"image-current"
                    decision={"call_id":"guard_"+kind,"tool":"phone.tap","argv":[image_id,"10","10"],"command":""}
                    reason="phone.tap screenshot expired"if kind=="expired"else"current completion"
                before_state={k:copy.deepcopy(v)for k,v in tools.__dict__.items()if k not in{"atomic_record","run_dir"}}
                failure=expect_error(OBS.ProviderError,lambda:tools.map(decision),message=reason)
                after_state={k:copy.deepcopy(v)for k,v in tools.__dict__.items()if k not in{"atomic_record","run_dir"}}
                assert before_state==after_state and writes==[] and list(run.iterdir())==[]
                return dict(failure,state_unchanged=True,zero_mapping_records=True,zero_dispatches=True)
            case("image_"+kind,"NEG10_SELECTED_MAP",image_guard)
        evidence=temp_path/"evidence";evidence.mkdir(mode=0o700)
        run=evidence/("20261106-000000-"+"a"*32);run.mkdir(mode=0o700);size=DAILY.evidence_item_size
        for name in ("local-01.request.json.new","health-outcome.json.new"):
            def rename(name=name):
                temporary=run/name;canonical=temporary.with_name(name[:-4]);raw=b'{"synthetic":"actual os.replace"}\n'
                temporary.write_bytes(raw);assert size(temporary,evidence)==len(raw);os.replace(temporary,canonical)
                assert not temporary.exists()and size(temporary,evidence)is None and size(canonical,evidence)==len(raw)
                return{"actual_os_replace":True,"bytes":len(raw),"known_temporary_absence_tolerated":True}
            case("rename_"+name,"NEG14_SELECTED_FILESYSTEM",rename)
        case("missing_canonical","NEG14_SELECTED_FILESYSTEM",lambda:expect_error(FileNotFoundError,lambda:size(run/"terminal.json",evidence),errno.ENOENT))
        case("unknown_temporary","NEG14_SELECTED_FILESYSTEM",lambda:expect_error(FileNotFoundError,lambda:size(run/"unqualified.tmp",evidence),errno.ENOENT))
        case("known_temporary_missing_parent","NEG14_SELECTED_FILESYSTEM",lambda:expect_error(FileNotFoundError,lambda:size(evidence/("20261106-000000-"+"b"*32)/"local-01.request.json.new",evidence),errno.ENOENT))
        target=run/"target.json";target.write_bytes(b"{}");link=run/"symlink.json";link.symlink_to(target.name)
        case("symlink_rejected","NEG14_SELECTED_FILESYSTEM",lambda:expect_error(RuntimeError,lambda:size(link,evidence)))
        nondirectory=evidence/("20261106-000000-"+"c"*32);nondirectory.write_bytes(b"not a directory")
        case("actual_enotdir","NEG14_SELECTED_FILESYSTEM",lambda:expect_error(NotADirectoryError,lambda:size(nondirectory/"local-01.request.json.new",evidence),errno.ENOTDIR))
        def scanner():
            error=PermissionError(errno.EACCES,"synthetic scanner callback")
            try:DAILY.raise_evidence_scan_error(error)
            except PermissionError as caught:
                assert caught is error
                return{"same_exception_object":True,"synthetic_callback_not_actual_scandir_EACCES":True}
            raise AssertionError("scanner error suppressed")
        case("scanner_eacces_same_exception","NEG14_SELECTED_FILESYSTEM",scanner)
        for directory,subdirs,files in os.walk(temp_path,topdown=False,followlinks=False):
            for name in files:(Path(directory)/name).unlink()
            for name in subdirs:(Path(directory)/name).rmdir()
        temp_path.rmdir()
        after=H.resources()
        restored=before["fds"]==after["fds"]and before["threads"]==after["threads"]and before["child_user_seconds"]==after["child_user_seconds"]and before["child_system_seconds"]==after["child_system_seconds"]
        assert restored and not temp_path.exists()
        rows.append({"name":"fd_thread_child_cpu_and_owned_temp_cleanup","scope":"NEG14_SELECTED_RESOURCE","passed":True,
                     "details":{"resources_restored":True,"owned_temp_removed":True,"rss_return_claimed":False}})
        _,final=H.verify_sources(package);assert final==initial
    except BaseException as error:
        fatal={"type":type(error).__name__,"message":str(error),"traceback":traceback.format_exc()}
    finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,old_signal)
    after=H.resources();passed=fatal is None and len(rows)==13 and not H.DENIED
    result={"schema":"razr60-native-v3-selected-neg10-neg14-host/v1","state":"PASSED_SELECTED_HOST_SCOPE"if passed else"FAILED",
            "pins_sha256":PINS_SHA,"script_sha256":sha(Path(__file__).read_bytes()),"helper_sha256":HELPER_SHA,
            "source_count":15,"source_files":imported,"same_daily_scanner_function_bytes_as_original":list(names),
            "case_count":len(rows),"cases":rows,"resources":{"before":before,"after":after},
            "audit_denied_events":H.DENIED,"fatal_error":fatal,"elapsed_seconds":time.monotonic()-start,
            "whole_NEG10_qualified":False,"whole_NEG14_qualified":False,"adopted":False,
            "phone_calls":0,"native_dispatches":0,"model_requests":0,
            "limits":["Four pre-dispatch image map checks only; no new screenshot or model image ingestion.",
                      "Two real renames and listed filesystem failures; EACCES is a marked synthetic callback.",
                      "No full capacity exhaustion, process-group cleanup or whole-runtime memory-return claim.",
                      "Complete pinned 15-source modules imported; no production monkeypatch or executor qualification bypass."]}
    pin=H.write_new(out/"RESULT.json",result)
    print(json.dumps({"state":result["state"],"case_count":len(rows),"result":pin,"script_sha256":result["script_sha256"],
                      "fatal_error":fatal,"resources_restored":before["fds"]==after["fds"]and before["threads"]==after["threads"],
                      "phone_calls":0,"native_dispatches":0},sort_keys=True))
    return 0 if passed else 1
if __name__=="__main__":sys.exit(main())
