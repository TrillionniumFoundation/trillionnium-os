#!/usr/bin/env python3
"""Host-only plan by default; one actual 7200-second supervisor when explicitly executed.
The pinned offline wrapper owns network restoration. This supervisor sends TERM
to that owned host wrapper at 6900 seconds and KILL only to it at 7200 seconds.
Neither host process exit nor timeout proves Android task cleanup.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, signal, stat, subprocess, sys, time
from pathlib import Path
HERE=Path(__file__).resolve().parent
PACKAGE="org.trillionnium.hepta.local"
APK="a8c4be595fbd89d79bc1c7693b9f3c7d2b86ac9980fadc324dc10a5718d3c593"
SOURCE="9816c63a3217734883d0544446161e81411c818bb32a9db8e9d239bb3dd970f1"
SELECTOR="13f67bdbe25c4485f6b4cb5763ba473269b91e0c95a8ea404252aebf0ba4d5bf"
SOFT_SECONDS=6900
HARD_SECONDS=7200
def need(x,m):
    if not x:raise RuntimeError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p,limit=8<<20):
    p=Path(p);s=p.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=limit,"nonregular/linked/large host file")
    b=p.read_bytes();need(len(b)==s.st_size,"host file changed");return b
def strict(b):
    def pairs(xs):
        r={}
        for k,v in xs:
            need(k not in r,"duplicate JSON key");r[k]=v
        return r
    return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError(x)))
def put(p,b):
    p=Path(p);p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"wb") as f:
        f.write(b);f.flush();os.fsync(f.fileno())
def save(p,v):put(p,(json.dumps(v,ensure_ascii=False,indent=2,allow_nan=False)+"\n").encode())
def verify_package(expected):
    raw=read(HERE/"PACKAGE-MANIFEST.json")
    need(sha(raw)==expected,"package manifest SHA differs")
    value=strict(raw);need(value["schema"]=="hepta.v30-full-core9-offline-package.v1","unknown package")
    for rel,pin in value["files"].items():
        part=Path(rel);need(not part.is_absolute() and ".." not in part.parts,"unsafe package member")
        b=read(HERE/part);need(sha(b)==pin["sha256"] and len(b)==pin["bytes"],"package member changed: "+rel)
    return strict(read(HERE/"HOST-PLAN.json"))
def actual_selection(directory,expected,choice):
    raw=read(directory/"RESULT.json");need(sha(raw)==expected,"actual selector RESULT SHA differs")
    result=strict(raw);candidate=strict(read(directory/"candidate.json"));config_raw=read(directory/"runtime-config.json")
    expected_candidate=choice["proposed_candidate"]
    need(result.get("status")=="configuration_verified" and result.get("phone_contacted") is True
         and result.get("script_sha256")==SELECTOR and result.get("source_manifest_sha256")==SOURCE,
         "an actual successful pinned V30 selection is required")
    need(candidate==expected_candidate and sha(config_raw)==choice["proposed_config_sha256"],
         "actual selected candidate/config differs from chosen plan")
    need(result.get("selected_config")==strict(config_raw)
         and result.get("final_configuration_sha256")==choice["proposed_config_sha256"]
         and result.get("model_full_sha_verified")==expected_candidate["model_sha256"],
         "actual model/config readback differs")
    for key in ("identity_before","identity_after"):
        v=result.get(key,{})
        need(v.get("package")==PACKAGE and v.get("apk_sha256")==APK and v.get("version_code")==30
             and v.get("uid")==10481,"actual APK/version/UID differs")
    for key in ("configuration_replacement_verified","journals_unchanged","final_no_native_worker_observed"):
        need(result.get(key) is True,"selector proof incomplete: "+key)
    return {"path":str(directory),"sha256":sha(raw),"candidate":candidate,
            "config_sha256":sha(config_raw),"past_readback_not_fresh_idle_claim":True}
def commands(choice,run_output,restore_output):
    wrapper=HERE/"offline/phone_offline_suite.py"
    run=["/usr/bin/python3","-B",str(wrapper),"run","--core",str(HERE/"core/core_phone_suite.py"),
         "--plan",choice["path"],"--expected-plan-sha256",choice["sha256"],
         "--adb","/synthetic/adb","--adb-host","127.0.0.1","--adb-port","5037","--serial","SYNTHETIC_LEGACY",
         "--data-setting-key","mobile_data1","--expected-default-subscription","1","--expected-multisim-config","dsds",
         "--suite-deadline-seconds","6000","--supervisor-timeout-seconds","7200","--preparation-seconds","120",
         "--network-poll-seconds","15","--child-exit-grace-seconds","45","--output",str(run_output),
         "--command-timeout","10","--stable-seconds","1","--restore-seconds","120"]
    restore=["/usr/bin/python3","-B",str(wrapper),"restore","--journal",str(run_output/"network-journal.json"),
             "--output",str(restore_output),"--command-timeout","10","--stable-seconds","1","--restore-seconds","120"]
    return {"run_argv":run,"restore_same_usb_argv":restore,
            "restore_after_verified_reconnect_argv":restore+["--allow-reconnected-usb"]}
def supervise(argv,out,soft_seconds=SOFT_SECONDS,hard_seconds=HARD_SECONDS):
    """Own the host child through signals and exceptions; never infer Android cleanup."""
    need(0<soft_seconds<hard_seconds,"invalid deadline")
    start=time.monotonic();soft_deadline=start+soft_seconds;hard_deadline=start+hard_seconds
    recovery_window=hard_seconds-soft_seconds
    report={"schema":"hepta.host-offline-supervisor-result.v2","command":argv,"started_wall_ms":int(time.time()*1000),
            "soft_term_seconds":soft_seconds,"hard_kill_seconds":hard_seconds,"soft_term_sent":False,
            "hard_kill_sent":False,"requested_signals":[],"phone_cleanup_known":None,"phone_restoration_verified":None,
            "automatic_retry":False,"restore_command_executed_by_supervisor":False,
            "deadline_scope":"owned host wrapper; interrupted/failed supervision still gives its bounded restoration window"}
    child=None;old_handlers={};term_deadline=None;failure=None
    def requested(number,frame):
        # No exception or process wait in a signal handler: repeated signals cannot interrupt restoration.
        if len(report["requested_signals"])<32:
            report["requested_signals"].append({"signal":number,"wall_ms":int(time.time()*1000)})
    def terminate_once(reason):
        nonlocal term_deadline
        if child is None or child.poll() is not None:return
        if not report["soft_term_sent"]:
            report.update(soft_term_sent=True,term_reason=reason,soft_term_wall_ms=int(time.time()*1000))
            term_deadline=min(hard_deadline,time.monotonic()+recovery_window)
            child.terminate()
    def finish_until(deadline):
        # Signal handler only records new requests while this bounded restoration wait runs.
        while child is not None and child.poll() is None and time.monotonic()<deadline:
            time.sleep(min(0.2,max(0,deadline-time.monotonic())))
        if child is not None and child.poll() is None:
            report.update(hard_kill_sent=True,hard_kill_wall_ms=int(time.time()*1000))
            child.kill()
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:report["host_exit_confirmation_unresolved"]=True
    try:
        for number in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):
            old_handlers[number]=signal.signal(number,requested)
        need(not report["requested_signals"],"supervisor interrupted before host wrapper launch")
        with os.fdopen(os.open(out/"wrapper.stdout",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"wb") as stdout, \
             os.fdopen(os.open(out/"wrapper.stderr",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"wb") as stderr:
            child=subprocess.Popen(argv,stdout=stdout,stderr=stderr)
            # Every operation after Popen, including proc metadata and STARTED publication,
            # is inside an owned-child try/finally.
            try:
                report["host_wrapper_pid"]=child.pid
                fields=Path("/proc/%d/stat"%child.pid).read_text().rsplit(")",1)[1].split()
                report["host_wrapper_start_ticks"]=int(fields[19])
                save(out/"STARTED.json",report)
                while child.poll() is None:
                    now=time.monotonic()
                    if report["requested_signals"]:
                        terminate_once("supervisor_signal")
                    elif now>=soft_deadline:
                        terminate_once("soft_deadline")
                    if term_deadline is not None:
                        finish_until(term_deadline);break
                    if now>=hard_deadline:
                        finish_until(hard_deadline);break
                    time.sleep(min(0.2,max(0,soft_deadline-now)))
            except BaseException as error:
                failure=type(error).__name__+": "+str(error)
                report["supervisor_exception"]=failure
            finally:
                if child.poll() is None:
                    try:
                        terminate_once("supervisor_exception_or_finally")
                        finish_until(term_deadline if term_deadline is not None else hard_deadline)
                    except BaseException as error:
                        report["host_shutdown_error"]=type(error).__name__+": "+str(error)
                        # Still only this Popen child. Never kill a phone PID or infer its cleanup.
                        if child.poll() is None:
                            report.update(hard_kill_sent=True,hard_kill_wall_ms=int(time.time()*1000))
                            child.kill()
                            try:child.wait(timeout=5)
                            except BaseException as last:report["host_exit_confirmation_error"]=type(last).__name__+": "+str(last)
                report["host_wrapper_exit_code"]=child.poll()
    except BaseException as error:
        failure=type(error).__name__+": "+str(error)
        report.setdefault("supervisor_exception",failure)
    finally:
        for number,previous in old_handlers.items():
            signal.signal(number,previous)
    interrupted=bool(report["soft_term_sent"] or report["requested_signals"] or failure)
    report.update(finished_wall_ms=int(time.time()*1000),elapsed_seconds=time.monotonic()-start,
                  remaining_host_descendants_status="not asserted by this supervisor",
                  verdict="interrupted_or_failed_review_required" if interrupted else "wrapper_exited_review_results",
                  test_acceptance_not_inferred_from_host_exit=True)
    save(out/"SUPERVISOR-RESULT.json",report)
    return report
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--package-sha256",required=True)
    p.add_argument("--model",choices=("gemma8192","lfm25-8192"))
    p.add_argument("--execute",action="store_true");p.add_argument("--exclusive-idle-window",action="store_true")
    p.add_argument("--selection",type=Path);p.add_argument("--selection-result-sha256")
    p.add_argument("--output",type=Path);p.add_argument("--run-output",type=Path);p.add_argument("--restore-output",type=Path)
    args=p.parse_args();plan=verify_package(args.package_sha256)
    if not args.execute:
        print(json.dumps({"status":"host_plan_only","phone_contacted":False,"models":plan["plans"],
                          "actual_supervisor_soft_seconds":SOFT_SECONDS,"actual_supervisor_hard_seconds":HARD_SECONDS,
                          "required_suite_seconds":5790,"suite_seconds":6000,"minimum_external_seconds":6645},ensure_ascii=False,indent=2))
        return 0
    need(args.exclusive_idle_window and args.model and args.selection and args.selection_result_sha256
         and args.output and args.run_output and args.restore_output,
         "execution requires chosen model, actual selection proof, exclusive idle window and new output paths")
    choice=plan["plans"][args.model]
    proof=actual_selection(args.selection.resolve(strict=True),args.selection_result_sha256,choice)
    out=args.output.resolve();run_output=args.run_output.resolve();restore_output=args.restore_output.resolve()
    need(len({str(out),str(run_output),str(restore_output)})==3 and not any(x.exists() for x in (out,run_output,restore_output)),
         "three distinct fresh output paths required")
    cmd=commands(choice,run_output,restore_output)
    # One full-suite execution per frozen package; no implicit candidate loop or replay.
    save(HERE/"EXECUTION-RESERVATION.json",{"model":args.model,"selection":proof,"supervisor_output":str(out),
                                         "run_output":str(run_output),"automatic_retry":False,"attempts":1})
    out.mkdir(mode=0o700,parents=True,exist_ok=False)
    save(out/"COMMANDS.json",cmd);save(out/"SELECTION-BINDING.json",proof)
    save(out/"PREFLIGHT-RESPONSIBILITY.json",{"phone_preflight_performed_by_supervisor":False,
        "root_must_already_verify":["current V30/chosen8192 model/config, clean idle and no native workers",
          "bound accessibility, unlocked unfolded default display, stable USB, exclusive window",
          "wifi enabled, selected mobile_data1=1, global mobile_data observed, airplane_mode_on=0",
          "default data subscription1 and multisim dsds; different or unknown values require new commands"],
        "wrapper_journals_actual_radio_baseline_before_changes":True,
        "wrapper_core_app_preflight_happens_after_radio_disable":True})
    report=supervise(cmd["run_argv"],out)
    for name in ("offline-result.json","network-journal.json","suite/suite-result.json"):
        path=run_output/name
        if path.is_file():
            raw=read(path);save(out/(name.replace("/","-")+".reference.json"),{"path":str(path),"bytes":len(raw),"sha256":sha(raw)})
    print(json.dumps({"supervisor_result":str(out/"SUPERVISOR-RESULT.json"),"wrapper_exit_code":report.get("host_wrapper_exit_code"),
                      "deadline_interrupted":report["soft_term_sent"],"offline_result":str(run_output/"offline-result.json"),
                      "restore_argv_saved":str(out/"COMMANDS.json"),"phone_cleanup_not_inferred":True},ensure_ascii=False))
    return 124 if report["verdict"]=="interrupted_or_failed_review_required" else (report.get("host_wrapper_exit_code") if report.get("host_wrapper_exit_code") is not None else 125)
if __name__=="__main__":raise SystemExit(main())
