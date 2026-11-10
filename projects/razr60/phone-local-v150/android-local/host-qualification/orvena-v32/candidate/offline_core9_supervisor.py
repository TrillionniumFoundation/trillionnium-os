#!/usr/bin/env python3
"""Bounded supervision for the owned offline wrapper; never infer phone cleanup.

This module has no standalone phone CLI. The scoped stage runner supplies the
already verified command and private evidence directory.
"""
from __future__ import annotations
import json, os, signal, subprocess, time
from pathlib import Path
SOFT_SECONDS=6900
HARD_SECONDS=7200
def need(x,m):
    if not x:raise RuntimeError(m)

def put(p,b):
    p=Path(p);p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"wb") as f:
        f.write(b);f.flush();os.fsync(f.fileno())

def save(p,v):put(p,(json.dumps(v,ensure_ascii=False,indent=2,allow_nan=False)+"\n").encode())

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
