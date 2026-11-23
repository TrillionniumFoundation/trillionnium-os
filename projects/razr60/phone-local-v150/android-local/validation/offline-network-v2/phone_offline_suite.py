#!/usr/bin/env python3
"""Run an already frozen phone suite inside a measured, reversible radio transaction.

Only run/restore contact the explicitly selected existing USB ADB transport.
No airplane mode, settings put, daemon reset, app kill or automatic case retry.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import socket
import stat
import subprocess
import sys
import time

import offline_guards as guard

CORE_SHA = "22f1e4643e3076f630749a79c7f2a30beba7171097c5ef8c36bcaa80d83c753c"
ASSERTIONS_SHA = "65999f565846afda7ff7ba75dee4eff1cc4e32a29f670b9182039139eec0d836"


class TerminationRequested(BaseException):
    pass


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()


def read_private(path, limit=2*1024*1024):
    path=Path(path)
    if path.is_symlink():raise guard.UnknownState("symlink file refused")
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,"rb") as stream:
        metadata=os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 or metadata.st_size>limit:
            raise guard.UnknownState("bounded single-link regular file required")
        data=stream.read(limit+1)
        if len(data)>limit:raise guard.UnknownState("file exceeds limit")
        return data


def write(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if not isinstance(value,bytes):value=encoded(value)
    temporary=path.with_name(path.name+".tmp-"+secrets.token_hex(8))
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as stream:stream.write(value);stream.flush();os.fsync(stream.fileno())
    if path.is_symlink():temporary.unlink();raise guard.UnknownState("output became symlink")
    os.replace(temporary,path)
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(directory)
    finally:os.close(directory)


def recv_exact(channel,count,deadline):
    value=bytearray()
    while len(value)<count:
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError("ADB operation deadline")
        channel.settimeout(remaining);chunk=channel.recv(count-len(value))
        if not chunk:raise OSError("ADB connection ended before complete reply")
        value.extend(chunk)
    return bytes(value)


def send_all(channel,data,deadline):
    remaining=deadline-time.monotonic()
    if remaining<=0:raise TimeoutError("ADB send deadline")
    channel.settimeout(remaining);channel.sendall(data)


def service(channel,name,deadline):
    data=name.encode();send_all(channel,("%04x"%len(data)).encode()+data,deadline)
    reply=recv_exact(channel,4,deadline)
    if reply==b"FAIL":
        size=recv_exact(channel,4,deadline)
        if re.fullmatch(rb"[0-9a-fA-F]{4}",size):recv_exact(channel,int(size,16),deadline)
        raise OSError("existing ADB server refused the exact service")
    if reply!=b"OKAY":raise OSError("invalid ADB service status")


class Phone:
    def __init__(self,args,out,expected=None,allow_reconnected=False):
        self.args=args;self.out=out;self.sequence=0;self.expected=expected
        self.allow_reconnected=allow_reconnected

    def smart(self,request,phase_deadline=None):
        if request not in ("host:version","host:devices-l"):raise ValueError("unlisted host read")
        deadline=min(time.monotonic()+self.args.command_timeout,phase_deadline or float("inf"))
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError("ADB host-read deadline reached")
        with socket.create_connection((self.args.adb_host,self.args.adb_port),timeout=remaining) as channel:
            service(channel,request,deadline);size=recv_exact(channel,4,deadline)
            if not re.fullmatch(rb"[0-9a-fA-F]{4}",size):raise OSError("invalid ADB payload size")
            data=recv_exact(channel,int(size,16),deadline)
        return data

    def identity(self,deadline=None):
        raw=self.smart("host:devices-l",deadline);identity=guard.usb_device(raw,self.args.serial)
        write(self.out/"usb-current.txt",raw)
        if self.expected is None:self.expected=identity
        keys=("serial","usb") if self.allow_reconnected else ("serial","usb","transport_id")
        if any(identity.get(k)!=self.expected.get(k) for k in keys):
            raise guard.UnknownState("original selected USB transport changed")
        return identity

    def command(self,command,label,deadline=None):
        command=tuple(command)
        reads={("settings","get","global","wifi_on"),("settings","get","global","mobile_data"),
               ("settings","get","global","multi_sim_data_call"),
               ("settings","get","global",self.args.data_setting_key),
               ("getprop","persist.radio.multisim.config"),("cmd","wifi","status"),("dumpsys","connectivity")}
        mutations={("svc",radio,value) for radio in ("wifi","data") for value in ("enable","disable")}
        if command not in reads|mutations:raise ValueError("command outside explicit radio transaction")
        started=time.monotonic();end=min(deadline or float("inf"),started+self.args.command_timeout)
        if end<=started:raise TimeoutError("transaction deadline reached before any phone command")
        identity=self.identity(end);self.sequence+=1
        stem=self.out/"commands"/("%04d-"%self.sequence+label)
        limit=2*1024*1024 if command==("dumpsys","connectivity") else 32768
        receipt={"command":list(command),"serial":self.args.serial,"transport_id":identity["transport_id"],
                 "host_wall_ms":int(time.time()*1000),"exit_code":None,"complete":False,"mutating":command in mutations}
        streams={1:bytearray(),2:bytearray()}
        try:
            if end<=time.monotonic():raise TimeoutError("transaction deadline reached")
            with socket.create_connection((self.args.adb_host,self.args.adb_port),timeout=end-time.monotonic()) as channel:
                service(channel,"host:transport-id:"+identity["transport_id"],end)
                service(channel,"shell,v2,raw:"+shlex.join(command),end)
                send_all(channel,b"\x04\x00\x00\x00\x00",end)
                while True:
                    header=recv_exact(channel,5,end);kind=header[0];length=int.from_bytes(header[1:],"little")
                    if kind==3:
                        if length!=1:raise OSError("invalid remote exit packet")
                        receipt["exit_code"]=recv_exact(channel,1,end)[0];receipt["complete"]=True;break
                    if kind not in streams or length>limit-sum(map(len,streams.values())):
                        raise guard.UnknownState("invalid or excessive shell output")
                    streams[kind].extend(recv_exact(channel,length,end))
            if receipt["exit_code"]!=0:raise OSError("remote command failed")
            return bytes(streams[1])
        except BaseException as error:
            receipt["error"]=type(error).__name__+": "+str(error);raise
        finally:
            receipt["elapsed_s"]=time.monotonic()-started
            for kind,name in ((1,"stdout"),(2,"stderr")):
                data=bytes(streams[kind]);write(Path(str(stem)+"."+name),data);receipt[name+"_sha256"]=guard.sha(data)
            write(Path(str(stem)+".json"),receipt)


class Transaction:
    def __init__(self,args,out,phone,state=None):
        self.args=args;self.out=out;self.phone=phone;self.restoring=False
        self.state=state or {"schema":"hepta.offline-network-journal.v1","run_id":secrets.token_hex(16),
            "wrapper_sha256":guard.sha(Path(__file__).read_bytes()),"guards_sha256":guard.sha(Path(guard.__file__).read_bytes()),
            "connection":{"adb_host":args.adb_host,"adb_port":args.adb_port,"serial":args.serial},
            "data_setting_key":args.data_setting_key,"expected_default_subscription":args.expected_default_subscription,
            "expected_multisim_config":args.expected_multisim_config,"original":None,
            "mutation_intents":{"wifi":False,"data":False},"mutation_returns":{},"snapshots":[],
            "restoration":{"attempted":False,"verified":False},"phone_cleanup_known":None,"errors":[]}

    def persist(self):
        self.state["usb_identity"]=self.phone.expected
        write(self.out/"network-journal.json",self.state)

    def binding(self,label,deadline=None):
        sub=guard.subscription_id(self.phone.command(("settings","get","global","multi_sim_data_call"),label+"-sub",deadline))
        mode=self.phone.command(("getprop","persist.radio.multisim.config"),label+"-multisim",deadline).decode().strip()
        if sub!=self.args.expected_default_subscription or mode!=self.args.expected_multisim_config:
            raise guard.UnknownState("default subscription or multisim mode changed; no svc data to a new SIM")
        return sub,mode

    def snapshot(self,label,deadline=None,network_required=True):
        sub,mode=self.binding(label,deadline)
        wifi=guard.switch_value(self.phone.command(("settings","get","global","wifi_on"),label+"-wifi-setting",deadline))
        global_data=guard.switch_value(self.phone.command(("settings","get","global","mobile_data"),label+"-global-data",deadline))
        selected=guard.switch_value(self.phone.command(("settings","get","global",self.args.data_setting_key),label+"-selected-data",deadline))
        enabled=guard.wifi_status(self.phone.command(("cmd","wifi","status"),label+"-wifi-status",deadline))
        # Re-read binding around the snapshot. The default-subscription shell
        # mutation is not atomic with this observation; record that limitation.
        if self.binding(label+"-end",deadline)!=(sub,mode):raise guard.UnknownState("subscription changed in snapshot")
        row={"label":label,"host_wall_ms":int(time.time()*1000),"wifi_on":wifi,"wifi_status_enabled":enabled,
             "mobile_data_global":global_data,"mobile_data_selected":selected,"data_setting_key":self.args.data_setting_key,
             "default_data_subscription":sub,"multisim_config":mode,"default_network_known":False,"default_network":None}
        try:
            row["default_network"]=guard.default_network(self.phone.command(("dumpsys","connectivity"),label+"-connectivity",deadline))
            row["default_network_known"]=True
        except Exception as error:
            row["network_error"]=str(error)
            if network_required:
                self.state["snapshots"].append(row);self.persist();raise
        self.state["snapshots"].append(row);self.persist();return row

    def baseline(self,deadline):
        first=self.snapshot("original-1",deadline);time.sleep(self.args.stable_seconds)
        second=self.snapshot("original-2",deadline)
        if not guard.stable_controls(first,second):raise guard.UnknownState("original radio settings not stable twice")
        if second["wifi_status_enabled"]!=bool(second["wifi_on"]):raise guard.UnknownState("original WiFi state is transitional")
        if second["mobile_data_selected"]!=1:
            raise guard.UnknownState("explicit candidate data-key qualification requires an observed 1-to-0 transition; no radio changes submitted")
        self.state["original"]=second;self.persist();return second

    def change(self,radio,enabled,phase,deadline):
        if radio=="data":self.binding(phase+"-data-target",deadline)
        if not self.restoring:
            self.state["mutation_intents"][radio]=True;self.persist()  # Persist before sending; timeout may still have effects.
        raw=self.phone.command(("svc",radio,"enable" if enabled else "disable"),phase+"-"+radio,deadline)
        self.state["mutation_returns"][phase+"-"+radio]={"remote_exit":0,"stdout_sha256":guard.sha(raw),"effect_requires_readback":True}
        self.persist()

    def disable(self,deadline):
        self.change("wifi",False,"disable",deadline);self.change("data",False,"disable",deadline)
        previous=None
        while time.monotonic()<deadline:
            current=self.snapshot("disabled-%d"%len(self.state["snapshots"]),deadline)
            if guard.offline(current) and previous is not None and guard.offline(previous) and guard.stable_controls(previous,current):
                self.state["offline_precondition_verified_twice"]=True
                self.state["data_key_qualification"]={"kind":"explicit_candidate_svc_readback","key":self.args.data_setting_key,
                    "original":self.state["original"]["mobile_data_selected"],"disabled_observed":0,
                    "android16_helper_storage_chain_claimed":False,"all_sim_or_modem_power_claimed":False,
                    "subscription_scope":"observed_stable_before_and_after_commands_not_atomic"}
                self.persist();return
            previous=current;time.sleep(self.args.stable_seconds)
        raise TimeoutError("radio-off/default-none state did not stabilize twice")

    def restore(self):
        self.restoring=True
        old=self.state.get("restoration",{})
        if old.get("attempted"):self.state.setdefault("previous_restoration_attempts",[]).append(dict(old))
        outcome={"attempted":True,"verified":False,"started_wall_ms":int(time.time()*1000)}
        self.state["restoration"]=outcome
        deadline=time.monotonic()+self.args.restore_seconds
        original=self.state.get("original")
        if original is None or not any(self.state["mutation_intents"].values()):
            outcome.update(verified=True,reason="no radio mutation submitted");self.persist();return True
        self.persist()
        for radio in ("wifi","data"):
            if not self.state["mutation_intents"].get(radio):continue
            target=original["wifi_on"] if radio=="wifi" else original["mobile_data_selected"]
            try:self.change(radio,bool(target),"restore",deadline)
            except Exception as error:outcome[radio+"_error"]=str(error);self.persist()
        previous=None
        while time.monotonic()<deadline:
            try:
                current=self.snapshot("restore-%d"%len(self.state["snapshots"]),deadline,network_required=False)
                if guard.restored(original,current) and previous is not None and guard.restored(original,previous) and guard.stable_controls(previous,current):
                    outcome.update(verified=True,verified_twice=True,selected_preferences_restored=True,
                        original_default_connectivity_reestablished=(current["default_network_known"] and
                           (original["default_network"] is None or current["default_network"] is not None)))
                    self.persist();return True
                previous=current
            except Exception as error:outcome["verification_error"]=str(error);previous=None
            time.sleep(min(self.args.stable_seconds,max(0,deadline-time.monotonic())))
        outcome.update(verified=False,manual_restoration_required=True);self.persist();return False


def frozen_suite(args,out):
    raw=read_private(args.plan)
    if guard.sha(raw)!=args.expected_plan_sha256:raise guard.UnknownState("exact frozen plan hash differs")
    plan=guard.strict_json(raw)
    source=Path(args.core).expanduser().resolve(strict=True);assertions=source.with_name("core_assertions.py")
    if guard.sha(read_private(source))!=CORE_SHA or guard.sha(read_private(assertions))!=ASSERTIONS_SHA:
        raise guard.UnknownState("independent core runner differs from qualified fixed revision")
    runner=out/"runner";runner.mkdir(mode=0o700)
    for p in (source,assertions):write(runner/p.name,read_private(p))
    write(out/"plan.json",raw)
    result=subprocess.run([sys.executable,"-B",str(runner/source.name),"validate",str(out/"plan.json")],capture_output=True,timeout=30)
    write(out/"plan-validation.stdout",result.stdout);write(out/"plan-validation.stderr",result.stderr)
    if result.returncode:raise guard.UnknownState("frozen core plan validation failed before phone contact")
    required=sum(float(case["timeout_seconds"])+90 for case in plan["cases"])+120
    if args.suite_deadline_seconds<required:raise guard.UnknownState("suite deadline shorter than frozen case budgets plus collection allowance: "+str(required))
    return runner/source.name,plan


def proc(pid):
    try:return guard.process_identity(Path("/proc/%d/stat"%pid).read_text())
    except FileNotFoundError:return None


def require_host_proc_namespace():
    own=proc(os.getpid())
    actual=guard.process_identity(Path("/proc/self/stat").read_text())
    if own is None or own!=actual or own["pid"]!=os.getpid():
        raise guard.UnknownState("host /proc PID namespace does not match Python; bounded child supervision unavailable")
    return own


def signal_owned(child,identity,number):
    if child.poll() is not None:return False
    now=proc(child.pid)
    if not isinstance(identity,dict) or now!=identity or now["pgrp"]!=child.pid or now["session"]!=child.pid:
        raise guard.UnknownState("owned host suite identity changed; no signal sent")
    os.killpg(child.pid,number);return True


def run(args,out):
    host_identity=require_host_proc_namespace()  # Before any ADB read or mutation.
    core,plan=frozen_suite(args,out)
    # Local adb version cannot create a server; all network controls use the
    # existing smart socket. The unchanged core runner retains its own gate.
    version=subprocess.run([args.adb,"version"],capture_output=True,timeout=10)
    match=re.search(rb"Android Debug Bridge version 1\.0\.(\d+)\b",version.stdout)
    if version.returncode or not match:raise guard.UnknownState("local ADB protocol version unknown")
    phone=Phone(args,out);server=phone.smart("host:version")
    if not re.fullmatch(rb"[0-9a-fA-F]{4}",server) or int(server,16)!=int(match[1]):raise guard.UnknownState("existing server/client protocol mismatch")
    phone.identity();transaction=Transaction(args,out,phone);child=None;identity=None;completed=False;restored=False
    transaction.state["host_supervisor_identity"]=host_identity
    def stopped(number,frame):
        transaction.state["requested_signal"]=number
        if not transaction.restoring:
            transaction.restoring=True
            raise TerminationRequested("host signal "+str(number))
    old={number:signal.signal(number,stopped) for number in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP)}
    try:
        transaction.baseline(time.monotonic()+args.preparation_seconds)
        transaction.disable(time.monotonic()+args.preparation_seconds)
        command=[sys.executable,"-B",str(core),"run",str(out/"plan.json"),"--adb",args.adb,"--adb-host",args.adb_host,
                 "--adb-port",str(args.adb_port),"--serial",args.serial,"--command-timeout",str(args.command_timeout),"--output",str(out/"suite")]
        stdout_fd=os.open(out/"suite.stdout",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        stderr_fd=os.open(out/"suite.stderr",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(stdout_fd,"wb") as stdout,os.fdopen(stderr_fd,"wb") as stderr:
            child=subprocess.Popen(command,stdout=stdout,stderr=stderr,start_new_session=True)
            identity=proc(child.pid)
            if identity is None:child.wait(timeout=1)
            transaction.state["suite"]={"pid":child.pid,"identity":identity,"command":command,"plan_sha256":args.expected_plan_sha256,
                                        "started_wall_ms":int(time.time()*1000),"exit_code":None}
            transaction.persist();end=time.monotonic()+args.suite_deadline_seconds;next_check=time.monotonic()+args.network_poll_seconds
            while child.poll() is None:
                if time.monotonic()>=end:raise TimeoutError("owned host suite deadline")
                if time.monotonic()>=next_check:
                    state=transaction.snapshot("during-%d"%len(transaction.state["snapshots"]),end)
                    if not guard.offline(state):raise guard.UnknownState("offline conditions changed during suite; no offline pass claimed")
                    next_check=time.monotonic()+args.network_poll_seconds
                time.sleep(0.2)
            transaction.state["suite"]["exit_code"]=child.returncode
            final_deadline=time.monotonic()+args.preparation_seconds
            first=transaction.snapshot("suite-end-1",final_deadline);time.sleep(args.stable_seconds)
            second=transaction.snapshot("suite-end-2",final_deadline)
            if not guard.offline(first) or not guard.offline(second) or not guard.stable_controls(first,second):raise guard.UnknownState("final offline conditions unverified")
            completed=True
    except (Exception,TerminationRequested) as error:
        transaction.state["errors"].append(type(error).__name__+": "+str(error))
    finally:
        # Once teardown begins, subsequent TERM/INT/HUP only record the request;
        # they must not interrupt radio restoration or its bounded verification.
        transaction.restoring=True
        # The suite runs in its own host process group. Interrupt its submissions,
        # never a phone PID, then restore radios immediately rather than waiting
        # for potentially slow phone evidence collection before restoration.
        if child is not None and child.poll() is None:
            transaction.state["phone_cleanup_known"]=False
            transaction.state["manual_phone_task_review_required"]=True
            try:signal_owned(child,identity,signal.SIGINT)
            except Exception as error:transaction.state["errors"].append("host suite interrupt: "+str(error))
        try:restored=transaction.restore()
        except Exception as error:
            transaction.state["restoration"].update(verified=False,error=str(error),manual_restoration_required=True)
        if child is not None and child.poll() is None:
            try:child.wait(timeout=args.child_exit_grace_seconds)
            except subprocess.TimeoutExpired:
                for number,wait in ((signal.SIGTERM,10),(signal.SIGKILL,5)):
                    try:
                        signal_owned(child,identity,number);child.wait(timeout=wait);break
                    except subprocess.TimeoutExpired:continue
                    except Exception as error:transaction.state["errors"].append("host child exit unresolved: "+str(error));break
        if child is not None and transaction.state.get("suite") is not None:transaction.state["suite"]["exit_code"]=child.poll()
        transaction.state["offline_conditions_observed_through_normal_suite"]=completed
        transaction.state["sampling_is_not_packet_capture"]=True
        transaction.state["whole_device_continuous_network_absence_claimed"]=False
        transaction.state["external_supervisor_timeout_margin_required"]=True
        transaction.persist()
        result=transaction.state.copy();result["finished_wall_ms"]=int(time.time()*1000)
        result["verdict"]="completed_and_restored" if completed and restored else "incomplete_or_restore_unverified"
        if (out/"suite/suite-result.json").is_file():
            try:
                raw=read_private(out/"suite/suite-result.json");receipt=guard.strict_json(raw)
                result["suite_report_sha256"]=guard.sha(raw);result["suite_verdict"]=receipt.get("suite_verdict")
                result["core_functional_acceptance"]=receipt.get("core_functional_acceptance")
            except Exception as error:
                result["suite_report_error"]=str(error);result["core_functional_acceptance"]="unverified"
        write(out/"offline-result.json",result)
        print(json.dumps({k:result.get(k) for k in ("verdict","suite_verdict","core_functional_acceptance","restoration","errors")},ensure_ascii=False),flush=True)
        for number,handler in old.items():signal.signal(number,handler)
    return 0 if (completed and restored and child is not None and child.returncode==0
                 and result.get("suite_verdict")=="pass" and result.get("core_functional_acceptance")=="pass") else 3


def restore(args,out):
    metadata=args.journal.stat()
    if metadata.st_uid!=os.getuid() or metadata.st_mode&0o077:raise guard.UnknownState("private owned restore journal required")
    state=guard.strict_json(read_private(args.journal))
    if state.get("schema")!="hepta.offline-network-journal.v1" or not state.get("original"):
        raise guard.UnknownState("journal lacks complete original state")
    if state.get("wrapper_sha256")!=guard.sha(Path(__file__).read_bytes()) or state.get("guards_sha256")!=guard.sha(Path(guard.__file__).read_bytes()):
        raise guard.UnknownState("restoration implementation differs from original journal")
    for key in ("adb_host","adb_port","serial"):setattr(args,key,state["connection"][key])
    args.data_setting_key=state["data_setting_key"];args.expected_default_subscription=state["expected_default_subscription"]
    args.expected_multisim_config=state["expected_multisim_config"]
    connection_valid(args)
    original=state["original"]
    intents=state.get("mutation_intents")
    if not isinstance(intents,dict) or set(intents)!={"wifi","data"} or any(type(x) is not bool for x in intents.values()):
        raise guard.UnknownState("invalid saved mutation intents")
    if not isinstance(state.get("usb_identity"),dict) or state["usb_identity"].get("serial")!=args.serial:
        raise guard.UnknownState("journal lacks the original selected USB identity")
    for key in ("wifi_on","mobile_data_global","mobile_data_selected"):
        if type(original.get(key)) is not int or original[key] not in (0,1):raise guard.UnknownState("original switch value unknown")
    if (original.get("data_setting_key")!=args.data_setting_key or original.get("default_data_subscription")!=args.expected_default_subscription
            or original.get("multisim_config")!=args.expected_multisim_config):raise guard.UnknownState("restore identity differs from original snapshot")
    phone=Phone(args,out,state["usb_identity"],args.allow_reconnected_usb)
    transaction=Transaction(args,out,phone,state);transaction.restoring=True
    old={n:signal.signal(n,lambda number,frame:None) for n in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP)}
    try:ok=transaction.restore()
    finally:
        for number,handler in old.items():signal.signal(number,handler)
    write(out/"offline-result.json",transaction.state);print(json.dumps(transaction.state["restoration"]));return 0 if ok else 3


def connection_valid(args):
    if (not isinstance(args.adb_host,str) or not ipaddress.ip_address(args.adb_host).is_loopback
            or type(args.adb_port) is not int or not 1<=args.adb_port<=65535
            or not isinstance(args.serial,str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}",args.serial)):
        raise guard.UnknownState("explicit loopback server/device required")
    guard.selected_data_key(args.data_setting_key,args.expected_default_subscription)
    if type(args.expected_default_subscription) is not int or not 0<=args.expected_default_subscription<=999999999 or args.expected_multisim_config not in ("dsds","dsda","tsts",""):
        raise guard.UnknownState("explicit observed subscription/mode required")


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest="operation",required=True)
    execute=sub.add_parser("run");execute.add_argument("--core",type=Path,required=True);execute.add_argument("--plan",type=Path,required=True)
    execute.add_argument("--expected-plan-sha256",required=True);execute.add_argument("--adb",required=True)
    execute.add_argument("--adb-host",default="127.0.0.1");execute.add_argument("--adb-port",type=int,required=True);execute.add_argument("--serial",required=True)
    execute.add_argument("--data-setting-key",required=True);execute.add_argument("--expected-default-subscription",type=int,required=True)
    execute.add_argument("--expected-multisim-config",required=True)
    execute.add_argument("--suite-deadline-seconds",type=int,default=6000);execute.add_argument("--supervisor-timeout-seconds",type=int,required=True)
    execute.add_argument("--preparation-seconds",type=int,default=120);execute.add_argument("--network-poll-seconds",type=int,default=15)
    execute.add_argument("--child-exit-grace-seconds",type=int,default=45)
    recovery=sub.add_parser("restore");recovery.add_argument("--journal",type=Path,required=True);recovery.add_argument("--allow-reconnected-usb",action="store_true")
    for command in (execute,recovery):
        command.add_argument("--output",type=Path,required=True);command.add_argument("--command-timeout",type=float,default=10)
        command.add_argument("--stable-seconds",type=float,default=1);command.add_argument("--restore-seconds",type=int,default=120)
    args=parser.parse_args()
    if not 1<=args.command_timeout<=20 or not 1<=args.stable_seconds<=5 or not 60<=args.restore_seconds<=180:
        parser.error("bounded command, stable-state and restoration timings required")
    if args.operation=="run":
        connection_valid(args)
        if not re.fullmatch(r"[0-9a-f]{64}",args.expected_plan_sha256):parser.error("exact plan SHA256 required")
        if not 1<=args.suite_deadline_seconds<=14400 or not 60<=args.preparation_seconds<=180 or not 5<=args.network_poll_seconds<=60 or not 15<=args.child_exit_grace_seconds<=90:parser.error("invalid bounded supervision interval")
        margin=3*args.preparation_seconds+args.suite_deadline_seconds+args.restore_seconds+args.child_exit_grace_seconds+120
        if args.supervisor_timeout_seconds<margin:parser.error("outer supervisor timeout must be at least "+str(margin)+" seconds so finally can restore")
        if not Path(args.adb).is_absolute() or not os.access(args.adb,os.X_OK):parser.error("existing absolute ADB executable required")
    out=args.output.expanduser().resolve();out.mkdir(parents=True,exist_ok=False,mode=0o700)
    return run(args,out) if args.operation=="run" else restore(args,out)


if __name__=="__main__":
    try:sys.exit(main())
    except (Exception,TerminationRequested) as error:
        print(json.dumps({"error":type(error).__name__+": "+str(error),"automatic_retry":False}),file=sys.stderr);sys.exit(2)
