#!/usr/bin/env python3
"""Host-only protocol fixtures; fake native frames/receipts, no phone or model calls."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe", ROOT/"component_probe_provider.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
OUT = Path(sys.argv[1]).absolute()
OUT.mkdir(mode=0o700, parents=False, exist_ok=False)
os.umask(0o077)
CHECKS = []
def test(name, fn):
    fn()
    CHECKS.append({"name": name, "passed": True})

def contract(nonce):
    c = {"schema": "hepta.native-component-probe.contract.v150.r6.1", "nonce": nonce,
         "owner_request_sha256": m.sha(m.owner_request(nonce).encode()),
         "selected_session_id": "fixture-session", "selected_profile_id": "fixture-profile",
         "executor_server_instance": "9"*32, "executor_journal": m.JOURNAL, "endpoint": m.SOCKET,
         "client_sha256": m.CLIENT_SHA, "parent_sha256": m.PARENT_SHA, "worker_sha256": m.WORKER_SHA,
         "policy_rule_sha256": m.POLICY_RULE_SHA, "patched_policy_sha256": m.PATCHED_POLICY_SHA,
         "retirement_proof_sha256": "1"*64, "retirement_resolution_sha256": "2"*64,
         "provider_source_sha256": m.sha((ROOT/"component_probe_provider.py").read_bytes()),
         "expires_unix_ms": int(time.time()*1000)+60000, "scope": m.SCOPE}
    return m.validate_contract(c)

def start(c, task="fixture-task", wrong_text=False):
    return {"protocol": m.PROTOCOL, "kind": "turn.start", "seq": 0,
            "turn": {"session_id": c["selected_session_id"], "profile_id": c["selected_profile_id"],
                     "task_id": task, "turn_id": "fixture-turn", "turn_stream_id": "fixture-stream",
                     "user_input": m.owner_request(c["nonce"])+("x" if wrong_text else "")}}

def receipt(c, aid, cmdsha):
    out = m.expected_output(c["nonce"])
    r = {"action_id": aid, "command_sha256": cmdsha, "state": "completed", "terminal": True,
         "server_instance": c["executor_server_instance"], "executor_revision": 6,
         "executor_context": m.PARENT_CONTEXT, "peer_context": m.BOOTSTRAP_CONTEXT,
         "execution_credentials_scope": "android_shell_uid2000",
         "required_execution_uid": 2000, "required_execution_gid": 2000,
         "handshake_stage": "worker_entry_after_exec_transition", "execution_context": m.WORKER_CONTEXT,
         "stdout_sha256": m.sha(out), "stderr_sha256": m.sha(b""), "stdout_bytes": len(out), "stderr_bytes": 0,
         "effect_started": True, "process_group_established": True, "waitpid_joined": True,
         "process_group_absent": True, "execution_credentials_verified": True,
         "supplementary_groups_cleared": True, "worker_domain_verified": True,
         "waitpid_identity_lost": False, "execution_uid": 2000, "execution_euid": 2000,
         "execution_gid": 2000, "execution_egid": 2000, "dispatch_count": 1,
         "execution_supplementary_group_count": 0, "exit_code": 0, "pid": 32123, "pgid": 32123}
    return {"version": 1, "protocol": "hepta_phone_local_v150", "receipt": r}

def result(c, callid, wrong_output=False):
    raw = m.expected_output(c["nonce"]) + (b"x" if wrong_output else b"")
    terminal = {"kind": "exited", "exit_code": 0, "signal": None, "stdout_bytes": len(raw),
                "stderr_bytes": 0, "output_truncated": False, "elapsed_ms": 2, "error": None}
    bodies = [{"kind": "accepted"}, {"kind": "started", "pid": 12345},
              {"kind": "output", "stream": "stdout", "encoding": "base64",
               "data": base64.b64encode(raw).decode(), "byte_count": len(raw)},
              {"kind": "terminal", "terminal": terminal}]
    return {"protocol": m.PROTOCOL, "kind": "tool.result", "seq": 1, "call_id": callid,
            "status": "terminal", "terminal": terminal,
            "events": [{"call_id": callid, "tool": "shell.exec", "seq": i, "target_id": None,
                        "event": e} for i, e in enumerate(bodies)],
            "registry": {"call_id": callid, "tool": "shell.exec", "state": "Terminal { kind: Exited }",
                         "cancellation_requested": False, "connection_lost": False}}

def run(c, directory=None, task="fixture-task", wrong_text=False, precancel=False,
        postcancel=False, eof=False, receipt_bad=None, wrong_output=False):
    state = directory or OUT/uuid.uuid4().hex
    if not state.exists():
        for d in (state, state/"claims", state/"evidence", state/"client-receipts"):
            m.private_dir(d)
    run_dir = state/"evidence"/uuid.uuid4().hex
    m.private_dir(run_dir)
    inspections = []
    class Client:
        @staticmethod
        def inspect(aid, cmdsha, include):
            assert include is False
            inspections.append((aid, cmdsha))
            r = receipt(c, aid, cmdsha)
            if receipt_bad:
                r["receipt"].update(receipt_bad)
            return r
    # Only Session's byte-pin read is mocked; fixture never calls serve(), client
    # execute(), a real UDS endpoint, native core, subprocess or a phone tool.
    original = m.read_file
    m.read_file = lambda path, limit, expected: b"fixture_pin_read"
    left, right = socket.socketpair()
    right.settimeout(2)
    session = m.Session(left, state, run_dir, c, Client, [False])
    outcome = []
    errors = []
    def work():
        try:
            outcome.append(session.run())
        except BaseException as error:
            errors.append(repr(error))
    thread = threading.Thread(target=work)
    thread.start()
    frames = []
    try:
        wire = m.encode(start(c, task, wrong_text))
        if precancel:
            wire += m.encode({"protocol": m.PROTOCOL, "kind": "turn.cancel", "seq": 1})
        right.sendall(wire)
        partial = b""
        while True:
            chunk = right.recv(65536)
            if not chunk:
                break
            partial += chunk
            while b"\n" in partial:
                raw, partial = partial.split(b"\n", 1)
                frame = m.decode(raw); frames.append(frame)
                if frame["kind"] == "tool.call":
                    call = frame["call"]
                    args = call["argv"]
                    assert args[:3] == ["/usr/bin/python3", str(m.CLIENT), "execute"]
                    assert call["timeout_ms"] == 15000
                    assert args[args.index("--timeout-ms")+1] == "3000"
                    assert base64.b64decode(args[args.index("--command-b64")+1]).decode() == m.fixed_command(c["nonce"])
                    assert all(call[k] == start(c, task)["turn"][k] for k in m.KEYS)
                    if eof:
                        right.close()
                        partial = b""
                        break
                    payload = m.encode(result(c, call["call_id"], wrong_output))
                    if postcancel:
                        payload += m.encode({"protocol": m.PROTOCOL, "kind": "turn.cancel", "seq": 2})
                    right.sendall(payload)
            if eof and right.fileno() == -1:
                break
        thread.join(2)
        assert not thread.is_alive() and not errors, errors
    finally:
        right.close()
        left.close()
        thread.join(1)
        m.read_file = original
    assert outcome and len([x for x in frames if x["kind"] == "tool.call"]) <= 1
    return {"state": state, "run": run_dir, "frames": frames, "inspections": inspections, "rc": outcome[0]}

def kind(r):
    return r["frames"][-1]["kind"] if r["frames"] else None

good_contract = contract("a"*32)
good = {}
def success():
    global good
    good = run(good_contract)
    assert good["rc"] == 0 and kind(good) == "turn.complete" and len(good["inspections"]) == 1
    assert (good["run"]/"component-outcome.json").is_file()
test("one-fixed-call-completes-only-after-native-and-original-receipt", success)
def duplicate():
    before = (good["state"]/"claims"/("a"*32+".json")).read_bytes()
    r = run(good_contract, good["state"], task="new-task-cannot-reuse-contract")
    assert r["rc"] != 0 and kind(r) == "turn.fail" and not r["inspections"]
    assert not any(x["kind"] == "tool.call" for x in r["frames"])
    assert (good["state"]/"claims"/("a"*32+".json")).read_bytes() == before
test("fresh-call-or-turn-id-cannot-bypass-consumed-nonce", duplicate)
def wrong_owner():
    r = run(contract("b"*32), wrong_text=True)
    assert kind(r) == "turn.fail" and not list((r["state"]/"claims").iterdir())
    assert not r["inspections"] and not any(x["kind"] == "tool.call" for x in r["frames"])
test("owner-byte-mismatch-dispatches-zero", wrong_owner)
def cancel_before():
    r = run(contract("c"*32), precancel=True)
    assert kind(r) == "turn.cancelled" and not r["inspections"]
    assert list((r["state"]/"claims").iterdir()) and not any(x["kind"] == "tool.call" for x in r["frames"])
test("buffered-cancel-retains-claim-with-zero-dispatch", cancel_before)
def cancel_after():
    r = run(contract("d"*32), postcancel=True)
    assert kind(r) == "turn.cancelled" and len(r["inspections"]) == 1
    assert not any(x["kind"] == "turn.complete" for x in r["frames"])
test("cancel-after-result-does-not-complete-or-redispatch", cancel_after)
def transport_eof():
    r = run(contract("e"*32), eof=True)
    assert r["rc"] != 0 and len(r["inspections"]) == 1
    assert (r["run"]/"component-failure.json").is_file()
test("disconnect-after-dispatch-inspects-only-original", transport_eof)
def bad_output():
    r = run(contract("f"*32), wrong_output=True)
    assert kind(r) == "turn.fail" and len(r["inspections"]) == 1
test("native-output-mismatch-fails-even-with-good-receipt", bad_output)
for i, bad in enumerate(({"execution_uid": 0}, {"worker_domain_verified": False},
                         {"process_group_absent": False}, {"server_instance": "0"*32},
                         {"dispatch_count": True}, {"waitpid_identity_lost": True})):
    def negative(bad=bad, i=i):
        r = run(contract(("%032x" % (i+1))), receipt_bad=bad)
        assert kind(r) == "turn.fail" and len(r["inspections"]) == 1
    test("original-receipt-rejects-"+next(iter(bad)), negative)
def no_arbitrary_command():
    for bad in (";id", "a"*31, "A"*32, "x"*32):
        try:
            m.fixed_command(bad)
        except m.Rejected:
            continue
        raise AssertionError("unsafe nonce accepted")
test("fixed-printf-generator-rejects-injection-and-malformed-nonce", no_arbitrary_command)
def duplicate_json():
    try:
        m.decode(b'{"a":1,"a":2}')
    except m.Rejected:
        return
    raise AssertionError("duplicate JSON accepted")
test("duplicate-json-member-rejected", duplicate_json)
def expiry():
    c = contract("7"*32); c["expires_unix_ms"] = 0
    r = run(c)
    assert kind(r) == "turn.fail" and not r["inspections"]
    assert not any(x["kind"] == "tool.call" for x in r["frames"])
test("expired-contract-dispatches-zero", expiry)
def error_terminal():
    c = contract("8"*32)
    value = result(c, "fixture-call")
    value["terminal"]["error"] = "synthetic native error"
    try:
        m.native_output(value, "fixture-call", m.expected_output(c["nonce"]))
    except m.Rejected:
        return
    raise AssertionError("native terminal error accepted as completed")
test("non-null-native-terminal-error-rejected", error_terminal)

report = {"schema": "hepta.native-component-probe.host-fixtures.v1",
          "status": "PASS", "checks": CHECKS, "passed": len(CHECKS),
          "source_sha256": m.sha((ROOT/"component_probe_provider.py").read_bytes()),
          "test_source_sha256": m.sha(Path(__file__).read_bytes()),
          "scope": "Synthetic host protocol frames and receipts. No actual native core, phone, SELinux transition, model or business qualification.",
          "phone_operations": 0, "model_requests": 0, "actual_native_admissions": 0}
m.create(OUT/"RESULT.json", report)
print(json.dumps({"status": "PASS", "checks": len(CHECKS),
                  "result": str(OUT/"RESULT.json"), "sha256": m.sha((OUT/"RESULT.json").read_bytes())}, indent=2))
