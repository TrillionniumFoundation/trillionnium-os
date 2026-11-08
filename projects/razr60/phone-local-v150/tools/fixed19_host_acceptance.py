#!/usr/bin/env python3
"""Fresh, isolated fixed19 host cases against an explicitly pinned private r9.

This is a new acceptance runner, not a relabelling of existing unit tests. It
does not connect to a phone, execute an Android command, start a model or edit
provider code. Synthetic native envelopes and injected decisions are labelled.
All accepted claims and case evidence stay in a newly created private run tree.
"""
from __future__ import annotations

import argparse
import ast
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import resource
import secrets
import stat
import struct
import subprocess
import sys
import threading
import time
import traceback
import types
from unittest import mock
import xml.etree.ElementTree as ET


DEFINITION_SHA = "c573959e59fd9fbe7a850d6d2d6d747e3135718493f15de4a8acde850bad93b0"
FIXTURE_SHA = "09576bc787bb4488af697b2577677bc49409c466cba2e56f0e53ccd4a6390854"
HOST_IDS = tuple("NEG-%02d" % n for n in range(4, 15))
PHYSICAL_FOLLOWUPS = {"NEG-04", "NEG-05", "NEG-07", "NEG-08", "NEG-09"}
INITIAL_CASES = ("NEG-10", "NEG-11", "NEG-12", "NEG-13", "NEG-14")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def raw_json(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def private_dir(path):
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    require(stat.S_IMODE(path.stat().st_mode) == 0o700, "private directory mode differs")
    return path


def save(path, value):
    raw = value if isinstance(value, bytes) else raw_json(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(fd)
    finally:
        os.close(fd)
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def fd_snapshot():
    result = {}
    for item in Path("/proc/self/fd").iterdir():
        try:
            result[item.name] = os.readlink(item)
        except FileNotFoundError:
            pass  # The directory enumeration's own descriptor is already closed.
    return result


def child_pids():
    path = Path("/proc/self/task") / str(os.getpid()) / "children"
    return sorted(int(value) for value in path.read_text().split())


def b64(raw):
    return base64.b64encode(raw).decode()


def fresh_identity(scope=None):
    token = secrets.token_hex(16)
    return {"session_id": (scope or {}).get("session_id", "session-" + token),
            "profile_id": (scope or {}).get("profile_id", "profile-" + token),
            "task_id": "task-" + token, "turn_id": "turn-" + token,
            "turn_stream_id": "stream-" + secrets.token_hex(16)}


def load_modules(source, fixture_path, overlay_manifest):
    require(source.is_absolute() and source.resolve(strict=True) == source, "canonical private source required")
    require((source / "ledger_round_evidence.py").is_file(), "actual r9 LedgerPrefix source required; no public r7 fallback")
    manifest = json.loads(overlay_manifest.read_bytes())
    expected = manifest["candidate_sha256"]
    actual = {p.name: sha(p.read_bytes()) for p in source.glob("*.py")}
    require(expected == actual, "private overlay source closure differs")
    require(sha(fixture_path.read_bytes()) == FIXTURE_SHA, "actual private host fixture pin differs")
    os.environ["HEPTA_PROVIDER_TEST_SOURCE"] = str(source)
    sys.path.insert(0, str(source))
    import daily_phone_local as daily  # Executes the real PARENTS checks.
    import provider_phone_local as provider
    import provider_codex_host as codex
    import phone_observation_tools as observations
    import phone_task_guards as guards
    import task_postconditions as contracts
    spec = importlib.util.spec_from_file_location("fixed19_actual_r9_fixture", fixture_path)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    for module in (daily, provider, codex, observations, guards, contracts):
        require(Path(module.__file__).resolve().parent == source, "module escaped selected actual source")
    return types.SimpleNamespace(f=fixture, daily=daily, provider=provider, codex=codex,
        observations=observations, guards=guards, contracts=contracts, source=source,
        source_sha256=actual, overlay_manifest_sha256=sha(overlay_manifest.read_bytes()))


class FixtureSession:
    """Use only helper methods from the pinned existing fixture, never its tests."""
    def __init__(self, modules, root):
        self.m, self.root = modules, private_dir(root)
        self.fd_before, self.children_before = fd_snapshot(), child_pids()
        f = modules.f
        self.h = f.ProviderFixture()
        self.h.root = self.root
        self.h.evidence = private_dir(self.root / "evidence")
        private_dir(self.h.evidence / "claims")
        self.h.counter, self.h.adapters = 0, []
        self.pin = mock.patch("phone_local_tools.validate_executor", side_effect=lambda value, **_: value)
        self.pin.start()
        self.closed_writers = set()
        self.rows = []
        save(self.root / "LAYER.json", {"layer": "host_isolated", "synthetic_native_envelopes": True,
            "model_decisions": "deterministic_fixture_not_model_generated", "phone_actions": 0,
            "external_file_location_check_injected": True, "original_parser_ledger_and_claims_used": True})

    def adapter(self, *, identity=None, nonce=None, request=None, contract=None, accept=True):
        identity = identity or fresh_identity()
        nonce = nonce or secrets.token_hex(16)
        request = request or "只执行本次隔离主机验收。新标记：" + nonce
        require(request.count(nonce) == 1, "fresh nonce must occur exactly once in the exact request")
        a = self.h.adapter(identity=identity, request=request, accept=False, profile=self.m.f.LEGACY_PROFILE)
        if contract is not None:
            directory = self.root / "task-contracts"
            if not directory.exists():
                private_dir(directory)
            a.args.contracts = directory
            value = {"schema": "hepta.task-contract.v149.1", "identity": {k: identity[k] for k in self.m.contracts.IDENTITY},
                "request_sha256": sha(request.encode()), "postconditions": contract["postconditions"], "coverage": contract["coverage"]}
            save(directory / (self.m.contracts.identity_key(identity) + ".json"), value)
        a._fixed19_request, a._fixed19_identity, a._fixed19_nonce = request, identity, nonce
        if accept:
            self.admit(a)
        return a

    def admit(self, a):
        self.h.send(a, {"protocol": self.m.f.PROTOCOL, "seq": 0, "kind": "turn.start",
                       "turn": {**a._fixed19_identity, "user_input": a._fixed19_request}})
        result = a.receive("turn.start", timeout=1)
        require(result is not None and a.claimed and a.accepted_identity == a._fixed19_identity, "turn admission absent")
        require(a.operation_profile["max_tool_calls"] == 7 and a.operation_profile["max_rounds"] == 8
                and a.operation_profile["max_duration_seconds"] == 300, "original fixed19 bounds changed")
        require(a.phone_tools.max_turn_image_bytes == 393216, "fixed19 image budget changed")
        self.claim(a)
        return result

    def claim(self, a):
        path = self.h.evidence / "claims" / self.m.contracts.identity_key(a._fixed19_identity)
        raw = path.read_bytes(); value = json.loads(raw)
        require(value["state"] == "accepted_no_redispatch" and value["identity"] == a._fixed19_identity
                and value["request_sha256"] == sha(a._fixed19_request.encode())
                and value["run_dir"] == str(a.run_dir), "durable accepted claim differs")
        return {"path": str(path.relative_to(self.root)), "sha256": sha(raw)}

    def decision(self, a, tool, argv=(), command="", *, round_number=1):
        a.round = a.phone_tools.round = round_number
        call = "r%02d_%s" % (round_number, secrets.token_hex(8))
        self.h.bind_host_request(a, call)
        value = {"kind": "tool.call", "call_id": call, "tool": tool, "command": command,
                 "argv": list(argv), "summary": "Deterministic host fixture decision", "task_status": "in_progress"}
        a._decision(value, call)
        return a.phone_tools.calls[call]

    def dispatch(self, a, record):
        a.tool_count = len(a.dispatched_calls) + 1
        a.emit("tool.call", call=record["wire_call"])
        require(record["call_id"] in a.dispatched_calls, "synthetic dispatch frame not emitted")

    def receive_receipt(self, a, record, raw):
        reply = self.m.f.native_result(record["call_id"], raw)
        reply["seq"] = a.in_seq
        self.h.send(a, reply)
        original = a.receive("tool.result", timeout=1)
        messages = [{"role": "tool", "tool_call_id": record["call_id"], "content": json.dumps(original)}]
        a.phone_tools.prepare(messages, messages, a.round + 1)
        a.action_ledger.confirm_validated_results(a.phone_tools)
        return original

    def fail(self, a, message="expected isolated fixed19 rejection"):
        if a.terminal is None:
            a.emit("turn.fail", error=message)
        outcome = json.loads((a.run_dir / "business-outcome.json").read_bytes())
        require(outcome["business_verified"] is False and a.terminal != "turn.complete", "negative case became business success")
        return outcome

    def close(self):
        for a, writer in self.h.adapters:
            a.frames.close(); a.inputs.close(); a.source.close()
            if writer not in self.closed_writers:
                os.close(writer)
        self.pin.stop()
        after, children = fd_snapshot(), child_pids()
        require(after == self.fd_before, "host fixture file descriptors did not return to baseline")
        require(children == self.children_before, "host fixture child process baseline changed")
        save(self.root / "RESOURCE-CLEANUP.json", {"fd_before": self.fd_before, "fd_after": after,
            "children_before": self.children_before, "children_after": children, "returned_to_baseline": True,
            "retained_evidence_deleted": False})

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def expect_rejection(m, action):
    try:
        action()
    except m.f.ProviderError as error:
        return {"type": type(error).__name__, "message": str(error)}
    raise AssertionError("invalid condition was accepted")


def case10(m, root):
    rows = []
    for variant in ("remaining_65535", "age_over_120", "foreign_call_id", "noncurrent_round"):
        with FixtureSession(m, root / variant) as h:
            a = h.adapter(); image_id = "r01_" + secrets.token_hex(8)
            if variant == "remaining_65535":
                a.phone_tools.encoded_bytes_used = 393216 - 65535
                decision = {"call_id": "r01_" + secrets.token_hex(8), "tool": "phone.screenshot", "command": "", "argv": ["0"]}
            else:
                a.round = a.phone_tools.round = 2
                a.phone_tools.latest = m.f.fresh_image(a.accepted_identity, call_id=image_id)
                if variant == "age_over_120":
                    a.phone_tools.latest["received_monotonic"] = time.monotonic() - 121
                elif variant == "noncurrent_round":
                    a.phone_tools.latest["attached_round"] = 1
                decision = {"call_id": "r02_" + secrets.token_hex(8), "tool": "phone.tap", "command": "",
                    "argv": [("r01_" + secrets.token_hex(8)) if variant == "foreign_call_id" else image_id, "100", "100"]}
            rejected = expect_rejection(m, lambda: a.phone_tools.map(decision))
            require(not a.phone_tools.calls and not a.dispatched_calls and not a.phone_tools.verified_facts, "invalid image caused a dispatch or fact")
            require(m.observations.MAX_IMAGE_BYTES == 196608 and a.phone_tools.max_turn_image_bytes == 393216, "image limit extended")
            h.fail(a)
            rows.append({"variant": variant, "rejection": rejected, "claim": h.claim(a), "dispatches": 0})
    return rows, [True, True, True], []


def structural_jpeg_fixture():
    # Intentionally only the original parser's structural JPEG contract. This
    # is not a real capture or an independent pixel-decoder qualification.
    seg = lambda marker, data: b"\xff" + bytes([marker]) + struct.pack(">H", len(data) + 2) + data
    return b"\xff\xd8" + seg(219, b"\0") + seg(196, b"\0") + seg(192, struct.pack(">BHHB", 8, 1496, 612, 1) + b"\1\x11\0") + seg(218, b"\1\1\0\0\x3f\0") + b"\x12\x23\x34\x45" + b"\xff\xd9"


def receipt_payload(m, record, kind, *, text="synthetic public value"):
    package = "com.example.calculator"
    if kind == "image":
        image = structural_jpeg_fixture()
        screenshot = {"schema": "hepta.phone-screenshot.v1", "status": "encoded", "capture_id": record["capture_id"],
            "serial": m.observations.SERIAL, "logical_display_id": 0, "physical_display_id": m.observations.PHYSICAL_DISPLAY,
            "rotation": 0, "viewport_before": m.f.VIEWPORT, "viewport_after": m.f.VIEWPORT,
            "original_width": 1224, "original_height": 2992, "encoded_width": 612, "encoded_height": 1496,
            "media_type": "image/jpeg", "encoding": "base64", "quality": 80, "data_base64": b64(image),
            "image_sha256": sha(image), "source_png_sha256": sha(m.f.PNG), "source_png_bytes": len(m.f.PNG), "encoded_bytes": len(image)}
        return {"schema": "hepta.capture-page-envelope.v149.1", "capture_id": record["capture_id"],
                "page_before_b64": b64(m.f.PAGE.encode()), "page_after_b64": b64(m.f.PAGE.encode()), "screenshot": screenshot}
    if kind == "return":
        component = m.guards.HEPTA_FULL_COMPONENT
        page = m.f.PAGE.replace("com.example.calculator/.Calculator", component)
        return {"schema": "hepta.return-receipt.v149.1", "operation_id": record["capture_id"], "launch_exit_code": 0,
                "launch_b64": b64(("Status: ok\nActivity: " + component + "\n").encode()),
                "page_b64": b64(page.encode()), "viewport_b64": b64(m.f.VIEWPORT.encode())}
    hierarchy = ET.Element("hierarchy", {"rotation": "0"})
    values = text if isinstance(text, dict) else {package + ":id/value": text}
    for view, value in values.items():
        ET.SubElement(hierarchy, "node", {"resource-id": view, "text": value, "package": package,
            "password": "false", "enabled": "true", "visible-to-user": "true", "bounds": "[10,20][400,180]"})
    return {"schema": "hepta.public-text-receipt.v149.1", "operation_id": record["capture_id"], "package": package,
            "page_before_b64": b64(m.f.PAGE.encode()), "page_after_b64": b64(m.f.PAGE.encode()),
            "viewport_before_b64": b64(m.f.VIEWPORT.encode()), "viewport_after_b64": b64(m.f.VIEWPORT.encode()),
            "xml_b64": b64(ET.tostring(hierarchy, encoding="utf-8"))}


def map_receipt_case(h, a, kind):
    tool, argv = {"image": ("phone.screenshot", ["0"]), "text": ("phone.read_text", ["com.example.calculator", "com.example.calculator:id/value"]),
                  "return": ("phone.return_hepta", [])}[kind]
    return h.decision(a, tool, argv)


def case11(m, root):
    rows = []
    common = ("outer_call_id", "event_call_id", "event_sequence", "output_byte_count", "terminal_byte_count", "terminal_exit", "truncation", "invalid_base64", "operation_binding")
    for kind in ("image", "text", "return"):
        variants = ("positive_control",) + common + (("image_hash", "source_hash", "source_serial") if kind == "image" else ())
        for variant in variants:
            with FixtureSession(m, root / (kind + "-" + variant)) as h:
                a = h.adapter(); record = map_receipt_case(h, a, kind)
                payload = receipt_payload(m, record, kind)
                if variant == "operation_binding":
                    payload["capture_id" if kind == "image" else "operation_id"] = secrets.token_hex(16)
                elif variant == "image_hash":
                    payload["screenshot"]["image_sha256"] = "0" * 64
                elif variant == "source_hash":
                    payload["screenshot"]["source_png_sha256"] = "not-a-sha256"
                elif variant == "source_serial":
                    payload["screenshot"]["serial"] = "FOREIGN_SYNTHETIC_DEVICE"
                reply = m.f.native_result(record["call_id"], raw_json(payload))
                if variant == "outer_call_id": reply["call_id"] = "r01_" + secrets.token_hex(8)
                elif variant == "event_call_id": reply["events"][1]["call_id"] = "r01_" + secrets.token_hex(8)
                elif variant == "event_sequence": reply["events"][1]["seq"] = 9
                elif variant == "output_byte_count": reply["events"][2]["event"]["byte_count"] += 1
                elif variant == "terminal_byte_count": reply["terminal"]["stdout_bytes"] += 1
                elif variant == "terminal_exit": reply["terminal"]["exit_code"] = 17
                elif variant == "truncation": reply["terminal"]["output_truncated"] = True
                elif variant == "invalid_base64": reply["events"][2]["event"]["data"] = "%%%"
                messages = [{"role": "tool", "tool_call_id": record["call_id"], "content": json.dumps(reply)}]
                save(a.run_dir / "synthetic-envelope-under-test.json", {"host_fixture_only": True, "original_envelope": reply})
                action = lambda: a.phone_tools.prepare(messages, messages, 2)
                if variant == "positive_control":
                    action(); rejection = None
                    require(bool(a.phone_tools.images if kind == "image" else a.phone_tools.verified_facts), "positive control did not qualify its retained shape")
                else:
                    rejection = expect_rejection(m, action)
                    require(not a.phone_tools.images and not a.phone_tools.verified_facts and not a.phone_tools.latest,
                            "malformed envelope supplied an image/text/return fact")
                    require(not a.phone_tools.local_observations, "malformed envelope supplied a local observation")
                require(not a.dispatched_calls, "parser fixture dispatched a tool")
                h.fail(a)
                rows.append({"kind": kind, "variant": variant, "positive_control": variant == "positive_control",
                    "rejection": rejection, "claim": h.claim(a), "synthetic_envelope_sha256": sha(raw_json(reply))})
    return rows, [True, True, True], []


def input_receipt(record):
    text, before = record["requested_text"].encode(), record["expected_text"].encode()
    return {"schema": "hepta.focused-unicode-input.v1", "status": "set_verified", "operation_id": record["call_id"],
            "display_id": 0, "package": record["package"], "view_id": record["view_id"],
            "requested_utf8_sha256": sha(text), "before_utf8_sha256": sha(before), "after_utf8_sha256": sha(text),
            "own_automation_disconnected": True, "action_attempted": True, "effect_state": "observed_exact_requested_text",
            "readback_text_b64": b64(text)}


def case12(m, root):
    rows = []
    package = "com.example.calculator"
    for variant in ("input_only", "public_receipt_without_return", "declared_postconditions_only"):
        with FixtureSession(m, root / variant) as h:
            nonce = secrets.token_hex(16)
            text = '中文🙂\n"quoted" literal $;& ' + nonce
            receipt = "HEPTA_UNICODE_READBACK\nsha256=%s\ncodepoints=%d\nutf8_bytes=%d" % (sha(text.encode()), len(text), len(text.encode()))
            conditions = [
                {"id": "editor", "kind": "text_readback_exact", "package": package, "view_id": package + ":id/unicode_input", "utf8_sha256": sha(text.encode())},
                {"id": "public_receipt", "kind": "public_text_exact", "package": package, "view_id": package + ":id/unicode_receipt", "utf8_sha256": sha(receipt.encode())},
                {"id": "return", "kind": "foreground_hepta"}]
            contract = {"postconditions": conditions, "coverage": "declared_postconditions_only" if variant == "declared_postconditions_only" else "entire_request"}
            a = h.adapter(nonce=nonce, request="输入以下原文并核验公开回执，最后返回HEPTA：\n" + text, contract=contract)
            first = h.decision(a, "phone.input_text", [package, package + ":id/unicode_input", ""], text)
            h.dispatch(a, first); h.receive_receipt(a, first, raw_json(input_receipt(first)))
            if variant != "input_only":
                second = h.decision(a, "phone.read_text", [package, package + ":id/unicode_receipt"], round_number=2)
                h.dispatch(a, second); h.receive_receipt(a, second, raw_json(receipt_payload(m, second, "text", text={package + ":id/unicode_receipt": receipt})))
            if variant == "declared_postconditions_only":
                third = h.decision(a, "phone.return_hepta", round_number=3)
                h.dispatch(a, third); h.receive_receipt(a, third, raw_json(receipt_payload(m, third, "return")))
            a._decision({"kind": "turn.complete", "call_id": "", "tool": "none", "command": "", "argv": [],
                "summary": "Synthetic model claims the whole task completed", "task_status": "completed"}, "unused")
            a.emit("turn.complete", summary="Synthetic model claims the whole task completed")
            outcome = json.loads((a.run_dir / "business-outcome.json").read_bytes())
            wire = json.loads(a.sink.getvalue().splitlines()[-1])
            require(wire["kind"] == "turn.fail" and "business_not_verified" in wire["error"], "partial task was emitted as complete")
            require(outcome["business_verified"] is False and outcome["model_reported_status"] == "completed", "model summary concealed incomplete business")
            expected = {"input_only": {"public_receipt", "return"}, "public_receipt_without_return": {"return"}, "declared_postconditions_only": set()}[variant]
            require(set(outcome["missing_postconditions"]) == expected, "missing conditions differ")
            if variant == "declared_postconditions_only":
                require(outcome["postconditions_verified"] is True and outcome["coverage"] == variant, "coverage-only rejection not exercised")
            rows.append({"variant": variant, "wire_kind": wire["kind"], "outcome_sha256": sha((a.run_dir / "business-outcome.json").read_bytes()),
                "missing_postconditions": sorted(expected), "coverage": outcome["coverage"], "claim": h.claim(a),
                "synthetic_confirmed_receipts": len(a.dispatched_calls), "phone_effects": 0})
    return rows, [True, True, True], []


def case13(m, root):
    with FixtureSession(m, root / "one-time-template") as h:
        contracts = private_dir(h.root / "task-contracts")
        templates = private_dir(contracts / "templates"); bindings = private_dir(contracts / "bindings")
        nonce = secrets.token_hex(16); request = "只读主机模板竞争验收，唯一标记：" + nonce
        scope = {k: v for k, v in fresh_identity().items() if k in ("session_id", "profile_id")}
        template = {"schema": "hepta.task-template.v149.1", "expected_scope": scope, "request_sha256": sha(request.encode()),
            "nonce": nonce, "postconditions": [{"id": "return", "kind": "foreground_hepta"}], "coverage": "entire_request"}
        template_path = templates / (sha(request.encode()) + ".json"); save(template_path, template)
        template_bytes = template_path.read_bytes()
        def create(identity):
            a = h.adapter(identity=identity, nonce=nonce, request=request, accept=False); a.args.contracts = contracts
            return a
        wrong = create(fresh_identity({**scope, "profile_id": "wrong-" + secrets.token_hex(16)}))
        wrong_rejected = expect_rejection(m, lambda: h.admit(wrong))
        require(not list(bindings.iterdir()) and template_path.read_bytes() == template_bytes, "wrong scope consumed the template")
        competitors = [create(fresh_identity(scope)) for _ in range(2)]
        barrier = threading.Barrier(2); results = []
        def admission(index, adapter):
            try:
                barrier.wait(timeout=5); h.admit(adapter)
                results.append({"index": index, "accepted": True})
            except m.f.ProviderError as error:
                results.append({"index": index, "accepted": False, "error": str(error)})
            except BaseException as error:
                results.append({"index": index, "unexpected": type(error).__name__ + ": " + str(error)})
        threads = [threading.Thread(target=admission, args=(i, a)) for i, a in enumerate(competitors)]
        for t in threads: t.start()
        for t in threads: t.join(6)
        require(not any(t.is_alive() for t in threads), "template admissions did not join")
        require(len(results) == 2 and not any("unexpected" in row for row in results)
                and sum(row["accepted"] for row in results) == 1, "O_EXCL template competition was not exactly one winner")
        binding_files = list(bindings.iterdir()); require(len(binding_files) == 1, "one binding required")
        binding_bytes = binding_files[0].read_bytes(); binding = json.loads(binding_bytes)
        require(binding["state"] == "consumed_no_reuse" and binding["nonce"] == nonce, "consumption binding differs")
        winner = competitors[next(row["index"] for row in results if row["accepted"])]
        new_turn = create(fresh_identity(scope))
        new_rejected = expect_rejection(m, lambda: h.admit(new_turn))
        replacement = create({**winner._fixed19_identity, "turn_stream_id": "stream-" + secrets.token_hex(16)})
        stream_rejected = expect_rejection(m, lambda: h.admit(replacement))
        require(binding_files[0].read_bytes() == binding_bytes and template_path.read_bytes() == template_bytes, "consumed binding/template rewritten")
        require(all(not a.dispatched_calls for a, _ in h.h.adapters), "template rejection dispatched a task")
        claims = {p.name: sha(p.read_bytes()) for p in (h.h.evidence / "claims").iterdir()}
        require(len(claims) == 4, "failed admission claims were removed or a replacement identity was consumed twice")
        h.fail(winner)
        rows = [{"wrong_scope_rejection": wrong_rejected, "race": results, "new_turn_rejection": new_rejected,
            "replacement_stream_rejection": stream_rejected, "binding_sha256": sha(binding_bytes),
            "template_sha256": sha(template_bytes), "claims_retained": claims, "dispatches": 0}]
    return rows, [True, True, True], []


def original_capacity(m, args):
    tree = ast.parse((m.source / "daily_phone_local.py").read_bytes())
    serve = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "serve")
    capacity = next(n for n in serve.body if isinstance(n, ast.FunctionDef) and n.name == "capacity")
    module = ast.Module(body=[copy.deepcopy(capacity)], type_ignores=[]); ast.fix_missing_locations(module)
    namespace = dict(vars(m.daily), args=args)
    exec(compile(module, str(m.source / "daily_phone_local.py") + ":unchanged_nested_capacity", "exec"), namespace)
    return namespace["capacity"], sha(ast.dump(capacity, include_attributes=False).encode())


def case14(m, root):
    rows = []
    with FixtureSession(m, root / "evidence-scan") as h:
        a = h.adapter(); claims_before = {p.name: p.read_bytes() for p in (h.h.evidence / "claims").iterdir()}
        run = private_dir(h.h.evidence / (time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(16)))
        temporary = run / "terminal.json.new"; save(temporary, {"synthetic_fixture": True})
        enumerated = list(run.iterdir()); require(temporary in enumerated, "rename race was not enumerated")
        os.replace(temporary, run / "terminal.json")
        require(m.daily.evidence_item_size(temporary, h.h.evidence) is None, "recognized atomic rename race rejected")
        unknown = run / "unrecognized.new"; save(unknown, b"fixture")
        list(run.iterdir()); os.replace(unknown, run / "unrecognized-retained")
        for missing in (unknown, run / "missing-canonical.json"):
            try: m.daily.evidence_item_size(missing, h.h.evidence)
            except FileNotFoundError: pass
            else: raise AssertionError("unknown missing evidence was silently ignored")
        blocked = private_dir(run / "unreadable-parent"); save(blocked / "existing.json", b"fixture")
        blocked.chmod(0)
        try:
            try: m.daily.evidence_item_size(blocked / "existing.json", h.h.evidence)
            except PermissionError: io_rejected = True
            else: io_rejected = False
        finally:
            blocked.chmod(0o700)
        require(io_rejected, "actual unreadable-path test unavailable or I/O failure was ignored")
        link = run / "not-regular"; link.symlink_to(run / "terminal.json")
        try: m.daily.evidence_item_size(link, h.h.evidence)
        except RuntimeError: pass
        else: raise AssertionError("nonregular evidence was accepted")
        # Retain the symlink case outside the scanned tree after checking it.
        os.replace(link, h.root / "retained-nonregular-scan-case")
        args = types.SimpleNamespace(state=h.root, evidence=h.h.evidence, workers=1, max_evidence_bytes=1)
        total = sum(p.stat().st_size for p in h.h.evidence.rglob("*") if p.is_file())
        reserve = 128 * m.daily.MAX_LINE
        capacity, code_hash = original_capacity(m, args)
        args.max_evidence_bytes = total + reserve
        require(capacity() is False, "exact evidence byte boundary was admitted")
        args.max_evidence_bytes += 1
        require(capacity() is True, "one-byte capacity margin or free-space precondition was not available")
        claims_after = {p.name: p.read_bytes() for p in (h.h.evidence / "claims").iterdir()}
        require(claims_before == claims_after, "capacity scan changed or deleted an accepted claim")
        h.fail(a)
        rows.append({"recognized_rename_race_tolerated": True, "unknown_missing_rejected": True, "actual_unreadable_path_rejected": True,
            "nonregular_rejected": True, "capacity_exact_boundary_rejected": True, "capacity_one_byte_margin_admitted": True,
            "capacity_test_method": "unchanged_actual_nested_function_AST_in_original_module_globals",
            "capacity_ast_sha256": code_hash, "claims_unchanged": True, "claim": h.claim(a)})
    # The startup orphan guard and whole serve() resource lifecycle are not
    # simulated or claimed by the nested capacity-function check above.
    return rows, [True, True, None], ["Retained orphan-spawn startup and whole worker/child cleanup not yet exercised; this case remains partial."]


CASES = {"NEG-10": case10, "NEG-11": case11, "NEG-12": case12, "NEG-13": case13, "NEG-14": case14}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=os.environ.get("HEPTA_PROVIDER_TEST_SOURCE"))
    parser.add_argument("--overlay-manifest", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--definition", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cases", nargs="+", choices=HOST_IDS, default=INITIAL_CASES)
    args = parser.parse_args()
    require(args.source is not None, "explicit actual private provider source required")
    args.source = Path(args.source).resolve(strict=True)
    definition_raw = args.definition.read_bytes(); require(sha(definition_raw) == DEFINITION_SHA, "original fixed19 definition pin differs")
    definition = json.loads(definition_raw)
    require(definition["case_count"] == 19 and definition["limits"]["maximum_sequential_tool_calls_before_final_summary"] == 7
            and definition["limits"]["model_rounds"] == 8 and definition["limits"]["turn_deadline_seconds"] == 300,
            "original fixed19 scope or limits differ")
    require(len(set(args.cases)) == len(args.cases), "a case cannot be retried within a run")
    os.umask(0o077)
    out = private_dir(args.out.absolute())
    started = time.time(); usage_before = resource.getrusage(resource.RUSAGE_SELF)
    m = load_modules(args.source, args.fixture, args.overlay_manifest)
    report = {"schema": "hepta.fixed19-independent-host-run.v1", "run_id": secrets.token_hex(16),
        "definition_sha256": DEFINITION_SHA, "definition_set_id": definition["set_id"], "original_definition_modified": False,
        "runner_sha256": sha(Path(__file__).read_bytes()), "source_sha256": m.source_sha256,
        "source_overlay_manifest_sha256": m.overlay_manifest_sha256, "private_fixture_sha256": FIXTURE_SHA,
        "fixed19_total_cases": 19, "requested_host_cases": args.cases, "host_only": True,
        "phone_actions": 0, "model_inference_requests": 0, "external_model_requests": 0,
        "production_source_or_claims_modified": False, "model_usage": None, "cost": {"external_model_cost": 0},
        "cases": [], "started_unix": started}
    definitions = {item["id"]: item for item in definition["cases"]}
    for case_id in args.cases:
        case_root = private_dir(out / case_id); t0 = time.monotonic()
        rows, checks, gaps, error = [], [None] * len(definitions[case_id]["pass_postconditions"]), [], None
        if case_id in CASES:
            try:
                rows, checks, gaps = CASES[case_id](m, case_root)
            except BaseException as exc:
                error = {"type": type(exc).__name__, "message": str(exc)}
                save(case_root / "failure-traceback.txt", traceback.format_exc().encode())
                gaps.append("Execution stopped at the recorded exception; earlier fragments are not a case pass.")
        else:
            gaps.append("Not implemented in this runner revision; no replacement coverage claimed.")
        host_pass = error is None and checks and all(value is True for value in checks)
        physical_pending = case_id in PHYSICAL_FOLLOWUPS
        row = {"id": case_id, "title": definitions[case_id]["title"], "layer": "host_isolated",
            "host_status": "PASS" if host_pass else "FAIL" if error else "PARTIAL" if rows else "NOT_RUN",
            "fixed19_case_complete": bool(host_pass and not physical_pending), "physical_followup_pending": physical_pending,
            "postconditions": [{"text": text, "verified": checks[index]} for index, text in enumerate(definitions[case_id]["pass_postconditions"])],
            "subcases": rows, "gaps": gaps, "error": error, "elapsed_seconds": time.monotonic() - t0,
            "phone_actions": 0, "evidence_restoration": "new private fixtures retained; no production baseline was modified"}
        save(case_root / "CASE-RESULT.json", row); report["cases"].append(row)
        print(json.dumps({"id": case_id, "host_status": row["host_status"], "fixed19_case_complete": row["fixed19_case_complete"],
                          "subcases": len(rows), "error": error}, ensure_ascii=False), flush=True)
    after = {p.name: sha(p.read_bytes()) for p in args.source.glob("*.py")}
    require(after == m.source_sha256 and sha(args.definition.read_bytes()) == DEFINITION_SHA, "source or fixed definition changed during run")
    report.update(source_unchanged=True, definition_unchanged=True, finished_unix=time.time(),
        host_pass_count=sum(row["host_status"] == "PASS" for row in report["cases"]),
        fixed19_complete_count=sum(row["fixed19_case_complete"] for row in report["cases"]),
        all_19_pass=False, installed_lifecycle_qualified=False,
        resources={"self_user_cpu_seconds": resource.getrusage(resource.RUSAGE_SELF).ru_utime - usage_before.ru_utime,
                   "self_system_cpu_seconds": resource.getrusage(resource.RUSAGE_SELF).ru_stime - usage_before.ru_stime,
                   "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss})
    save(out / "RESULT.json", report)
    evidence = [{"path": str(p.relative_to(out)), "bytes": p.stat().st_size, "sha256": sha(p.read_bytes())}
                for p in sorted(out.rglob("*")) if p.is_file() and not p.is_symlink()]
    save(out / "EVIDENCE-MANIFEST.json", {"schema": "hepta.fixed19-host-evidence.v1", "files": evidence})
    print(json.dumps({"result": str(out / "RESULT.json"), "sha256": sha((out / "RESULT.json").read_bytes()),
        "host_pass_count": report["host_pass_count"], "fixed19_complete_count": report["fixed19_complete_count"], "of_original_19": 19}), flush=True)
    return 1 if any(row["host_status"] == "FAIL" for row in report["cases"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
