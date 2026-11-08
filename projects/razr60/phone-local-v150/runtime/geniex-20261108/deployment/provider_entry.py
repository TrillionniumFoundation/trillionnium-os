#!/usr/bin/env python3
"""Pinned same-process GNU entry after the init-owned native preflight.

This code neither creates a new SELinux domain nor acquires capabilities. It
checks the capabilities inherited across exec, checks the original native
endpoint without dispatching an action, and runs the selected daily provider in
this interpreter. It does not spawn a CPU server or repair owner claims.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys

CONTEXT = "u:r:trillionnium_owner_open_bootstrap:s0"
CAPS = (1 << 0) | (1 << 1) | (1 << 5) | (1 << 18)
STATE = Path("/var/lib/trillionnium/owner-open")


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def private_file(path, maximum=8 * 1024 * 1024):
    path = Path(path)
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent, "noncanonical private parent")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o600 and 0 <= before.st_size <= maximum,
                "private file identity differs")
        raw = bytearray()
        while len(raw) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after, named = os.fstat(fd), path.lstat()
        fields = ("st_dev", "st_ino", "st_size", "st_mode", "st_uid", "st_gid", "st_nlink", "st_mtime_ns", "st_ctime_ns")
        require(len(raw) == before.st_size and all(getattr(before, key) == getattr(after, key) == getattr(named, key)
                                                 for key in fields), "private file changed")
        return bytes(raw)
    finally:
        os.close(fd)


def config_contract(value):
    require(isinstance(value, dict) and set(value) == {
        "schema", "instance", "source_sha256", "base_config_sha256", "geniex_config_sha256", "retained_claims_sha256",
        "stage", "mode"}, "entry config fields differ")
    require(value["schema"] == "hepta.geniex-provider-start.v1" and
            isinstance(value["instance"], str) and re.fullmatch("[0-9a-f]{32}", value["instance"]), "entry identity differs")
    require(value["mode"] in {"preflight_only", "serve"}, "unselected entry mode")
    require(isinstance(value["source_sha256"], dict) and 10 <= len(value["source_sha256"]) <= 64,
            "source set differs")
    require({"daily_phone_local.py", "native_backend.py", "provider_bridge.py", "startup_health.py"} <= set(value["source_sha256"]),
            "required source absent")
    for name, digest in value["source_sha256"].items():
        require(re.fullmatch(r"[a-z][a-z0-9_]*\.py", name) and isinstance(digest, str) and
                re.fullmatch("[0-9a-f]{64}", digest), "source pin differs")
    for key in ("base_config_sha256", "geniex_config_sha256", "retained_claims_sha256"):
        require(isinstance(value[key], str) and re.fullmatch("[0-9a-f]{64}", value[key]), "configuration hash absent")
    require(isinstance(value["stage"], dict) and set(value["stage"]) == {"st_dev", "st_ino"}
            and all(type(value["stage"][key]) is int for key in value["stage"])
            and value["stage"]["st_dev"] >= 0 and value["stage"]["st_ino"] > 0, "stage identity differs")
    return value


def actual_identity():
    require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, "provider is not actual UID/GID zero")
    context = Path("/proc/self/attr/current").read_text().rstrip("\n\0")
    require(context == CONTEXT, "provider did not inherit the real bootstrap domain")
    status = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        key, separator, value = line.partition(":")
        if separator:
            status[key] = value.strip()
    require(int(status["CapEff"], 16) == CAPS and int(status["CapPrm"], 16) == CAPS,
            "provider capabilities changed across exec")
    return {"pid": os.getpid(), "context": context, "CapEff": status["CapEff"], "CapPrm": status["CapPrm"]}


def no_stop():
    try:
        (STATE / "emergency-stop").lstat()
    except FileNotFoundError:
        require(STATE.is_dir() and STATE.resolve(strict=True) == STATE, "state unavailable while checking stop")
    else:
        raise RuntimeError("owner stop is present")


def native_health(source):
    sys.path.insert(0, str(source))
    import native_backend
    value = native_backend.R6Transport().exchange({"op": "health"}, timeout=2.0)
    require(isinstance(value, dict) and value.get("version") == 1 and type(value.get("version")) is int
            and value.get("protocol") == "hepta_phone_local_v150" and value.get("executor_revision") == 6
            and type(value.get("executor_revision")) is int and value.get("state") == "ready"
            and value.get("execute_authorized") is True
            and value.get("executor_context") == "u:r:trillionnium_owner_open_phone_executor:s0"
            and value.get("peer_context") == CONTEXT
            and value.get("required_worker_context") == "u:r:trillionnium_owner_open_phone_worker:s0"
            and isinstance(value.get("server_instance"), str) and re.fullmatch("[0-9a-f]{32}", value["server_instance"]),
            "actual native endpoint is not ready for this bootstrap caller")
    return value


def record_post_exec(candidate, value, config_sha256, identity, health, boot_id):
    require(isinstance(boot_id, str) and re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", boot_id), "kernel boot identity differs")
    evidence = candidate / "startup-evidence"
    info = evidence.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
            stat.S_IMODE(info.st_mode) == 0o700 and evidence.resolve(strict=True) == evidence,
            "startup evidence directory differs")
    intent_raw = private_file(evidence / ("entry-" + boot_id + ".json"), 131072)
    intent = strict_json(intent_raw)
    plan_raw = private_file(candidate / "startup/entry-plan.json", 131072)
    plan = strict_json(plan_raw)
    require(intent.get("schema") == "hepta.geniex-provider-entry-intent.v1" and
            intent.get("instance") == value["instance"] and intent.get("pid") == identity["pid"] and
            type(intent.get("pid")) is int and intent.get("ppid") == 1 and type(intent.get("ppid")) is int and
            intent.get("context") == CONTEXT and intent.get("effective_capabilities") == CAPS and
            type(intent.get("effective_capabilities")) is int and intent.get("permitted_capabilities") == CAPS and
            type(intent.get("permitted_capabilities")) is int and intent.get("stage") == value["stage"] and
            intent.get("state") == "validated_exec_intent_not_ready" and
            intent.get("entry_plan_sha256") == sha(plan_raw) and plan.get("launch_config_sha256") == config_sha256,
            "post-exec process is not bound to the original init entry intent")
    record = {"schema": "hepta.geniex-provider-post-exec-preflight.v1", "instance": value["instance"],
              "mode": value["mode"], "boot_id": boot_id, "identity": identity, "native_health": health,
              "entry_intent_sha256": sha(intent_raw), "entry_plan_sha256": sha(plan_raw),
              "launch_config_sha256": config_sha256, "stage": value["stage"],
              "state": "identity_and_health_verified_provider_listen_not_yet_proved",
              "model_executed": False, "phone_action_executed": False, "model_or_app_qualified": False}
    path = evidence / ("post-exec-" + boot_id + ".json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write((json.dumps(record, sort_keys=True) + "\n").encode())
        stream.flush(); os.fsync(stream.fileno())
    fd = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--config-sha256", required=True)
    args = parser.parse_args()
    raw = private_file(args.config, 131072)
    require(sha(raw) == args.config_sha256, "selected launch configuration changed")
    value = config_contract(strict_json(raw))
    candidate = STATE / "phone-local-v150" / ("geniex-candidate-" + value["instance"])
    require(args.config == candidate / "startup/provider-start.json", "configuration is not in selected candidate")
    identity = actual_identity()
    no_stop()
    info = (candidate / "stage").stat()
    require(info.st_dev == value["stage"]["st_dev"] and info.st_ino == value["stage"]["st_ino"]
            and info.st_uid == info.st_gid == 2000 and stat.S_IMODE(info.st_mode) == 0o700,
            "post-exec staging identity differs")
    source = candidate / "source"
    for name, digest in value["source_sha256"].items():
        require(sha(private_file(source / name)) == digest, "provider source changed")
    base = candidate / "local-config-base.json"
    geniex = candidate / "geniex-config.json"
    claims = STATE / "phone-local-v150/retained-claims.json"
    for path, digest in ((base, value["base_config_sha256"]), (geniex, value["geniex_config_sha256"]),
                         (claims, value["retained_claims_sha256"])):
        require(sha(private_file(path)) == digest, "configuration or original claims changed")
    health = native_health(source)
    no_stop()
    record = record_post_exec(candidate, value, args.config_sha256, identity, health,
                              Path("/proc/sys/kernel/random/boot_id").read_text().strip())
    if value["mode"] == "preflight_only":
        print(json.dumps(record, sort_keys=True))
        return 0
    from startup_health import run_prelisten
    startup_health = run_prelisten(source, candidate, no_stop=no_stop)
    require(startup_health.get("listen_authorized") is True
            and startup_health.get("native_uid2000_npu_qualified") is True,
            "native NPU startup health did not authorize provider listen")
    no_stop()
    sys.argv = [str(source / "daily_phone_local.py"), "--state", str(STATE / "phone-local-v150/provider-state"),
                "--config", str(base), "--geniex-config", str(geniex), "--port", "18080", "--workers", "1",
                "--timeout", "55", "--retained-claims", str(claims),
                "--retained-claims-sha256", value["retained_claims_sha256"]]
    # Same process/interpreter: no second exec can silently alter the measured
    # capabilities. The real daily parser, selector and all durable claims remain.
    runpy.run_path(str(source / "daily_phone_local.py"), run_name="__main__")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print("HEPTA_GENIEX_POST_EXEC_HOLD " + type(error).__name__ + ": " + str(error), file=sys.stderr)
        raise SystemExit(70)
