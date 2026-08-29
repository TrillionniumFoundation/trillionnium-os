#!/usr/bin/env python3
"""Release-candidate exact-argv ADB qualification entry.

This wrapper selects the lifecycle-correct release relay while retaining the
reviewed preflight, bounded process observation and no-redispatch mechanics of
the selected qualification implementation.  It also fails closed if the
selected implementation ever stops removing ambient ADB routing variables or
stops reporting exactly-once/no-redispatch operation records.
"""
from __future__ import annotations

import sys
import time

import qualify_owner_open_adb_selected as base

SELECTED_RELAY = "tools/owner-open/adb_smart_socket_relay_release.py"
RELEASE_REMOVED_ENVIRONMENT = (
    "ANDROID_SERIAL",
    "ADB_SERVER_PORT",
    "ANDROID_ADB_SERVER_PORT",
)
RELEASE_OPERATION_INVARIANTS = {
    "spawn_count": 1,
    "automatic_redispatch": False,
}


def wait_descriptor(path, process, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            value = base.strict_json(
                path.read_bytes(), "relay descriptor", base.MAX_PLAN_BYTES
            )
            if (
                not isinstance(value, dict)
                or value.get("schema")
                != "org.trillionnium.owner-open.adb-smart-socket-relay.v1"
            ):
                raise base.QualificationError(
                    "relay descriptor schema is incompatible"
                )
            if value.get("selected_entry") != SELECTED_RELAY:
                raise base.QualificationError(
                    "relay descriptor does not identify the release entry"
                )
            return value
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=1)
            raise base.QualificationError(
                "relay exited before ready: "
                f"rc={process.returncode} stdout={stdout[-512:]!r} "
                f"stderr={stderr[-2048:]!r}"
            )
        time.sleep(base.POLL_SECONDS)
    raise base.QualificationError("relay did not become ready within its timeout")


_selected_run_step = base.run_step


def run_step(adb, step, environment, cwd):
    leaked = [name for name in RELEASE_REMOVED_ENVIRONMENT if name in environment]
    if leaked:
        raise base.QualificationError(
            f"release ADB environment retained forbidden routing variables: {leaked}"
        )
    record, passed = _selected_run_step(adb, step, environment, cwd)
    drift = {
        key: record.get(key)
        for key, expected in RELEASE_OPERATION_INVARIANTS.items()
        if record.get(key) != expected
    }
    if drift:
        raise base.QualificationError(
            f"release ADB exactly-once/no-redispatch record drifted: {drift}"
        )
    return record, passed


base.wait_descriptor = wait_descriptor
base.run_step = run_step


def main(argv: list[str]) -> int:
    return base.main(argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
