#!/usr/bin/env python3
"""Release-candidate exact-argv ADB qualification entry.

This wrapper selects the lifecycle-correct release relay while retaining the
reviewed preflight, bounded process observation and no-redispatch mechanics of
the selected qualification implementation.
"""
from __future__ import annotations

import sys
import time

import qualify_owner_open_adb_selected as base

SELECTED_RELAY = "tools/owner-open/adb_smart_socket_relay_release.py"


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


base.wait_descriptor = wait_descriptor


def main(argv: list[str]) -> int:
    return base.main(argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
