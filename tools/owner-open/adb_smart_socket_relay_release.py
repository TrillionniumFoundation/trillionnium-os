#!/usr/bin/env python3
"""Release-candidate entry for the owner-open ADB smart-socket relay.

It reuses the selected relay's strict parsing, private outputs, bounds and
byte-transparent pumps, while guaranteeing transfer/watchdog task cleanup on
all normal, error and cancellation paths.
"""
from __future__ import annotations

import asyncio
import sys

import adb_smart_socket_relay_selected as base

SELECTED_ENTRY = "tools/owner-open/adb_smart_socket_relay_release.py"


class ReleaseRelay(base.Relay):
    # The shared implementation owns lifecycle, failure fencing and publication.
    # The release entry changes identity only, never the transport semantics.
    selected_entry = SELECTED_ENTRY


async def run(args) -> int:
    limits = base.Limits(
        args.max_clients,
        args.buffer_bytes,
        args.event_bytes,
        args.connect_timeout,
        args.idle_timeout,
        args.shutdown_grace,
    )
    limits.validate()
    event_handle = base.open_private(args.events, "event log") if args.events else None
    events = base.EventWriter(event_handle, limits.event_bytes)
    relay = ReleaseRelay(
        args.listen_host,
        args.listen_port,
        args.upstream_host,
        args.upstream_port,
        limits,
        events,
    )
    loop = asyncio.get_running_loop()
    for current in (base.signal.SIGTERM, base.signal.SIGINT):
        try:
            loop.add_signal_handler(current, relay.stop)
        except NotImplementedError:
            pass
    try:
        await relay.start(args.descriptor)
        return await relay.serve()
    finally:
        if event_handle is not None:
            event_handle.close()


def main(argv: list[str]) -> int:
    try:
        return asyncio.run(run(base.parse_args(argv)))
    except (OSError, base.RelayError) as error:
        print(f"owner-open ADB smart-socket relay failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
