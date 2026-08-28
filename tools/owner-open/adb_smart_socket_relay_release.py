#!/usr/bin/env python3
"""Release-candidate entry for the owner-open ADB smart-socket relay.

It reuses the selected relay's strict parsing, private outputs, bounds and
byte-transparent pumps, while guaranteeing transfer/watchdog task cleanup on
all normal, error and cancellation paths.
"""
from __future__ import annotations

import asyncio
import sys
import time

import adb_smart_socket_relay_selected as base

SELECTED_ENTRY = "tools/owner-open/adb_smart_socket_relay_release.py"


class ReleaseRelay(base.Relay):
    async def accept(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        if self.semaphore.locked():
            try:
                await self.events.append("connection_rejected", reason="max_clients")
            finally:
                await base.close_writer(writer, self.limits.shutdown_grace)
            return
        await self.semaphore.acquire()
        identifier = self.next_identifier
        self.next_identifier += 1
        current = asyncio.current_task()
        if current is not None:
            self.connections.add(current)
        state = base.ConnectionState(identifier, time.monotonic())
        upstream_writer: asyncio.StreamWriter | None = None
        transfers: asyncio.Task[None] | None = None
        watchdog: asyncio.Task[None] | None = None
        started = time.monotonic()
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(self.upstream_host, self.upstream_port),
                timeout=self.limits.connect_timeout,
            )
            for output in (writer, upstream_writer):
                output.transport.set_write_buffer_limits(
                    high=self.limits.buffer_bytes,
                    low=max(1, self.limits.buffer_bytes // 4),
                )
            await self.events.append("connection_started", connection_id=identifier)
            transfers = asyncio.create_task(
                base.transfer_pair(
                    reader,
                    writer,
                    upstream_reader,
                    upstream_writer,
                    state,
                ),
                name=f"adb-relay-transfer-{identifier}",
            )
            watchdog = asyncio.create_task(
                base.idle_watchdog(state, self.limits.idle_timeout),
                name=f"adb-relay-watchdog-{identifier}",
            )
            done, _pending = await asyncio.wait(
                {transfers, watchdog}, return_when=asyncio.FIRST_COMPLETED
            )
            if watchdog in done:
                watchdog.result()
            else:
                await transfers
        except asyncio.CancelledError:
            state.terminal = "relay_shutdown"
            raise
        except Exception as error:
            if state.terminal == "completed":
                state.terminal = "transport_error"
            state.error = f"{type(error).__name__}: {error}"
        finally:
            for task in (transfers, watchdog):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(
                *(task for task in (transfers, watchdog) if task is not None),
                return_exceptions=True,
            )
            await base.close_writer(writer, self.limits.shutdown_grace)
            await base.close_writer(upstream_writer, self.limits.shutdown_grace)
            try:
                await self.events.append(
                    "connection_terminal",
                    connection_id=identifier,
                    terminal=state.terminal,
                    error=state.error,
                    client_to_upstream_bytes=state.client_to_upstream,
                    upstream_to_client_bytes=state.upstream_to_client,
                    elapsed_ms=max(0, int((time.monotonic() - started) * 1000)),
                    payload_logged=False,
                    automatic_redispatch=False,
                )
            finally:
                self.semaphore.release()
                if current is not None:
                    self.connections.discard(current)

    async def start(self, descriptor):
        result = await super().start(None)
        result["selected_entry"] = SELECTED_ENTRY
        if descriptor is not None:
            base.atomic_private_json(descriptor, result)
        return result


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
