#!/usr/bin/env python3
"""Mechanism-only bounded multi-inflight broker for one owner-open Host."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

from owner_open_broker_admission_v2 import BrokerAdmissionMixin
from owner_open_broker_base_v2 import BrokerBase
from owner_open_broker_common import BrokerError, require_id
from owner_open_broker_convergence_v2 import BrokerConvergenceMixin
from owner_open_broker_mux import MuxError
from owner_open_broker_server_v2 import BrokerServerMixin


class Broker(
    BrokerServerMixin,
    BrokerAdmissionMixin,
    BrokerConvergenceMixin,
    BrokerBase,
):
    """One bounded broker instance with no automatic effect redispatch."""


def _client_weights(values: list[str], parser: argparse.ArgumentParser) -> dict[str, int]:
    parsed: dict[str, int] = {}
    for value in values:
        client_id, separator, raw_weight = value.partition("=")
        if not separator:
            parser.error("--client-weight must be CLIENT_ID=WEIGHT")
        client_id = require_id(client_id, "client weight client_id")
        try:
            weight = int(raw_weight, 10)
        except ValueError:
            parser.error("--client-weight WEIGHT must be an integer")
        if not 1 <= weight <= 1_024:
            parser.error("--client-weight WEIGHT is outside 1..=1024")
        if client_id in parsed:
            parser.error("--client-weight repeats a client_id")
        parsed[client_id] = weight
    return parsed


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--descriptor", required=True, type=Path)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--audit-file", type=Path)
    parser.add_argument("--broker-id", required=True)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--upstream-arg", action="append", default=[])
    parser.add_argument("--max-clients", type=int, default=16)
    parser.add_argument("--client-queue-frames", type=int, default=1024)
    parser.add_argument("--client-queue-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--max-pending-requests", type=int, default=256)
    parser.add_argument("--max-inflight-requests", type=int, default=16)
    parser.add_argument("--max-retired-requests", type=int, default=4096)
    parser.add_argument("--client-weight", action="append", default=[])
    args = parser.parse_args(argv)
    args.broker_id = require_id(args.broker_id, "broker_id")
    args.client_weights = _client_weights(args.client_weight, parser)
    if args.audit_file is None:
        args.audit_file = Path(f"{args.descriptor}.audit.jsonl")
    bounds = {
        "max_clients": 1024,
        "client_queue_frames": 65_536,
        "client_queue_bytes": 1024 * 1024 * 1024,
        "max_pending_requests": 65_536,
        "max_inflight_requests": 4_096,
        "max_retired_requests": 1_000_000,
    }
    for field, maximum in bounds.items():
        if not 1 <= getattr(args, field) <= maximum:
            parser.error(f"--{field.replace('_', '-')} is outside the finite bound")
    if args.max_inflight_requests > args.max_pending_requests:
        parser.error("--max-inflight-requests exceeds --max-pending-requests")
    return args


def main(argv: list[str]) -> int:
    try:
        return Broker(parse_args(argv)).serve()
    except (BrokerError, MuxError, OSError, subprocess.SubprocessError) as error:
        print(f"owner-open broker failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
