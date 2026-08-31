#!/usr/bin/env python3
"""Stable entrypoint for the bounded owner-open connection broker v2."""
from __future__ import annotations

import sys

from owner_open_connection_broker_v2 import main

# Language-boundary contract markers consumed by the Android ingress source
# audit.  The implementation emits the same canonical fields from v2.
ENTRYPOINT_CONTRACT = {
    "kind": "broker.hello.ack",
    "automatic_redispatch": False,
}


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
