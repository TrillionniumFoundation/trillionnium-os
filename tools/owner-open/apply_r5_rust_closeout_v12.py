#!/usr/bin/env python3
"""Apply the exact v12 complete-graph Clippy repairs.

The v11 applicator owns all previously reviewed runtime, persistence, broker,
EOF and owner-open-types closure. This wrapper closes the next two full-graph
warnings by passing one typed digest preimage instead of eight loose arguments
and by using direct Result propagation after cleanup. Protocol bytes, cleanup
ordering, error precedence and effect semantics remain unchanged. This is
exact-preimage and requires ``--apply``.
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_PATH = SCRIPT_DIR / "apply_r5_rust_closeout_v11.py"
SPEC = importlib.util.spec_from_file_location("owner_open_r5_rust_closeout_v11", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the v11 R5 Rust closeout applicator")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

REPAIR = BASE.REPAIR


def repair_event_store_digest_preimage() -> None:
    path = "crates/trillionnium-owner-open-event-store/src/lib.rs"
    REPAIR.replace_exact(
        path,
        "        let record_sha256 = record_digest(\n"
        "            store_seq,\n"
        "            turn_seq,\n"
        "            &input.scope,\n"
        "            &input.event_id,\n"
        "            &input.kind,\n"
        "            &input.payload,\n"
        "            &payload_sha256,\n"
        "            &previous_record_sha256,\n"
        "        )?;\n",
        "        let record_sha256 = record_digest(&RecordPreimage {\n"
        "            schema: EVENT_RECORD_SCHEMA,\n"
        "            store_seq,\n"
        "            turn_seq,\n"
        "            scope: &input.scope,\n"
        "            event_id: &input.event_id,\n"
        "            kind: &input.kind,\n"
        "            payload: &input.payload,\n"
        "            payload_sha256: &payload_sha256,\n"
        "            previous_record_sha256: &previous_record_sha256,\n"
        "        })?;\n",
    )
    REPAIR.replace_exact(
        path,
        "    let expected = record_digest(\n"
        "        record.store_seq,\n"
        "        record.turn_seq,\n"
        "        &record.scope,\n"
        "        &record.event_id,\n"
        "        &record.kind,\n"
        "        &record.payload,\n"
        "        &record.payload_sha256,\n"
        "        &record.previous_record_sha256,\n"
        "    )?;\n",
        "    let expected = record_digest(&RecordPreimage {\n"
        "        schema: EVENT_RECORD_SCHEMA,\n"
        "        store_seq: record.store_seq,\n"
        "        turn_seq: record.turn_seq,\n"
        "        scope: &record.scope,\n"
        "        event_id: &record.event_id,\n"
        "        kind: &record.kind,\n"
        "        payload: &record.payload,\n"
        "        payload_sha256: &record.payload_sha256,\n"
        "        previous_record_sha256: &record.previous_record_sha256,\n"
        "    })?;\n",
    )
    REPAIR.replace_exact(
        path,
        "fn record_digest(\n"
        "    store_seq: u64,\n"
        "    turn_seq: u64,\n"
        "    scope: &TurnScope,\n"
        "    event_id: &str,\n"
        "    kind: &str,\n"
        "    payload: &Value,\n"
        "    payload_sha256: &str,\n"
        "    previous_record_sha256: &str,\n"
        ") -> Result<String> {\n"
        "    let encoded = serde_json::to_vec(&RecordPreimage {\n"
        "        schema: EVENT_RECORD_SCHEMA,\n"
        "        store_seq,\n"
        "        turn_seq,\n"
        "        scope,\n"
        "        event_id,\n"
        "        kind,\n"
        "        payload,\n"
        "        payload_sha256,\n"
        "        previous_record_sha256,\n"
        "    })\n"
        "    .map_err(|error| EventStoreError::InvalidRecord(error.to_string()))?;\n"
        "    Ok(sha256_hex(&encoded))\n"
        "}\n",
        "fn record_digest(preimage: &RecordPreimage<'_>) -> Result<String> {\n"
        "    let encoded = serde_json::to_vec(preimage)\n"
        "        .map_err(|error| EventStoreError::InvalidRecord(error.to_string()))?;\n"
        "    Ok(sha256_hex(&encoded))\n"
        "}\n",
    )


def repair_provider_result_propagation() -> None:
    path = "crates/trillionnium-owner-open-provider-jsonl/src/lib.rs"
    REPAIR.replace_exact(
        path,
        "        let terminal = match result {\n"
        "            Ok(terminal) => terminal,\n"
        "            Err(error) => return Err(error),\n"
        "        };\n",
        "        let terminal = result?;\n",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the exact audited v12 complete-graph Clippy replacements",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if not arguments.apply:
        raise SystemExit("HOLD: --apply is required")
    if BASE.main() != 0:
        raise RuntimeError("v11 R5 Rust closeout applicator failed")
    repair_event_store_digest_preimage()
    repair_provider_result_propagation()
    print("PASS_R5_RUST_CLOSEOUT_V12_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
