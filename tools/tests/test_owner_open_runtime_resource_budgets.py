"""Check named runtime sub-budgets against the unchanged source catalog.

These arithmetic/configuration tests do not qualify whole RSS, device resource
use, replay working memory or installed process lifecycle.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


def constant(path: str, name: str) -> int:
    source = (ROOT / path).read_text(encoding="utf-8")
    found = re.search(r"(?:pub(?:\(crate\))? )?const " + re.escape(name)
                      + r": usize = ([^;]+);", source)
    if not found:
        raise AssertionError(f"missing numeric source constant: {name}")

    def integer(node: ast.AST) -> int:
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.BinOp):
            left, right = integer(node.left), integer(node.right)
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.LShift):
                return left << right
        raise AssertionError(f"unsupported source constant expression: {name}")

    return integer(ast.parse(found.group(1).strip(), mode="eval").body)


class RuntimeResourceBudgetTests(unittest.TestCase):
    def setUp(self) -> None:
        catalog = json.loads((ROOT / "docs/machine/module-catalog.v1.json").read_text())
        self.modules = {item["id"]: item for item in catalog["modules"]}
        self.runtime = "crates/trillionnium-owner-open-job-runtime/src/types.rs"

    def test_resident_and_raw_buffer_sub_budgets_fit_catalog_memory(self) -> None:
        observations = constant(self.runtime, "MAX_JOB_RUNTIME_OBSERVATION_BYTES")
        buffers = constant(self.runtime, "MAX_JOB_RUNTIME_PROCESS_BUFFER_BYTES")
        catalog = self.modules["MOD-JOB-RUNTIME"]["resource_contract"]
        self.assertLessEqual(observations + buffers, catalog["memory_bytes"])
        self.assertLessEqual(constant(self.runtime, "MAX_JOB_RUNTIME_JOBS"), catalog["process_count"])

    def test_window_and_registry_history_counts_are_bounded(self) -> None:
        catalog = self.modules["MOD-JOB-RUNTIME"]["resource_contract"]
        self.assertLessEqual(constant(self.runtime, "MAX_JOB_RUNTIME_OBSERVATIONS"), catalog["queue_items"])
        history = constant(self.runtime, "MAX_JOB_RUNTIME_RETAINED_KEYS") * constant(
            self.runtime, "MAX_JOB_RUNTIME_REGISTRY_EVENTS_PER_JOB")
        self.assertLessEqual(history, catalog["queue_items"])

    def test_event_store_resident_and_working_reservations_fit_catalog(self) -> None:
        source = "crates/trillionnium-owner-open-event-store/src/lib.rs"
        catalog = self.modules["MOD-EVENT-STORE"]["resource_contract"]
        resident = constant(source, "MAX_EVENT_RESIDENT_BYTES")
        working = constant(source, "MAX_EVENT_WORKING_BYTES")
        self.assertLessEqual(resident * 2, working)
        self.assertLessEqual(working, catalog["memory_bytes"])

    def test_provider_raw_decode_config_and_stream_writer_fit_named_memory(self) -> None:
        source = "crates/trillionnium-owner-open-provider-jsonl/src/lib.rs"
        raw = constant(source, "MAX_JSONL_PROVIDER_RAW_BUFFER_BYTES")
        decode = constant(source, "MAX_JSONL_PROVIDER_JSON_WORK_BYTES")
        config = constant(source, "MAX_JSONL_PROVIDER_CONFIG_WORK_BYTES")
        writer = constant(source, "JSONL_PROVIDER_WRITE_BUFFER_BYTES")
        self.assertLessEqual(raw + decode + config + writer,
                             self.modules["MOD-PROVIDER"]["resource_contract"]["memory_bytes"])
        self.assertLessEqual(constant(source, "MAX_JSONL_PROVIDER_JSON_BYTES") * 8, decode)

    def test_direct_runtime_shared_buffer_and_leader_gates_fit_module(self) -> None:
        source = "crates/trillionnium-owner-open-runtime/src/resources.rs"
        catalog = self.modules["MOD-TOOL-RUNTIME"]["resource_contract"]
        owned = constant(source, "MAX_RUNTIME_OWNED_BUFFER_BYTES")
        active = constant(source, "MAX_RUNTIME_ACTIVE_BUFFER_BYTES")
        self.assertLessEqual(owned, active)
        self.assertLessEqual(active, catalog["memory_bytes"])
        self.assertLessEqual(constant(source, "MAX_RUNTIME_ACTIVE_PROCESSES"), catalog["process_count"])

    def test_event_store_descriptor_gate_is_shared_across_handles(self) -> None:
        source = "crates/trillionnium-owner-open-event-store/src/resources.rs"
        total = constant(source, "MAX_EVENT_PROCESS_DESCRIPTORS")
        headroom = constant(source, "EVENT_STORE_CONTROL_DESCRIPTORS")
        self.assertLessEqual(total, self.modules["MOD-EVENT-STORE"]["resource_contract"]["fd_count"])
        self.assertLessEqual(constant("crates/trillionnium-owner-open-event-store/src/lib.rs", "MAX_EVENT_SEGMENTS") + headroom, total)

    def test_segment_descriptors_reserve_control_headroom(self) -> None:
        segments = constant("crates/trillionnium-owner-open-event-store/src/lib.rs", "MAX_EVENT_SEGMENTS")
        self.assertLessEqual(segments + 16, self.modules["MOD-EVENT-STORE"]["resource_contract"]["fd_count"])


if __name__ == "__main__":
    unittest.main()
