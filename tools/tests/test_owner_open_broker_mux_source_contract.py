from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
BROKER_ROOT = ROOT / "owner-open"


class BrokerMuxSourceContractTest(unittest.TestCase):
    def read(self, name: str) -> str:
        path = BROKER_ROOT / name
        self.assertTrue(path.is_file(), path)
        return path.read_text(encoding="utf-8")

    def test_stable_entrypoint_selects_v2_and_preserves_android_contract(self) -> None:
        entrypoint = self.read("owner_open_connection_broker.py")
        self.assertIn("from owner_open_connection_broker_v2 import main", entrypoint)
        self.assertIn('"kind": "broker.hello.ack"', entrypoint)
        self.assertIn('"automatic_redispatch": False', entrypoint)
        self.assertNotIn("automatic_effect_redispatch", entrypoint)

    def test_single_active_request_state_is_absent(self) -> None:
        sources = "\n".join(
            self.read(name)
            for name in (
                "owner_open_connection_broker.py",
                "owner_open_connection_broker_v2.py",
                "owner_open_broker_base_v2.py",
                "owner_open_broker_convergence_v2.py",
                "owner_open_broker_admission_v2.py",
                "owner_open_broker_server_v2.py",
                "owner_open_broker_mux.py",
            )
        )
        self.assertNotIn("self.active_request", sources)
        self.assertIn("WeightedFairMux", sources)
        self.assertIn("max_inflight_requests", sources)
        self.assertIn("bounded_weighted_round_robin", sources)

    def test_timeout_fences_exact_ordering_key_without_redispatch(self) -> None:
        mux = self.read("owner_open_broker_mux.py")
        convergence = self.read("owner_open_broker_convergence_v2.py")
        self.assertIn("def fence_active", mux)
        self.assertIn("ordering key is fenced after unresolved effect", mux)
        self.assertIn("unknown_after_timeout", convergence)
        self.assertIn("ordering_key_uncertain", convergence)
        self.assertIn("self.mux.fence_active", convergence)
        self.assertNotIn("automatic_redispatch = True", mux + convergence)

    def test_supplied_upstream_sequence_is_authoritative(self) -> None:
        mux = self.read("owner_open_broker_mux.py")
        match_start = mux.index("    def match(")
        match_end = mux.index("    def sequence_state", match_start)
        match_body = mux[match_start:match_end]
        self.assertIn("A supplied upstream sequence is authoritative", match_body)
        self.assertIn("return None", match_body)
        self.assertNotIn("if seq in self._retired", match_body)

    def test_job_lineage_precedes_operation_id(self) -> None:
        mux = self.read("owner_open_broker_mux.py")
        fields = mux[mux.index("_ORDERING_FIELDS"):mux.index("class MuxError")]
        self.assertLess(fields.index('"job_id"'), fields.index('"operation_id"'))


if __name__ == "__main__":
    unittest.main()
