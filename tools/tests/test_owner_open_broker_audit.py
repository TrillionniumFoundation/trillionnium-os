from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "owner-open"))

from owner_open_broker_audit import BrokerAuditJournal
from owner_open_broker_common import BrokerError


class BrokerAuditTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "audit.jsonl"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_reopen_replays_terminal_and_preserves_unresolved_truth(self) -> None:
        journal = BrokerAuditJournal(self.path, broker_id="broker")
        completed = journal.admit(
            broker_epoch="epoch-a",
            client_id="client",
            request_id="completed",
            request_sha256="a" * 64,
            client_seq=0,
            upstream_seq=1,
            request_kind="job.inspect",
            correlation={"job_id": "job-a"},
        ).binding
        journal.forwarded(completed, frame_sha256="b" * 64, frame_bytes=123)
        terminal = {
            "kind": "result",
            "request_id": "completed",
            "frame": {"kind": "job.inspect.result"},
        }
        journal.terminal(completed, owner_message=terminal)
        unresolved = journal.admit(
            broker_epoch="epoch-a",
            client_id="client",
            request_id="unresolved",
            request_sha256="c" * 64,
            client_seq=1,
            upstream_seq=2,
            request_kind="job.start",
            correlation={"job_id": "job-b"},
        ).binding
        journal.forwarded(unresolved, frame_sha256="d" * 64, frame_bytes=456)
        journal.close()

        reopened = BrokerAuditJournal(self.path, broker_id="broker")
        completed_again = reopened.lookup("client", "completed")
        unresolved_again = reopened.lookup("client", "unresolved")
        self.assertIsNotNone(completed_again)
        self.assertEqual(completed_again.terminal_message, terminal)
        self.assertIsNotNone(unresolved_again)
        self.assertEqual(unresolved_again.stage, "broker.forwarded")
        self.assertIsNone(unresolved_again.terminal_message)
        self.assertEqual(reopened.next_upstream_seq, 3)
        reopened.close()

    def test_same_request_id_different_digest_conflicts_without_append(self) -> None:
        journal = BrokerAuditJournal(self.path, broker_id="broker")
        first = journal.admit(
            broker_epoch="epoch",
            client_id="client",
            request_id="request",
            request_sha256="a" * 64,
            client_seq=0,
            upstream_seq=1,
            request_kind="job.inspect",
            correlation={},
        )
        conflict = journal.admit(
            broker_epoch="epoch",
            client_id="client",
            request_id="request",
            request_sha256="b" * 64,
            client_seq=1,
            upstream_seq=2,
            request_kind="job.inspect",
            correlation={},
        )
        self.assertEqual(first.disposition, "new")
        self.assertEqual(conflict.disposition, "conflict")
        journal.close()
        self.assertEqual(len(self.path.read_text().splitlines()), 1)

    def test_fsync_failure_poisoning_never_authorizes_forward(self) -> None:
        journal = BrokerAuditJournal(self.path, broker_id="broker")
        with mock.patch(
            "owner_open_broker_audit.os.fsync",
            side_effect=OSError("disk full"),
        ):
            with self.assertRaisesRegex(BrokerError, "append became uncertain"):
                journal.admit(
                    broker_epoch="epoch",
                    client_id="client",
                    request_id="request",
                    request_sha256="a" * 64,
                    client_seq=0,
                    upstream_seq=1,
                    request_kind="job.start",
                    correlation={},
                )
        self.assertIsNone(journal.lookup("client", "request"))
        with self.assertRaisesRegex(BrokerError, "poisoned"):
            journal.admit(
                broker_epoch="epoch",
                client_id="client",
                request_id="second",
                request_sha256="b" * 64,
                client_seq=1,
                upstream_seq=2,
                request_kind="job.start",
                correlation={},
            )
        journal.close()

    def test_record_tamper_fails_closed_on_reopen(self) -> None:
        journal = BrokerAuditJournal(self.path, broker_id="broker")
        journal.admit(
            broker_epoch="epoch",
            client_id="client",
            request_id="request",
            request_sha256="a" * 64,
            client_seq=0,
            upstream_seq=1,
            request_kind="job.inspect",
            correlation={},
        )
        journal.close()
        value = json.loads(self.path.read_text())
        value["request_kind"] = "job.kill"
        self.path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        )
        os.chmod(self.path, 0o600)
        with self.assertRaisesRegex(BrokerError, "digest mismatch"):
            BrokerAuditJournal(self.path, broker_id="broker")


if __name__ == "__main__":
    unittest.main()
