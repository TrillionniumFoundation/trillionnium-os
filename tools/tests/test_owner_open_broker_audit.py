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

from owner_open_broker_audit import (
    MAX_AUDIT_BYTES,
    MAX_AUDIT_RECORDS,
    BrokerAuditJournal,
)
from owner_open_broker_common import BrokerError
from owner_open_broker_common import canonical, strict_json


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

    def test_create_replacement_between_open_and_identity_check_fails_closed(self) -> None:
        real_open = os.open
        moved = self.root / "audit.original"

        def racing_open(target, flags, *args):
            descriptor = real_open(target, flags, *args)
            if Path(target) == self.path and flags & getattr(os, "O_EXCL", 0):
                os.rename(self.path, moved)
                self.path.write_bytes(b"replacement")
                os.chmod(self.path, 0o600)
            return descriptor

        with mock.patch("owner_open_broker_audit.os.open", side_effect=racing_open):
            with self.assertRaisesRegex(BrokerError, "inode|pathname"):
                BrokerAuditJournal(self.path, broker_id="broker")

    def test_path_replacement_before_append_poisoned_and_never_binds(self) -> None:
        journal = BrokerAuditJournal(self.path, broker_id="broker")
        moved = self.root / "audit.original"
        self.path.rename(moved)
        self.path.write_bytes(b"")
        os.chmod(self.path, 0o600)

        with self.assertRaisesRegex(BrokerError, "identity drift"):
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
        self.assertEqual(self.path.read_bytes(), b"")
        self.assertEqual(moved.read_bytes(), b"")
        journal.close()

    def test_replacement_during_fsync_poisoned_after_uncertain_append(self) -> None:
        journal = BrokerAuditJournal(self.path, broker_id="broker")
        moved = self.root / "audit.original"
        real_fsync = os.fsync
        replaced = False

        def racing_fsync(descriptor: int) -> None:
            nonlocal replaced
            real_fsync(descriptor)
            if descriptor == journal._fd and not replaced:
                replaced = True
                self.path.rename(moved)
                self.path.write_bytes(b"")
                os.chmod(self.path, 0o600)

        with mock.patch(
            "owner_open_broker_audit.os.fsync", side_effect=racing_fsync
        ):
            with self.assertRaisesRegex(BrokerError, "identity drift"):
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
        self.assertTrue(replaced)
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
        self.assertEqual(self.path.read_bytes(), b"")
        self.assertGreater(len(moved.read_bytes()), 0)
        journal.close()

    def test_path_replacement_during_load_fails_closed(self) -> None:
        journal = BrokerAuditJournal(self.path, broker_id="broker")
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
        journal.close()
        original = self.path.read_bytes()
        moved = self.root / "audit.original"
        replaced = False
        real_read = os.read

        def racing_read(descriptor: int, count: int) -> bytes:
            nonlocal replaced
            value = real_read(descriptor, count)
            if not replaced:
                replaced = True
                self.path.rename(moved)
                self.path.write_bytes(original)
                os.chmod(self.path, 0o600)
            return value

        with mock.patch("owner_open_broker_audit.os.read", side_effect=racing_read):
            with self.assertRaisesRegex(BrokerError, "identity drift"):
                BrokerAuditJournal(self.path, broker_id="broker")
        self.assertTrue(replaced)
        self.assertNotEqual(self.path.stat().st_ino, moved.stat().st_ino)

    def test_descriptor_substitution_is_rejected_even_when_path_matches(self) -> None:
        journal = BrokerAuditJournal(self.path, broker_id="broker")
        moved = self.root / "audit.original"
        replacement = self.root / "audit.replacement"
        self.path.rename(moved)
        replacement.write_bytes(b"")
        os.chmod(replacement, 0o600)
        alternate_fd = os.open(replacement, os.O_RDWR | os.O_APPEND)
        try:
            os.dup2(alternate_fd, journal._fd)
        finally:
            os.close(alternate_fd)
        replacement.rename(self.path)

        with self.assertRaisesRegex(BrokerError, "identity drift"):
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
        journal.close()

    def test_protocol_json_rejects_nonfinite_numbers(self) -> None:
        with self.assertRaisesRegex(BrokerError, "non-finite"):
            strict_json(b'{"value":NaN}', label="test frame")
        with self.assertRaisesRegex(ValueError, "Out of range float"):
            canonical({"value": float("inf")})

    def test_audit_limits_are_finite_and_configurable_downward(self) -> None:
        for kwargs in (
            {"maximum_bytes": 0},
            {"maximum_bytes": MAX_AUDIT_BYTES + 1},
            {"maximum_records": 0},
            {"maximum_records": MAX_AUDIT_RECORDS + 1},
        ):
            with self.assertRaises(BrokerError):
                BrokerAuditJournal(self.path, broker_id="broker", **kwargs)
        journal = BrokerAuditJournal(
            self.path,
            broker_id="broker",
            maximum_bytes=4096,
            maximum_records=4,
        )
        journal.close()


if __name__ == "__main__":
    unittest.main()
