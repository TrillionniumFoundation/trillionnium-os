"""Durable accepted/forwarded/terminal journal for the owner-open broker."""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import threading
import time
from typing import Any

from owner_open_broker_common import (
    BrokerError,
    canonical,
    strict_json,
    validate_private_parent,
)

SCHEMA = "org.trillionnium.owner-open.broker-audit.v1"
ZERO_SHA256 = "0" * 64
MAX_AUDIT_BYTES = 64 * 1024 * 1024
MAX_AUDIT_RECORDS = 100_000
MAX_AUDIT_LINE_BYTES = 2 * 1024 * 1024
STAGES = {"broker.accepted", "broker.forwarded", "broker.terminal"}


@dataclass
class AuditBinding:
    client_id: str
    request_id: str
    request_sha256: str
    client_seq: int
    upstream_seq: int
    request_kind: str
    correlation: dict[str, str | None]
    broker_epoch: str
    stage: str = "broker.accepted"
    terminal_message: dict[str, Any] | None = None

    @property
    def key(self) -> tuple[str, str]:
        return self.client_id, self.request_id


@dataclass(frozen=True)
class Admission:
    disposition: str
    binding: AuditBinding


class BrokerAuditJournal:
    def __init__(
        self,
        path: Path,
        *,
        broker_id: str,
        maximum_bytes: int = MAX_AUDIT_BYTES,
        maximum_records: int = MAX_AUDIT_RECORDS,
    ) -> None:
        validate_private_parent(path, "broker audit")
        self.path = path
        self.broker_id = broker_id
        self.maximum_bytes = maximum_bytes
        self.maximum_records = maximum_records
        self._lock = threading.Lock()
        self._poisoned: str | None = None
        self._bindings: dict[tuple[str, str], AuditBinding] = {}
        self._next_seq = 0
        self._previous_sha256 = ZERO_SHA256
        self._bytes = 0
        self._highest_upstream_seq = 0
        self._created = not path.exists()
        flags = (
            os.O_RDWR
            | os.O_APPEND
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        self._fd = os.open(path, flags, 0o600)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._validate_metadata()
            self._load()
            if self._created:
                directory = os.open(
                    path.parent,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                )
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except Exception:
            os.close(self._fd)
            raise

    def _validate_metadata(self) -> None:
        metadata = os.fstat(self._fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > self.maximum_bytes
        ):
            raise BrokerError(
                "broker audit must be one service-owned mode-0600 regular file within its bound"
            )

    @staticmethod
    def _record_sha256(record: dict[str, Any]) -> str:
        preimage = dict(record)
        preimage.pop("record_sha256", None)
        return hashlib.sha256(canonical(preimage)).hexdigest()

    def _load(self) -> None:
        os.lseek(self._fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = self.maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(self._fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > self.maximum_bytes:
            raise BrokerError("broker audit exceeds its configured byte bound")
        self._bytes = len(raw)
        if not raw:
            os.lseek(self._fd, 0, os.SEEK_END)
            return
        if not raw.endswith(b"\n"):
            raise BrokerError("broker audit has an unterminated final record")
        lines = raw.splitlines()
        if len(lines) > self.maximum_records:
            raise BrokerError("broker audit exceeds its configured record bound")
        previous = ZERO_SHA256
        for expected_seq, line in enumerate(lines):
            if not line or len(line) > MAX_AUDIT_LINE_BYTES:
                raise BrokerError("broker audit contains an empty or oversized record")
            value = strict_json(
                line,
                label=f"broker audit record {expected_seq}",
                maximum=MAX_AUDIT_LINE_BYTES,
            )
            if not isinstance(value, dict):
                raise BrokerError("broker audit record is not an object")
            if value.get("schema") != SCHEMA:
                raise BrokerError("broker audit schema is unsupported")
            if value.get("seq") != expected_seq:
                raise BrokerError("broker audit sequence is not contiguous")
            if value.get("broker_id") != self.broker_id:
                raise BrokerError("broker audit broker_id conflicts with configuration")
            if value.get("previous_record_sha256") != previous:
                raise BrokerError("broker audit previous-record digest mismatch")
            observed = value.get("record_sha256")
            if not isinstance(observed, str) or observed != self._record_sha256(value):
                raise BrokerError("broker audit record digest mismatch")
            self._apply_recovered(value)
            previous = observed
        self._next_seq = len(lines)
        self._previous_sha256 = previous
        os.lseek(self._fd, 0, os.SEEK_END)

    def _binding_fields(self, record: dict[str, Any]) -> tuple[Any, ...]:
        return (
            record.get("request_sha256"),
            record.get("client_seq"),
            record.get("upstream_seq"),
            record.get("request_kind"),
            record.get("correlation"),
        )

    def _apply_recovered(self, record: dict[str, Any]) -> None:
        stage = record.get("stage")
        if stage not in STAGES:
            raise BrokerError("broker audit stage is unsupported")
        client_id = record.get("client_id")
        request_id = record.get("request_id")
        if not isinstance(client_id, str) or not isinstance(request_id, str):
            raise BrokerError("broker audit request key is malformed")
        key = client_id, request_id
        binding = self._bindings.get(key)
        if stage == "broker.accepted":
            if binding is not None:
                raise BrokerError("broker audit contains duplicate request acceptance")
            request_sha256 = record.get("request_sha256")
            client_seq = record.get("client_seq")
            upstream_seq = record.get("upstream_seq")
            request_kind = record.get("request_kind")
            correlation = record.get("correlation")
            broker_epoch = record.get("broker_epoch")
            if (
                not isinstance(request_sha256, str)
                or len(request_sha256) != 64
                or isinstance(client_seq, bool)
                or not isinstance(client_seq, int)
                or client_seq < 0
                or isinstance(upstream_seq, bool)
                or not isinstance(upstream_seq, int)
                or upstream_seq <= 0
                or not isinstance(request_kind, str)
                or not isinstance(correlation, dict)
                or not isinstance(broker_epoch, str)
            ):
                raise BrokerError("broker audit accepted record is malformed")
            self._highest_upstream_seq = max(self._highest_upstream_seq, upstream_seq)
            self._bindings[key] = AuditBinding(
                client_id=client_id,
                request_id=request_id,
                request_sha256=request_sha256,
                client_seq=client_seq,
                upstream_seq=upstream_seq,
                request_kind=request_kind,
                correlation=correlation,
                broker_epoch=broker_epoch,
            )
            return
        if binding is None:
            raise BrokerError("broker audit transition has no accepted request")
        if self._binding_fields(record) != (
            binding.request_sha256,
            binding.client_seq,
            binding.upstream_seq,
            binding.request_kind,
            binding.correlation,
        ):
            raise BrokerError("broker audit transition drifted from accepted request")
        if stage == "broker.forwarded":
            if binding.stage != "broker.accepted":
                raise BrokerError("broker audit forwarded transition is out of order")
            binding.stage = stage
            return
        if binding.stage == "broker.terminal":
            raise BrokerError("broker audit contains multiple terminal transitions")
        message = record.get("owner_message")
        if not isinstance(message, dict):
            raise BrokerError("broker audit terminal record has no owner message")
        binding.stage = stage
        binding.terminal_message = message

    def _append(
        self,
        binding: AuditBinding,
        stage: str,
        *,
        details: dict[str, Any] | None = None,
        owner_message: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self._poisoned is not None:
            raise BrokerError(f"broker audit is poisoned: {self._poisoned}")
        if self._next_seq >= self.maximum_records:
            raise BrokerError("broker audit record capacity is exhausted")
        record: dict[str, Any] = {
            "schema": SCHEMA,
            "seq": self._next_seq,
            "stage": stage,
            "broker_id": self.broker_id,
            "broker_epoch": binding.broker_epoch,
            "client_id": binding.client_id,
            "request_id": binding.request_id,
            "request_sha256": binding.request_sha256,
            "client_seq": binding.client_seq,
            "upstream_seq": binding.upstream_seq,
            "request_kind": binding.request_kind,
            "correlation": binding.correlation,
            "observed_at_unix_ns": time.time_ns(),
            "details": details or {},
            "previous_record_sha256": self._previous_sha256,
            "automatic_redispatch": False,
        }
        if owner_message is not None:
            record["owner_message"] = owner_message
        record["record_sha256"] = self._record_sha256(record)
        encoded = canonical(record) + b"\n"
        if len(encoded) > MAX_AUDIT_LINE_BYTES:
            raise BrokerError("broker audit record exceeds its line bound")
        if self._bytes + len(encoded) > self.maximum_bytes:
            raise BrokerError("broker audit byte capacity is exhausted")
        try:
            offset = 0
            while offset < len(encoded):
                written = os.write(self._fd, encoded[offset:])
                if written <= 0:
                    raise OSError("broker audit write made no progress")
                offset += written
            os.fsync(self._fd)
        except OSError as error:
            self._poisoned = str(error)
            raise BrokerError(f"broker audit append became uncertain: {error}") from error
        self._next_seq += 1
        self._previous_sha256 = record["record_sha256"]
        self._bytes += len(encoded)
        return record

    def lookup(self, client_id: str, request_id: str) -> AuditBinding | None:
        with self._lock:
            return self._bindings.get((client_id, request_id))

    def admit(
        self,
        *,
        broker_epoch: str,
        client_id: str,
        request_id: str,
        request_sha256: str,
        client_seq: int,
        upstream_seq: int,
        request_kind: str,
        correlation: dict[str, str | None],
    ) -> Admission:
        key = client_id, request_id
        with self._lock:
            existing = self._bindings.get(key)
            if existing is not None:
                if existing.request_sha256 != request_sha256:
                    return Admission("conflict", existing)
                if existing.terminal_message is not None:
                    return Admission("terminal", existing)
                return Admission("unresolved", existing)
            binding = AuditBinding(
                client_id=client_id,
                request_id=request_id,
                request_sha256=request_sha256,
                client_seq=client_seq,
                upstream_seq=upstream_seq,
                request_kind=request_kind,
                correlation=correlation,
                broker_epoch=broker_epoch,
            )
            self._append(binding, "broker.accepted")
            self._highest_upstream_seq = max(self._highest_upstream_seq, upstream_seq)
            self._bindings[key] = binding
            return Admission("new", binding)

    def forwarded(self, binding: AuditBinding, *, frame_sha256: str, frame_bytes: int) -> None:
        with self._lock:
            if binding.stage != "broker.accepted":
                raise BrokerError("broker request cannot be forwarded from its current state")
            self._append(
                binding,
                "broker.forwarded",
                details={
                    "frame_sha256": frame_sha256,
                    "frame_bytes": frame_bytes,
                    "write_attempts": 1,
                },
            )
            binding.stage = "broker.forwarded"

    def terminal(
        self,
        binding: AuditBinding,
        *,
        owner_message: dict[str, Any],
        details: dict[str, Any] | None = None,
    ) -> None:
        with self._lock:
            if binding.stage == "broker.terminal":
                if binding.terminal_message != owner_message:
                    raise BrokerError("broker terminal result conflicts with durable result")
                return
            self._append(
                binding,
                "broker.terminal",
                details=details,
                owner_message=owner_message,
            )
            binding.stage = "broker.terminal"
            binding.terminal_message = owner_message

    @property
    def next_upstream_seq(self) -> int:
        with self._lock:
            return self._highest_upstream_seq + 1

    def close(self) -> None:
        with self._lock:
            if getattr(self, "_fd", None) is None:
                return
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None
