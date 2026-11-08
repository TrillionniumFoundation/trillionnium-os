"""GenieX candidate over the unchanged r6 native process supervisor.

No server is started here. No old receipt, claim, CPU cancellation reader, UID,
SELinux rule, or device permission is changed. Production uses the existing
bootstrap -> native executor -> UID2000 phone_worker boundary.
"""
from __future__ import annotations

import base64
import dataclasses
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import shlex
import socket
import stat
import struct
import threading
import time
from typing import Callable


PROTOCOL = "hepta_phone_local_v150"
ENDPOINT = "hepta_phone_executor_v150_r6"
SDK_COMMIT = "071f609995470bdb0e0769ab964754adfaab7e47"
WORKER_SOURCE_SHA = "07cd434bea9d1214acef499a69ed204ecef879a6ac05c82f24d062160e2efb3e"
TOKENIZER_LIBRARY_SHA = "7a1a80346ddd7d1e775a00435b87303d7794c08d3c75251bcfc5d911fa82227d"
GRAMMAR_PROFILE = "qairt-output-grammar-core-r2-v1"
GRAMMAR_R3_PROFILE = "qairt-output-grammar-core-r2-vlm-r3-v1"
GRAMMAR_PROFILES = frozenset((GRAMMAR_PROFILE, GRAMMAR_R3_PROFILE))
GRAMMAR_CORE_SHA = "06e65cbec4de0831e0010c02ff424e197a519f35b137344cb62ff92369abdb5d"
ORIGINAL_VLM_SHA = "8afccd775a6a6a2cef0521d30aa30df824a85d3617d913fc3cf49fe32795cb87"
# This is the actual built R3 candidate, not an assertion of deployment or of
# passing its independent ABI/phone gates. Selecting it requires the R3 profile.
GRAMMAR_R3_VLM_SHA = "773e23de3f892d2cd9c468e7b0af32e6c254af341d4ed0e7ef0eda95f6ee1d73"
GRAMMAR_SUBSET = "hepta.mobile-schema-gbnf-subset.v1"
GRAMMAR_COMPILER_KIND = "reviewed_python_source"
GRAMMAR_CONVERTER_COMMIT = "19cce6919992fdffd92e0ac152caaf1e2b8f254e"
MAX_NATIVE_OUTPUT = 8 * 1024 * 1024
MAX_RAW_TEXT = 1024 * 1024
PROFILE = {
    "name": "daily-qairt-4096-process60-v1", "context_tokens": 4096,
    "max_prompt_tokens": 3584, "max_generation_tokens": 256,
    "reserved_tokens": 256, "max_native_ms": 60000, "max_worker_ms": 55000,
    "max_rounds": 25, "max_tool_calls": 24, "max_duration_seconds": 300,
    "max_turn_image_bytes": 24 * 196608,
}


class BackendError(RuntimeError):
    pass


class Cancelled(BackendError):
    pass


def require(value, message):
    if not value:
        raise BackendError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def strict_json(raw: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(BackendError("nonfinite JSON")))


def hex_string(value, length):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def private_dir(path: Path, uid: int):
    require(path.is_absolute() and path.resolve(strict=True) == path, "noncanonical private directory")
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == uid,
            "private directory ownership/mode differs")


def read_private(path: Path, uid: int, limit: int) -> bytes:
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent, "noncanonical private file parent")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == uid
                and stat.S_IMODE(before.st_mode) == 0o600 and 0 <= before.st_size <= limit, "private file identity differs")
        parts, size = [], 0
        while size <= limit:
            part = os.read(fd, min(65536, limit + 1 - size))
            if not part:
                break
            parts.append(part); size += len(part)
        after, named = os.fstat(fd), path.lstat()
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(size == before.st_size and all(getattr(before, key) == getattr(after, key) == getattr(named, key)
                                             for key in fields), "private file changed while reading")
        return b"".join(parts)
    finally:
        os.close(fd)


def exclusive(path: Path, raw: bytes, uid: int | None = None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        if uid is not None and uid != os.getuid():
            require(os.getuid() == 0, "only existing root may stage files for the fixed execution UID")
            os.fchown(fd, uid, uid)
        view = memoryview(raw)
        while view:
            size = os.write(fd, view)
            require(size > 0, "short evidence write")
            view = view[size:]
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def sync_directory(path: Path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class CancelGate:
    """The broker's serialized acceptance order, independent of worker JSON.

    The provider calls cancel() when it accepts its cancellation frame. A worker
    result can be delivered only after accept_completion() wins this lock. This
    is not a replacement for the provider's final native-dispatch cancel guard.
    """
    def __init__(self):
        self.lock = threading.RLock()
        self.cancelled = False
        self.accepted = False
        self.directory = None
        self.events = []

    def bind(self, directory: Path):
        with self.lock:
            require(self.directory is None, "cancellation gate already bound")
            self.directory = directory
            if self.cancelled:
                self._event("cancel_accepted_before_dispatch")

    def _event(self, kind):
        row = {"schema": "hepta.geniex-order-event.v1", "sequence": len(self.events), "kind": kind,
               "monotonic_ns": time.monotonic_ns(), "previous_sha256": self.events[-1]["sha256"] if self.events else None}
        raw = canonical_json(row)
        exclusive(self.directory / ("order-%03d.json" % len(self.events)), raw)
        self.events.append({"kind": kind, "sha256": sha(raw)})

    def cancel(self):
        with self.lock:
            if not self.cancelled:
                self.cancelled = True
                if self.directory is not None:
                    self._event("cancel_after_completion_acceptance" if self.accepted else "cancel_accepted")

    def accept_completion(self):
        with self.lock:
            if self.cancelled:
                return False
            require(not self.accepted, "completion already accepted")
            self._event("completion_accepted")
            self.accepted = True
            return True


@dataclasses.dataclass(frozen=True)
class NativePolicy:
    server_uid: int = 0
    execution_uid: int = 2000
    server_context: str = "u:r:trillionnium_owner_open_phone_executor:s0"
    caller_context: str = "u:r:trillionnium_owner_open_bootstrap:s0"
    worker_context: str = "u:r:trillionnium_owner_open_phone_worker:s0"
    credential_scope: str = "android_shell_uid2000"
    supplementary_group_count: int = 0
    production: bool = True


ANDROID_POLICY = NativePolicy()


class R6Transport:
    """The unchanged length-prefixed native protocol with exact peer checks.

    Fixture policy injection is only a Python test seam, never a JSON config
    option. Any nonproduction policy is labelled as host evidence in receipts.
    """
    def __init__(self, endpoint=ENDPOINT, policy=ANDROID_POLICY):
        require(endpoint == ENDPOINT or not policy.production, "production endpoint pin differs")
        self.endpoint, self.policy = endpoint, policy

    def exchange(self, payload, *, timeout=72.0, gate=None, on_poll=None):
        raw = canonical_json({"version": 1, **payload})
        require(0 < len(raw) <= 262144, "native request bound")
        frame = struct.pack(">I", len(raw)) + raw
        deadline = time.monotonic() + timeout
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(min(timeout, 2.0)); sock.connect("\0" + self.endpoint)
            pid, uid, gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(type(pid) is int and pid > 1 and uid == self.policy.server_uid and gid == self.policy.server_uid,
                    "native peer credentials differ")
            if self.policy.production:
                context = sock.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PEERSEC", 31), 256).rstrip(b"\0\n").decode("ascii")
                require(context == self.policy.server_context, "native peer SELinux context differs")
            sock.setblocking(False)
            sent, received, response_size = 0, bytearray(), None
            while True:
                if on_poll:
                    on_poll()
                if gate is not None and gate.cancelled:
                    raise Cancelled("native connection closed after accepted cancellation")
                require(time.monotonic() < deadline, "native transport deadline; original action inspection required")
                reads, writes, _ = select.select([sock], [sock] if sent < len(frame) else [], [], 0.02)
                if writes:
                    try:
                        count = sock.send(frame[sent:])
                    except BlockingIOError:
                        count = 0
                    if count:
                        sent += count
                if reads:
                    part = sock.recv(65536)
                    require(part, "native response ended before complete frame")
                    received.extend(part)
                    if response_size is None and len(received) >= 4:
                        response_size = struct.unpack(">I", received[:4])[0]
                        require(0 < response_size <= 12 * 1024 * 1024, "native response bound")
                    if response_size is not None and len(received) >= response_size + 4:
                        require(len(received) == response_size + 4, "trailing native response bytes")
                        return strict_json(bytes(received[4:]))

    def health(self):
        return self.exchange({"op": "health"}, timeout=2.0)

    def inspect(self, action_id, command_sha256, include_output=False):
        return self.exchange({"op": "inspect", "action_id": action_id,
                              "command_sha256": command_sha256, "include_output": include_output}, timeout=2.0)


def validate_native(envelope, *, request_id, command_sha256, server_instance, policy=ANDROID_POLICY,
                    require_output=True):
    require(isinstance(envelope, dict) and type(envelope.get("version")) is int and envelope["version"] == 1
            and envelope.get("protocol") == PROTOCOL, "native envelope differs")
    require(envelope.get("duplicate") is False, "duplicate native action is inspection-only, not a new inference")
    row = envelope.get("receipt")
    require(isinstance(row, dict) and row.get("action_id") == request_id
            and row.get("command_sha256") == command_sha256 and row.get("server_instance") == server_instance,
            "native request/server identity differs")
    ints = {"executor_revision": 6, "dispatch_count": 1, "required_execution_uid": policy.execution_uid,
            "required_execution_gid": policy.execution_uid, "execution_uid": policy.execution_uid,
            "execution_euid": policy.execution_uid, "execution_gid": policy.execution_uid,
            "execution_egid": policy.execution_uid, "execution_supplementary_group_count": policy.supplementary_group_count}
    require(all(type(row.get(key)) is int and row[key] == value for key, value in ints.items()), "native integer/credential field differs")
    require(type(row.get("pid")) is int and row["pid"] > 1 and type(row.get("pgid")) is int and row["pgid"] == row["pid"],
            "native process identity differs")
    for key in ("terminal", "effect_started", "process_group_established", "waitpid_joined", "process_group_absent",
                "execution_credentials_verified", "worker_domain_verified"):
        require(row.get(key) is True, "native termination not proven: " + key)
    require(row.get("waitpid_identity_lost") is False and row.get("can_redispatch") is False,
            "native wait identity lost or replay permitted")
    require(row.get("supplementary_groups_cleared") is (policy.supplementary_group_count == 0), "native supplementary group proof differs")
    for key, value in {"executor_context": policy.server_context, "peer_context": policy.caller_context,
                       "execution_context": policy.worker_context, "execution_credentials_scope": policy.credential_scope,
                       "handshake_stage": "worker_entry_after_exec_transition"}.items():
        require(row.get(key) == value, "native security domain differs: " + key)
    require(row.get("state") in {"completed", "failed", "timed_out", "cancelled", "output_limit_exceeded"}, "native state is not a known terminal")
    code, sig = row.get("exit_code"), row.get("term_signal")
    require((type(code) is int and 0 <= code <= 255 and sig is None)
            or (code is None and type(sig) is int and 1 <= sig <= 64), "native kernel wait status missing or contradictory")
    if require_output:
        total = 0
        for name in ("stdout", "stderr"):
            encoded = envelope.get(name + "_b64")
            require(isinstance(encoded, str), "native output absent")
            raw = base64.b64decode(encoded, validate=True)
            require(base64.b64encode(raw).decode() == encoded and type(row.get(name + "_bytes")) is int
                    and len(raw) == row[name + "_bytes"] and sha(raw) == row.get(name + "_sha256"), "native output hash/size differs")
            total += len(raw)
        require(total <= MAX_NATIVE_OUTPUT, "native output exceeds bound")
    return row


def validate_worker(value, raw, native, *, request_id, expected_inputs, expected_model, expected_output_path, expected_formatted_sha256,
                    max_prompt_tokens, max_tokens=256, policy=ANDROID_POLICY):
    require(isinstance(value, dict) and value.get("schema") == "hepta.geniex-once.result.v1", "GenieX result schema differs")
    require(value.get("production_receipt") is False and value.get("process_exit_observed") is False
            and value.get("native_action_authorized") is False, "worker evidence was upgraded into a production receipt")
    require(value.get("request_id") == request_id and value.get("sdk_source_commit") == SDK_COMMIT
            and value.get("sdk_version") in {"0.10.0", "v0.10.0"}, "GenieX request/ABI differs")
    require(value.get("mode") == "vlm" and value.get("runtime") == "qairt" and value.get("compute_requested") == "npu"
            and value.get("device_resolved") == "NPU" and value.get("device_warning") is None
            and value.get("vit_device_requested") is None, "GenieX runtime/device differs")
    ints = {"pid": native["pid"], "pgid": native["pgid"], "sid": native["pid"], "n_ctx_create": 0,
            "n_gpu_layers_create": 0, "power_mode_create": 6, "generate_attempt_count": 1,
            "signal_observed": 0, "max_tokens": max_tokens, "worker_exit_status_planned": 0}
    require(all(type(value.get(key)) is int and value[key] == expected for key, expected in ints.items()), "GenieX process/config integer differs")
    require(value.get("power_mode_name") == "sustained_high_performance" and value.get("model_path") == expected_model,
            "GenieX model/power differs")
    require(value.get("input_sha256") == expected_inputs and value.get("raw_text_file") == expected_output_path,
            "GenieX request inputs/output path differ")
    require(value.get("formatted_prompt_sha256") == expected_formatted_sha256,
            "GenieX formatted prompt differs from the counted formatter")
    require(value.get("automatic_retry") is False and value.get("generation_complete") is True
            and value.get("raw_text_present") is True and value.get("raw_text_utf8") is True
            and value.get("raw_text_truncated") is False and value.get("raw_text_source") == "sdk_full_text"
            and value.get("input_metadata_unchanged") is True and value.get("deadline_observed") is False
            and value.get("callback_limit_observed") is False, "GenieX result is not complete and uncancelled")
    require(value.get("worker_outcome") == "completed" and value.get("error") is None
            and value.get("stop_reason") in {"eos", "stop_sequence"}, "GenieX stop/error differs")
    codes = value.get("sdk_rc")
    require(isinstance(codes, dict) and all(type(codes.get(key)) is int and codes[key] == 0 for key in
            ("resolve", "set_log_level", "init", "create", "template", "generate", "destroy", "deinit")), "GenieX SDK did not complete successfully")
    require(type(value.get("raw_text_bytes")) is int and len(raw) == value["raw_text_bytes"] <= MAX_RAW_TEXT
            and sha(raw) == value.get("raw_text_sha256"), "GenieX raw output hash/size differs")
    raw.decode("utf-8", errors="strict")
    profile = value.get("profile")
    require(isinstance(profile, dict) and type(profile.get("prompt_tokens")) is int
            and max(1, max_prompt_tokens - 1) <= profile["prompt_tokens"] <= max_prompt_tokens
            and type(profile.get("generated_tokens")) is int and 0 <= profile["generated_tokens"] <= max_tokens,
            "actual SDK token count differs from counted QAIRT segments/BOS bound")
    return raw.decode("utf-8")


def validate_worker_deadline(value, native, *, request_id, expected_inputs, expected_model, expected_output_path):
    """Classify a frozen worker deadline only after native process cleanup.

    This accepts no model text and grants no phone action. Exit 124 alone is
    insufficient: the original worker metadata must bind the same request,
    process, artifacts and inputs and explicitly attest its deadline fence.
    """
    require(isinstance(value, dict) and value.get("schema") == "hepta.geniex-once.result.v1",
            "deadline worker schema differs")
    require(value.get("production_receipt") is False and value.get("process_exit_observed") is False
            and value.get("native_action_authorized") is False, "deadline metadata claims native authority")
    require(value.get("request_id") == request_id and value.get("sdk_source_commit") == SDK_COMMIT
            and value.get("sdk_version") in {"0.10.0", "v0.10.0"}, "deadline worker request/ABI differs")
    require(value.get("mode") == "vlm" and value.get("runtime") == "qairt"
            and value.get("compute_requested") == "npu" and value.get("device_resolved") == "NPU"
            and value.get("device_warning") is None and value.get("vit_device_requested") is None,
            "deadline worker runtime/device differs")
    integers = {"pid": native["pid"], "pgid": native["pgid"], "sid": native["pid"],
                "n_ctx_create": 0, "n_gpu_layers_create": 0, "power_mode_create": 6,
                "signal_observed": 0, "max_tokens": 256, "worker_exit_status_planned": 124}
    require(all(type(value.get(key)) is int and value[key] == expected for key, expected in integers.items()),
            "deadline worker process/config differs")
    require(value.get("model_path") == expected_model and value.get("input_sha256") == expected_inputs
            and value.get("raw_text_file") == expected_output_path and value.get("input_metadata_unchanged") is True,
            "deadline worker input binding differs")
    require(value.get("automatic_retry") is False and value.get("generation_complete") is False
            and value.get("deadline_observed") is True and value.get("worker_outcome") == "deadline_observed",
            "worker did not attest a deadline fence")


def formatter_segments(original_inputs):
    head, middle, tail = b"<|im_start|>system\n", b"<|im_end|>\n<|im_start|>user\n", b"<|im_end|>\n<|im_start|>assistant\n"
    first = head + original_inputs["system"] + middle
    return [first, original_inputs["prompt"] + tail] if original_inputs["image"] is not None else [first + original_inputs["prompt"] + tail]


def validate_counter(value, native, *, request_id, expected_inputs, original_inputs, config, admission_limit):
    """Validate the original pre-generation tokenizer evidence, not model text."""
    require(isinstance(value, dict) and value.get("schema") == "hepta.geniex-token-count.v1"
            and value.get("request_id") == request_id and value.get("status") == "success"
            and value.get("success") is True and value.get("error") is None, "native token admission did not succeed")
    require(value.get("sdk_commit") == SDK_COMMIT
            and value.get("processor_commit") == "6b68dd0de5b9a84c316cc3babfe9f2477d9c6079"
            and value.get("processor_blob") == "41eee100525d06dc9c040b24f44a71cfd0d2d31f"
            and value.get("library_sha256") == config.tokenizer_library_sha256
            and value.get("tokenizer_sha256") == config.tokenizer_sha256,
            "native tokenizer/formatter artifacts differ")
    require(type(value.get("pid")) is int and value["pid"] > 1 and value["pid"] != native["pid"]
            and type(value.get("pgid")) is int and value["pgid"] == native["pgid"]
            and type(value.get("sid")) is int and value["sid"] == native["pid"],
            "native counter was not in the supervised model process group")
    require(value.get("input_sha256") == {key: expected_inputs[key] for key in ("prompt", "system", "image")}
            and ((expected_inputs["grammar"] is None and config.grammar_profile is None)
                 or (hex_string(expected_inputs["grammar"], 64) and config.grammar_profile in GRAMMAR_PROFILES))
            and value.get("input_unchanged") is True and value.get("raw_input_preserved") is True,
            "native token admission inputs differ")
    require(value.get("method") == "exact_sdk_formatted_text_segments_plus_bos_upper_bound"
            and value.get("is_exact_token_count") is False and value.get("ffi_add_special_tokens") is False,
            "native token-count method differs")
    require(value.get("model_loaded") is False and value.get("native_receipt") is False,
            "counter evidence was upgraded into model/process authority")
    has_image = expected_inputs["image"] is not None
    expected_sizes = {key: len(original_inputs[key]) if original_inputs[key] is not None else 0
                      for key in ("prompt", "system", "image")}
    require(value.get("input_bytes") == expected_sizes and all(type(size) is int for size in value["input_bytes"].values()),
            "counter input byte sizes differ")
    integers = {"formatter_overhead_utf8_bytes": 80, "image_pad_tokens": 256 if has_image else 0,
                "vision_boundary_tokens": 2 if has_image else 0, "bos_token_upper_bound": 1,
                "context_tokens": 4096, "max_prompt_tokens": admission_limit,
                "generation_tokens": 256, "reserved_tokens": 256}
    require(all(type(value.get(key)) is int and value[key] == count for key, count in integers.items()),
            "native compiled context/vision budget differs")
    counts, sizes, hashes = (value.get(key) for key in ("segment_token_counts", "segment_utf8_bytes", "segment_sha256"))
    parts = 2 if has_image else 1
    require(isinstance(counts, list) and isinstance(sizes, list) and isinstance(hashes, list)
            and len(counts) == len(sizes) == len(hashes) == parts
            and all(type(count) is int and 0 < count <= 65536 for count in counts)
            and all(type(size) is int and 0 <= size <= 65536 + 80 for size in sizes)
            and all(hex_string(digest, 64) for digest in hashes), "native token segments malformed")
    segments = formatter_segments(original_inputs)
    require(sizes == list(map(len, segments)) and hashes == [sha(segment) for segment in segments],
            "counter did not encode the exact pinned formatter segments")
    total = sum(counts)
    upper = total + integers["image_pad_tokens"] + integers["vision_boundary_tokens"] + 1
    require(type(value.get("formatted_text_tokens")) is int and value["formatted_text_tokens"] == total
            and type(value.get("prompt_tokens_upper_bound")) is int and value["prompt_tokens_upper_bound"] == upper
            and 0 < upper <= admission_limit, "native token bound exceeded or incoherent")
    return upper


@dataclasses.dataclass(frozen=True)
class BackendConfig:
    evidence_root: Path
    stage_root: Path
    android_stage_root: str
    worker_android: str
    worker_sha256: str
    model_android: str
    tokenizer_android: str
    plugin_path: str
    qairt_lib_path: str
    ld_library_path: str
    adsp_library_path: str
    artifact_manifest_sha256: str
    tokenizer_sha256: str
    counter_android: str
    counter_sha256: str
    tokenizer_library_android: str
    tokenizer_library_sha256: str
    max_worker_ms: int = 55000
    max_native_ms: int = 60000
    grammar_profile: str | None = None
    core_android: str | None = None
    core_sha256: str | None = None
    schema_compiler_sha256: str | None = None
    vlm_android: str | None = None
    vlm_sha256: str | None = None

    def validate(self, policy=ANDROID_POLICY):
        private_dir(self.evidence_root, os.getuid())
        private_dir(self.stage_root, policy.execution_uid)
        require(type(self.max_worker_ms) is int and 1 <= self.max_worker_ms <= 55000
                and type(self.max_native_ms) is int and self.max_worker_ms + 1000 <= self.max_native_ms <= 60000,
                "explicit native/process deadline bounds differ")
        require(all(hex_string(value, 64) for value in (self.worker_sha256, self.artifact_manifest_sha256, self.tokenizer_sha256,
                    self.counter_sha256, self.tokenizer_library_sha256)),
                "artifact pin absent")
        for path in (self.android_stage_root, self.worker_android, self.model_android, self.tokenizer_android, self.plugin_path, self.qairt_lib_path,
                     self.counter_android, self.tokenizer_library_android):
            require(isinstance(path, str) and path.startswith("/") and str(PurePosixPath(path)) == path
                    and ".." not in PurePosixPath(path).parts and "\0" not in path and "\n" not in path, "noncanonical configured Android path")
        require(PurePosixPath(self.model_android).name == "genie_config.json"
                and PurePosixPath(self.tokenizer_android).name == "tokenizer.json"
                and PurePosixPath(self.model_android).parent == PurePosixPath(self.tokenizer_android).parent,
                "QAIRT requires same-bundle genie_config.json/tokenizer.json entry files")
        for value, separator in ((self.ld_library_path, ":"), (self.adsp_library_path, ";")):
            require(isinstance(value, str) and value and all(part.startswith("/") and "\0" not in part and "\n" not in part
                    for part in value.split(separator)), "runtime library path list differs")
        if self.grammar_profile is None:
            require(self.core_android is None and self.core_sha256 is None and self.schema_compiler_sha256 is None
                    and self.vlm_android is None and self.vlm_sha256 is None,
                    "grammar artifacts require their explicit reviewed profile")
        else:
            require(self.grammar_profile in GRAMMAR_PROFILES
                    and hex_string(self.core_sha256, 64) and hex_string(self.schema_compiler_sha256, 64),
                    "unknown or unpinned output grammar profile")
            require(isinstance(self.core_android, str) and self.core_android.startswith("/")
                    and str(PurePosixPath(self.core_android)) == self.core_android
                    and ".." not in PurePosixPath(self.core_android).parts
                    and "\0" not in self.core_android and "\n" not in self.core_android
                    and PurePosixPath(self.core_android).name == "libgeniex_core.so",
                    "noncanonical grammar core path")
            # The reviewed Android bundle keeps its QAIRT DSOs under lib/qairt;
            # lib and lib/llama_cpp precede it in the measured loader order.
            # The explicit Python-only host policy keeps its existing flat
            # fixture layout. JSON configuration cannot select that policy.
            grammar_directory = self.plugin_path + "/qairt" if policy.production else self.plugin_path
            require(str(PurePosixPath(self.core_android).parent) == grammar_directory,
                    "grammar core differs from the selected QAIRT directory" if policy.production
                    else "grammar core must be the selected first loader directory")
            if not policy.production:
                require(self.plugin_path == self.ld_library_path.split(":")[0],
                        "grammar core must be the selected first loader directory")
            if self.grammar_profile == GRAMMAR_R3_PROFILE:
                require(isinstance(self.vlm_android, str) and hex_string(self.vlm_sha256, 64),
                        "R3 output grammar requires an explicit VLM path and pin")
            else:
                require((self.vlm_android is None and self.vlm_sha256 is None)
                        or (isinstance(self.vlm_android, str) and hex_string(self.vlm_sha256, 64)),
                        "R2 VLM path and pin must be supplied together")
            vlm_path, vlm_sha = self.selected_vlm()
            require(vlm_path.startswith("/") and str(PurePosixPath(vlm_path)) == vlm_path
                    and ".." not in PurePosixPath(vlm_path).parts and "\0" not in vlm_path and "\n" not in vlm_path
                    and PurePosixPath(vlm_path).name == "libgeniex_vlm.so", "noncanonical grammar VLM path")
            require(str(PurePosixPath(vlm_path).parent) == grammar_directory,
                    "grammar VLM differs from the selected QAIRT directory" if policy.production
                    else "grammar VLM must be the selected first loader directory")
            if policy.production:
                expected_loader = [self.plugin_path, self.plugin_path + "/llama_cpp", grammar_directory,
                                   grammar_directory + "/htp-files", "/system/lib64", "/vendor/lib64"]
                require(self.ld_library_path.split(":") == expected_loader,
                        "Android grammar bundle loader layout differs")
                require(self.qairt_lib_path == grammar_directory + "/htp-files",
                        "Android grammar QAIRT HTP directory differs")
                require(self.tokenizer_library_android == grammar_directory + "/libgeniex-proc.so",
                        "Android grammar tokenizer library path differs")
                require(self.core_sha256 == GRAMMAR_CORE_SHA, "unreviewed Android output grammar core")
                expected_vlm = GRAMMAR_R3_VLM_SHA if self.grammar_profile == GRAMMAR_R3_PROFILE else ORIGINAL_VLM_SHA
                require(vlm_sha == expected_vlm, "Android VLM hash differs from the explicit grammar profile")
        if policy.production:
            parts = self.ld_library_path.split(":")
            require(parts[-2:] == ["/system/lib64", "/vendor/lib64"], "Android system/vendor loader order differs")
            require(self.tokenizer_library_sha256 == TOKENIZER_LIBRARY_SHA,
                    "native counter library differs from selected official QAIRT package")

    def selected_vlm(self):
        if self.grammar_profile is None:
            return None, None
        if self.grammar_profile == GRAMMAR_PROFILE and self.vlm_android is None and self.vlm_sha256 is None:
            # Old R2 JSON remains readable. New source pins the original VLM
            # rather than silently using whichever SONAME is in the directory.
            return str(PurePosixPath(self.core_android).with_name("libgeniex_vlm.so")), ORIGINAL_VLM_SHA
        return self.vlm_android, self.vlm_sha256

    def vlm_binding(self):
        if self.grammar_profile is None:
            return {}
        path, digest = self.selected_vlm()
        return {"vlm_android": path, "vlm_sha256": digest}

    def digest(self):
        value = dataclasses.asdict(self)
        value.update(evidence_root=str(self.evidence_root), stage_root=str(self.stage_root))
        return sha(canonical_json(value))


def owner_binding(owner_path: Path, claim_path: Path):
    owner_raw, claim_raw = read_private(owner_path, os.getuid(), 1024 * 1024), read_private(claim_path, os.getuid(), 65536)
    owner, claim = strict_json(owner_raw), strict_json(claim_raw)
    require(owner.get("schema") == "hepta.accepted-owner-request.v150.1" and owner.get("source") == "accepted_turn_start_frame"
            and claim.get("state") == "accepted_no_redispatch" and claim.get("identity") == owner.get("identity")
            and claim.get("run_dir") == str(owner_path.parent), "accepted owner turn/claim binding differs")
    data = base64.b64decode(owner.get("request_utf8_b64", ""), validate=True)
    require(data and len(data) <= 512 * 1024 and b"\0" not in data and data.decode("utf-8")
            and sha(data) == owner.get("request_sha256") == claim.get("request_sha256"), "accepted owner request digest differs")
    return {"identity": owner["identity"], "owner_request_sha256": sha(data),
            "accepted_owner_evidence_sha256": sha(owner_raw), "accepted_claim_sha256": sha(claim_raw)}


def validate_budget(budget, inputs, tokenizer_sha256, *, grammar_profile=None, schema_compiler_sha256=None):
    """Bind the required pre-generation native counting operation to its input.

    This is a reservation with a hard 3584 admission ceiling. It is not a Python
    token count. The fixed command runs the native counter first; only its zero
    exit may exec the model. Its original result is validated after waitpid and
    before any model text can reach the unchanged provider decision parser.
    """
    require(isinstance(budget, dict) and budget.get("schema") == "hepta.qairt-token-budget.v1"
            and budget.get("profile") == PROFILE["name"] and budget.get("tokenizer_sha256") == tokenizer_sha256
            and budget.get("input_sha256") == inputs
            and budget.get("method") == "native_pre_generation_tokenizer_required"
            and budget.get("python_token_count_performed") is False, "native QAIRT token admission absent or unbound")
    require(type(budget.get("admission_limit_tokens")) is int and budget["admission_limit_tokens"] == 3584
            and budget.get("generation_tokens") == 256 and type(budget.get("generation_tokens")) is int
            and budget.get("reserved_tokens") == 256 and type(budget.get("reserved_tokens")) is int
            and budget.get("context_tokens") == 4096 and type(budget.get("context_tokens")) is int,
            "QAIRT budget exceeds the compiled 4096 context")
    require(hex_string(budget.get("counter_contract_sha256"), 64), "token counter/template contract pin absent")
    require(budget.get("grammar_profile") == grammar_profile, "output grammar profile/budget differs")
    if grammar_profile is None:
        require(inputs["grammar"] is None and budget.get("schema_conversion") is None,
                "original QAIRT runtime must not receive grammar")
    else:
        require(grammar_profile in GRAMMAR_PROFILES and hex_string(inputs["grammar"], 64)
                and hex_string(schema_compiler_sha256, 64), "output grammar input/pin absent")
        proof = budget.get("schema_conversion")
        require(isinstance(proof, dict) and proof.get("schema") == "hepta.schema-gbnf-conversion.v1"
                and proof.get("subset") == GRAMMAR_SUBSET
                and proof.get("reference_converter_commit") == GRAMMAR_CONVERTER_COMMIT
                and proof.get("compiler_kind") == GRAMMAR_COMPILER_KIND
                and proof.get("compiler_source_sha256") == schema_compiler_sha256
                and proof.get("grammar_sha256") == inputs["grammar"] and proof.get("grammar_root") == "root"
                and proof.get("root_schema_kind") in {"mobile_use", "health_final_only"}
                and hex_string(proof.get("original_schema_sha256"), 64)
                and hex_string(proof.get("canonical_schema_sha256"), 64), "schema/grammar conversion binding differs")
        require(all(type(proof.get(key)) is int and 0 < proof[key] <= 65536
                    for key in ("original_schema_bytes", "grammar_bytes"))
                and all(proof.get(key) is True for key in ("input_bytes_preserved", "conversion_completed"))
                and all(proof.get(key) is False for key in ("model_loaded", "native_action_authorized", "production_receipt")),
                "schema converter did not finish cleanly")
        require(not ({"executable_elf", "returncode", "child_waited", "input_sent_unchanged"} & set(proof)),
                "in-process Python conversion is not a native subprocess receipt")
    return budget["admission_limit_tokens"]


class NativeBackend:
    def __init__(self, config: BackendConfig, transport=None):
        self.config = config
        self.transport = transport or R6Transport()
        self.policy = self.transport.policy
        config.validate(self.policy)

    def _command(self, request_id, native_dir, has_system, has_grammar, has_image):
        c = self.config
        args = [c.worker_android, "--request-id", request_id, "--mode", "vlm", "--runtime", "qairt", "--compute", "npu",
                "--model", c.model_android, "--tokenizer", c.tokenizer_android, "--ctx-size", "0", "--max-tokens", "256",
                "--timeout-ms", str(c.max_worker_ms), "--prompt-file", native_dir + "/prompt.txt",
                "--result-file", native_dir + "/worker-result.json", "--text-file", native_dir + "/generated.bin"]
        for enabled, flag, name in ((has_system, "--system-file", "system.txt"), (has_grammar, "--grammar-file", "grammar.txt"),
                                    (has_image, "--image", "current.png")):
            if enabled:
                args += [flag, native_dir + "/" + name]
        # Only fixed code/config and shell-quoted paths are executable. Prompt,
        # generated text, tool output and image bytes never enter this command.
        env = ["LD_LIBRARY_PATH=" + c.ld_library_path, "ADSP_LIBRARY_PATH=" + c.adsp_library_path,
               "GENIEX_PLUGIN_PATH=" + c.plugin_path, "GENIEX_QAIRT_LIB=" + c.qairt_lib_path,
               "GGML_HEXAGON_PROFILE=0", "GGML_HEXAGON_VERBOSE=0"]
        if self.policy.production:
            env_binary, sha_binary = "/system/bin/env", "/system/bin/sha256sum"
        else:
            env_binary, sha_binary = "/usr/bin/env", "/usr/bin/sha256sum"
        env.append("PATH=/system/bin:/vendor/bin" if self.policy.production else "PATH=/usr/bin:/bin")
        checks = []
        if self.policy.production and c.grammar_profile in GRAMMAR_PROFILES:
            # These directories precede the pinned QAIRT directory. Even a
            # dangling symlink is an unexpected shadow and must stop this exact
            # request before any tokenizer or model process can start.
            for directory in (c.plugin_path, c.plugin_path + "/llama_cpp"):
                for name in ("libgeniex_core.so", "libgeniex_vlm.so"):
                    shadow = shlex.quote(directory + "/" + name)
                    checks.append("[ ! -e " + shadow + " ] && [ ! -L " + shadow + " ] || exit 65")
        artifacts = [(c.worker_android, c.worker_sha256), (c.counter_android, c.counter_sha256),
                     (c.tokenizer_library_android, c.tokenizer_library_sha256), (c.tokenizer_android, c.tokenizer_sha256)]
        if c.grammar_profile is not None:
            artifacts.append((c.core_android, c.core_sha256))
            artifacts.append(c.selected_vlm())
        for path, expected_sha in artifacts:
            verify = shlex.quote(sha_binary) + " " + shlex.quote(path)
            checks.append("[ \"$(" + verify + ")\" = " + shlex.quote(expected_sha + "  " + path) + " ] || exit 65")
        counter = [c.counter_android, "--request-id", request_id, "--library", c.tokenizer_library_android,
            "--library-sha256", c.tokenizer_library_sha256, "--tokenizer", c.tokenizer_android,
            "--tokenizer-sha256", c.tokenizer_sha256, "--prompt-file", native_dir + "/prompt.txt",
            "--system-file", native_dir + "/system.txt", "--result-file", native_dir + "/counter-result.json",
            "--max-prompt", "3584"]
        if has_image:
            counter += ["--image", native_dir + "/current.png"]
        require(has_system and has_grammar == (c.grammar_profile in GRAMMAR_PROFILES),
                "native QAIRT system/grammar selection differs from the configured runtime")
        return ("cd " + shlex.quote(str(PurePosixPath(c.model_android).parent)) + " || exit 65; "
                + "; ".join(checks) + "; " + shlex.join([env_binary, "-i", *env, *counter]) + " && exec "
                + shlex.join([env_binary, "-i", *env, *args]))

    def run(self, *, request_id, prompt: bytes, system: bytes | None, grammar: bytes | None, image: bytes | None,
            owner_path: Path, owner_claim_path: Path, budget: dict, gate: CancelGate, on_poll: Callable | None = None):
        # The ordinary request interface, owner proof and resulting evidence
        # shapes are unchanged. Startup diagnostics have a separate entry point
        # and never manufacture an accepted user turn.
        return self._run_bound(request_id=request_id, prompt=prompt, system=system, grammar=grammar, image=image,
            binding_loader=lambda: owner_binding(owner_path, owner_claim_path), budget=budget, gate=gate, on_poll=on_poll)

    def run_startup_health(self, *, candidate: Path, counter, compiler, gate: CancelGate,
                           on_poll: Callable | None = None):
        import startup_health
        prepared = startup_health.prepare_request(self, candidate, counter, compiler)
        def binding_loader():
            current = startup_health.startup_binding(self, candidate)
            require(current == prepared["binding"], "startup proof changed before native intent")
            return current
        return self._run_bound(request_id=prepared["request_id"], prompt=startup_health.PROMPT,
            system=startup_health.SYSTEM, grammar=prepared["grammar"], image=None,
            binding_loader=binding_loader, budget=prepared["budget"], gate=gate, on_poll=on_poll)

    def _run_bound(self, *, request_id, prompt: bytes, system: bytes | None, grammar: bytes | None,
                   image: bytes | None, binding_loader: Callable, budget: dict, gate: CancelGate,
                   on_poll: Callable | None = None):
        require(hex_string(request_id, 32), "request identity malformed")
        inputs = {"prompt": prompt, "system": system, "grammar": grammar, "image": image}
        for key, raw in inputs.items():
            if raw is None:
                require(key != "prompt", "prompt missing"); continue
            require(isinstance(raw, bytes) and 0 < len(raw) <= (8 * 1024 * 1024 if key == "image" else 65536), "input size/type differs")
            if key != "image":
                raw.decode("utf-8", errors="strict"); require(b"\0" not in raw, "NUL text input")
        expected_inputs = {key: sha(raw) if raw is not None else None for key, raw in inputs.items()}
        admission_limit = validate_budget(budget, expected_inputs, self.config.tokenizer_sha256,
            grammar_profile=self.config.grammar_profile, schema_compiler_sha256=self.config.schema_compiler_sha256)
        binding = binding_loader()
        lock_fd = os.open(self.config.evidence_root / "backend.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            lock_info = os.fstat(lock_fd)
            require(stat.S_ISREG(lock_info.st_mode) and lock_info.st_uid == os.getuid() and lock_info.st_nlink == 1
                    and stat.S_IMODE(lock_info.st_mode) == 0o600, "backend lock identity differs")
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for old in self.config.evidence_root.iterdir():
                if old.is_dir():
                    terminal = old / "terminal.json"
                    require(terminal.exists(), "prior GenieX intent unresolved; inspect original action")
                    row = strict_json(read_private(terminal, os.getuid(), 131072))
                    require(row.get("cleanup_confirmed") is True and row.get("state") != "unknown", "prior GenieX cleanup UNKNOWN")
                    original_intent = read_private(old / "intent.json", os.getuid(), 131072)
                    require(row.get("intent_sha256") == sha(original_intent), "prior GenieX intent bytes differ")
                    if row.get("proof_type") == "native_r6_waitpid_process_group.v1":
                        original_native = read_private(old / "native-result.json", os.getuid(), 12 * 1024 * 1024)
                        dispatch = strict_json(read_private(old / "dispatch-intent.json", os.getuid(), 65536))
                        require(row.get("native_sha") == sha(original_native), "prior native receipt bytes differ")
                        validate_native(strict_json(original_native), request_id=row["request_id"],
                            command_sha256=dispatch["command_sha256"], server_instance=dispatch["server_instance"], policy=self.policy)
                    else:
                        require(row.get("proof_type") == "known_not_dispatched.v1" and not (old / "dispatch-intent.json").exists(),
                                "prior no-dispatch proof differs")
            directory = self.config.evidence_root / request_id
            directory.mkdir(mode=0o700, exist_ok=False)
            sync_directory(self.config.evidence_root)
            gate.bind(directory)
            stage = self.config.stage_root / request_id
            stage.mkdir(mode=0o700, exist_ok=False)
            if self.policy.execution_uid != os.getuid():
                os.chown(stage, self.policy.execution_uid, self.policy.execution_uid)
            sync_directory(self.config.stage_root)
            private_dir(stage, self.policy.execution_uid)
            native_dir = self.config.android_stage_root + "/" + request_id
            command = self._command(request_id, native_dir, system is not None, grammar is not None, image is not None)
            command_digest = sha(command.encode())
            intent = {"schema": "hepta.geniex-native-intent.v1", "request_id": request_id, **binding,
                      "backend_config_sha256": self.config.digest(), "artifact_manifest_sha256": self.config.artifact_manifest_sha256,
                      "worker_source_sha256": WORKER_SOURCE_SHA, "worker_executable_sha256": self.config.worker_sha256,
                      "counter_executable_sha256": self.config.counter_sha256,
                      "tokenizer_library_sha256": self.config.tokenizer_library_sha256,
                      "grammar_profile": self.config.grammar_profile, "core_sha256": self.config.core_sha256,
                      **self.config.vlm_binding(),
                      "schema_compiler_sha256": self.config.schema_compiler_sha256,
                      "input_sha256": expected_inputs, "token_budget": budget, "command_sha256": command_digest,
                      "profile": PROFILE, "stage_directory": str(stage), "android_stage_directory": native_dir,
                      "endpoint": self.transport.endpoint, "automatic_retry": False, "can_redispatch": False}
            if binding.get("request_kind") == "startup_health":
                intent["schema"] = "hepta.geniex-startup-native-intent.v1"
            exclusive(directory / "intent.json", canonical_json(intent))
            for name, key in (("prompt.txt", "prompt"), ("system.txt", "system"), ("grammar.txt", "grammar"), ("current.png", "image")):
                if inputs[key] is not None:
                    exclusive(stage / name, inputs[key], self.policy.execution_uid)
            if on_poll:
                on_poll()
            if gate.cancelled:
                return self._terminal(directory, intent, "cancelled", True, False, "cancelled_before_native_dispatch")
            try:
                health = self.transport.health()
                exclusive(directory / "native-health.json", canonical_json(health))
                require(health.get("protocol") == PROTOCOL and health.get("executor_revision") == 6
                        and health.get("state") == "ready" and health.get("execute_authorized") is True
                        and hex_string(health.get("server_instance"), 32), "native executor not ready/authorized; original recovery gate remains enforced")
                if binding.get("request_kind") == "startup_health":
                    require(health["server_instance"] == binding["startup_binding"]["native_server_instance"],
                            "startup native executor restarted after post-exec preflight")
            except Exception as exc:
                return self._terminal(directory, intent, "failed", True, False, "known_not_dispatched: " + str(exc))
            instance = health["server_instance"]
            exclusive(directory / "dispatch-intent.json", canonical_json({"request_id": request_id,
                      "command_sha256": command_digest, "server_instance": instance, "attempt_count": 1}))
            native_envelope = None
            error = None
            try:
                native_envelope = self.transport.exchange({"op": "execute", "action_id": request_id,
                    "command_sha256": command_digest, "command": command, "timeout_ms": self.config.max_native_ms},
                    timeout=self.config.max_native_ms / 1000 + 12, gate=gate, on_poll=on_poll)
            except Exception as exc:
                error = type(exc).__name__ + ": " + str(exc)
                exclusive(directory / "transport-ended.json", canonical_json({"error": error, "automatic_retry": False}))
            if native_envelope is None:
                # This is inspection of the original action, never another execute.
                deadline = time.monotonic() + 6.0
                while time.monotonic() < deadline:
                    try:
                        observed = self.transport.inspect(request_id, command_digest, include_output=True)
                        if observed.get("receipt", {}).get("terminal") is True:
                            native_envelope = observed; break
                    except Exception:
                        pass
                    time.sleep(0.05)
            if native_envelope is None:
                return self._terminal(directory, intent, "unknown", False, False, error or "native termination unavailable")
            native_raw = canonical_json(native_envelope)
            exclusive(directory / "native-result.json", native_raw)
            try:
                native = validate_native(native_envelope, request_id=request_id, command_sha256=command_digest,
                                         server_instance=instance, policy=self.policy)
            except Exception as exc:
                return self._terminal(directory, intent, "unknown", False, False, str(exc), native_sha=sha(native_raw))
            if on_poll:
                on_poll()
            counter_raw = None
            try:
                counter_raw = read_private(stage / "counter-result.json", self.policy.execution_uid, 131072)
                # Preserve original counter diagnostics even if it denied the
                # prompt or a later SDK abort produced no worker metadata.
                exclusive(directory / "counter-result.json", counter_raw)
            except FileNotFoundError:
                pass
            except Exception as exc:
                return self._terminal(directory, intent, "failed", True, False,
                                      "counter_evidence_unreadable: " + str(exc), native_sha=sha(native_raw))
            counter_hashes = {"counter_sha": sha(counter_raw)} if counter_raw is not None else {}
            if gate.cancelled or native["state"] == "cancelled":
                return self._terminal(directory, intent, "cancelled", True, False,
                                      "accepted_cancel_or_native_cancel", native_sha=sha(native_raw), **counter_hashes)
            if native["state"] == "timed_out":
                return self._terminal(directory, intent, "timed_out", True, False,
                                      "native_supervisor_timeout", timeout_origin="native_supervisor",
                                      native_sha=sha(native_raw), **counter_hashes)
            if (native["state"] == "completed" and type(native.get("exit_code")) is int
                    and native["exit_code"] == 124 and native.get("term_signal") is None
                    and native.get("client_disconnected") is False and native.get("error") in (None, "")):
                try:
                    deadline_raw = read_private(stage / "worker-result.json", self.policy.execution_uid, 131072)
                    exclusive(directory / "worker-result.json", deadline_raw)
                    validate_worker_deadline(strict_json(deadline_raw), native, request_id=request_id,
                        expected_inputs=expected_inputs, expected_model=self.config.model_android,
                        expected_output_path=native_dir + "/generated.bin")
                except Exception as exc:
                    return self._terminal(directory, intent, "failed", True, False,
                                          "unverified_worker_deadline: " + str(exc), native_sha=sha(native_raw), **counter_hashes)
                return self._terminal(directory, intent, "timed_out", True, False,
                                      "worker_deadline_observed", timeout_origin="frozen_worker",
                                      native_sha=sha(native_raw), worker_sha=sha(deadline_raw), **counter_hashes)
            if not (native["state"] == "completed" and type(native.get("exit_code")) is int and native["exit_code"] == 0
                    and native.get("term_signal") is None and native.get("client_disconnected") is False
                    and native.get("error") in (None, "")):
                return self._terminal(directory, intent, "failed", True, False, "native_process_did_not_exit_successfully",
                                      native_sha=sha(native_raw), **counter_hashes)
            try:
                require(counter_raw is not None, "successful native process has no original tokenizer admission")
                counter_result = strict_json(counter_raw)
                admitted_tokens = validate_counter(counter_result, native, request_id=request_id,
                    expected_inputs=expected_inputs, original_inputs=inputs, config=self.config, admission_limit=admission_limit)
                result_raw = read_private(stage / "worker-result.json", self.policy.execution_uid, 131072)
                text = read_private(stage / "generated.bin", self.policy.execution_uid, MAX_RAW_TEXT)
                result = strict_json(result_raw)
                decoded = validate_worker(result, text, native, request_id=request_id, expected_inputs=expected_inputs,
                    expected_model=self.config.model_android, expected_output_path=native_dir + "/generated.bin",
                    expected_formatted_sha256=sha(b"<__image__>".join(formatter_segments(inputs))),
                    max_prompt_tokens=admitted_tokens, policy=self.policy)
            except Exception as exc:
                return self._terminal(directory, intent, "failed", True, False, str(exc), native_sha=sha(native_raw))
            # Retain original worker bytes privately before accepting completion.
            exclusive(directory / "worker-result.json", result_raw)
            exclusive(directory / "generated.bin", text)
            if on_poll:
                on_poll()
            if not gate.accept_completion():
                return self._terminal(directory, intent, "cancelled", True, False, "cancel_won_completion_acceptance",
                                      native_sha=sha(native_raw), worker_sha=sha(result_raw), text_sha=sha(text), counter_sha=sha(counter_raw))
            receipt = self._terminal(directory, intent, "completed", True, True, None, native_sha=sha(native_raw),
                                     worker_sha=sha(result_raw), text_sha=sha(text), counter_sha=sha(counter_raw),
                                     admitted_prompt_tokens_upper_bound=admitted_tokens)
            return {"receipt": receipt["receipt"], "text": decoded}
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN); os.close(lock_fd)

    def _terminal(self, directory, intent, state, cleanup, usable, error, **hashes):
        proof_type = ("known_not_dispatched.v1" if not (directory / "dispatch-intent.json").exists() else
                      "native_r6_waitpid_process_group.v1" if cleanup else "unresolved_native_action.v1")
        row = {"schema": "hepta.geniex-isolated-process-receipt.v1", "proof_type": proof_type,
               "request_id": intent["request_id"], "intent_sha256": sha(canonical_json(intent)), "state": state,
               "cleanup_confirmed": cleanup, "model_result_usable": usable, "error": error,
               "inference_backend": "geniex_qairt_isolated_process", "profile": PROFILE["name"],
               "grammar_profile": self.config.grammar_profile, "core_sha256": self.config.core_sha256,
               **self.config.vlm_binding(),
               "proof_environment": "android_native" if self.policy.production else "host_fixture",
               "automatic_retry": False, "can_redispatch": False, "native_action_authorized": False, **hashes}
        if intent.get("request_kind") == "startup_health":
            row.update(schema="hepta.geniex-startup-process-receipt.v1", request_kind="startup_health",
                       startup_binding_sha256=sha(canonical_json(intent["startup_binding"])))
        exclusive(directory / "terminal.json", canonical_json(row))
        return {"receipt": row, "text": None}
