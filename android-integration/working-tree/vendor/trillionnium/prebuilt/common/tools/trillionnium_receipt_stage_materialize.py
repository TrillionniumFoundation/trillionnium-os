#!/usr/bin/env python3
"""Deterministically materialize the fixed Android receipt-stage v1 tree.

Twenty-four physical build/evidence inputs are retained by descriptor for the
entire operation.  The three runtime documents and the self-hashed stage
receipt are derived, never accepted from the caller.  A custody + publication
round trip through the shared verifier must pass before the absent target
directory is atomically published.
"""

from __future__ import annotations

import argparse
import copy
import ctypes
import errno
import os
from pathlib import Path
import secrets
import stat
import sys
from dataclasses import dataclass
from typing import Mapping, Sequence

if __package__:
    from . import trillionnium_receipt_stage_verify as VERIFY
else:
    import trillionnium_receipt_stage_verify as VERIFY


PHYSICAL_ROLES = VERIFY.EXPECTED_ROLES[:-3]
DERIVED_ROLES = VERIFY.EXPECTED_ROLES[-3:]
STAGE_RECEIPT = "receipt-stage.v1.json"
WORKSPACE_PREFIX = ".receipt-stage-materialize."
RENAME_NOREPLACE = 1


def directory_flags() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def regular_flags() -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def clean_basename(value: str, label: str) -> str:
    if value in {"", ".", ".."} or os.path.basename(value) != value:
        raise VERIFY.StageError(f"{label} is not a clean basename")
    return value


def read_exact_fd(fd: int, size: int, label: str) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(fd, min(1024 * 1024, remaining))
        if not chunk:
            raise VERIFY.StageError(f"{label} bytes were truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(fd, 1):
        raise VERIFY.StageError(f"{label} bytes grew during validation")
    return b"".join(chunks)


@dataclass
class OwnedDirectory:
    parent: object
    name: str
    label: str
    display_path: str
    fd: int
    initial: os.stat_result
    expected_mode: int

    @classmethod
    def create(
        cls,
        parent: object,
        name: str,
        label: str,
        display_path: str,
        mode: int,
    ) -> "OwnedDirectory":
        name = clean_basename(name, label)
        parent.assert_stable()
        created: os.stat_result | None = None
        fd = -1
        try:
            os.mkdir(name, mode, dir_fd=parent.fd)
            created = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
            fd = os.open(name, directory_flags(), dir_fd=parent.fd)
            held = os.fstat(fd)
            if VERIFY.directory_identity(held) != VERIFY.directory_identity(created):
                raise VERIFY.StageError(f"{label} changed while opening")
            VERIFY.validate_directory_policy(held, label)
            if stat.S_IMODE(held.st_mode) != mode:
                raise VERIFY.StageError(f"{label} mode drifted while creating")
            os.fsync(parent.fd)
            result = cls(
                parent=parent,
                name=name,
                label=label,
                display_path=display_path,
                fd=fd,
                initial=held,
                expected_mode=mode,
            )
            result.assert_stable()
            return result
        except FileExistsError as error:
            raise VERIFY.StageError(f"{label} already exists") from error
        except BaseException as primary:
            cleanup_errors: list[BaseException] = []
            if fd >= 0:
                try:
                    os.close(fd)
                except BaseException as error:
                    cleanup_errors.append(error)
            if created is not None:
                try:
                    current = os.stat(
                        name, dir_fd=parent.fd, follow_symlinks=False
                    )
                    if VERIFY.inode_identity(current) != VERIFY.inode_identity(created):
                        raise VERIFY.StageError(
                            f"{label} cleanup refused a replaced directory"
                        )
                    os.rmdir(name, dir_fd=parent.fd)
                    os.fsync(parent.fd)
                except FileNotFoundError:
                    pass
                except BaseException as error:
                    cleanup_errors.append(error)
            if cleanup_errors:
                raise VERIFY.StageError(
                    f"{label} creation failed: {primary}; cleanup also failed: "
                    + "; ".join(str(error) for error in cleanup_errors)
                ) from primary
            raise

    def reanchor(self, parent: object, name: str, display_path: str) -> None:
        self.parent = parent
        self.name = clean_basename(name, self.label)
        self.display_path = display_path

    def assert_stable(self) -> None:
        self.parent.assert_stable()
        held = os.fstat(self.fd)
        if VERIFY.directory_identity(held) != VERIFY.directory_identity(self.initial):
            raise VERIFY.StageError(f"{self.label} retained directory changed")
        lexical = os.stat(self.name, dir_fd=self.parent.fd, follow_symlinks=False)
        if VERIFY.directory_identity(lexical) != VERIFY.directory_identity(
            self.initial
        ):
            raise VERIFY.StageError(f"{self.label} pathname identity changed")
        if (
            not stat.S_ISDIR(held.st_mode)
            or stat.S_IMODE(held.st_mode) != self.expected_mode
        ):
            raise VERIFY.StageError(f"{self.label} directory metadata changed")

    def close(self) -> None:
        os.close(self.fd)


@dataclass
class OwnedFile:
    parent: OwnedDirectory
    name: str
    label: str
    relative_path: str
    fd: int
    initial: os.stat_result
    expected_raw: bytes
    expected_mode: int

    @classmethod
    def publish(
        cls,
        parent: OwnedDirectory,
        name: str,
        label: str,
        relative_path: str,
        raw: bytes,
        mode: int,
    ) -> "OwnedFile":
        name = clean_basename(name, label)
        parent.assert_stable()
        try:
            os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise VERIFY.StageError(f"{label} already exists")
        temporary = f".receipt-stage.{secrets.token_hex(16)}"
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = -1
        linked = False
        cleanup_errors: list[BaseException] = []
        try:
            fd = os.open(temporary, flags, 0o600, dir_fd=parent.fd)
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise VERIFY.StageError(f"{label} write stalled")
                view = view[written:]
            os.fchmod(fd, mode)
            os.fsync(fd)
            os.link(
                temporary,
                name,
                src_dir_fd=parent.fd,
                dst_dir_fd=parent.fd,
                follow_symlinks=False,
            )
            linked = True
            os.unlink(temporary, dir_fd=parent.fd)
            temporary = ""
            os.fsync(parent.fd)
            initial = os.fstat(fd)
            if (
                not stat.S_ISREG(initial.st_mode)
                or stat.S_IMODE(initial.st_mode) != mode
                or initial.st_nlink != 1
                or initial.st_size != len(raw)
                or initial.st_uid not in {0, os.geteuid()}
            ):
                raise VERIFY.StageError(f"{label} metadata drifted while publishing")
            result = cls(
                parent=parent,
                name=name,
                label=label,
                relative_path=relative_path,
                fd=fd,
                initial=initial,
                expected_raw=raw,
                expected_mode=mode,
            )
            result.assert_stable()
            return result
        except BaseException as primary:
            if linked and fd >= 0:
                try:
                    current = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
                    if VERIFY.inode_identity(current) != VERIFY.inode_identity(
                        os.fstat(fd)
                    ):
                        raise VERIFY.StageError(
                            f"{label} cleanup refused a replaced pathname"
                        )
                    os.unlink(name, dir_fd=parent.fd)
                except FileNotFoundError:
                    pass
                except BaseException as error:
                    cleanup_errors.append(error)
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=parent.fd)
                except FileNotFoundError:
                    pass
                except BaseException as error:
                    cleanup_errors.append(error)
            if fd >= 0:
                try:
                    os.close(fd)
                except BaseException as error:
                    cleanup_errors.append(error)
            if cleanup_errors:
                raise VERIFY.StageError(
                    f"{label} publication failed: {primary}; cleanup also failed: "
                    + "; ".join(str(error) for error in cleanup_errors)
                ) from primary
            raise

    def metadata_failures(self, suffix: str) -> list[str]:
        failures: list[str] = []
        held = os.fstat(self.fd)
        if VERIFY.stat_identity(held) != VERIFY.stat_identity(self.initial):
            failures.append(f"retained inode changed{suffix}")
        if (
            not stat.S_ISREG(held.st_mode)
            or stat.S_IMODE(held.st_mode) != self.expected_mode
            or held.st_nlink != 1
            or held.st_size != len(self.expected_raw)
        ):
            failures.append(f"retained metadata changed{suffix}")
        try:
            self.parent.assert_stable()
        except BaseException as error:
            failures.append(f"retained parent changed{suffix}: {error}")
        try:
            lexical = os.stat(
                self.name, dir_fd=self.parent.fd, follow_symlinks=False
            )
        except BaseException as error:
            failures.append(f"pathname unavailable{suffix}: {error}")
        else:
            if VERIFY.stat_identity(lexical) != VERIFY.stat_identity(self.initial):
                failures.append(f"pathname identity changed{suffix}")
            if (
                not stat.S_ISREG(lexical.st_mode)
                or stat.S_IMODE(lexical.st_mode) != self.expected_mode
                or lexical.st_nlink != 1
                or lexical.st_size != len(self.expected_raw)
            ):
                failures.append(f"pathname metadata changed{suffix}")
        return failures

    def assert_metadata(self) -> None:
        failures = self.metadata_failures("")
        if failures:
            raise VERIFY.StageError(f"{self.label}: " + "; ".join(failures))

    def assert_stable(self) -> None:
        failures = self.metadata_failures(" before read")
        if failures:
            raise VERIFY.StageError(f"{self.label}: " + "; ".join(failures))
        raw = read_exact_fd(self.fd, len(self.expected_raw), self.label)
        if raw != self.expected_raw:
            raise VERIFY.StageError(f"{self.label} bytes changed")
        failures = self.metadata_failures(" after read")
        if failures:
            raise VERIFY.StageError(
                f"{self.label} post-read stability check failed: "
                + "; ".join(failures)
            )

    def close(self) -> None:
        os.close(self.fd)


@dataclass
class RetainedStageTree:
    root: OwnedDirectory
    directories: dict[str, OwnedDirectory]
    files: dict[str, OwnedFile]

    @classmethod
    def create(
        cls,
        parent: OwnedDirectory,
        root_name: str,
        display_path: str,
        specs: Mapping[str, Mapping[str, object]],
        raw_by_role: Mapping[str, bytes],
        receipt_raw: bytes,
    ) -> "RetainedStageTree":
        root = OwnedDirectory.create(
            parent,
            root_name,
            "candidate receipt-stage root",
            display_path,
            0o755,
        )
        directories = {"": root}
        files: dict[str, OwnedFile] = {}

        def ensure_directory(relative: str) -> OwnedDirectory:
            if relative in directories:
                return directories[relative]
            parent_relative, _, name = relative.rpartition("/")
            parent_directory = ensure_directory(parent_relative)
            directory = OwnedDirectory.create(
                parent_directory,
                name,
                f"candidate stage directory {relative}",
                os.path.join(display_path, relative),
                0o755,
            )
            directories[relative] = directory
            return directory

        plans = [
            (
                str(specs[role]["stage_path"]),
                raw_by_role[role],
                int(str(specs[role]["mode"]), 8),
                f"candidate stage artifact {role}",
            )
            for role in VERIFY.EXPECTED_ROLES
        ]
        plans.append((STAGE_RECEIPT, receipt_raw, 0o444, "candidate stage receipt"))
        for relative, raw, mode, label in plans:
            VERIFY.clean_relative_path(relative, label)
            parent_relative, _, name = relative.rpartition("/")
            directory = ensure_directory(parent_relative)
            files[relative] = OwnedFile.publish(
                directory, name, label, relative, raw, mode
            )
        result = cls(root=root, directories=directories, files=files)
        result.assert_stable()
        return result

    def expected_children(self) -> dict[str, set[str]]:
        result = {relative: set() for relative in self.directories}
        for relative in self.directories:
            if not relative:
                continue
            parent, _, name = relative.rpartition("/")
            result[parent].add(name)
        for relative in self.files:
            parent, _, name = relative.rpartition("/")
            result[parent].add(name)
        return result

    def assert_layout(self) -> None:
        expected = self.expected_children()
        for relative, directory in self.directories.items():
            directory.assert_stable()
            observed = {entry.name for entry in os.scandir(directory.fd)}
            if observed != expected[relative]:
                raise VERIFY.StageError(
                    f"candidate stage layout drifted at {relative or '.'}"
                )
        for item in self.files.values():
            item.assert_metadata()

    def assert_stable(self) -> None:
        self.assert_layout()
        for item in self.files.values():
            item.assert_stable()
        # The whole-tree postcheck closes the gap between each individual
        # file's post-read check and the end of the final materializer gate.
        self.assert_layout()

    def close_non_root(self) -> list[tuple[str, BaseException]]:
        failures: list[tuple[str, BaseException]] = []
        for relative, item in reversed(list(self.files.items())):
            try:
                item.close()
            except BaseException as error:
                failures.append((f"output file teardown {relative}", error))
        children = sorted(
            ((path, item) for path, item in self.directories.items() if path),
            key=lambda pair: pair[0].count("/"),
            reverse=True,
        )
        for relative, item in children:
            try:
                item.close()
            except BaseException as error:
                failures.append((f"output directory teardown {relative}", error))
        return failures


def rename_noreplace(
    source_parent_fd: int,
    source_name: str,
    target_parent_fd: int,
    target_name: str,
) -> None:
    source_name = clean_basename(source_name, "rename source")
    target_name = clean_basename(target_name, "rename target")
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "renameat2", None)
    if function is None:
        raise VERIFY.StageError("host libc lacks renameat2(RENAME_NOREPLACE)")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    if (
        function(
            source_parent_fd,
            os.fsencode(source_name),
            target_parent_fd,
            os.fsencode(target_name),
            RENAME_NOREPLACE,
        )
        == 0
    ):
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise VERIFY.StageError("receipt-stage output target already exists")
    raise OSError(error_number, os.strerror(error_number))


def directory_names(directory: OwnedDirectory) -> set[str]:
    directory.assert_stable()
    return {entry.name for entry in os.scandir(directory.fd)}


def read_regular_at(
    directory: OwnedDirectory,
    name: str,
    label: str,
    expected_mode: int,
) -> bytes:
    name = clean_basename(name, label)
    directory.assert_stable()
    before = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != expected_mode
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > VERIFY.MAX_INPUT_BYTES
    ):
        raise VERIFY.StageError(f"{label} metadata is invalid")
    fd = os.open(name, regular_flags(), dir_fd=directory.fd)
    try:
        held_before = os.fstat(fd)
        if VERIFY.stat_identity(held_before) != VERIFY.stat_identity(before):
            raise VERIFY.StageError(f"{label} changed while opening")
        raw = read_exact_fd(fd, before.st_size, label)
        failures: list[str] = []
        held_after = os.fstat(fd)
        if VERIFY.stat_identity(held_after) != VERIFY.stat_identity(before):
            failures.append("retained inode changed after read")
        try:
            directory.assert_stable()
        except BaseException as error:
            failures.append(f"retained parent changed after read: {error}")
        try:
            lexical_after = os.stat(
                name, dir_fd=directory.fd, follow_symlinks=False
            )
        except BaseException as error:
            failures.append(f"pathname unavailable after read: {error}")
        else:
            if VERIFY.stat_identity(lexical_after) != VERIFY.stat_identity(before):
                failures.append("pathname identity changed after read")
            if (
                not stat.S_ISREG(lexical_after.st_mode)
                or stat.S_IMODE(lexical_after.st_mode) != expected_mode
                or lexical_after.st_nlink != 1
                or lexical_after.st_size != len(raw)
            ):
                failures.append("pathname metadata changed after read")
        if failures:
            raise VERIFY.StageError(
                f"{label} post-read stability check failed: " + "; ".join(failures)
            )
        return raw
    finally:
        os.close(fd)


def validate_verifier_round_trip(
    custody: OwnedDirectory,
    published: OwnedDirectory,
    specs: Mapping[str, Mapping[str, object]],
    raw_by_role: Mapping[str, bytes],
    receipt_raw: bytes,
) -> None:
    expected: dict[str, tuple[bytes, int]] = {
        str(specs[role]["output_filename"]): (
            raw_by_role[role],
            int(str(specs[role]["mode"]), 8),
        )
        for role in VERIFY.EXPECTED_ROLES
    }
    expected[STAGE_RECEIPT] = (receipt_raw, 0o444)
    expected_names = set(expected) | {"custody.v1.json"}
    if directory_names(custody) != expected_names:
        raise VERIFY.StageError("custody verifier output layout drifted")
    for name, (raw, mode) in expected.items():
        if read_regular_at(custody, name, f"custody verifier output {name}", mode) != raw:
            raise VERIFY.StageError(f"custody verifier output bytes drifted for {name}")
    custody_raw = read_regular_at(
        custody, "custody.v1.json", "custody verifier attestation", 0o444
    )
    if directory_names(custody) != expected_names:
        raise VERIFY.StageError("custody verifier output layout changed after reads")

    if directory_names(published) != expected_names:
        raise VERIFY.StageError("publish verifier output layout drifted")
    for name, (raw, mode) in expected.items():
        if (
            read_regular_at(published, name, f"publish verifier output {name}", mode)
            != raw
        ):
            raise VERIFY.StageError(f"publish verifier output bytes drifted for {name}")
    if (
        read_regular_at(
            published,
            "custody.v1.json",
            "publish verifier custody attestation",
            0o444,
        )
        != custody_raw
    ):
        raise VERIFY.StageError("publish verifier custody attestation drifted")
    if directory_names(published) != expected_names:
        raise VERIFY.StageError("publish verifier output layout changed after reads")


def remove_directory_contents(fd: int, device: int, label: str) -> None:
    for entry in sorted(os.scandir(fd), key=lambda item: item.name):
        name = clean_basename(entry.name, f"{label} cleanup entry")
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(before.st_mode):
            child_fd = os.open(name, directory_flags(), dir_fd=fd)
            try:
                held = os.fstat(child_fd)
                if (
                    VERIFY.inode_identity(held) != VERIFY.inode_identity(before)
                    or held.st_dev != device
                ):
                    raise VERIFY.StageError(
                        f"{label} cleanup refused a changed or foreign directory {name}"
                    )
                remove_directory_contents(child_fd, device, f"{label}/{name}")
                held_after = os.fstat(child_fd)
                lexical_after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if (
                    VERIFY.inode_identity(held_after)
                    != VERIFY.inode_identity(before)
                    or VERIFY.inode_identity(lexical_after)
                    != VERIFY.inode_identity(before)
                ):
                    raise VERIFY.StageError(
                        f"{label} cleanup refused a replaced directory {name}"
                    )
                os.rmdir(name, dir_fd=fd)
            finally:
                os.close(child_fd)
        else:
            current = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if VERIFY.stat_identity(current) != VERIFY.stat_identity(before):
                raise VERIFY.StageError(
                    f"{label} cleanup refused a replaced entry {name}"
                )
            os.unlink(name, dir_fd=fd)
    os.fsync(fd)


def cleanup_owned_root(
    parent: object,
    name: str,
    expected: os.stat_result,
    label: str,
) -> None:
    name = clean_basename(name, label)
    parent.assert_stable()
    try:
        lexical = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if VERIFY.directory_identity(lexical) != VERIFY.directory_identity(expected):
        raise VERIFY.StageError(f"{label} cleanup refused a replaced pathname")
    fd = os.open(name, directory_flags(), dir_fd=parent.fd)
    try:
        held = os.fstat(fd)
        if VERIFY.directory_identity(held) != VERIFY.directory_identity(expected):
            raise VERIFY.StageError(f"{label} cleanup opened a changed directory")
        remove_directory_contents(fd, held.st_dev, label)
        held_after = os.fstat(fd)
        parent.assert_stable()
        lexical_after = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        if (
            VERIFY.directory_identity(held_after)
            != VERIFY.directory_identity(expected)
            or VERIFY.directory_identity(lexical_after)
            != VERIFY.directory_identity(expected)
        ):
            raise VERIFY.StageError(f"{label} cleanup refused a replaced pathname")
        os.rmdir(name, dir_fd=parent.fd)
        os.fsync(parent.fd)
    finally:
        os.close(fd)


def raise_materialization_errors(
    errors: Sequence[tuple[str, BaseException]],
) -> None:
    if not errors:
        return
    phase, primary = errors[0]
    message = f"{phase}: {primary}"
    if len(errors) > 1:
        message += "; secondary failures: " + "; ".join(
            f"{secondary_phase}: {error}"
            for secondary_phase, error in errors[1:]
        )
    raise VERIFY.StageError(message) from primary


def parse_inputs(values: Sequence[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        role, separator, path = value.partition("=")
        if not separator or role not in PHYSICAL_ROLES or role in result or not path:
            raise VERIFY.StageError(f"invalid or duplicate physical input: {value!r}")
        result[role] = VERIFY.resolve_cli_path(path, f"physical input {role}")
    if tuple(result) != PHYSICAL_ROLES:
        raise VERIFY.StageError(
            f"physical inputs must contain the exact ordered {len(PHYSICAL_ROLES)}-role source set"
        )
    return result


def role_entry(
    spec: Mapping[str, object],
    raw: bytes,
    *,
    document_schema: str | None = None,
) -> dict[str, object]:
    result = {
        "bytes": len(raw),
        "document_schema": (
            spec["document_schema"] if document_schema is None else document_schema
        ),
        "install_path": spec["install_path"],
        "kind": spec["kind"],
        "mode": spec["mode"],
        "role": spec["role"],
        "semantic": spec["semantic"],
        "sha256": VERIFY.sha256(raw),
        "stage_path": spec["stage_path"],
        "tag": spec["tag"],
    }
    if "install_paths" in spec:
        result["install_paths"] = spec["install_paths"]
    return result


def kv_bytes(values: Mapping[str, object]) -> bytes:
    return "".join(f"{key}={values[key]}\n" for key in sorted(values)).encode()


def root_manifest_overrides(
    required: Mapping[str, str],
    entries: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    return {
        **required,
        "agent_accessibility_build_variants": "userdebug",
        "agent_accessibility_sha256": entries["common_accessibility"]["sha256"],
        "agent_operation_first_use_authority": "daemon_sealed_hardware_anchor_hold_userdebug_only",
        "agent_operation_replay_ack_transport": "source_wired_device_evidence_hold_userdebug_only",
        "agent_operation_replay_control_product_wired": "source_wired_device_evidence_hold_userdebug_only",
        "agent_system_api_epoch_activation": "source_wired_device_evidence_hold_userdebug_only",
        "agent_system_api_replay_sync_archive_presence": "present_fresh_v9_archive_with_p01_overlay",
        "agent_system_api_replay_sync_build_variants": "userdebug",
        "agent_system_api_replay_sync_protocol": "trillionnium.direct-operation-replay-sync-command.v3",
        "agent_system_api_replay_sync_protocol_role": "direct_operation_outer_ack_replay_sync",
        "agent_system_api_replay_sync_rootfs_path": "/usr/local/bin/trillionnium-system-api-device-conformance-replay-sync",
        "agent_system_api_replay_sync_signed_source": "/system_ext/bin/trillionnium-system-api-device-conformance-replay-sync",
        "agent_system_api_replay_sync_socket": "daemon_supervised_fixed_fd_not_public_socket",
        "agentd_payload_owner": "0:2000",
        "agentd_build_variants": "userdebug",
        "android_receipt_stage_custody_path": "/system_ext/etc/trillionnium/p01-userdebug/receipt-stage-custody.v1.json",
        "android_receipt_stage_path": "/system_ext/etc/trillionnium/p01-userdebug/receipt-stage.v1.json",
        "p01_agent_manifest_path": "/system_ext/etc/trillionnium/agents/agent-codex-direct-v1.json",
        "p01_binding_schema": "trillionnium.direct-operation.binding.v3",
        "p01_daemon_binding_custody_predispatch_wired": "true_userdebug_conformance_only",
        "p01_daemon_direct_tool_call_prepared_ack_wired": "true_userdebug_conformance_only",
        "p01_daemon_logical_delivery_admission_wired": "true_userdebug_conformance_only",
        "p01_final_artifact_set_path": "/system_ext/etc/trillionnium/p01-userdebug/p01-userdebug-final-daemon-artifact-set.v5.json",
        "p01_runtime_config_path": "/system_ext/etc/trillionnium/p01-userdebug/runtime.env",
        "p01_system_api_device_replay_sync_path": "/system_ext/bin/trillionnium-system-api-device-conformance-replay-sync",
        "rootfs_common_artifact_set_path": "/system_ext/etc/trillionnium/linux/common-codex-rootfs-artifact-set.v5.json",
        "rootfs_package_contract_path": "/system_ext/etc/trillionnium/linux/rootfs-package.contract.v9.json",
        "rootfs_package_receipt_path": "/system_ext/etc/trillionnium/linux/rootfs-package-receipt.json",
    }


def derive_root_manifest(
    base: Mapping[str, str],
    contract: Mapping[str, object],
    required: Mapping[str, str],
    entries: Mapping[str, Mapping[str, object]],
) -> bytes:
    result: dict[str, object] = copy.deepcopy(dict(base))
    result.update(root_manifest_overrides(required, entries))
    for claim in contract["claims"]:
        if claim["evidence_role"] != "root_linux_manifest":
            continue
        pointer = claim["json_pointer"]
        if pointer.count("/") != 1:
            raise VERIFY.StageError("root-linux manifest claim must address one flat key")
        key = pointer[1:].replace("~1", "/").replace("~0", "~")
        result[key] = entries[claim["artifact_role"]][claim["artifact_field"]]
    return kv_bytes(result)


def stage_receipt_bytes(
    contract: Mapping[str, object],
    entries: Mapping[str, Mapping[str, object]],
    source_bom: Mapping[str, object],
) -> bytes:
    artifacts = [entries[role] for role in VERIFY.EXPECTED_ROLES]
    manifest_entry = entries["resolved_manifest"]
    bom_entry = entries["source_bom"]
    resolved = source_bom.get("resolved_manifest")
    source_set = source_bom.get("source_set")
    if type(resolved) is not dict or type(source_set) is not dict:
        raise VERIFY.StageError("source BOM lacks resolved_manifest or source_set")
    value: dict[str, object] = {
        "artifacts": artifacts,
        "claims": contract["claims"],
        "contract_schema": contract["schema"],
        "cross_bindings": contract["cross_bindings"],
        "decision": contract["decision"],
        "public_release_allowed": False,
        "receipt_id_scope": contract["stage_receipt_id_scope"],
        "release_authority": VERIFY.HOLD,
        "resolved_manifest": {
            "artifact_role": "resolved_manifest",
            "bytes": manifest_entry["bytes"],
            "sha256": manifest_entry["sha256"],
        },
        "schema": contract["stage_receipt_schema"],
        "source_bom": {
            "artifact_role": "source_bom",
            "bytes": bom_entry["bytes"],
            "receipt_id": source_bom.get("receipt_id"),
            "resolved_manifest_sha256": manifest_entry["sha256"],
            "schema": source_bom.get("schema"),
            "sha256": bom_entry["sha256"],
            "source_set_sha256": source_set.get("sha256"),
        },
    }
    value["receipt_id"] = "sha256:" + VERIFY.sha256(VERIFY.compact_json(value))
    return VERIFY.pretty_json(value)


def verifier_arguments(
    phase: str,
    contract_path: str,
    input_root: Path,
    output_root: Path,
    specs: Mapping[str, Mapping[str, object]],
    custody_input: Path | None = None,
    *,
    allow_userdebug_dogfood: bool = False,
) -> list[str]:
    arguments = [
        "--phase",
        phase,
        "--contract",
        contract_path,
        "--receipt",
        str(input_root / STAGE_RECEIPT),
        "--receipt-output",
        str(output_root / STAGE_RECEIPT),
        "--custody-output",
        str(output_root / "custody.v1.json"),
    ]
    if custody_input is not None:
        arguments += ["--custody-input", str(custody_input)]
    if allow_userdebug_dogfood:
        arguments.append("--allow-userdebug-dogfood")
    for role in VERIFY.EXPECTED_ROLES:
        spec = specs[role]
        if phase == "custody":
            source = input_root / spec["stage_path"]
        else:
            source = input_root / spec["output_filename"]
        arguments += ["--artifact-in", f"{role}={source}"]
        arguments += [
            "--artifact-out",
            f"{role}={output_root / spec['output_filename']}",
        ]
    return arguments


def ensure_target_absent(
    parent: VERIFY.RetainedDirectoryPath, name: str
) -> None:
    try:
        os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise VERIFY.StageError("receipt-stage output target already exists")


def validate_source_mode(item: VERIFY.RetainedInput, kind: object) -> None:
    actual = stat.S_IMODE(item.initial.st_mode)
    allowed = {0o555, 0o755} if kind == "elf" else {0o444, 0o644}
    if actual not in allowed:
        rendered = ", ".join(f"{mode:04o}" for mode in sorted(allowed))
        raise VERIFY.StageError(f"{item.label} source mode must be one of {rendered}")


def materialize(
    *,
    contract_path: str,
    base_manifest_path: str,
    stage_root: str,
    input_paths: Mapping[str, str],
    allow_userdebug_dogfood: bool = False,
) -> None:
    target = Path(stage_root)
    if target.parts[-2:] != ("trillionnium", "receipt-stage-v1"):
        raise VERIFY.StageError("output must end in trillionnium/receipt-stage-v1")
    output_parent = VERIFY.RetainedDirectoryPath.acquire(
        str(target.parent), "receipt-stage output parent"
    )
    retained: list[VERIFY.RetainedInput] = []
    errors: list[tuple[str, BaseException]] = []
    workspace: OwnedDirectory | None = None
    stage_container: OwnedDirectory | None = None
    custody_directory: OwnedDirectory | None = None
    publish_directory: OwnedDirectory | None = None
    tree: RetainedStageTree | None = None
    published_target = False
    target_cleaned = False
    try:
        ensure_target_absent(output_parent, target.name)
        contract_input = VERIFY.RetainedInput.acquire(
            contract_path,
            "receipt-stage contract",
        )
        retained.append(contract_input)
        contract = VERIFY.validate_contract(contract_input.data)
        specs = {spec["role"]: spec for spec in contract["role_specs"]}
        base_input = VERIFY.RetainedInput.acquire(
            base_manifest_path,
            "root-linux base manifest",
        )
        retained.append(base_input)
        base_manifest = VERIFY.parse_kv(
            base_input.data, "root-linux base manifest", require_sorted=False
        )

        physical: dict[str, VERIFY.RetainedInput] = {}
        entries: dict[str, dict[str, object]] = {}
        raw_by_role: dict[str, bytes] = {}
        for role in PHYSICAL_ROLES:
            item = VERIFY.RetainedInput.acquire(
                input_paths[role], f"physical stage input {role}"
            )
            retained.append(item)
            physical[role] = item
            validate_source_mode(item, specs[role]["kind"])
            raw_by_role[role] = item.data
            document_schema = None
            if role == "source_bom" and allow_userdebug_dogfood:
                source_document = VERIFY.parse_json(item.data, role)
                if (
                    source_document.get("schema")
                    != VERIFY.USERDEBUG_DOGFOOD_SOURCE_BOM_SCHEMA
                ):
                    raise VERIFY.StageError(
                        "dogfood receipt-stage input has the wrong source BOM schema"
                    )
                document_schema = VERIFY.USERDEBUG_DOGFOOD_SOURCE_BOM_SCHEMA
            entries[role] = role_entry(
                specs[role], item.data, document_schema=document_schema
            )

        documents: dict[str, Mapping[str, object]] = {}
        for role in (
            "fresh_base_receipt",
            "fresh_base_sbom",
            "source_bom",
            "common_artifact_set",
            "p01_final_artifact_set",
            "rootfs_contract",
            "rootfs_receipt",
        ):
            documents[role] = VERIFY.parse_json(raw_by_role[role], role)
        runtime, required_manifest = VERIFY.derive_runtime_bindings(
            documents, entries
        )
        runtime_raw = kv_bytes(runtime)
        raw_by_role["p01_runtime_config"] = runtime_raw
        entries["p01_runtime_config"] = role_entry(
            specs["p01_runtime_config"], runtime_raw
        )

        agent_raw = VERIFY.pretty_json(VERIFY.expected_agent_manifest(entries))
        raw_by_role["p01_agent_manifest"] = agent_raw
        entries["p01_agent_manifest"] = role_entry(
            specs["p01_agent_manifest"], agent_raw
        )

        manifest_raw = derive_root_manifest(
            base_manifest, contract, required_manifest, entries
        )
        raw_by_role["root_linux_manifest"] = manifest_raw
        entries["root_linux_manifest"] = role_entry(
            specs["root_linux_manifest"], manifest_raw
        )
        receipt_raw = stage_receipt_bytes(
            contract, entries, documents["source_bom"]
        )

        workspace_name = WORKSPACE_PREFIX + secrets.token_hex(16)
        workspace_path = os.path.join(str(target.parent), workspace_name)
        workspace = OwnedDirectory.create(
            output_parent,
            workspace_name,
            "receipt-stage materializer workspace",
            workspace_path,
            0o700,
        )
        stage_container_path = os.path.join(workspace_path, "trillionnium")
        stage_container = OwnedDirectory.create(
            workspace,
            "trillionnium",
            "candidate stage container",
            stage_container_path,
            0o755,
        )
        candidate_path = os.path.join(stage_container_path, "receipt-stage-v1")
        tree = RetainedStageTree.create(
            stage_container,
            "receipt-stage-v1",
            candidate_path,
            specs,
            raw_by_role,
            receipt_raw,
        )
        custody_path = os.path.join(workspace_path, "verifier-custody")
        custody_directory = OwnedDirectory.create(
            workspace,
            "verifier-custody",
            "custody verifier output directory",
            custody_path,
            0o700,
        )
        publish_path = os.path.join(workspace_path, "verifier-published")
        publish_directory = OwnedDirectory.create(
            workspace,
            "verifier-published",
            "publish verifier output directory",
            publish_path,
            0o700,
        )

        for item in retained:
            item.assert_stable()
        output_parent.assert_stable()
        workspace.assert_stable()
        tree.assert_stable()

        custody_args = verifier_arguments(
            "custody",
            contract_path,
            Path(candidate_path),
            Path(custody_path),
            specs,
            allow_userdebug_dogfood=allow_userdebug_dogfood,
        )
        VERIFY.run(custody_args)
        publish_args = verifier_arguments(
            "publish",
            contract_path,
            Path(custody_path),
            Path(publish_path),
            specs,
            Path(custody_path) / "custody.v1.json",
            allow_userdebug_dogfood=allow_userdebug_dogfood,
        )
        VERIFY.run(publish_args)
        validate_verifier_round_trip(
            custody_directory,
            publish_directory,
            specs,
            raw_by_role,
            receipt_raw,
        )

        for item in retained:
            item.assert_stable()
        output_parent.assert_stable()
        workspace.assert_stable()
        tree.assert_stable()
        ensure_target_absent(output_parent, target.name)
        rename_noreplace(
            stage_container.fd,
            tree.root.name,
            output_parent.fd,
            target.name,
        )
        tree.root.reanchor(output_parent, target.name, str(target))
        published_target = True
        os.fsync(stage_container.fd)
        os.fsync(output_parent.fd)
        # First target gate while all original source descriptors remain held.
        output_parent.assert_stable()
        tree.assert_stable()
    except BaseException as error:
        errors.append(("primary materialization/publication", error))

    # Original inputs remain held through publication.  Their complete final
    # byte/path gate and descriptor teardown precede the genuinely final
    # target-tree gate.
    for item in reversed(retained):
        try:
            item.assert_stable()
        except BaseException as error:
            errors.append((f"input final gate {item.label}", error))
        try:
            item.close()
        except BaseException as error:
            errors.append((f"input teardown {item.label}", error))
    retained.clear()

    if published_target and tree is not None:
        try:
            output_parent.assert_stable()
            tree.assert_stable()
        except BaseException as error:
            errors.append(("final target-tree gate", error))

    if errors and published_target and tree is not None:
        try:
            cleanup_owned_root(
                output_parent,
                target.name,
                tree.root.initial,
                "failed published receipt-stage target",
            )
            target_cleaned = True
        except BaseException as error:
            errors.append(("failure cleanup published target", error))

    # The workspace is never an output.  Remove only the exact inode created
    # through the retained output-parent descriptor; replacements are refused.
    if workspace is not None:
        try:
            cleanup_owned_root(
                output_parent,
                workspace.name,
                workspace.initial,
                "receipt-stage materializer workspace",
            )
        except BaseException as error:
            errors.append(("workspace cleanup", error))

    if errors and published_target and not target_cleaned and tree is not None:
        try:
            cleanup_owned_root(
                output_parent,
                target.name,
                tree.root.initial,
                "failed published receipt-stage target",
            )
            target_cleaned = True
        except BaseException as error:
            errors.append(("post-workspace failure cleanup published target", error))

    if tree is not None:
        errors.extend(tree.close_non_root())
    for label, directory in (
        ("publish verifier directory teardown", publish_directory),
        ("custody verifier directory teardown", custody_directory),
        ("candidate stage container teardown", stage_container),
    ):
        if directory is None:
            continue
        try:
            directory.close()
        except BaseException as error:
            errors.append((label, error))
    if workspace is not None:
        try:
            workspace.close()
        except BaseException as error:
            errors.append(("workspace descriptor teardown", error))

    # A teardown failure also converts an otherwise successful publication to
    # a clean failure while the target parent and target-root identity remain.
    if errors and published_target and not target_cleaned and tree is not None:
        try:
            cleanup_owned_root(
                output_parent,
                target.name,
                tree.root.initial,
                "failed published receipt-stage target",
            )
            target_cleaned = True
        except BaseException as error:
            errors.append(("post-teardown failure cleanup published target", error))

    if tree is not None:
        try:
            tree.root.close()
        except BaseException as error:
            errors.append(("target root descriptor teardown", error))
    if errors and published_target and not target_cleaned and tree is not None:
        try:
            cleanup_owned_root(
                output_parent,
                target.name,
                tree.root.initial,
                "failed published receipt-stage target",
            )
            target_cleaned = True
        except BaseException as error:
            errors.append(("post-root-teardown failure cleanup published target", error))
    try:
        output_parent.close()
    except BaseException as error:
        errors.append(("output parent teardown", error))

    raise_materialization_errors(errors)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--contract", required=True)
    value.add_argument("--base-root-linux-manifest", required=True)
    value.add_argument("--stage-root", required=True)
    value.add_argument("--input", action="append", default=[])
    value.add_argument(
        "--allow-userdebug-dogfood",
        action="store_true",
        help="accept the explicit non-authorizing userdebug dogfood source BOM",
    )
    return value


def run(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    contract_path = VERIFY.resolve_cli_path(args.contract, "contract")
    base_manifest_path = VERIFY.resolve_cli_path(
        args.base_root_linux_manifest, "base root-linux manifest"
    )
    stage_root = VERIFY.resolve_cli_path(args.stage_root, "stage root")
    input_paths = parse_inputs(args.input)
    materialize(
        contract_path=contract_path,
        base_manifest_path=base_manifest_path,
        stage_root=stage_root,
        input_paths=input_paths,
        allow_userdebug_dogfood=args.allow_userdebug_dogfood,
    )
    return 0


def main() -> int:
    try:
        return run()
    except (OSError, VERIFY.StageError, ValueError) as error:
        print(f"receipt-stage materialization denied: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
