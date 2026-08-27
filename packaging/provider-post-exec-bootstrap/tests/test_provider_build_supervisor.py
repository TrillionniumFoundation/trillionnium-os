from __future__ import annotations

import array
import importlib.util
import os
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

DIRECTORY = Path(__file__).resolve().parents[1]
MODULE_PATH = DIRECTORY / "build_provider_payload.py"
SUPERVISOR_SOURCE = DIRECTORY / "src/provider_build_supervisor.c"
INCLUDE = DIRECTORY / "include"
SPEC = importlib.util.spec_from_file_location(
    "provider_payload_builder_supervisor_tests",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class ProviderBuildSupervisorTest(unittest.TestCase):
    def test_cgroup_zero_residue_precedes_publication_and_closes_failures(
        self,
    ) -> None:
        source = SUPERVISOR_SOURCE.read_text(encoding="utf-8")
        program = source[source.index("int main(int argc, char **argv)") :]
        publication = program.index("rename_candidate(")
        retirement = program.index(
            "retire_empty_cgroup(cgroup_root_fd, cgroup_fd, cgroup_name)"
        )
        cleanup = program.index("cleanup:")
        self.assertLess(retirement, publication)
        self.assertGreater(cleanup, publication)
        self.assertIn(
            "kill_cgroup_and_wait_empty(cgroup_fd)",
            program[cleanup:],
        )
        self.assertNotIn(
            "(void)unlinkat(cgroup_root_fd, cgroup_name, AT_REMOVEDIR)",
            program[cleanup:],
        )

    def test_protocol_layout_matches_compiled_contract(self) -> None:
        self.assertEqual(
            struct.calcsize(builder.SUPERVISOR_HELLO_FORMAT),
            32,
        )
        self.assertEqual(
            struct.calcsize(builder.SUPERVISOR_INIT_FORMAT),
            64,
        )
        self.assertEqual(
            struct.calcsize(builder.SUPERVISOR_CID_REQUEST_FORMAT),
            112,
        )
        self.assertEqual(
            struct.calcsize(builder.SUPERVISOR_CID_RESPONSE_FORMAT),
            116,
        )
        self.assertEqual(
            struct.calcsize(builder.SUPERVISOR_READY_FORMAT),
            268,
        )

    def test_supervisor_provider_set_is_codex_singleton(self) -> None:
        source = SUPERVISOR_SOURCE.read_text(encoding="utf-8")
        self.assertEqual(builder.PROVIDERS, ("codex",))
        self.assertIn('strcmp(options->provider, "codex") != 0', source)
        self.assertNotIn('strcmp(options->provider, "retired_provider")', source)

    def test_retained_tombstone_fd_replaces_unreachable_path_lookup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-supervisor-tombstone."
        ) as temporary:
            tombstone = Path(temporary) / "cid"
            tombstone.mkdir(mode=0o700)
            tombstone.chmod(0o500)
            descriptor = os.open(
                tombstone,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            try:
                opened = os.fstat(descriptor)
                identity = (opened.st_dev, opened.st_ino)
                record = {
                    "state": "empty_cleanup_tombstone_retained",
                    "requested_path": "/root/unreachable/cid",
                    "expected_identity": {
                        "device": identity[0],
                        "inode": identity[1],
                    },
                    "observed_identity": {
                        "device": identity[0],
                        "inode": identity[1],
                    },
                    "mode": "0500",
                    "empty": True,
                    "same_uid_concurrent_child_name_replacement_proven": False,
                    "same_uid_concurrent_retained_stage_path_replacement_proven": (
                        False
                    ),
                }
                with builder._pinned_stage_records(
                    [record],
                    retained_descriptors={identity: descriptor},
                ):
                    self.assertEqual(
                        stat.S_IMODE(os.fstat(descriptor).st_mode),
                        0o500,
                    )
                wrong = dict(record)
                wrong["expected_identity"] = {
                    "device": identity[0],
                    "inode": identity[1] + 1,
                }
                wrong["observed_identity"] = dict(
                    wrong["expected_identity"]
                )
                with self.assertRaisesRegex(
                    builder.BuildError,
                    "retained stage FD identity drifted",
                ):
                    with builder._pinned_stage_records(
                        [wrong],
                        retained_descriptors={
                            (
                                identity[0],
                                identity[1] + 1,
                            ): descriptor
                        },
                    ):
                        pass
            finally:
                os.close(descriptor)

    def test_direct_failure_stage_reuses_canonical_receipt_and_verifier(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-supervisor-fixed-stage."
        ) as temporary:
            root = Path(temporary)
            output = root / "codex-amd64-cross"
            cache = root / "cache"
            candidate = root / ".failure-candidate"
            cache.mkdir()
            candidate.mkdir(mode=0o700)
            snapshots = builder._snapshot_build_context()
            recipe_sha256 = builder._sha256_bytes(
                snapshots["provider-payload-recipe-v1.json"]
            )
            builder_sha256 = builder._sha256_bytes(
                snapshots["build_provider_payload.py"]
            )
            containerfile_sha256 = builder._sha256_bytes(
                snapshots["Containerfile"]
            )
            input_identity = builder._container_input_identity(
                recipe_sha256,
                builder_sha256,
                containerfile_sha256,
            )
            build_context = builder._build_context_receipt(snapshots)
            projection = builder._new_container_projection(
                input_identity=input_identity,
                provider_name="codex",
                profile="amd64-cross",
                output=output,
                cache=cache,
                image_reference=None,
                build_context=build_context,
            )
            opened = candidate.stat()
            returned = builder._persist_build_failure(
                provider_name="codex",
                profile="amd64-cross",
                output=output,
                cache=cache,
                engine="docker",
                failed_phase="prefetch",
                completed_phases=[],
                recipe_sha256=recipe_sha256,
                builder_sha256=builder_sha256,
                containerfile_sha256=containerfile_sha256,
                input_snapshots=snapshots,
                expected_image_tag=builder._container_image_tag(
                    recipe_sha256,
                    builder_sha256,
                    containerfile_sha256,
                    "amd64-cross",
                ),
                image_id=None,
                container_command=None,
                success_output_published=False,
                success_output_parent_fsync_completed=False,
                publication_destination_installed=False,
                publication_destination_identity_preserved=False,
                error=builder.BuildError("fixed-stage negative fixture"),
                container_projection=projection,
                direct_stage=candidate,
                direct_stage_identity=(opened.st_dev, opened.st_ino),
            )
            self.assertEqual(returned, output.with_name(f"{output.name}.failure"))
            self.assertFalse(returned.exists())
            descriptor = os.open(
                candidate,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            try:
                receipt = builder._verify_failure_output_fd(
                    descriptor,
                    returned,
                )
            finally:
                os.close(descriptor)
            self.assertEqual(receipt["failed_phase"], "prefetch")
            self.assertFalse(receipt["success_output_published"])

    def test_python_receiver_rejects_wrong_frame_credentials_and_closes_fd(
        self,
    ) -> None:
        left, right = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_SEQPACKET,
        )
        left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        client = object.__new__(builder._SupervisedBuildClient)
        client.socket = left
        client.supervisor_pid = os.getpid() + 1
        with tempfile.TemporaryDirectory(
            prefix="provider-supervisor-rights."
        ) as temporary:
            descriptor = os.open(
                temporary,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            before = len(os.listdir("/proc/self/fd"))
            try:
                size = struct.calcsize(builder.SUPERVISOR_INIT_FORMAT)
                content = struct.pack(
                    builder.SUPERVISOR_INIT_FORMAT,
                    builder.SUPERVISOR_PROTOCOL_MAGIC,
                    builder.SUPERVISOR_PROTOCOL_VERSION,
                    builder.SUPERVISOR_KIND_INIT,
                    size,
                    0,
                    bytes(range(32)),
                    1,
                    os.getpid(),
                    os.getuid(),
                    os.getgid(),
                )
                rights = array.array("i", [descriptor])
                right.sendmsg(
                    [content],
                    [
                        (
                            socket.SOL_SOCKET,
                            socket.SCM_RIGHTS,
                            rights.tobytes(),
                        )
                    ],
                )
                with self.assertRaisesRegex(
                    builder.BuildError,
                    "credentials are not exact root",
                ):
                    client._receive(
                        expected_kind=builder.SUPERVISOR_KIND_INIT,
                        expected_size=size,
                        expected_descriptor_count=1,
                    )
                self.assertEqual(len(os.listdir("/proc/self/fd")), before)
            finally:
                os.close(descriptor)
                left.close()
                right.close()

    def test_container_absence_uses_complete_live_inventory(self) -> None:
        name = "trillionnium-provider-" + ("a" * 64)
        container_id = "b" * 64
        with mock.patch.object(
            builder,
            "_run",
            side_effect=[
                "27.5.1\n",
                f"{container_id}\t{name}\n",
            ],
        ) as run:
            with self.assertRaisesRegex(
                builder.BuildError,
                "container remains present",
            ):
                builder._verify_container_absent(
                    "docker",
                    name,
                    container_id,
                )
            self.assertEqual(run.call_count, 2)
        with mock.patch.object(
            builder,
            "_run",
            side_effect=["27.5.1\n", ""],
        ):
            builder._verify_container_absent(
                "docker",
                name,
                container_id,
            )

    def test_c_protocol_rejects_extra_rights_and_unknown_header_flags(
        self,
    ) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("host C compiler is unavailable")
        harness = textwrap.dedent(
            r"""
            #define main provider_supervisor_program_main
            #include "provider_build_supervisor.c"
            #undef main

            int main(void) {
                int pair[2] = {-1, -1};
                int passcred = 1;
                struct tpbs_hello hello = {
                    .header = {
                        .magic = TPBS_MAGIC,
                        .version = TPBS_VERSION,
                        .kind = TPBS_HELLO,
                        .size = sizeof(struct tpbs_hello),
                        .flags = 0,
                    },
                };
                struct frame frame;
                if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                               pair) != 0 ||
                    setsockopt(pair[0], SOL_SOCKET, SO_PASSCRED, &passcred,
                               sizeof(passcred)) != 0 ||
                    send_frame(pair[1], &hello, sizeof(hello), NULL, 0) != 0 ||
                    receive_frame(pair[0], getpid(), getuid(), getgid(),
                                  &frame) != 0 ||
                    validate_hello(&frame) != 0) {
                    return 10;
                }
                close_frame(&frame);
                if (send_frame(pair[1], &hello, sizeof(hello), &pair[1], 1)
                        != 0 ||
                    receive_frame(pair[0], getpid(), getuid(), getgid(),
                                  &frame) != 0 ||
                    validate_hello(&frame) == 0) {
                    return 11;
                }
                close_frame(&frame);
                hello.header.flags = 1;
                if (send_frame(pair[1], &hello, sizeof(hello), NULL, 0) != 0 ||
                    receive_frame(pair[0], getpid(), getuid(), getgid(),
                                  &frame) == 0) {
                    return 12;
                }
                close(pair[0]);
                close(pair[1]);
                return 0;
            }
            """
        )
        with tempfile.TemporaryDirectory(
            prefix="provider-supervisor-c-test."
        ) as temporary:
            root = Path(temporary)
            source = root / "harness.c"
            binary = root / "harness"
            source.write_text(harness, encoding="utf-8")
            subprocess.run(
                [
                    compiler,
                    "-std=c17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-Wconversion",
                    "-Wshadow",
                    f"-I{INCLUDE}",
                    f"-I{DIRECTORY / 'src'}",
                    str(source),
                    "-o",
                    str(binary),
                ],
                check=True,
            )
            completed = subprocess.run(
                [str(binary)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
