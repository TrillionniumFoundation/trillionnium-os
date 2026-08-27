from __future__ import annotations

import ast
import difflib
import errno
import hashlib
import importlib.util
import inspect
import io
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import time
import unittest
from contextlib import contextmanager, nullcontext, redirect_stderr
from pathlib import Path
from unittest import mock

DIRECTORY = Path(__file__).resolve().parents[1]
MODULE_PATH = DIRECTORY / "build_provider_payload.py"
SPEC = importlib.util.spec_from_file_location("provider_payload_builder", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def reconcile_preflight_receipt(provider_name: str) -> dict[str, object]:
    recipe = builder.load_recipe()
    return {
        "schema": builder.BUILDER_RECEIPT_SCHEMA,
        "provider": provider_name,
        "source_checkpoint": builder._source_checkpoint_projection(
            provider_name, recipe["providers"][provider_name]
        ),
    }


def synthetic_lld_map_row(kind: str, value: str, ordinal: int) -> str:
    address = 0x1000000 + ordinal * 16
    prefix = (
        f"{address:>16x} {address:>16x} {1:>8x} {1:>5d} "
    )
    assert len(prefix) == 49
    if kind == "out":
        return prefix + value
    if kind == "in":
        return prefix + " " * 8 + value + ":(.text)"
    if kind == "symbol":
        return prefix + " " * 16 + value
    raise AssertionError(f"unknown synthetic lld row kind: {kind}")


def synthetic_codex_lock_fixture(
) -> tuple[bytes, bytes, bytes, list[str], dict[str, object]]:
    names = [f"trillionnium-workspace-fixture-{index:03d}" for index in range(132)]
    blocks = [
        (
            "[[package]]\n"
            f'name = "{name}"\n'
            'version = "0.0.0"\n'
            "dependencies = [\n"
            ' \"registry-fixture\",\n'
            "]\n"
        )
        for name in names
    ]
    blocks.extend(
        [
            (
                "[[package]]\n"
                'name = "registry-fixture"\n'
                'version = "1.2.3"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                f'checksum = "{"a" * 64}"\n'
                "dependencies = [\n"
                ' "git-fixture",\n'
                "]\n"
            ),
            (
                "[[package]]\n"
                'name = "git-fixture"\n'
                'version = "0.1.0"\n'
                'source = "git+https://example.invalid/frozen?rev='
                f'{"b" * 40}#{"c" * 40}"\n'
            ),
        ]
    )
    upstream = ("version = 4\n\n" + "\n".join(blocks)).encode("utf-8")
    derived = upstream.replace(
        b'version = "0.0.0"\n',
        b'version = "0.144.1"\n',
    )
    patch = "".join(
        difflib.unified_diff(
            upstream.decode("utf-8").splitlines(keepends=True),
            derived.decode("utf-8").splitlines(keepends=True),
            fromfile="codex-rs/Cargo.lock.upstream",
            tofile="codex-rs/Cargo.lock.derived",
        )
    ).encode("utf-8")
    rule: dict[str, object] = {
        "upstream_relative_path": "codex-rs/Cargo.lock",
        "workspace_version": "0.144.1",
        "workspace_package_count": 132,
        "workspace_package_names_sha256": hashlib.sha256(
            (
                json.dumps(
                    names,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
                + "\n"
            ).encode("ascii")
        ).hexdigest(),
        "transformation": (
            "source_less_workspace_package_version_0.0.0_to_0.144.1_only"
        ),
        "derived_sha256": hashlib.sha256(derived).hexdigest(),
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
    }
    return upstream, derived, patch, names, rule


def codex_metadata_fixture(
    resolved_features: dict[str, list[str]],
) -> str:
    packages = [
        {
            "id": f"path+file:///fixture/{name}#0.144.1",
            "name": name,
        }
        for name in resolved_features
    ]
    return json.dumps(
        {
            "packages": packages,
            "resolve": {
                "nodes": [
                    {
                        "id": package["id"],
                        "features": resolved_features[package["name"]],
                    }
                    for package in packages
                ]
            },
        },
        sort_keys=True,
    )


def container_lifecycle_fixture(
    root: Path,
    *,
    provider_name: str = "codex",
    profile: str = "amd64-cross",
) -> tuple[
    dict[str, object],
    object,
    list[str],
    str,
]:
    snapshots = builder._snapshot_build_context()
    recipe_sha256 = hashlib.sha256(
        snapshots["provider-payload-recipe-v1.json"]
    ).hexdigest()
    builder_sha256 = hashlib.sha256(
        snapshots["build_provider_payload.py"]
    ).hexdigest()
    containerfile_sha256 = hashlib.sha256(
        snapshots["Containerfile"]
    ).hexdigest()
    input_identity = builder._container_input_identity(
        recipe_sha256,
        builder_sha256,
        containerfile_sha256,
    )
    output = root / "output"
    cache = root / "cache"
    stage = root / f".{output.name}.abcdefgh"
    image_id = f"sha256:{'1' * 64}"
    build_context = builder._build_context_receipt(snapshots)
    projection = builder._new_container_projection(
        input_identity=input_identity,
        provider_name=provider_name,
        profile=profile,
        output=output,
        cache=cache,
        image_reference=image_id,
        build_context=build_context,
    )
    custody = builder._prepare_container_cidfile_custody(
        output,
        projection["attempt_id_sha256"],
    )
    inner = builder._provider_container_inner_arguments(
        provider_name=provider_name,
        profile=profile,
        image_id=image_id,
        recipe_sha256=recipe_sha256,
        builder_sha256=builder_sha256,
        containerfile_sha256=containerfile_sha256,
        attempt_id=projection["attempt_id_sha256"],
        output=output,
        cache=cache,
        container_name=projection["name"],
        cidfile_host_path=custody.cidfile_path,
        build_context_tar_sha256=build_context["tar_sha256"],
        build_context_tar_byte_length=build_context["tar_byte_length"],
        build_context_member_manifest_sha256=build_context[
            "member_manifest_sha256"
        ],
    )
    command = builder._provider_container_command(
        engine="docker",
        provider_name=provider_name,
        profile=profile,
        image_id=image_id,
        recipe_sha256=recipe_sha256,
        builder_sha256=builder_sha256,
        containerfile_sha256=containerfile_sha256,
        attempt_id=projection["attempt_id_sha256"],
        output=output,
        cache=cache,
        stage=stage,
        container_name=projection["name"],
        cidfile_host_path=custody.cidfile_path,
        run_user=f"{os.getuid()}:{os.getgid()}",
        build_context_tar_sha256=build_context["tar_sha256"],
        build_context_tar_byte_length=build_context["tar_byte_length"],
        build_context_member_manifest_sha256=build_context[
            "member_manifest_sha256"
        ],
    )
    builder._validate_provider_container_command(
        command,
        "test lifecycle fixture",
    )
    return projection, custody, command, "2" * 64


class FrozenRecipeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._publication_custody_temp = tempfile.TemporaryDirectory(
            prefix="provider-publication-test-custody."
        )
        self.addCleanup(self._publication_custody_temp.cleanup)
        custody = Path(self._publication_custody_temp.name)
        custody.chmod(0o700)
        patcher = mock.patch.object(
            builder,
            "PUBLICATION_TEST_ONLY_CUSTODY_DIRECTORY",
            custody,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_exact_upstream_pins_and_all_authority_flags_remain_closed(self) -> None:
        recipe = builder.load_recipe()
        self.assertEqual(builder.PROVIDERS, ("codex",))
        self.assertEqual(set(recipe["providers"]), {"codex"})
        codex = recipe["providers"]["codex"]
        self.assertEqual(
            codex["dereferenced_commit_sha1"],
            "44918ea10c0f99151c6710411b4322c2f5c96bea",
        )
        self.assertEqual(codex["expected_uid"], 5901)
        self.assertEqual(codex["expected_gid"], 5901)
        self.assertTrue(codex["required_symbol_table"])
        self.assertFalse(codex["required_dynamic_segment"])
        self.assertEqual(
            builder._provider_resource_contract("codex", codex),
            {
                "build_jobs": 2,
                "cargo_profile": {
                    "name": "release",
                    "debug": "none",
                    "incremental": False,
                    "lto": False,
                    "codegen_units": 4,
                    "strip": False,
                },
                "linker_threads": 1,
            },
        )
        self.assertEqual(
            set(recipe["builder"]["profiles"]),
            {"amd64-cross", "arm64-native"},
        )
        self.assertEqual(recipe["builder"]["image_build_network"], "default")
        for field in builder.FALSE_AUTHORITY_FIELDS:
            self.assertIs(recipe[field], False)
        plan = builder._plan("codex", "amd64-cross")
        self.assertEqual(
            plan["resource_contract"],
            builder._provider_resource_contract("codex", codex),
        )
        self.assertEqual(plan["container_network"], "none")
        self.assertEqual(
            plan["container_proxy_environment"],
            builder._container_proxy_environment(),
        )
        self.assertIsNone(plan["source_checkpoint"])
        self.assertIs(plan["accepts_external_binary"], False)
        self.assertIs(plan["accepts_external_source_tree"], False)
        self.assertIs(plan["accepts_flag_or_environment_override"], False)
        self.assertIs(plan["requires_unstripped_final_elf"], True)
        for field in builder.FALSE_AUTHORITY_FIELDS:
            self.assertIs(plan[field], False)
        with self.assertRaisesRegex(builder.BuildError, "outside the Codex singleton"):
            builder._plan("retired_provider", "amd64-cross")
        with self.assertRaisesRegex(builder.BuildError, "no frozen resource contract"):
            builder._provider_resource_contract("retired_provider", codex)

    def test_recipe_rejects_unknown_fields_and_pin_drift(self) -> None:
        original_path = builder.RECIPE_PATH
        with tempfile.TemporaryDirectory(prefix="provider-recipe-test.") as temporary:
            temporary_path = Path(temporary) / "recipe.json"
            recipe = json.loads(original_path.read_text(encoding="utf-8"))
            recipe["unexpected"] = True
            temporary_path.write_text(json.dumps(recipe), encoding="utf-8")
            builder.RECIPE_PATH = temporary_path
            try:
                with self.assertRaisesRegex(builder.BuildError, "field set drifted"):
                    builder.load_recipe()
            finally:
                builder.RECIPE_PATH = original_path

            recipe = json.loads(original_path.read_text(encoding="utf-8"))
            for provider_name, path, drift in (
                ("codex", ("build_jobs",), 3),
                ("codex", ("linker_threads",), 2),
                ("codex", ("cargo_profile", "lto"), True),
                ("codex", ("cargo_profile", "codegen_units"), 8),
            ):
                with self.subTest(provider=provider_name, path=path):
                    mutated = json.loads(json.dumps(recipe))
                    value = mutated["providers"][provider_name]
                    for key in path[:-1]:
                        value = value[key]
                    value[path[-1]] = drift
                    temporary_path.write_text(
                        json.dumps(mutated), encoding="utf-8"
                    )
                    builder.RECIPE_PATH = temporary_path
                    try:
                        with self.assertRaisesRegex(
                            builder.BuildError,
                            "low-resource build contract drifted",
                        ):
                            builder.load_recipe()
                    finally:
                        builder.RECIPE_PATH = original_path

            mutated = json.loads(json.dumps(recipe))
            mutated["builder"]["image_build_network"] = "host"
            temporary_path.write_text(
                json.dumps(mutated), encoding="utf-8"
            )
            builder.RECIPE_PATH = temporary_path
            try:
                with self.assertRaisesRegex(
                    builder.BuildError,
                    "frozen builder base, network",
                ):
                    builder.load_recipe()
            finally:
                builder.RECIPE_PATH = original_path

            mutated = json.loads(json.dumps(recipe))
            mutated["providers"]["retired_provider"] = {}
            temporary_path.write_text(json.dumps(mutated), encoding="utf-8")
            builder.RECIPE_PATH = temporary_path
            try:
                with self.assertRaisesRegex(
                    builder.BuildError, "closed provider/profile set drifted"
                ):
                    builder.load_recipe()
            finally:
                builder.RECIPE_PATH = original_path

            recipe["providers"]["codex"]["dereferenced_commit_sha1"] = "1" * 40
            temporary_path.write_text(json.dumps(recipe), encoding="utf-8")
            builder.RECIPE_PATH = temporary_path
            try:
                with self.assertRaisesRegex(builder.BuildError, "source pins drifted"):
                    builder.load_recipe()
            finally:
                builder.RECIPE_PATH = original_path

    def test_reproducibility_build_recipe_rejects_reverse_tampering(self) -> None:
        recipe = builder.load_recipe()
        for provider_name in builder.PROVIDERS:
            with self.subTest(provider=provider_name):
                provider = recipe["providers"][provider_name]
                profile = "amd64-cross"
                resource_contract = builder._provider_resource_contract(
                    provider_name, provider
                )
                command = builder._expected_provider_build_command(
                    recipe, provider_name, profile
                )
                compiler_arguments = builder._bootstrap_compile_arguments(
                    recipe, provider
                )
                receipt = {
                    "provider": provider_name,
                    "builders": [
                        {"profile": profile},
                        {"profile": "arm64-native"},
                    ],
                    "build_recipe": {
                        "command": command,
                        "compiler_arguments": compiler_arguments,
                        "externally_supplied_definitions": recipe["bootstrap"][
                            "externally_supplied_definitions"
                        ],
                        "resource_contract": resource_contract,
                        "container_network": "none",
                        "container_proxy_environment": (
                            builder._container_proxy_environment()
                        ),
                    },
                }
                equal_outputs = {
                    "resource_contract": resource_contract,
                }
                builder._verify_reproducibility_build_recipe(
                    receipt,
                    equal_outputs,
                    recipe,
                )

                for mutation in (
                    "equal_outputs_resource_contract",
                    "build_recipe_resource_contract",
                    "build_recipe_command",
                    "build_recipe_container_network",
                    "build_recipe_proxy_environment",
                ):
                    with self.subTest(provider=provider_name, mutation=mutation):
                        mutated_receipt = json.loads(json.dumps(receipt))
                        mutated_equal_outputs = json.loads(
                            json.dumps(equal_outputs)
                        )
                        if mutation == "equal_outputs_resource_contract":
                            mutated_equal_outputs["resource_contract"][
                                "build_jobs"
                            ] = 3
                        elif mutation == "build_recipe_resource_contract":
                            mutated_receipt["build_recipe"][
                                "resource_contract"
                            ]["build_jobs"] = 3
                        elif mutation == "build_recipe_command":
                            mutated_receipt["build_recipe"]["command"] = [
                                "true"
                            ]
                        elif mutation == "build_recipe_container_network":
                            mutated_receipt["build_recipe"][
                                "container_network"
                            ] = "host"
                        else:
                            mutated_receipt["build_recipe"][
                                "container_proxy_environment"
                            ][0]["value"] = "http://untrusted.invalid"
                        with self.assertRaisesRegex(
                            builder.BuildError,
                            "low-resource build recipe drifted",
                        ):
                            builder._verify_reproducibility_build_recipe(
                                mutated_receipt,
                                mutated_equal_outputs,
                                recipe,
                            )

    def test_reproducibility_builder_resolvers_are_bound_but_not_equalized(
        self,
    ) -> None:
        recipe = builder.load_recipe()
        build_context = builder._build_context_receipt(
            builder._snapshot_build_context()
        )
        builders = []
        for index, profile in enumerate(builder.BUILDER_PROFILES, start=1):
            profile_recipe = recipe["builder"]["profiles"][profile]
            builders.append(
                {
                    "profile": profile,
                    "platform": profile_recipe["platform"],
                    "base_platform_manifest_sha256": profile_recipe[
                        "manifest_sha256"
                    ],
                    "built_image_id": f"sha256:{index:064x}",
                    "build_context": build_context,
                    "builder_receipt_sha256": f"{index + 2:064x}",
                    "image_build_network": "default",
                    "retained_artifact_resolver": (
                        builder.RETAINED_ARTIFACT_RESOLVER_OPENAT2
                        if profile == "amd64-cross"
                        else builder.RETAINED_ARTIFACT_RESOLVER_COMPONENT_WALK
                    ),
                    "container": {
                        "command": [
                            "docker",
                            "run",
                            "--provider",
                            "codex",
                            "--recipe-sha256",
                            "a" * 64,
                            "--builder-sha256",
                            "b" * 64,
                            "--containerfile-sha256",
                            "c" * 64,
                        ],
                    },
                }
            )
        with mock.patch.object(builder, "_verify_container_projection"):
            builder._verify_reproducibility_builders(builders, recipe)

            tampered = json.loads(json.dumps(builders))
            tampered[1]["retained_artifact_resolver"] = "unsafe-path-walk"
            with self.assertRaisesRegex(
                builder.BuildError, "resolver is not allowed"
            ):
                builder._verify_reproducibility_builders(tampered, recipe)

            network_tampered = json.loads(json.dumps(builders))
            network_tampered[1]["image_build_network"] = "host"
            with self.assertRaisesRegex(
                builder.BuildError, "builder identity drifted"
            ):
                builder._verify_reproducibility_builders(
                    network_tampered, recipe
                )

            extra_field = json.loads(json.dumps(builders))
            extra_field[0]["resolver_claim_unbound"] = True
            with self.assertRaisesRegex(builder.BuildError, "field set drifted"):
                builder._verify_reproducibility_builders(extra_field, recipe)

    def test_runtime_candidate_profiles_cross_bind_and_select_native(self) -> None:
        abi_digest = "c" * 64
        builders = [
            {
                "profile": profile,
                "platform": platform,
                "base_platform_manifest_sha256": digest,
            }
            for profile, platform, digest in (
                ("amd64-cross", "linux/amd64", "a" * 64),
                ("arm64-native", "linux/arm64", "b" * 64),
            )
        ]
        candidates = [
            {
                "profile": value["profile"],
                "platform": value["platform"],
                "base_platform_manifest_sha256": value[
                    "base_platform_manifest_sha256"
                ],
                "runtime_closure_manifest": {
                    "logical_path": (
                        f"runtime-candidates/{value['profile']}/"
                        "runtime-closure.json"
                    ),
                    "byte_length": 1,
                    "sha256": ("d" if index == 0 else "e") * 64,
                },
                "bundle_inventory_sha256": (
                    "f" if index == 0 else "1"
                )
                * 64,
                "abi_contract_sha256": abi_digest,
            }
            for index, value in enumerate(builders)
        ]
        equal_outputs = {"runtime_abi_contract_sha256": abi_digest}
        builder._verify_runtime_candidate_headers(
            candidates, "arm64-native", builders, equal_outputs
        )

        mutations = {}
        reversed_candidates = json.loads(json.dumps(candidates))
        reversed_candidates.reverse()
        mutations["profile order"] = (reversed_candidates, "arm64-native")
        platform_drift = json.loads(json.dumps(candidates))
        platform_drift[1]["platform"] = "linux/amd64"
        mutations["builder cross-binding"] = (
            platform_drift,
            "arm64-native",
        )
        manifest_drift = json.loads(json.dumps(candidates))
        manifest_drift[1]["runtime_closure_manifest"]["logical_path"] = (
            "runtime-candidates/amd64-cross/runtime-closure.json"
        )
        mutations["manifest profile binding"] = (
            manifest_drift,
            "arm64-native",
        )
        abi_drift = json.loads(json.dumps(candidates))
        abi_drift[0]["abi_contract_sha256"] = "2" * 64
        mutations["ABI cross-binding"] = (abi_drift, "arm64-native")
        mutations["selected cross profile"] = (candidates, "amd64-cross")
        for name, (values, selected) in mutations.items():
            with self.subTest(mutation=name), self.assertRaises(
                builder.BuildError
            ):
                builder._verify_runtime_candidate_headers(
                    values, selected, builders, equal_outputs
                )

    def test_runtime_candidates_stage_only_static_empty_manifests(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-runtime-candidate-stage-test."
        ) as temporary:
            stage = Path(temporary)
            candidates = []
            receipts = []
            for index, (profile, platform) in enumerate(
                (
                    ("amd64-cross", "linux/amd64"),
                    ("arm64-native", "linux/arm64"),
                ),
                start=1,
            ):
                receipt = {
                    "provider": "codex",
                    "builder": {
                        "profile": profile,
                        "platform": platform,
                        "base_platform_manifest_sha256": f"{index + 10:064x}",
                    },
                    "build": {"runtime_closure": []},
                    "elf_contract": {
                        "has_dynamic_segment": False,
                        "interpreter": None,
                        "needed_order": [],
                    },
                }
                receipts.append(receipt)
                candidates.append(
                    builder._stage_runtime_candidate(stage, receipt)
                )

            self.assertEqual(
                [candidate["profile"] for candidate in candidates],
                list(builder.BUILDER_PROFILES),
            )
            self.assertEqual(
                candidates[0]["abi_contract_sha256"],
                candidates[1]["abi_contract_sha256"],
            )
            self.assertEqual(
                candidates[0]["bundle_inventory_sha256"],
                candidates[1]["bundle_inventory_sha256"],
            )
            for candidate in candidates:
                profile = candidate["profile"]
                manifest = candidate["runtime_closure_manifest"]
                self.assertEqual(
                    manifest["logical_path"],
                    f"runtime-candidates/{profile}/runtime-closure.json",
                )
                value = json.loads(
                    (stage / manifest["logical_path"]).read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(
                    value,
                    builder._runtime_closure_manifest_value("codex", []),
                )

            dso_receipt = json.loads(json.dumps(receipts[0]))
            dso_receipt["build"]["runtime_closure"] = [{}]
            with self.assertRaisesRegex(builder.BuildError, "cannot contain DSOs"):
                builder._stage_runtime_candidate(stage, dso_receipt)
            dynamic_contract = json.loads(json.dumps(receipts[0]["elf_contract"]))
            dynamic_contract["has_dynamic_segment"] = True
            with self.assertRaisesRegex(builder.BuildError, "fully static"):
                builder._runtime_abi_contract(
                    "codex", dynamic_contract, []
                )

    def test_public_cli_has_no_binary_source_toolchain_or_flag_override(self) -> None:
        forbidden = (
            "--binary",
            "--source-tree",
            "--compiler",
            "--linker",
            "--sysroot",
            "--cflags",
            "--ldflags",
            "--environment",
        )
        for argument in forbidden:
            with (
                self.subTest(argument=argument),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                builder.parse_args(
                    [
                        "build",
                        "--provider",
                        "codex",
                        "--builder-profile",
                        "amd64-cross",
                        "--output-dir",
                        "/tmp/out",
                        "--cache-dir",
                        "/tmp/cache",
                        argument,
                        "attacker-controlled",
                    ]
                )

    def test_source_hold_gate_does_not_intercept_codex(self) -> None:
        class CodexReachedNextPhase(RuntimeError):
            pass

        with tempfile.TemporaryDirectory(
            prefix="provider-codex-gate-scope-test."
        ) as temporary:
            root = Path(temporary)
            with (
                mock.patch.object(
                    builder,
                    "_snapshot_build_context",
                    side_effect=CodexReachedNextPhase,
                ),
                self.assertRaises(CodexReachedNextPhase),
            ):
                builder._public_build(
                    "codex",
                    "amd64-cross",
                    root / "output",
                    root / "cache",
                    "docker",
                )

            recipe = builder.load_recipe()
            with (
                mock.patch.object(builder, "load_recipe", return_value=recipe),
                mock.patch.object(
                    builder,
                    "_sha256_file",
                    side_effect=CodexReachedNextPhase,
                ),
                self.assertRaises(CodexReachedNextPhase),
            ):
                builder._container_build(
                    provider_name="codex",
                    profile="amd64-cross",
                    builder_image_id=f"sha256:{'1' * 64}",
                    expected_recipe_sha256="2" * 64,
                    expected_builder_sha256="3" * 64,
                    expected_containerfile_sha256="4" * 64,
                    expected_build_context_tar_sha256="5" * 64,
                    expected_build_context_tar_byte_length=1,
                    expected_build_context_member_manifest_sha256="6" * 64,
                    expected_attempt_id="7" * 64,
                    requested_output="/output",
                    cache_root="/cache",
                    expected_container_name="held",
                    expected_cidfile_host_path="/held/cid",
                    container_cidfile_path="/run/held/cid",
                )

            codex_receipts = [
                {
                    "schema": builder.BUILDER_RECEIPT_SCHEMA,
                    "provider": "codex",
                    "target_architecture": builder.TARGET_ARCHITECTURE,
                    "source_date_epoch": 1_783_900_800,
                    "recipe": {},
                    "bootstrap": {},
                    "retained_fd_contract": {},
                    "source_checkpoint": None,
                    "builder": {
                        "profile": profile,
                        "built_image_id": f"sha256:{identity * 64}",
                        "base_platform_manifest_sha256": identity * 64,
                    },
                }
                for profile, identity in (
                    ("amd64-cross", "a"),
                    ("arm64-native", "b"),
                )
            ]
            codex_roots = [root / "codex-a", root / "codex-b"]
            for codex_root, receipt in zip(
                codex_roots, codex_receipts, strict=True
            ):
                codex_root.mkdir()
                (
                    codex_root / "provider-builder-receipt.json"
                ).write_bytes(builder._json_bytes(receipt))
            descriptors = [
                os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                for path in codex_roots
            ]
            verified_preloaded: list[dict[str, object]] = []

            def verify_preloaded(
                _descriptor: int,
                *,
                preloaded_receipt: dict[str, object] | None = None,
                **_kwargs: object,
            ) -> dict[str, object]:
                self.assertIsNotNone(preloaded_receipt)
                verified_preloaded.append(preloaded_receipt)
                return preloaded_receipt

            try:
                with (
                    mock.patch.object(
                        builder,
                        "_verify_builder_output_fd",
                        side_effect=verify_preloaded,
                    ),
                    mock.patch.object(
                        builder,
                        "_equal_output_projection",
                        side_effect=CodexReachedNextPhase,
                    ),
                    self.assertRaises(CodexReachedNextPhase),
                ):
                    builder._reconcile_from_fds(
                        descriptors, root / "codex-reconciled"
                    )
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)
            self.assertEqual(len(verified_preloaded), 2)

    def test_retained_fd_verifier_cli_consumes_the_inherited_directory(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-retained-fd-cli."
        ) as temporary:
            root = Path(temporary)
            inherited = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, inherited)
            builder_fd = os.open(MODULE_PATH, os.O_RDONLY)
            recipe_fd = os.open(builder.RECIPE_PATH, os.O_RDONLY)
            containerfile_fd = os.open(builder.CONTAINERFILE_PATH, os.O_RDONLY)
            for descriptor in (builder_fd, recipe_fd, containerfile_fd):
                self.addCleanup(os.close, descriptor)
            expected = os.fstat(inherited)

            def verify_retained(
                descriptor: int,
                *,
                verification_sources: dict[str, object],
            ) -> str:
                observed = os.fstat(descriptor)
                self.assertEqual(
                    (observed.st_dev, observed.st_ino),
                    (expected.st_dev, expected.st_ino),
                )
                self.assertNotEqual(descriptor, inherited)
                self.assertEqual(
                    verification_sources["builder_sha256"],
                    builder._sha256_file(MODULE_PATH),
                )
                self.assertEqual(
                    verification_sources["recipe_sha256"],
                    builder._sha256_file(builder.RECIPE_PATH),
                )
                self.assertEqual(
                    verification_sources["containerfile_sha256"],
                    builder._sha256_file(builder.CONTAINERFILE_PATH),
                )
                return builder.REPRODUCIBILITY_RECEIPT_SCHEMA

            stdout = io.StringIO()
            with (
                mock.patch.object(
                    builder,
                    "_verify_any_output_fd",
                    side_effect=verify_retained,
                ) as verifier,
                mock.patch.object(builder.sys, "stdout", stdout),
            ):
                result = builder.main(
                    [
                        "_verify-retained-fd",
                        "--output-fd",
                        str(inherited),
                        "--builder-fd",
                        str(builder_fd),
                        "--recipe-fd",
                        str(recipe_fd),
                        "--containerfile-fd",
                        str(containerfile_fd),
                    ]
                )
            self.assertEqual(result, 0)
            verifier.assert_called_once()
            self.assertEqual(
                json.loads(stdout.getvalue()),
                {
                    "decision": (
                        "PASS_RETAINED_FD_STRUCTURAL_RECEIPT_ONLY_"
                        "NOT_PRODUCT_ACTIVE"
                    ),
                    "schema": builder.REPRODUCIBILITY_RECEIPT_SCHEMA,
                },
            )
            self.assertEqual(
                (os.fstat(inherited).st_dev, os.fstat(inherited).st_ino),
                (expected.st_dev, expected.st_ino),
            )

        stderr = io.StringIO()
        with tempfile.TemporaryDirectory(
            prefix="provider-retained-fd-invalid."
        ) as temporary:
            output_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            builder_fd = os.open(MODULE_PATH, os.O_RDONLY)
            recipe_fd = os.open(builder.RECIPE_PATH, os.O_RDONLY)
            try:
                with mock.patch.object(builder.sys, "stderr", stderr):
                    self.assertEqual(
                        builder.main(
                            [
                                "_verify-retained-fd",
                                "--output-fd",
                                str(output_fd),
                                "--builder-fd",
                                str(builder_fd),
                                "--recipe-fd",
                                str(recipe_fd),
                                "--containerfile-fd",
                                str(recipe_fd),
                            ]
                        ),
                        1,
                    )
            finally:
                os.close(recipe_fd)
                os.close(builder_fd)
                os.close(output_fd)
        self.assertIn("four distinct inherited data FDs", stderr.getvalue())

    def test_retained_verifier_sources_ignore_post_open_name_rebind(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-retained-source-rebind."
        ) as temporary:
            root = Path(temporary)
            paths = {
                "builder": root / "builder.py",
                "recipe": root / "recipe.json",
                "containerfile": root / "Containerfile",
            }
            originals = {
                "builder": MODULE_PATH.read_bytes(),
                "recipe": builder.RECIPE_PATH.read_bytes(),
                "containerfile": builder.CONTAINERFILE_PATH.read_bytes(),
            }
            for role, path in paths.items():
                path.write_bytes(originals[role])
            descriptors = {
                role: os.open(path, os.O_RDONLY | os.O_CLOEXEC)
                for role, path in paths.items()
            }
            try:
                for ordinal, path in enumerate(paths.values()):
                    replacement = root / f"replacement-{ordinal}"
                    replacement.write_bytes(b"divergent-name-bytes")
                    os.replace(replacement, path)
                sources = builder._retained_verification_sources(
                    descriptors["builder"],
                    descriptors["recipe"],
                    descriptors["containerfile"],
                )
            finally:
                for descriptor in descriptors.values():
                    os.close(descriptor)
            self.assertEqual(
                sources["builder_sha256"],
                hashlib.sha256(originals["builder"]).hexdigest(),
            )
            self.assertEqual(
                sources["recipe_sha256"],
                hashlib.sha256(originals["recipe"]).hexdigest(),
            )
            self.assertEqual(
                sources["containerfile_sha256"],
                hashlib.sha256(originals["containerfile"]).hexdigest(),
            )
            self.assertEqual(
                sources["recipe"]["schema"], builder.RECIPE_SCHEMA
            )

    def test_fixture_and_response_file_override_tokens_fail_closed(self) -> None:
        for argument in (
            "-include",
            "-imacros=evil.h",
            "-fplugin=/tmp/evil.so",
            "--specs=/tmp/evil.specs",
            "provider_post_exec_bootstrap_fixture.c",
            "-DTRILLIONNIUM_BOOTSTRAP_STOP=return",
            "FAULT_SKIP_FILTER",
        ):
            with self.subTest(argument=argument), self.assertRaises(builder.BuildError):
                builder._validate_arguments([argument])

    def test_repro_verifier_uses_full_retained_candidate_provenance(self) -> None:
        source = inspect.getsource(builder._verify_reproducibility_output_fd)
        self.assertIn("_verify_codex_retained_source_contract(", source)
        self.assertIn("_verify_codex_target_toolchain_wrappers(", source)
        self.assertIn('target_static_libraries"] != []', source)

    def test_pinned_root_fd_survives_receipt_read_then_real_path_swap(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-rootfd-lifetime-test."
        ) as temporary:
            base = Path(temporary)
            root = base / "output"
            pinned_path = base / "pinned-original"
            root.mkdir()
            receipt_path = root / "provider-builder-receipt.json"
            receipt_path.write_text(
                json.dumps({"identity": "original"}), encoding="utf-8"
            )
            payload = root / "payload"
            payload.write_bytes(b"original-retained-payload")
            artifact = builder._artifact(payload, "payload")

            root_descriptor = builder._open_fixed_root(root)
            try:
                identity = os.fstat(root_descriptor)
                self.assertTrue(
                    builder._fixed_root_entry_exists_fd(
                        root_descriptor, "provider-builder-receipt.json"
                    )
                )
                self.assertEqual(
                    builder._read_json_from_fixed_root_fd(
                        root_descriptor, "provider-builder-receipt.json"
                    ),
                    {"identity": "original"},
                )

                root.rename(pinned_path)
                root.mkdir()
                (root / "provider-builder-receipt.json").write_text(
                    json.dumps({"identity": "replacement"}), encoding="utf-8"
                )
                (root / "payload").write_bytes(b"attacker-controlled-payload")

                after_swap = os.fstat(root_descriptor)
                self.assertEqual(
                    (identity.st_dev, identity.st_ino),
                    (after_swap.st_dev, after_swap.st_ino),
                )
                self.assertEqual(
                    builder._read_json_from_fixed_root_fd(
                        root_descriptor, "provider-builder-receipt.json"
                    ),
                    {"identity": "original"},
                )
                with builder._retained_artifact_snapshots_from_fd(
                    root_descriptor, [artifact]
                ) as copies:
                    self.assertEqual(
                        builder._artifact_path(copies, artifact).read_bytes(),
                        b"original-retained-payload",
                    )
            finally:
                os.close(root_descriptor)

    def test_openat2_nonblock_contract_and_fifo_fail_fast(self) -> None:
        captured: dict[str, int] = {}

        class CaptureOpenAt2:
            @staticmethod
            def syscall(
                _number: object,
                _root: object,
                _path: object,
                how_pointer: object,
                _size: object,
            ) -> int:
                how = builder.ctypes.cast(
                    how_pointer, builder.ctypes.POINTER(builder._OpenHow)
                ).contents
                captured["flags"] = how.flags
                builder.ctypes.set_errno(errno.ENOENT)
                return -1

        with (
            mock.patch.object(
                builder.ctypes,
                "CDLL",
                return_value=CaptureOpenAt2(),
            ),
            self.assertRaises(builder.BuildError),
        ):
            builder._openat2_beneath(0, "missing")
        self.assertTrue(captured["flags"] & os.O_NONBLOCK)
        self.assertEqual(
            builder.REQUIRED_RETAINED_OPEN_FLAGS,
            (
                "O_RDONLY",
                "O_CLOEXEC",
                "O_NOFOLLOW",
                "O_NONBLOCK",
            ),
        )
        self.assertEqual(
            builder.RETAINED_COMPONENT_WALK_DIRECTORY_FLAGS,
            ("O_RDONLY", "O_DIRECTORY", "O_CLOEXEC", "O_NOFOLLOW"),
        )

        with tempfile.TemporaryDirectory(
            prefix="provider-fifo-openat2-test."
        ) as temporary:
            root = Path(temporary)
            fifo = root / "fifo"
            os.mkfifo(fifo, 0o600)
            keeper = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
            artifact = {
                "logical_path": "fifo",
                "byte_length": 1,
                "sha256": "a" * 64,
            }
            started = time.monotonic()
            try:
                with self.assertRaisesRegex(
                    builder.BuildError, "exact regular inode"
                ):
                    with builder._retained_artifact_snapshots(
                        root, [artifact]
                    ):
                        pass
            finally:
                os.close(keeper)
            self.assertLess(time.monotonic() - started, 1.0)

    def test_all_direct_regular_read_opens_request_nonblock(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        syntax = ast.parse(source)
        violations: list[int] = []
        for syntax_node in ast.walk(syntax):
            if (
                not isinstance(syntax_node, ast.Call)
                or not isinstance(syntax_node.func, ast.Attribute)
                or not isinstance(syntax_node.func.value, ast.Name)
                or syntax_node.func.value.id != "os"
                or syntax_node.func.attr != "open"
            ):
                continue
            call_source = ast.get_source_segment(source, syntax_node) or ""
            if (
                "os.O_RDONLY" in call_source
                and "os.O_DIRECTORY" not in call_source
                and "os.O_NONBLOCK" not in call_source
            ):
                violations.append(syntax_node.lineno)
        self.assertEqual(violations, [])

    def test_path_regular_read_helpers_reject_fifo_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-path-read-fifo-test."
        ) as temporary:
            root = Path(temporary)
            fifo = root / "fifo"
            os.mkfifo(fifo, 0o600)
            started = time.monotonic()
            with self.assertRaises(builder.BuildError):
                builder._sha256_file(fifo)
            with self.assertRaises(builder.BuildError):
                builder._read_json(fifo)
            with (
                mock.patch.object(builder, "DIRECTORY", root),
                mock.patch.object(builder, "BUILD_CONTEXT_PATHS", ("fifo",)),
                self.assertRaises(builder.BuildError),
            ):
                builder._snapshot_build_context()
            self.assertLess(time.monotonic() - started, 1.0)

    def test_fsync_tree_regular_open_requests_nonblock(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-fsync-tree-open-flags-test."
        ) as temporary:
            root = Path(temporary)
            (root / "artifact").write_bytes(b"candidate")
            root_descriptor = os.open(
                root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            real_open = os.open
            captured: list[int] = []

            def capture_open(
                path: object,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                if path == "artifact":
                    captured.append(flags)
                if dir_fd is None:
                    return real_open(path, flags, mode)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            try:
                with mock.patch.object(builder.os, "open", side_effect=capture_open):
                    builder._fsync_tree_fd(root_descriptor)
            finally:
                os.close(root_descriptor)
            self.assertEqual(len(captured), 1)
            self.assertTrue(captured[0] & os.O_NONBLOCK)

    def test_section_extraction_is_private_explicit_and_source_read_only(
        self,
    ) -> None:
        compiler = shutil.which("aarch64-linux-gnu-gcc")
        objcopy = shutil.which("aarch64-linux-gnu-objcopy") or shutil.which(
            "objcopy"
        )
        if compiler is None or objcopy is None or not hasattr(os, "memfd_create"):
            self.skipTest("AArch64 compiler, objcopy, or memfd is unavailable")
        with tempfile.TemporaryDirectory(
            prefix="provider-section-readonly-test."
        ) as temporary:
            root = Path(temporary)
            source = root / "fixture.c"
            elf = root / "fixture.o"
            destination = root / "section.bin"
            source.write_text(
                "__attribute__((section(\".trillionnium.test\"),used)) "
                "const unsigned char fixture[]={1,2,3,4,5};\n",
                encoding="utf-8",
            )
            subprocess.run(
                [compiler, "-c", str(source), "-o", str(elf)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            before = elf.stat(follow_symlinks=False)
            before_bytes = elf.read_bytes()
            before_sha256 = hashlib.sha256(before_bytes).hexdigest()
            real_run = builder._run
            captured: list[tuple[list[str], tuple[int, ...]]] = []
            real_link = builder._link_unnamed_fd_noreplace
            linked: list[tuple[int, int, str]] = []

            def capture_run(arguments: list[str], **kwargs: object) -> str:
                passed = tuple(kwargs.get("pass_descriptors", ()))
                captured.append((list(arguments), passed))
                return real_run(arguments, **kwargs)

            def capture_link(
                source_descriptor: int,
                parent_descriptor: int,
                destination_name: str,
            ) -> None:
                before = os.fstat(source_descriptor)
                self.assertEqual(before.st_nlink, 0)
                names = os.listdir(parent_descriptor)
                self.assertNotIn(destination_name, names)
                self.assertFalse(
                    any("section-stage" in name for name in names)
                )
                real_link(
                    source_descriptor,
                    parent_descriptor,
                    destination_name,
                )
                after = os.fstat(source_descriptor)
                named = os.stat(
                    destination_name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                self.assertEqual(after.st_nlink, 1)
                self.assertEqual(
                    (after.st_dev, after.st_ino),
                    (named.st_dev, named.st_ino),
                )
                linked.append(
                    (source_descriptor, parent_descriptor, destination_name)
                )

            with (
                mock.patch.object(builder, "_run", side_effect=capture_run),
                mock.patch.object(
                    builder,
                    "_link_unnamed_fd_noreplace",
                    side_effect=capture_link,
                ),
            ):
                builder._extract_section(
                    elf,
                    ".trillionnium.test",
                    destination,
                )
            after = elf.stat(follow_symlinks=False)
            self.assertEqual(
                (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                    before.st_nlink,
                    before.st_uid,
                    before.st_gid,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                ),
                (
                    after.st_dev,
                    after.st_ino,
                    after.st_mode,
                    after.st_nlink,
                    after.st_uid,
                    after.st_gid,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ),
            )
            self.assertEqual(elf.read_bytes(), before_bytes)
            self.assertEqual(builder._sha256_file(elf), before_sha256)
            self.assertEqual(destination.read_bytes(), b"\x01\x02\x03\x04\x05")
            self.assertTrue(stat.S_ISREG(destination.stat().st_mode))
            self.assertEqual(destination.stat().st_nlink, 1)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o400)
            self.assertEqual(len(captured), 1)
            arguments, passed = captured[0]
            self.assertEqual(len(passed), 3)
            self.assertEqual(arguments[-2], f"/proc/self/fd/{passed[0]}")
            self.assertEqual(arguments[-1], f"/proc/self/fd/{passed[1]}")
            self.assertIn(
                f".trillionnium.test=/proc/self/fd/{passed[2]}",
                arguments,
            )
            self.assertNotIn(str(elf), arguments)
            self.assertEqual(len(linked), 1)
            self.assertEqual(linked[0][2], destination.name)

    def test_section_extraction_rejects_source_mutation_and_leaves_no_output(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-section-mutation-test."
        ) as temporary:
            root = Path(temporary)
            elf = root / "fixture.elf"
            destination = root / "section.bin"
            elf.write_bytes(b"retained-source")

            def mutate_source(*_args: object, **_kwargs: object) -> str:
                elf.write_bytes(b"mutated-source")
                return ""

            with (
                mock.patch.object(
                    builder.shutil,
                    "which",
                    return_value="/usr/bin/objcopy",
                ),
                mock.patch.object(builder, "_run", side_effect=mutate_source),
                self.assertRaisesRegex(
                    builder.BuildError,
                    "source identity changed",
                ),
            ):
                builder._extract_section(
                    elf,
                    ".trillionnium.test",
                    destination,
                )
            self.assertFalse(destination.exists())

    def test_section_extraction_failure_preserves_source_and_destination_absence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-section-failure-test."
        ) as temporary:
            root = Path(temporary)
            elf = root / "fixture.elf"
            destination = root / "section.bin"
            original = b"retained-source"
            elf.write_bytes(original)
            before = elf.stat(follow_symlinks=False)
            with (
                mock.patch.object(
                    builder.shutil,
                    "which",
                    return_value="/usr/bin/objcopy",
                ),
                mock.patch.object(
                    builder,
                    "_run",
                    side_effect=builder.BuildError("forced objcopy failure"),
                ),
                self.assertRaisesRegex(builder.BuildError, "forced objcopy failure"),
            ):
                builder._extract_section(
                    elf,
                    ".trillionnium.test",
                    destination,
                )
            after = elf.stat(follow_symlinks=False)
            self.assertEqual(elf.read_bytes(), original)
            self.assertEqual(
                (before.st_ino, before.st_mtime_ns, before.st_ctime_ns),
                (after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
            )
            self.assertFalse(destination.exists())

    def test_section_extraction_never_exposes_partial_destination(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-section-partial-stage-test."
        ) as temporary:
            root = Path(temporary)
            elf = root / "fixture.elf"
            destination = root / "section.bin"
            elf.write_bytes(b"retained-source")
            real_copy = builder._copy_descriptor_bytes
            copy_calls = 0

            def emulate_objcopy(_arguments: object, **kwargs: object) -> str:
                passed = tuple(kwargs["pass_descriptors"])
                os.write(passed[1], b"disposable-objcopy-output")
                os.write(passed[2], b"complete-section")
                return ""

            def fail_during_stage_copy(
                source_descriptor: int,
                destination_descriptor: int,
            ) -> tuple[int, str]:
                nonlocal copy_calls
                copy_calls += 1
                if copy_calls == 2:
                    os.write(destination_descriptor, b"partial")
                    os.fsync(destination_descriptor)
                    raise builder.BuildError("forced partial stage copy")
                return real_copy(source_descriptor, destination_descriptor)

            with (
                mock.patch.object(
                    builder.shutil,
                    "which",
                    return_value="/usr/bin/objcopy",
                ),
                mock.patch.object(builder, "_run", side_effect=emulate_objcopy),
                mock.patch.object(
                    builder,
                    "_copy_descriptor_bytes",
                    side_effect=fail_during_stage_copy,
                ),
                self.assertRaisesRegex(
                    builder.BuildError,
                    "forced partial stage copy",
                ),
            ):
                builder._extract_section(
                    elf,
                    ".trillionnium.test",
                    destination,
                )
            self.assertFalse(destination.exists())
            self.assertEqual(
                [entry.name for entry in root.iterdir()],
                [elf.name],
            )

    def test_section_extraction_no_replace_preserves_existing_destination(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-section-noreplace-test."
        ) as temporary:
            root = Path(temporary)
            elf = root / "fixture.elf"
            destination = root / "section.bin"
            elf.write_bytes(b"retained-source")
            destination.write_bytes(b"existing-destination")

            def emulate_objcopy(_arguments: object, **kwargs: object) -> str:
                passed = tuple(kwargs["pass_descriptors"])
                os.write(passed[1], b"disposable-objcopy-output")
                os.write(passed[2], b"complete-section")
                return ""

            with (
                mock.patch.object(
                    builder.shutil,
                    "which",
                    return_value="/usr/bin/objcopy",
                ),
                mock.patch.object(builder, "_run", side_effect=emulate_objcopy),
                self.assertRaises(builder.BuildError),
            ):
                builder._extract_section(
                    elf,
                    ".trillionnium.test",
                    destination,
                )
            self.assertEqual(destination.read_bytes(), b"existing-destination")
            self.assertEqual(
                sorted(entry.name for entry in root.iterdir()),
                sorted([destination.name, elf.name]),
            )

    def test_reconcile_preflight_malformed_identity_never_falls_back(
        self,
    ) -> None:
        exact_codex = reconcile_preflight_receipt("codex")
        malformed_values = []
        for mutation in (
            {"schema": "wrong"},
            {"provider": "unknown"},
        ):
            value = json.loads(json.dumps(exact_codex))
            value.update(mutation)
            malformed_values.append(value)
        missing_checkpoint = json.loads(json.dumps(exact_codex))
        missing_checkpoint.pop("source_checkpoint")
        malformed_values.append(missing_checkpoint)
        drifted_checkpoint = json.loads(json.dumps(exact_codex))
        drifted_checkpoint["source_checkpoint"] = {}
        malformed_values.append(drifted_checkpoint)

        for malformed in malformed_values:
            with (
                self.subTest(malformed=malformed),
                tempfile.TemporaryDirectory(
                    prefix="provider-reconcile-preflight-malformed."
                ) as temporary,
            ):
                root = Path(temporary)
                (root / "provider-builder-receipt.json").write_bytes(
                    builder._json_bytes(malformed)
                )
                descriptor = os.open(
                    root, os.O_RDONLY | os.O_DIRECTORY
                )
                try:
                    with (
                        mock.patch.object(
                            builder, "_verify_builder_output_fd"
                        ) as full_verify,
                        self.assertRaises(builder.BuildError),
                    ):
                        builder._reconcile_builder_receipt_preflight_fd(
                            descriptor, builder.load_recipe()
                        )
                finally:
                    os.close(descriptor)
                full_verify.assert_not_called()

        with tempfile.TemporaryDirectory(
            prefix="provider-reconcile-preflight-kind."
        ) as temporary:
            root = Path(temporary)
            (root / "provider-builder-receipt.json").write_bytes(
                builder._json_bytes(exact_codex)
            )
            (root / "provider-reproducibility-receipt.json").write_bytes(
                builder._json_bytes({"schema": "conflicting-kind"})
            )
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(
                    builder.BuildError, "exactly one builder receipt kind"
                ):
                    builder._reconcile_builder_receipt_preflight_fd(
                        descriptor, builder.load_recipe()
                    )
            finally:
                os.close(descriptor)

    def test_preloaded_builder_verifier_never_reopens_receipt(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-preloaded-builder-receipt."
        ) as temporary:
            root = Path(temporary)
            (root / "provider-builder-receipt.json").write_bytes(
                builder._json_bytes(reconcile_preflight_receipt("codex"))
            )
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                preloaded = builder._reconcile_builder_receipt_preflight_fd(
                    descriptor, builder.load_recipe()
                )
                with (
                    mock.patch.object(
                        builder, "_read_json_from_fixed_root_fd"
                    ) as reopen,
                    self.assertRaisesRegex(
                        builder.BuildError, "field set drifted"
                    ),
                ):
                    builder._verify_builder_output_fd(
                        descriptor, preloaded_receipt=preloaded
                    )
            finally:
                os.close(descriptor)
            reopen.assert_not_called()

    def test_reconcile_receipt_name_aba_uses_original_preloaded_object(
        self,
    ) -> None:
        class ReachedCodexProjection(RuntimeError):
            pass

        def codex_receipt(profile: str, identity: str) -> dict[str, object]:
            value = reconcile_preflight_receipt("codex")
            value.update(
                {
                    "target_architecture": builder.TARGET_ARCHITECTURE,
                    "source_date_epoch": 1_783_900_800,
                    "recipe": {},
                    "bootstrap": {},
                    "retained_fd_contract": {},
                    "builder": {
                        "profile": profile,
                        "built_image_id": f"sha256:{identity * 64}",
                        "base_platform_manifest_sha256": identity * 64,
                    },
                }
            )
            return value

        with tempfile.TemporaryDirectory(
            prefix="provider-reconcile-receipt-aba."
        ) as temporary:
            base = Path(temporary)
            roots = [base / "builder-a", base / "builder-b"]
            initial_receipts = [
                codex_receipt("amd64-cross", "a"),
                codex_receipt("arm64-native", "b"),
            ]
            for root, receipt in zip(
                roots, initial_receipts, strict=True
            ):
                root.mkdir()
                (root / "provider-builder-receipt.json").write_bytes(
                    builder._json_bytes(receipt)
                )
            descriptors = [
                os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                for root in roots
            ]
            real_read = builder._read_json_from_fixed_root_fd
            read_counts: dict[tuple[int, int], int] = {}
            replaced = False

            def read_then_rebind(
                descriptor: int,
                logical_path: str,
                maximum: int = builder.MAX_RECEIPT_BYTES,
            ) -> dict[str, object]:
                nonlocal replaced
                value = real_read(descriptor, logical_path, maximum)
                metadata = os.fstat(descriptor)
                identity = (metadata.st_dev, metadata.st_ino)
                read_counts[identity] = read_counts.get(identity, 0) + 1
                if sum(read_counts.values()) == 2 and not replaced:
                    named = roots[0] / "provider-builder-receipt.json"
                    named.rename(roots[0] / ".retained-codex-receipt")
                    named.write_bytes(
                        builder._json_bytes(
                            {"provider": "retired_provider"}
                        )
                    )
                    replaced = True
                return value

            full_receipts: list[dict[str, object]] = []

            def verify_preloaded(
                _descriptor: int,
                *,
                preloaded_receipt: dict[str, object] | None = None,
                **_kwargs: object,
            ) -> dict[str, object]:
                self.assertIsNotNone(preloaded_receipt)
                full_receipts.append(preloaded_receipt)
                return preloaded_receipt

            projected_providers: list[str] = []

            def project(receipt: dict[str, object]) -> dict[str, object]:
                projected_providers.append(receipt["provider"])
                raise ReachedCodexProjection

            try:
                with (
                    mock.patch.object(
                        builder,
                        "_read_json_from_fixed_root_fd",
                        side_effect=read_then_rebind,
                    ) as fixed_read,
                    mock.patch.object(
                        builder,
                        "_verify_builder_output_fd",
                        side_effect=verify_preloaded,
                    ),
                    mock.patch.object(
                        builder,
                        "_equal_output_projection",
                        side_effect=project,
                    ),
                    mock.patch.object(
                        builder.tempfile, "TemporaryDirectory"
                    ) as temporary_directory,
                    mock.patch.object(
                        builder, "_publish_directory_noreplace"
                    ) as publish,
                    self.assertRaises(ReachedCodexProjection),
                ):
                    builder._reconcile_from_fds(
                        descriptors, base / "reconciled"
                    )
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)
            self.assertTrue(replaced)
            self.assertEqual(fixed_read.call_count, 2)
            self.assertEqual(sorted(read_counts.values()), [1, 1])
            self.assertEqual(
                [receipt["provider"] for receipt in full_receipts],
                ["codex", "codex"],
            )
            self.assertEqual(projected_providers, ["codex"])
            self.assertEqual(
                json.loads(
                    (roots[0] / "provider-builder-receipt.json").read_bytes()
                )["provider"],
                "retired_provider",
            )
            temporary_directory.assert_not_called()
            publish.assert_not_called()

    def test_reconcile_rejects_full_verifier_receipt_copy(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-reconcile-preloaded-copy."
        ) as temporary:
            base = Path(temporary)
            roots = [base / "builder-a", base / "builder-b"]
            for root in roots:
                root.mkdir()
                (root / "provider-builder-receipt.json").write_bytes(
                    builder._json_bytes(reconcile_preflight_receipt("codex"))
                )
            descriptors = [
                os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                for root in roots
            ]

            def return_copy(
                _descriptor: int,
                *,
                preloaded_receipt: dict[str, object] | None = None,
                **_kwargs: object,
            ) -> dict[str, object]:
                self.assertIsNotNone(preloaded_receipt)
                return dict(preloaded_receipt)

            try:
                with (
                    mock.patch.object(
                        builder,
                        "_verify_builder_output_fd",
                        side_effect=return_copy,
                    ),
                    mock.patch.object(
                        builder, "_equal_output_projection"
                    ) as project,
                    self.assertRaisesRegex(
                        builder.BuildError, "did not consume its preflight receipt"
                    ),
                ):
                    builder._reconcile_from_fds(
                        descriptors, base / "reconciled"
                    )
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)
            project.assert_not_called()


class ContainerLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self._publication_custody_temp = tempfile.TemporaryDirectory(
            prefix="provider-publication-test-custody."
        )
        self.addCleanup(self._publication_custody_temp.cleanup)
        self.publication_custody = Path(self._publication_custody_temp.name)
        self.publication_custody.chmod(0o700)
        self._publication_custody_patch = mock.patch.object(
            builder,
            "PUBLICATION_TEST_ONLY_CUSTODY_DIRECTORY",
            self.publication_custody,
        )
        self._publication_custody_patch.start()
        self.addCleanup(self._publication_custody_patch.stop)

    def test_canonical_outer_container_command_rejects_every_argv_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-canonical-command-test."
        ) as temporary:
            _projection, custody, command, _container_id = (
                container_lifecycle_fixture(Path(temporary))
            )
            try:
                builder._validate_provider_container_command(
                    command,
                    "canonical command",
                )
                image_index = command.index("--provider") - 1
                mutations: dict[str, list[str]] = {}

                entrypoint = list(command)
                entrypoint[image_index:image_index] = [
                    "--entrypoint",
                    "/bin/false",
                ]
                mutations["entrypoint"] = entrypoint

                extra_mount = list(command)
                extra_mount[image_index:image_index] = [
                    "--mount",
                    "type=bind,src=/tmp,dst=/host-tmp",
                ]
                mutations["extra_mount"] = extra_mount

                duplicate_user = list(command)
                duplicate_user[image_index:image_index] = [
                    "--user",
                    "1:1",
                ]
                mutations["duplicate_user"] = duplicate_user

                root_user = list(command)
                root_user[root_user.index("--user") + 1] = "0:0"
                mutations["root_user"] = root_user

                writable_cache = list(command)
                cache_index = next(
                    index
                    for index, value in enumerate(writable_cache)
                    if value.startswith("type=bind,src=")
                    and value.endswith(",dst=/cache,readonly")
                )
                writable_cache[cache_index] = writable_cache[
                    cache_index
                ].removesuffix(",readonly")
                mutations["writable_cache"] = writable_cache

                reordered_mounts = list(command)
                mount_indexes = [
                    index + 1
                    for index, value in enumerate(reordered_mounts[:-1])
                    if value == "--mount"
                ]
                (
                    reordered_mounts[mount_indexes[0]],
                    reordered_mounts[mount_indexes[1]],
                ) = (
                    reordered_mounts[mount_indexes[1]],
                    reordered_mounts[mount_indexes[0]],
                )
                mutations["reordered_mounts"] = reordered_mounts

                alternate_engine = list(command)
                alternate_engine[0] = "podman"
                mutations["alternate_engine"] = alternate_engine

                for label, mutation in mutations.items():
                    with (
                        self.subTest(mutation=label),
                        self.assertRaises(builder.BuildError),
                    ):
                        builder._validate_provider_container_command(
                            mutation,
                            f"tampered {label} command",
                        )
            finally:
                custody.close()

    def test_attempt_identity_binds_every_public_input_and_name_is_closed(
        self,
    ) -> None:
        input_identity = "a" * 64
        output = "/tmp/provider-output"
        cache = "/tmp/provider-cache"
        baseline = builder._build_attempt_identity(
            input_identity,
            "codex",
            "amd64-cross",
            output,
            cache,
        )
        self.assertEqual(
            baseline,
            builder._build_attempt_identity(
                input_identity,
                "codex",
                "amd64-cross",
                output,
                cache,
            ),
        )
        mutations = (
            ("b" * 64, "codex", "amd64-cross", output, cache),
            (input_identity, "codex", "arm64-native", output, cache),
            (input_identity, "codex", "amd64-cross", f"{output}-2", cache),
            (input_identity, "codex", "amd64-cross", output, f"{cache}-2"),
        )
        self.assertEqual(
            len(
                {
                    builder._build_attempt_identity(*mutation)
                    for mutation in mutations
                }
                | {baseline}
            ),
            len(mutations) + 1,
        )
        with self.assertRaisesRegex(builder.BuildError, "outside the closed set"):
            builder._build_attempt_identity(
                input_identity,
                "retired_provider",
                "amd64-cross",
                output,
                cache,
            )
        name = builder._container_name(baseline)
        self.assertLessEqual(
            len(name.encode("ascii")),
            builder.CONTAINER_NAME_MAX_BYTES,
        )
        self.assertRegex(name, r"^[a-z0-9][a-z0-9_.-]*$")

    def test_cidfile_custody_rejects_preexisting_names_and_symlinks(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-cid-preexist-test."
        ) as temporary:
            root = Path(temporary)
            projection, custody, _command, _container_id = (
                container_lifecycle_fixture(root)
            )
            custody.close()
            sentinel = custody.path / "sentinel"
            sentinel.write_bytes(b"do not remove\n")
            with self.assertRaisesRegex(
                builder.BuildError,
                "already exists",
            ):
                builder._prepare_container_cidfile_custody(
                    root / "output",
                    projection["attempt_id_sha256"],
                )
            self.assertEqual(sentinel.read_bytes(), b"do not remove\n")

        for entry_kind in ("regular", "symlink"):
            with (
                self.subTest(entry_kind=entry_kind),
                tempfile.TemporaryDirectory(
                    prefix="provider-cid-entry-test."
                ) as temporary,
            ):
                root = Path(temporary)
                _projection, custody, _command, _container_id = (
                    container_lifecycle_fixture(root)
                )
                target = root / "target"
                target.write_bytes(b"target\n")
                if entry_kind == "regular":
                    custody.cidfile_path.write_bytes(b"pre-existing\n")
                else:
                    custody.cidfile_path.symlink_to(target)
                try:
                    with self.assertRaisesRegex(
                        builder.BuildError,
                        "strictly absent",
                    ):
                        builder._assert_container_cidfile_absent(custody)
                    self.assertTrue(
                        custody.cidfile_path.exists()
                        or custody.cidfile_path.is_symlink()
                    )
                finally:
                    custody.close()

    def test_success_and_failed_run_capture_exact_id_then_unlink_and_fsync(
        self,
    ) -> None:
        cases = (
            (
                "success",
                True,
                "captured_after_success",
                True,
                False,
            ),
            (
                "failed",
                False,
                "captured_after_failed_run",
                False,
                True,
            ),
        )
        for (
            label,
            completed_zero,
            state,
            cross_check,
            allow_failure_states,
        ) in cases:
            with (
                self.subTest(label=label),
                tempfile.TemporaryDirectory(
                    prefix=f"provider-cid-{label}-test."
                ) as temporary,
            ):
                root = Path(temporary)
                projection, custody, command, container_id = (
                    container_lifecycle_fixture(root)
                )
                builder._write_bytes(
                    custody.cidfile_path,
                    container_id.encode("ascii"),
                    mode=0o444,
                )
                try:
                    finalized, tombstone = (
                        builder._finalize_container_cidfile_custody(
                            custody,
                            projection,
                            command=command,
                            completed_zero=completed_zero,
                            expected_container_id=(
                                container_id if cross_check else None
                            ),
                            captured_state=state,
                            allow_absent=False,
                        )
                    )
                    self.assertEqual(finalized["id"], container_id)
                    self.assertEqual(
                        finalized["cidfile"]["state"],
                        state,
                    )
                    self.assertFalse(custody.cidfile_path.exists())
                    self.assertEqual(list(custody.path.iterdir()), [])
                    self.assertEqual(
                        stat.S_IMODE(custody.path.stat().st_mode),
                        0o500,
                    )
                    self.assertTrue(
                        finalized["cidfile"][
                            "captured_after_exit_via_fixed_fd"
                        ]
                    )
                    self.assertTrue(
                        finalized["cidfile"][
                            "container_id_cidfile_observed"
                        ]
                    )
                    self.assertTrue(
                        finalized["cidfile"]["unlinked_after_capture"]
                    )
                    self.assertTrue(
                        finalized["cidfile"]["output_parent_fsynced"]
                    )
                    self.assertIs(
                        finalized["client_disconnect_does_not_imply_container_stop"],
                        True,
                    )
                    self.assertEqual(
                        tombstone["role"],
                        "container_cidfile_custody",
                    )
                    builder._verify_container_projection(
                        finalized,
                        provider_name="codex",
                        profile="amd64-cross",
                        recipe_sha256=builder._one_command_option_value(
                            command,
                            "--recipe-sha256",
                            "test command",
                        ),
                        builder_sha256=builder._one_command_option_value(
                            command,
                            "--builder-sha256",
                            "test command",
                        ),
                        containerfile_sha256=(
                            builder._one_command_option_value(
                                command,
                                "--containerfile-sha256",
                                "test command",
                            )
                        ),
                        image_reference=f"sha256:{'1' * 64}",
                        allow_failure_states=allow_failure_states,
                    )
                finally:
                    custody.close()

    def test_malformed_symlink_and_mutated_cidfiles_are_retained_untrusted(
        self,
    ) -> None:
        for entry_kind in ("malformed", "symlink", "mutated"):
            with (
                self.subTest(entry_kind=entry_kind),
                tempfile.TemporaryDirectory(
                    prefix=f"provider-cid-{entry_kind}-test."
                ) as temporary,
            ):
                root = Path(temporary)
                projection, custody, command, container_id = (
                    container_lifecycle_fixture(root)
                )
                target = root / "target"
                target.write_bytes(container_id.encode("ascii"))
                if entry_kind == "malformed":
                    builder._write_bytes(
                        custody.cidfile_path,
                        b"not-a-container-id",
                        mode=0o444,
                    )
                elif entry_kind == "symlink":
                    custody.cidfile_path.symlink_to(target)
                else:
                    builder._write_bytes(
                        custody.cidfile_path,
                        container_id.encode("ascii"),
                        mode=0o444,
                    )
                original_read = builder._read_bounded_fd

                def mutate_after_read(
                    descriptor: int,
                    logical_path: str,
                    maximum: int,
                ) -> bytes:
                    content = original_read(
                        descriptor,
                        logical_path,
                        maximum,
                    )
                    if (
                        entry_kind == "mutated"
                        and logical_path == builder.CONTAINER_CIDFILE_NAME
                    ):
                        custody.cidfile_path.chmod(0o600)
                        custody.cidfile_path.write_bytes(b"3" * 64)
                    return content

                try:
                    patch = (
                        mock.patch.object(
                            builder,
                            "_read_bounded_fd",
                            side_effect=mutate_after_read,
                        )
                        if entry_kind == "mutated"
                        else nullcontext()
                    )
                    with (
                        patch,
                        self.assertRaises(
                            builder.ContainerCustodyError
                        ) as captured,
                    ):
                        builder._finalize_container_cidfile_custody(
                            custody,
                            projection,
                            command=command,
                            completed_zero=True,
                            expected_container_id=container_id,
                            captured_state="captured_after_success",
                            allow_absent=False,
                        )
                    self.assertEqual(
                        captured.exception.container_projection[
                            "cidfile"
                        ]["state"],
                        "retained_untrusted",
                    )
                    self.assertTrue(
                        custody.cidfile_path.exists()
                        or custody.cidfile_path.is_symlink()
                    )
                finally:
                    custody.close()

    def test_controller_crash_retains_deterministic_orphan_cidfile(
        self,
    ) -> None:
        recipe = builder.load_recipe()
        snapshots = builder._snapshot_build_context()
        recipe_sha256 = hashlib.sha256(
            snapshots["provider-payload-recipe-v1.json"]
        ).hexdigest()
        builder_sha256 = hashlib.sha256(
            snapshots["build_provider_payload.py"]
        ).hexdigest()
        containerfile_sha256 = hashlib.sha256(
            snapshots["Containerfile"]
        ).hexdigest()
        image_tag = builder._container_image_tag(
            recipe_sha256,
            builder_sha256,
            containerfile_sha256,
            "amd64-cross",
        )
        container_id = "4" * 64
        with tempfile.TemporaryDirectory(
            prefix="provider-controller-crash-test."
        ) as temporary:
            root = Path(temporary)
            output = root / "output"
            cache = root / "cache"
            cache.mkdir()
            captured_command: list[str] = []

            def crash(arguments: list[str], **_: object) -> str:
                captured_command.extend(arguments)
                cidfile = Path(
                    arguments[arguments.index("--cidfile") + 1]
                )
                builder._write_bytes(
                    cidfile,
                    container_id.encode("ascii"),
                    mode=0o444,
                )
                raise KeyboardInterrupt("simulated controller crash")

            with (
                mock.patch.object(builder, "load_recipe", return_value=recipe),
                mock.patch.object(
                    builder,
                    "_snapshot_build_context",
                    return_value=snapshots,
                ),
                mock.patch.object(builder, "_prefetch"),
                mock.patch.object(
                    builder,
                    "_build_container_image",
                    return_value=(
                        image_tag,
                        f"sha256:{'b' * 64}",
                        builder_sha256,
                        containerfile_sha256,
                        builder._build_context_receipt(snapshots),
                    ),
                ),
                mock.patch.object(builder, "_run", side_effect=crash),
                self.assertRaises(KeyboardInterrupt),
            ):
                builder._public_build(
                    "codex",
                    "amd64-cross",
                    output,
                    cache,
                    "docker",
                )
            cidfile = Path(
                captured_command[captured_command.index("--cidfile") + 1]
            )
            self.assertEqual(cidfile.read_text(encoding="ascii"), container_id)
            self.assertFalse(output.exists())
            self.assertFalse(output.with_name("output.failure").exists())
            self.assertEqual(
                captured_command[
                    captured_command.index("--name") + 1
                ],
                builder._container_name(
                    builder._build_attempt_identity(
                        builder._container_input_identity(
                            recipe_sha256,
                            builder_sha256,
                            containerfile_sha256,
                        ),
                        "codex",
                        "amd64-cross",
                        str(output),
                        str(cache),
                    )
                ),
            )

    def test_container_name_collision_fails_without_broad_cleanup(
        self,
    ) -> None:
        recipe = builder.load_recipe()
        snapshots = builder._snapshot_build_context()
        recipe_sha256 = hashlib.sha256(
            snapshots["provider-payload-recipe-v1.json"]
        ).hexdigest()
        builder_sha256 = hashlib.sha256(
            snapshots["build_provider_payload.py"]
        ).hexdigest()
        containerfile_sha256 = hashlib.sha256(
            snapshots["Containerfile"]
        ).hexdigest()
        image_tag = builder._container_image_tag(
            recipe_sha256,
            builder_sha256,
            containerfile_sha256,
            "amd64-cross",
        )
        observed: list[list[str]] = []

        def collide(arguments: list[str], **_: object) -> str:
            observed.append(list(arguments))
            raise builder.CommandFailure(
                arguments,
                125,
                "Conflict. The container name is already in use.\n",
                False,
            )

        with tempfile.TemporaryDirectory(
            prefix="provider-container-name-collision-test."
        ) as temporary:
            root = Path(temporary)
            output = root / "output"
            cache = root / "cache"
            cache.mkdir()
            with (
                mock.patch.object(builder, "load_recipe", return_value=recipe),
                mock.patch.object(
                    builder,
                    "_snapshot_build_context",
                    return_value=snapshots,
                ),
                mock.patch.object(builder, "_prefetch"),
                mock.patch.object(
                    builder,
                    "_build_container_image",
                    return_value=(
                        image_tag,
                        f"sha256:{'b' * 64}",
                        builder_sha256,
                        containerfile_sha256,
                        builder._build_context_receipt(snapshots),
                    ),
                ),
                mock.patch.object(builder, "_run", side_effect=collide),
                self.assertRaises(builder.BuildError),
            ):
                builder._public_build(
                    "codex",
                    "amd64-cross",
                    output,
                    cache,
                    "docker",
                )
            self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0][:2], ["docker", "run"])
            self.assertFalse(
                any(
                    action in observed[0]
                    for action in ("rm", "stop", "kill")
                )
            )
            failure = builder._verify_failure_output(
                output.with_name("output.failure")
            )
            self.assertEqual(failure["cause"]["return_code"], 125)
            self.assertEqual(
                failure["container"]["cidfile"]["state"],
                "absent_after_failed_run",
            )
            self.assertIsNone(failure["container"]["id"])
            self.assertFalse(
                failure["container"]["cidfile"][
                    "container_id_cidfile_observed"
                ]
            )
            self.assertIs(
                failure["container"][
                    "client_disconnect_does_not_imply_container_stop"
                ],
                True,
            )
            self.assertEqual(
                failure["container"]["name"],
                observed[0][observed[0].index("--name") + 1],
            )
            self.assertFalse(
                Path(
                    failure["container"]["cidfile"]["host_path"]
                ).exists()
            )

    def test_sealed_stdin_context_resists_post_hash_mutation_and_rejects_drift(
        self,
    ) -> None:
        recipe = builder.load_recipe()
        snapshots = builder._snapshot_build_context()
        original = dict(snapshots)
        recipe_sha256 = hashlib.sha256(
            snapshots["provider-payload-recipe-v1.json"]
        ).hexdigest()
        builder_sha256 = hashlib.sha256(
            snapshots["build_provider_payload.py"]
        ).hexdigest()
        containerfile_sha256 = hashlib.sha256(
            snapshots["Containerfile"]
        ).hexdigest()
        captured_tar: list[bytes] = []

        def race(arguments: list[str], **kwargs: object) -> str:
            if arguments[1:3] == ["image", "inspect"]:
                return f"sha256:{'5' * 64}\n"
            descriptor = kwargs["stdin_descriptor"]
            self.assertIsInstance(descriptor, int)
            with self.assertRaises(OSError) as sealed:
                os.pwrite(descriptor, b"attacker", 0)
            self.assertIn(
                sealed.exception.errno,
                {errno.EPERM, errno.EBUSY},
            )
            metadata = os.fstat(descriptor)
            captured_tar.append(
                os.pread(descriptor, metadata.st_size, 0)
            )
            snapshots["Containerfile"] = b"same-UID post-hash mutation"
            return f"sha256:{'5' * 64}\n"

        with (
            mock.patch.object(builder, "_verify_remote_base_manifest"),
            mock.patch.object(builder, "_run", side_effect=race),
        ):
            builder._build_container_image(
                "docker",
                "amd64-cross",
                recipe,
                recipe_sha256,
                snapshots,
                builder_sha256,
                containerfile_sha256,
            )
        self.assertEqual(
            captured_tar,
            [builder._deterministic_build_context_tar(original)],
        )
        self.assertEqual(captured_tar[0][-1024:], b"\0" * 1024)

        drifted = dict(original)
        drifted["Containerfile"] = b"pre-build drift"
        with (
            mock.patch.object(builder, "_run") as run,
            self.assertRaisesRegex(
                builder.BuildError,
                "sealed builder context identity drifted",
            ),
        ):
            builder._build_container_image(
                "docker",
                "amd64-cross",
                recipe,
                recipe_sha256,
                drifted,
                builder_sha256,
                containerfile_sha256,
            )
        run.assert_not_called()

    def test_quiet_build_id_is_authoritative_and_retag_race_is_rejected(
        self,
    ) -> None:
        recipe = builder.load_recipe()
        snapshots = builder._snapshot_build_context()
        recipe_sha256 = hashlib.sha256(
            snapshots["provider-payload-recipe-v1.json"]
        ).hexdigest()
        builder_sha256 = hashlib.sha256(
            snapshots["build_provider_payload.py"]
        ).hexdigest()
        containerfile_sha256 = hashlib.sha256(
            snapshots["Containerfile"]
        ).hexdigest()
        produced = f"sha256:{'6' * 64}"
        retargeted = f"sha256:{'7' * 64}"
        observed: list[list[str]] = []

        def retag_race(
            arguments: list[str],
            **kwargs: object,
        ) -> str:
            observed.append(list(arguments))
            if arguments[1:3] == ["image", "inspect"]:
                self.assertNotIn("stdin_descriptor", kwargs)
                return f"{retargeted}\n"
            self.assertIn("--quiet", arguments)
            self.assertEqual(arguments[-1], "-")
            self.assertIsInstance(kwargs.get("stdin_descriptor"), int)
            return f"{produced}\n"

        with (
            mock.patch.object(builder, "_verify_remote_base_manifest"),
            mock.patch.object(builder, "_run", side_effect=retag_race),
            self.assertRaisesRegex(
                builder.BuildError,
                "mutable builder tag",
            ),
        ):
            builder._build_container_image(
                "docker",
                "amd64-cross",
                recipe,
                recipe_sha256,
                snapshots,
                builder_sha256,
                containerfile_sha256,
            )
        self.assertEqual(len(observed), 2)
        self.assertEqual(observed[0][:2], ["docker", "build"])
        self.assertEqual(observed[0].count("--quiet"), 1)
        self.assertEqual(
            observed[1][:5],
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
            ],
        )

    def test_build_context_receipt_binds_complete_frozen_context(
        self,
    ) -> None:
        snapshots = builder._snapshot_build_context()
        receipt = builder._build_context_receipt(snapshots)
        recipe_sha256 = hashlib.sha256(
            snapshots["provider-payload-recipe-v1.json"]
        ).hexdigest()
        builder_sha256 = hashlib.sha256(
            snapshots["build_provider_payload.py"]
        ).hexdigest()
        containerfile_sha256 = hashlib.sha256(
            snapshots["Containerfile"]
        ).hexdigest()
        builder._verify_build_context_receipt(
            receipt,
            snapshots=snapshots,
        )
        builder._verify_build_context_lifecycle_inputs(
            receipt,
            recipe_sha256=recipe_sha256,
            builder_sha256=builder_sha256,
            containerfile_sha256=containerfile_sha256,
        )

        tampered_tar = json.loads(json.dumps(receipt))
        tampered_tar["tar_sha256"] = "8" * 64
        with self.assertRaisesRegex(
            builder.BuildError,
            "differs from frozen snapshot bytes",
        ):
            builder._verify_build_context_lifecycle_inputs(
                tampered_tar,
                recipe_sha256=recipe_sha256,
                builder_sha256=builder_sha256,
                containerfile_sha256=containerfile_sha256,
            )

        tampered_non_lifecycle_member = json.loads(json.dumps(receipt))
        for member in tampered_non_lifecycle_member["members"]:
            if member["path"] == "src/provider_post_exec_bootstrap.c":
                member["sha256"] = "9" * 64
                break
        tampered_non_lifecycle_member["member_manifest_sha256"] = (
            builder._domain_digest(
                builder.BUILD_CONTEXT_MEMBER_MANIFEST_DOMAIN,
                [
                    builder._json_bytes(
                        tampered_non_lifecycle_member["members"]
                    )
                ],
            )
        )
        with self.assertRaisesRegex(
            builder.BuildError,
            "differs from frozen snapshot bytes",
        ):
            builder._verify_build_context_lifecycle_inputs(
                tampered_non_lifecycle_member,
                recipe_sha256=recipe_sha256,
                builder_sha256=builder_sha256,
                containerfile_sha256=containerfile_sha256,
            )

        tampered_member_manifest = json.loads(json.dumps(receipt))
        tampered_member_manifest["member_manifest_sha256"] = "a" * 64
        with self.assertRaisesRegex(
            builder.BuildError,
            "transport contract drifted",
        ):
            builder._verify_build_context_lifecycle_inputs(
                tampered_member_manifest,
                recipe_sha256=recipe_sha256,
                builder_sha256=builder_sha256,
                containerfile_sha256=containerfile_sha256,
            )


class OfflineCodexClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self._publication_custody_temp = tempfile.TemporaryDirectory(
            prefix="provider-publication-test-custody."
        )
        self.addCleanup(self._publication_custody_temp.cleanup)
        self.publication_custody = Path(self._publication_custody_temp.name)
        self.publication_custody.chmod(0o700)
        self._publication_custody_patch = mock.patch.object(
            builder,
            "PUBLICATION_TEST_ONLY_CUSTODY_DIRECTORY",
            self.publication_custody,
        )
        self._publication_custody_patch.start()
        self.addCleanup(self._publication_custody_patch.stop)

    _RUST_CRT_ROOTS = (
        Path(
            "/usr/local/rustup/toolchains/"
            "1.95.0-x86_64-unknown-linux-gnu/lib/rustlib/"
            "aarch64-unknown-linux-musl/lib/self-contained"
        ),
        Path(
            "/usr/local/rustup/toolchains/"
            "1.95.0-aarch64-unknown-linux-gnu/lib/rustlib/"
            "aarch64-unknown-linux-musl/lib/self-contained"
        ),
    )

    @staticmethod
    def _rust_like_linker_arguments(root: Path) -> list[str]:
        return [
            str(root / "crt1.o"),
            str(root / "crti.o"),
            str(root / "crtbegin.o"),
            "/output/.work/target/aarch64-unknown-linux-musl/release/main.o",
            "-Wl,--as-needed",
            "-Wl,-Bstatic",
            "-lunwind",
            "-lc",
            "-Wl,-Bdynamic",
            "-Wl,--eh-frame-hdr",
            "-nostartfiles",
            "-L",
            str(root),
            "-static",
            "-no-pie",
            "-nodefaultlibs",
            "-Wl,-e,trillionnium_provider_post_final_exec_entry",
            "-Wl,-Map,/output/.work/build/final.map",
            "-Wl,--threads=1",
            "-Wl,-z,noexecstack",
            "-o",
            "/output/.work/target/aarch64-unknown-linux-musl/release/codex",
            str(root / "crtend.o"),
            str(root / "crtn.o"),
        ]

    def _run_linker_wrapper(
        self, arguments: list[str]
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(
            prefix="provider-codex-linker-wrapper."
        ) as temporary:
            wrapper = Path(temporary) / "aarch64-linux-musl-cargo-linker"
            wrapper.write_bytes(
                builder.CODEX_TARGET_TOOLCHAIN_WRAPPERS["linker"][1]
            )
            wrapper.chmod(0o555)
            return subprocess.run(
                [str(wrapper), *arguments],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

    def test_codex_linker_rejects_missing_or_duplicate_rust_crt(
        self,
    ) -> None:
        root = self._RUST_CRT_ROOTS[0]
        arguments = self._rust_like_linker_arguments(root)
        crt_paths = [str(root / name) for name in (
            "crt1.o",
            "crti.o",
            "crtbegin.o",
            "crtend.o",
            "crtn.o",
        )]
        for crt_path in crt_paths:
            with self.subTest(missing=Path(crt_path).name):
                result = self._run_linker_wrapper(
                    [argument for argument in arguments if argument != crt_path]
                )
                self.assertEqual(result.returncode, 2)
                self.assertRegex(
                    result.stderr,
                    "CRT.*(missing|order)|crt1\\.o root",
                )
            with self.subTest(duplicate=Path(crt_path).name):
                duplicated = list(arguments)
                duplicated.insert(3, crt_path)
                result = self._run_linker_wrapper(duplicated)
                self.assertEqual(result.returncode, 2)
                self.assertIn("CRT sequence is duplicated", result.stderr)

    def test_codex_linker_rejects_unexpected_or_mixed_rust_crt(
        self,
    ) -> None:
        root, other_root = self._RUST_CRT_ROOTS
        arguments = self._rust_like_linker_arguments(root)
        for variant in (
            "crt0.o",
            "Scrt1.o",
            "rcrt1.o",
            "crtbeginS.o",
            "crtbeginT.o",
            "crtendS.o",
        ):
            with self.subTest(variant=variant):
                unexpected = list(arguments)
                unexpected.insert(3, str(root / variant))
                result = self._run_linker_wrapper(unexpected)
                self.assertEqual(result.returncode, 2)
                self.assertIn("unexpected or aliased target CRT", result.stderr)

        mixed = list(arguments)
        mixed[1] = str(other_root / "crti.o")
        result = self._run_linker_wrapper(mixed)
        self.assertEqual(result.returncode, 2)
        self.assertIn("CRT sequence is missing, mixed, or out of order", result.stderr)

        reordered = list(arguments)
        reordered[1], reordered[2] = reordered[2], reordered[1]
        result = self._run_linker_wrapper(reordered)
        self.assertEqual(result.returncode, 2)
        self.assertIn("CRT sequence is missing, mixed, or out of order", result.stderr)

    def test_codex_linker_rejects_missing_duplicate_or_aliased_rust_runtime(
        self,
    ) -> None:
        root = self._RUST_CRT_ROOTS[0]
        arguments = self._rust_like_linker_arguments(root)
        for flag, archive, label in (
            ("-lc", "libc.a", "libc"),
            ("-lunwind", "libunwind.a", "libunwind"),
        ):
            with self.subTest(missing=label):
                missing = [
                    argument for argument in arguments if argument != flag
                ]
                result = self._run_linker_wrapper(missing)
                self.assertEqual(result.returncode, 2)
                self.assertIn(
                    f"{label} contract must appear exactly once",
                    result.stderr,
                )

            with self.subTest(duplicate=label):
                duplicate = list(arguments)
                duplicate.insert(7, flag)
                result = self._run_linker_wrapper(duplicate)
                self.assertEqual(result.returncode, 2)
                self.assertIn(
                    f"{label} contract must appear exactly once",
                    result.stderr,
                )

            for alias in (f"-Wl,{flag}", str(root / archive)):
                with self.subTest(label=label, alias=alias):
                    aliased = [
                        alias if argument == flag else argument
                        for argument in arguments
                    ]
                    result = self._run_linker_wrapper(aliased)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn(
                        f"unexpected target {label} alias",
                        result.stderr,
                    )

    def test_codex_linker_rejects_unbounded_linker_indirection(self) -> None:
        root = self._RUST_CRT_ROOTS[0]
        arguments = self._rust_like_linker_arguments(root)
        for injected in (
            ["@/output/arguments.rsp"],
            ["-Wl,@/output/arguments.rsp"],
            ["-T", "/output/linker.ld"],
            ["-T/output/linker.ld"],
            ["--script=/output/linker.ld"],
            ["-script=/output/linker.ld"],
            ["-Wl,-T,/output/linker.ld"],
            ["-Wl,--script=/output/linker.ld"],
            ["-Xlinker", "@/output/arguments.rsp"],
            ["-Xlinker=-T/output/linker.ld"],
            ["--version-script=/output/versions.ld"],
            ["-version-script", "/output/versions.ld"],
            ["-Wl,-version-script,/output/versions.ld"],
            ["-Wl,--dynamic-list,/output/dynamic.list"],
            ["--retain-symbols-file=/output/symbols.txt"],
            ["--just-symbols=/output/alternate.o"],
            ["--defsym=trillionnium_provider_post_final_exec_entry=0"],
            ["-defsym=trillionnium_provider_post_final_exec_entry=0"],
            ["-defsym", "trillionnium_provider_post_final_exec_entry=0"],
            ["--wrap=_start"],
            ["-wrap=_start"],
            ["-Wl,--wrap,_start"],
            ["-Wl,-wrap,_start"],
            ["-wrap", "_start"],
            ["-Wl,--allow-multiple-definition"],
            ["-Wl,--unresolved-symbols=ignore-all"],
            ["--plugin=/output/linker-plugin.so"],
            ["-plugin=/output/linker-plugin.so"],
            ["-plugin", "/output/linker-plugin.so"],
            ["-fuse-ld=/output/alternate-linker"],
            ["/output/implicit-linker-script.lds"],
            ["--sysroot", "/output/alternate-sysroot"],
            ["--sysroot=/output/alternate-sysroot"],
            ["-sysroot=/output/alternate-sysroot"],
            ["-sysroot", "/output/alternate-sysroot"],
            ["-Wl,--sysroot=/output/alternate-sysroot"],
            ["-Wl,-sysroot,/output/alternate-sysroot"],
            ["-L/output/alternate-sysroot"],
            ["-Wl,-L,/output/alternate-sysroot"],
            ["-l:libc.a"],
            ["-Wl,-l:libunwind.a"],
        ):
            with self.subTest(injected=injected):
                mutated = list(arguments)
                mutated[3:3] = injected
                result = self._run_linker_wrapper(mutated)
                self.assertEqual(result.returncode, 2)
                self.assertIn("outside the closed allowlist", result.stderr)

        for injected in (
            ["-lmalicious"],
            ["-Wl,-lmalicious"],
            ["--library=malicious"],
            ["-library=malicious"],
            ["--library", "malicious"],
            ["-library", "malicious"],
            ["-l", "malicious"],
            ["-Wl,--library,malicious"],
            ["-Wl,-library,malicious"],
        ):
            with self.subTest(library_alias=injected):
                mutated = list(arguments)
                mutated[3:3] = injected
                result = self._run_linker_wrapper(mutated)
                self.assertEqual(result.returncode, 2)
                self.assertIn("outside the closed allowlist", result.stderr)

    def test_pinned_zig_wrapper_rejects_gnu_lld_alias_matrix(self) -> None:
        if os.environ.get("TRILLIONNIUM_RUN_REAL_ZIG_CRT_SMOKE") != "1":
            self.skipTest("pinned Zig closed-linker negative matrix is opt-in")
        root = next(
            candidate for candidate in self._RUST_CRT_ROOTS if candidate.is_dir()
        )
        baseline = self._rust_like_linker_arguments(root)
        for injected in (
            ["@/output/.work/args.rsp"],
            ["-Xlinker", "--wrap=_start"],
            ["--script=/output/.work/script.ld"],
            ["-script=/output/.work/script.ld"],
            ["-version-script", "/output/.work/version.map"],
            ["-Wl,-version-script,/output/.work/version.map"],
            ["--wrap=_start"],
            ["-wrap=_start"],
            ["-wrap", "_start"],
            ["--defsym=main=0"],
            ["-defsym=main=0"],
            ["-defsym", "main=0"],
            ["--plugin=/output/.work/plugin.so"],
            ["-plugin=/output/.work/plugin.so"],
            ["-plugin", "/output/.work/plugin.so"],
            ["--sysroot=/output/.work/sysroot"],
            ["-sysroot=/output/.work/sysroot"],
            ["-sysroot", "/output/.work/sysroot"],
            ["-Wl,-L,/output/.work/sysroot"],
            ["-l:libc.a"],
            ["--library=c"],
            ["-library=c"],
            ["-library", "c"],
        ):
            with self.subTest(injected=injected):
                arguments = list(baseline)
                arguments[3:3] = injected
                result = self._run_linker_wrapper(arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn("outside the closed allowlist", result.stderr)

    def test_real_rust_like_zig_link_preserves_controlled_static_entry(
        self,
    ) -> None:
        if os.environ.get("TRILLIONNIUM_RUN_REAL_ZIG_CRT_SMOKE") != "1":
            self.skipTest("real Zig/Rust CRT smoke is opt-in")
        zig = Path("/opt/zig/zig")
        host_triple = {
            "x86_64": "x86_64-unknown-linux-gnu",
            "aarch64": "aarch64-unknown-linux-gnu",
        }.get(os.uname().machine)
        self.assertIsNotNone(host_triple)
        root = Path(
            "/usr/local/rustup/toolchains"
        ) / f"1.95.0-{host_triple}" / (
            "lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained"
        )
        for name in (
            "crt1.o",
            "crti.o",
            "crtbegin.o",
            "crtend.o",
            "crtn.o",
            "libc.a",
            "libunwind.a",
        ):
            component = root / name
            self.assertTrue(component.is_file())
            self.assertFalse(component.is_symlink())
        self.assertTrue(zig.is_file())

        build = Path("/output/.work/build")
        build.mkdir(parents=True)
        core = build / "provider-post-exec-bootstrap.o"
        entry = build / "provider-post-exec-entry.o"
        main_source = build / "main.c"
        main_object = build / "main.o"
        final_elf = build / "rust-like-zig-smoke"
        link_map = build / "final.map"
        wrapper = build / "aarch64-linux-musl-cargo-linker"
        main_source.write_text(
            "int main(void) { return 0; }\n",
            encoding="utf-8",
        )
        wrapper.write_bytes(
            builder.CODEX_TARGET_TOOLCHAIN_WRAPPERS["linker"][1]
        )
        wrapper.chmod(0o555)
        recipe = builder.load_recipe()
        compile_arguments = builder._bootstrap_compile_arguments(
            recipe, recipe["providers"]["codex"]
        )

        def run(arguments: list[str]) -> None:
            result = subprocess.run(
                arguments,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(
                result.returncode,
                0,
                f"command failed: {arguments!r}\n{result.stdout}",
            )

        run(
            [
                str(zig),
                "cc",
                *compile_arguments,
                "-c",
                str(DIRECTORY / "src/provider_post_exec_bootstrap.c"),
                "-o",
                str(core),
            ]
        )
        run(
            [
                str(zig),
                "cc",
                *compile_arguments,
                "-c",
                str(DIRECTORY / "src/provider_post_exec_entry.S"),
                "-o",
                str(entry),
            ]
        )
        run(
            [
                str(zig),
                "cc",
                "-target",
                "aarch64-linux-musl",
                "-c",
                str(main_source),
                "-o",
                str(main_object),
            ]
        )
        run(
            [
                str(wrapper),
                str(root / "crt1.o"),
                str(root / "crti.o"),
                str(root / "crtbegin.o"),
                str(main_object),
                "-Wl,--as-needed",
                "-Wl,-Bstatic",
                "-lunwind",
                "-lc",
                "-Wl,-Bdynamic",
                "-Wl,--eh-frame-hdr",
                "-nostartfiles",
                "-L",
                str(root),
                "-static",
                "-no-pie",
                "-nodefaultlibs",
                str(core),
                str(entry),
                "-Wl,-e,trillionnium_provider_post_final_exec_entry",
                "-Wl,-Map,/output/.work/build/final.map",
                "-Wl,--build-id=sha1",
                "-Wl,--threads=1",
                "-Wl,-z,noexecstack",
                "-o",
                str(final_elf),
                str(root / "crtend.o"),
                str(root / "crtn.o"),
            ]
        )
        inspection = build / "inspection"
        inspection.mkdir()
        facts = builder._inspect_final_elf(
            final_elf, "codex", core, inspection, recipe
        )
        self.assertEqual(facts["elf_type"], "EXEC")
        self.assertEqual(facts["mechanism"], "controlled_entry_before_crt")
        self.assertEqual(
            facts["entry_address"],
            facts["controlled_entry"]["address"],
        )
        self.assertNotEqual(
            facts["entry_address"],
            facts["original_start"]["address"],
        )
        self.assertFalse(facts["has_dynamic_segment"])
        self.assertTrue(link_map.is_file())
        program_headers = builder._readelf(
            final_elf, "--program-headers", "--wide"
        )
        self.assertNotIn("INTERP", program_headers)
        map_text = link_map.read_text(encoding="utf-8")
        for name in (
            "crt1.o",
            "crti.o",
            "crtbegin.o",
            "crtend.o",
            "crtn.o",
            "libc.a",
        ):
            self.assertIn(str(root / name), map_text)
        self.assertNotRegex(map_text, r"/\.cache/zig/\S*/crt1\.o")
        self.assertNotRegex(map_text, r"/\.cache/zig/\S*/libunwind\.a")
        symbols = builder._readelf(final_elf, "--symbols", "--wide")
        start = builder._symbol_facts(symbols, "_start")
        self.assertEqual(start, facts["original_start"])

    def test_vendor_inventory_accepts_exact_zero_length_regular_files(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-zero-vendor-file."
        ) as temporary:
            root = Path(temporary) / "cargo-vendor"
            package = root / "crate-1.0.0"
            package.mkdir(parents=True)
            root.chmod(0o755)
            package.chmod(0o755)
            empty = package / "rustfmt.toml"
            empty.write_bytes(b"")
            empty.chmod(0o644)
            entries, digest = builder._vendor_member_inventory(root)
        self.assertEqual(entries[-1]["byte_length"], 0)
        self.assertEqual(
            entries[-1]["sha256"],
            hashlib.sha256(b"").hexdigest(),
        )
        self.assertEqual(
            digest,
            hashlib.sha256(
                json.dumps(
                    entries,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest(),
        )

    def test_derived_lock_changes_only_exact_132_workspace_versions(self) -> None:
        upstream, expected, expected_patch, names, rule = (
            synthetic_codex_lock_fixture()
        )
        derived, patch, changed = builder._derive_codex_lock_bytes(
            upstream, rule
        )
        self.assertEqual(derived, expected)
        self.assertEqual(patch, expected_patch)
        self.assertEqual(changed, names)
        self.assertEqual(
            upstream.count(b'version = "0.0.0"\n'),
            132,
        )
        self.assertEqual(
            derived.count(b'version = "0.144.1"\n'),
            132,
        )
        self.assertNotIn(b'version = "0.0.0"\n', derived)

        changed_patch_lines = [
            line
            for line in patch.splitlines()
            if line.startswith((b"+", b"-"))
            and not line.startswith((b"+++", b"---"))
        ]
        self.assertEqual(len(changed_patch_lines), 264)
        self.assertEqual(
            set(changed_patch_lines),
            {
                b'-version = "0.0.0"',
                b'+version = "0.144.1"',
            },
        )
        for frozen in (
            b'source = "registry+https://github.com/rust-lang/crates.io-index"',
            b'checksum = "' + b"a" * 64 + b'"',
            b' "git-fixture",',
            (
                b'source = "git+https://example.invalid/frozen?rev='
                + b"b" * 40
                + b"#"
                + b"c" * 40
                + b'"'
            ),
        ):
            self.assertEqual(upstream.count(frozen), 1)
            self.assertEqual(derived.count(frozen), 1)

    def test_derived_lock_rejects_inventory_and_nonlocal_drift(self) -> None:
        upstream, _derived, _patch, names, rule = (
            synthetic_codex_lock_fixture()
        )
        mutations = {
            "registry checksum": upstream.replace(
                b'checksum = "' + b"a" * 64 + b'"',
                b'checksum = "' + b"d" * 64 + b'"',
                1,
            ),
            "registry dependency": upstream.replace(
                b' "git-fixture",',
                b' "git-fixture-drift",',
                1,
            ),
            "git source": upstream.replace(
                b"#" + b"c" * 40 + b'"',
                b"#" + b"d" * 40 + b'"',
                1,
            ),
            "workspace package became sourced": upstream.replace(
                (
                    f'name = "{names[0]}"\n'
                    'version = "0.0.0"\n'
                ).encode("ascii"),
                (
                    f'name = "{names[0]}"\n'
                    'version = "0.0.0"\n'
                    'source = "registry+https://example.invalid/index"\n'
                ).encode("ascii"),
                1,
            ),
            "workspace version was prechanged": upstream.replace(
                (
                    f'name = "{names[0]}"\n'
                    'version = "0.0.0"\n'
                ).encode("ascii"),
                (
                    f'name = "{names[0]}"\n'
                    'version = "0.0.1"\n'
                ).encode("ascii"),
                1,
            ),
            "duplicate workspace package name": upstream.replace(
                f'name = "{names[1]}"'.encode("ascii"),
                f'name = "{names[0]}"'.encode("ascii"),
                1,
            ),
        }
        for label, mutated in mutations.items():
            with (
                self.subTest(label=label),
                self.assertRaises(builder.BuildError),
            ):
                builder._derive_codex_lock_bytes(mutated, rule)

        for key, drift in (
            ("workspace_package_count", 131),
            ("workspace_package_names_sha256", "d" * 64),
            ("derived_sha256", "d" * 64),
            ("patch_sha256", "d" * 64),
            ("workspace_version", "0.144.2"),
        ):
            with (
                self.subTest(rule_key=key),
                self.assertRaises(builder.BuildError),
            ):
                builder._derive_codex_lock_bytes(
                    upstream,
                    {**rule, key: drift},
                )

    def test_workspace_manifest_inventory_must_match_derived_lock(self) -> None:
        _upstream, _derived, _patch, names, _rule = (
            synthetic_codex_lock_fixture()
        )
        with tempfile.TemporaryDirectory(
            prefix="provider-codex-manifest-inventory."
        ) as temporary:
            source = Path(temporary)
            codex_rs = source / "codex-rs"
            codex_rs.mkdir()
            (codex_rs / "Cargo.toml").write_text(
                "[workspace]\n"
                "[workspace.package]\n"
                'version = "0.144.1"\n',
                encoding="utf-8",
            )
            for index, name in enumerate(names):
                package = codex_rs / f"fixture-{index:03d}"
                package.mkdir()
                (package / "Cargo.toml").write_text(
                    "[package]\n"
                    f'name = "{name}"\n'
                    "version.workspace = true\n",
                    encoding="utf-8",
                )
            builder._verify_codex_workspace_manifests(
                source, names, "0.144.1"
            )

            drifted = codex_rs / "fixture-000" / "Cargo.toml"
            drifted.write_text(
                "[package]\n"
                'name = "attacker-substituted-workspace-package"\n'
                "version.workspace = true\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                builder.BuildError, "manifest/lock workspace package set"
            ):
                builder._verify_codex_workspace_manifests(
                    source, names, "0.144.1"
                )

    def test_codex_cargo_is_frozen_offline_and_binds_config_and_v8(
        self,
    ) -> None:
        self.assertIn(
            "codex_inputs",
            inspect.signature(builder._codex_build).parameters,
        )
        _upstream, derived, _patch, _names, rule = (
            synthetic_codex_lock_fixture()
        )
        with tempfile.TemporaryDirectory(
            prefix="provider-codex-offline-build."
        ) as temporary:
            root = Path(temporary)
            source = root / "source"
            codex_rs = source / "codex-rs"
            codex_rs.mkdir(parents=True)
            (codex_rs / "Cargo.lock").write_bytes(derived)
            build = root / "build"
            build.mkdir()
            config = root / "cargo-source-config.toml"
            config.write_text(
                "[net]\noffline = true\n",
                encoding="utf-8",
            )
            v8_archive = root / "librusty-v8.a.gz"
            v8_archive.write_bytes(b"pinned-v8-archive")
            v8_binding = root / "src-binding.rs"
            v8_binding.write_bytes(b"pinned-v8-binding")
            vendor_root = root / "cargo-vendor"
            vendor_root.mkdir()
            (vendor_root / "fixture").write_bytes(b"pinned-vendor")
            vendor_entries, vendor_inventory = (
                builder._vendor_member_inventory(vendor_root)
            )
            vendor_manifest = root / "cargo-vendor-members.json"
            vendor_manifest.write_bytes(
                builder._json_bytes(
                    {
                        "schema": (
                            "trillionnium.cargo-vendor-member-manifest.v1"
                        ),
                        "root_name": vendor_root.name,
                        "entry_count": len(vendor_entries),
                        "inventory_sha256": vendor_inventory,
                        "entries": vendor_entries,
                    }
                )
            )
            bootstrap_core = root / "bootstrap.o"
            bootstrap_entry = root / "entry.o"
            bootstrap_core.write_bytes(b"bootstrap")
            bootstrap_entry.write_bytes(b"entry")
            provider = {
                "source_subdirectory": "codex-rs",
                "cargo_target": "aarch64-unknown-linux-musl",
                "cargo_package": "codex-cli",
                "cargo_binary": "codex",
                "build_jobs": 2,
                "linker_threads": 1,
                "cargo_profile": {
                    "name": "release",
                    "debug": "none",
                    "incremental": False,
                    "lto": False,
                    "codegen_units": 4,
                    "strip": False,
                },
                "derived_lock": rule,
                "rusty_v8": {
                    "resolved_features": {
                        "codex-cli": [],
                        "codex-code-mode": [],
                        "codex-core": [],
                        "v8": ["default", "use_custom_libcxx"],
                    }
                },
                "cargo_vendor": {
                    "root_name": vendor_root.name,
                    "entry_count": len(vendor_entries),
                    "inventory_sha256": vendor_inventory,
                },
            }
            recipe = {
                "builder": {"rust_version": "1.95.0"},
                "providers": {"codex": provider},
            }
            codex_inputs = {
                "cargo_source_config": config,
                "rusty_v8_archive": v8_archive,
                "rusty_v8_binding": v8_binding,
                "derived_lock": codex_rs / "Cargo.lock",
                "source_inventory_sha256": builder._source_inventory_digest(
                    source
                ),
                "cargo_vendor_root": vendor_root,
                "cargo_vendor_member_manifest": vendor_manifest,
                "cargo_vendor_inventory_sha256": vendor_inventory,
            }
            calls: list[tuple[list[str], dict[str, str]]] = []

            def capture_run(
                arguments: list[str],
                *,
                environment: dict[str, str],
                **_: object,
            ) -> str:
                calls.append((list(arguments), dict(environment)))
                if "build" in arguments:
                    (build / "final.map").write_text(
                        "fixture-link-map\n", encoding="utf-8"
                    )
                    return ""
                return codex_metadata_fixture(
                    provider["rusty_v8"]["resolved_features"]
                )

            with mock.patch.object(builder, "_run", side_effect=capture_run):
                _elf, _map, command, build_environment = builder._codex_build(
                    recipe,
                    "amd64-cross",
                    source,
                    build,
                    {
                        "core": bootstrap_core,
                        "mechanism": bootstrap_entry,
                    },
                    {
                        "CARGO_HOME": "/output/.cargo-home",
                        "CARGO_TARGET_DIR": "/output/.work/target",
                        "PATH": "/opt/zig:/usr/local/bin:/usr/bin:/bin",
                    },
                    codex_inputs,
                )

            cargo_executable = (
                "/usr/local/rustup/toolchains/"
                "1.95.0-x86_64-unknown-linux-gnu/bin/cargo"
            )
            rustc_executable = (
                "/usr/local/rustup/toolchains/"
                "1.95.0-x86_64-unknown-linux-gnu/bin/rustc"
            )
            cargo_calls = [
                (arguments, environment)
                for arguments, environment in calls
                if arguments and arguments[0] == cargo_executable
            ]
            self.assertTrue(cargo_calls)
            for arguments, environment in cargo_calls:
                self.assertEqual(
                    arguments[:3],
                    [cargo_executable, "--config", str(config)],
                )
                self.assertIn("--frozen", arguments)
                self.assertNotIn("--locked", arguments)
                self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
                self.assertEqual(environment["RUSTUP_HOME"], "/usr/local/rustup")
                self.assertEqual(environment["RUSTUP_TOOLCHAIN"], "1.95.0")
                self.assertEqual(environment["RUSTC"], rustc_executable)
                self.assertNotIn("/usr/local/cargo/bin", environment["PATH"])
                self.assertEqual(
                    environment["AWS_LC_SYS_CMAKE_BUILDER"], "0"
                )
                self.assertEqual(
                    environment["CFLAGS_aarch64_unknown_linux_musl"],
                    "-pthread -Wno-error=frame-larger-than",
                )
                self.assertEqual(
                    environment["CXXFLAGS_aarch64_unknown_linux_musl"],
                    "-pthread -Wno-error=frame-larger-than",
                )
                self.assertEqual(
                    environment["RUSTY_V8_ARCHIVE"],
                    str(v8_archive),
                )
                self.assertEqual(
                    environment["RUSTY_V8_SRC_BINDING_PATH"],
                    str(v8_binding),
                )
                self.assertNotIn("RUSTY_V8_MIRROR", environment)
            wrapper_root = build / "target-toolchain"
            for role, (filename, content) in (
                builder.CODEX_TARGET_TOOLCHAIN_WRAPPERS.items()
            ):
                with self.subTest(wrapper=role):
                    wrapper = wrapper_root / filename
                    self.assertEqual(wrapper.read_bytes(), content)
                    self.assertTrue(wrapper.stat().st_mode & 0o111)
            linker_wrapper = builder.CODEX_TARGET_TOOLCHAIN_WRAPPERS["linker"][1]
            self.assertIn(b"-Wl,--print-map", linker_wrapper)
            self.assertIn(b'>"${map_path}"', linker_wrapper)
            self.assertIn(b"-nostdlib", linker_wrapper)
            self.assertIn(b"-Wl,--threads=1)", linker_wrapper)
            self.assertIn(
                b"target linker thread contract must appear exactly once",
                linker_wrapper,
            )
            self.assertIn(b"/usr/bin/taskset --cpu-list", linker_wrapper)
            self.assertIn(b'"${first_cpu}"', linker_wrapper)
            self.assertNotIn(
                b"-nostdlib",
                builder.CODEX_TARGET_TOOLCHAIN_WRAPPERS["cc"][1],
            )
            self.assertEqual(
                build_environment[
                    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"
                ],
                str(wrapper_root / "aarch64-linux-musl-cargo-linker"),
            )
            self.assertNotEqual(
                build_environment[
                    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"
                ],
                build_environment["CC_aarch64_unknown_linux_musl"],
            )
            self.assertIn("build", command)
            self.assertEqual(
                command[command.index("build") + 1 : command.index("--frozen")],
                ["--jobs", "2"],
            )
            self.assertEqual(build_environment["CARGO_NET_OFFLINE"], "true")
            self.assertEqual(
                build_environment["CARGO_PROFILE_RELEASE_LTO"], "false"
            )
            self.assertEqual(
                build_environment["CARGO_PROFILE_RELEASE_CODEGEN_UNITS"], "4"
            )
            self.assertEqual(
                build_environment["CARGO_PROFILE_RELEASE_INCREMENTAL"],
                "false",
            )
            self.assertEqual(
                build_environment["CARGO_PROFILE_RELEASE_STRIP"], "false"
            )
            self.assertIn(
                "link-arg=-Wl,--build-id=sha1",
                build_environment["CARGO_ENCODED_RUSTFLAGS"].split("\x1f"),
            )
            self.assertIn(
                "link-arg=-Wl,--threads=1",
                build_environment["CARGO_ENCODED_RUSTFLAGS"].split("\x1f"),
            )

    def test_codex_build_rejects_post_run_source_and_lock_drift(self) -> None:
        _upstream, derived, _patch, _names, rule = (
            synthetic_codex_lock_fixture()
        )
        for mutation in ("untracked source", "derived lock", "vendor tree"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory(
                    prefix="provider-codex-build-drift."
                ) as temporary,
            ):
                root = Path(temporary)
                source = root / "source"
                codex_rs = source / "codex-rs"
                codex_rs.mkdir(parents=True)
                lock = codex_rs / "Cargo.lock"
                lock.write_bytes(derived)
                build = root / "build"
                build.mkdir()
                config = root / "cargo-source-config.toml"
                config.write_text(
                    "[net]\noffline = true\n",
                    encoding="utf-8",
                )
                v8_archive = root / "rusty-v8.a.gz"
                v8_archive.write_bytes(b"v8 archive")
                v8_binding = root / "rusty-v8-binding.rs"
                v8_binding.write_bytes(b"v8 binding")
                vendor_root = root / "cargo-vendor"
                vendor_root.mkdir()
                (vendor_root / "fixture").write_bytes(b"vendor")
                vendor_entries, vendor_inventory = (
                    builder._vendor_member_inventory(vendor_root)
                )
                vendor_manifest = root / "cargo-vendor-members.json"
                vendor_manifest.write_bytes(
                    builder._json_bytes(
                        {
                            "schema": (
                                "trillionnium.cargo-vendor-member-manifest.v1"
                            ),
                            "root_name": vendor_root.name,
                            "entry_count": len(vendor_entries),
                            "inventory_sha256": vendor_inventory,
                            "entries": vendor_entries,
                        }
                    )
                )
                core = root / "bootstrap.o"
                core.write_bytes(b"bootstrap")
                entry = root / "entry.o"
                entry.write_bytes(b"entry")
                recipe = {
                    "builder": {"rust_version": "1.95.0"},
                    "providers": {
                        "codex": {
                            "source_subdirectory": "codex-rs",
                            "cargo_target": "aarch64-unknown-linux-musl",
                            "cargo_package": "codex-cli",
                            "cargo_binary": "codex",
                            "build_jobs": 2,
                            "linker_threads": 1,
                            "cargo_profile": {
                                "name": "release",
                                "debug": "none",
                                "incremental": False,
                                "lto": False,
                                "codegen_units": 4,
                                "strip": False,
                            },
                            "derived_lock": rule,
                            "rusty_v8": {
                                "resolved_features": {
                                    "codex-cli": [],
                                    "codex-code-mode": [],
                                    "codex-core": [],
                                    "v8": [
                                        "default",
                                        "use_custom_libcxx",
                                    ],
                                }
                            },
                            "cargo_vendor": {
                                "root_name": vendor_root.name,
                                "entry_count": len(vendor_entries),
                                "inventory_sha256": vendor_inventory,
                            },
                        }
                    },
                }
                codex_inputs = {
                    "cargo_source_config": config,
                    "rusty_v8_archive": v8_archive,
                    "rusty_v8_binding": v8_binding,
                    "derived_lock": lock,
                    "source_inventory_sha256": (
                        builder._source_inventory_digest(source)
                    ),
                    "cargo_vendor_root": vendor_root,
                    "cargo_vendor_member_manifest": vendor_manifest,
                    "cargo_vendor_inventory_sha256": vendor_inventory,
                }

                def mutate_after_cargo(
                    arguments: list[str],
                    **_: object,
                ) -> str:
                    if "build" not in arguments:
                        return codex_metadata_fixture(
                            recipe["providers"]["codex"]["rusty_v8"][
                                "resolved_features"
                            ]
                        )
                    (build / "final.map").write_text(
                        "fixture-link-map\n", encoding="utf-8"
                    )
                    if mutation == "untracked source":
                        (source / "attacker-untracked").write_bytes(b"drift")
                    elif mutation == "derived lock":
                        lock.write_bytes(derived + b"# drift\n")
                        codex_inputs["source_inventory_sha256"] = (
                            builder._source_inventory_digest(source)
                        )
                    else:
                        (vendor_root / "attacker-untracked").write_bytes(
                            b"drift"
                        )
                    return ""

                expected = (
                    "derived source changed"
                    if mutation == "untracked source"
                    else (
                        "derived Cargo.lock changed"
                        if mutation == "derived lock"
                        else "Cargo vendor (member inventory|tree changed)"
                    )
                )
                with (
                    mock.patch.object(
                        builder,
                        "_run",
                        side_effect=mutate_after_cargo,
                    ),
                    self.assertRaisesRegex(builder.BuildError, expected),
                ):
                    builder._codex_build(
                        recipe,
                        "amd64-cross",
                        source,
                        build,
                        {"core": core, "mechanism": entry},
                        {
                            "CARGO_HOME": "/output/.cargo-home",
                            "CARGO_TARGET_DIR": "/output/.work/target",
                            "PATH": "/opt/zig:/usr/local/bin:/usr/bin:/bin",
                        },
                        codex_inputs,
                    )

    def test_codex_metadata_feature_closure_rejects_v8_variant_drift(
        self,
    ) -> None:
        expected = {
            "codex-cli": [],
            "codex-code-mode": [],
            "codex-core": [],
            "v8": ["default", "use_custom_libcxx"],
        }
        provider = {"rusty_v8": {"resolved_features": expected}}
        builder._verify_codex_metadata_features(
            codex_metadata_fixture(expected),
            provider,
        )
        mutations = {
            "sandbox feature": {
                **expected,
                "codex-code-mode": ["sandbox"],
            },
            "pointer compression": {
                **expected,
                "v8": [
                    "default",
                    "use_custom_libcxx",
                    "v8_enable_pointer_compression",
                    "v8_enable_sandbox",
                ],
            },
            "missing custom libcxx": {
                **expected,
                "v8": ["default"],
            },
        }
        for label, observed in mutations.items():
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(
                    builder.BuildError,
                    "feature closure drifted",
                ),
            ):
                builder._verify_codex_metadata_features(
                    codex_metadata_fixture(observed),
                    provider,
                )

    def test_public_container_run_is_network_none_with_read_only_cache(
        self,
    ) -> None:
        container_build_source = inspect.getsource(builder._container_build)
        self.assertIn("_prepare_codex_source", container_build_source)
        self.assertNotIn("fetch", container_build_source)

        recipe = builder.load_recipe()
        snapshots = builder._snapshot_build_context()
        recipe_sha256 = hashlib.sha256(
            snapshots["provider-payload-recipe-v1.json"]
        ).hexdigest()
        builder_sha256 = hashlib.sha256(
            snapshots["build_provider_payload.py"]
        ).hexdigest()
        containerfile_sha256 = hashlib.sha256(
            snapshots["Containerfile"]
        ).hexdigest()
        captured: list[list[str]] = []
        container_id = "d" * 64

        def capture_run(arguments: list[str], **_: object) -> str:
            captured.append(list(arguments))
            if arguments[:2] == ["docker", "run"]:
                cidfile = Path(
                    arguments[arguments.index("--cidfile") + 1]
                )
                builder._write_bytes(
                    cidfile,
                    container_id.encode("ascii"),
                    mode=0o444,
                )
            return ""

        with tempfile.TemporaryDirectory(
            prefix="provider-network-none-test."
        ) as temporary:
            root = Path(temporary)
            output = root / "output"
            cache = root / "cache"
            cache.mkdir()
            with (
                mock.patch.object(builder, "load_recipe", return_value=recipe),
                mock.patch.object(builder, "_prefetch"),
                mock.patch.object(
                    builder,
                    "_build_container_image",
                    return_value=(
                        builder._container_image_tag(
                            recipe_sha256,
                            builder_sha256,
                            containerfile_sha256,
                            "amd64-cross",
                        ),
                        f"sha256:{'b' * 64}",
                        builder_sha256,
                        containerfile_sha256,
                        builder._build_context_receipt(snapshots),
                    ),
                ),
                mock.patch.object(builder, "_run", side_effect=capture_run),
                mock.patch.object(
                    builder,
                    "_verify_pending_container_output",
                    return_value={"container": {"id": container_id}},
                ),
                mock.patch.object(
                    builder,
                    "_rewrite_builder_container_projection",
                ),
                mock.patch.object(builder, "_verify_builder_output"),
                mock.patch.object(builder, "_verify_builder_output_fd"),
            ):
                builder._public_build(
                    "codex",
                    "amd64-cross",
                    output,
                    cache,
                    "docker",
                )
        runs = [
            arguments
            for arguments in captured
            if len(arguments) >= 2 and arguments[:2] == ["docker", "run"]
        ]
        self.assertEqual(len(runs), 1)
        arguments = runs[0]
        self.assertEqual(
            arguments[2 : 2 + len(builder._provider_container_isolation_arguments())],
            builder._provider_container_isolation_arguments(),
        )
        network_index = arguments.index("--network")
        self.assertEqual(arguments[network_index + 1], "none")
        ulimit_index = arguments.index("--ulimit")
        self.assertEqual(
            arguments[ulimit_index + 1],
            f"nofile={builder.CONTAINER_NOFILE_ULIMIT}",
        )
        self.assertIn(
            f"type=bind,src={cache.resolve()},dst=/cache,readonly",
            arguments,
        )
        self.assertIn(
            (
                f"type=bind,src={cache.resolve() / 'cargo-vendor'},"
                "dst=/opt/trillionnium/cargo-vendor,readonly"
            ),
            arguments,
        )
        immutable_image_id = f"sha256:{'b' * 64}"
        mutable_tag = builder._container_image_tag(
            recipe_sha256,
            builder_sha256,
            containerfile_sha256,
            "amd64-cross",
        )
        provider_index = arguments.index("--provider")
        self.assertEqual(arguments[provider_index - 1], immutable_image_id)
        self.assertNotIn(mutable_tag, arguments)
        self.assertEqual(arguments.count("--name"), 1)
        self.assertEqual(arguments.count("--cidfile"), 1)
        expected_attempt = builder._build_attempt_identity(
            builder._container_input_identity(
                recipe_sha256,
                builder_sha256,
                containerfile_sha256,
            ),
            "codex",
            "amd64-cross",
            str(output.resolve()),
            str(cache.resolve()),
        )
        expected_name = builder._container_name(expected_attempt)
        expected_cidfile = (
            builder._container_cidfile_custody_path(
                output.resolve(),
                expected_attempt,
            )
            / builder.CONTAINER_CIDFILE_NAME
        )
        self.assertEqual(
            arguments[arguments.index("--name") + 1],
            expected_name,
        )
        self.assertEqual(
            arguments[arguments.index("--cidfile") + 1],
            str(expected_cidfile),
        )
        self.assertIn(
            (
                "type=bind,"
                f"src={expected_cidfile.parent},"
                f"dst={builder.CONTAINER_CIDFILE_MOUNT},readonly"
            ),
            arguments,
        )
        build_context = builder._build_context_receipt(snapshots)
        self.assertEqual(
            builder._one_command_option_value(
                arguments,
                "--build-context-tar-sha256",
                "test provider container command",
            ),
            build_context["tar_sha256"],
        )
        self.assertEqual(
            builder._one_command_option_value(
                arguments,
                "--build-context-tar-byte-length",
                "test provider container command",
            ),
            str(build_context["tar_byte_length"]),
        )
        self.assertEqual(
            builder._one_command_option_value(
                arguments,
                "--build-context-member-manifest-sha256",
                "test provider container command",
            ),
            build_context["member_manifest_sha256"],
        )
        builder._validate_provider_container_command(
            arguments,
            "test provider container command",
        )
        environment_bindings = [
            arguments[index + 1]
            for index, argument in enumerate(arguments[:-1])
            if argument == "--env"
        ]
        self.assertEqual(
            environment_bindings,
            builder._provider_container_environment_bindings(),
        )
        for mutation in (
            "proxy_value",
            "proxy_missing",
            "network_duplicate",
            "read_only_missing",
            "capability_add",
            "memory_drift",
        ):
            with self.subTest(mutation=mutation):
                tampered = list(arguments)
                proxy_index = tampered.index("HTTP_PROXY=")
                if mutation == "proxy_value":
                    tampered[proxy_index] = "HTTP_PROXY=http://untrusted.invalid"
                elif mutation == "proxy_missing":
                    del tampered[proxy_index - 1 : proxy_index + 1]
                elif mutation == "network_duplicate":
                    tampered.extend(["--network", "host"])
                elif mutation == "read_only_missing":
                    tampered.remove("--read-only")
                elif mutation == "capability_add":
                    tampered.extend(["--cap-add", "SYS_ADMIN"])
                else:
                    tampered[tampered.index(builder.CONTAINER_MEMORY_LIMIT)] = "0"
                with self.assertRaises(builder.BuildError):
                    builder._validate_provider_container_command(
                        tampered,
                        "tampered provider container command",
                    )

    def test_builder_image_build_uses_frozen_default_network(self) -> None:
        recipe = builder.load_recipe()
        snapshots = builder._snapshot_build_context()
        captured: list[list[str]] = []
        captured_contexts: list[bytes] = []

        def capture_run(arguments: list[str], **kwargs: object) -> str:
            captured.append(list(arguments))
            if arguments[1:3] == ["image", "inspect"]:
                return f"sha256:{'c' * 64}\n"
            descriptor = kwargs.get("stdin_descriptor")
            self.assertIsInstance(descriptor, int)
            metadata = os.fstat(descriptor)
            captured_contexts.append(
                os.pread(descriptor, metadata.st_size, 0)
            )
            return f"sha256:{'c' * 64}\n"

        with tempfile.TemporaryDirectory(
            prefix="provider-image-network-test."
        ) as temporary:
            recipe_sha256 = hashlib.sha256(
                snapshots["provider-payload-recipe-v1.json"]
            ).hexdigest()
            builder_sha256 = hashlib.sha256(
                snapshots["build_provider_payload.py"]
            ).hexdigest()
            containerfile_sha256 = hashlib.sha256(
                snapshots["Containerfile"]
            ).hexdigest()
            with (
                mock.patch.object(builder, "_verify_remote_base_manifest"),
                mock.patch.object(builder, "_run", side_effect=capture_run),
            ):
                (
                    _tag,
                    image_id,
                    observed_builder,
                    observed_containerfile,
                    build_context,
                ) = (
                    builder._build_container_image(
                        "docker",
                        "amd64-cross",
                        recipe,
                        recipe_sha256,
                        snapshots,
                        builder_sha256,
                        containerfile_sha256,
                    )
                )
        builds = [
            arguments
            for arguments in captured
            if arguments[:2] == ["docker", "build"]
        ]
        self.assertEqual(len(builds), 1)
        arguments = builds[0]
        self.assertEqual(arguments.count("--network"), 1)
        network_index = arguments.index("--network")
        self.assertEqual(arguments[network_index + 1], "default")
        self.assertNotIn("host", arguments)
        self.assertEqual(arguments[-1], "-")
        self.assertNotIn("--file", arguments)
        self.assertEqual(
            captured_contexts,
            [builder._deterministic_build_context_tar(snapshots)],
        )
        with tarfile.open(fileobj=io.BytesIO(captured_contexts[0])) as archive:
            self.assertEqual(
                archive.extractfile("Dockerfile").read(),
                snapshots["Containerfile"],
            )
        self.assertEqual(image_id, f"sha256:{'c' * 64}")
        self.assertEqual(observed_builder, builder_sha256)
        self.assertEqual(observed_containerfile, containerfile_sha256)
        self.assertEqual(
            build_context,
            builder._build_context_receipt(snapshots),
        )

    def test_public_build_persists_atomic_failure_receipts(self) -> None:
        recipe = builder.load_recipe()
        for failed_phase in ("prefetch", "container"):
            with (
                self.subTest(failed_phase=failed_phase),
                tempfile.TemporaryDirectory(
                    prefix="provider-failure-receipt-test."
                ) as temporary,
            ):
                root = Path(temporary)
                output = root / "output"
                cache = root / "cache"
                cache.mkdir()
                builder_sha256 = builder._sha256_file(
                    Path(builder.__file__).resolve()
                )
                recipe_sha256 = builder._sha256_file(builder.RECIPE_PATH)
                containerfile_sha256 = builder._sha256_file(
                    builder.CONTAINERFILE_PATH
                )
                image_tag = builder._container_image_tag(
                    recipe_sha256,
                    builder_sha256,
                    containerfile_sha256,
                    "amd64-cross",
                )
                image_result = (
                    image_tag,
                    f"sha256:{'b' * 64}",
                    builder_sha256,
                    containerfile_sha256,
                    builder._build_context_receipt(
                        builder._snapshot_build_context()
                    ),
                )

                def prefetch(*_: object, **__: object) -> None:
                    if failed_phase == "prefetch":
                        raise builder.BuildError("injected prefetch failure")

                def run(arguments: list[str], **_: object) -> str:
                    raise builder.CommandFailure(
                        arguments,
                        77,
                        "injected container failure\n",
                        False,
                    )

                with (
                    mock.patch.object(
                        builder, "load_recipe", return_value=recipe
                    ),
                    mock.patch.object(
                        builder, "_prefetch", side_effect=prefetch
                    ),
                    mock.patch.object(
                        builder,
                        "_build_container_image",
                        return_value=image_result,
                    ),
                    mock.patch.object(builder, "_run", side_effect=run),
                    self.assertRaises(builder.BuildError),
                ):
                    builder._public_build(
                        "codex",
                        "amd64-cross",
                        output,
                        cache,
                        "docker",
                    )

                failure = output.with_name("output.failure")
                self.assertFalse(output.exists())
                self.assertTrue(failure.is_dir())
                receipt = builder._verify_failure_output(failure)
                self.assertEqual(receipt["failed_phase"], failed_phase)
                expected_completed = (
                    []
                    if failed_phase == "prefetch"
                    else ["prefetch", "image", "stage"]
                )
                self.assertEqual(
                    receipt["completed_phases"], expected_completed
                )
                self.assertFalse(receipt["success_output_published"])
                if failed_phase == "container":
                    self.assertEqual(receipt["cause"]["return_code"], 77)
                    self.assertEqual(
                        receipt["container"]["network"], "none"
                    )
                    self.assertIsNone(receipt["container"]["id"])
                    self.assertIs(receipt["container"]["run_invoked"], True)
                    self.assertIs(
                        receipt["container"]["completed_zero"],
                        False,
                    )
                    self.assertEqual(
                        receipt["container"]["cidfile"]["state"],
                        "absent_after_failed_run",
                    )
                    self.assertFalse(
                        Path(
                            receipt["container"]["cidfile"]["host_path"]
                        ).exists()
                    )
                    self.assertEqual(
                        receipt["container"]["name"],
                        builder._container_name(
                            receipt["attempt_id_sha256"]
                        ),
                    )
                    self.assertIs(
                        receipt["container"][
                            "client_disconnect_does_not_imply_container_stop"
                        ],
                        True,
                    )
                    self.assertEqual(
                        receipt["container"]["cidfile"][
                            "cleanup_tombstone"
                        ]["role"],
                        "container_cidfile_custody",
                    )
                    self.assertEqual(
                        receipt["image"]["build_context"],
                        receipt["container"]["build_context"],
                    )
                    tampered = json.loads(json.dumps(receipt))
                    tampered["cause"]["command"] = [
                        "docker",
                        "version",
                    ]
                    tampered["receipt_sha256"] = (
                        builder._failure_receipt_hash(tampered)
                    )
                    receipt_path = (
                        failure / "provider-build-failure-receipt.json"
                    )
                    receipt_path.chmod(0o600)
                    receipt_path.write_bytes(builder._json_bytes(tampered))
                    receipt_path.chmod(0o400)
                    with self.assertRaisesRegex(
                        builder.BuildError,
                        "cause command differs",
                    ):
                        builder._verify_failure_output(failure)

    def test_public_build_failure_receipt_covers_every_phase_prefix(self) -> None:
        recipe = builder.load_recipe()
        phases = {
            "prefetch": [],
            "image": ["prefetch"],
            "image_identity": ["prefetch"],
            "stage": ["prefetch", "image"],
            "container": ["prefetch", "image", "stage"],
            "verify": ["prefetch", "image", "stage", "container"],
            "cleanup": [
                "prefetch",
                "image",
                "stage",
                "container",
                "verify",
            ],
            "publish": [
                "prefetch",
                "image",
                "stage",
                "container",
                "verify",
                "cleanup",
            ],
        }
        original_publish = builder._publish_directory_noreplace
        original_create_stage = builder._create_owned_stage
        original_rmtree = shutil.rmtree
        for injected_phase, expected_completed in phases.items():
            with (
                self.subTest(injected_phase=injected_phase),
                tempfile.TemporaryDirectory(
                    prefix="provider-failure-phase-test."
                ) as temporary,
            ):
                root = Path(temporary)
                output = root / "output"
                cache = root / "cache"
                cache.mkdir()
                recipe_sha256 = builder._sha256_file(builder.RECIPE_PATH)
                builder_sha256 = builder._sha256_file(
                    Path(builder.__file__).resolve()
                )
                containerfile_sha256 = builder._sha256_file(
                    builder.CONTAINERFILE_PATH
                )
                image_tag = builder._container_image_tag(
                    recipe_sha256,
                    builder_sha256,
                    containerfile_sha256,
                    "amd64-cross",
                )
                create_count = 0

                def create_stage(
                    parent: Path,
                    prefix: str,
                ) -> tuple[Path, tuple[int, int]]:
                    nonlocal create_count
                    create_count += 1
                    if injected_phase == "stage" and create_count == 1:
                        raise builder.BuildError("injected stage creation failure")
                    return original_create_stage(parent, prefix)

                def prefetch(*_: object, **__: object) -> None:
                    if injected_phase == "prefetch":
                        raise builder.BuildError("injected prefetch failure")

                def image(
                    *_: object,
                    **__: object,
                ) -> tuple[str, str, str, str, dict[str, object]]:
                    if injected_phase == "image":
                        raise builder.BuildError("injected image failure")
                    observed_builder = (
                        "f" * 64
                        if injected_phase == "image_identity"
                        else builder_sha256
                    )
                    return (
                        image_tag,
                        f"sha256:{'b' * 64}",
                        observed_builder,
                        containerfile_sha256,
                        builder._build_context_receipt(
                            builder._snapshot_build_context()
                        ),
                    )

                def run(arguments: list[str], **_: object) -> str:
                    if injected_phase == "container":
                        raise builder.CommandFailure(
                            arguments,
                            77,
                            "injected container failure\n",
                            False,
                        )
                    output_mount = next(
                        value
                        for value in arguments
                        if value.startswith("type=bind,src=")
                        and value.endswith(",dst=/output")
                    )
                    stage = Path(
                        output_mount.removeprefix("type=bind,src=").removesuffix(
                            ",dst=/output"
                        )
                    )
                    (stage / ".work").mkdir()
                    cidfile = Path(
                        arguments[arguments.index("--cidfile") + 1]
                    )
                    builder._write_bytes(
                        cidfile,
                        b"d" * 64,
                        mode=0o444,
                    )
                    return ""

                def verify(_: Path) -> None:
                    if injected_phase == "verify":
                        raise builder.BuildError("injected verify failure")

                def remove(path: object, *args: object, **kwargs: object) -> None:
                    candidate = Path(path)
                    if injected_phase == "cleanup" and candidate.name == ".work":
                        raise OSError(errno.EIO, "injected cleanup failure")
                    original_rmtree(candidate, *args, **kwargs)

                def publish(
                    stage: Path,
                    destination: Path,
                    expected_identity: tuple[int, int],
                    verifier: object | None = None,
                ) -> None:
                    if injected_phase == "publish" and destination == output:
                        raise builder.BuildError("injected publish failure")
                    original_publish(
                        stage,
                        destination,
                        expected_identity,
                        verifier,
                    )

                with (
                    mock.patch.object(builder, "load_recipe", return_value=recipe),
                    mock.patch.object(builder, "_prefetch", side_effect=prefetch),
                    mock.patch.object(
                        builder,
                        "_build_container_image",
                        side_effect=image,
                    ),
                    mock.patch.object(
                        builder,
                        "_create_owned_stage",
                        side_effect=create_stage,
                    ),
                    mock.patch.object(builder, "_run", side_effect=run),
                    mock.patch.object(
                        builder,
                        "_verify_pending_container_output",
                        return_value={"container": {"id": "d" * 64}},
                    ),
                    mock.patch.object(
                        builder,
                        "_rewrite_builder_container_projection",
                    ),
                    mock.patch.object(
                        builder,
                        "_verify_builder_output",
                        side_effect=verify,
                    ),
                    mock.patch.object(
                        builder,
                        "_publish_directory_noreplace",
                        side_effect=publish,
                    ),
                    mock.patch.object(shutil, "rmtree", side_effect=remove),
                    self.assertRaises(Exception),
                ):
                    builder._public_build(
                        "codex",
                        "amd64-cross",
                        output,
                        cache,
                        "docker",
                    )

                failure = output.with_name("output.failure")
                self.assertFalse(output.exists())
                receipt = builder._verify_failure_output(failure)
                expected_phase = (
                    "image"
                    if injected_phase == "image_identity"
                    else injected_phase
                )
                self.assertEqual(receipt["failed_phase"], expected_phase)
                self.assertEqual(
                    receipt["completed_phases"],
                    expected_completed,
                )
                self.assertFalse(receipt["success_output_published"])
                self.assertFalse(
                    receipt["success_output_parent_fsync_completed"]
                )
                if injected_phase in {"image", "image_identity"}:
                    self.assertIsNone(receipt["image"]["image_id"])
                if injected_phase == "container":
                    self.assertEqual(receipt["cause"]["return_code"], 77)

    def test_failure_receipt_rejects_alias_mode_and_tree_tampering(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-failure-tamper-test."
        ) as temporary:
            root = Path(temporary)
            output = root / "output"
            cache = root / "cache"
            cache.mkdir()
            recipe_sha256 = builder._sha256_file(builder.RECIPE_PATH)
            builder_sha256 = builder._sha256_file(
                Path(builder.__file__).resolve()
            )
            containerfile_sha256 = builder._sha256_file(
                builder.CONTAINERFILE_PATH
            )
            failure = builder._persist_build_failure(
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
                input_snapshots=builder._snapshot_build_context(),
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
                error=builder.BuildError("injected failure"),
            )
            builder._verify_failure_output(failure)

            failure.chmod(0o777)
            with self.assertRaisesRegex(builder.BuildError, "root mode"):
                builder._verify_failure_output(failure)
            failure.chmod(0o500)

            inputs = failure / "inputs"
            inputs.chmod(0o777)
            with self.assertRaisesRegex(builder.BuildError, "mode, type, or links"):
                builder._verify_failure_output(failure)
            inputs.chmod(0o500)

            failure.chmod(0o700)
            extra = failure / "unexpected"
            extra.write_bytes(b"unexpected")
            extra.chmod(0o400)
            failure.chmod(0o500)
            with self.assertRaisesRegex(builder.BuildError, "missing or extra"):
                builder._verify_failure_output(failure)
            failure.chmod(0o700)
            extra.unlink()
            failure.chmod(0o500)

            actual = root / "actual-failure"
            failure.rename(actual)
            failure.symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(builder.BuildError, "aliased"):
                builder._verify_failure_output(failure)
            failure.unlink()
            actual.rename(failure)

    def test_owned_stage_refuses_replaced_name_and_combined_cause_is_retained(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-owned-stage-test."
        ) as temporary:
            root = Path(temporary)
            stage, identity = builder._create_owned_stage(root, ".stage.")
            published = root / "published"
            stage.rename(published)
            stage.mkdir()
            stage.chmod(0o555)
            with self.assertRaisesRegex(builder.BuildError, "no longer identifies"):
                builder._cleanup_owned_stage(stage, identity)
            self.assertTrue(stage.is_dir())
            self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o555)
            stage.rmdir()
            shutil.rmtree(published)

            output = root / "output"
            cache = root / "cache"
            cache.mkdir()
            recipe_sha256 = builder._sha256_file(builder.RECIPE_PATH)
            builder_sha256 = builder._sha256_file(
                Path(builder.__file__).resolve()
            )
            containerfile_sha256 = builder._sha256_file(
                builder.CONTAINERFILE_PATH
            )
            primary = builder.CommandFailure(
                ["false"],
                77,
                "primary command failure\n",
                False,
            )
            combined = builder.CombinedBuildFailure(
                primary,
                OSError(errno.EIO, "secondary cleanup failure"),
            )
            failure = builder._persist_build_failure(
                provider_name="codex",
                profile="amd64-cross",
                output=output,
                cache=cache,
                engine="docker",
                failed_phase="image",
                completed_phases=["prefetch"],
                recipe_sha256=recipe_sha256,
                builder_sha256=builder_sha256,
                containerfile_sha256=containerfile_sha256,
                input_snapshots=builder._snapshot_build_context(),
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
                error=combined,
            )
            receipt = builder._verify_failure_output(failure)
            self.assertEqual(receipt["cause"]["exception_type"], "CommandFailure")
            self.assertEqual(
                receipt["cause"]["secondary_exception_type"],
                "OSError",
            )
            self.assertEqual(receipt["cause"]["return_code"], 77)
            self.assertEqual(receipt["cause"]["command"], ["false"])

    def test_failure_diagnostic_has_strict_cap_and_nested_truncation(self) -> None:
        maximum = builder.MAX_FAILURE_DIAGNOSTIC_BYTES
        exact_with_newline, exact_with_newline_truncated = (
            builder._bounded_failure_diagnostic(
                builder.BuildError("x" * (maximum - 1) + "\n")
            )
        )
        self.assertEqual(len(exact_with_newline), maximum)
        self.assertFalse(exact_with_newline_truncated)

        exact_without_newline, exact_without_newline_truncated = (
            builder._bounded_failure_diagnostic(
                builder.BuildError("x" * maximum)
            )
        )
        self.assertEqual(len(exact_without_newline), maximum)
        self.assertTrue(exact_without_newline_truncated)
        self.assertTrue(exact_without_newline.endswith(b"\n"))

        oversized, oversized_truncated = builder._bounded_failure_diagnostic(
            builder.BuildError("x" * (maximum + 4096))
        )
        self.assertEqual(len(oversized), maximum)
        self.assertTrue(oversized_truncated)
        self.assertTrue(oversized.endswith(b"\n"))

        command = builder.CommandFailure(
            ["false"],
            77,
            "already bounded command tail\n",
            True,
        )
        combined = builder.CombinedBuildFailure(
            command,
            OSError(errno.EIO, "cleanup failed"),
        )
        diagnostic, combined_truncated = builder._bounded_failure_diagnostic(
            combined
        )
        self.assertLessEqual(len(diagnostic), maximum)
        self.assertTrue(combined_truncated)

        deeply_nested = builder.CombinedBuildFailure(
            builder.BuildError("primary"),
            builder.CombinedBuildFailure(
                OSError(errno.EIO, "secondary one"),
                builder.CommandFailure(
                    ["false"],
                    78,
                    "deeply nested truncated tail\n",
                    True,
                ),
            ),
        )
        nested_diagnostic, nested_truncated = (
            builder._bounded_failure_diagnostic(deeply_nested)
        )
        self.assertLessEqual(len(nested_diagnostic), maximum)
        self.assertTrue(nested_truncated)

        utf8_diagnostic, utf8_truncated = builder._bounded_failure_diagnostic(
            builder.BuildError("汉" * maximum)
        )
        self.assertLessEqual(len(utf8_diagnostic), maximum)
        self.assertTrue(utf8_truncated)
        self.assertTrue(utf8_diagnostic.endswith(b"\n"))
        utf8_diagnostic.decode("utf-8", errors="strict")

    def test_evidence_publication_conflict_is_machine_readable_combined(
        self,
    ) -> None:
        recipe = builder.load_recipe()
        with tempfile.TemporaryDirectory(
            prefix="provider-evidence-conflict-test."
        ) as temporary:
            root = Path(temporary)
            output = root / "output"
            failure = root / "output.failure"
            cache = root / "cache"
            cache.mkdir()
            sentinel = b"pre-existing evidence sentinel\n"

            def prefetch(*_: object, **__: object) -> None:
                failure.mkdir()
                (failure / "sentinel").write_bytes(sentinel)
                raise builder.BuildError("injected primary build failure")

            with (
                mock.patch.object(builder, "load_recipe", return_value=recipe),
                mock.patch.object(builder, "_prefetch", side_effect=prefetch),
                self.assertRaises(builder.CombinedBuildFailure) as captured,
            ):
                builder._public_build(
                    "codex",
                    "amd64-cross",
                    output,
                    cache,
                    "docker",
                )
            self.assertIsInstance(
                captured.exception.primary_error,
                builder.BuildError,
            )
            self.assertIsInstance(
                captured.exception.secondary_error,
                builder.BuildError,
            )
            self.assertIn(
                "injected primary build failure",
                str(captured.exception.primary_error),
            )
            self.assertIn(
                "failure evidence already exists",
                str(captured.exception.secondary_error),
            )
            self.assertEqual((failure / "sentinel").read_bytes(), sentinel)

    def test_evidence_rename_conflict_preserves_secondary_context(
        self,
    ) -> None:
        recipe = builder.load_recipe()
        with tempfile.TemporaryDirectory(
            prefix="provider-evidence-rename-conflict-test."
        ) as temporary:
            root = Path(temporary)
            output = root / "output"
            failure = root / "output.failure"
            cache = root / "cache"
            cache.mkdir()
            sentinel = b"rename-time sentinel\n"
            sentinel_identity: tuple[int, int] | None = None

            def prefetch(*_: object, **__: object) -> None:
                raise builder.BuildError("injected primary build failure")

            def conflict(
                _: int,
                __: str,
                destination_name: str,
            ) -> None:
                nonlocal sentinel_identity
                self.assertEqual(destination_name, failure.name)
                failure.mkdir()
                sentinel_path = failure / "sentinel"
                sentinel_path.write_bytes(sentinel)
                metadata = sentinel_path.stat()
                sentinel_identity = (metadata.st_dev, metadata.st_ino)
                raise builder.BuildError(
                    "atomic no-replace publication failed: File exists"
                )

            with (
                mock.patch.object(builder, "load_recipe", return_value=recipe),
                mock.patch.object(builder, "_prefetch", side_effect=prefetch),
                mock.patch.object(
                    builder,
                    "_renameat2_noreplace",
                    side_effect=conflict,
                ),
                self.assertRaises(builder.CombinedBuildFailure) as captured,
            ):
                builder._public_build(
                    "codex",
                    "amd64-cross",
                    output,
                    cache,
                    "docker",
                )
            self.assertIn(
                "injected primary build failure",
                str(captured.exception.primary_error),
            )
            secondary = captured.exception.secondary_error
            self.assertIsInstance(
                secondary,
                builder.ContextualBuildFailure,
            )
            self.assertIn(
                "atomic no-replace publication failed",
                str(secondary.primary_error),
            )
            self.assertEqual(len(secondary.cleanup_tombstones), 1)
            tombstone = secondary.cleanup_tombstones[0]
            self.assertEqual(tombstone["role"], "failure_evidence_stage")
            tombstone_path = Path(tombstone["requested_path"])
            self.assertTrue(tombstone_path.is_dir())
            self.assertEqual(list(tombstone_path.iterdir()), [])
            self.assertEqual(
                stat.S_IMODE(tombstone_path.stat().st_mode),
                0o500,
            )
            sentinel_path = failure / "sentinel"
            metadata = sentinel_path.stat()
            self.assertEqual(
                (metadata.st_dev, metadata.st_ino),
                sentinel_identity,
            )
            self.assertEqual(sentinel_path.read_bytes(), sentinel)

    def test_cleanup_retains_explicit_empty_tombstone_receipt(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-cleanup-tombstone-test."
        ) as temporary:
            root = Path(temporary)
            stage, identity = builder._create_owned_stage(root, ".stage.")
            nested = stage / "nested"
            nested.mkdir()
            (nested / "artifact").write_bytes(b"candidate bytes")
            (nested / "artifact-link").symlink_to("artifact")
            os.link(nested / "artifact", nested / "artifact-hardlink")
            tombstone = builder._cleanup_tombstone_with_role(
                builder._cleanup_owned_stage(stage, identity),
                "provider_output_stage",
            )
            self.assertTrue(stage.is_dir())
            self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o500)
            self.assertEqual(list(stage.iterdir()), [])
            self.assertEqual(
                tombstone["state"],
                "empty_cleanup_tombstone_retained",
            )
            self.assertFalse(
                tombstone[
                    "same_uid_concurrent_child_name_replacement_proven"
                ]
            )
            self.assertFalse(
                tombstone[
                    "same_uid_concurrent_retained_stage_path_replacement_proven"
                ]
            )

            output = root / "output"
            cache = root / "cache"
            cache.mkdir()
            snapshots = builder._snapshot_build_context()
            recipe_sha256 = hashlib.sha256(
                snapshots["provider-payload-recipe-v1.json"]
            ).hexdigest()
            builder_sha256 = hashlib.sha256(
                snapshots["build_provider_payload.py"]
            ).hexdigest()
            containerfile_sha256 = hashlib.sha256(
                snapshots["Containerfile"]
            ).hexdigest()
            failure = builder._persist_build_failure(
                provider_name="codex",
                profile="amd64-cross",
                output=output,
                cache=cache,
                engine="docker",
                failed_phase="container",
                completed_phases=["prefetch", "image", "stage"],
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
                image_id=f"sha256:{'b' * 64}",
                container_command=None,
                success_output_published=False,
                success_output_parent_fsync_completed=False,
                publication_destination_installed=False,
                publication_destination_identity_preserved=False,
                error=builder.BuildError("injected container failure"),
                candidate_stage=(
                    builder._candidate_stage_from_cleanup_tombstone(
                        tombstone
                    )
                ),
                cleanup_tombstones=[tombstone],
            )
            receipt = builder._verify_failure_output(failure)
            self.assertTrue(receipt["candidate_stage_retained"])
            self.assertEqual(
                receipt["candidate_stage"]["state"],
                "empty_cleanup_tombstone_retained",
            )
            self.assertEqual(receipt["cleanup_tombstones"], [tombstone])

    def test_fd_scandir_context_closes_every_explicit_duplicate(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-fd-scandir-test."
        ) as temporary:
            root = Path(temporary)
            for index in range(64):
                (root / f"entry-{index:03d}").mkdir()
            descriptor = os.open(
                root,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
            )
            try:
                baseline = len(os.listdir("/proc/self/fd"))
                for _ in range(128):
                    with builder._scandir_fd(descriptor) as iterator:
                        names = sorted(entry.name for entry in iterator)
                    self.assertEqual(len(names), 64)
                self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)
                os.fstat(descriptor)
            finally:
                os.close(descriptor)

    def test_cleanup_and_retained_verifier_reject_name_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-cleanup-race-test."
        ) as temporary:
            root = Path(temporary)
            stage, identity = builder._create_owned_stage(root, ".stage.")
            (stage / "artifact").write_bytes(b"owned")
            held = root / "held-owned"
            original_remove_contents = builder._remove_directory_contents_fd

            def replace_before_final_stat(descriptor: int) -> None:
                original_remove_contents(descriptor)
                stage.rename(held)
                stage.mkdir()
                (stage / "replacement").write_bytes(b"replacement")

            with (
                mock.patch.object(
                    builder,
                    "_remove_directory_contents_fd",
                    side_effect=replace_before_final_stat,
                ),
                self.assertRaisesRegex(builder.BuildError, "name changed"),
            ):
                builder._cleanup_owned_stage(stage, identity)
            self.assertTrue(held.is_dir())
            self.assertEqual(list(held.iterdir()), [])
            self.assertEqual(
                (stage / "replacement").read_bytes(),
                b"replacement",
            )
            shutil.rmtree(stage)
            held.chmod(0o700)
            held.rmdir()

            candidate, candidate_identity = builder._create_owned_stage(
                root,
                ".candidate.",
            )
            (candidate / "artifact").write_bytes(b"candidate")
            primary = builder.CommandFailure(
                ["false"],
                77,
                "primary failure\n",
                False,
            )
            combined = builder.CombinedBuildFailure(
                primary,
                OSError(errno.EIO, "cleanup failed"),
                candidate_stage=builder._candidate_stage_state(
                    candidate,
                    candidate_identity,
                    "provider_output_stage",
                ),
            )
            output = root / "output"
            cache = root / "cache"
            cache.mkdir()
            snapshots = builder._snapshot_build_context()
            recipe_sha256 = hashlib.sha256(
                snapshots["provider-payload-recipe-v1.json"]
            ).hexdigest()
            builder_sha256 = hashlib.sha256(
                snapshots["build_provider_payload.py"]
            ).hexdigest()
            containerfile_sha256 = hashlib.sha256(
                snapshots["Containerfile"]
            ).hexdigest()
            failure = builder._persist_build_failure(
                provider_name="codex",
                profile="amd64-cross",
                output=output,
                cache=cache,
                engine="docker",
                failed_phase="image",
                completed_phases=["prefetch"],
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
                error=combined,
            )
            held_candidate = root / "held-candidate"
            original_inventory = builder._failure_tree_inventory_fd
            swapped = False

            def swap_after_pin(
                descriptor: int,
                prefix: str = "",
            ) -> dict[str, tuple[str, int, int, tuple[int, ...]]]:
                nonlocal swapped
                result = original_inventory(descriptor, prefix)
                if not swapped and not prefix:
                    candidate.rename(held_candidate)
                    candidate.mkdir()
                    swapped = True
                return result

            with (
                mock.patch.object(
                    builder,
                    "_failure_tree_inventory_fd",
                    side_effect=swap_after_pin,
                ),
                self.assertRaisesRegex(
                    builder.BuildError,
                    "path identity changed",
                ),
            ):
                builder._verify_failure_output(failure)
            self.assertTrue(held_candidate.is_dir())
            self.assertTrue(candidate.is_dir())

            candidate.rmdir()
            held_candidate.rename(candidate)
            aba_observed = False

            def aba_swap_after_pin(
                descriptor: int,
                prefix: str = "",
            ) -> dict[str, tuple[str, int, int, tuple[int, ...]]]:
                nonlocal aba_observed
                result = original_inventory(descriptor, prefix)
                if not aba_observed and not prefix:
                    candidate.rename(held_candidate)
                    candidate.mkdir()
                    candidate.rmdir()
                    held_candidate.rename(candidate)
                    aba_observed = True
                return result

            with mock.patch.object(
                builder,
                "_failure_tree_inventory_fd",
                side_effect=aba_swap_after_pin,
            ):
                aba_receipt = builder._verify_failure_output(failure)
            self.assertTrue(aba_observed)
            self.assertFalse(
                aba_receipt["candidate_stage"][
                    "same_uid_concurrent_retained_stage_path_replacement_proven"
                ]
            )

    def test_publish_after_rename_failure_is_recorded_without_false_absence(
        self,
    ) -> None:
        recipe = builder.load_recipe()
        original_publish = builder._publish_directory_noreplace
        with tempfile.TemporaryDirectory(
            prefix="provider-publish-installed-test."
        ) as temporary:
            root = Path(temporary)
            output = root / "output"
            cache = root / "cache"
            cache.mkdir()
            recipe_sha256 = builder._sha256_file(builder.RECIPE_PATH)
            builder_sha256 = builder._sha256_file(
                Path(builder.__file__).resolve()
            )
            containerfile_sha256 = builder._sha256_file(
                builder.CONTAINERFILE_PATH
            )
            image_tag = builder._container_image_tag(
                recipe_sha256,
                builder_sha256,
                containerfile_sha256,
                "amd64-cross",
            )

            def publish(
                stage: Path,
                destination: Path,
                expected_identity: tuple[int, int],
                verifier: object | None = None,
            ) -> None:
                if destination == output:
                    stage.rename(destination)
                    raise builder.PublicationFailure(
                        "injected parent fsync failure",
                        destination_installed=True,
                        destination_identity_preserved=True,
                        parent_fsync_completed=False,
                    )
                original_publish(
                    stage,
                    destination,
                    expected_identity,
                    verifier,
                )

            def run(arguments: list[str], **_: object) -> str:
                cidfile = Path(
                    arguments[arguments.index("--cidfile") + 1]
                )
                builder._write_bytes(
                    cidfile,
                    b"d" * 64,
                    mode=0o444,
                )
                return ""

            with (
                mock.patch.object(builder, "load_recipe", return_value=recipe),
                mock.patch.object(builder, "_prefetch"),
                mock.patch.object(
                    builder,
                    "_build_container_image",
                    return_value=(
                        image_tag,
                        f"sha256:{'b' * 64}",
                        builder_sha256,
                        containerfile_sha256,
                        builder._build_context_receipt(
                            builder._snapshot_build_context()
                        ),
                    ),
                ),
                mock.patch.object(builder, "_run", side_effect=run),
                mock.patch.object(
                    builder,
                    "_verify_pending_container_output",
                    return_value={"container": {"id": "d" * 64}},
                ),
                mock.patch.object(
                    builder,
                    "_rewrite_builder_container_projection",
                ),
                mock.patch.object(builder, "_verify_builder_output"),
                mock.patch.object(builder, "_verify_builder_output_fd"),
                mock.patch.object(
                    builder,
                    "_publish_directory_noreplace",
                    side_effect=publish,
                ),
                self.assertRaises(builder.PublicationFailure),
            ):
                builder._public_build(
                    "codex",
                    "amd64-cross",
                    output,
                    cache,
                    "docker",
                )

            failure = output.with_name("output.failure")
            self.assertTrue(output.is_dir())
            self.assertTrue(failure.is_dir())
            with mock.patch.object(builder, "_verify_builder_output_fd"):
                receipt = builder._verify_failure_output(failure)
            self.assertTrue(receipt["success_output_published"])
            self.assertFalse(
                receipt["success_output_parent_fsync_completed"]
            )
            self.assertTrue(receipt["cause"]["destination_installed"])
            self.assertFalse(receipt["cause"]["parent_fsync_completed"])

    def test_no_replace_publication_reports_parent_fsync_after_rename(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-publish-fsync-test."
        ) as temporary:
            root = Path(temporary)
            stage, identity = builder._create_owned_stage(root, ".stage.")
            (stage / "artifact").write_bytes(b"payload")
            output = root / "output"
            parent_identity = (root.stat().st_dev, root.stat().st_ino)
            original_fsync = os.fsync

            def fsync(descriptor: int) -> None:
                metadata = os.fstat(descriptor)
                if (
                    (metadata.st_dev, metadata.st_ino) == parent_identity
                    and output.exists()
                ):
                    raise OSError(errno.EIO, "injected parent fsync failure")
                original_fsync(descriptor)

            with (
                mock.patch.object(os, "fsync", side_effect=fsync),
                self.assertRaises(builder.PublicationFailure) as captured,
            ):
                builder._publish_directory_noreplace(
                    stage,
                    output,
                    identity,
                )
            self.assertTrue(captured.exception.destination_installed)
            self.assertFalse(captured.exception.parent_fsync_completed)
            self.assertEqual((output / "artifact").read_bytes(), b"payload")

    def test_no_replace_publication_preserves_racing_destination(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-publish-destination-race-test."
        ) as temporary:
            root = Path(temporary)
            stage, identity = builder._create_owned_stage(root, ".stage.")
            (stage / "artifact").write_bytes(b"candidate")
            output = root / "output"
            original_rename = builder._renameat2_noreplace

            def race(
                parent_descriptor: int,
                source_name: str,
                destination_name: str,
            ) -> None:
                output.mkdir()
                (output / "sentinel").write_bytes(b"racing-owner")
                original_rename(
                    parent_descriptor,
                    source_name,
                    destination_name,
                )

            with (
                mock.patch.object(
                    builder, "_renameat2_noreplace", side_effect=race
                ),
                self.assertRaisesRegex(
                    builder.BuildError, "atomic no-replace publication failed"
                ),
            ):
                builder._publish_directory_noreplace(
                    stage, output, identity
                )
            self.assertEqual(
                (output / "sentinel").read_bytes(), b"racing-owner"
            )
            self.assertEqual((stage / "artifact").read_bytes(), b"candidate")

    def test_no_replace_publication_reconciles_post_commit_wrapper_error(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-publish-rename-commit-unknown-test."
        ) as temporary:
            root = Path(temporary)
            stage, identity = builder._create_owned_stage(root, ".stage.")
            (stage / "artifact").write_bytes(b"candidate")
            output = root / "output"
            original_rename = builder._renameat2_noreplace

            def committed_then_reported_error(
                parent_descriptor: int,
                source_name: str,
                destination_name: str,
            ) -> None:
                original_rename(
                    parent_descriptor,
                    source_name,
                    destination_name,
                )
                raise OSError(errno.EINTR, "injected post-commit interruption")

            with mock.patch.object(
                builder,
                "_renameat2_noreplace",
                side_effect=committed_then_reported_error,
            ):
                builder._publish_directory_noreplace(
                    stage, output, identity
                )
            self.assertFalse(stage.exists())
            self.assertEqual(
                (output / "artifact").read_bytes(), b"candidate"
            )
            for name in builder._publication_journal_names(
                builder._publication_target_key(root.stat(), output)
            ):
                self.assertFalse((self.publication_custody / name).exists())

    def test_no_replace_publication_persists_lost_names_hold(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-publish-lost-names-hold-test."
        ) as temporary:
            root = Path(temporary)
            stage, identity = builder._create_owned_stage(root, ".stage.")
            (stage / "artifact").write_bytes(b"candidate")
            output = root / "output"
            detached = root / "detached-stage"

            def detach_then_report_error(
                parent_descriptor: int,
                source_name: str,
                _destination_name: str,
            ) -> None:
                os.rename(
                    source_name,
                    detached.name,
                    src_dir_fd=parent_descriptor,
                    dst_dir_fd=parent_descriptor,
                )
                raise OSError(errno.EINTR, "injected lost fixed names")

            with (
                mock.patch.object(
                    builder,
                    "_renameat2_noreplace",
                    side_effect=detach_then_report_error,
                ),
                self.assertRaisesRegex(
                    builder.PublicationFailure,
                    "durable rename-attempted journal",
                ),
            ):
                builder._publish_directory_noreplace(stage, output, identity)
            journal_names = builder._publication_journal_names(
                builder._publication_target_key(root.stat(), output)
            )
            self.assertTrue(
                all((self.publication_custody / name).is_file() for name in journal_names)
            )
            self.assertFalse(stage.exists())
            self.assertFalse(output.exists())

            replacement, replacement_identity = builder._create_owned_stage(
                root,
                ".replacement.",
            )
            (replacement / "artifact").write_bytes(b"replacement")
            with self.assertRaisesRegex(
                builder.BuildError,
                "another operation; permanent HOLD",
            ):
                builder._publish_directory_noreplace(
                    replacement,
                    output,
                    replacement_identity,
                )
            self.assertTrue(
                all((self.publication_custody / name).is_file() for name in journal_names)
            )

    def test_publication_single_flight_rejects_same_stage_second_caller(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-publish-single-flight-test."
        ) as temporary:
            root = Path(temporary)
            stage, identity = builder._create_owned_stage(root, ".stage.")
            (stage / "artifact").write_bytes(b"candidate")
            output = root / "output"
            parent_fd = os.open(
                self.publication_custody,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            held_fd = -1
            target_key = builder._publication_target_key(
                root.stat(),
                output,
            )
            try:
                held_fd, _, _ = builder._acquire_publication_lock_fd(
                    parent_fd,
                    target_key,
                )
                with self.assertRaisesRegex(
                    builder.BuildError,
                    "active single-flight",
                ):
                    builder._publish_directory_noreplace(
                        stage,
                        output,
                        identity,
                    )
                self.assertTrue(stage.is_dir())
                self.assertFalse(output.exists())
            finally:
                if held_fd >= 0:
                    os.close(held_fd)
                os.close(parent_fd)
            builder._publish_directory_noreplace(stage, output, identity)
            self.assertEqual((output / "artifact").read_bytes(), b"candidate")

    def test_publication_restart_reuses_rename_attempted_journal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-publish-attempt-restart-test."
        ) as temporary:
            root = Path(temporary)
            stage, identity = builder._create_owned_stage(root, ".stage.")
            (stage / "artifact").write_bytes(b"candidate")
            output = root / "output"
            original_create = builder._create_publication_journal_fd
            calls = 0

            def crash_after_durable_attempt(*args, **kwargs):
                nonlocal calls
                calls += 1
                result = original_create(*args, **kwargs)
                if calls == 2:
                    raise OSError(errno.EIO, "injected crash after attempted journal")
                return result

            with (
                mock.patch.object(
                    builder,
                    "_create_publication_journal_fd",
                    side_effect=crash_after_durable_attempt,
                ),
                self.assertRaisesRegex(OSError, "injected crash"),
            ):
                builder._publish_directory_noreplace(stage, output, identity)
            journal_names = builder._publication_journal_names(
                builder._publication_target_key(root.stat(), output)
            )
            self.assertTrue(
                all((self.publication_custody / name).is_file() for name in journal_names)
            )
            journal = json.loads(
                (self.publication_custody / journal_names[1]).read_text("ascii")
            )
            self.assertEqual(journal["schema"], builder.PUBLICATION_JOURNAL_SCHEMA)
            self.assertEqual(
                journal["candidate_digest"],
                builder._publication_candidate_digest(
                    journal["canonical_tree_seal"]
                ),
            )
            self.assertRegex(journal["operation_id"], r"^[0-9a-f]{64}$")
            def create_resolution_only(descriptor, name, payload):
                if name in journal_names:
                    raise AssertionError(
                        "exact rename-attempted state must not be recreated"
                    )
                return original_create(descriptor, name, payload)

            with mock.patch.object(
                builder,
                "_create_publication_journal_fd",
                side_effect=create_resolution_only,
            ):
                builder._publish_directory_noreplace(stage, output, identity)
            self.assertFalse(stage.exists())
            self.assertEqual((output / "artifact").read_bytes(), b"candidate")
            self.assertTrue(
                all(not (self.publication_custody / name).exists() for name in journal_names)
            )

    def test_publication_restart_reconciles_retirement_crash(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-publish-retirement-restart-test."
        ) as temporary:
            root = Path(temporary)
            stage, identity = builder._create_owned_stage(root, ".stage.")
            (stage / "artifact").write_bytes(b"candidate")
            output = root / "output"
            original_archive = builder._archive_publication_journal_exact_fd
            injected = False

            def archive_then_crash(*args, **kwargs):
                nonlocal injected
                result = original_archive(*args, **kwargs)
                if not injected:
                    injected = True
                    raise OSError(errno.EIO, "injected retirement crash")
                return result

            with (
                mock.patch.object(
                    builder,
                    "_archive_publication_journal_exact_fd",
                    side_effect=archive_then_crash,
                ),
                self.assertRaises(builder.PublicationFailure),
            ):
                builder._publish_directory_noreplace(stage, output, identity)
            intent_name, attempted_name = builder._publication_journal_names(
                builder._publication_target_key(root.stat(), output)
            )
            self.assertTrue((self.publication_custody / intent_name).is_file())
            self.assertFalse((self.publication_custody / attempted_name).exists())
            self.assertFalse(stage.exists())
            builder._publish_directory_noreplace(stage, output, identity)
            self.assertEqual((output / "artifact").read_bytes(), b"candidate")
            self.assertFalse((self.publication_custody / intent_name).exists())

    def test_publication_journal_rejects_same_inode_candidate_aba(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-publish-candidate-aba-test."
        ) as temporary:
            root = Path(temporary)
            stage, identity = builder._create_owned_stage(root, ".stage.")
            artifact = stage / "artifact"
            artifact.write_bytes(b"candidate-a")
            output = root / "output"
            original_create = builder._create_publication_journal_fd
            calls = 0

            def crash_after_durable_attempt(*args, **kwargs):
                nonlocal calls
                calls += 1
                result = original_create(*args, **kwargs)
                if calls == 2:
                    raise OSError(errno.EIO, "injected crash")
                return result

            with (
                mock.patch.object(
                    builder,
                    "_create_publication_journal_fd",
                    side_effect=crash_after_durable_attempt,
                ),
                self.assertRaises(OSError),
            ):
                builder._publish_directory_noreplace(stage, output, identity)
            before = stage.stat()
            artifact.write_bytes(b"candidate-b")
            after = stage.stat()
            self.assertEqual(
                (before.st_dev, before.st_ino),
                (after.st_dev, after.st_ino),
            )
            with self.assertRaisesRegex(
                builder.BuildError,
                "another operation; permanent HOLD",
            ):
                builder._publish_directory_noreplace(stage, output, identity)
            detached = root / "detached-original-stage"
            stage.rename(detached)
            stage.mkdir(mode=0o700)
            (stage / "artifact").write_bytes(b"candidate-a")
            replacement = stage.stat()
            with self.assertRaisesRegex(
                builder.BuildError,
                "another operation; permanent HOLD",
            ):
                builder._publish_directory_noreplace(
                    stage,
                    output,
                    (replacement.st_dev, replacement.st_ino),
                )

    def test_publication_custody_name_rebind_barriers_permanently_hold(
        self,
    ) -> None:
        def candidate(root: Path, prefix: str, content: bytes):
            stage, identity = builder._create_owned_stage(root, prefix)
            (stage / "artifact").write_bytes(content)
            return stage, identity

        def assert_divergent_hold(root: Path, output: Path, label: str) -> None:
            replacement, replacement_identity = candidate(
                root,
                f".{label}-divergent.",
                b"divergent-candidate",
            )
            with self.assertRaisesRegex(
                (builder.BuildError, builder.PublicationFailure),
                "permanent HOLD|another or rebound operation|resolved committed",
            ):
                builder._publish_directory_noreplace(
                    replacement,
                    output,
                    replacement_identity,
                )

        with tempfile.TemporaryDirectory(
            prefix="provider-publication-custody-rebind."
        ) as temporary:
            root = Path(temporary)

            creation_stage, creation_identity = candidate(
                root,
                ".creation-stage.",
                b"creation",
            )
            creation_output = root / "creation-output"
            original_create = builder._create_publication_journal_fd
            creation_rebound = False

            def rebind_after_creation(descriptor, name, payload):
                nonlocal creation_rebound
                identity = original_create(descriptor, name, payload)
                if payload["state"] == "intent" and not creation_rebound:
                    os.rename(
                        name,
                        f"{name}.rebound.json",
                        src_dir_fd=descriptor,
                        dst_dir_fd=descriptor,
                    )
                    os.fsync(descriptor)
                    creation_rebound = True
                return identity

            with (
                mock.patch.object(
                    builder,
                    "_create_publication_journal_fd",
                    side_effect=rebind_after_creation,
                ),
                self.assertRaisesRegex(
                    builder.BuildError,
                    "detached; permanent HOLD",
                ),
            ):
                builder._publish_directory_noreplace(
                    creation_stage,
                    creation_output,
                    creation_identity,
                )
            self.assertTrue(creation_rebound)
            assert_divergent_hold(root, creation_output, "creation")

            pre_stage, pre_identity = candidate(
                root,
                ".pre-rename-stage.",
                b"pre-rename",
            )
            pre_output = root / "pre-rename-output"
            pre_attempted = builder._publication_journal_names(
                builder._publication_target_key(root.stat(), pre_output)
            )[1]
            original_rename = builder._renameat2_noreplace
            pre_rebound = False

            # Keep the custody FD lifetime explicit inside the barrier hook.
            custody_fd = os.open(
                self.publication_custody,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )

            def rebind_at_rename_retained(
                descriptor,
                source_name,
                destination_name,
            ):
                nonlocal pre_rebound
                if not pre_rebound:
                    os.rename(
                        pre_attempted,
                        f"{pre_attempted}.rebound.json",
                        src_dir_fd=custody_fd,
                        dst_dir_fd=custody_fd,
                    )
                    os.fsync(custody_fd)
                    pre_rebound = True
                return original_rename(descriptor, source_name, destination_name)

            try:
                with (
                    mock.patch.object(
                        builder,
                        "_renameat2_noreplace",
                        side_effect=rebind_at_rename_retained,
                    ),
                    self.assertRaises(builder.PublicationFailure),
                ):
                    builder._publish_directory_noreplace(
                        pre_stage,
                        pre_output,
                        pre_identity,
                    )
            finally:
                os.close(custody_fd)
            self.assertTrue(pre_rebound)
            assert_divergent_hold(root, pre_output, "pre-rename")

            retirement_stage, retirement_identity = candidate(
                root,
                ".retirement-stage.",
                b"retirement",
            )
            retirement_output = root / "retirement-output-rebind"
            original_archive = builder._archive_publication_journal_exact_fd
            retirement_rebound = False

            def rebind_at_retirement(
                descriptor,
                source_name,
                archive_name,
                identity,
            ):
                nonlocal retirement_rebound
                if not retirement_rebound:
                    os.rename(
                        source_name,
                        f"{source_name}.rebound.json",
                        src_dir_fd=descriptor,
                        dst_dir_fd=descriptor,
                    )
                    os.fsync(descriptor)
                    retirement_rebound = True
                return original_archive(
                    descriptor,
                    source_name,
                    archive_name,
                    identity,
                )

            with (
                mock.patch.object(
                    builder,
                    "_archive_publication_journal_exact_fd",
                    side_effect=rebind_at_retirement,
                ),
                self.assertRaises(builder.PublicationFailure),
            ):
                builder._publish_directory_noreplace(
                    retirement_stage,
                    retirement_output,
                    retirement_identity,
                )
            self.assertTrue(retirement_rebound)
            assert_divergent_hold(root, retirement_output, "retirement")

    def test_publication_without_root_custody_is_source_only_hold(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-publication-missing-custody."
        ) as temporary:
            root = Path(temporary)
            stage, identity = builder._create_owned_stage(root, ".stage.")
            (stage / "artifact").write_bytes(b"candidate")
            output = root / "output"
            with (
                mock.patch.object(
                    builder,
                    "PUBLICATION_TEST_ONLY_CUSTODY_DIRECTORY",
                    None,
                ),
                mock.patch.object(
                    builder,
                    "PUBLICATION_CUSTODY_ROOT",
                    root / "missing-root-custody",
                ),
                self.assertRaisesRegex(
                    builder.BuildError,
                    "source-only HOLD",
                ),
            ):
                builder._publish_directory_noreplace(
                    stage,
                    output,
                    identity,
                )
            self.assertTrue(stage.is_dir())
            self.assertFalse(output.exists())

    def test_publication_lock_fifo_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-publish-lock-fifo-test."
        ) as temporary:
            root = Path(temporary)
            output = root / "output"
            target_key = builder._publication_target_key(
                root.stat(),
                output,
            )
            os.mkfifo(
                self.publication_custody / builder._publication_lock_name(target_key),
                0o600,
            )
            parent_fd = os.open(
                self.publication_custody,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            started = time.monotonic()
            try:
                with self.assertRaises(builder.BuildError):
                    builder._acquire_publication_lock_fd(
                        parent_fd,
                        target_key,
                    )
            finally:
                os.close(parent_fd)
            self.assertLess(time.monotonic() - started, 1.0)

    def test_reconcile_source_uses_retained_no_replace_publisher(self) -> None:
        source = inspect.getsource(builder._reconcile_from_fds)
        self.assertIn("_publish_directory_noreplace(", source)
        self.assertIn("verifier=_verify_reproducibility_output_fd", source)
        self.assertNotIn("os.replace(", source)
        self.assertNotIn(".rename(", source)

    def test_publication_rejects_parent_path_rebind_before_rename(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-publish-parent-rebind-test."
        ) as temporary:
            base = Path(temporary)
            parent = base / "parent"
            parent.mkdir()
            stage, identity = builder._create_owned_stage(parent, ".stage.")
            (stage / "artifact").write_bytes(b"candidate")
            output = parent / "output"
            held_parent = base / "held-parent"
            original_fsync_tree = builder._fsync_tree_fd
            rebound = False

            def rebind(descriptor: int) -> None:
                nonlocal rebound
                original_fsync_tree(descriptor)
                if not rebound:
                    parent.rename(held_parent)
                    parent.mkdir()
                    rebound = True

            with (
                mock.patch.object(
                    builder, "_fsync_tree_fd", side_effect=rebind
                ),
                self.assertRaisesRegex(builder.BuildError, "parent path was rebound"),
            ):
                builder._publish_directory_noreplace(
                    stage, output, identity
                )
            self.assertTrue(rebound)
            self.assertFalse(output.exists())
            self.assertFalse((held_parent / "output").exists())
            self.assertEqual(
                (held_parent / stage.name / "artifact").read_bytes(),
                b"candidate",
            )

    def test_publication_detects_post_publish_file_drift(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-publish-post-drift-test."
        ) as temporary:
            root = Path(temporary)
            stage, identity = builder._create_owned_stage(root, ".stage.")
            (stage / "artifact").write_bytes(b"candidate")
            output = root / "output"
            parent_identity = (root.stat().st_dev, root.stat().st_ino)
            original_fsync = os.fsync
            drifted = False

            def verifier(descriptor: int) -> None:
                artifact_descriptor = os.open(
                    "artifact",
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                try:
                    content = os.read(artifact_descriptor, 64)
                finally:
                    os.close(artifact_descriptor)
                if content != b"candidate":
                    raise builder.BuildError(
                        "post-publication artifact drift detected"
                    )

            def fsync(descriptor: int) -> None:
                nonlocal drifted
                original_fsync(descriptor)
                metadata = os.fstat(descriptor)
                if (
                    not drifted
                    and (metadata.st_dev, metadata.st_ino) == parent_identity
                    and output.exists()
                ):
                    (output / "artifact").write_bytes(b"drifted")
                    drifted = True

            with (
                mock.patch.object(os, "fsync", side_effect=fsync),
                self.assertRaises(builder.PublicationFailure) as captured,
            ):
                builder._publish_directory_noreplace(
                    stage,
                    output,
                    identity,
                    verifier=verifier,
                )
            self.assertTrue(drifted)
            self.assertTrue(captured.exception.destination_installed)
            self.assertTrue(
                captured.exception.destination_identity_preserved
            )
            self.assertEqual(
                (output / "artifact").read_bytes(), b"drifted"
            )

    def test_publication_rejects_stage_and_final_name_replacement(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-publish-replacement-test."
        ) as temporary:
            root = Path(temporary)
            stage, identity = builder._create_owned_stage(root, ".stage.")
            (stage / "artifact").write_bytes(b"original")
            moved = root / "moved-original"
            stage.rename(moved)
            stage.mkdir()
            (stage / "artifact").write_bytes(b"replacement")
            output = root / "output"
            with self.assertRaisesRegex(builder.BuildError, "identity is not pinned"):
                builder._publish_directory_noreplace(
                    stage,
                    output,
                    identity,
                )
            self.assertFalse(output.exists())
            self.assertEqual((moved / "artifact").read_bytes(), b"original")
            self.assertEqual((stage / "artifact").read_bytes(), b"replacement")
            shutil.rmtree(stage)
            shutil.rmtree(moved)

            stage, identity = builder._create_owned_stage(root, ".stage.")
            (stage / "artifact").write_bytes(b"published")
            output_alias = root / "output-alias"
            parent_identity = (root.stat().st_dev, root.stat().st_ino)
            original_fsync = os.fsync
            swapped = False

            def fsync(descriptor: int) -> None:
                nonlocal swapped
                original_fsync(descriptor)
                metadata = os.fstat(descriptor)
                if (
                    not swapped
                    and (metadata.st_dev, metadata.st_ino) == parent_identity
                    and output.exists()
                ):
                    output.rename(output_alias)
                    output.mkdir()
                    (output / "artifact").write_bytes(b"replacement")
                    swapped = True

            with (
                mock.patch.object(os, "fsync", side_effect=fsync),
                self.assertRaises(builder.PublicationFailure) as captured,
            ):
                builder._publish_directory_noreplace(
                    stage,
                    output,
                    identity,
                )
            self.assertTrue(captured.exception.destination_installed)
            self.assertFalse(
                captured.exception.destination_identity_preserved
            )
            self.assertEqual(
                (output_alias / "artifact").read_bytes(),
                b"published",
            )
            self.assertEqual(
                (output / "artifact").read_bytes(),
                b"replacement",
            )
            shutil.rmtree(output)
            shutil.rmtree(output_alias)

    def test_failure_receipt_is_umask_independent_and_detects_late_tamper(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-failure-umask-test."
        ) as temporary:
            root = Path(temporary)
            output = root / "output"
            cache = root / "cache"
            cache.mkdir()
            snapshots = builder._snapshot_build_context()
            recipe_sha256 = hashlib.sha256(
                snapshots["provider-payload-recipe-v1.json"]
            ).hexdigest()
            builder_sha256 = hashlib.sha256(
                snapshots["build_provider_payload.py"]
            ).hexdigest()
            containerfile_sha256 = hashlib.sha256(
                snapshots["Containerfile"]
            ).hexdigest()
            previous_umask = os.umask(0o777)
            try:
                failure = builder._persist_build_failure(
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
                    error=builder.BuildError("injected failure"),
                )
            finally:
                os.umask(previous_umask)
            receipt = builder._verify_failure_output(failure)
            self.assertEqual(
                stat.S_IMODE(failure.stat().st_mode),
                0o500,
            )
            self.assertFalse(receipt["candidate_stage_retained"])

            original_snapshots = builder._retained_artifact_snapshots_from_fd
            mutated = False

            @contextmanager
            def mutate_during_snapshot(
                root_descriptor: int,
                artifacts: object,
            ) -> object:
                nonlocal mutated
                with original_snapshots(root_descriptor, artifacts) as copies:
                    if not mutated:
                        receipt_path = (
                            failure / "provider-build-failure-receipt.json"
                        )
                        content = receipt_path.read_bytes()
                        marker = b'"admission_wired":false'
                        self.assertIn(marker, content)
                        receipt_path.chmod(0o600)
                        receipt_path.write_bytes(
                            content.replace(
                                marker,
                                b'"admission_wired":true ',
                                1,
                            )
                        )
                        receipt_path.chmod(0o400)
                        mutated = True
                    yield copies

            with (
                mock.patch.object(
                    builder,
                    "_retained_artifact_snapshots_from_fd",
                    side_effect=mutate_during_snapshot,
                ),
                self.assertRaisesRegex(builder.BuildError, "changed during"),
            ):
                builder._verify_failure_output(failure)

    def test_prefetch_failure_uses_pre_frozen_input_snapshots(self) -> None:
        recipe = builder.load_recipe()
        snapshots = builder._snapshot_build_context()
        expected_recipe_sha256 = hashlib.sha256(
            snapshots["provider-payload-recipe-v1.json"]
        ).hexdigest()
        with tempfile.TemporaryDirectory(
            prefix="provider-prefetch-snapshot-test."
        ) as temporary:
            root = Path(temporary)
            output = root / "output"
            cache = root / "cache"
            cache.mkdir()
            drifted_recipe = root / "drifted-recipe.json"
            drifted_recipe.write_bytes(b"{}\n")

            def prefetch(*_: object, **__: object) -> None:
                builder.RECIPE_PATH = drifted_recipe
                raise builder.BuildError("injected prefetch failure")

            original_recipe_path = builder.RECIPE_PATH
            try:
                with (
                    mock.patch.object(builder, "load_recipe", return_value=recipe),
                    mock.patch.object(
                        builder,
                        "_snapshot_build_context",
                        return_value=snapshots,
                    ),
                    mock.patch.object(
                        builder,
                        "_prefetch",
                        side_effect=prefetch,
                    ),
                    self.assertRaises(builder.BuildError),
                ):
                    builder._public_build(
                        "codex",
                        "amd64-cross",
                        output,
                        cache,
                        "docker",
                    )
            finally:
                builder.RECIPE_PATH = original_recipe_path
            receipt = builder._verify_failure_output(
                output.with_name("output.failure")
            )
            self.assertEqual(
                receipt["inputs"]["recipe"]["sha256"],
                expected_recipe_sha256,
            )

    def test_cleanup_failure_records_retained_candidate_stage(self) -> None:
        recipe = builder.load_recipe()
        snapshots = builder._snapshot_build_context()
        recipe_sha256 = hashlib.sha256(
            snapshots["provider-payload-recipe-v1.json"]
        ).hexdigest()
        builder_sha256 = hashlib.sha256(
            snapshots["build_provider_payload.py"]
        ).hexdigest()
        containerfile_sha256 = hashlib.sha256(
            snapshots["Containerfile"]
        ).hexdigest()
        image_tag = builder._container_image_tag(
            recipe_sha256,
            builder_sha256,
            containerfile_sha256,
            "amd64-cross",
        )
        original_cleanup = builder._cleanup_owned_stage
        cleanup_count = 0

        def cleanup(
            stage: Path,
            identity: tuple[int, int],
        ) -> dict[str, object]:
            nonlocal cleanup_count
            cleanup_count += 1
            if cleanup_count == 1:
                raise OSError(errno.EIO, "injected owned-stage cleanup failure")
            return original_cleanup(stage, identity)

        def run(arguments: list[str], **_: object) -> str:
            raise builder.CommandFailure(
                arguments,
                77,
                "injected container failure\n",
                False,
            )

        with tempfile.TemporaryDirectory(
            prefix="provider-retained-candidate-test."
        ) as temporary:
            root = Path(temporary)
            output = root / "output"
            cache = root / "cache"
            cache.mkdir()
            with (
                mock.patch.object(builder, "load_recipe", return_value=recipe),
                mock.patch.object(
                    builder,
                    "_snapshot_build_context",
                    return_value=snapshots,
                ),
                mock.patch.object(builder, "_prefetch"),
                mock.patch.object(
                    builder,
                    "_build_container_image",
                    return_value=(
                        image_tag,
                        f"sha256:{'b' * 64}",
                        builder_sha256,
                        containerfile_sha256,
                        builder._build_context_receipt(snapshots),
                    ),
                ),
                mock.patch.object(builder, "_run", side_effect=run),
                mock.patch.object(
                    builder,
                    "_cleanup_owned_stage",
                    side_effect=cleanup,
                ),
                self.assertRaises(builder.CombinedBuildFailure),
            ):
                builder._public_build(
                    "codex",
                    "amd64-cross",
                    output,
                    cache,
                    "docker",
                )
            failure = output.with_name("output.failure")
            receipt = builder._verify_failure_output(failure)
            self.assertEqual(receipt["failed_phase"], "container")
            self.assertEqual(
                receipt["cause"]["exception_type"],
                "CommandFailure",
            )
            self.assertEqual(
                receipt["cause"]["secondary_exception_type"],
                "OSError",
            )
            self.assertEqual(receipt["cause"]["return_code"], 77)
            self.assertTrue(receipt["candidate_stage_retained"])
            candidate = receipt["candidate_stage"]
            self.assertEqual(candidate["state"], "retained_at_owned_path")
            self.assertEqual(candidate["role"], "provider_output_stage")
            self.assertFalse(
                candidate[
                    "same_uid_concurrent_retained_stage_path_replacement_proven"
                ]
            )
            self.assertEqual(
                [
                    tombstone["role"]
                    for tombstone in receipt["cleanup_tombstones"]
                ],
                ["container_cidfile_custody"],
            )
            retained_path = Path(candidate["requested_path"])
            self.assertTrue(retained_path.is_dir())
            expected_identity = candidate["expected_identity"]
            original_cleanup(
                retained_path,
                (
                    expected_identity["device"],
                    expected_identity["inode"],
                ),
            )

    def test_containerfile_preinstalls_exact_rust_components_and_target(
        self,
    ) -> None:
        content = (DIRECTORY / "Containerfile").read_text(encoding="utf-8")
        copy_offset = content.index("COPY --chmod")
        setup = content[:copy_offset]
        self.assertRegex(
            setup,
            (
                r"rustup target add --toolchain 1\.95\.0 "
                r"aarch64-unknown-linux-musl \\"
            ),
        )
        self.assertRegex(
            setup,
            (
                r"rustup component add --toolchain 1\.95\.0 "
                r"clippy rustfmt rust-src \\"
            ),
        )

    def test_source_receipt_separates_pristine_and_derived_codex_inputs(
        self,
    ) -> None:
        upstream, derived, patch_bytes, names, rule = (
            synthetic_codex_lock_fixture()
        )

        def artifact_spec(path: Path) -> dict[str, object]:
            content = path.read_bytes()
            return {
                "filename": path.name,
                "byte_length": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }

        with tempfile.TemporaryDirectory(
            prefix="provider-source-receipt-schema."
        ) as temporary:
            root = Path(temporary)
            source = root / "source"
            codex_rs = source / "codex-rs"
            codex_rs.mkdir(parents=True)
            derived_path = codex_rs / "Cargo.lock"
            derived_path.write_bytes(derived)
            (codex_rs / "rust-toolchain.toml").write_text(
                '[toolchain]\nchannel = "1.95.0"\n',
                encoding="utf-8",
            )
            inputs = root / "inputs"
            inputs.mkdir()

            def pinned(name: str, content: bytes) -> Path:
                path = inputs / name
                path.write_bytes(content)
                return path

            source_archive = pinned("codex-source.tar.xz", b"source-archive")
            tag_object = pinned("codex-tag.object", b"tag-object")
            commit_object = pinned("codex-commit.object", b"commit-object")
            source_member_manifest = pinned(
                "codex-source-members.json",
                b'{"entries":[]}\n',
            )
            source_logical_symlinks = pinned(
                "codex-source-logical-symlinks.json",
                b'{"symlinks":[]}\n',
            )
            upstream_path = pinned("Cargo.lock.upstream", upstream)
            patch_path = pinned("Cargo.lock.patch", patch_bytes)
            vendor_archive = pinned("cargo-vendor.tar.xz", b"vendor-archive")
            vendor_manifest = pinned(
                "cargo-vendor-members.json", b'{"members":[]}\n'
            )
            cargo_config = pinned(
                "cargo-source-config.toml",
                b"[net]\noffline = true\n",
            )
            v8_archive = pinned("rusty-v8.a.gz", b"v8-archive")
            v8_binding = pinned("rusty-v8-binding.rs", b"v8-binding")
            v8_checksums = pinned("rusty-v8.sha256", b"v8-checksums")

            rusty_v8_contract = {
                "crate_version": "149.2.0",
                "crate_checksum_sha256": "1" * 64,
                "target": "aarch64-unknown-linux-musl",
                "variant": "release",
                "resolved_features": {
                    "codex-cli": [],
                    "codex-code-mode": [],
                    "codex-core": [],
                    "v8": ["default", "use_custom_libcxx"],
                },
                "archive_uncompressed_byte_length": 123,
                "archive_uncompressed_sha256": "2" * 64,
                "release_prerelease": True,
                "release_immutable": False,
                "upstream_signature_proven": False,
                "github_attestation_proven": False,
            }
            provider = {
                "repository_url": "https://github.com/openai/codex",
                "version": "0.144.1",
                "annotated_tag": "rust-v0.144.1",
                "annotated_tag_object_sha1": "3" * 40,
                "dereferenced_commit_sha1": "4" * 40,
                "source_tree_sha1": "5" * 40,
                "source_archive": artifact_spec(source_archive),
                "source_identity": {
                    "tag_object": artifact_spec(tag_object),
                    "commit_object": artifact_spec(commit_object),
                    "source_member_manifest": artifact_spec(
                        source_member_manifest
                    ),
                    "logical_symlinks": artifact_spec(
                        source_logical_symlinks
                    ),
                    "source_root_name": "codex-rust-v0.144.1",
                    "source_entry_count": 1,
                    "source_inventory_sha256": "b" * 64,
                },
                "cargo_vendor": {
                    "archive": artifact_spec(vendor_archive),
                    "member_manifest": artifact_spec(vendor_manifest),
                    "root_name": "vendor",
                    "entry_count": 1,
                    "inventory_sha256": "a" * 64,
                },
                "cargo_source_config": artifact_spec(cargo_config),
                "rusty_v8": {
                    **rusty_v8_contract,
                    "archive": artifact_spec(v8_archive),
                    "binding": artifact_spec(v8_binding),
                    "checksums": artifact_spec(v8_checksums),
                },
                "derived_lock": rule,
                "lockfiles": {
                    "codex-rs/Cargo.lock": hashlib.sha256(upstream).hexdigest(),
                },
            }
            metadata_command = [
                "cargo",
                "--config",
                str(cargo_config),
                "metadata",
                "--frozen",
            ]
            codex_inputs = {
                "source_archive": source_archive,
                "tag_object": tag_object,
                "commit_object": commit_object,
                "source_member_manifest": source_member_manifest,
                "source_logical_symlinks": source_logical_symlinks,
                "upstream_lock": upstream_path,
                "derived_lock": derived_path,
                "lock_patch": patch_path,
                "cargo_vendor_archive": vendor_archive,
                "cargo_vendor_member_manifest": vendor_manifest,
                "cargo_vendor_inventory_sha256": "a" * 64,
                "post_build_vendor_inventory_sha256": "a" * 64,
                "cargo_source_config": cargo_config,
                "rusty_v8_archive": v8_archive,
                "rusty_v8_binding": v8_binding,
                "rusty_v8_checksums": v8_checksums,
                "source_inventory_sha256": "6" * 64,
                "post_build_source_inventory_sha256": "6" * 64,
                "cargo_metadata_command": metadata_command,
            }
            output = root / "codex-output"
            output.mkdir()
            receipt = builder._source_receipt(
                "codex",
                provider,
                source,
                output,
                codex_inputs,
            )

            self.assertEqual(set(receipt), builder.EXPECTED_SOURCE_KEYS)
            self.assertTrue(receipt["pristine_upstream_source_proven"])
            self.assertTrue(receipt["build_source_derived"])
            self.assertEqual(
                receipt["source_archive"],
                receipt["dependency_assets"]["source_archive"],
            )
            self.assertEqual(len(receipt["patched_sources"]), 1)
            self.assertEqual(
                receipt["patched_sources"][0],
                receipt["derived_build_source"]["lock_patch"],
            )
            self.assertEqual(
                set(receipt["derived_build_source"]),
                builder.EXPECTED_CODEX_DERIVED_BUILD_SOURCE_KEYS,
            )
            self.assertEqual(
                set(receipt["dependency_assets"]),
                builder.EXPECTED_CODEX_DEPENDENCY_ASSET_KEYS,
            )
            derived_source = receipt["derived_build_source"]
            self.assertEqual(
                derived_source["pristine_source_tree_sha1"],
                provider["source_tree_sha1"],
            )
            self.assertEqual(
                derived_source["upstream_lock"]["sha256"],
                hashlib.sha256(upstream).hexdigest(),
            )
            self.assertEqual(
                derived_source["derived_lock"]["sha256"],
                rule["derived_sha256"],
            )
            self.assertEqual(
                derived_source["lock_patch"]["sha256"],
                rule["patch_sha256"],
            )
            self.assertEqual(
                derived_source["workspace_package_count"],
                len(names),
            )
            self.assertEqual(
                derived_source["pre_build_source_inventory_sha256"],
                derived_source["post_build_source_inventory_sha256"],
            )
            self.assertEqual(
                derived_source["cargo_metadata_command"],
                metadata_command,
            )
            self.assertEqual(
                receipt["dependency_assets"]["rusty_v8_contract"],
                rusty_v8_contract,
            )
            self.assertEqual(
                receipt["dependency_assets"]["source_member_manifest"][
                    "sha256"
                ],
                artifact_spec(source_member_manifest)["sha256"],
            )
            self.assertEqual(
                receipt["dependency_assets"]["source_logical_symlinks"][
                    "sha256"
                ],
                artifact_spec(source_logical_symlinks)["sha256"],
            )
            self.assertEqual(
                receipt["dependency_assets"]["cargo_vendor_contract"],
                {
                    "root_name": "vendor",
                    "entry_count": 1,
                    "pre_build_inventory_sha256": "a" * 64,
                    "post_build_inventory_sha256": "a" * 64,
                    "cache_bind_mount_read_only": True,
                    "archive_retained_in_builder_output": False,
                },
            )
            self.assertEqual(len(receipt["lockfiles"]), 3)
            self.assertEqual(
                {artifact["sha256"] for artifact in receipt["lockfiles"]},
                {
                    hashlib.sha256(upstream).hexdigest(),
                    hashlib.sha256(derived).hexdigest(),
                    hashlib.sha256(
                        (codex_rs / "rust-toolchain.toml").read_bytes()
                    ).hexdigest(),
                },
            )

            with self.assertRaisesRegex(
                builder.BuildError, "inputs are incomplete"
            ):
                builder._source_receipt(
                    "codex",
                    provider,
                    source,
                    root / "unused-output",
                )

    def test_source_archive_has_zero_symlinks_then_restores_exact_logical_link(
        self,
    ) -> None:
        root_name = "codex-rust-v0.144.1"
        link_relative = "codex-rs/vendor/bubblewrap/LICENSE"
        link_target = "COPYING"
        copying_content = b"frozen bubblewrap license\n"

        def write_archive(archive: Path, *, materialize_link: bool) -> None:
            with tarfile.open(archive, mode="w:xz") as bundle:
                for directory in (
                    root_name,
                    f"{root_name}/codex-rs",
                    f"{root_name}/codex-rs/vendor",
                    f"{root_name}/codex-rs/vendor/bubblewrap",
                ):
                    value = tarfile.TarInfo(directory)
                    value.type = tarfile.DIRTYPE
                    value.mode = 0o755
                    bundle.addfile(value)
                copying = tarfile.TarInfo(
                    f"{root_name}/codex-rs/vendor/bubblewrap/COPYING"
                )
                copying.size = len(copying_content)
                copying.mode = 0o644
                bundle.addfile(copying, io.BytesIO(copying_content))
                license_value = tarfile.TarInfo(
                    f"{root_name}/{link_relative}"
                )
                if materialize_link:
                    materialized = link_target.encode("utf-8")
                    license_value.size = len(materialized)
                    license_value.mode = 0o644
                    bundle.addfile(
                        license_value,
                        io.BytesIO(materialized),
                    )
                else:
                    license_value.type = tarfile.SYMTYPE
                    license_value.linkname = link_target
                    license_value.mode = 0o777
                    bundle.addfile(license_value)

        def write_manifests(
            source: Path,
        ) -> tuple[Path, Path, dict[str, object]]:
            logical_entry = {
                "path": link_relative,
                "target": link_target,
                "byte_length": len(link_target.encode("utf-8")),
                "sha256": hashlib.sha256(
                    link_target.encode("utf-8")
                ).hexdigest(),
                "git_mode": "120000",
                "git_oid": builder._git_object_sha1(
                    "blob",
                    link_target.encode("utf-8"),
                ),
                "materialized_in_archive_as": "regular",
                "materialized_mode": "0644",
            }
            entries: list[dict[str, object]] = [
                {
                    "path": ".",
                    "kind": "directory",
                    "mode": f"{stat.S_IMODE(source.lstat().st_mode):04o}",
                }
            ]
            for path in sorted(
                source.rglob("*"),
                key=lambda value: (
                    value.relative_to(source).as_posix().encode("utf-8")
                ),
            ):
                relative = path.relative_to(source).as_posix()
                metadata = path.lstat()
                entry: dict[str, object] = {
                    "path": relative,
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                }
                if stat.S_ISDIR(metadata.st_mode):
                    entry["kind"] = "directory"
                else:
                    self.assertTrue(stat.S_ISREG(metadata.st_mode))
                    content = path.read_bytes()
                    entry.update(
                        {
                            "kind": "regular",
                            "byte_length": len(content),
                            "sha256": hashlib.sha256(content).hexdigest(),
                            "git_mode": (
                                "120000"
                                if relative == link_relative
                                else (
                                    "100755"
                                    if metadata.st_mode & 0o111
                                    else "100644"
                                )
                            ),
                            "git_oid": builder._git_object_sha1(
                                "blob", content
                            ),
                        }
                    )
                entries.append(entry)
            inventory = hashlib.sha256(
                json.dumps(
                    entries,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
            member_manifest = source.parent / "source-members.json"
            member_manifest.write_bytes(
                builder._json_bytes(
                    {
                        "schema": (
                            "trillionnium.codex-source-member-manifest.v1"
                        ),
                        "root_name": root_name,
                        "entry_count": len(entries),
                        "inventory_sha256": inventory,
                        "archive_allowed_symlinks": [],
                        "entries": entries,
                    }
                )
            )
            logical_manifest = source.parent / "logical-symlinks.json"
            logical_manifest.write_bytes(
                builder._json_bytes(
                    {
                        "schema": (
                            "trillionnium.codex-source-logical-symlinks.v1"
                        ),
                        "archive_allowed_symlinks": [],
                        "entry_count": 1,
                        "entries": [logical_entry],
                    }
                )
            )
            provider = {
                "source_identity": {
                    "source_root_name": root_name,
                    "source_entry_count": len(entries),
                    "source_inventory_sha256": inventory,
                }
            }
            return member_manifest, logical_manifest, provider

        with tempfile.TemporaryDirectory(
            prefix="provider-source-symlink-test."
        ) as temporary:
            root = Path(temporary)
            regular_archive = root / "regular-source.tar.xz"
            write_archive(regular_archive, materialize_link=True)
            with mock.patch.object(
                tarfile.TarFile,
                "extractall",
                side_effect=AssertionError("extractall must not be used"),
            ):
                extracted = builder._safe_extract_tar_xz(
                    regular_archive,
                    root / "regular-extracted",
                )
            materialized = extracted / link_relative
            self.assertFalse(materialized.is_symlink())
            self.assertEqual(
                materialized.read_bytes(),
                link_target.encode("utf-8"),
            )
            member_manifest, logical_manifest, provider = write_manifests(
                extracted
            )
            builder._verify_and_restore_codex_source_archive(
                extracted,
                member_manifest,
                logical_manifest,
                provider,
            )
            self.assertTrue(materialized.is_symlink())
            self.assertEqual(os.readlink(materialized), link_target)

            symlink_archive = root / "symlink-source.tar.xz"
            write_archive(symlink_archive, materialize_link=False)
            with self.assertRaisesRegex(
                builder.BuildError,
                "unapproved source archive symlink",
            ):
                builder._safe_extract_tar_xz(
                    symlink_archive,
                    root / "symlink-extracted",
                )

            drifted = builder._safe_extract_tar_xz(
                regular_archive,
                root / "drifted-extracted",
            )
            drifted_members, drifted_logical, drifted_provider = (
                write_manifests(drifted)
            )
            (drifted / link_relative).write_bytes(b"attacker drift")
            with self.assertRaisesRegex(
                builder.BuildError,
                "(materialized logical symlink bytes|member inventory) drifted",
            ):
                builder._verify_and_restore_codex_source_archive(
                    drifted,
                    drifted_members,
                    drifted_logical,
                    drifted_provider,
                )

            unsafe = builder._safe_extract_tar_xz(
                regular_archive,
                root / "unsafe-extracted",
            )
            unsafe_members, unsafe_logical, unsafe_provider = write_manifests(
                unsafe
            )
            unsafe_value = json.loads(
                unsafe_logical.read_text(encoding="utf-8")
            )
            unsafe_value["entries"][0]["target"] = "../COPYING"
            unsafe_value["entries"][0]["git_oid"] = builder._git_object_sha1(
                "blob", b"../COPYING"
            )
            unsafe_logical.write_bytes(builder._json_bytes(unsafe_value))
            with self.assertRaisesRegex(
                builder.BuildError,
                "logical symlink entry is unsafe",
            ):
                builder._verify_and_restore_codex_source_archive(
                    unsafe,
                    unsafe_members,
                    unsafe_logical,
                    unsafe_provider,
                )


class Aarch64ElfGateTests(unittest.TestCase):
    def test_nonpreemptible_symbol_accepts_linker_internalization(self) -> None:
        base = {
            "address": 0x400100,
            "size": 64,
            "type": "FUNC",
            "section": "7",
        }
        self.assertTrue(
            builder._is_nonpreemptible_definition(
                {**base, "binding": "GLOBAL", "visibility": "HIDDEN"},
                "FUNC",
            )
        )
        self.assertTrue(
            builder._is_nonpreemptible_definition(
                {**base, "binding": "LOCAL", "visibility": "DEFAULT"},
                "FUNC",
            )
        )
        self.assertFalse(
            builder._is_nonpreemptible_definition(
                {**base, "binding": "GLOBAL", "visibility": "DEFAULT"},
                "FUNC",
            )
        )
        self.assertFalse(
            builder._is_nonpreemptible_definition(
                {**base, "binding": "LOCAL", "visibility": "PROTECTED"},
                "FUNC",
            )
        )
        self.assertFalse(
            builder._is_nonpreemptible_definition(
                {**base, "binding": "LOCAL", "visibility": "DEFAULT"},
                "OBJECT",
            )
        )

    def test_run_fails_closed_when_complete_output_would_be_truncated(self) -> None:
        with tempfile.TemporaryDirectory(prefix="provider-run-output.") as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(
                builder.BuildError,
                "complete-output limit",
            ):
                builder._run(
                    ["/usr/bin/printf", "abcdef"],
                    cwd=root,
                    maximum_output=4,
                    require_complete_output=True,
                )
            self.assertEqual(
                builder._run(
                    ["/usr/bin/printf", "abcdef"],
                    cwd=root,
                    maximum_output=4,
                ),
                "cdef",
            )
            for invalid in (0, -1, True):
                with self.subTest(invalid=invalid), self.assertRaisesRegex(
                    builder.BuildError,
                    "positive integer",
                ):
                    builder._run(
                        ["/usr/bin/printf", "abcdef"],
                        cwd=root,
                        maximum_output=invalid,
                    )

    def test_symbol_facts_accepts_identical_symtab_and_dynsym_entries(self) -> None:
        name = "trillionnium_provider_post_final_exec_bootstrap"
        section = (
            f"  14: 0000000000400100     0 SECTION LOCAL  DEFAULT     7 {name}"
        )
        undefined = (
            f"  15: 0000000000000000     0 FUNC    GLOBAL DEFAULT   UND {name}"
        )
        first = f"  17: 0000000000400100    64 FUNC    GLOBAL HIDDEN     7 {name}"
        second = f"  29: 0000000000400100    64 FUNC    GLOBAL HIDDEN     7 {name}"
        self.assertEqual(
            builder._symbol_facts(
                "Symbol table '.dynsym' contains 18 entries:\n"
                f"{undefined}\n{first}\n"
                "Symbol table '.symtab' contains 30 entries:\n"
                f"{section}\n{second}\n",
                name,
            ),
            {
                "address": 0x400100,
                "size": 64,
                "type": "FUNC",
                "binding": "GLOBAL",
                "visibility": "HIDDEN",
                "section": "7",
            },
        )

    def test_symbol_facts_rejects_same_table_duplicates_or_cross_table_drift(
        self,
    ) -> None:
        name = "trillionnium_provider_post_final_exec_bootstrap"
        first = f"  17: 0000000000400100    64 FUNC    GLOBAL HIDDEN     7 {name}"
        identical = f"  29: 0000000000400100    64 FUNC    GLOBAL HIDDEN     7 {name}"
        distinct = f"  30: 0000000000400200    64 FUNC    GLOBAL HIDDEN     7 {name}"
        with self.assertRaisesRegex(builder.BuildError, "exactly one"):
            builder._symbol_facts(
                "Symbol table '.symtab' contains 31 entries:\n"
                f"{first}\n{identical}\n",
                name,
            )
        with self.assertRaisesRegex(builder.BuildError, "exactly one"):
            builder._symbol_facts(
                "Symbol table '.dynsym' contains 18 entries:\n"
                f"{first}\n"
                "Symbol table '.symtab' contains 31 entries:\n"
                f"{distinct}\n",
                name,
            )
        with self.assertRaisesRegex(builder.BuildError, "outside"):
            builder._symbol_facts(first, name)
        malformed = (
            f"  31: not-an-address    64 FUNC    GLOBAL HIDDEN     7 {name}"
        )
        with self.assertRaisesRegex(builder.BuildError, "malformed"):
            builder._symbol_facts(
                "Symbol table '.symtab' contains 32 entries:\n"
                f"{first}\n{malformed}\n",
                name,
            )

    @classmethod
    def setUpClass(cls) -> None:
        required = (
            "aarch64-linux-gnu-gcc",
            "aarch64-linux-gnu-objcopy",
            "aarch64-linux-gnu-strip",
            "readelf",
        )
        missing = [command for command in required if shutil.which(command) is None]
        if missing:
            raise unittest.SkipTest(f"missing AArch64 fixture tools: {missing}")
        cls.temporary = tempfile.TemporaryDirectory(prefix="provider-elf-test.")
        cls.root = Path(cls.temporary.name)
        cls.build = cls.root / "build"
        cls.build.mkdir()
        start = cls.root / "start.S"
        start.write_text(
            """.section .text.start,"ax",%progbits
.globl _start
.type _start,%function
_start:
  b _start
.size _start,.-_start
.section .data.rel.ro,"aw",%progbits
.xword _start
.zero 24
.section .note.GNU-stack,"",%progbits
""",
            encoding="utf-8",
        )
        include = DIRECTORY / "include"
        source = DIRECTORY / "src"
        common = [
            "aarch64-linux-gnu-gcc",
            "-std=c11",
            "-O2",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-lto",
            "-fno-plt",
            "-fvisibility=hidden",
            "-fno-ident",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(include),
            "-DTRILLIONNIUM_EXPECTED_UID=5901",
            "-DTRILLIONNIUM_EXPECTED_GID=5901",
        ]
        cls.core = cls.root / "core.o"
        cls.entry = cls.root / "entry.o"
        cls.start = cls.root / "start.o"
        cls.codex = cls.root / "codex"
        for source_path, destination in (
            (source / "provider_post_exec_bootstrap.c", cls.core),
            (source / "provider_post_exec_entry.S", cls.entry),
        ):
            subprocess.run(
                [*common, "-c", str(source_path), "-o", str(destination)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        subprocess.run(
            [
                "aarch64-linux-gnu-gcc",
                "-c",
                str(start),
                "-o",
                str(cls.start),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        subprocess.run(
            [
                "aarch64-linux-gnu-gcc",
                "-nostdlib",
                "-static",
                "-Wl,-z,noexecstack",
                "-Wl,-e,trillionnium_provider_post_final_exec_entry",
                f"-Wl,-Map,{cls.root / 'final.map'}",
                str(cls.core),
                str(cls.entry),
                str(cls.start),
                "-o",
                str(cls.codex),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_real_aarch64_controlled_entry_filter_and_symbol_table_pass(self) -> None:
        facts = builder._inspect_final_elf(
            self.codex, "codex", self.core, self.build, builder.load_recipe()
        )
        self.assertEqual(facts["elf_type"], "EXEC")
        self.assertEqual(facts["mechanism"], "controlled_entry_before_crt")
        self.assertEqual(facts["controlled_entry"]["size"], 32)
        self.assertEqual(facts["entry_address"], facts["controlled_entry"]["address"])
        self.assertEqual(facts["filter"]["byte_length"], 37 * 8)
        self.assertTrue(facts["has_symbol_table"])
        self.assertFalse(facts["has_dynamic_segment"])
        self.assertFalse(facts["has_preinit_array"])

    def test_stripped_or_filter_mutated_payload_fails_closed(self) -> None:
        stripped = self.root / "codex-stripped"
        subprocess.run(
            [
                "aarch64-linux-gnu-strip",
                "--strip-all",
                "-o",
                str(stripped),
                str(self.codex),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        with self.assertRaisesRegex(builder.BuildError, "stripped"):
            builder._inspect_final_elf(
                stripped,
                "codex",
                self.core,
                self.root / "stripped-inspection",
                builder.load_recipe(),
            )

        mutated = self.root / "codex-filter-mutated"
        shutil.copyfile(self.codex, mutated)
        filter_bytes = self.root / "mutated-filter.bin"
        subprocess.run(
            [
                "aarch64-linux-gnu-objcopy",
                "--dump-section",
                f".trillionnium.provider_filter={filter_bytes}",
                str(mutated),
            ],
            check=True,
        )
        content = bytearray(filter_bytes.read_bytes())
        content[-1] ^= 1
        filter_bytes.write_bytes(content)
        subprocess.run(
            [
                "aarch64-linux-gnu-objcopy",
                "--update-section",
                f".trillionnium.provider_filter={filter_bytes}",
                str(mutated),
            ],
            check=True,
        )
        with self.assertRaisesRegex(
            builder.BuildError, "differ from the retained bootstrap object"
        ):
            builder._verify_filter_object_binding(
                mutated, self.core, self.root / "mutated-filter-binding"
            )

    def test_retained_artifact_verifier_rejects_symlink_and_digest_drift(self) -> None:
        artifact = builder._artifact(self.codex, "codex")
        with tempfile.TemporaryDirectory(prefix="provider-retained-test.") as temporary:
            root = Path(temporary)
            (root / "real").write_bytes(self.codex.read_bytes())
            (root / "codex").symlink_to("real")
            with self.assertRaisesRegex(builder.BuildError, "aliased"):
                with builder._retained_artifact_snapshots(root, [artifact]):
                    pass

            (root / "codex").unlink()
            shutil.copyfile(self.codex, root / "codex")
            drifted = dict(artifact)
            drifted["sha256"] = "1" * 64
            with self.assertRaisesRegex(builder.BuildError, "digest drifted"):
                with builder._retained_artifact_snapshots(root, [drifted]):
                    pass

            with builder._retained_artifact_snapshots(
                root, [artifact]
            ) as copies:
                private = builder._artifact_path(copies, artifact)
                self.assertNotEqual(private.parent, root)
                self.assertEqual(private.read_bytes(), self.codex.read_bytes())

    def test_retained_artifact_rejects_parent_and_root_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-parent-symlink-test."
        ) as temporary:
            base = Path(temporary)
            root = base / "root"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            payload = outside / "payload"
            payload.write_bytes(self.codex.read_bytes())
            artifact = builder._artifact(payload, "parent/payload")
            (root / "parent").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(builder.BuildError, "aliased"):
                with builder._retained_artifact_snapshots(root, [artifact]):
                    pass

            alias = base / "root-alias"
            alias.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(builder.BuildError, "root.*aliased"):
                with builder._retained_artifact_snapshots(alias, []):
                    pass

    def test_retained_artifact_replacement_drift_and_openat2_fallback(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="provider-retained-drift-test."
        ) as temporary:
            root = Path(temporary)
            source = root / "codex"
            source.write_bytes(self.codex.read_bytes())
            artifact = builder._artifact(source, "codex")
            original_copy = builder._copy_descriptor_bytes

            def mutate_after_copy(
                source_descriptor: int, destination_descriptor: int
            ) -> tuple[int, str]:
                result = original_copy(source_descriptor, destination_descriptor)
                source.write_bytes(b"replacement")
                return result

            with (
                mock.patch.object(
                    builder,
                    "_copy_descriptor_bytes",
                    side_effect=mutate_after_copy,
                ),
                self.assertRaisesRegex(builder.BuildError, "identity changed"),
            ):
                with builder._retained_artifact_snapshots(root, [artifact]):
                    pass

            source.write_bytes(self.codex.read_bytes())
            artifact = builder._artifact(source, "codex")

            class NoOpenAt2:
                @staticmethod
                def syscall(*_: object) -> int:
                    builder.ctypes.set_errno(errno.ENOSYS)
                    return -1

            with mock.patch.object(
                builder.ctypes, "CDLL", return_value=NoOpenAt2()
            ):
                with builder._retained_artifact_snapshots(root, [artifact]):
                    descriptor = builder._open_fixed_root(root)
                    try:
                        opened, resolver = builder._open_beneath_with_resolver(
                            descriptor, "codex"
                        )
                        os.close(opened)
                    finally:
                        os.close(descriptor)
                    self.assertEqual(
                        resolver,
                        builder.RETAINED_ARTIFACT_RESOLVER_COMPONENT_WALK,
                    )

    def test_component_walk_rejects_unsafe_paths_and_symlinks(self) -> None:
        class NoOpenAt2:
            @staticmethod
            def syscall(*_: object) -> int:
                builder.ctypes.set_errno(errno.ENOSYS)
                return -1

        with tempfile.TemporaryDirectory(
            prefix="provider-component-walk-test."
        ) as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            (outside / "payload").write_bytes(b"outside")
            (root / "real").mkdir()
            (root / "real" / "payload").write_bytes(b"inside")
            (root / "parent-link").symlink_to(
                root / "real", target_is_directory=True
            )
            (root / "final-link").symlink_to(root / "real" / "payload")
            descriptor = builder._open_fixed_root(root)
            try:
                with mock.patch.object(
                    builder.ctypes, "CDLL", return_value=NoOpenAt2()
                ):
                    for logical in (
                        "",
                        "/real/payload",
                        "real//payload",
                        "real/./payload",
                        "real/../outside/payload",
                        "real/payload/",
                    ):
                        with self.subTest(logical=logical), self.assertRaisesRegex(
                            builder.BuildError, "logical path is unsafe"
                        ):
                            builder._open_beneath_with_resolver(
                                descriptor, logical
                            )
                    for logical in ("parent-link/payload", "final-link"):
                        with self.subTest(logical=logical), self.assertRaisesRegex(
                            builder.BuildError, "aliased"
                        ):
                            builder._open_beneath_with_resolver(
                                descriptor, logical
                            )
            finally:
                os.close(descriptor)

    def test_openat2_einval_does_not_downgrade_to_component_walk(self) -> None:
        class PolicyRejectedOpenAt2:
            @staticmethod
            def syscall(*_: object) -> int:
                builder.ctypes.set_errno(errno.EINVAL)
                return -1

        with (
            mock.patch.object(
                builder.ctypes,
                "CDLL",
                return_value=PolicyRejectedOpenAt2(),
            ),
            mock.patch.object(builder, "_openat_component_walk") as fallback,
            self.assertRaisesRegex(
                builder.BuildError, "policy was rejected.*fallback is forbidden"
            ),
        ):
            builder._open_beneath_with_resolver(0, "payload")
        fallback.assert_not_called()

    def test_component_walk_holds_parent_fd_across_directory_replacement(
        self,
    ) -> None:
        class NoOpenAt2:
            @staticmethod
            def syscall(*_: object) -> int:
                builder.ctypes.set_errno(errno.ENOSYS)
                return -1

        with tempfile.TemporaryDirectory(
            prefix="provider-component-walk-race-test."
        ) as temporary:
            root = Path(temporary)
            parent = root / "parent"
            pinned = root / "pinned-parent"
            parent.mkdir()
            (parent / "payload").write_bytes(b"pinned-original")
            root_descriptor = builder._open_fixed_root(root)
            original_open = os.open
            swapped = False

            def swapping_open(
                path: object,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal swapped
                descriptor = original_open(
                    path, flags, mode, dir_fd=dir_fd
                )
                if path == "parent" and not swapped:
                    swapped = True
                    parent.rename(pinned)
                    parent.mkdir()
                    (parent / "payload").write_bytes(b"replacement")
                return descriptor

            try:
                with (
                    mock.patch.object(
                        builder.ctypes, "CDLL", return_value=NoOpenAt2()
                    ),
                    mock.patch.object(
                        builder.os, "open", side_effect=swapping_open
                    ),
                ):
                    descriptor, resolver = builder._open_beneath_with_resolver(
                        root_descriptor, "parent/payload"
                    )
                try:
                    self.assertEqual(os.read(descriptor, 64), b"pinned-original")
                finally:
                    os.close(descriptor)
                self.assertTrue(swapped)
                self.assertEqual(
                    resolver,
                    builder.RETAINED_ARTIFACT_RESOLVER_COMPONENT_WALK,
                )
            finally:
                os.close(root_descriptor)

    def test_retained_resolver_record_rejects_unknown_or_tampered_values(
        self,
    ) -> None:
        for resolver in builder.ALLOWED_RETAINED_ARTIFACT_RESOLVERS:
            self.assertEqual(
                builder._validate_retained_artifact_resolver(
                    resolver, "test receipt"
                ),
                resolver,
            )
        for resolver in (
            "",
            "openat2",
            "dirfd-component-walk:O_NOFOLLOW",
            ["openat2"],
        ):
            with self.subTest(resolver=resolver), self.assertRaisesRegex(
                builder.BuildError, "resolver is not allowed"
            ):
                builder._validate_retained_artifact_resolver(
                    resolver, "test receipt"
                )


if __name__ == "__main__":
    unittest.main()
