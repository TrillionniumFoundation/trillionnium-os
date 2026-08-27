#!/usr/bin/env python3
"""Materialize one disabled common Codex AgentManifest from measured inputs.

The manifest's historically named ``identity_key_sha256`` field is the exact
measured common Codex launcher executable SHA-256.  It is not a public-key
digest and is never accepted from a caller.  This stage reuses the rootfs v9
contract materializer's retained-FD input, receipt, ELF, and publication gates,
then emits one canonical, read-only manifest for the later rootfs contract
materializer.  It does not package a rootfs, mutate Android/vendor sources,
admit the P0.1 launcher, or claim product/device/release authority.
"""

from __future__ import annotations

import argparse
import copy
from pathlib import Path
import sys
import types


# Importing the adjacent custody implementation must not create an ignored
# __pycache__ entry and invalidate a source BOM frozen immediately beforehand.
sys.dont_write_bytecode = True


EVIDENCE_FACTORY = Path(__file__).resolve().parent
ROOTFS_SOURCE = EVIDENCE_FACTORY / "materialize_rootfs_contract.py"
ROOTFS_MODULE_NAME = "_trillionnium_materialize_rootfs_contract_source"


def load_rootfs_source() -> types.ModuleType:
    """Execute the adjacent reviewed source without consulting ``.pyc`` files."""

    source = ROOTFS_SOURCE.read_bytes()
    code = compile(source, str(ROOTFS_SOURCE), "exec", dont_inherit=True)
    module = types.ModuleType(ROOTFS_MODULE_NAME)
    module.__file__ = str(ROOTFS_SOURCE)
    module.__package__ = ""
    if ROOTFS_MODULE_NAME in sys.modules:
        raise RuntimeError("rootfs source module name is already occupied")
    sys.modules[ROOTFS_MODULE_NAME] = module
    try:
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(ROOTFS_MODULE_NAME, None)
        raise
    return module


rootfs = load_rootfs_source()


LAUNCHER_FILENAME_PREFIX = "trillionnium-codex-agent-"
MANIFEST_FIELDS = {
    "adapter",
    "adapter_version",
    "agent_id",
    "api_version",
    "enabled",
    "health",
    "identity_key_sha256",
    "network_policy",
    "peer_gid",
    "peer_uid",
    "registered_at_unix_ms",
    "selinux_domain",
    "updated_at_unix_ms",
}
TEMPLATE_REQUIRED_FIELDS = MANIFEST_FIELDS - {
    "registered_at_unix_ms",
    "updated_at_unix_ms",
}


def manifest_policy(template: dict[str, object]) -> dict[str, object]:
    inputs = rootfs.require_mapping(template["inputs"], "template.inputs")
    policy = rootfs.require_mapping(
        inputs["agent_manifest"], "template.inputs.agent_manifest"
    )
    required = rootfs.require_mapping(
        policy["required_fields"],
        "template.inputs.agent_manifest.required_fields",
    )
    allowed = policy["allowed_fields"]
    if set(required) != TEMPLATE_REQUIRED_FIELDS or set(allowed) != MANIFEST_FIELDS:
        rootfs.deny("template AgentManifest field closure is not the common v9 set")
    return policy


def adapter_version_from_launcher_binding(common_evidence: dict[str, object]) -> str:
    bindings = rootfs.require_mapping(
        common_evidence["artifact_bindings"], "common artifact bindings"
    )
    launcher = rootfs.require_mapping(
        bindings["codex_launcher"], "common Codex launcher binding"
    )
    filename = launcher.get("file")
    if not isinstance(filename, str) or not filename.startswith(
        LAUNCHER_FILENAME_PREFIX
    ):
        rootfs.deny("common Codex launcher filename cannot derive adapter version")
    version = filename[len(LAUNCHER_FILENAME_PREFIX) :]
    if not version:
        rootfs.deny("common Codex launcher filename has an empty adapter version")
    return version


def materialize_manifest(
    template: dict[str, object],
    common_evidence: dict[str, object],
    launcher_sha256: str,
) -> dict[str, object]:
    policy = manifest_policy(template)
    required = rootfs.require_mapping(
        policy["required_fields"],
        "template.inputs.agent_manifest.required_fields",
    )
    manifest = copy.deepcopy(required)
    manifest["adapter_version"] = adapter_version_from_launcher_binding(
        common_evidence
    )
    manifest["identity_key_sha256"] = launcher_sha256
    manifest["registered_at_unix_ms"] = 0
    manifest["updated_at_unix_ms"] = 0
    if set(manifest) != MANIFEST_FIELDS:
        rootfs.deny("materialized common AgentManifest field closure drifted")
    validated, _adapter_version = rootfs.validate_manifest(
        manifest,
        policy,
        launcher_sha256,
    )
    if validated != manifest:
        rootfs.deny("materialized common AgentManifest validation changed its fields")
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--common-artifact-set-receipt", type=Path, required=True)
    parser.add_argument("--common-launcher-ab-receipt", type=Path, required=True)
    parser.add_argument("--daemon", type=Path, required=True)
    parser.add_argument("--codex-launcher", type=Path, required=True)
    parser.add_argument("--system-api-tool", type=Path, required=True)
    parser.add_argument("--accessibility-tool", type=Path, required=True)
    parser.add_argument("--system-api-replay-sync", type=Path, required=True)
    parser.add_argument(
        "--source-date-epoch",
        type=rootfs.parse_source_date_epoch,
        required=True,
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser


def run(args: argparse.Namespace) -> None:
    with rootfs.PublicationAwareExitStack() as stack:
        template_input = stack.enter_context(
            rootfs.FrozenInput.open(
                args.template,
                "template",
                rootfs.MAX_TEMPLATE_BYTES,
            )
        )
        common_artifact_set_receipt = stack.enter_context(
            rootfs.FrozenInput.open(
                args.common_artifact_set_receipt,
                "common_artifact_set_receipt",
                rootfs.MAX_COMMON_RECEIPT_BYTES,
            )
        )
        common_launcher_ab_receipt = stack.enter_context(
            rootfs.FrozenInput.open(
                args.common_launcher_ab_receipt,
                "common_launcher_ab_receipt",
                rootfs.MAX_LAUNCHER_AB_RECEIPT_BYTES,
            )
        )
        daemon = stack.enter_context(
            rootfs.FrozenInput.open(
                args.daemon,
                "daemon",
                rootfs.MAX_BINARY_BYTES,
                require_executable=True,
            )
        )
        launcher = stack.enter_context(
            rootfs.FrozenInput.open(
                args.codex_launcher,
                "codex_launcher",
                rootfs.MAX_BINARY_BYTES,
                require_executable=True,
            )
        )
        system_api_tool = stack.enter_context(
            rootfs.FrozenInput.open(
                args.system_api_tool,
                "system_api_tool",
                rootfs.MAX_BINARY_BYTES,
                require_executable=True,
            )
        )
        accessibility_tool = stack.enter_context(
            rootfs.FrozenInput.open(
                args.accessibility_tool,
                "accessibility_tool",
                rootfs.MAX_BINARY_BYTES,
                require_executable=True,
            )
        )
        replay_sync = stack.enter_context(
            rootfs.FrozenInput.open(
                args.system_api_replay_sync,
                "system_api_replay_sync",
                rootfs.MAX_BINARY_BYTES,
                require_executable=True,
            )
        )

        template = rootfs.validate_template(
            rootfs.strict_json_bytes(template_input.read_all(), "template")
        )
        rootfs.verify_aarch64_elf(daemon, require_static=False)
        rootfs.verify_aarch64_elf(launcher, require_static=True)
        rootfs.verify_aarch64_elf(system_api_tool, require_static=False)
        rootfs.verify_aarch64_elf(accessibility_tool, require_static=False)
        rootfs.verify_aarch64_elf(replay_sync, require_static=False)

        common_receipt_raw = common_artifact_set_receipt.read_all()
        common_evidence = rootfs.validate_common_artifact_set(
            rootfs.strict_json_bytes(
                common_receipt_raw,
                "common artifact-set receipt",
            ),
            common_receipt_raw,
            common_artifact_set_receipt,
            {
                "daemon": daemon,
                "codex_launcher": launcher,
                "system_api_tool": system_api_tool,
                "accessibility_tool": accessibility_tool,
                "replay_sync_helper": replay_sync,
            },
        )
        launcher_ab_raw = common_launcher_ab_receipt.read_all()
        rootfs.validate_common_launcher_ab(
            rootfs.strict_json_bytes(
                launcher_ab_raw,
                "common launcher A/B receipt",
            ),
            launcher_ab_raw,
            common_launcher_ab_receipt,
            common_receipt_raw,
            common_evidence,
        )
        content = rootfs.canonical_json(
            materialize_manifest(template, common_evidence, launcher.sha256)
        )

        frozen_inputs = (
            template_input,
            common_artifact_set_receipt,
            common_launcher_ab_receipt,
            daemon,
            launcher,
            system_api_tool,
            accessibility_tool,
            replay_sync,
        )
        for frozen in frozen_inputs:
            frozen.verify_unchanged()

        def verify_inputs_before_commit() -> None:
            for frozen in frozen_inputs:
                frozen.verify_final()

        rootfs.publish_new(
            args.output,
            content,
            args.source_date_epoch,
            verify_inputs_before_commit,
            post_commit_teardown=stack.close_retained_inputs,
        )


def main() -> int:
    args = build_parser().parse_args()
    try:
        run(args)
    except (rootfs.MaterializerError, OSError) as error:
        print(f"common AgentManifest materialization denied: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
