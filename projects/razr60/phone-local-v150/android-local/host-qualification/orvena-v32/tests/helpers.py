import ast
import contextlib
import copy
import hashlib
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
CANDIDATE = ROOT / "candidate"
TEST_SOURCE = ROOT / "tests/fixtures/v32-source-inputs"
sys.dont_write_bytecode = True
sys.path.insert(0, str(CANDIDATE / "drivers"))
import qualification_scope as qs
import phone_acceptance as ac
import phone_suite as ps


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); sys.modules[name] = value
    spec.loader.exec_module(value); return value


m = module(CANDIDATE / "orvena_qualification.py", "scoped_orvena_stages_tested")
o = module(CANDIDATE / "ordinary/ordinary_launcher.py", "scoped_ordinary_launcher_tested")
observer = module(CANDIDATE / "ordinary/ordinary_start_observer.py", "scoped_ordinary_observer_tested")
issuer = module(CANDIDATE / "prepare_binding.py", "scoped_issuer_tested")
normalize = module(CANDIDATE / "normalize_roles.py", "scoped_roles_tested")


def basic_context(axis="npu"):
    runtime = dict(schema="hepta.local-runtime.v2", model_profile=qs.PROFILE, compute=axis, context_tokens=8192, threads=4)
    return dict(binding_sha256="b" * 64, scope_sha256="c" * 64, build_identity_sha256="d" * 64,
        device_target=dict(serial="SYNTHETIC", logical_display_id=0, physical_display_id="123456789", input_width=1224, input_height=2992),
        complete_source_inventory_sha256="e" * 64, portable_source_inventory_sha256=issuer.PORTABLE_INVENTORY_SHA,
        source_commit=issuer.SOURCE_COMMIT, runtime_config_sha256=qs.sha(qs.encoded(runtime)), runtime_config=runtime,
        app_uid=10481, candidate=dict(package=qs.PACKAGE, apk_sha256="f" * 64, version_code=32,
            model_profile=qs.PROFILE, model_sha256=qs.MODEL_SHA, compute=axis, context_tokens=8192, threads=4))


def observation(package, oid="a" * 32, window=7):
    return dict(observation_id=oid, package=package, window_id=window, screen_width=1224, screen_height=2992,
        window=dict(scope="active_root_only", metadata_status="observed", window_id=window, type=1, display_id=0,
                    root_bounds=[0, 0, 1224, 2992], bounds=[0, 0, 1224, 2992], root_class="android.widget.FrameLayout"),
        nodes=[])


def binding_fixture(output, axis="npu"):
    """Synthetic parser inputs only. This bypasses no real build/phone guard."""
    output = Path(output); output.mkdir(parents=True)
    q = basic_context(axis)
    expected = qs.strict(qs.read(CANDIDATE / "reference/EXPECTED-FULL-V32-INVENTORY.json"))
    # Public source hashes; synthetic wrapper must never be cited as a real build.
    inputs = qs.strict(qs.read(ROOT / "tests/fixtures/build-asset-inputs.json"))
    asset = qs.encoded(dict(schema="hepta.actual-build-inputs.v1", version_code=32, source_inputs=inputs))
    mac = qs.encoded(dict(schema="synthetic.test-compiler-wrapper.v1", source_inputs=inputs))
    integration = qs.encoded(dict(schema="hepta.independent-v32-source-integration.v1", source_commit=issuer.SOURCE_COMMIT,
        source_tree="81955c2053ba24cab0783c9cb7636a49c0f186de",
        actual_source_assembly_verified=True, file_count=1194, files=expected["files"],
        portable_inventory_sha256=issuer.PORTABLE_INVENTORY_SHA, synthetic_test_fixture=True))
    q["build_identity_sha256"] = qs.sha(asset); q["complete_source_inventory_sha256"] = qs.sha(integration)
    scope = dict(schema="hepta.qualification-scope.v1", enabled=True, qualification_id="synthetic-helper-test",
        build_identity_sha256=qs.sha(asset), runtime_config_sha256=q["runtime_config_sha256"],
        hepta_apk_sha256=q["candidate"]["apk_sha256"], hepta_version_code=32,
        launcher_component="com.motorola.launcher3/com.android.launcher3.CustomizationPanelLauncher")
    roles = {}
    files = {}
    for index, (role, package) in enumerate(qs.ROLES.items()):
        data = qs.encoded(observation(package, str(index + 1) * 32))
        files["observations/" + role + ".json"] = data
        rows = [{"key": "base", "sha256": qs.sha(("synthetic-apk-" + role).encode())}]
        digest = qs.apk_set_sha(rows)
        roles[role] = dict(package=package, uid=1000 + index, version_code=36, enabled=True,
                           apk_rows=rows, apk_set_sha256=digest, stable_before_after=True)
        scope.update({role + "_package": package, role + "_uid": 1000 + index, role + "_version_code": 36,
                      role + "_apk_set_sha256": digest, role + "_observation_sha256": qs.sha(data)})
    roles_raw = qs.encoded(dict(schema="hepta.scope-installed-role-identities.v1", roles=roles,
        launcher_component=scope["launcher_component"], original_evidence=[dict(path="/synthetic-only", sha256="1" * 64)]))
    static = qs.encoded(dict(schema="hepta.local-model.static-acceptance.v3", package=qs.PACKAGE, version_code=32,
        apk_sha256=q["candidate"]["apk_sha256"], permissions=[], actual_build_identity_asset=qs.ASSET_NAME,
        actual_build_identity_sha256=qs.sha(asset)))
    files.update({"qualification-scope.json": qs.encoded(scope), "build-identity.json": asset,
        "runtime-config.json": qs.encoded(q["runtime_config"]), "mac-build-receipt.json": mac,
        "static-acceptance.json": static, "role-identities.json": roles_raw, "source-integration-manifest.json": integration})
    q.update(schema=qs.SCHEMA, phone_contacted=False, scope_sha256=qs.sha(files["qualification-scope.json"]),
        source_directory=str(TEST_SOURCE.resolve()), sampler_requested=qs.expected_sampler(), synthetic_test_fixture=True,
        files={name: dict(bytes=len(data), sha256=qs.sha(data)) for name, data in files.items()})
    q.pop("binding_sha256"); q.pop("runtime_config")
    for name, data in files.items(): qs.private_write(output / name, data)
    raw = qs.encoded(q); qs.private_write(output / "BINDING.json", raw)
    return qs.load_binding(output / "BINDING.json", qs.sha(raw))


def production_scope_fixture(output):
    source = ROOT / "tests/fixtures/production-scope-positive/task"
    target = Path(output) / "task"; shutil.copytree(source, target)
    raw_scope = (target / "qualification-scope.json").read_bytes(); scope = qs.strict(raw_scope)
    q = dict(binding_sha256="b" * 64, scope_sha256=qs.sha(raw_scope), scope=scope,
             build_identity_sha256=scope["build_identity_sha256"], runtime_config_sha256=scope["runtime_config_sha256"],
             raw_files={"qualification-scope.json": raw_scope, "build-identity.json": (target / "build-identity.json").read_bytes(),
                        "runtime-config.json": (target / "scope-runtime-config.json").read_bytes()})
    owner = qs.strict((target / "owner.json").read_bytes())
    return q, owner["task_id"], owner["instruction"]


def package_manifest():
    files = {str(path.relative_to(CANDIDATE)): dict(bytes=path.stat().st_size, sha256=qs.sha(path.read_bytes()))
             for path in sorted(CANDIDATE.rglob("*")) if path.is_file() and "__pycache__" not in path.parts
             and path.name != "PACKAGE-MANIFEST.json"}
    return dict(schema="hepta.orvena-v32-scoped-package.v1", source_commit=issuer.SOURCE_COMMIT, files=files)


def build_report_fields(q):
    return dict(source_commit=issuer.SOURCE_COMMIT, source_tree='81955c2053ba24cab0783c9cb7636a49c0f186de',
        complete_source_inventory_sha256=q['complete_source_inventory_sha256'], portable_source_inventory_sha256=q['portable_source_inventory_sha256'],
        actual_build_identity_sha256=q['build_identity_sha256'], actual_build_identity_asset=qs.ASSET_NAME,
        build_receipt_sha256=qs.sha(q['raw_files']['mac-build-receipt.json']),
        static_acceptance_sha256=qs.sha(q['raw_files']['static-acceptance.json']),
        host_checks_sha256='5' * 64, host_gate_qualification_sha256='6' * 64)


def synthetic_upgrade_receipt(q, upgrade_sha='7' * 64, selector_sha='8' * 64):
    apk = q['candidate']['apk_sha256']
    identity = dict(package=qs.PACKAGE, apk_sha256=apk, version_code=32, uid=q['app_uid'])
    return dict(schema='hepta.upgrade-v32-once.v1', status='upgrade_verified', phone_contacted=True,
        new_apk_sha256=apk, expected_uid=q['app_uid'], script_sha256=upgrade_sha, selector_sha256=selector_sha,
        install_readback_verified=True, ordinary_launch_verified=True,
        permission_free_host_apk_bound_to_installed_bytes=True, same_signing_certificate_verified=True,
        identity_after_main=identity, identity_after_install=copy.deepcopy(identity), **build_report_fields(q),
        host_apks=dict(new=dict(path='/synthetic-only.apk', sha256=apk, bytes=128),
          new_permission_evidence=dict(apk_sha256=apk, apk_bytes=128, host_apk='/synthetic-only.apk',
              method=observer.PERMISSION_PROOF_METHOD, internet_permission_declared=False, requested_permissions=[],
              permissions_stdout_sha256='9' * 64, manifest_stdout_sha256='0' * 64)),
        synthetic_test_fixture=True)


def synthetic_selection_receipt(q, selector_sha='8' * 64):
    identity = dict(package=qs.PACKAGE, apk_sha256=q['candidate']['apk_sha256'], version_code=32, uid=q['app_uid'])
    value = dict(schema='hepta.select-runtime-once.v3-observed-accessibility', status='configuration_verified', phone_contacted=True,
        script_sha256=selector_sha, expected_apk_sha256=q['candidate']['apk_sha256'], expected_uid=q['app_uid'],
        selected_config=q['runtime_config'], final_configuration_sha256=q['runtime_config_sha256'], model_full_sha_verified=qs.MODEL_SHA,
        selected_model=dict(file='Orvena-4B.Q4_K_M.gguf', bytes=qs.MODEL_BYTES, sha256=qs.MODEL_SHA, architecture='qwen35'),
        configuration_replacement_verified=True, ordinary_launch_verified=True, journals_unchanged=True,
        final_no_native_worker_observed=True, identity_before=identity, identity_after=copy.deepcopy(identity),
        **build_report_fields(q), synthetic_test_fixture=True)
    candidate = dict(q['candidate'], uid=q['app_uid'], config_sha256=q['runtime_config_sha256'], **build_report_fields(q))
    return value, candidate
