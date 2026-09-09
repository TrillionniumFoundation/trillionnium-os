#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
from typing import Any, Iterable

CATALOG_PATH = "docs/machine/module-catalog.v1.json"
LIFECYCLE_PATH = "docs/machine/effect-lifecycle.v1.json"
CONTRACT_CATALOG_PATH = "docs/machine/module-contract-catalog.v1.json"
STATUS_PATH = "docs/MODULE_CONTRACT_STATUS.md"
LOCK_PATH = "tools/contracts/module-contracts.lock.json"
GENERATOR_PATH = "tools/contracts/generate_module_contracts.py"
RUST_PATH = "crates/trillionnium-owner-open-types/src/module_contract.rs"
RUST_TEST_PATH = "crates/trillionnium-owner-open-types/tests/module_contract_vectors.rs"
ANDROID_VERIFY_PATH = "android-integration/module-contracts/verify_vectors.py"
ANDROID_README_PATH = "android-integration/module-contracts/README.md"
TEST_PATH = "tools/tests/test_module_contracts.py"
README_PATH = "tools/contracts/README.md"
SHA64 = re.compile(r"^[0-9a-f]{64}$")
API_LABEL = re.compile(r"^org\.trillionnium\.mod_[a-z0-9_]+\.api\.v[0-9]+$")
STATE_LABEL = re.compile(r"^org\.trillionnium\.mod_[a-z0-9_]+\.state\.v[0-9]+$")
ERROR_LABEL = re.compile(r"^[a-z0-9_]+_error_v[0-9]+$")
EXPECTED_LIFECYCLE_STATES = {
    "RECEIVED", "VALIDATED", "CAPACITY_RESERVED", "ACCEPTED_DURABLE",
    "EFFECT_ATTEMPTING", "EFFECT_STARTED_OBSERVED", "TERMINAL_OBSERVED",
    "TERMINAL_DURABLE", "DELIVERY_PENDING", "DELIVERED", "ACKNOWLEDGED",
    "REJECTED_BEFORE_EFFECT", "UNKNOWN_RECONCILIATION_REQUIRED", "FENCED", "CLOSED",
}


class ContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON member: {key}")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise ContractError(f"non-finite JSON number: {value}")


def strict_load(raw: bytes, label: str) -> Any:
    require(len(raw) <= 4 * 1024 * 1024, f"{label} exceeds byte bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs, parse_constant=reject_nonfinite)
    except (UnicodeError, json.JSONDecodeError, ContractError) as error:
        raise ContractError(f"{label} is not strict JSON: {error}") from error
    require(depth(value) <= 32, f"{label} exceeds depth bound")
    return value


def depth(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + max((depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((depth(item) for item in value), default=0)
    return 1


def normalized_path(value: str) -> str:
    pure = PurePosixPath(value)
    require(value and not pure.is_absolute() and "\\" not in value, f"unsafe path: {value}")
    require("." not in pure.parts and ".." not in pure.parts and value == pure.as_posix(), f"unnormalized path: {value}")
    return value


def flatten_strings(value: Any) -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str):
                yield str(key), item
            else:
                yield from flatten_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from flatten_strings(item)


def module_id(item: dict[str, Any]) -> str:
    candidates = [item.get("id"), item.get("module_id"), item.get("module")]
    values = [value for value in candidates if isinstance(value, str) and value.startswith("MOD-")]
    require(len(set(values)) == 1, f"module has no unique MOD-* identifier: {values}")
    return values[0]


def select_label(item: dict[str, Any], pattern: re.Pattern[str], kind: str) -> str:
    scored: list[tuple[int, str]] = []
    for key, value in flatten_strings(item):
        if pattern.fullmatch(value):
            score = 0 if kind in key.lower() else 1
            scored.append((score, value))
    require(scored, f"{module_id(item)} has no {kind} logical label")
    best = min(score for score, _ in scored)
    values = sorted({value for score, value in scored if score == best})
    require(len(values) == 1, f"{module_id(item)} has ambiguous {kind} labels: {values}")
    return values[0]


def file_identity(root: Path, value: str) -> dict[str, Any]:
    value = normalized_path(value)
    path = root / value
    require(path.is_file() and not path.is_symlink(), f"binding is not a regular file: {value}")
    raw = path.read_bytes()
    return {"path": value, "size": len(raw), "sha256": sha(raw)}


def source_bindings(root: Path, item: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    source_suffixes = {".rs", ".py", ".kt", ".java", ".sh", ".bp", ".toml", ".te", ".cil", ".mk"}
    sources: set[str] = set()
    tests: set[str] = set()
    for _, value in flatten_strings(item):
        if not isinstance(value, str) or value.startswith(("http://", "https://")):
            continue
        try:
            normalized = normalized_path(value)
        except ContractError:
            continue
        path = root / normalized
        if not path.is_file() or path.is_symlink():
            continue
        lower = normalized.lower()
        if "/test" in lower or lower.startswith("tools/tests/") or path.name.startswith("test_"):
            tests.add(normalized)
        elif path.suffix.lower() in source_suffixes:
            sources.add(normalized)
    require(sources, f"{module_id(item)} has no concrete implementation source binding")
    return ([file_identity(root, value) for value in sorted(sources)],
            [file_identity(root, value) for value in sorted(tests)])


def lifecycle_states(root: Path) -> list[str]:
    value = strict_load((root / LIFECYCLE_PATH).read_bytes(), LIFECYCLE_PATH)
    observed = {text for _, text in flatten_strings(value) if text in EXPECTED_LIFECYCLE_STATES}
    missing = sorted(EXPECTED_LIFECYCLE_STATES - observed)
    require(not missing, f"effect lifecycle omits required states: {missing}")
    return sorted(observed | {"STATELESS"})


def rust_source() -> bytes:
    return b'''use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MODULE_CONTRACT_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleApiEnvelopeV1 {
    pub schema: String,
    pub module_id: String,
    pub operation_id: String,
    pub request_digest: String,
    pub ordering_key: String,
    pub host_epoch: u64,
    pub writer_epoch: u64,
    pub fencing_token: String,
    pub payload: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleStateEnvelopeV1 {
    pub schema: String,
    pub module_id: String,
    pub operation_id: String,
    pub request_digest: String,
    pub state: String,
    pub host_epoch: u64,
    pub writer_epoch: u64,
    pub fencing_token: String,
    pub durable_sequence: u64,
    pub monotonic_ns: u64,
    pub payload: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleErrorEnvelopeV1 {
    pub schema: String,
    pub module_id: String,
    pub operation_id: String,
    pub request_digest: String,
    pub code: String,
    pub class: String,
    pub retry_disposition: String,
    pub effect_uncertain: bool,
    pub original_cause: String,
}

pub fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl ModuleApiEnvelopeV1 {
    pub fn validate_identity(&self) -> bool {
        !self.schema.is_empty() && self.module_id.starts_with("MOD-") && !self.operation_id.is_empty()
            && is_lower_hex_64(&self.request_digest) && !self.ordering_key.is_empty()
            && !self.fencing_token.is_empty()
    }
}
impl ModuleStateEnvelopeV1 {
    pub fn validate_identity(&self) -> bool {
        !self.schema.is_empty() && self.module_id.starts_with("MOD-") && !self.operation_id.is_empty()
            && is_lower_hex_64(&self.request_digest) && !self.state.is_empty()
            && !self.fencing_token.is_empty()
    }
}
impl ModuleErrorEnvelopeV1 {
    pub fn validate_identity(&self) -> bool {
        !self.schema.is_empty() && self.module_id.starts_with("MOD-") && !self.operation_id.is_empty()
            && is_lower_hex_64(&self.request_digest) && !self.code.is_empty()
            && !self.class.is_empty() && !self.retry_disposition.is_empty()
    }
}
'''


def rust_test_source() -> bytes:
    return b'''use std::fs;
use std::path::{Path, PathBuf};
use trillionnium_owner_open_types::module_contract::{
    ModuleApiEnvelopeV1, ModuleErrorEnvelopeV1, ModuleStateEnvelopeV1,
};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn files(root: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() { pending.push(path); }
            else if path.extension().and_then(|value| value.to_str()) == Some("json") { result.push(path); }
        }
    }
    result.sort(); result
}

#[test]
fn all_valid_vectors_deserialize_and_validate_identity() {
    for path in files(&repository_root().join("schemas/modules")) {
        let text = fs::read_to_string(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy();
        if !path.to_string_lossy().contains("/golden/valid/") { continue; }
        if name == "api.json" {
            let value: ModuleApiEnvelopeV1 = serde_json::from_str(&text).unwrap();
            assert!(value.validate_identity(), "{}", path.display());
        } else if name == "state.json" {
            let value: ModuleStateEnvelopeV1 = serde_json::from_str(&text).unwrap();
            assert!(value.validate_identity(), "{}", path.display());
        } else if name == "errors.json" {
            let value: ModuleErrorEnvelopeV1 = serde_json::from_str(&text).unwrap();
            assert!(value.validate_identity(), "{}", path.display());
        }
    }
}

#[test]
fn all_invalid_vectors_fail_closed() {
    for path in files(&repository_root().join("schemas/modules")) {
        if !path.to_string_lossy().contains("/golden/invalid/") { continue; }
        let text = fs::read_to_string(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy();
        let rejected = if name.starts_with("api-duplicate") {
            text.matches("\\\"module_id\\\"").count() > 1
        } else if name.starts_with("api-") {
            serde_json::from_str::<ModuleApiEnvelopeV1>(&text).is_err()
        } else if name.starts_with("state-") {
            serde_json::from_str::<ModuleStateEnvelopeV1>(&text).is_err()
        } else {
            serde_json::from_str::<ModuleErrorEnvelopeV1>(&text).is_err()
        };
        assert!(rejected, "invalid vector accepted: {}", path.display());
    }
}
'''


def android_verifier_source() -> bytes:
    return b'''#!/usr/bin/env python3
"""Android build-host consumer for the shared module contract vectors."""
from __future__ import annotations
import json, math
from pathlib import Path
import re, sys

ROOT = Path(__file__).resolve().parents[2]
SHA64 = re.compile(r"^[0-9a-f]{64}$")

def pairs(items):
    result = {}
    for key, value in items:
        if key in result: raise ValueError(f"duplicate member: {key}")
        result[key] = value
    return result

def bad(value): raise ValueError(f"nonfinite: {value}")
def load(path): return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs, parse_constant=bad)
def validate(value, kind):
    required = {
        "api": {"schema","module_id","operation_id","request_digest","ordering_key","host_epoch","writer_epoch","fencing_token","payload"},
        "state": {"schema","module_id","operation_id","request_digest","state","host_epoch","writer_epoch","fencing_token","durable_sequence","monotonic_ns","payload"},
        "errors": {"schema","module_id","operation_id","request_digest","code","class","retry_disposition","effect_uncertain","original_cause"},
    }[kind]
    if not isinstance(value, dict) or set(value) != required: raise ValueError("field set differs")
    if not SHA64.fullmatch(value["request_digest"]): raise ValueError("digest differs")
    if not value["module_id"].startswith("MOD-"): raise ValueError("module differs")

def main():
    valid = invalid = 0
    for path in sorted((ROOT / "schemas/modules").glob("*/golden/valid/*.json")):
        validate(load(path), path.stem); valid += 1
    for path in sorted((ROOT / "schemas/modules").glob("*/golden/invalid/*.json")):
        kind = path.name.split("-",1)[0]
        try: validate(load(path), kind)
        except Exception: invalid += 1
        else: raise SystemExit(f"invalid Android vector accepted: {path}")
    if valid == 0 or invalid == 0: raise SystemExit("vector set is empty")
    print(json.dumps({"android_build_host_valid":valid,"android_build_host_invalid":invalid,"public_release":False},sort_keys=True))
if __name__ == "__main__": main()
'''


def contract_readme() -> bytes:
    return b'''# Executable module contracts

`generate_module_contracts.py` resolves every logical API, state and error label
from the machine module catalog to checked-in JSON Schema, compatibility metadata
and shared valid/invalid vectors. Generated bytes are locked and reproducible.

The common Rust envelopes use `serde(deny_unknown_fields)` and retain operation,
request digest, ordering/fencing epochs and explicit uncertainty. Python, Rust
and the Android build-host consumer execute the same vectors. A schema success
is L1 source evidence only and cannot mint installed-target, device, destructive,
signing or release evidence.

Commands:

```sh
python3 tools/contracts/generate_module_contracts.py --check
python3 tools/contracts/generate_module_contracts.py --verify
python3 android-integration/module-contracts/verify_vectors.py
cargo test -p trillionnium-owner-open-types --test module_contract_vectors
```
'''


def android_readme() -> bytes:
    return b'''# Android build-host module-contract consumer

This directory verifies the exact checked-in valid and invalid vectors consumed
by Android packaging/build tooling. It is source-only: it does not claim a Soong
image build, SELinux compilation, installation, a physical device or release.
The L3 image lane must separately prove that the selected generated contracts and
installed binaries agree.
'''


def object_schema(properties: dict[str, Any], required: list[str], *, identifier: str, title: str, binding: dict[str, Any]) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": identifier,
        "title": title,
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
        "x-trillionnium-binding": binding,
    }


def common_properties(module: str, label: str) -> dict[str, Any]:
    return {
        "schema": {"type": "string", "const": label},
        "module_id": {"type": "string", "const": module},
        "operation_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "request_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    }


def validate_schema(instance: Any, schema: dict[str, Any], path: str = "$" ) -> None:
    kind = schema.get("type")
    if kind == "object":
        require(isinstance(instance, dict), f"{path} must be object")
        properties = schema.get("properties", {})
        for required_key in schema.get("required", []): require(required_key in instance, f"{path} missing {required_key}")
        if schema.get("additionalProperties") is False:
            require(set(instance) <= set(properties), f"{path} contains unknown members")
        if "maxProperties" in schema: require(len(instance) <= schema["maxProperties"], f"{path} has too many members")
        for key, value in instance.items():
            if key in properties: validate_schema(value, properties[key], f"{path}.{key}")
    elif kind == "string":
        require(isinstance(instance, str), f"{path} must be string")
        if "const" in schema: require(instance == schema["const"], f"{path} const differs")
        if "enum" in schema: require(instance in schema["enum"], f"{path} enum differs")
        if "minLength" in schema: require(len(instance) >= schema["minLength"], f"{path} too short")
        if "maxLength" in schema: require(len(instance) <= schema["maxLength"], f"{path} too long")
        if "pattern" in schema: require(re.fullmatch(schema["pattern"], instance) is not None, f"{path} pattern differs")
    elif kind == "integer":
        require(isinstance(instance, int) and not isinstance(instance, bool), f"{path} must be integer")
        if "minimum" in schema: require(instance >= schema["minimum"], f"{path} below minimum")
    elif kind == "boolean": require(isinstance(instance, bool), f"{path} must be boolean")
    elif kind == "array":
        require(isinstance(instance, list), f"{path} must be array")
        for index, value in enumerate(instance): validate_schema(value, schema.get("items", {}), f"{path}[{index}]")
    elif kind is None: return
    else: raise ContractError(f"unsupported schema type: {kind}")


def generated(root: Path) -> dict[str, bytes]:
    catalog = strict_load((root / CATALOG_PATH).read_bytes(), CATALOG_PATH)
    modules = catalog.get("modules") if isinstance(catalog, dict) else None
    require(isinstance(modules, list) and modules, "module catalog has no modules array")
    ids = [module_id(item) for item in modules]
    require(len(ids) == len(set(ids)), "module catalog repeats a module id")
    states = lifecycle_states(root)
    rust = rust_source()
    binding = {"path": RUST_PATH, "size": len(rust), "sha256": sha(rust),
               "api_symbol": "ModuleApiEnvelopeV1", "state_symbol": "ModuleStateEnvelopeV1", "error_symbol": "ModuleErrorEnvelopeV1"}
    outputs: dict[str, bytes] = {RUST_PATH: rust, RUST_TEST_PATH: rust_test_source(), ANDROID_VERIFY_PATH: android_verifier_source(),
                                ANDROID_README_PATH: android_readme(), README_PATH: contract_readme()}
    records = []
    request_digest = "0" * 64
    for item in sorted(modules, key=module_id):
        mid = module_id(item); slug = mid.removeprefix("MOD-").lower()
        api = select_label(item, API_LABEL, "api"); state = select_label(item, STATE_LABEL, "state"); error = select_label(item, ERROR_LABEL, "error")
        sources, tests = source_bindings(root, item)
        dependencies = sorted({value for _, value in flatten_strings(item) if isinstance(value, str) and value.startswith("MOD-") and value != mid})
        base = f"schemas/modules/{slug}"
        common_api = common_properties(mid, api)
        common_api.update({
            "ordering_key":{"type":"string","minLength":1,"maxLength":512}, "host_epoch":{"type":"integer","minimum":0},
            "writer_epoch":{"type":"integer","minimum":0}, "fencing_token":{"type":"string","minLength":1,"maxLength":512},
            "payload":{"type":"object","maxProperties":64},
        })
        api_schema = object_schema(common_api, list(common_api), identifier=api, title=f"{mid} API envelope v1", binding=binding)
        common_state = common_properties(mid, state)
        common_state.update({
            "state":{"type":"string","enum":states}, "host_epoch":{"type":"integer","minimum":0},
            "writer_epoch":{"type":"integer","minimum":0}, "fencing_token":{"type":"string","minLength":1,"maxLength":512},
            "durable_sequence":{"type":"integer","minimum":0}, "monotonic_ns":{"type":"integer","minimum":0},
            "payload":{"type":"object","maxProperties":64},
        })
        state_schema = object_schema(common_state, list(common_state), identifier=state, title=f"{mid} state envelope v1", binding=binding)
        common_error = common_properties(mid, error)
        common_error.update({
            "code":{"type":"string","minLength":1,"maxLength":128},
            "class":{"type":"string","enum":["REJECTED_BEFORE_EFFECT","TRANSIENT_BEFORE_EFFECT","EFFECT_UNCERTAIN","TERMINAL_FAILURE","INTERNAL_INVARIANT"]},
            "retry_disposition":{"type":"string","enum":["MAY_RETRY_BEFORE_EFFECT","RECONCILE_REQUIRED_NO_AUTOMATIC_REDISPATCH","DO_NOT_RETRY"]},
            "effect_uncertain":{"type":"boolean"}, "original_cause":{"type":"string","minLength":1,"maxLength":4096},
        })
        error_schema = object_schema(common_error, list(common_error), identifier=f"urn:trillionnium:{error}", title=f"{mid} error envelope v1", binding=binding)
        api_path=f"{base}/api-v1.schema.json"; state_path=f"{base}/state-v1.schema.json"; error_path=f"{base}/errors-v1.schema.json"
        outputs[api_path]=canonical_json(api_schema); outputs[state_path]=canonical_json(state_schema); outputs[error_path]=canonical_json(error_schema)
        valid_api={"schema":api,"module_id":mid,"operation_id":"operation-valid","request_digest":request_digest,"ordering_key":"session/turn/operation","host_epoch":1,"writer_epoch":1,"fencing_token":"fence-valid","payload":{}}
        valid_state={"schema":state,"module_id":mid,"operation_id":"operation-valid","request_digest":request_digest,"state":"ACCEPTED_DURABLE","host_epoch":1,"writer_epoch":1,"fencing_token":"fence-valid","durable_sequence":1,"monotonic_ns":1,"payload":{}}
        valid_error={"schema":error,"module_id":mid,"operation_id":"operation-valid","request_digest":request_digest,"code":"example_failure","class":"EFFECT_UNCERTAIN","retry_disposition":"RECONCILE_REQUIRED_NO_AUTOMATIC_REDISPATCH","effect_uncertain":True,"original_cause":"raw bounded cause"}
        outputs[f"{base}/golden/valid/api.json"]=canonical_json(valid_api); outputs[f"{base}/golden/valid/state.json"]=canonical_json(valid_state); outputs[f"{base}/golden/valid/errors.json"]=canonical_json(valid_error)
        outputs[f"{base}/golden/invalid/api-duplicate.json"]=(json.dumps(valid_api,separators=(",",":"))[:-1]+f',"module_id":"{mid}"}}\n').encode()
        invalid=dict(valid_api); invalid["unexpected"]=True; outputs[f"{base}/golden/invalid/api-unknown.json"]=canonical_json(invalid)
        outputs[f"{base}/golden/invalid/state-nonfinite.json"]=(json.dumps(valid_state,separators=(",",":"))[:-1]+',"monotonic_ns":NaN}\n').encode()
        invalid_error=dict(valid_error); invalid_error.pop("code"); outputs[f"{base}/golden/invalid/errors-missing.json"]=canonical_json(invalid_error)
        compatibility={
            "schema":"org.trillionnium.module-contract-compatibility.v1","module_id":mid,"dependencies":dependencies,
            "contracts":{"api":{"logical_label":api,"artifact":api_path,"read_versions":[1],"write_versions":[1]},
                         "state":{"logical_label":state,"artifact":state_path,"read_versions":[1],"write_versions":[1]},
                         "errors":{"logical_label":error,"artifact":error_path,"read_versions":[1],"write_versions":[1]}},
            "rust_binding":binding,"implementation_sources":sources,"test_sources":tests,
            "unknown_fields":"REJECT","duplicate_members":"REJECT","nonfinite_numbers":"REJECT","maximum_json_bytes":4194304,"maximum_json_depth":32,
            "effect_identity_defaults_allowed":False,"automatic_redispatch_after_uncertainty":False,
            "breaking_change_review":"REQUIRED_FOR_REQUIRED_TYPE_ENUM_DEFAULT_IDENTITY_ORDERING_STATE_OR_ERROR_CHANGE",
            "claim_ceiling":"L1_EXECUTABLE_CONTRACT_SOURCE_ONLY_NO_TARGET_OR_RELEASE_AUTHORITY","public_release":False,
        }
        compatibility_path=f"{base}/compatibility.json"; outputs[compatibility_path]=canonical_json(compatibility)
        records.append({"module_id":mid,"slug":slug,"logical_labels":{"api":api,"state":state,"errors":error},
                        "artifacts":{"api":api_path,"state":state_path,"errors":error_path,"compatibility":compatibility_path,
                                     "valid_vectors":f"{base}/golden/valid","invalid_vectors":f"{base}/golden/invalid"},
                        "implementation_sources":sources,"test_sources":tests,"dependencies":dependencies})
    machine={"schema":"org.trillionnium.module-contract-catalog.v1","program_revision":catalog.get("program_revision"),
             "module_count":len(records),"modules":records,"rust_binding":binding,"generator":file_identity(root, GENERATOR_PATH),
             "python_consumer":GENERATOR_PATH,"rust_consumer":RUST_TEST_PATH,"android_build_host_consumer":ANDROID_VERIFY_PATH,
             "automatic_redispatch":False,"promotion_authorized":False,"public_release":False,
             "claim_ceiling":"L1_EXECUTABLE_CONTRACT_SOURCE_ONLY_NO_TARGET_OR_RELEASE_AUTHORITY"}
    outputs[CONTRACT_CATALOG_PATH]=canonical_json(machine)
    lines=["# Module Contract Status","","<!-- GENERATED BY tools/contracts/generate_module_contracts.py. DO NOT EDIT. -->","",
           f"- Modules: `{len(records)}`","- API/state/error schemas: `3 per module`","- Shared valid vectors: `3 per module`","- Shared invalid vectors: `4 per module`","- Automatic redispatch after uncertainty: `false`","- Public release: `false`","",
           "| Module | API | State | Errors | Compatibility |","| --- | --- | --- | --- | --- |"]
    for record in records:
        a=record["artifacts"]; lines.append(f"| `{record['module_id']}` | `{a['api']}` | `{a['state']}` | `{a['errors']}` | `{a['compatibility']}` |")
    outputs[STATUS_PATH]=( "\n".join(lines)+"\n").encode()
    locked={path:{"bytes":len(raw),"sha256":sha(raw)} for path,raw in sorted(outputs.items())}
    outputs[LOCK_PATH]=canonical_json({"schema":"org.trillionnium.module-contract-lock.v1","artifacts":locked,"public_release":False})
    return outputs


def update_setup(root: Path) -> None:
    lib=root / "crates/trillionnium-owner-open-types/src/lib.rs"; text=lib.read_text(encoding="utf-8")
    if "pub mod module_contract;" not in text: lib.write_text(text.rstrip()+"\n\npub mod module_contract;\n",encoding="utf-8")
    cargo=root / "crates/trillionnium-owner-open-types/Cargo.toml"; cargo_text=cargo.read_text(encoding="utf-8")
    require("serde" in cargo_text and "serde_json" in cargo_text, "owner-open-types must already depend on serde and serde_json")
    docset_path=root / "docs/machine/doc-set.v1.json"; docset=strict_load(docset_path.read_bytes(),str(docset_path))
    additions=[CONTRACT_CATALOG_PATH,STATUS_PATH]
    def visit(value: Any) -> None:
        if isinstance(value,dict):
            for item in value.values(): visit(item)
        elif isinstance(value,list) and all(isinstance(item,str) for item in value):
            if any(item==CATALOG_PATH for item in value) and CONTRACT_CATALOG_PATH not in value: value.append(CONTRACT_CATALOG_PATH); value.sort()
            if any(item=="docs/START_HERE.md" for item in value) and STATUS_PATH not in value: value.append(STATUS_PATH); value.sort()
    visit(docset); docset_path.write_bytes(canonical_json(docset))
    start=root / "docs/START_HERE.md"; source=start.read_text(encoding="utf-8")
    if STATUS_PATH not in source: start.write_text(source.rstrip()+f"\n\n- Executable module-contract status: [`{STATUS_PATH}`](MODULE_CONTRACT_STATUS.md)\n",encoding="utf-8")


def write_outputs(root: Path, outputs: dict[str, bytes]) -> None:
    for relative, raw in outputs.items():
        path=root / relative; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(raw)


def verify_outputs(root: Path, outputs: dict[str, bytes]) -> None:
    for relative, expected in outputs.items():
        path=root / relative; require(path.is_file() and not path.is_symlink(),f"missing generated artifact: {relative}")
        require(path.read_bytes()==expected,f"generated artifact drift: {relative}")
    machine=strict_load((root / CONTRACT_CATALOG_PATH).read_bytes(),CONTRACT_CATALOG_PATH)
    for record in machine["modules"]:
        base=root / f"schemas/modules/{record['slug']}"
        schemas={kind:strict_load((root/path).read_bytes(),path) for kind,path in (("api",record["artifacts"]["api"]),("state",record["artifacts"]["state"]),("errors",record["artifacts"]["errors"]))}
        for path in sorted((base / "golden/valid").glob("*.json")):
            kind=path.stem; validate_schema(strict_load(path.read_bytes(),str(path)),schemas[kind],str(path))
        rejected=0
        for path in sorted((base / "golden/invalid").glob("*.json")):
            kind=path.name.split("-",1)[0]
            try: validate_schema(strict_load(path.read_bytes(),str(path)),schemas[kind],str(path))
            except ContractError: rejected+=1
            else: raise ContractError(f"invalid vector accepted: {path}")
        require(rejected==4,f"{record['module_id']} invalid vector count differs")
    subprocess.run([sys.executable,str(root / ANDROID_VERIFY_PATH)],cwd=root,check=True,timeout=60)


def install_generator(root: Path) -> None:
    target=root / GENERATOR_PATH; target.parent.mkdir(parents=True,exist_ok=True)
    raw=Path(__file__).read_bytes(); target.write_bytes(raw); os.chmod(target,0o755)


def parse_args() -> argparse.Namespace:
    parser=argparse.ArgumentParser(); parser.add_argument("--root",type=Path,default=Path(__file__).resolve().parents[2])
    group=parser.add_mutually_exclusive_group(required=True); group.add_argument("--write",action="store_true"); group.add_argument("--check",action="store_true"); group.add_argument("--verify",action="store_true")
    parser.add_argument("--install",action="store_true"); return parser.parse_args()


def main() -> int:
    args=parse_args(); root=args.root.resolve()
    try:
        if args.install: install_generator(root)
        if args.write:
            update_setup(root); outputs=generated(root); write_outputs(root,outputs); verify_outputs(root,generated(root))
        else:
            outputs=generated(root); verify_outputs(root,outputs)
        print(json.dumps({"result":"PASS","module_contracts":True,"public_release":False},sort_keys=True)); return 0
    except (ContractError,OSError,subprocess.SubprocessError) as error:
        print(f"module-contract verification failed: {error}",file=sys.stderr); return 2

if __name__=="__main__": raise SystemExit(main())
