#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
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
import unicodedata
from typing import Any, Iterable

CATALOG_PATH = "docs/machine/module-catalog.v1.json"
LIFECYCLE_PATH = "docs/machine/effect-lifecycle.v1.json"
CONTRACT_CATALOG_PATH = "docs/machine/module-contract-catalog.v1.json"
STATUS_PATH = "docs/MODULE_CONTRACT_STATUS.md"
LOCK_PATH = "tools/contracts/module-contracts.lock.json"
GENERATOR_PATH = "tools/contracts/generate_module_contracts.py"
RUST_PATH = "crates/trillionnium-owner-open-types/src/module_contract.rs"
RUST_TEST_PATH = "crates/trillionnium-owner-open-types/tests/module_contract_vectors.rs"
RUST_SCHEMA_BIN_PATH = "crates/trillionnium-owner-open-types/src/bin/generate_module_contract_schemas.rs"
SCHEMARS_PATH = "schemas/modules/_shared/envelopes-v1.schemars.json"
COMPAT_CHECK_PATH = "tools/contracts/check_module_contract_compatibility.py"
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


def strict_float(raw: str) -> float:
    value = float(raw)
    require(math.isfinite(value), f"non-finite JSON number: {raw}")
    return value


def strict_load(raw: bytes, label: str) -> Any:
    require(len(raw) <= 4 * 1024 * 1024, f"{label} exceeds byte bound")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=strict_pairs,
            parse_constant=reject_nonfinite,
            parse_float=strict_float,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError, ContractError) as error:
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
            if isinstance(item, str):
                yield "item", item
            else:
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


def bytes_identity(path: str, raw: bytes) -> dict[str, Any]:
    return {"path": normalized_path(path), "size": len(raw), "sha256": sha(raw)}


def source_bindings(root: Path, item: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    source_suffixes = {".rs", ".py", ".kt", ".java", ".sh", ".bp", ".toml", ".te", ".cil", ".mk", ".c", ".cc", ".cpp", ".h", ".hpp", ".json"}
    paths = item.get("paths")
    require(isinstance(paths, list) and paths and all(isinstance(value, str) for value in paths), f"{module_id(item)} has no path closure")
    sources: set[str] = set()
    tests: set[str] = set()
    for value in paths:
        normalized = normalized_path(value)
        path = root / normalized
        require(path.exists() and not path.is_symlink(), f"module path is unavailable or a symlink: {normalized}")
        candidates = [path] if path.is_file() else sorted(path.rglob("*"))
        require(len(candidates) <= 4096, f"module path expands beyond file bound: {normalized}")
        for candidate in candidates:
            if not candidate.is_file() or candidate.is_symlink() or candidate.suffix.lower() not in source_suffixes:
                continue
            relative = candidate.relative_to(root).as_posix()
            if relative in {RUST_PATH, RUST_TEST_PATH, RUST_SCHEMA_BIN_PATH, ANDROID_VERIFY_PATH, ANDROID_README_PATH, README_PATH, GENERATOR_PATH, COMPAT_CHECK_PATH, LOCK_PATH, CONTRACT_CATALOG_PATH, STATUS_PATH, SCHEMARS_PATH}:
                continue
            if relative.startswith("schemas/modules/"):
                continue
            lower = relative.lower()
            if "/test" in lower or lower.startswith("tools/tests/") or candidate.name.startswith("test_"):
                tests.add(relative)
            else:
                sources.add(relative)
    # Every module binds the shared generated-contract test; module-local tests
    # are retained when they exist under the declared implementation closure.
    if (root / TEST_PATH).is_file() and not (root / TEST_PATH).is_symlink():
        tests.add(TEST_PATH)
    require(sources, f"{module_id(item)} has no concrete implementation source binding")
    require(tests, f"{module_id(item)} has no concrete contract test binding")
    require(len(sources) <= 1024 and len(tests) <= 1024, f"{module_id(item)} binding inventory exceeds bound")
    return ([file_identity(root, value) for value in sorted(sources)],
            [file_identity(root, value) for value in sorted(tests)])


def lifecycle_states(root: Path) -> list[str]:
    value = strict_load((root / LIFECYCLE_PATH).read_bytes(), LIFECYCLE_PATH)
    observed = {text for _, text in flatten_strings(value) if text in EXPECTED_LIFECYCLE_STATES}
    missing = sorted(EXPECTED_LIFECYCLE_STATES - observed)
    require(not missing, f"effect lifecycle omits required states: {missing}")
    return sorted(observed | {"STATELESS"})


def rust_source() -> bytes:
    return b'''use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{MechanicalLimits, ProtocolError, decode_strict_value};

pub const MODULE_CONTRACT_VERSION: u32 = 1;
pub const MAX_MODULE_CONTRACT_JSON_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_MODULE_CONTRACT_JSON_DEPTH: usize = 32;
pub const MAX_MODULE_CONTRACT_ID_BYTES: usize = 256;
pub const MAX_MODULE_CONTRACT_KEY_BYTES: usize = 512;
pub const MAX_MODULE_CONTRACT_CAUSE_BYTES: usize = 4096;
pub const MAX_MODULE_CONTRACT_PAYLOAD_PROPERTIES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModuleLifecycleStateV1 {
    Received,
    Validated,
    CapacityReserved,
    AcceptedDurable,
    EffectAttempting,
    EffectStartedObserved,
    TerminalObserved,
    TerminalDurable,
    DeliveryPending,
    Delivered,
    Acknowledged,
    RejectedBeforeEffect,
    UnknownReconciliationRequired,
    Fenced,
    Closed,
    Stateless,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModuleErrorClassV1 {
    RejectedBeforeEffect,
    TransientBeforeEffect,
    EffectUncertain,
    TerminalFailure,
    InternalInvariant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModuleRetryDispositionV1 {
    MayRetryBeforeEffect,
    ReconcileRequiredNoAutomaticRedispatch,
    DoNotRetry,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModuleStateEnvelopeV1 {
    pub schema: String,
    pub module_id: String,
    pub operation_id: String,
    pub request_digest: String,
    pub state: ModuleLifecycleStateV1,
    pub host_epoch: u64,
    pub writer_epoch: u64,
    pub fencing_token: String,
    pub durable_sequence: u64,
    pub monotonic_ns: u64,
    pub payload: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModuleErrorEnvelopeV1 {
    pub schema: String,
    pub module_id: String,
    pub operation_id: String,
    pub request_digest: String,
    pub code: String,
    pub class: ModuleErrorClassV1,
    pub retry_disposition: ModuleRetryDispositionV1,
    pub effect_uncertain: bool,
    pub original_cause: String,
}

fn invalid(message: impl Into<String>) -> ProtocolError {
    ProtocolError::InvalidFrame(message.into())
}

pub fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn validate_depth(value: &Value, depth: usize) -> Result<(), ProtocolError> {
    if depth > MAX_MODULE_CONTRACT_JSON_DEPTH {
        return Err(invalid("module contract exceeds JSON depth bound"));
    }
    match value {
        Value::Array(values) => {
            for value in values {
                validate_depth(value, depth + 1)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_depth(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn strict_value(encoded: &[u8]) -> Result<Value, ProtocolError> {
    let limits = MechanicalLimits {
        max_frame_bytes: MAX_MODULE_CONTRACT_JSON_BYTES,
        ..MechanicalLimits::default()
    };
    let value = decode_strict_value(encoded, &limits)?;
    validate_depth(&value, 1)?;
    Ok(value)
}

fn validate_common(
    schema: &str,
    module_id: &str,
    operation_id: &str,
    request_digest: &str,
    expected_schema: &str,
    expected_module_id: &str,
) -> Result<(), ProtocolError> {
    if schema != expected_schema {
        return Err(invalid("module contract schema identity differs"));
    }
    if module_id != expected_module_id || !module_id.starts_with("MOD-") {
        return Err(invalid("module contract module identity differs"));
    }
    if !valid_text(operation_id, MAX_MODULE_CONTRACT_ID_BYTES) {
        return Err(invalid("module contract operation identity is invalid"));
    }
    if !is_lower_hex_64(request_digest) {
        return Err(invalid("module contract request digest is invalid"));
    }
    Ok(())
}

fn validate_payload(payload: &Value) -> Result<(), ProtocolError> {
    match payload {
        Value::Object(values) if values.len() <= MAX_MODULE_CONTRACT_PAYLOAD_PROPERTIES => Ok(()),
        Value::Object(_) => Err(invalid("module contract payload has too many properties")),
        _ => Err(invalid("module contract payload must be an object")),
    }
}

impl ModuleApiEnvelopeV1 {
    pub fn validate_binding(
        &self,
        expected_schema: &str,
        expected_module_id: &str,
    ) -> Result<(), ProtocolError> {
        validate_common(
            &self.schema,
            &self.module_id,
            &self.operation_id,
            &self.request_digest,
            expected_schema,
            expected_module_id,
        )?;
        if !valid_text(&self.ordering_key, MAX_MODULE_CONTRACT_KEY_BYTES)
            || !valid_text(&self.fencing_token, MAX_MODULE_CONTRACT_KEY_BYTES)
        {
            return Err(invalid(
                "module contract ordering or fencing identity is invalid",
            ));
        }
        validate_payload(&self.payload)
    }
}

impl ModuleStateEnvelopeV1 {
    pub fn validate_binding(
        &self,
        expected_schema: &str,
        expected_module_id: &str,
    ) -> Result<(), ProtocolError> {
        validate_common(
            &self.schema,
            &self.module_id,
            &self.operation_id,
            &self.request_digest,
            expected_schema,
            expected_module_id,
        )?;
        if !valid_text(&self.fencing_token, MAX_MODULE_CONTRACT_KEY_BYTES) {
            return Err(invalid("module contract fencing identity is invalid"));
        }
        validate_payload(&self.payload)
    }
}

impl ModuleErrorEnvelopeV1 {
    pub fn validate_binding(
        &self,
        expected_schema: &str,
        expected_module_id: &str,
    ) -> Result<(), ProtocolError> {
        validate_common(
            &self.schema,
            &self.module_id,
            &self.operation_id,
            &self.request_digest,
            expected_schema,
            expected_module_id,
        )?;
        if !valid_text(&self.code, 128)
            || !valid_text(&self.original_cause, MAX_MODULE_CONTRACT_CAUSE_BYTES)
        {
            return Err(invalid("module contract error fields are invalid"));
        }
        let uncertain = matches!(self.class, ModuleErrorClassV1::EffectUncertain);
        let reconcile = matches!(
            self.retry_disposition,
            ModuleRetryDispositionV1::ReconcileRequiredNoAutomaticRedispatch
        );
        if uncertain != self.effect_uncertain || reconcile != self.effect_uncertain {
            return Err(invalid("effect uncertainty and retry disposition differ"));
        }
        Ok(())
    }
}

pub fn parse_module_api(encoded: &[u8]) -> Result<ModuleApiEnvelopeV1, ProtocolError> {
    serde_json::from_value(strict_value(encoded)?)
        .map_err(|error| invalid(format!("invalid module API envelope: {error}")))
}

pub fn parse_module_state(encoded: &[u8]) -> Result<ModuleStateEnvelopeV1, ProtocolError> {
    serde_json::from_value(strict_value(encoded)?)
        .map_err(|error| invalid(format!("invalid module state envelope: {error}")))
}

pub fn parse_module_error(encoded: &[u8]) -> Result<ModuleErrorEnvelopeV1, ProtocolError> {
    serde_json::from_value(strict_value(encoded)?)
        .map_err(|error| invalid(format!("invalid module error envelope: {error}")))
}
'''


def rust_schema_binary_source() -> bytes:
    return b'''use schemars::schema_for;
use serde_json::json;
use trillionnium_owner_open_types::module_contract::{
    ModuleApiEnvelopeV1, ModuleErrorEnvelopeV1, ModuleStateEnvelopeV1,
};

fn main() {
    let value = json!({
        "api": schema_for!(ModuleApiEnvelopeV1),
        "errors": schema_for!(ModuleErrorEnvelopeV1),
        "schema": "org.trillionnium.module-schemars-bundle.v1",
        "state": schema_for!(ModuleStateEnvelopeV1),
        "version": 1,
    });
    println!(
        "{}",
        serde_json::to_string(&value).expect("serialize schemars bundle")
    );
}
'''


def rust_test_source() -> bytes:
    return b'''use std::fs;
use std::path::{Path, PathBuf};

use schemars::schema_for;
use serde_json::{Value, json};
use trillionnium_owner_open_types::module_contract::{
    ModuleApiEnvelopeV1, ModuleErrorEnvelopeV1, ModuleStateEnvelopeV1, parse_module_api,
    parse_module_error, parse_module_state,
};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("read JSON")).expect("parse JSON")
}

#[test]
fn checked_in_schemars_bundle_is_exact() {
    let expected =
        read_json(&repository_root().join("schemas/modules/_shared/envelopes-v1.schemars.json"));
    let actual = json!({
        "api": schema_for!(ModuleApiEnvelopeV1),
        "errors": schema_for!(ModuleErrorEnvelopeV1),
        "schema": "org.trillionnium.module-schemars-bundle.v1",
        "state": schema_for!(ModuleStateEnvelopeV1),
        "version": 1,
    });
    assert_eq!(expected, actual);
}

#[test]
fn every_shared_vector_is_consumed_fail_closed() {
    let root = repository_root();
    let modules = root.join("schemas/modules");
    for entry in fs::read_dir(modules).expect("read modules") {
        let directory = entry.expect("module entry").path();
        if !directory.is_dir() || directory.file_name().and_then(|v| v.to_str()) == Some("_shared")
        {
            continue;
        }
        let compatibility = read_json(&directory.join("compatibility.json"));
        let module_id = compatibility["module_id"].as_str().expect("module id");
        for kind in ["api", "state", "errors"] {
            let schema = compatibility["contracts"][kind]["logical_label"]
                .as_str()
                .expect("logical label");
            let valid = fs::read(directory.join("golden/valid").join(format!("{kind}.json")))
                .expect("valid vector");
            match kind {
                "api" => parse_module_api(&valid)
                    .and_then(|value| value.validate_binding(schema, module_id))
                    .expect("valid API vector"),
                "state" => parse_module_state(&valid)
                    .and_then(|value| value.validate_binding(schema, module_id))
                    .expect("valid state vector"),
                "errors" => parse_module_error(&valid)
                    .and_then(|value| value.validate_binding(schema, module_id))
                    .expect("valid error vector"),
                _ => unreachable!(),
            }
        }
        for entry in fs::read_dir(directory.join("golden/invalid")).expect("invalid vectors") {
            let path = entry.expect("invalid vector").path();
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .expect("name");
            let raw = fs::read(&path).expect("read invalid vector");
            let rejected = if name.starts_with("api-") {
                parse_module_api(&raw)
                    .and_then(|value| {
                        value.validate_binding(
                            compatibility["contracts"]["api"]["logical_label"]
                                .as_str()
                                .expect("API label"),
                            module_id,
                        )
                    })
                    .is_err()
            } else if name.starts_with("state-") {
                parse_module_state(&raw)
                    .and_then(|value| {
                        value.validate_binding(
                            compatibility["contracts"]["state"]["logical_label"]
                                .as_str()
                                .expect("state label"),
                            module_id,
                        )
                    })
                    .is_err()
            } else {
                parse_module_error(&raw)
                    .and_then(|value| {
                        value.validate_binding(
                            compatibility["contracts"]["errors"]["logical_label"]
                                .as_str()
                                .expect("error label"),
                            module_id,
                        )
                    })
                    .is_err()
            };
            assert!(rejected, "invalid vector accepted: {}", path.display());
        }
    }
}
'''


def android_verifier_source() -> bytes:
    return b'''#!/usr/bin/env python3
"""Android build-host consumer for the exact shared module-contract vectors."""
from __future__ import annotations

import json
import math
from pathlib import Path
import re
import unicodedata

ROOT = Path(__file__).resolve().parents[2]
MAX_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 32
MAX_U64 = (1 << 64) - 1
SHA64 = re.compile(r"^[0-9a-f]{64}$")
STATES = {
    "RECEIVED", "VALIDATED", "CAPACITY_RESERVED", "ACCEPTED_DURABLE",
    "EFFECT_ATTEMPTING", "EFFECT_STARTED_OBSERVED", "TERMINAL_OBSERVED",
    "TERMINAL_DURABLE", "DELIVERY_PENDING", "DELIVERED", "ACKNOWLEDGED",
    "REJECTED_BEFORE_EFFECT", "UNKNOWN_RECONCILIATION_REQUIRED", "FENCED",
    "CLOSED", "STATELESS",
}
ERROR_CLASSES = {
    "REJECTED_BEFORE_EFFECT", "TRANSIENT_BEFORE_EFFECT", "EFFECT_UNCERTAIN",
    "TERMINAL_FAILURE", "INTERNAL_INVARIANT",
}
RETRY_DISPOSITIONS = {
    "MAY_RETRY_BEFORE_EFFECT",
    "RECONCILE_REQUIRED_NO_AUTOMATIC_REDISPATCH",
    "DO_NOT_RETRY",
}


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate member: {key}")
        result[key] = value
    return result


def bad(value):
    raise ValueError(f"nonfinite: {value}")


def finite_float(raw):
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError(f"nonfinite JSON number: {raw}")
    return value


def depth(value):
    if isinstance(value, dict):
        return 1 + max((depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((depth(item) for item in value), default=0)
    return 1


def load(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular vector: {path}")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError("vector byte bound differs")
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=pairs,
        parse_constant=bad,
        parse_float=finite_float,
    )
    if depth(value) > MAX_DEPTH:
        raise ValueError("vector depth bound differs")
    return value


def text(value, maximum):
    if not isinstance(value, str) or not value:
        return False
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        return False
    return (
        len(encoded) <= maximum
        and not any(unicodedata.category(char) == "Cc" for char in value)
    )


def u64(value):
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_U64


def validate(value, kind, module_id, label):
    required = {
        "api": {"schema","module_id","operation_id","request_digest","ordering_key","host_epoch","writer_epoch","fencing_token","payload"},
        "state": {"schema","module_id","operation_id","request_digest","state","host_epoch","writer_epoch","fencing_token","durable_sequence","monotonic_ns","payload"},
        "errors": {"schema","module_id","operation_id","request_digest","code","class","retry_disposition","effect_uncertain","original_cause"},
    }[kind]
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("field set differs")
    if value["schema"] != label or value["module_id"] != module_id or not module_id.startswith("MOD-"):
        raise ValueError("contract identity differs")
    if not text(value["operation_id"], 256):
        raise ValueError("operation identity differs")
    if not isinstance(value["request_digest"], str) or not SHA64.fullmatch(value["request_digest"]):
        raise ValueError("digest differs")
    if kind in {"api", "state"}:
        if not isinstance(value["payload"], dict) or len(value["payload"]) > 64:
            raise ValueError("payload differs")
        if not u64(value["host_epoch"]) or not u64(value["writer_epoch"]):
            raise ValueError("epoch differs")
        if not text(value["fencing_token"], 512):
            raise ValueError("fencing token differs")
    if kind == "api":
        if not text(value["ordering_key"], 512):
            raise ValueError("ordering key differs")
    elif kind == "state":
        if value["state"] not in STATES:
            raise ValueError("state differs")
        if not u64(value["durable_sequence"]) or not u64(value["monotonic_ns"]):
            raise ValueError("state ordering differs")
    else:
        if not text(value["code"], 128) or not text(value["original_cause"], 4096):
            raise ValueError("error text differs")
        if value["class"] not in ERROR_CLASSES or value["retry_disposition"] not in RETRY_DISPOSITIONS:
            raise ValueError("error enum differs")
        if not isinstance(value["effect_uncertain"], bool):
            raise ValueError("effect uncertainty type differs")
        uncertain = value["class"] == "EFFECT_UNCERTAIN"
        reconcile = value["retry_disposition"] == "RECONCILE_REQUIRED_NO_AUTOMATIC_REDISPATCH"
        if uncertain != value["effect_uncertain"] or reconcile != value["effect_uncertain"]:
            raise ValueError("uncertainty semantics differ")


def main():
    valid = invalid = 0
    for directory in sorted((ROOT / "schemas/modules").iterdir()):
        if not directory.is_dir() or directory.name == "_shared":
            continue
        compatibility = load(directory / "compatibility.json")
        module_id = compatibility["module_id"]
        for kind in ("api", "state", "errors"):
            label = compatibility["contracts"][kind]["logical_label"]
            validate(load(directory / "golden/valid" / f"{kind}.json"), kind, module_id, label)
            valid += 1
        for path in sorted((directory / "golden/invalid").glob("*.json")):
            kind = path.name.split("-", 1)[0]
            try:
                validate(load(path), kind, module_id, compatibility["contracts"][kind]["logical_label"])
            except Exception:
                invalid += 1
            else:
                raise SystemExit(f"invalid Android vector accepted: {path}")
    if valid == 0 or invalid == 0:
        raise SystemExit("vector set is empty")
    print(json.dumps({"android_build_host_valid":valid,"android_build_host_invalid":invalid,"public_release":False},sort_keys=True))


if __name__ == "__main__":
    main()
'''


def compatibility_checker_source() -> bytes:
    return b'#!/usr/bin/env python3\n"""Fail-closed semantic compatibility check for generated module contracts."""\nfrom __future__ import annotations\n\nimport argparse\nimport json\nimport math\nfrom pathlib import Path\nimport re\nimport subprocess\nimport sys\nfrom typing import Any\n\nROOT = Path(__file__).resolve().parents[2]\nCATALOG = "docs/machine/module-contract-catalog.v1.json"\nSHA40 = re.compile(r"^[0-9a-f]{40}$")\n\n\ndef finite_float(raw: str) -> float:\n    value = float(raw)\n    if not math.isfinite(value):\n        raise ValueError(f"nonfinite JSON number: {raw}")\n    return value\n\n\ndef load(raw: bytes, label: str) -> Any:\n    def pairs(items):\n        out = {}\n        for key, value in items:\n            if key in out:\n                raise ValueError(f"{label}: duplicate member {key}")\n            out[key] = value\n        return out\n\n    return json.loads(\n        raw.decode("utf-8"),\n        object_pairs_hook=pairs,\n        parse_constant=lambda value: (_ for _ in ()).throw(\n            ValueError(f"{label}: nonfinite {value}")\n        ),\n        parse_float=finite_float,\n    )\n\n\ndef git(args: list[str], label: str, *, root: Path = ROOT) -> bytes:\n    result = subprocess.run(\n        ["git", "--no-replace-objects", *args],\n        cwd=root,\n        capture_output=True,\n        check=False,\n        timeout=30,\n    )\n    if result.returncode != 0:\n        detail = result.stderr.decode("utf-8", "replace").strip()\n        raise ValueError(f"{label}: git returned {result.returncode}: {detail}")\n    return result.stdout\n\n\ndef resolve_commit(ref: str, *, root: Path = ROOT) -> str:\n    if not isinstance(ref, str) or not ref or "\\x00" in ref or "\\n" in ref:\n        raise ValueError("base ref is malformed")\n    raw = git(\n        ["rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"],\n        "resolve base ref",\n        root=root,\n    )\n    values = raw.decode("ascii", "strict").splitlines()\n    if len(values) != 1 or SHA40.fullmatch(values[0]) is None:\n        raise ValueError("base ref did not resolve to one exact commit")\n    commit = values[0]\n    git(\n        ["merge-base", "--is-ancestor", commit, "HEAD"],\n        "verify base ancestry",\n        root=root,\n    )\n    return commit\n\n\ndef show(\n    commit: str,\n    path: str,\n    *,\n    allow_absent: bool = False,\n    root: Path = ROOT,\n) -> bytes | None:\n    if SHA40.fullmatch(commit) is None:\n        raise ValueError("show requires an exact commit")\n    if (\n        not isinstance(path, str)\n        or not path\n        or path.startswith("/")\n        or "\\\\" in path\n        or "\\x00" in path\n        or "\\n" in path\n        or any(part in {"", ".", ".."} for part in path.split("/"))\n    ):\n        raise ValueError(f"unsafe tree path: {path!r}")\n\n    listing = git(\n        ["ls-tree", "-z", "--full-tree", commit, "--", path],\n        f"inspect {path} in verified base",\n        root=root,\n    )\n    entries = [entry for entry in listing.split(b"\\0") if entry]\n    if not entries:\n        if allow_absent:\n            return None\n        raise ValueError(f"verified base path is absent: {path}")\n    if len(entries) != 1:\n        raise ValueError(f"verified base path is ambiguous: {path}")\n\n    metadata, separator, encoded_name = entries[0].partition(b"\\t")\n    if not separator:\n        raise ValueError(f"malformed ls-tree result for {path}")\n    try:\n        mode, kind, object_id = metadata.decode("ascii", "strict").split(" ")\n        observed_name = encoded_name.decode("utf-8", "strict")\n    except (UnicodeError, ValueError) as error:\n        raise ValueError(f"malformed ls-tree identity for {path}") from error\n    if (\n        observed_name != path\n        or kind != "blob"\n        or mode not in {"100644", "100755"}\n        or SHA40.fullmatch(object_id) is None\n    ):\n        raise ValueError(f"verified base object is not one regular tracked file: {path}")\n    return git(["cat-file", "blob", object_id], f"read verified base file {path}", root=root)\n\n\nNON_SEMANTIC = {\n    "$schema",\n    "$id",\n    "title",\n    "description",\n    "examples",\n    "x-trillionnium-binding",\n}\nNAMED_SCHEMA_MAPS = {\n    "$defs",\n    "definitions",\n    "properties",\n    "patternProperties",\n    "dependentSchemas",\n}\nSCHEMA_SINGLE = {\n    "additionalProperties",\n    "unevaluatedProperties",\n    "propertyNames",\n    "contains",\n    "contentSchema",\n    "if",\n    "then",\n    "else",\n    "not",\n    "unevaluatedItems",\n}\nSCHEMA_ARRAYS = {"allOf", "anyOf", "oneOf", "prefixItems"}\n\n\ndef normalized_data(value: Any) -> Any:\n    if isinstance(value, dict):\n        return {\n            key: normalized_data(item)\n            for key, item in sorted(value.items())\n        }\n    if isinstance(value, list):\n        return [normalized_data(item) for item in value]\n    return value\n\n\ndef fingerprint(value: Any) -> Any:\n    """Remove annotations only where the dictionary is a JSON Schema object."""\n    if isinstance(value, bool):\n        return value\n    if not isinstance(value, dict):\n        return normalized_data(value)\n\n    result = {}\n    for key, item in sorted(value.items()):\n        if key in NON_SEMANTIC:\n            continue\n        if key in NAMED_SCHEMA_MAPS and isinstance(item, dict):\n            # Keys here are application property/definition names. They are\n            # semantic even when they happen to be called "title" or "$id".\n            result[key] = {\n                name: fingerprint(child)\n                for name, child in sorted(item.items())\n            }\n        elif key == "dependencies" and isinstance(item, dict):\n            result[key] = {\n                name: (\n                    fingerprint(child)\n                    if isinstance(child, (dict, bool))\n                    else normalized_data(child)\n                )\n                for name, child in sorted(item.items())\n            }\n        elif key in SCHEMA_SINGLE and isinstance(item, (dict, bool)):\n            result[key] = fingerprint(item)\n        elif key == "items":\n            if isinstance(item, list):\n                result[key] = [fingerprint(child) for child in item]\n            elif isinstance(item, (dict, bool)):\n                result[key] = fingerprint(item)\n            else:\n                result[key] = normalized_data(item)\n        elif key in SCHEMA_ARRAYS and isinstance(item, list):\n            result[key] = [fingerprint(child) for child in item]\n        else:\n            # Values of const/enum/default-like or unknown extension keywords\n            # are data, not automatically nested schemas. Preserve them.\n            result[key] = normalized_data(item)\n    return result\n\n\ndef main() -> int:\n    parser = argparse.ArgumentParser()\n    parser.add_argument("--base-ref", required=True)\n    args = parser.parse_args()\n\n    current = load((ROOT / CATALOG).read_bytes(), CATALOG)\n    base_commit = resolve_commit(args.base_ref)\n    old_raw = show(base_commit, CATALOG, allow_absent=True)\n    if old_raw is None:\n        for module in current["modules"]:\n            compatibility = load(\n                (ROOT / module["artifacts"]["compatibility"]).read_bytes(),\n                module["module_id"],\n            )\n            if compatibility.get("change_review_class") != "INITIAL_V1":\n                raise SystemExit("initial contract lacks INITIAL_V1 review class")\n        print(\n            json.dumps(\n                {\n                    "base_commit": base_commit,\n                    "modules": current["module_count"],\n                    "public_release": False,\n                    "result": "PASS_INITIAL_V1",\n                },\n                sort_keys=True,\n            )\n        )\n        return 0\n\n    old = load(old_raw, CATALOG)\n    old_by = {item["module_id"]: item for item in old["modules"]}\n    current_by = {item["module_id"]: item for item in current["modules"]}\n    if set(old_by) != set(current_by):\n        raise SystemExit(\n            "module set changed without a separately reviewed catalog migration"\n        )\n\n    changed = []\n    for module_id in sorted(current_by):\n        for kind in ("api", "state", "errors"):\n            new_path = current_by[module_id]["artifacts"][kind]\n            old_path = old_by[module_id]["artifacts"][kind]\n            old_schema_raw = show(base_commit, old_path)\n            if fingerprint(load(old_schema_raw, old_path)) != fingerprint(\n                load((ROOT / new_path).read_bytes(), new_path)\n            ):\n                changed.append(f"{module_id}:{kind}")\n        compatibility = load(\n            (ROOT / current_by[module_id]["artifacts"]["compatibility"]).read_bytes(),\n            module_id,\n        )\n        if (\n            any(item.startswith(module_id + ":") for item in changed)\n            and compatibility.get("change_review_class") == "NO_CHANGE"\n        ):\n            raise SystemExit(\n                "semantic schema drift lacks migration/rollback review class: "\n                f"{module_id}"\n            )\n\n    print(\n        json.dumps(\n            {\n                "base_commit": base_commit,\n                "public_release": False,\n                "result": "PASS",\n                "semantic_changes": changed,\n            },\n            sort_keys=True,\n        )\n    )\n    return 0\n\n\nif __name__ == "__main__":\n    try:\n        raise SystemExit(main())\n    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:\n        print(f"module-contract compatibility failed: {error}", file=sys.stderr)\n        raise SystemExit(2)\n'


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


def _resolve_local_schema(node: Any, root: dict[str, Any]) -> Any:
    seen: set[str] = set()
    while isinstance(node, dict) and isinstance(node.get("$ref"), str):
        reference = node["$ref"]
        require(reference.startswith("#/"), f"unsupported non-local schemars reference: {reference}")
        require(reference not in seen, f"cyclic schemars reference: {reference}")
        seen.add(reference)
        current: Any = root
        for token in reference[2:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            require(isinstance(current, dict) and token in current, f"unresolved schemars reference: {reference}")
            current = current[token]
        node = current
    return node


def _schema_type(node: Any, root: dict[str, Any]) -> str | None:
    node = _resolve_local_schema(node, root)
    return node.get("type") if isinstance(node, dict) else None


def _schema_enum(node: Any, root: dict[str, Any]) -> set[str] | None:
    node = _resolve_local_schema(node, root)
    if not isinstance(node, dict) or not isinstance(node.get("enum"), list):
        return None
    values = node["enum"]
    require(all(isinstance(value, str) for value in values), "schemars enum contains non-string values")
    return set(values)


def specialize_schemars_schema(
    base: dict[str, Any],
    *,
    identifier: str,
    title: str,
    module: str,
    label: str,
    kind: str,
    binding: dict[str, Any],
) -> dict[str, Any]:
    result = copy.deepcopy(base)
    require(result.get("type") == "object", f"schemars {kind} root must be object")
    require(result.get("additionalProperties") is False, f"schemars {kind} must deny unknown fields")
    properties = result.get("properties")
    require(isinstance(properties, dict), f"schemars {kind} properties are malformed")

    def direct(field: str) -> dict[str, Any]:
        value = properties.get(field)
        require(isinstance(value, dict) and "$ref" not in value, f"schemars {kind}.{field} is not a direct field schema")
        return value

    def bounded_text(field: str, maximum: int) -> None:
        direct(field).update(
            {
                "type": "string",
                "minLength": 1,
                "maxLength": maximum,
                "x-trillionnium-maxUtf8Bytes": maximum,
                "x-trillionnium-forbidUnicodeControls": True,
            }
        )

    direct("schema").update({"type": "string", "const": label})
    direct("module_id").update({"type": "string", "const": module})
    bounded_text("operation_id", 256)
    direct("request_digest").update({"type": "string", "pattern": "^[0-9a-f]{64}$"})
    if kind in {"api", "state"}:
        bounded_text("fencing_token", 512)
        properties["payload"] = {"type": "object", "maxProperties": 64}
    if kind == "api":
        bounded_text("ordering_key", 512)
    elif kind == "errors":
        bounded_text("code", 128)
        bounded_text("original_cause", 4096)
    result["$id"] = identifier
    result["title"] = title
    result["x-trillionnium-binding"] = binding
    return result


def validate_schema(instance: Any, schema: Any, path: str = "$", root: dict[str, Any] | None = None) -> None:
    if root is None:
        require(isinstance(schema, dict), f"{path} root schema must be object")
        root = schema
    if schema is True:
        return
    require(schema is not False and isinstance(schema, dict), f"{path} is rejected by schema")
    if "$ref" in schema:
        validate_schema(instance, _resolve_local_schema(schema, root), path, root)
        return
    for child in schema.get("allOf", []):
        validate_schema(instance, child, path, root)
    kind = schema.get("type")
    if kind == "object":
        require(isinstance(instance, dict), f"{path} must be object")
        properties = schema.get("properties", {})
        for required_key in schema.get("required", []):
            require(required_key in instance, f"{path} missing {required_key}")
        if schema.get("additionalProperties") is False:
            require(set(instance) <= set(properties), f"{path} contains unknown members")
        if "maxProperties" in schema:
            require(len(instance) <= schema["maxProperties"], f"{path} has too many members")
        for key, value in instance.items():
            if key in properties:
                validate_schema(value, properties[key], f"{path}.{key}", root)
    elif kind == "string":
        require(isinstance(instance, str), f"{path} must be string")
        if "const" in schema:
            require(instance == schema["const"], f"{path} const differs")
        if "enum" in schema:
            require(instance in schema["enum"], f"{path} enum differs")
        if "minLength" in schema:
            require(len(instance) >= schema["minLength"], f"{path} too short")
        if "maxLength" in schema:
            require(len(instance) <= schema["maxLength"], f"{path} too long")
        if "pattern" in schema:
            require(re.fullmatch(schema["pattern"], instance) is not None, f"{path} pattern differs")
        maximum_utf8 = schema.get("x-trillionnium-maxUtf8Bytes")
        if maximum_utf8 is not None:
            require(
                isinstance(maximum_utf8, int)
                and not isinstance(maximum_utf8, bool)
                and maximum_utf8 > 0,
                f"{path} UTF-8 byte bound is invalid",
            )
            require(valid_text(instance, maximum_utf8), f"{path} UTF-8 text domain differs")
        if schema.get("x-trillionnium-forbidUnicodeControls") is not None:
            require(
                schema["x-trillionnium-forbidUnicodeControls"] is True,
                f"{path} Unicode-control policy differs",
            )
            require(
                not any(unicodedata.category(char) == "Cc" for char in instance),
                f"{path} contains a Unicode control character",
            )
    elif kind == "integer":
        require(isinstance(instance, int) and not isinstance(instance, bool), f"{path} must be integer")
        if "minimum" in schema:
            require(instance >= schema["minimum"], f"{path} below minimum")
        if schema.get("format") == "uint64":
            require(instance <= (1 << 64) - 1, f"{path} exceeds uint64")
    elif kind == "boolean":
        require(isinstance(instance, bool), f"{path} must be boolean")
    elif kind == "array":
        require(isinstance(instance, list), f"{path} must be array")
        for index, value in enumerate(instance):
            validate_schema(value, schema.get("items", {}), f"{path}[{index}]", root)
    elif kind is None:
        if "enum" in schema:
            require(instance in schema["enum"], f"{path} enum differs")
        return
    else:
        raise ContractError(f"unsupported schema type: {kind}")

def recursive_key_present(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(recursive_key_present(item, key) for item in value.values())
    if isinstance(value, list):
        return any(recursive_key_present(item, key) for item in value)
    return False


def validate_schemars_bundle(raw: bytes) -> tuple[dict[str, Any], bytes]:
    value = strict_load(raw, "schemars bundle")
    require(isinstance(value, dict), "schemars bundle must be an object")
    require(value.get("schema") == "org.trillionnium.module-schemars-bundle.v1", "schemars bundle identity differs")
    require(value.get("version") == 1, "schemars bundle version differs")
    expected = {
        "api": {"schema","module_id","operation_id","request_digest","ordering_key","host_epoch","writer_epoch","fencing_token","payload"},
        "state": {"schema","module_id","operation_id","request_digest","state","host_epoch","writer_epoch","fencing_token","durable_sequence","monotonic_ns","payload"},
        "errors": {"schema","module_id","operation_id","request_digest","code","class","retry_disposition","effect_uncertain","original_cause"},
    }
    for kind, fields in expected.items():
        schema = value.get(kind)
        require(isinstance(schema, dict), f"schemars bundle omits {kind}")
        properties = schema.get("properties")
        require(isinstance(properties, dict) and set(properties) == fields, f"schemars {kind} property set differs")
        require(set(schema.get("required", [])) == fields, f"schemars {kind} required set differs")
        require(schema.get("additionalProperties") is False, f"schemars {kind} must deny unknown fields")
        require(not recursive_key_present(schema, "default"), f"schemars {kind} contains an implicit default")
        for field in fields:
            require(field in properties, f"schemars {kind}.{field} is absent")
    scalar_types = {
        "api": {"schema":"string","module_id":"string","operation_id":"string","request_digest":"string","ordering_key":"string","host_epoch":"integer","writer_epoch":"integer","fencing_token":"string"},
        "state": {"schema":"string","module_id":"string","operation_id":"string","request_digest":"string","host_epoch":"integer","writer_epoch":"integer","fencing_token":"string","durable_sequence":"integer","monotonic_ns":"integer"},
        "errors": {"schema":"string","module_id":"string","operation_id":"string","request_digest":"string","code":"string","effect_uncertain":"boolean","original_cause":"string"},
    }
    for kind, mapping in scalar_types.items():
        for field, expected_type in mapping.items():
            require(_schema_type(value[kind]["properties"][field], value[kind]) == expected_type, f"schemars {kind}.{field} type differs")
    require(_schema_enum(value["state"]["properties"]["state"], value["state"]) == EXPECTED_LIFECYCLE_STATES | {"STATELESS"}, "schemars lifecycle enum differs")
    require(_schema_enum(value["errors"]["properties"]["class"], value["errors"]) == {"REJECTED_BEFORE_EFFECT","TRANSIENT_BEFORE_EFFECT","EFFECT_UNCERTAIN","TERMINAL_FAILURE","INTERNAL_INVARIANT"}, "schemars error-class enum differs")
    require(_schema_enum(value["errors"]["properties"]["retry_disposition"], value["errors"]) == {"MAY_RETRY_BEFORE_EFFECT","RECONCILE_REQUIRED_NO_AUTOMATIC_REDISPATCH","DO_NOT_RETRY"}, "schemars retry enum differs")
    return value, canonical_json(value)


def explicit_labels(item: dict[str, Any]) -> tuple[str, str, str]:
    mid = module_id(item)
    api_contract = item.get("api_contract")
    state_contract = item.get("state_contract")
    require(isinstance(api_contract, dict) and isinstance(state_contract, dict), f"{mid} contract objects are malformed")
    api = api_contract.get("schema")
    state = state_contract.get("schema")
    errors = api_contract.get("errors")
    require(isinstance(api, str) and API_LABEL.fullmatch(api), f"{mid} API label is invalid")
    require(isinstance(state, str) and STATE_LABEL.fullmatch(state), f"{mid} state label is invalid")
    require(isinstance(errors, list) and len(errors) == 1 and isinstance(errors[0], str), f"{mid} must declare exactly one error label")
    error = errors[0]
    require(ERROR_LABEL.fullmatch(error) is not None, f"{mid} error label is invalid")
    return api, state, error


def version_numbers(item: dict[str, Any]) -> tuple[list[int], list[int]]:
    mid = module_id(item)
    compatibility = item.get("compatibility")
    require(isinstance(compatibility, dict), f"{mid} compatibility is malformed")
    matrix = compatibility.get("read_write_matrix")
    require(isinstance(matrix, dict), f"{mid} read/write matrix is malformed")
    def parse(name: str) -> list[int]:
        raw = matrix.get(name)
        require(isinstance(raw, list) and raw, f"{mid} {name} versions are malformed")
        values=[]
        for value in raw:
            require(isinstance(value,str) and re.fullmatch(r"v[1-9][0-9]*",value), f"{mid} {name} version is invalid")
            values.append(int(value[1:]))
        require(len(values)==len(set(values)), f"{mid} {name} versions repeat")
        return sorted(values)
    return parse("read"), parse("write")


def valid_text(value: Any, maximum: int) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        return False
    return (
        len(encoded) <= maximum
        and not any(unicodedata.category(char) == "Cc" for char in value)
    )


def validate_semantics(value: Any, kind: str, module_id_value: str, label: str) -> None:
    require(isinstance(value, dict), "contract vector must be an object")
    require(
        value.get("module_id") == module_id_value and value.get("schema") == label,
        "contract vector identity differs",
    )
    require(valid_text(value.get("operation_id"), 256), "operation identity differs")
    require(
        isinstance(value.get("request_digest"), str)
        and SHA64.fullmatch(value["request_digest"]) is not None,
        "request digest differs",
    )
    if kind in {"api", "state"}:
        for field in ("host_epoch", "writer_epoch"):
            require(
                isinstance(value.get(field), int)
                and not isinstance(value[field], bool)
                and 0 <= value[field] <= (1 << 64) - 1,
                f"{field} differs",
            )
        require(valid_text(value.get("fencing_token"), 512), "fencing token differs")
        require(
            isinstance(value.get("payload"), dict) and len(value["payload"]) <= 64,
            "payload differs",
        )
    if kind == "api":
        require(valid_text(value.get("ordering_key"), 512), "ordering key differs")
    elif kind == "state":
        require(
            value.get("state") in EXPECTED_LIFECYCLE_STATES | {"STATELESS"},
            "state differs",
        )
        for field in ("durable_sequence", "monotonic_ns"):
            require(
                isinstance(value.get(field), int)
                and not isinstance(value[field], bool)
                and 0 <= value[field] <= (1 << 64) - 1,
                f"{field} differs",
            )
    else:
        require(valid_text(value.get("code"), 128), "error code differs")
        require(
            valid_text(value.get("original_cause"), 4096),
            "original cause differs",
        )
        require(
            value.get("class")
            in {
                "REJECTED_BEFORE_EFFECT",
                "TRANSIENT_BEFORE_EFFECT",
                "EFFECT_UNCERTAIN",
                "TERMINAL_FAILURE",
                "INTERNAL_INVARIANT",
            },
            "error class differs",
        )
        require(
            value.get("retry_disposition")
            in {
                "MAY_RETRY_BEFORE_EFFECT",
                "RECONCILE_REQUIRED_NO_AUTOMATIC_REDISPATCH",
                "DO_NOT_RETRY",
            },
            "retry disposition differs",
        )
        require(
            isinstance(value.get("effect_uncertain"), bool),
            "effect uncertainty type differs",
        )
        uncertain = value.get("class") == "EFFECT_UNCERTAIN"
        reconcile = (
            value.get("retry_disposition")
            == "RECONCILE_REQUIRED_NO_AUTOMATIC_REDISPATCH"
        )
        require(
            value.get("effect_uncertain") is uncertain and reconcile is uncertain,
            "error uncertainty semantics differ",
        )


def static_outputs() -> dict[str, bytes]:
    return {
        RUST_PATH: rust_source(),
        RUST_SCHEMA_BIN_PATH: rust_schema_binary_source(),
        RUST_TEST_PATH: rust_test_source(),
        ANDROID_VERIFY_PATH: android_verifier_source(),
        ANDROID_README_PATH: android_readme(),
        README_PATH: contract_readme(),
        COMPAT_CHECK_PATH: compatibility_checker_source(),
    }


def generated(root: Path, schemars_raw: bytes) -> dict[str, bytes]:
    catalog = strict_load((root / CATALOG_PATH).read_bytes(), CATALOG_PATH)
    modules = catalog.get("modules") if isinstance(catalog, dict) else None
    require(isinstance(modules, list) and modules, "module catalog has no modules array")
    ids = [module_id(item) for item in modules]
    require(len(ids) == len(set(ids)), "module catalog repeats a module id")
    schemars, normalized_schemars = validate_schemars_bundle(schemars_raw)
    states = lifecycle_states(root)
    rust = rust_source()
    contract_tests = [bytes_identity(path, raw) for path, raw in sorted(static_outputs().items()) if path in {RUST_TEST_PATH, ANDROID_VERIFY_PATH, COMPAT_CHECK_PATH}]
    binding = {
        "path": RUST_PATH,
        "size": len(rust),
        "sha256": sha(rust),
        "api_symbol": "ModuleApiEnvelopeV1",
        "state_symbol": "ModuleStateEnvelopeV1",
        "error_symbol": "ModuleErrorEnvelopeV1",
        "schemars": bytes_identity(SCHEMARS_PATH, normalized_schemars),
        "contract_tests": contract_tests,
    }
    outputs: dict[str, bytes] = static_outputs()
    outputs[SCHEMARS_PATH] = normalized_schemars
    records = []
    request_digest = "0" * 64
    for item in sorted(modules, key=module_id):
        mid = module_id(item)
        slug = mid.removeprefix("MOD-").lower()
        api, state, error = explicit_labels(item)
        sources, tests = source_bindings(root, item)
        dependencies = item.get("dependencies")
        require(isinstance(dependencies, list) and all(isinstance(value, str) for value in dependencies), f"{mid} dependencies are malformed")
        dependencies = sorted(set(dependencies))
        require(mid not in dependencies and set(dependencies) <= set(ids), f"{mid} dependencies are invalid")
        read_versions, write_versions = version_numbers(item)
        base = f"schemas/modules/{slug}"
        api_schema = specialize_schemars_schema(
            schemars["api"], identifier=api, title=f"{mid} API envelope v1",
            module=mid, label=api, kind="api", binding=binding,
        )
        state_schema = specialize_schemars_schema(
            schemars["state"], identifier=state, title=f"{mid} state envelope v1",
            module=mid, label=state, kind="state", binding=binding,
        )
        error_schema = specialize_schemars_schema(
            schemars["errors"], identifier=f"urn:trillionnium:{error}", title=f"{mid} error envelope v1",
            module=mid, label=error, kind="errors", binding=binding,
        )
        api_path=f"{base}/api-v1.schema.json"
        state_path=f"{base}/state-v1.schema.json"
        error_path=f"{base}/errors-v1.schema.json"
        outputs[api_path]=canonical_json(api_schema)
        outputs[state_path]=canonical_json(state_schema)
        outputs[error_path]=canonical_json(error_schema)
        valid_api = {
            "schema": api,
            "module_id": mid,
            "operation_id": "o" * 256,
            "request_digest": request_digest,
            "ordering_key": "k" * 512,
            "host_epoch": 1,
            "writer_epoch": 1,
            "fencing_token": "f" * 512,
            "payload": {},
        }
        valid_state = {
            "schema": state,
            "module_id": mid,
            "operation_id": "o" * 256,
            "request_digest": request_digest,
            "state": "ACCEPTED_DURABLE",
            "host_epoch": 1,
            "writer_epoch": 1,
            "fencing_token": "f" * 512,
            "durable_sequence": 1,
            "monotonic_ns": 1,
            "payload": {},
        }
        valid_error = {
            "schema": error,
            "module_id": mid,
            "operation_id": "o" * 256,
            "request_digest": request_digest,
            "code": "c" * 128,
            "class": "EFFECT_UNCERTAIN",
            "retry_disposition": "RECONCILE_REQUIRED_NO_AUTOMATIC_REDISPATCH",
            "effect_uncertain": True,
            "original_cause": "r" * 4096,
        }
        outputs[f"{base}/golden/valid/api.json"] = canonical_json(valid_api)
        outputs[f"{base}/golden/valid/state.json"] = canonical_json(valid_state)
        outputs[f"{base}/golden/valid/errors.json"] = canonical_json(valid_error)

        outputs[f"{base}/golden/invalid/api-duplicate.json"] = (
            json.dumps(valid_api, separators=(",", ":"))[:-1]
            + f',"module_id":"{mid}"}}\n'
        ).encode()
        invalid = dict(valid_api)
        invalid["unexpected"] = True
        outputs[f"{base}/golden/invalid/api-unknown.json"] = canonical_json(invalid)
        invalid = dict(valid_api)
        invalid.pop("ordering_key")
        outputs[f"{base}/golden/invalid/api-missing-ordering.json"] = canonical_json(invalid)
        invalid = dict(valid_api)
        invalid.pop("request_digest")
        invalid["request_hash"] = request_digest
        outputs[f"{base}/golden/invalid/api-identity-alias.json"] = canonical_json(invalid)
        nested: Any = {}
        for _ in range(40):
            nested = {"nested": nested}
        invalid = dict(valid_api)
        invalid["payload"] = nested
        outputs[f"{base}/golden/invalid/api-depth.json"] = canonical_json(invalid)
        invalid = dict(valid_api)
        invalid["host_epoch"] = True
        outputs[f"{base}/golden/invalid/api-boolean-epoch.json"] = canonical_json(invalid)

        invalid = copy.deepcopy(valid_api)
        invalid["payload"] = {"nested": ["__POSITIVE_EXPONENT_OVERFLOW__"]}
        raw = json.dumps(invalid, separators=(",", ":"), ensure_ascii=False)
        outputs[f"{base}/golden/invalid/api-payload-positive-exponent-overflow.json"] = (
            raw.replace('"__POSITIVE_EXPONENT_OVERFLOW__"', "1e400") + "\n"
        ).encode("utf-8")
        invalid = copy.deepcopy(valid_api)
        invalid["payload"] = {"nested": ["__NEGATIVE_EXPONENT_OVERFLOW__"]}
        raw = json.dumps(invalid, separators=(",", ":"), ensure_ascii=False)
        outputs[f"{base}/golden/invalid/api-payload-negative-exponent-overflow.json"] = (
            raw.replace('"__NEGATIVE_EXPONENT_OVERFLOW__"', "-1e400") + "\n"
        ).encode("utf-8")
        invalid = dict(valid_api)
        invalid["operation_id"] = "é" * 129
        outputs[f"{base}/golden/invalid/api-operation-multibyte-overflow.json"] = canonical_json(invalid)
        invalid = dict(valid_api)
        invalid["operation_id"] = "operation\u0085control"
        outputs[f"{base}/golden/invalid/api-operation-unicode-control.json"] = canonical_json(invalid)
        invalid = dict(valid_api)
        invalid["ordering_key"] = "é" * 257
        outputs[f"{base}/golden/invalid/api-ordering-multibyte-overflow.json"] = canonical_json(invalid)

        outputs[f"{base}/golden/invalid/state-nonfinite.json"] = (
            json.dumps(valid_state, separators=(",", ":"))[:-1]
            + ',"monotonic_ns":NaN}\n'
        ).encode()
        invalid = dict(valid_state)
        invalid["state"] = "REENTER_ACCEPTED_AFTER_FENCE"
        outputs[f"{base}/golden/invalid/state-invalid.json"] = canonical_json(invalid)
        invalid = dict(valid_state)
        invalid["durable_sequence"] = True
        outputs[f"{base}/golden/invalid/state-boolean-sequence.json"] = canonical_json(invalid)
        invalid = dict(valid_state)
        invalid["fencing_token"] = "é" * 257
        outputs[f"{base}/golden/invalid/state-fencing-multibyte-overflow.json"] = canonical_json(invalid)
        invalid = dict(valid_state)
        invalid["fencing_token"] = "fence\u0085control"
        outputs[f"{base}/golden/invalid/state-fencing-unicode-control.json"] = canonical_json(invalid)

        invalid = dict(valid_error)
        invalid.pop("code")
        outputs[f"{base}/golden/invalid/errors-missing.json"] = canonical_json(invalid)
        invalid = dict(valid_error)
        invalid["retry_disposition"] = "AUTOMATIC_REDISPATCH"
        outputs[f"{base}/golden/invalid/errors-retry.json"] = canonical_json(invalid)
        invalid = dict(valid_error)
        invalid["class"] = "UNKNOWN_ERROR_CLASS"
        outputs[f"{base}/golden/invalid/errors-class.json"] = canonical_json(invalid)
        invalid = dict(valid_error)
        invalid["effect_uncertain"] = False
        outputs[f"{base}/golden/invalid/errors-uncertainty.json"] = canonical_json(invalid)
        invalid = dict(valid_error)
        invalid["module_id"] = "MOD-CROSS-SPLICE"
        outputs[f"{base}/golden/invalid/errors-module-splice.json"] = canonical_json(invalid)
        invalid = dict(valid_error)
        invalid["code"] = "é" * 65
        outputs[f"{base}/golden/invalid/errors-code-multibyte-overflow.json"] = canonical_json(invalid)
        invalid = dict(valid_error)
        invalid["original_cause"] = "é" * 2049
        outputs[f"{base}/golden/invalid/errors-cause-multibyte-overflow.json"] = canonical_json(invalid)
        invalid = dict(valid_error)
        invalid["original_cause"] = "cause\u0085control"
        outputs[f"{base}/golden/invalid/errors-cause-unicode-control.json"] = canonical_json(invalid)
        compatibility_path=f"{base}/compatibility.json"
        compatibility={
            "schema":"org.trillionnium.module-contract-compatibility.v1",
            "module_id":mid,
            "api_semver":item["compatibility"]["api_semver"],
            "state_schema_version":item["state_contract"]["version"],
            "dependencies":dependencies,
            "contracts":{
                "api":{"logical_label":api,"artifact":api_path,"read_versions":read_versions,"write_versions":write_versions},
                "state":{"logical_label":state,"artifact":state_path,"read_versions":read_versions,"write_versions":write_versions},
                "errors":{"logical_label":error,"artifact":error_path,"read_versions":read_versions,"write_versions":write_versions},
            },
            "rust_binding":binding,
            "implementation_sources":sources,
            "test_sources":tests,
            "contract_tests":contract_tests,
            "unknown_fields":"REJECT",
            "duplicate_members":"REJECT",
            "nonfinite_numbers":"REJECT",
            "maximum_json_bytes":4194304,
            "maximum_json_depth":32,
            "effect_identity_defaults_allowed":False,
            "field_aliases_allowed":False,
            "automatic_redispatch_after_uncertainty":False,
            "change_review_class":"INITIAL_V1",
            "breaking_change_review":"REQUIRED_FOR_REQUIRED_TYPE_ENUM_DEFAULT_IDENTITY_ORDERING_STATE_OR_ERROR_CHANGE",
            "migration_review":item["migration"],
            "rollback_review":item["rollback"],
            "claim_ceiling":"L1_EXECUTABLE_CONTRACT_SOURCE_ONLY_NO_TARGET_OR_RELEASE_AUTHORITY",
            "public_release":False,
        }
        outputs[compatibility_path]=canonical_json(compatibility)
        records.append({
            "module_id":mid,
            "slug":slug,
            "logical_labels":{"api":api,"state":state,"errors":error},
            "artifacts":{"api":api_path,"state":state_path,"errors":error_path,"compatibility":compatibility_path,"valid_vectors":f"{base}/golden/valid","invalid_vectors":f"{base}/golden/invalid"},
            "implementation_sources":sources,
            "test_sources":tests,
            "dependencies":dependencies,
            "read_versions":read_versions,
            "write_versions":write_versions,
        })
    record_by={record["module_id"]:record for record in records}
    pairs=[]
    for consumer in records:
        for producer_id in consumer["dependencies"]:
            producer=record_by[producer_id]
            compatible=sorted(set(producer["write_versions"]) & set(consumer["read_versions"]))
            require(compatible, f"producer/consumer versions do not intersect: {producer_id}->{consumer['module_id']}")
            pairs.append({"producer":producer_id,"consumer":consumer["module_id"],"compatible_api_versions":compatible,"decision":"PASS"})
    machine={
        "schema":"org.trillionnium.module-contract-catalog.v1",
        "program_revision":catalog.get("program_revision"),
        "module_count":len(records),
        "modules":records,
        "producer_consumer_pair_count":len(pairs),
        "producer_consumer_pairs":pairs,
        "rust_binding":binding,
        "schemars_bundle":bytes_identity(SCHEMARS_PATH,normalized_schemars),
        "generator":file_identity(root,GENERATOR_PATH),
        "compatibility_checker":bytes_identity(COMPAT_CHECK_PATH,outputs[COMPAT_CHECK_PATH]),
        "python_consumer":GENERATOR_PATH,
        "rust_consumer":RUST_TEST_PATH,
        "android_build_host_consumer":ANDROID_VERIFY_PATH,
        "automatic_redispatch":False,
        "promotion_authorized":False,
        "public_release":False,
        "claim_ceiling":"L1_EXECUTABLE_CONTRACT_SOURCE_ONLY_NO_TARGET_OR_RELEASE_AUTHORITY",
    }
    outputs[CONTRACT_CATALOG_PATH]=canonical_json(machine)
    lines=["# Module Contract Status","","<!-- GENERATED BY tools/contracts/generate_module_contracts.py. DO NOT EDIT. -->","",f"- Modules: `{len(records)}`","- API/state/error schemas: `3 per module`","- Shared valid vectors: `3 per module`","- Shared invalid vectors: `24 per module`",f"- Producer/consumer pairs: `{len(pairs)}`","- Schemars projection: `byte-bound`","- Automatic redispatch after uncertainty: `false`","- Public release: `false`","","| Module | API | State | Errors | Compatibility |","| --- | --- | --- | --- | --- |"]
    for record in records:
        a=record["artifacts"]
        lines.append(f"| `{record['module_id']}` | `{a['api']}` | `{a['state']}` | `{a['errors']}` | `{a['compatibility']}` |")
    outputs[STATUS_PATH]=( "\n".join(lines)+"\n").encode()
    locked={path:{"bytes":len(raw),"sha256":sha(raw)} for path,raw in sorted(outputs.items())}
    outputs[LOCK_PATH]=canonical_json({"schema":"org.trillionnium.module-contract-lock.v1","artifacts":locked,"automatic_redispatch":False,"public_release":False})
    return outputs


def update_setup(root: Path) -> None:
    lib=root / "crates/trillionnium-owner-open-types/src/lib.rs"; text=lib.read_text(encoding="utf-8")
    if "pub mod module_contract;" not in text: lib.write_text(text.rstrip()+"\n\npub mod module_contract;\n",encoding="utf-8")
    cargo=root / "crates/trillionnium-owner-open-types/Cargo.toml"; cargo_text=cargo.read_text(encoding="utf-8")
    require("serde" in cargo_text and "serde_json" in cargo_text, "owner-open-types must already depend on serde and serde_json")
    if "schemars.workspace = true" not in cargo_text:
        marker="[dependencies]\n"
        require(cargo_text.count(marker)==1,"owner-open-types dependency section is ambiguous")
        cargo_text=cargo_text.replace(marker,marker+"schemars.workspace = true\n",1)
        cargo.write_text(cargo_text,encoding="utf-8")
    docset_path=root / "docs/machine/doc-set.v1.json"; docset=strict_load(docset_path.read_bytes(),str(docset_path))
    additions=[CONTRACT_CATALOG_PATH,STATUS_PATH]
    def visit(value: Any) -> None:
        if isinstance(value,dict):
            for item in value.values(): visit(item)
        elif isinstance(value,list) and all(isinstance(item,str) for item in value):
            if any(item==CATALOG_PATH for item in value) and CONTRACT_CATALOG_PATH not in value: value.append(CONTRACT_CATALOG_PATH)
            if any(item=="docs/START_HERE.md" for item in value) and STATUS_PATH not in value: value.append(STATUS_PATH)
    visit(docset); docset_path.write_bytes(canonical_json(docset))
    start=root / "docs/START_HERE.md"; source=start.read_text(encoding="utf-8")
    if STATUS_PATH not in source: start.write_text(source.rstrip()+f"\n\n- Executable module-contract status: [`{STATUS_PATH}`](MODULE_CONTRACT_STATUS.md)\n",encoding="utf-8")


def write_outputs(root: Path, outputs: dict[str, bytes]) -> None:
    for relative, raw in outputs.items():
        path=root / relative; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(raw)


def verify_outputs(root: Path, outputs: dict[str, bytes]) -> None:
    for relative, expected in outputs.items():
        path=root / relative
        require(path.is_file() and not path.is_symlink(),f"missing generated artifact: {relative}")
        require(path.read_bytes()==expected,f"generated artifact drift: {relative}")
    machine=strict_load((root / CONTRACT_CATALOG_PATH).read_bytes(),CONTRACT_CATALOG_PATH)
    require(machine.get("module_count")==len(machine.get("modules",[])),"module contract count differs")
    require(machine.get("producer_consumer_pair_count")==len(machine.get("producer_consumer_pairs",[])),"producer/consumer count differs")
    for record in machine["modules"]:
        base=root / f"schemas/modules/{record['slug']}"
        schemas={kind:strict_load((root/path).read_bytes(),path) for kind,path in (("api",record["artifacts"]["api"]),("state",record["artifacts"]["state"]),("errors",record["artifacts"]["errors"]))}
        for path in sorted((base / "golden/valid").glob("*.json")):
            kind=path.stem
            value=strict_load(path.read_bytes(),str(path))
            validate_schema(value,schemas[kind],str(path))
            validate_semantics(value,kind,record["module_id"],record["logical_labels"][kind])
        rejected=0
        for path in sorted((base / "golden/invalid").glob("*.json")):
            kind=path.name.split("-",1)[0]
            try:
                value=strict_load(path.read_bytes(),str(path))
                validate_schema(value,schemas[kind],str(path))
                validate_semantics(value,kind,record["module_id"],record["logical_labels"][kind])
            except ContractError:
                rejected+=1
            else:
                raise ContractError(f"invalid vector accepted: {path}")
        require(rejected==24,f"{record['module_id']} invalid vector count differs: {rejected}")
    subprocess.run([sys.executable,str(root / ANDROID_VERIFY_PATH)],cwd=root,check=True,timeout=60)


def install_generator(root: Path) -> None:
    target=root / GENERATOR_PATH; target.parent.mkdir(parents=True,exist_ok=True)
    raw=Path(__file__).read_bytes(); target.write_bytes(raw); os.chmod(target,0o755)


def parse_args() -> argparse.Namespace:
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,default=Path(__file__).resolve().parents[2])
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--prepare",action="store_true")
    group.add_argument("--write",action="store_true")
    group.add_argument("--check",action="store_true")
    group.add_argument("--verify",action="store_true")
    parser.add_argument("--install",action="store_true")
    parser.add_argument("--schemars-file",type=Path)
    return parser.parse_args()


def read_schemars(args: argparse.Namespace, root: Path) -> bytes:
    path=args.schemars_file if args.schemars_file is not None else root / SCHEMARS_PATH
    require(path.is_file() and not path.is_symlink(),"schemars bundle is unavailable")
    return path.read_bytes()


def main() -> int:
    args=parse_args(); root=args.root.resolve()
    try:
        if args.install:
            install_generator(root)
        if args.prepare:
            update_setup(root)
            write_outputs(root,static_outputs())
        elif args.write:
            update_setup(root)
            write_outputs(root,static_outputs())
            schemars_raw=read_schemars(args,root)
            outputs=generated(root,schemars_raw)
            write_outputs(root,outputs)
            verify_outputs(root,generated(root,schemars_raw))
        else:
            schemars_raw=read_schemars(args,root)
            outputs=generated(root,schemars_raw)
            verify_outputs(root,outputs)
        print(json.dumps({"result":"PASS","module_contracts":True,"public_release":False},sort_keys=True))
        return 0
    except (ContractError,OSError,subprocess.SubprocessError) as error:
        print(f"module-contract verification failed: {error}",file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
