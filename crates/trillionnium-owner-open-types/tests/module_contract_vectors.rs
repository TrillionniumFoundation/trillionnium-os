use std::fs;
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
