use schemars::schema_for;
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
