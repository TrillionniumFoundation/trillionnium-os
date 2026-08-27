use trillionnium_tool_runtime::{
    AndroidGatewayAdapter, ToolRuntimeAdapter, android_gateway_manifests,
    executable_android_gateway_manifests, production_agent_api_manifests,
};

const ISOLATED_DEFAULT_GRAPH: &str = "TRILLIONNIUM_PRODUCTION_DIRECT_ONLY_ISOLATED_DEFAULT_GRAPH";

#[test]
fn default_library_has_no_generic_android_plan_effect_catalog() {
    // A workspace-wide test build unifies dev-dependency features from the
    // retired plan conformance crates. Verify the production-negative contract
    // in a separately resolved package graph instead of weakening it in that
    // known-positive legacy graph.
    if cfg!(feature = "legacy-authority-effects") {
        assert_default_library_in_isolated_feature_graph();
        return;
    }

    assert_default_library_catalog_is_direct_only();
}

fn assert_default_library_catalog_is_direct_only() {
    assert!(android_gateway_manifests().is_empty());
    assert!(executable_android_gateway_manifests().is_empty());
    assert!(production_agent_api_manifests().is_empty());
    assert!(
        AndroidGatewayAdapter::system_default()
            .manifests()
            .is_empty()
    );
}

fn assert_default_library_in_isolated_feature_graph() {
    assert!(
        std::env::var_os(ISOLATED_DEFAULT_GRAPH).is_none(),
        "the isolated default graph unexpectedly enabled legacy-authority-effects"
    );

    let target_dir = tempfile::Builder::new()
        .prefix("trillionnium-production-direct-only-")
        .tempdir()
        .expect("create an isolated Cargo target directory");
    let output = std::process::Command::new(
        std::env::var_os("CARGO").unwrap_or_else(|| std::ffi::OsString::from("cargo")),
    )
    .current_dir(env!("CARGO_MANIFEST_DIR"))
    .args([
        "test",
        "--quiet",
        "--locked",
        "--offline",
        "--no-default-features",
        "--package",
        "trillionnium-tool-runtime",
        "--test",
        "production_direct_only",
        "--",
        "--exact",
        "default_library_has_no_generic_android_plan_effect_catalog",
    ])
    .env("CARGO_TARGET_DIR", target_dir.path())
    .env(ISOLATED_DEFAULT_GRAPH, "1")
    .output()
    .expect("run the production-negative test in an isolated default feature graph");

    assert!(
        output.status.success(),
        "isolated default feature graph failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
