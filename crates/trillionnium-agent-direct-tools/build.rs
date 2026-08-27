use std::env;

fn main() {
    const FEATURE_ENV: &str = "CARGO_FEATURE_DEVICE_LAUNCH_PACKAGE_CONFORMANCE";
    const VARIANT_ENV: &str = "TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT";

    println!("cargo:rerun-if-env-changed={VARIANT_ENV}");
    println!(
        "cargo:rustc-check-cfg=cfg(p01_conformance_variant, values(\"userdebug\", \"invalid\"))"
    );
    let variant = match (
        env::var_os(FEATURE_ENV).is_some(),
        env::var(VARIANT_ENV).as_deref(),
    ) {
        (true, Ok("userdebug")) => "userdebug",
        (true, _) => {
            panic!("{VARIANT_ENV} must be exactly userdebug for the device-conformance feature")
        }
        (false, _) => "invalid",
    };
    println!("cargo:rustc-cfg=p01_conformance_variant=\"{variant}\"");
}
