use std::env;

const FEATURE_ENV: &str = "CARGO_FEATURE_P0_LAUNCH_PACKAGE_PROVIDER_CONFORMANCE";
const VARIANT_ENV: &str = "TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT";

fn main() {
    println!("cargo:rerun-if-env-changed={VARIANT_ENV}");
    println!("cargo:rustc-check-cfg=cfg(p01_provider_conformance_variant, values(\"userdebug\"))");

    if env::var_os(FEATURE_ENV).is_none() {
        return;
    }

    let variant = env::var(VARIANT_ENV).unwrap_or_else(|_| {
        panic!("{VARIANT_ENV}=userdebug is required for the non-product P0 provider feature")
    });
    match variant.as_str() {
        "userdebug" => {
            println!("cargo:rustc-cfg=p01_provider_conformance_variant=\"{variant}\"");
            println!("cargo:rustc-env={VARIANT_ENV}={variant}");
        }
        _ => panic!(
            "{VARIANT_ENV} must be exactly userdebug for the non-product P0 provider feature"
        ),
    }
}
