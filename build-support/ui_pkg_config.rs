use std::env;
use std::process::Command;

pub fn configure() {
    println!("cargo:rerun-if-changed=../../build-support/ui_pkg_config.rs");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR");

    if env::var_os("CARGO_FEATURE_UI").is_none() {
        return;
    }

    let output = Command::new("pkg-config")
        .args(["--libs", "libadwaita-1", "gtk4"])
        .output()
        .expect("feature `ui` requires pkg-config to locate libadwaita-1 and gtk4");

    if !output.status.success() {
        panic!(
            "feature `ui` requires pkg-config modules libadwaita-1 and gtk4; pkg-config failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let libs = String::from_utf8_lossy(&output.stdout);
    for token in libs.split_whitespace() {
        if let Some(path) = token.strip_prefix("-L") {
            if !path.is_empty() {
                println!("cargo:rustc-link-search=native={path}");
            }
        } else if let Some(lib) = token.strip_prefix("-l") {
            if !lib.is_empty() {
                println!("cargo:rustc-link-lib={lib}");
            }
        } else if token.starts_with("-Wl,") {
            println!("cargo:rustc-link-arg={token}");
        }
    }
}
