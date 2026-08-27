#![cfg(feature = "production-durable-hotpath")]

use std::process::{Command, Stdio};

#[test]
fn product_binaries_fail_entry_checkpoint_before_rejecting_caller_argv() {
    for binary in [
        env!("CARGO_BIN_EXE_trillionnium-agent-system-api"),
        env!("CARGO_BIN_EXE_trillionnium-agent-accessibility"),
    ] {
        let output = Command::new(binary)
            .arg("caller-selected-invalid-mode")
            .stdin(Stdio::null())
            .output()
            .expect("run product Direct Tool fixture");
        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
        assert!(
            stderr.contains("product Direct Tool entry checkpoint"),
            "unexpected stderr: {stderr}"
        );
        assert!(
            !stderr.contains("usage:"),
            "argv was parsed before checkpoint"
        );
    }
}

#[test]
fn source_order_keeps_checkpoint_before_argv_and_stdin() {
    for source in [
        include_str!("../src/bin/system_api.rs"),
        include_str!("../src/bin/accessibility.rs"),
    ] {
        let entry = source
            .find(
                "let _entry_checkpoint = production_entry_hardening::enter_product_direct_tool_checkpoint(",
            )
            .expect("entry checkpoint call");
        let run = source[..entry]
            .rfind("fn run() -> trillionnium_agent_direct_tools::Result<()> {")
            .expect("product run function containing entry checkpoint");
        assert!(run < entry);
        assert!(entry < source.find("std::env::args_os").expect("argv read"));
        assert!(entry < source.find("read_request()?").expect("stdin read"));
    }
}
