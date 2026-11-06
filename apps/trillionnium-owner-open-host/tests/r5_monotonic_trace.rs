use serde_json::Value;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
mod support;
use support::secure_tempdir;

#[test]
fn real_provider_callback_preserves_failure_and_exports_only_snapshot_evidence() {
    let root = secure_tempdir();
    let provider = root.path().join("provider.sh");
    fs::write(&provider, r#"#!/bin/sh
IFS= read -r start || exit 10
sleep 0.03
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":0,"call":{"call_id":"owned-trace-call","tool":"shell.exec","command":"printf owned-output; sleep 0.02; exit 9"}}'
IFS= read -r result || exit 11
case "$result" in *'"kind":"tool.result"'*) ;; *) exit 12 ;; esac
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":1,"summary":"observed tool failure"}'
"#).unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();
    let prefix = root.path().join("trace");
    let mut child = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-host"))
        .args([
            "--transport-core",
            env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-core"),
        ])
        .arg("--provider")
        .arg(&provider)
        .arg("--event-store")
        .arg(root.path().join("events.jsonl"))
        .env("TRILLIONNIUM_OWNER_TRACE_SAMPLE", "owned-real-turn")
        .env("TRILLIONNIUM_OWNER_TRACE_OUTPUT", &prefix)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "{{\"kind\":\"hello\",\"seq\":0,\"payload\":{{\"protocol\":\"trillionnium.agent.turn.v1\",\"protocol_version\":1}}}}").unwrap();
        writeln!(stdin, "{{\"kind\":\"turn.start\",\"seq\":1,\"direction\":\"client_to_host\",\"payload\":{{\"protocol\":\"trillionnium.agent.turn.v1\",\"protocol_version\":1,\"session_id\":\"owned-session\",\"task_id\":\"owned-task\",\"turn_id\":\"owned-turn\",\"user_input\":\"owned callback fixture\"}}}}").unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let frames = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str::<Value>(s).unwrap())
        .collect::<Vec<_>>();
    let result = frames.iter().find(|v| v["kind"] == "tool.result").unwrap();
    assert_eq!(result["payload"]["exit_code"], 9);
    assert_eq!(frames.last().unwrap()["kind"], "turn.end");
    let core: Value =
        serde_json::from_slice(&fs::read(prefix.with_extension("core")).unwrap()).unwrap();
    let transport: Value =
        serde_json::from_slice(&fs::read(prefix.with_extension("transport")).unwrap()).unwrap();
    for snapshot in [&core, &transport] {
        assert_eq!(snapshot["snapshot_only"], true);
        assert_eq!(snapshot["trace_complete"], false);
        assert_eq!(snapshot["producer_quiescence_proven"], false);
        assert_eq!(snapshot["installed_qualified"], false);
        assert_eq!(snapshot["sample_id"], "owned-real-turn");
        for row in snapshot["records"].as_array().unwrap() {
            assert!(row["end_ns"].as_u64().unwrap() >= row["start_ns"].as_u64().unwrap());
            assert_eq!(row["scope_sha256"].as_str().unwrap().len(), 64);
        }
    }
    let rows = core["records"].as_array().unwrap();
    let mut missing = Vec::new();
    for expected in [
        "host_decode",
        "host_capacity_wait",
        "journal_append",
        "journal_fsync",
        "provider_spawn",
        "provider_first_event",
        "provider_wait",
        "callback_admission",
        "tool_spawn",
        "tool_output",
        "tool_exit",
        "tool_cleanup",
        "terminal_persistence",
    ] {
        if !rows.iter().any(|row| row["stage"] == expected) {
            missing.push(expected);
        }
    }
    // Nonblocking producer contention can legitimately reject a record.
    // A missing boundary must remain explicitly unqualified, never be filled
    // with a fabricated duration or silently asserted as full coverage.
    if !missing.is_empty() {
        assert_eq!(
            core["loss_observed"], true,
            "missing without retained loss: {core}"
        );
        assert!(core["lost_records"].as_u64().unwrap() > 0);
        assert_eq!(core["snapshot_without_observed_loss"], false);
    }
    if let Some(first) = rows
        .iter()
        .find(|row| row["stage"] == "provider_first_event")
    {
        assert!(
            first["end_ns"].as_u64().unwrap() - first["start_ns"].as_u64().unwrap() >= 20_000_000
        );
    }
    let delivery = transport["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["stage"] == "client_delivery");
    if !delivery {
        assert_eq!(transport["loss_observed"], true);
        assert!(transport["lost_records"].as_u64().unwrap() > 0);
        assert_eq!(transport["snapshot_without_observed_loss"], false);
    }
    println!(
        "owned stage evidence coverage: missing_core={missing:?} transport_delivery_observed={delivery}; snapshots remain provisional; core={core}; transport={transport}"
    );
}

#[test]
fn disabled_entrypoint_creates_no_trace_file() {
    let root = secure_tempdir();
    let prefix = root.path().join("disabled");
    let result = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-core"))
        .arg("--help")
        .env_remove("TRILLIONNIUM_OWNER_TRACE_SAMPLE")
        .env("TRILLIONNIUM_OWNER_TRACE_OUTPUT", &prefix)
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(!prefix.with_extension("core").exists());
}

#[test]
fn opt_in_export_collision_is_nonzero_without_replacing_existing_inode() {
    let root = secure_tempdir();
    let prefix = root.path().join("collision");
    let entity = prefix.with_extension("core");
    fs::write(&entity, b"existing evidence").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-core"))
        .arg("--help")
        .env("TRILLIONNIUM_OWNER_TRACE_SAMPLE", "collision")
        .env("TRILLIONNIUM_OWNER_TRACE_OUTPUT", &prefix)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(fs::read(entity).unwrap(), b"existing evidence");
    assert!(String::from_utf8_lossy(&result.stderr).contains("trace export unavailable"));
}
