#!/usr/bin/env python3
"""One-shot r4 foundation hardening used by the bootstrap workflow.

The workflow removes this script after applying the deterministic changes.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESIRED_HOST_MAIN = "use std::env;\nuse std::io::{self, BufRead, BufReader, Read, Write};\nuse std::os::unix::ffi::OsStrExt;\nuse std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};\nuse std::os::unix::net::{UnixListener, UnixStream};\nuse std::path::{Path, PathBuf};\nuse std::sync::atomic::{AtomicU64, Ordering};\nuse std::time::{SystemTime, UNIX_EPOCH};\n\nuse trillionnium_owner_open_host::{ConnectionEngine, UnavailableProvider};\nuse trillionnium_owner_open_types::MechanicalLimits;\n\nstatic CONNECTION_ORDINAL: AtomicU64 = AtomicU64::new(1);\n\nfn main() {\n    if let Err(error) = run() {\n        eprintln!(\"trillionnium-owner-open-host: {error}\");\n        std::process::exit(2);\n    }\n}\n\nfn run() -> Result<(), String> {\n    let args = env::args_os().skip(1).collect::<Vec<_>>();\n    match args.as_slice() {\n        [] => serve_stdio(),\n        [flag] if flag == \"--stdio\" => serve_stdio(),\n        [flag, path] if flag == \"--unix\" => serve_unix(Path::new(path)),\n        _ => Err(\n            \"usage: trillionnium-owner-open-host [--stdio | --unix /absolute/socket/path]\"\n                .to_string(),\n        ),\n    }\n}\n\nfn serve_stdio() -> Result<(), String> {\n    let stdin = io::stdin();\n    let stdout = io::stdout();\n    process_connection(\n        BufReader::new(stdin.lock()),\n        stdout.lock(),\n        new_connection_id(),\n    )\n}\n\nfn serve_unix(path: &Path) -> Result<(), String> {\n    validate_socket_path(path)?;\n    if std::fs::symlink_metadata(path).is_ok() {\n        return Err(format!(\n            \"refusing to replace existing socket path {}; remove a proven stale entry explicitly\",\n            path.display()\n        ));\n    }\n    let parent = path\n        .parent()\n        .ok_or_else(|| \"Unix socket path has no parent\".to_string())?;\n    validate_socket_parent(parent)?;\n\n    let listener = UnixListener::bind(path)\n        .map_err(|error| format!(\"cannot bind Unix socket {}: {error}\", path.display()))?;\n    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))\n        .map_err(|error| format!(\"cannot set Unix socket mode on {}: {error}\", path.display()))?;\n    let socket_metadata = std::fs::symlink_metadata(path)\n        .map_err(|error| format!(\"cannot inspect bound Unix socket {}: {error}\", path.display()))?;\n    let effective_uid = unsafe { libc::geteuid() };\n    if !socket_metadata.file_type().is_socket()\n        || socket_metadata.uid() != effective_uid\n        || socket_metadata.mode() & 0o7777 != 0o600\n        || socket_metadata.nlink() != 1\n    {\n        return Err(\"bound Unix socket does not have the expected owner-controlled identity\".to_string());\n    }\n    let _cleanup = SocketCleanup {\n        path: path.to_path_buf(),\n        device: socket_metadata.dev(),\n        inode: socket_metadata.ino(),\n    };\n\n    for accepted in listener.incoming() {\n        match accepted {\n            Ok(stream) => {\n                if let Err(error) = serve_stream(stream) {\n                    eprintln!(\"owner-open connection closed: {error}\");\n                }\n            }\n            Err(error) => eprintln!(\"owner-open accept failed: {error}\"),\n        }\n    }\n    Ok(())\n}\n\nfn validate_socket_parent(parent: &Path) -> Result<(), String> {\n    let metadata = std::fs::symlink_metadata(parent)\n        .map_err(|error| format!(\"cannot inspect socket parent {}: {error}\", parent.display()))?;\n    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.nlink() == 0 {\n        return Err(\"Unix socket parent must be a stable real directory\".to_string());\n    }\n    let mode = metadata.mode() & 0o7777;\n    let effective_uid = unsafe { libc::geteuid() };\n    let trusted_owner = metadata.uid() == 0 || metadata.uid() == effective_uid;\n    let root_sticky_directory = metadata.uid() == 0 && mode & libc::S_ISVTX != 0;\n    if !trusted_owner || (mode & 0o022 != 0 && !root_sticky_directory) {\n        return Err(format!(\n            \"Unix socket parent must be root/service-owned and not group/world writable: {} (uid {}, mode {:04o})\",\n            parent.display(),\n            metadata.uid(),\n            mode\n        ));\n    }\n    Ok(())\n}\n\nstruct SocketCleanup {\n    path: PathBuf,\n    device: u64,\n    inode: u64,\n}\n\nimpl Drop for SocketCleanup {\n    fn drop(&mut self) {\n        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {\n            return;\n        };\n        if metadata.file_type().is_socket()\n            && metadata.dev() == self.device\n            && metadata.ino() == self.inode\n        {\n            let _ = std::fs::remove_file(&self.path);\n        }\n    }\n}\n\nfn serve_stream(stream: UnixStream) -> Result<(), String> {\n    let writer = stream\n        .try_clone()\n        .map_err(|error| format!(\"cannot clone Unix stream: {error}\"))?;\n    process_connection(BufReader::new(stream), writer, new_connection_id())\n}\n\nfn process_connection<R: BufRead, W: Write>(\n    mut reader: R,\n    mut writer: W,\n    connection_id: String,\n) -> Result<(), String> {\n    let limits = MechanicalLimits::default();\n    let mut engine = ConnectionEngine::new(connection_id, UnavailableProvider::default())\n        .map_err(|error| error.to_string())?\n        .with_limits(limits.clone());\n    loop {\n        let Some(frame) = read_bounded_frame(&mut reader, limits.max_frame_bytes)? else {\n            return Ok(());\n        };\n        match engine.handle_encoded(&frame) {\n            Ok(output) => {\n                for frame in output {\n                    write_frame(&mut writer, &frame, limits.max_frame_bytes)?;\n                }\n            }\n            Err(error) => {\n                let response = engine.error_frame(&error);\n                write_frame(&mut writer, &response, limits.max_frame_bytes)?;\n            }\n        }\n    }\n}\n\nfn read_bounded_frame<R: BufRead>(\n    reader: &mut R,\n    max_frame_bytes: usize,\n) -> Result<Option<Vec<u8>>, String> {\n    let mut frame = Vec::new();\n    let read = reader\n        .take(max_frame_bytes as u64 + 2)\n        .read_until(b'\\n', &mut frame)\n        .map_err(|error| format!(\"failed to read frame: {error}\"))?;\n    if read == 0 {\n        return Ok(None);\n    }\n    if frame.last() != Some(&b'\\n') {\n        return Err(\"frame is not newline terminated or exceeds the configured bound\".to_string());\n    }\n    frame.pop();\n    if frame.is_empty() || frame.len() > max_frame_bytes {\n        return Err(\"frame is empty or exceeds the configured bound\".to_string());\n    }\n    Ok(Some(frame))\n}\n\nfn write_frame<W: Write>(\n    writer: &mut W,\n    frame: &impl serde::Serialize,\n    max_frame_bytes: usize,\n) -> Result<(), String> {\n    let encoded = serde_json::to_vec(frame)\n        .map_err(|error| format!(\"failed to encode response frame: {error}\"))?;\n    if encoded.is_empty() || encoded.len() > max_frame_bytes {\n        return Err(\"response frame is empty or exceeds the configured bound\".to_string());\n    }\n    writer\n        .write_all(&encoded)\n        .and_then(|_| writer.write_all(b\"\\n\"))\n        .and_then(|_| writer.flush())\n        .map_err(|error| format!(\"failed to write response frame: {error}\"))\n}\n\nfn validate_socket_path(path: &Path) -> Result<(), String> {\n    if path.as_os_str().as_bytes().first() == Some(&b'@') {\n        return Err(\n            \"Android abstract sockets require the W6 Android carrier; use --stdio or a filesystem UDS in the foundation build\"\n                .to_string(),\n        );\n    }\n    if !path.is_absolute() {\n        return Err(\"Unix socket path must be absolute\".to_string());\n    }\n    if path.as_os_str().as_bytes().len() > 100 {\n        return Err(\"Unix socket path exceeds the portable byte bound\".to_string());\n    }\n    Ok(())\n}\n\nfn new_connection_id() -> String {\n    let ordinal = CONNECTION_ORDINAL.fetch_add(1, Ordering::Relaxed);\n    let nanos = SystemTime::now()\n        .duration_since(UNIX_EPOCH)\n        .map(|duration| duration.as_nanos())\n        .unwrap_or(0);\n    format!(\"connection-{}-{nanos}-{ordinal}\", std::process::id())\n}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n    use serde_json::Value;\n    use std::io::Cursor;\n\n    #[test]\n    fn stdio_protocol_emits_hello_ack_and_honest_provider_hold() {\n        let input = concat!(\n            \"{\\\"kind\\\":\\\"hello\\\",\\\"seq\\\":0,\\\"payload\\\":{}}\\n\",\n            \"{\\\"kind\\\":\\\"turn.start\\\",\\\"seq\\\":1,\\\"payload\\\":{\",\n            \"\\\"protocol\\\":\\\"trillionnium.agent.turn.v1\\\",\",\n            \"\\\"protocol_version\\\":1,\",\n            \"\\\"session_id\\\":\\\"session-1\\\",\",\n            \"\\\"task_id\\\":\\\"task-1\\\",\",\n            \"\\\"turn_id\\\":\\\"turn-1\\\",\",\n            \"\\\"user_input\\\":\\\"pwd\\\"}}\\n\"\n        );\n        let mut output = Vec::new();\n        process_connection(\n            BufReader::new(Cursor::new(input.as_bytes())),\n            &mut output,\n            \"connection-test\".to_string(),\n        )\n        .unwrap();\n        let frames = String::from_utf8(output)\n            .unwrap()\n            .lines()\n            .map(|line| serde_json::from_str::<Value>(line).unwrap())\n            .collect::<Vec<_>>();\n        assert_eq!(frames[0][\"kind\"], \"hello.ack\");\n        assert_eq!(frames[1][\"kind\"], \"turn.accepted\");\n        assert_eq!(frames.last().unwrap()[\"kind\"], \"turn.end\");\n        assert_eq!(\n            frames.last().unwrap()[\"payload\"][\"status\"],\n            \"provider_unavailable\"\n        );\n    }\n\n    #[test]\n    fn oversized_or_unterminated_frames_are_rejected() {\n        let mut reader = BufReader::new(Cursor::new(b\"abcd\"));\n        assert!(read_bounded_frame(&mut reader, 3).is_err());\n    }\n\n    #[test]\n    fn foundation_refuses_to_guess_an_android_abstract_socket() {\n        assert!(validate_socket_path(Path::new(\"@abstract\")).is_err());\n        assert!(validate_socket_path(Path::new(\"relative.sock\")).is_err());\n        assert!(validate_socket_path(Path::new(\"/tmp/owner-open.sock\")).is_ok());\n    }\n\n    #[test]\n    fn writable_service_owned_socket_parent_is_rejected() {\n        let path = std::env::temp_dir().join(format!(\n            \"trillionnium-owner-open-parent-{}-{}\",\n            std::process::id(),\n            CONNECTION_ORDINAL.fetch_add(1, Ordering::Relaxed)\n        ));\n        std::fs::create_dir(&path).unwrap();\n        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();\n        let error = validate_socket_parent(&path).unwrap_err();\n        assert!(error.contains(\"not group/world writable\"));\n        std::fs::remove_dir(&path).unwrap();\n    }\n}\n"
DESIRED_FOUNDATION_WORKFLOW = "name: owner-open foundation\n\non:\n  pull_request:\n    paths:\n      - \"Cargo.toml\"\n      - \"apps/trillionnium-owner-open-host/**\"\n      - \"Cargo.lock\"\n      - \"crates/trillionnium-owner-open-types/**\"\n      - \"docs/TRILLIONNIUM_OWNER_OPEN_R4_EXECUTION_PLAN.md\"\n      - \"docs/status/owner-open-r4-*\"\n      - \"docs/security/owner-open-threat-model.md\"\n      - \"docs/protocols/owner-open-direct-agent-host-v1.md\"\n      - \"docs/contracts/owner-open-forbidden-default-graph-v1.json\"\n      - \"docs/contracts/codex-sovereign-direct-tools-v1.json\"\n      - \"schemas/codex-sovereign-direct-tools.schema.json\"\n      - \"tools/generate-owner-open-types.py\"\n      - \"tools/verify-owner-open-foundation.py\"\n      - \"tools/tests/**\"\n      - \".github/workflows/owner-open-foundation.yml\"\n  push:\n    branches:\n      - main\n      - \"codex/**\"\n    paths:\n      - \"Cargo.toml\"\n      - \"apps/trillionnium-owner-open-host/**\"\n      - \"Cargo.lock\"\n      - \"crates/trillionnium-owner-open-types/**\"\n      - \"docs/TRILLIONNIUM_OWNER_OPEN_R4_EXECUTION_PLAN.md\"\n      - \"docs/status/owner-open-r4-*\"\n      - \"docs/security/owner-open-threat-model.md\"\n      - \"docs/protocols/owner-open-direct-agent-host-v1.md\"\n      - \"docs/contracts/owner-open-forbidden-default-graph-v1.json\"\n      - \"docs/contracts/codex-sovereign-direct-tools-v1.json\"\n      - \"schemas/codex-sovereign-direct-tools.schema.json\"\n      - \"tools/generate-owner-open-types.py\"\n      - \"tools/verify-owner-open-foundation.py\"\n      - \"tools/tests/**\"\n      - \".github/workflows/owner-open-foundation.yml\"\n  workflow_dispatch:\n\npermissions:\n  contents: read\n\nconcurrency:\n  group: owner-open-foundation-${{ github.ref }}\n  cancel-in-progress: true\n\njobs:\n  foundation:\n    name: L0-L1 owner-open foundation\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n\n    steps:\n      - name: Check out source\n        uses: actions/checkout@v4\n\n      - name: Set up Python\n        uses: actions/setup-python@v5\n        with:\n          python-version: \"3.12\"\n\n      - name: Set up Rust 1.93\n        uses: dtolnay/rust-toolchain@master\n        with:\n          toolchain: \"1.93.0\"\n          components: rustfmt\n\n      - name: Validate JSON and Python syntax\n        run: |\n          python3 -m json.tool docs/status/owner-open-r4-status.json >/dev/null\n          python3 -m json.tool docs/contracts/owner-open-forbidden-default-graph-v1.json >/dev/null\n          python3 -m json.tool schemas/codex-sovereign-direct-tools.schema.json >/dev/null\n          python3 -m py_compile \\\n            tools/generate-owner-open-types.py \\\n            tools/verify-owner-open-foundation.py \\\n            tools/tests/test_verify_owner_open_foundation.py\n\n      - name: Verify generated codec constants\n        run: python3 tools/generate-owner-open-types.py --check\n\n      - name: Verify owner-open default graph and status\n        run: python3 tools/verify-owner-open-foundation.py --json | tee owner-open-foundation-report.json\n\n      - name: Run verifier negative tests\n        run: python3 -m unittest discover -s tools/tests -p 'test_*.py' -v\n\n      - name: Check isolated Rust formatting\n        run: |\n          cargo fmt --package trillionnium-owner-open-types -- --check\n          cargo fmt --package trillionnium-owner-open-host -- --check\n\n      - name: Refresh lock and test isolated owner-open packages\n        run: |\n          cargo generate-lockfile\n          cargo test --locked --package trillionnium-owner-open-types\n          cargo test --locked --package trillionnium-owner-open-host\n\n      - name: Capture Cargo graph and generated lock\n        run: |\n          cargo metadata --locked --format-version 1 > owner-open-cargo-metadata.json\n          cargo tree --locked -e features -p trillionnium-owner-open-types > owner-open-cargo-tree.txt\n          cargo tree --locked -e features -p trillionnium-owner-open-host >> owner-open-cargo-tree.txt\n          git diff -- Cargo.lock > owner-open-cargo-lock.patch || true\n\n      - name: Upload L0-L1 foundation evidence\n        uses: actions/upload-artifact@v4\n        with:\n          name: owner-open-foundation-${{ github.sha }}\n          if-no-files-found: error\n          retention-days: 14\n          path: |\n            Cargo.lock\n            owner-open-foundation-report.json\n            owner-open-cargo-metadata.json\n            owner-open-cargo-tree.txt\n            owner-open-cargo-lock.patch\n"


def patch_owner_open_types() -> None:
    path = ROOT / "crates/trillionnium-owner-open-types/src/lib.rs"
    text = path.read_text(encoding="utf-8")
    old = """        match (&self.command, &self.argv) {
            (Some(_), None) | (None, Some(_)) => Ok(()),
            (None, None) => Err(invalid("shell.exec requires command or argv")),
            (Some(_), Some(_)) => Err(invalid(
                "shell.exec command and argv are mutually exclusive",
            )),
        }
"""
    new = """        match (&self.command, &self.argv) {
            (Some(_), None) => Ok(()),
            (None, Some(argv)) if !argv.is_empty() => Ok(()),
            (None, Some(_)) => Err(invalid("shell.exec argv requires an executable")),
            (None, None) => Err(invalid("shell.exec requires command or argv")),
            (Some(_), Some(_)) => Err(invalid(
                "shell.exec command and argv are mutually exclusive",
            )),
        }
"""
    if old in text:
        text = text.replace(old, new, 1)
    elif new not in text:
        raise RuntimeError("shell.exec validation anchor is missing")

    empty_shell_test = """
        call.command = None;
        call.argv = Some(Vec::new());
        assert!(call.validate_shell_exec(&limits).is_err());
"""
    test_anchor = """        call.command = Some("pwd".to_string());
        assert!(call.validate_shell_exec(&limits).is_err());
"""
    if empty_shell_test not in text:
        if test_anchor not in text:
            raise RuntimeError("shell.exec test anchor is missing")
        text = text.replace(test_anchor, test_anchor + empty_shell_test, 1)

    empty_adb_test_name = "fn adb_empty_argv_preserves_ordinary_client_behavior()"
    if empty_adb_test_name not in text:
        anchor = """    #[test]
    fn no_serial_host_port_or_privilege_is_injected_by_the_codec() {
"""
        test = """    #[test]
    fn adb_empty_argv_preserves_ordinary_client_behavior() {
        let limits = MechanicalLimits::default();
        let mut call = base_tool_call();
        call.tool = "adb.exec".to_string();
        call.target = None;
        call.argv = Some(Vec::new());
        call.validate_adb_exec(&limits).unwrap();
    }

"""
        if anchor not in text:
            raise RuntimeError("ADB codec test anchor is missing")
        text = text.replace(anchor, test + anchor, 1)
    path.write_text(text, encoding="utf-8")


def patch_host_manifest() -> None:
    path = ROOT / "apps/trillionnium-owner-open-host/Cargo.toml"
    text = path.read_text(encoding="utf-8")
    if "libc.workspace = true" not in text:
        anchor = "[dependencies]\n"
        if anchor not in text:
            raise RuntimeError("owner-open Host dependency section is missing")
        text = text.replace(anchor, anchor + "libc.workspace = true\n", 1)
    path.write_text(text, encoding="utf-8")


def patch_schema() -> None:
    path = ROOT / "schemas/codex-sovereign-direct-tools.schema.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    shell_argv = value["$defs"]["shellExec"]["allOf"][1]["oneOf"][1]["properties"]["argv"]
    shell_argv["minItems"] = 1
    adb_argv = value["$defs"]["adbExec"]["allOf"][1]["properties"]["argv"]
    adb_argv.pop("minItems", None)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    patch_owner_open_types()
    patch_host_manifest()
    patch_schema()
    (ROOT / "apps/trillionnium-owner-open-host/src/main.rs").write_text(
        DESIRED_HOST_MAIN, encoding="utf-8"
    )
    (ROOT / ".github/workflows/owner-open-foundation.yml").write_text(
        DESIRED_FOUNDATION_WORKFLOW, encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
