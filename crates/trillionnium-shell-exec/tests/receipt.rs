use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};

use tempfile::TempDir;
use trillionnium_os_types::agent_descriptor_registry;
use trillionnium_os_types::direct_effect::{
    DirectEffectExecutionProfileV1, DirectEffectModelArgumentsV1, DirectEffectRequestV1,
    DirectEffectRiskClassV1, DirectEffectToolV1, INVOCATION_ID_PREFIX, OS_TOOL_CALL_ID_PREFIX,
    PROVIDER_ATTEMPT_ID_PREFIX,
};
use trillionnium_shell_exec::{
    DurableShellExecLedgerV1, DurableShellExecReceiptStoreV1, ShellExecEffectReceiptV1,
};

fn digest(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn private_tempdir() -> TempDir {
    let directory = TempDir::new().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn boottime_ms() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) },
        0
    );
    value.tv_sec as u64 * 1000 + value.tv_nsec as u64 / 1_000_000
}

fn request(now: u64) -> DirectEffectRequestV1 {
    DirectEffectRequestV1::derive_os_owned(
        agent_descriptor_registry::CODEX.provider_id.to_string(),
        agent_descriptor_registry::CODEX.agent_id.to_string(),
        digest('1'),
        format!("{INVOCATION_ID_PREFIX}{}", digest('2')),
        format!("{PROVIDER_ATTEMPT_ID_PREFIX}{}", digest('3')),
        format!("{OS_TOOL_CALL_ID_PREFIX}{}", digest('4')),
        1,
        digest('5'),
        digest('6'),
        trillionnium_shell_exec::current_boot_id_sha256().unwrap(),
        DirectEffectToolV1::ShellExecV1,
        DirectEffectModelArgumentsV1 {
            argv: vec!["/usr/bin/printf".to_string(), "literal".to_string()],
            cwd: None,
            timeout_ms: 5_000,
            stdout_limit_bytes: 16,
            stderr_limit_bytes: 16,
            total_output_limit_bytes: 16,
            requested_profile: DirectEffectExecutionProfileV1::Standard,
        },
        now + 5_000,
        DirectEffectExecutionProfileV1::Standard,
        DirectEffectRiskClassV1::Standard,
        None,
        digest('8'),
        digest('9'),
    )
    .unwrap()
}

fn terminal_record(ledger_root: &TempDir) -> trillionnium_shell_exec::DurableEffectRecordV1 {
    let now = boottime_ms();
    let request = request(now);
    let mut ledger = DurableShellExecLedgerV1::open(ledger_root.path()).unwrap();
    ledger.prepare_or_recover(&request).unwrap();
    ledger
        .finish_not_dispatched_policy(&request, "test_policy_rejection", now)
        .unwrap();
    ledger.record(&request.effect_id).unwrap().unwrap()
}

fn indeterminate_record(ledger_root: &TempDir) -> trillionnium_shell_exec::DurableEffectRecordV1 {
    let now = boottime_ms();
    let request = request(now);
    let mut ledger = DurableShellExecLedgerV1::open(ledger_root.path()).unwrap();
    ledger.prepare_or_recover(&request).unwrap();
    ledger.mark_dispatched(&request, now, &digest('a')).unwrap();
    ledger
        .hold_restart_indeterminate(&request, now + 1)
        .unwrap();
    ledger.record(&request.effect_id).unwrap().unwrap()
}

fn receipt_name(root: &TempDir) -> String {
    fs::read_dir(root.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .find(|name| name.starts_with("receipt-") && name.ends_with(".v1.json"))
        .unwrap()
}

#[test]
fn terminal_receipt_is_canonical_idempotent_and_repairs_missing_or_stale_temp() {
    let ledger_root = private_tempdir();
    let receipt_root = private_tempdir();
    let record = terminal_record(&ledger_root);
    let store = DurableShellExecReceiptStoreV1::open(receipt_root.path()).unwrap();
    let first = store.ensure(&record).unwrap();
    let decoded: ShellExecEffectReceiptV1 = serde_json::from_slice(&first).unwrap();
    assert_eq!(decoded.body.request, record.request);
    assert_eq!(decoded.body.durable_state, record.state);
    assert_eq!(
        decoded.body.terminal_response_sha256.as_deref(),
        record
            .terminal_response
            .as_deref()
            .map(trillionnium_os_types::sha256_bytes)
            .as_deref()
    );
    assert_eq!(store.ensure(&record).unwrap(), first);

    let final_name = receipt_name(&receipt_root);
    fs::remove_file(receipt_root.path().join(&final_name)).unwrap();
    let temporary_name = format!(".{final_name}.tmp");
    fs::write(receipt_root.path().join(&temporary_name), b"crash-prefix").unwrap();
    fs::set_permissions(
        receipt_root.path().join(&temporary_name),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert_eq!(store.ensure(&record).unwrap(), first);
    assert!(!receipt_root.path().join(temporary_name).exists());
    store.verify_catalog(&[record]).unwrap();
}

#[test]
fn indeterminate_receipt_has_no_terminal_bytes_and_is_catalog_complete() {
    let ledger_root = private_tempdir();
    let receipt_root = private_tempdir();
    let record = indeterminate_record(&ledger_root);
    let store = DurableShellExecReceiptStoreV1::open(receipt_root.path()).unwrap();
    let bytes = store.ensure(&record).unwrap();
    let decoded: ShellExecEffectReceiptV1 = serde_json::from_slice(&bytes).unwrap();
    assert!(decoded.body.terminal_response_sha256.is_none());
    assert!(decoded.body.terminal_response_bytes.is_none());
    assert!(decoded.body.durable_state.dispatch_occurred);
    store.verify_catalog(&[record]).unwrap();
}

#[test]
fn tamper_noncanonical_oversize_mode_hardlink_and_symlink_fail_closed() {
    let ledger_root = private_tempdir();
    let record = terminal_record(&ledger_root);

    for mutation in ["noncanonical", "oversize", "mode", "hardlink", "symlink"] {
        let receipt_root = private_tempdir();
        let store = DurableShellExecReceiptStoreV1::open(receipt_root.path()).unwrap();
        store.ensure(&record).unwrap();
        let name = receipt_name(&receipt_root);
        let path = receipt_root.path().join(&name);
        match mutation {
            "noncanonical" => fs::write(&path, b"{ }\n").unwrap(),
            "oversize" => fs::write(&path, vec![b'x'; 512 * 1024 + 1]).unwrap(),
            "mode" => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            }
            "hardlink" => {
                fs::hard_link(&path, receipt_root.path().join("second-link")).unwrap();
            }
            "symlink" => {
                fs::remove_file(&path).unwrap();
                let target = receipt_root.path().join("target");
                fs::write(&target, b"{}").unwrap();
                symlink(&target, &path).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(store.ensure(&record).is_err(), "mutation {mutation}");
    }
}

#[test]
fn stale_receipt_temporary_requires_exact_private_regular_custody() {
    let ledger_root = private_tempdir();
    let record = terminal_record(&ledger_root);
    for mutation in ["mode", "hardlink", "symlink", "directory"] {
        let receipt_root = private_tempdir();
        let store = DurableShellExecReceiptStoreV1::open(receipt_root.path()).unwrap();
        store.ensure(&record).unwrap();
        let final_name = receipt_name(&receipt_root);
        fs::remove_file(receipt_root.path().join(&final_name)).unwrap();
        let temporary = receipt_root.path().join(format!(".{final_name}.tmp"));
        match mutation {
            "mode" => {
                fs::write(&temporary, b"prefix").unwrap();
                fs::set_permissions(&temporary, fs::Permissions::from_mode(0o640)).unwrap();
            }
            "hardlink" => {
                let source = receipt_root.path().join("source");
                fs::write(&source, b"prefix").unwrap();
                fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
                fs::hard_link(source, &temporary).unwrap();
            }
            "symlink" => {
                let source = receipt_root.path().join("source");
                fs::write(&source, b"prefix").unwrap();
                symlink(source, &temporary).unwrap();
            }
            "directory" => fs::create_dir(&temporary).unwrap(),
            _ => unreachable!(),
        }
        assert!(store.ensure(&record).is_err(), "mutation {mutation}");
    }
}

#[test]
fn unknown_catalog_entries_writer_lock_and_root_swap_fail_closed() {
    let ledger_root = private_tempdir();
    let receipt_root = private_tempdir();
    let record = terminal_record(&ledger_root);
    let store = DurableShellExecReceiptStoreV1::open(receipt_root.path()).unwrap();
    assert!(DurableShellExecReceiptStoreV1::open(receipt_root.path()).is_err());
    assert!(store.verify_catalog(std::slice::from_ref(&record)).is_err());
    store.ensure(&record).unwrap();
    fs::write(receipt_root.path().join("unknown-receipt"), b"x").unwrap();
    assert!(store.verify_catalog(std::slice::from_ref(&record)).is_err());
    fs::remove_file(receipt_root.path().join("unknown-receipt")).unwrap();

    let retained = receipt_root.path().with_extension("retained");
    fs::rename(receipt_root.path(), &retained).unwrap();
    fs::create_dir(receipt_root.path()).unwrap();
    fs::set_permissions(receipt_root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(store.ensure(&record).is_err());
    assert_eq!(fs::read_dir(receipt_root.path()).unwrap().count(), 0);
}
