//! Non-production readiness, provider conformance, and end-to-end smoke tool.
//!
//! These entrypoints are deliberately separate from `trillionniumd`, whose
//! default and production mode serve only the OS Agent API control plane.

use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::json;
use trillionnium_agent_api_uds::{
    AgentApiRequest, DEFAULT_AGENT_API_CALL_TIMEOUT, DEFAULT_AGENT_API_SOCKET,
};
use trillionnium_audit_sqlite::AuditStore;
use trillionnium_dbus::AgentService;
use trillionnium_os_types::{
    AGENT_API_VERSION, TaskId, TaskInput, ToolCallId, ToolCallInput, now_unix_ms, sha256_bytes,
};
#[cfg(test)]
use trillionnium_tool_runtime::supervised_codex::CodexExecutionMode;
use trillionnium_tool_runtime::{
    LocalShimAdapter, execute_with_adapter, generated_system_status_manifest, validate_manifest,
    validate_tool_call,
};

#[path = "../providers/codex.rs"]
// The smoke binary only exercises the adapter readiness/plan entrypoints; the
// shared provider module also contains daemon-only lifecycle helpers.
#[allow(dead_code)]
mod codex_adapter;
#[path = "../providers/contract.rs"]
mod provider_contract;

use provider_contract::AgentAdapter;

fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [flag] if flag == "--codex-readiness" => provider_readiness("codex"),
        [flag] if flag == "--codex-plan-smoke" => provider_plan_smoke("codex"),
        [flag] if flag == "--codex-agent-api-smoke" => provider_agent_api_smoke("codex"),
        [flag] if flag == "--android-gateway-e2e-smoke" => android_gateway_e2e_smoke(),
        [flag] if flag == "--agent-api-v2-health-smoke" => {
            agent_api_v2_health_smoke(DEFAULT_AGENT_API_SOCKET)
        }
        [flag, socket] if flag == "--agent-api-v2-health-smoke" => {
            agent_api_v2_health_smoke(socket)
        }
        [flag, command] if flag == "--once" && command == "smoke" => local_runtime_smoke(),
        [flag] if flag == "--print-manifest" => print_manifest(),
        _ => bail!(
            "usage: trillionnium-smoke [--codex-readiness | \
             --codex-plan-smoke | --codex-agent-api-smoke | \
             --android-gateway-e2e-smoke | \
             --agent-api-v2-health-smoke [socket] | --once smoke | \
             --print-manifest]"
        ),
    }
}

fn agent_api_v2_health_smoke(socket: impl AsRef<Path>) -> Result<()> {
    let request = AgentApiRequest::new(
        format!("health-smoke-{}", now_unix_ms()),
        "health",
        "",
        json!({}),
    )?;
    let response =
        trillionnium_agent_api_uds::call(socket, &request, DEFAULT_AGENT_API_CALL_TIMEOUT)?;
    if !response.ok {
        bail!(
            "Agent API v2 health failed closed: {}",
            response.error.as_deref().unwrap_or("missing error")
        );
    }
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn provider_readiness(provider: &str) -> Result<()> {
    let secret = random_secret()?;
    let adapter = adapter_from_env(provider, secret)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "registration": adapter.register(),
            "health": adapter.health(),
        }))?
    );
    Ok(())
}

fn provider_plan_smoke(provider: &str) -> Result<()> {
    bail!(
        "{provider} direct plan smoke is production-disabled: use the device lifecycle harness so typed runtime evidence is durably acknowledged"
    )
}

fn provider_agent_api_smoke(provider: &str) -> Result<()> {
    bail!(
        "{provider} direct Agent API smoke is production-disabled: Phase 6 must enter through the durable provider runtime-evidence acknowledgement path"
    )
}

fn android_gateway_e2e_smoke() -> Result<()> {
    let now = now_unix_ms();
    let audit_path = default_audit_path()?;
    let service = AgentService::from_store(AuditStore::open(&audit_path)?)
        .context("failed to restore Agent API control plane")?;
    let task = service
        .create_task_local(TaskInput {
            title: "Rust control plane to Android Authority gateway".to_string(),
            description: Some("Explicit harness approval through production executor path".into()),
            metadata: json!({
                "api_version": AGENT_API_VERSION,
                "harness": true,
                "adb_is_transport_only": true,
            }),
        })
        .map_err(anyhow::Error::msg)?;
    let arguments = json!({
        "request_id": format!("planned-rust-gateway-{now}"),
        "source_id": "probe:rust-control-plane",
        "context_sha256": sha256_bytes(b"rust-control-plane-context"),
        "plan_sha256": sha256_bytes(b"rust-control-plane-plan"),
        "provider_output_sha256": sha256_bytes(b"bounded-agent-plan"),
        "approval_nonce": format!("explicit-harness-approval-{now}"),
        "network_scope": "exact_https_url",
        "payload": {"url": "https://example.com/"},
    });
    let dispatch = service
        .run_tool_local(&task.id.0, "android.browser.open_bounded", &arguments)
        .map_err(anyhow::Error::msg)?;
    let approval_id = dispatch
        .pointer("/approval/id")
        .and_then(serde_json::Value::as_str)
        .context("Android gateway smoke did not stop at OS approval")?;
    let approved = service
        .approve_local(approval_id)
        .map_err(anyhow::Error::msg)?;
    if approved
        .pointer("/tool_run/status")
        .and_then(serde_json::Value::as_str)
        != Some("succeeded")
    {
        bail!("Android gateway execution did not succeed");
    }
    let receipt = json!({
        "schema": "org.trillionnium.android-gateway-e2e-smoke.v1",
        "decision": "PASS_RUST_AGENT_API_TO_ANDROID_AUTHORITY_WITH_OS_APPROVAL",
        "task": task,
        "dispatch_before_approval": dispatch,
        "approval_and_execution": approved,
        "android_gateway_bypassed": false,
        "adb_is_transport_only": true,
        "audit_path": audit_path,
    });
    if let Some(path) = env::var_os("TRILLIONNIUM_ANDROID_GATEWAY_RECEIPT_PATH").map(PathBuf::from)
    {
        write_json_receipt(&path, &receipt)?;
    }
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

fn local_runtime_smoke() -> Result<()> {
    let manifest = generated_system_status_manifest();
    let call = ToolCallInput {
        task_id: TaskId::new(),
        tool_call_id: ToolCallId::new(),
        tool_name: manifest.name.clone(),
        arguments: json!({}),
        agent_execution_binding: None,
    };
    let manifest_validation = validate_manifest(&manifest)?;
    let call_validation = validate_tool_call(&manifest, &call)?;
    let output = execute_with_adapter(&LocalShimAdapter, &manifest, &call)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": manifest_validation.valid && call_validation.valid,
            "manifest": manifest.name,
            "output": output,
            "production_daemon_invoked": false,
        }))?
    );
    Ok(())
}

fn print_manifest() -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&generated_system_status_manifest())?
    );
    Ok(())
}

fn adapter_from_env(provider: &str, secret: [u8; 32]) -> Result<Box<dyn AgentAdapter>> {
    match provider {
        "codex" => Ok(Box::new(codex_adapter::CodexAdapter::from_env(secret)?)),
        _ => bail!("unknown provider adapter: {provider}"),
    }
}

fn random_secret() -> Result<[u8; 32]> {
    let mut secret = [0u8; 32];
    File::open("/dev/urandom")
        .context("failed to open OS random source")?
        .read_exact(&mut secret)
        .context("failed to read OS random source")?;
    Ok(secret)
}

fn write_json_receipt(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let parent = path.parent().context("receipt path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = File::create(&temporary)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn default_audit_path() -> Result<PathBuf> {
    let base = env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("."));
    let directory = base.join("trillionnium-os");
    fs::create_dir_all(&directory)?;
    Ok(directory.join("audit.sqlite"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_execution_mode_type_has_no_legacy_plan_variant() {
        assert!(serde_json::from_str::<CodexExecutionMode>("\"plan_only\"").is_err());
        assert_eq!(
            serde_json::from_str::<CodexExecutionMode>("\"agent_direct_v1\"").unwrap(),
            CodexExecutionMode::AgentDirectV1
        );
        assert_eq!(codex_adapter::CODEX_AGENT_ID, "agent-codex-direct-v1");
    }
}
