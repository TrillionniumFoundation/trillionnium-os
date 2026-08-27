use std::fs;
use std::io::{BufReader, Cursor};
use std::os::unix::fs::PermissionsExt as _;
use std::thread;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde_json::{Value, json};
use tempfile::TempDir;
use trillionnium_os_types::agent_descriptor_registry;
use trillionnium_os_types::direct_effect::{
    DirectEffectExecutionProfileV1, DirectEffectIndeterminateReasonV1,
    DirectEffectModelArgumentsV1, DirectEffectRequestV1, DirectEffectRiskClassV1,
    DirectEffectToolV1, INVOCATION_ID_PREFIX, OS_TOOL_CALL_ID_PREFIX, PROVIDER_ATTEMPT_ID_PREFIX,
};
use trillionnium_shell_exec::mcp_adapter::{
    HostConformanceSeqpacketListenerV1, MAX_TRANSPORT_REQUEST_BYTES, MCP_RESULT_SCHEMA,
    ProductTransportBackendV1, ShellExecMcpBackendV1, ShellExecMcpDispositionV1,
    ShellExecMcpResultV1, ShellExecPeerIdentityV1, ShellExecPeerRoleV1,
    ShellExecTransportRequestV1, ShellExecTransportResponseV1, host_conformance_seqpacket_pair,
};
use trillionnium_shell_exec::{
    CancellationTokenV1, DurableShellExecLedgerV1, HostConformanceWorkerV1, RootLinuxPathPolicyV1,
    SHELL_EXEC_FIRST_SLICE_MAX_TIMEOUT_MS, SHELL_EXEC_MAX_RAW_OUTPUT_BYTES, ShellExecBrokerCoreV1,
    TRANSPORT_PROTOCOL,
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

#[test]
fn public_peer_role_is_closed_before_any_payload_decode() {
    let agentd = ShellExecPeerIdentityV1 {
        pid: 1,
        uid: trillionnium_shell_exec::AGENTD_UID,
        gid: trillionnium_shell_exec::AGENTD_GID,
        selinux_domain: trillionnium_shell_exec::AGENTD_SELINUX_DOMAIN.to_string(),
    };
    assert_eq!(
        agentd.classify().unwrap(),
        ShellExecPeerRoleV1::AgentHostRegistration
    );
    let shell = ShellExecPeerIdentityV1 {
        pid: 2,
        uid: trillionnium_shell_exec::SHELL_ADAPTER_UID,
        gid: trillionnium_shell_exec::SHELL_ADAPTER_GID,
        selinux_domain: trillionnium_shell_exec::SHELL_ADAPTER_SELINUX_DOMAIN.to_string(),
    };
    assert_eq!(
        shell.classify().unwrap(),
        ShellExecPeerRoleV1::ShellAdapterExecute
    );

    let cross_role_uid = ShellExecPeerIdentityV1 {
        uid: trillionnium_shell_exec::AGENTD_UID,
        selinux_domain: trillionnium_shell_exec::SHELL_ADAPTER_SELINUX_DOMAIN.to_string(),
        ..shell.clone()
    };
    assert!(cross_role_uid.classify().is_err());

    let wrong_agentd_gid = ShellExecPeerIdentityV1 {
        gid: trillionnium_shell_exec::AGENTD_GID + 1,
        ..agentd.clone()
    };
    assert!(wrong_agentd_gid.classify().is_err());
    assert!(wrong_agentd_gid.require_agentd().is_err());
    let wrong_shell_gid = ShellExecPeerIdentityV1 {
        gid: trillionnium_shell_exec::SHELL_ADAPTER_GID + 1,
        ..shell
    };
    assert!(wrong_shell_gid.classify().is_err());
    assert!(wrong_shell_gid.require_shell_adapter().is_err());
}

#[test]
fn stdio_mcp_to_fixed_transport_to_durable_worker_is_binary_safe() {
    let root = private_tempdir();
    let workspace = root.path().join("workspace");
    let temporary = root.path().join("temporary");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir(&temporary).unwrap();
    let socket = root.path().join("shell-exec.sock");
    let listener = HostConformanceSeqpacketListenerV1::bind(&socket).unwrap();
    let ledger_root = root.path().to_path_buf();
    let fixture = env!("CARGO_BIN_EXE_shell-exec-host-fixture").to_string();
    let server_fixture = fixture.clone();

    let server = thread::spawn(move || {
        let connection = listener.accept().unwrap();
        let transport = connection.receive_request().unwrap();
        assert_eq!(
            transport.arguments.argv,
            vec![server_fixture, "emit-binary".to_string()]
        );
        let now = boottime_ms();
        let request = DirectEffectRequestV1::derive_os_owned(
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
            transport.arguments.clone(),
            now + transport.arguments.timeout_ms,
            DirectEffectExecutionProfileV1::Standard,
            DirectEffectRiskClassV1::Standard,
            None,
            digest('8'),
            digest('9'),
        )
        .unwrap();
        let worker = HostConformanceWorkerV1::new(
            RootLinuxPathPolicyV1::for_host_conformance(&workspace, &temporary).unwrap(),
        );
        let mut broker = ShellExecBrokerCoreV1::new(
            DurableShellExecLedgerV1::open(&ledger_root).unwrap(),
            worker,
        );
        let exact_terminal = broker
            .execute_authenticated(&request, now, &digest('d'), &CancellationTokenV1::default())
            .unwrap();
        let (ledger, _) = broker.into_parts();
        let state = ledger.state(&request.effect_id).unwrap().clone();
        let response =
            ShellExecTransportResponseV1::terminal(request, state, &exact_terminal).unwrap();
        connection.send_response(&response).unwrap();
    });

    let arguments = json!({
        "argv": [fixture, "emit-binary"],
        "cwd": null,
        "timeout_ms": 5000,
        "stdout_limit_bytes": 1024,
        "stderr_limit_bytes": 1024,
        "total_output_limit_bytes": 2048,
        "requested_profile": "standard"
    });
    let frames = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": trillionnium_agent_direct_tools::mcp::PROTOCOL_VERSION}
        }),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "trillionnium_shell_exec", "arguments": arguments}
        }),
    ];
    let input = frames
        .iter()
        .map(|frame| serde_json::to_string(frame).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let mut output = Vec::new();
    trillionnium_shell_exec::mcp_adapter::serve(
        BufReader::new(Cursor::new(input.into_bytes())),
        &mut output,
        ProductTransportBackendV1::for_host_conformance_path(&socket),
    )
    .unwrap();
    server.join().unwrap();

    let responses = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 3);
    assert_eq!(
        responses[1]["result"]["tools"][0]["name"],
        "trillionnium_shell_exec"
    );
    let result = &responses[2]["result"];
    assert_eq!(result["isError"], false);
    let structured = &result["structuredContent"];
    assert_eq!(structured["schema"], MCP_RESULT_SCHEMA);
    assert_eq!(structured["protocol"], TRANSPORT_PROTOCOL);
    assert_eq!(structured["ok"], true);
    assert_eq!(structured["disposition"], "terminal");
    assert_eq!(
        BASE64_STANDARD
            .decode(
                structured["terminal_response"]["stdout"]["data"]
                    .as_str()
                    .unwrap()
            )
            .unwrap(),
        [0xff, 0x00, 0xfe]
    );
    assert_eq!(
        BASE64_STANDARD
            .decode(
                structured["terminal_response"]["stderr"]["data"]
                    .as_str()
                    .unwrap()
            )
            .unwrap(),
        [0x80, 0x00]
    );
}

#[test]
fn mcp_schema_and_runtime_reject_os_envelope_and_inline_shell_fields() {
    let schema = trillionnium_shell_exec::mcp_adapter::mcp_tool().input_schema;
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["requested_profile"]["const"],
        "standard"
    );
    assert_eq!(
        schema["properties"]["timeout_ms"]["maximum"],
        SHELL_EXEC_FIRST_SLICE_MAX_TIMEOUT_MS
    );
    assert_eq!(
        schema["properties"]["cwd"]["oneOf"][1]["properties"]["scope"]["const"],
        "workspace"
    );
    let temporary_cwd = json!({
        "argv": ["/usr/bin/printf"],
        "cwd": {"scope": "temporary", "relative": "subdir"},
        "timeout_ms": 5000,
        "stdout_limit_bytes": 16,
        "stderr_limit_bytes": 16,
        "total_output_limit_bytes": 16,
        "requested_profile": "standard"
    });
    assert!(serde_json::from_value::<DirectEffectModelArgumentsV1>(temporary_cwd).is_err());
    for name in [
        "stdout_limit_bytes",
        "stderr_limit_bytes",
        "total_output_limit_bytes",
    ] {
        assert_eq!(
            schema["properties"][name]["maximum"],
            SHELL_EXEC_MAX_RAW_OUTPUT_BYTES
        );
    }
    for forbidden in [
        "effect_id",
        "request_sha256",
        "absolute_deadline_boottime_ms",
        "serial",
        "host",
        "port",
        "command",
    ] {
        assert!(schema["properties"].get(forbidden).is_none());
    }
}

#[test]
fn fixed_product_backend_never_requires_or_exposes_an_invocation_token() {
    let mut backend = ProductTransportBackendV1::fixed();
    let error = backend.execute(&semantic_arguments()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("fixed shell broker connection failed")
    );
    assert!(!error.to_string().contains("token"));
}

#[test]
fn indeterminate_mcp_result_requires_a_complete_os_effect_identity() {
    let mut result = ShellExecMcpResultV1 {
        schema: MCP_RESULT_SCHEMA.to_string(),
        protocol: TRANSPORT_PROTOCOL.to_string(),
        ok: false,
        disposition: ShellExecMcpDispositionV1::Indeterminate,
        effect_id: format!("effect:{}", digest('a')),
        request_sha256: digest('b'),
        semantic_arguments_sha256: digest('c'),
        stdout_limit_bytes: 16,
        stderr_limit_bytes: 16,
        total_output_limit_bytes: 16,
        terminal_response: None,
        indeterminate_reason: Some(DirectEffectIndeterminateReasonV1::BackendLostAfterDispatch),
        error: Some("effect_outcome_indeterminate".to_string()),
    };
    result.validate().unwrap();

    for malformed in [
        "effect:".to_string(),
        "effect:not-a-digest".to_string(),
        format!("effect:{}", "A".repeat(64)),
    ] {
        result.effect_id = malformed;
        assert!(result.validate().is_err());
    }
    result.effect_id = format!("effect:{}", digest('a'));
    result.stdout_limit_bytes = 17;
    assert!(result.validate().is_err());
}

fn semantic_arguments() -> DirectEffectModelArgumentsV1 {
    serde_json::from_value(json!({
        "argv": ["/usr/bin/printf", "%s", "packet"],
        "cwd": null,
        "timeout_ms": 5000,
        "stdout_limit_bytes": 1024,
        "stderr_limit_bytes": 1024,
        "total_output_limit_bytes": 2048,
        "requested_profile": "standard"
    }))
    .unwrap()
}

#[test]
fn seqpacket_rejects_oversized_record_without_stream_truncation() {
    let (sender, receiver) =
        host_conformance_seqpacket_pair(std::time::Duration::from_secs(1)).unwrap();
    sender
        .send_raw_packet_for_host_conformance(&vec![b'x'; MAX_TRANSPORT_REQUEST_BYTES + 1])
        .unwrap();
    assert!(receiver.receive_request().is_err());
}

#[test]
fn seqpacket_rejects_a_second_request_record() {
    let (sender, receiver) =
        host_conformance_seqpacket_pair(std::time::Duration::from_secs(1)).unwrap();
    let request = ShellExecTransportRequestV1::derive_for_invocation(
        semantic_arguments(),
        format!("shell-inv:{}", "a".repeat(64)),
        1,
    )
    .unwrap();
    sender.send_request(&request).unwrap();
    sender.send_request(&request).unwrap();
    assert!(receiver.receive_request().is_err());
}
