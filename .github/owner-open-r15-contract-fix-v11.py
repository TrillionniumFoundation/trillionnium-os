from pathlib import Path

runtime_test = Path("crates/trillionnium-owner-open-job-runtime/tests/runtime.rs")
text = runtime_test.read_text()

accepted_start_marker = (
    "#[test]\n"
    "fn accepted_without_terminal_is_unknown_and_not_redispatched() {"
)
accepted_end_marker = (
    "\n#[test]\n"
    "fn configured_unavailable_journal_is_unknown_and_never_dispatched() {"
)
if text.count(accepted_start_marker) != 1 or text.count(accepted_end_marker) != 1:
    raise SystemExit("R15 accepted-without-terminal test markers are not exact")
accepted_start = text.index(accepted_start_marker)
accepted_end = text.index(accepted_end_marker, accepted_start)
accepted_replacement = r'''#[test]
fn accepted_without_terminal_is_unknown_and_not_redispatched() {
    let directory = tempfile::tempdir().unwrap();
    let journal_path = directory.path().join("jobs.jsonl");
    let job = key("job-uncertain");
    let request = request('e', "pipe");
    {
        let journal = JobJournal::open_best_effort(Some(&journal_path));
        journal
            .begin_operation(
                &job,
                &request,
                "start-uncertain",
                "start",
                &"f".repeat(64),
                json!({"fixture": true}),
            )
            .unwrap();
    }
    let marker = directory.path().join("must-not-run");
    let manager = reopen_after_dispatcher_shutdown(&journal_path);
    let result = manager
        .start(start_request(
            job,
            request,
            "different-delivery-operation",
            format!("touch '{}'", marker.display()),
            None,
        ))
        .unwrap();
    assert_eq!(result.disposition, StartDisposition::UnknownAfterRestart);
    assert!(!marker.exists());
}
'''
text = text[:accepted_start] + accepted_replacement + text[accepted_end:]

unavailable_start_marker = (
    "#[test]\n"
    "fn configured_unavailable_journal_is_unknown_and_never_dispatched() {"
)
unavailable_end_marker = (
    "\n#[test]\n"
    "fn capacity_rejection_happens_before_spawn_or_visible_side_effect() {"
)
if text.count(unavailable_start_marker) != 1 or text.count(unavailable_end_marker) != 1:
    raise SystemExit("R15 journal-unavailable test markers are not exact")
unavailable_start = text.index(unavailable_start_marker)
unavailable_end = text.index(unavailable_end_marker, unavailable_start)
unavailable_replacement = r'''#[test]
fn configured_unavailable_journal_is_rejected_before_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let journal_path = directory.path().join("jobs.jsonl");
    let held = JobJournal::open_best_effort(Some(&journal_path));
    assert_eq!(held.status().unwrap(), JournalStatus::Durable);
    let manager = JobManager::open(JobRuntimeConfig::default(), Some(&journal_path)).unwrap();
    assert!(matches!(
        manager.journal().status().unwrap(),
        JournalStatus::Unavailable { .. }
    ));
    let marker = directory.path().join("must-not-run-unavailable");
    let error = manager
        .start(start_request(
            key("job-unavailable"),
            request('f', "pipe"),
            "start-unavailable",
            format!("touch '{}'", marker.display()),
            None,
        ))
        .unwrap_err();
    assert!(matches!(
        error,
        trillionnium_owner_open_job_runtime::JobRuntimeError::Journal(message)
            if message == "job journal is unavailable and unjournaled effects are disabled"
    ));
    assert!(!marker.exists());
}
'''
text = text[:unavailable_start] + unavailable_replacement + text[unavailable_end:]
runtime_test.write_text(text)

durable = Path("crates/trillionnium-shell-exec/src/durable.rs")
text = durable.read_text()
old = "    Ok((value.f_bavail as u64).saturating_mul(value.f_frsize as u64))\n"
new = "    Ok(value.f_bavail.saturating_mul(value.f_frsize))\n"
if text.count(old) != 1:
    raise SystemExit("R15 statvfs conversion anchor is not exact")
durable.write_text(text.replace(old, new, 1))

post_exec_test = Path(
    "apps/trillionnium-agent-privilege-broker/src/"
    "linux_provider_post_exec_test_kernel.rs"
)
text = post_exec_test.read_text()
old = '''        assert!(
            launcher
                .find("null.as_raw_fd(),\\n                expected_parent_pid,")
                .is_some()
        );
'''
new = '''        assert!(launcher.contains("null.as_raw_fd(),\\n                expected_parent_pid,"));
'''
if text.count(old) != 1:
    raise SystemExit("R15 parent-pid source assertion anchor is not exact")
post_exec_test.write_text(text.replace(old, new, 1))

daemon = Path("apps/trillionniumd/src/main.rs")
text = daemon.read_text()
start_marker = "fn codex_provider(\n"
end_marker = "\nconst DEFAULT_AGENT_MANIFEST_DIR"
if text.count(start_marker) != 1 or text.count(end_marker) != 1:
    raise SystemExit("R15 Codex provider function markers are not exact")
start = text.index(start_marker)
end = text.index(end_marker, start)
function = text[start:end]
expected_tail = '''    codex_adapter::CodexAdapter::new_bound(
        codex_adapter::config_from_env()?,
        secret,
        capability_identity,
    )
}
'''
if function.count(expected_tail) != 1 or not function.endswith(expected_tail):
    raise SystemExit("R15 Codex provider constructor tail is not exact")
new_tail = '''    let adapter = codex_adapter::CodexAdapter::new_bound(
        codex_adapter::config_from_env()?,
        secret,
        capability_identity,
    )?;
    let adapter_registration = provider_contract::AgentAdapter::register(&adapter);
    if adapter_registration.api_version != registration.api_version
        || adapter_registration.agent_id != registration.agent_id
        || adapter_registration.adapter != registration.adapter
        || adapter_registration.adapter_version != registration.adapter_version
        || adapter_registration.network_policy != registration.network_policy
    {
        bail!("bound Codex adapter registration differs from OS-owned AgentRegistration");
    }
    Ok(adapter)
}
'''
daemon.write_text(
    text[:start]
    + function[: -len(expected_tail)]
    + new_tail
    + text[end:]
)

runtime_authority = Path(
    "apps/trillionniumd/src/direct_operation_runtime_authority_transport.rs"
)
text = runtime_authority.read_text()
old = r'''    #[test]
    fn malformed_or_uncorrelated_messages_hold_before_response() {
        let fixture = runtime_fixture();
        let (mut client, server) = spawn_session(&fixture);
        let retained_challenge: DirectOperationRuntimeAuthoritySessionChallengeV3 =
            read_canonical_frame(&mut client).unwrap();
        let mut wrong_challenge = retained_challenge.clone();
        wrong_challenge.adapter_peer_identity_sha256 = digest("wrong-peer");
        wrong_challenge.challenge_sha256 = wrong_challenge.canonical_sha256().unwrap();
        let wrong_hello = DirectOperationRuntimeAuthoritySessionHelloV3::derive(
            &wrong_challenge,
            &fixture.binding,
            &fixture.binding_sha256,
            fixture.adapter,
            &fixture.custody,
        )
        .unwrap();
        let probe = DirectOperationRuntimeAuthorityProbeV3::derive_first_use(
            &wrong_hello,
            &digest("directory"),
        )
        .unwrap();
        write_frame(&mut client, &wrong_hello);
        write_frame(&mut client, &probe);
        client.shutdown(Shutdown::Write).unwrap();
        assert!(server.join().unwrap().is_err());
    }
'''
new = r'''    #[test]
    fn malformed_or_uncorrelated_messages_hold_before_response() {
        let fixture = runtime_fixture();
        let (mut client, server) = spawn_session(&fixture);
        let retained_challenge: DirectOperationRuntimeAuthoritySessionChallengeV3 =
            read_canonical_frame(&mut client).unwrap();
        let mut wrong_challenge = retained_challenge.clone();
        wrong_challenge.adapter_peer_identity_sha256 = digest("wrong-peer");
        wrong_challenge.challenge_sha256 = wrong_challenge.canonical_sha256().unwrap();
        let wrong_hello = DirectOperationRuntimeAuthoritySessionHelloV3::derive(
            &wrong_challenge,
            &fixture.binding,
            &fixture.binding_sha256,
            fixture.adapter,
            &fixture.custody,
        )
        .unwrap();
        let probe = DirectOperationRuntimeAuthorityProbeV3::derive_first_use(
            &wrong_hello,
            &digest("directory"),
        )
        .unwrap();
        write_frame(&mut client, &wrong_hello);
        let probe_frame = encoded_frame(&probe);
        match client.write_all(&probe_frame) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::NotConnected
                ) => {}
            Err(error) => panic!("unexpected malformed-session write failure: {error}"),
        }
        match client.shutdown(Shutdown::Write) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::NotConnected
                ) => {}
            Err(error) => panic!("unexpected malformed-session shutdown failure: {error}"),
        }
        assert!(server.join().unwrap().is_err());
        let mut response = [0_u8; 1];
        match client.read(&mut response) {
            Ok(0) => {}
            Ok(count) => panic!("malformed session received {count} response bytes"),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::NotConnected
                ) => {}
            Err(error) => panic!("unexpected malformed-session read failure: {error}"),
        }
    }
'''
if text.count(old) != 1:
    raise SystemExit("R15 malformed-session close-race anchor is not exact")
runtime_authority.write_text(text.replace(old, new, 1))
