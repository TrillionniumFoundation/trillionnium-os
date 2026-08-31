#[cfg(test)]
mod flow_tests {
    use super::*;

    fn options(buffer_bytes: usize) -> Options {
        Options {
            core: PathBuf::from("/unused"),
            core_args: Vec::new(),
            event_store: Some(PathBuf::from("/tmp/events.jsonl")),
            buffer_bytes,
            max_credit_bytes: 4096,
            max_chunk_bytes: 2048,
            control_history: 8,
            help: false,
        }
    }

    fn control(seq: u64, command: StreamControl, fingerprint: &str) -> ParsedFlowControl {
        ParsedFlowControl {
            control_seq: seq,
            command,
            resumed_through_cursor: None,
            request_fingerprint: fingerprint.to_string(),
        }
    }

    fn data(cursor: u64, bytes: usize) -> RunTurnFrame {
        RunTurnFrame {
            kind: FRAME_MODEL_DELTA.to_string(),
            seq: cursor,
            payload: json!({"text": "x".repeat(bytes)}),
            direction: Some("host_to_client".to_string()),
            client_seq: None,
            host_seq: Some(cursor),
            frame_sha256: None,
            event_id: Some(format!("stream-event-{cursor}")),
            connection_id: Some("core".to_string()),
            stream_id: Some("stream".to_string()),
            turn_stream_id: Some("stream".to_string()),
            session_id: Some("session".to_string()),
            profile_id: Some("owner-open".to_string()),
            task_id: Some("task".to_string()),
            turn_id: Some("turn".to_string()),
            call_id: None,
            job_id: None,
            tool: None,
            target: None,
            target_id: None,
            extensions: BTreeMap::new(),
        }
    }

    fn job_output(cursor: u64, bytes: usize) -> RunTurnFrame {
        let mut frame = data(cursor, bytes);
        frame.kind = "job.output".to_string();
        frame.job_id = Some("job-1".to_string());
        frame.stream_id = Some("job-stream-1".to_string());
        frame.payload = json!({
            "stream": "stdout",
            "encoding": "base64",
            "data": "eA==".repeat(bytes),
        });
        frame
    }

    #[test]
    fn pause_credit_and_resume_release_queued_frames_in_order() {
        let mut flow = StreamDelivery::new(&options(4096));
        flow.apply_control(&control(0, StreamControl::Pause, "pause"))
            .unwrap();
        assert!(matches!(flow.submit(data(1, 32)).unwrap(), SubmitResult::Queued));
        flow.apply_control(&control(
            1,
            StreamControl::WindowUpdate { credit_bytes: 1024 },
            "credit",
        ))
        .unwrap();
        assert!(flow.drain().unwrap().is_empty());
        flow.apply_control(&control(2, StreamControl::Resume, "resume"))
            .unwrap();
        let drained = flow.drain().unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].event_id.as_deref(), Some("stream-event-1"));
    }

    #[test]
    fn job_output_is_subject_to_pause_and_credit() {
        assert!(is_flow_controlled_kind("job.output"));
        let mut flow = StreamDelivery::new(&options(4096));
        flow.apply_control(&control(0, StreamControl::Pause, "pause"))
            .unwrap();
        assert!(matches!(
            flow.submit(job_output(2, 16)).unwrap(),
            SubmitResult::Queued
        ));
        flow.apply_control(&control(
            1,
            StreamControl::WindowUpdate { credit_bytes: 4096 },
            "credit",
        ))
        .unwrap();
        assert!(flow.drain().unwrap().is_empty());
        flow.apply_control(&control(2, StreamControl::Resume, "resume"))
            .unwrap();
        let drained = flow.drain().unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].kind, "job.output");
        assert_eq!(drained[0].job_id.as_deref(), Some("job-1"));
    }

    #[test]
    fn opaque_job_event_id_uses_explicit_durable_cursor_for_gap_recovery() {
        let mut flow = StreamDelivery::new(&options(128));
        flow.apply_control(&control(0, StreamControl::Pause, "pause"))
            .unwrap();
        let mut frame = job_output(7, 512);
        frame.event_id = Some("job-event-opaque-content-bound-id".to_string());
        frame
            .extensions
            .insert("durable_cursor".to_string(), json!(41));
        let result = flow.submit(frame).unwrap();
        let gap = match result {
            SubmitResult::GapStarted(gap) => gap,
            other => panic!("unexpected submit result: {other:?}"),
        };
        assert_eq!(gap.first_cursor, Some(41));
        assert_eq!(gap.last_cursor, Some(41));
        assert_eq!(gap.required_resume_cursor(), Some(42));
        assert_eq!(gap.first_event_id.as_deref(), Some("job-event-opaque-content-bound-id"));
    }

    #[test]
    fn malformed_explicit_durable_cursor_fails_closed() {
        let mut flow = StreamDelivery::new(&options(4096));
        flow.apply_control(&control(0, StreamControl::Pause, "pause"))
            .unwrap();
        let mut frame = job_output(1, 16);
        frame
            .extensions
            .insert("durable_cursor".to_string(), json!("not-a-cursor"));
        let error = flow.submit(frame).expect_err("malformed cursor must be rejected");
        assert!(error.to_string().contains("durable_cursor"));
    }

    #[test]
    fn hello_ack_advertises_every_classified_bounded_frame() {
        let options = options(4096);
        let flow = StreamDelivery::new(&options);
        let journal = TransportJournal::open(None);
        let mut hello = data(0, 0);
        hello.kind = FRAME_HELLO_ACK.to_string();
        hello.payload = json!({});

        augment_core_frame(&mut hello, None, &options, &flow, false, &journal);

        let advertised = hello
            .payload
            .get("flow_controlled_frame_kinds")
            .and_then(Value::as_array)
            .expect("HELLO_ACK must advertise bounded frame classes");
        let advertised = advertised
            .iter()
            .map(|value| value.as_str().expect("class names are strings"))
            .collect::<Vec<_>>();
        assert_eq!(advertised, FLOW_CONTROLLED_FRAME_KINDS);
        for kind in FLOW_CONTROLLED_FRAME_KINDS {
            assert!(is_flow_controlled_kind(kind));
        }
    }

    #[test]
    fn overflow_requires_cursor_bound_resynchronization() {
        let mut flow = StreamDelivery::new(&options(128));
        flow.apply_control(&control(0, StreamControl::Pause, "pause"))
            .unwrap();
        let result = flow.submit(data(4, 512)).unwrap();
        let gap = match result {
            SubmitResult::GapStarted(gap) => gap,
            other => panic!("unexpected submit result: {other:?}"),
        };
        assert_eq!(gap.required_resume_cursor(), Some(5));

        let mut missing_cursor = control(1, StreamControl::Resume, "resume-missing");
        assert!(flow.apply_control(&missing_cursor).is_err());
        missing_cursor.resumed_through_cursor = Some(4);
        assert!(flow.apply_control(&missing_cursor).is_err());
        missing_cursor.resumed_through_cursor = Some(5);
        missing_cursor.request_fingerprint = "resume-good".to_string();
        flow.apply_control(&missing_cursor).unwrap();
        assert!(flow.gap.is_none());
    }

    #[test]
    fn duplicate_sequence_is_bound_to_exact_payload_fingerprint() {
        let mut flow = StreamDelivery::new(&options(4096));
        let first = control(
            0,
            StreamControl::WindowUpdate { credit_bytes: 100 },
            "same",
        );
        assert_eq!(flow.apply_control(&first).unwrap().0, ApplyDisposition::Applied);
        assert_eq!(flow.apply_control(&first).unwrap().0, ApplyDisposition::Existing);
        let drift = control(
            0,
            StreamControl::WindowUpdate { credit_bytes: 100 },
            "different",
        );
        assert!(flow.apply_control(&drift).is_err());
    }
}
