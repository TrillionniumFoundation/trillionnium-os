use super::*;
use crate::{Recorder, Stage};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Barrier};
fn parent() -> tempfile::TempDir {
    let p = tempfile::tempdir().unwrap();
    std::fs::set_permissions(p.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    p
}
fn recorder(p: &Path) -> Arc<Recorder> {
    Recorder::new_stream("actual-v2", "core", &p.join("raw")).unwrap()
}
fn stream(r: &Recorder) -> &Stream {
    r.stream.as_ref().unwrap()
}
fn rows(p: &Path) -> Vec<serde_json::Value> {
    let mut chunks: Vec<_> = std::fs::read_dir(p)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().ends_with(".chunk.json"))
        .map(|p| serde_json::from_slice::<serde_json::Value>(&std::fs::read(p).unwrap()).unwrap())
        .collect();
    chunks.sort_by_key(|v| v["epoch"].as_u64().unwrap());
    chunks
        .into_iter()
        .flat_map(|v| v["records"].as_array().unwrap().clone())
        .collect()
}
#[test]
fn one_lifetime_13000_keeps_all_start_ids_and_closed_publication_ranges() {
    let p = parent();
    let r = recorder(p.path());
    for i in 0..13000 {
        r.start(Stage::ToolExit, "ordinary actual monotonic span", false)
            .finish();
        if (i + 1) % 200 == 0 {
            stream(&r).drain(false).unwrap();
        }
    }
    stream(&r).drain(true).unwrap();
    let values = rows(p.path());
    assert_eq!(values.len(), 13000);
    let mut ids: Vec<_> = values
        .iter()
        .map(|v| v["start_claim_id"].as_u64().unwrap())
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, (0..13000).collect::<Vec<_>>());
    assert!(values
        .windows(2)
        .all(|v| v[0]["completion_sequence"].as_u64() < v[1]["completion_sequence"].as_u64()));
    assert_eq!(stream(&r).lost(), 0);
    assert_eq!(stream(&r).open(), 0);
    assert_eq!(resident(stream(&r).claims.load(Ordering::Acquire)), 0);
    assert!(r.snapshot().is_err());
}
#[test]
fn long_span_retains_start_credit_but_does_not_pin_completed_banks() {
    let p = parent();
    let r = recorder(p.path());
    let long = r.start(Stage::ProviderWait, "genuine long scope", true);
    for i in 0..2000 {
        r.start(Stage::HostDecode, "ordinary", false).finish();
        if (i + 1) % 256 == 0 {
            stream(&r).drain(false).unwrap();
        }
    }
    assert_eq!(stream(&r).open(), 1);
    assert_eq!(stream(&r).lost(), 0);
    assert!(!rows(p.path()).is_empty());
    long.finish();
    stream(&r).drain(true).unwrap();
    let values = rows(p.path());
    assert_eq!(values.len(), 2001);
    assert_eq!(values.last().unwrap()["start_claim_id"], 0);
    assert!(
        values.last().unwrap()["completion_sequence"]
            .as_u64()
            .unwrap()
            > 0
    );
}
#[test]
fn pending_and_closed_share_exact1024_credit_limit_without_overwrite() {
    let p = parent();
    let r = recorder(p.path());
    let spans: Vec<_> = (0..1024)
        .map(|_| r.start(Stage::ProviderWait, "pending", true))
        .collect();
    assert_eq!(stream(&r).open(), 1024);
    assert!(r.start(Stage::HostDecode, "overflow", false).0.is_none());
    assert!(stream(&r).lost() > 0);
    for span in spans {
        span.finish();
    }
    assert!(stream(&r).drain(true).is_err());
    assert_eq!(resident(stream(&r).claims.load(Ordering::Acquire)), 1024);
    assert!(std::fs::read_dir(p.path()).unwrap().all(|e| !e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .ends_with(".ack.json")));
}
#[test]
fn actual_ack_exclusive_collision_retains_credits_and_first_phase() {
    let p = parent();
    let r = recorder(p.path());
    for _ in 0..256 {
        r.start(Stage::ToolExit, "ordinary", false).finish();
    }
    let name = { format!("{}.e0.ack.json", stream(&r).output.lock().unwrap().base) };
    std::fs::write(p.path().join(name), b"retained exact collision").unwrap();
    let error = stream(&r).drain(false).unwrap_err();
    assert!(error.starts_with("ack.open_exclusive:"));
    assert_eq!(resident(stream(&r).claims.load(Ordering::Acquire)), 256);
    assert_ne!(stream(&r).banks[0].state.load(Ordering::Acquire), FREE);
    assert!(stream(&r).drain(false).unwrap_err().contains(&error));
}
#[test]
fn actual_parent_replacement_preserves_unacked_records_and_never_resumes() {
    let outer = parent();
    let p = outer.path().join("owned");
    std::fs::create_dir(&p).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    let r = recorder(&p);
    for _ in 0..256 {
        r.start(Stage::HostDecode, "ordinary", false).finish();
    }
    std::fs::rename(&p, outer.path().join("retained")).unwrap();
    std::fs::create_dir(&p).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    let first = stream(&r).drain(false).unwrap_err();
    assert!(first.starts_with("chunk.parent_before:"));
    assert!(std::fs::read_dir(&p).unwrap().next().is_none());
    assert_eq!(resident(stream(&r).claims.load(Ordering::Acquire)), 256);
    assert!(stream(&r).drain(false).unwrap_err().contains(&first));
}
#[test]
fn final_close_with_actual_pending_span_and_later_start_cannot_fake_completion() {
    let p = parent();
    let r = recorder(p.path());
    let ready = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    let child = {
        let r = Arc::clone(&r);
        let ready = Arc::clone(&ready);
        let resume = Arc::clone(&resume);
        std::thread::spawn(move || {
            let span = r.start(Stage::ProviderWait, "pending", true);
            ready.wait();
            resume.wait();
            span.finish();
        })
    };
    ready.wait();
    assert!(stream(&r).drain(true).is_err());
    assert!(r
        .start(Stage::HostDecode, "after source close", false)
        .0
        .is_none());
    resume.wait();
    child.join().unwrap();
    assert!(stream(&r).lost() > 0);
    assert!(stream(&r).drain(true).is_err());
    assert!(!std::fs::read_dir(p.path()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .ends_with(".terminator.json")));
}
#[test]
fn exact_physical_generation_role_names_and_context_exclusive_identity() {
    let p = parent();
    let a = Stream::new("physical", "transport", &p.path().join("same")).unwrap();
    let b = Stream::new("physical", "core", &p.path().join("same")).unwrap();
    assert_ne!(a.output.lock().unwrap().base, b.output.lock().unwrap().base);
    assert_eq!(a.generation.pid, b.generation.pid);
    assert!(a.generation.start_time_ticks > 0);
    assert!(Stream::new("physical", "core", &p.path().join("same")).is_err());
}
#[test]
fn empty_scope_preserves_zero_start_and_complete_zero_set() {
    let p = parent();
    let r = recorder(p.path());
    stream(&r).drain(true).unwrap();
    assert!(rows(p.path()).is_empty());
    assert_eq!(stream(&r).claims.load(Ordering::Acquire), SOURCE_CLOSED);
}

#[test]
fn retained_bank_selection_after_actual_seal_chooses_new_available_bank() {
    let p = parent();
    let r = recorder(p.path());
    let s = stream(&r);
    let id = s.claim().unwrap();
    let start = crate::monotonic_ns().unwrap();
    let retained = s.active.load(Ordering::Acquire);
    for _ in 0..256 {
        r.start(Stage::HostDecode, "ordinary", false).finish();
    }
    s.drain(false).unwrap();
    assert_ne!(s.active.load(Ordering::Acquire), retained);
    assert_eq!(s.banks[retained].state.load(Ordering::Acquire), FREE);
    // This is the exact state a preempted publisher sees after retaining the
    // prior pointer, with the new bank actually opened by a physical ACK/drain.
    let record = Record {
        sequence: id,
        stage: Stage::ProviderWait,
        scope_sha256: format!("{:x}", Sha256::digest(b"retained start")),
        pid: std::process::id(),
        tid: unsafe { libc::syscall(libc::SYS_gettid) },
        start_ns: start,
        end_ns: crate::monotonic_ns().unwrap(),
        end: "observed_boundary",
    };
    assert!(s.publish_completed_from(record, retained));
    s.claims.fetch_sub(1 << PENDING_SHIFT, Ordering::AcqRel);
    s.drain(true).unwrap();
    assert_eq!(s.lost(), 0);
    assert_eq!(rows(p.path()).last().unwrap()["start_claim_id"], 0);
}
#[test]
fn final_busy_exporter_preserves_first_atomic_phase_and_never_acknowledges_later() {
    let p = parent();
    let r = recorder(p.path());
    let s = stream(&r);
    let guard = s.output.lock().unwrap();
    assert_eq!(s.drain(true).unwrap_err(), "exporter.acquire: final busy");
    drop(guard);
    assert!(s
        .drain(false)
        .unwrap_err()
        .contains("exporter.acquire: final busy"));
    assert_eq!(s.first_failure.load(Ordering::Acquire), 1);
    assert!(s.lost() > 0);
    assert!(!std::fs::read_dir(p.path()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .ends_with(".ack.json")));
}
