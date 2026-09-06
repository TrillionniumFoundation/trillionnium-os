use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// `DurableEventStore` deliberately rejects group/world-writable parents.
/// `tempfile::tempdir` follows the process umask, so make integration
/// fixtures deterministic even when the test runner uses 0002/0022.
pub fn secure_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private temporary directory");
    directory
}

/// Read the logical v1 JSONL view of a turn store.
///
/// v7 writes to `<path>.segments`; older fixtures and compatibility entrypoints
/// may still write directly to `<path>`.  Tests should inspect the logical
/// stream rather than assume one physical layout.
#[allow(dead_code)]
pub fn read_event_store(path: &Path) -> String {
    if path.is_file() {
        return fs::read_to_string(path).expect("read event store");
    }
    let root = segmented_root(path);
    let mut segments = fs::read_dir(root)
        .map(|entries| {
            entries
                .map(|entry| entry.expect("read event-store directory").path())
                .filter(|candidate| {
                    candidate.file_name().is_some_and(|name| {
                        let name = name.to_string_lossy();
                        name.starts_with("segment-") && name.ends_with(".jsonl")
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    segments.sort();
    let mut contents = String::new();
    for segment in segments {
        contents.push_str(&fs::read_to_string(segment).expect("read event-store segment"));
    }
    contents
}

/// Return the logical bytes of a turn store for immutability assertions.
#[allow(dead_code)]
pub fn read_event_store_bytes(path: &Path) -> Vec<u8> {
    if path.is_file() {
        return fs::read(path).expect("read event store");
    }
    let root = segmented_root(path);
    let mut segments = fs::read_dir(root)
        .map(|entries| {
            entries
                .map(|entry| entry.expect("read event-store directory").path())
                .filter(|candidate| {
                    candidate.file_name().is_some_and(|name| {
                        let name = name.to_string_lossy();
                        name.starts_with("segment-") && name.ends_with(".jsonl")
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    segments.sort();
    let mut contents = Vec::new();
    for segment in segments {
        contents.extend_from_slice(&fs::read(segment).expect("read event-store segment"));
    }
    contents
}

fn segmented_root(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.segments", path.display()))
}
