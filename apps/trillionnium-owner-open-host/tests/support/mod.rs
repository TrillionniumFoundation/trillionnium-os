use std::fs;
use std::os::unix::fs::PermissionsExt;

/// `DurableEventStore` deliberately rejects group/world-writable parents.
/// `tempfile::tempdir` follows the process umask, so make integration
/// fixtures deterministic even when the test runner uses 0002/0022.
pub fn secure_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private temporary directory");
    directory
}
