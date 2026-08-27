//! Small Linux syscall shims whose libc symbol surface differs across targets.
//!
//! In particular, the Rust `libc` crate exposes `renameat2()` for glibc targets
//! but not for every musl target.  The kernel ABI and `SYS_renameat2` number are
//! available on both supported build targets, so keep the no-replace primitive
//! in one target-independent wrapper instead of silently falling back to
//! replace-capable `renameat()`.

use std::ffi::CStr;
use std::os::fd::RawFd;

pub(crate) fn renameat2_noreplace(
    old_directory: RawFd,
    old_name: &CStr,
    new_directory: RawFd,
    new_name: &CStr,
) -> libc::c_int {
    // SAFETY: both names are retained `CStr` values and therefore NUL
    // terminated for the duration of the call. Directory descriptors are
    // borrowed from live `File` values at every call site. The raw syscall is
    // required because musl's libc bindings do not export the function symbol.
    unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            old_directory,
            old_name.as_ptr(),
            new_directory,
            new_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        ) as libc::c_int
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;

    use super::renameat2_noreplace;

    #[test]
    fn raw_syscall_preserves_no_replace_on_supported_linux_targets() {
        let directory = tempfile::tempdir().unwrap();
        let directory_file = File::open(directory.path()).unwrap();
        let from_name = CString::new("from").unwrap();
        let to_name = CString::new("to").unwrap();

        let mut from = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.path().join("from"))
            .unwrap();
        from.write_all(b"from").unwrap();
        drop(from);

        assert_eq!(
            renameat2_noreplace(
                directory_file.as_raw_fd(),
                &from_name,
                directory_file.as_raw_fd(),
                &to_name,
            ),
            0
        );
        assert_eq!(std::fs::read(directory.path().join("to")).unwrap(), b"from");

        std::fs::write(directory.path().join("from"), b"second").unwrap();
        assert_eq!(
            renameat2_noreplace(
                directory_file.as_raw_fd(),
                &from_name,
                directory_file.as_raw_fd(),
                &to_name,
            ),
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(directory.path().join("to")).unwrap(), b"from");
        assert_eq!(
            std::fs::read(directory.path().join("from")).unwrap(),
            b"second"
        );
    }
}
