//! Linux 5.4-compatible retained-dirfd path resolution.
//!
//! The target kernel reserves the `openat2` syscall number but does not
//! implement the syscall. Product custody therefore uses one fixed algorithm:
//! validate a relative path lexically, open every component relative to the
//! previously retained directory, reject symlinks at every step, and reject a
//! device transition. There is no runtime fallback from another resolver.

use std::ffi::CString;
use std::mem::zeroed;
use std::os::fd::{FromRawFd as _, OwnedFd, RawFd};

use thiserror::Error;

pub const RETAINED_PATH_RESOLUTION_METHOD: &str =
    "openat_component_walk_retained_dirfd_nofollow_same_device_v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequiredFileTypeV1 {
    Directory,
    Regular,
}

#[derive(Debug, Error)]
pub enum RetainedPathError {
    #[error("retained path is not a normalized nonempty relative path")]
    InvalidRelativePath,
    #[error("retained path crossed a filesystem device boundary")]
    DeviceBoundary,
    #[error("retained path component has the wrong file type")]
    WrongFileType,
    #[error("retained path operation failed: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, RetainedPathError>;

/// Opens a normalized relative path beneath an already-retained directory.
///
/// Every intermediate component is opened `O_DIRECTORY|O_NOFOLLOW`. The final
/// component is also `O_NOFOLLOW`, must have the requested file type, and must
/// remain on the starting directory's device. Returned descriptors always
/// carry `FD_CLOEXEC`.
pub fn open_beneath_component_walk(
    directory: RawFd,
    relative: &str,
    final_flags: libc::c_int,
    required_type: RequiredFileTypeV1,
) -> Result<OwnedFd> {
    let components = validated_components(relative)?;
    let root_metadata = metadata(directory)?;
    if root_metadata.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(RetainedPathError::WrongFileType);
    }
    let duplicate = unsafe { libc::fcntl(directory, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a fresh descriptor.
    let mut current = unsafe { OwnedFd::from_raw_fd(duplicate) };
    for (index, component) in components.iter().enumerate() {
        let final_component = index + 1 == components.len();
        let flags = if final_component {
            final_flags | libc::O_CLOEXEC | libc::O_NOFOLLOW
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
        };
        // SAFETY: component is one validated NUL-terminated basename and
        // current is a retained directory descriptor.
        let descriptor = unsafe { libc::openat(current.as_raw_fd(), component.as_ptr(), flags) };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a fresh descriptor.
        let opened = unsafe { OwnedFd::from_raw_fd(descriptor) };
        let observed = metadata(opened.as_raw_fd())?;
        if observed.st_dev != root_metadata.st_dev {
            return Err(RetainedPathError::DeviceBoundary);
        }
        let observed_type = observed.st_mode & libc::S_IFMT;
        let expected_type = if final_component {
            match required_type {
                RequiredFileTypeV1::Directory => libc::S_IFDIR,
                RequiredFileTypeV1::Regular => libc::S_IFREG,
            }
        } else {
            libc::S_IFDIR
        };
        if observed_type != expected_type {
            return Err(RetainedPathError::WrongFileType);
        }
        current = opened;
    }
    Ok(current)
}

fn validated_components(relative: &str) -> Result<Vec<CString>> {
    if relative.is_empty()
        || relative.starts_with('/')
        || relative.ends_with('/')
        || relative.as_bytes().contains(&0)
    {
        return Err(RetainedPathError::InvalidRelativePath);
    }
    relative
        .split('/')
        .map(|component| {
            if component.is_empty() || component == "." || component == ".." {
                return Err(RetainedPathError::InvalidRelativePath);
            }
            CString::new(component).map_err(|_| RetainedPathError::InvalidRelativePath)
        })
        .collect()
}

fn metadata(descriptor: RawFd) -> Result<libc::stat> {
    // SAFETY: zero is a valid initial representation and fstat initializes it.
    let mut value: libc::stat = unsafe { zeroed() };
    // SAFETY: value is writable and descriptor remains live for the call.
    if unsafe { libc::fstat(descriptor, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(value)
}

use std::os::fd::AsRawFd as _;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::symlink;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    use tempfile::TempDir;

    use super::*;

    fn root_descriptor(root: &TempDir) -> OwnedFd {
        let path = CString::new(root.path().as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: path is live and NUL terminated; success is uniquely owned.
        let descriptor = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        assert!(descriptor >= 0);
        // SAFETY: open returned a fresh descriptor.
        unsafe { OwnedFd::from_raw_fd(descriptor) }
    }

    #[test]
    fn fixed_component_walk_does_not_depend_on_openat2() {
        let root = TempDir::new().unwrap();
        fs::create_dir(root.path().join("a")).unwrap();
        fs::write(root.path().join("a/value"), b"inside").unwrap();
        let rootfd = root_descriptor(&root);

        // This target's syscall 437 behaves as ENOSYS. The product resolver
        // deliberately does not probe or call it; ordinary openat custody must
        // continue to work under that kernel condition.
        let simulated_openat2 = std::io::Error::from_raw_os_error(libc::ENOSYS);
        assert_eq!(simulated_openat2.raw_os_error(), Some(libc::ENOSYS));
        let opened = open_beneath_component_walk(
            rootfd.as_raw_fd(),
            "a/value",
            libc::O_RDONLY,
            RequiredFileTypeV1::Regular,
        )
        .unwrap();
        let mut bytes = [0_u8; 6];
        assert_eq!(
            unsafe { libc::pread(opened.as_raw_fd(), bytes.as_mut_ptr().cast(), 6, 0) },
            6
        );
        assert_eq!(&bytes, b"inside");
    }

    #[test]
    fn rejects_empty_dot_dot_and_symlink_components() {
        let root = TempDir::new().unwrap();
        fs::create_dir(root.path().join("safe")).unwrap();
        fs::write(root.path().join("safe/value"), b"inside").unwrap();
        symlink("safe", root.path().join("link")).unwrap();
        let rootfd = root_descriptor(&root);
        for path in [
            "",
            "/safe/value",
            "safe//value",
            "safe/./value",
            "safe/../safe/value",
            "safe/value/",
        ] {
            assert!(
                open_beneath_component_walk(
                    rootfd.as_raw_fd(),
                    path,
                    libc::O_RDONLY,
                    RequiredFileTypeV1::Regular
                )
                .is_err(),
                "accepted {path:?}"
            );
        }
        assert!(
            open_beneath_component_walk(
                rootfd.as_raw_fd(),
                "link/value",
                libc::O_RDONLY,
                RequiredFileTypeV1::Regular
            )
            .is_err()
        );
    }

    #[test]
    fn intermediate_rename_and_symlink_swap_never_escape_retained_tree() {
        let root = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        fs::create_dir(root.path().join("live")).unwrap();
        fs::write(root.path().join("live/value"), b"inside").unwrap();
        fs::write(outside.path().join("value"), b"OUTSIDE").unwrap();
        let rootfd = root_descriptor(&root);
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let live = root.path().join("live");
        let held = root.path().join("held");
        let outside_path = outside.path().to_path_buf();
        let swapper = thread::spawn(move || {
            while worker_running.load(Ordering::Relaxed) {
                if fs::rename(&live, &held).is_ok() {
                    let _ = symlink(&outside_path, &live);
                    let _ = fs::remove_file(&live);
                    let _ = fs::rename(&held, &live);
                }
            }
        });
        for _ in 0..2_000 {
            if let Ok(opened) = open_beneath_component_walk(
                rootfd.as_raw_fd(),
                "live/value",
                libc::O_RDONLY,
                RequiredFileTypeV1::Regular,
            ) {
                let mut bytes = [0_u8; 7];
                let count = unsafe {
                    libc::pread(
                        opened.as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                        0,
                    )
                };
                assert_eq!(count, 6);
                assert_eq!(&bytes[..6], b"inside");
            }
        }
        running.store(false, Ordering::Relaxed);
        swapper.join().unwrap();
    }
}
