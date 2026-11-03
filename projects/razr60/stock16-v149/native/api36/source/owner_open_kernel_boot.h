#pragma once

#include <array>
#include <cerrno>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

namespace trillionnium::owner_open {
constexpr const char* kKernelBootIdPath = "/proc/sys/kernel/random/boot_id";
constexpr long kProcSuperMagic = 0x9fa0;

inline bool CanonicalKernelBootId(std::string_view raw) {
  if (raw.size() != 37 || raw.back() != '\n') return false;
  for (std::size_t i = 0; i != 36; ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (raw[i] != '-') return false;
    } else if (!((raw[i] >= '0' && raw[i] <= '9') ||
                 (raw[i] >= 'a' && raw[i] <= 'f'))) return false;
  }
  return true;
}

// Return an O_CLOEXEC read-only descriptor to the actual kernel proc file.
// No caller path, environment boot ID, symlink/current marker, or private state
// can select a runtime generation. The caller explicitly transfers this one FD.
inline int OpenValidatedProcBootId(const char* path, std::string* boot_id) {
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return -1;
  if (fd < 3) {
    const int copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    const int saved = errno;
    close(fd);
    errno = saved;
    if (copy < 0) return -1;
    fd = copy;
  }
  struct stat before {}, named {}, after {};
  struct statfs filesystem {};
  std::array<char, 38> bytes {};
  ssize_t count;
  do { count = pread(fd, bytes.data(), bytes.size(), 0); }
  while (count < 0 && errno == EINTR);
  const int flags = fcntl(fd, F_GETFL);
  const bool ok = count == 37 && CanonicalKernelBootId(std::string_view(bytes.data(), 37)) &&
      flags >= 0 && (flags & O_ACCMODE) == O_RDONLY &&
      fstat(fd, &before) == 0 && lstat(path, &named) == 0 &&
      fstatfs(fd, &filesystem) == 0 && filesystem.f_type == kProcSuperMagic &&
      S_ISREG(before.st_mode) && S_ISREG(named.st_mode) && before.st_uid == 0 &&
      before.st_dev == named.st_dev && before.st_ino == named.st_ino &&
      fstat(fd, &after) == 0 && before.st_dev == after.st_dev &&
      before.st_ino == after.st_ino && before.st_mode == after.st_mode &&
      before.st_uid == after.st_uid && before.st_gid == after.st_gid;
  if (!ok) {
    close(fd);
    errno = EINVAL;
    return -1;
  }
  boot_id->assign(bytes.data(), 36);
  return fd;
}

inline int OpenKernelBootId(std::string* boot_id) {
  return OpenValidatedProcBootId(kKernelBootIdPath, boot_id);
}

// The inherited descriptor is opened through the actual read-only proc bind
// that Python will see after chroot, and must identify the same kernel file.
inline int OpenMountedKernelBootId(int host_fd, const std::string& host_boot_id) {
  constexpr const char* mounted_path =
      "/data/trillionnium/owner-open/root/proc/sys/kernel/random/boot_id";
  std::string mounted_boot_id;
  const int fd = OpenValidatedProcBootId(mounted_path, &mounted_boot_id);
  if (fd < 0) return -1;
  struct stat host {}, mounted {};
  if (mounted_boot_id != host_boot_id || fstat(host_fd, &host) != 0 ||
      fstat(fd, &mounted) != 0 || host.st_dev != mounted.st_dev ||
      host.st_ino != mounted.st_ino || host.st_uid != mounted.st_uid ||
      host.st_mode != mounted.st_mode) {
    close(fd);
    errno = EINVAL;
    return -1;
  }
  return fd;
}
}  // namespace trillionnium::owner_open
