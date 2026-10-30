#pragma once

#include <cerrno>
#include <fcntl.h>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

namespace trillionnium::owner_open {

enum class InhibitObservation { Absent, Present, Unknown };

// Mechanism only: one fixed leaf, no caller-selected command or PID. The
// production callers pin the root-owned state path; host fixtures use a
// private temporary directory and their own uid/gid.
class EmergencyInhibit {
 public:
  EmergencyInhibit(const char* state, uid_t uid, gid_t gid)
      : state_(state), uid_(uid), gid_(gid) {}

  InhibitObservation Observe() const {
    const int parent = OpenParent();
    if (parent < 0) return InhibitObservation::Unknown;
    struct stat metadata {};
    const int result = fstatat(parent, "emergency-stop", &metadata, AT_SYMLINK_NOFOLLOW);
    const int saved = errno;
    close(parent);
    errno = saved;
    if (result == 0) return InhibitObservation::Present;  // Every leaf inhibits.
    return errno == ENOENT ? InhibitObservation::Absent : InhibitObservation::Unknown;
  }

  bool Publish(bool* created) const {
    if (created == nullptr) { errno = EINVAL; return false; }
    *created = false;
    const int parent = OpenParent();
    if (parent < 0) return false;
    int fd = openat(parent, "emergency-stop", O_WRONLY | O_CREAT | O_EXCL |
                    O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd >= 0) {
      *created = true;
    } else if (errno == EEXIST) {
      fd = openat(parent, "emergency-stop", O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    }
    if (fd < 0) { const int saved = errno; close(parent); errno = saved; return false; }
    struct stat metadata {};
    bool ok = fstat(fd, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
        metadata.st_uid == uid_ && metadata.st_gid == gid_ && metadata.st_nlink == 1 &&
        (metadata.st_mode & 07777) == 0600;
    if (!ok) errno = EPERM;
    static constexpr std::string_view value = "owner-authorized emergency stop\n";
    if (ok && *created) {
      std::size_t offset = 0;
      while (offset < value.size()) {
        const ssize_t count = write(fd, value.data() + offset, value.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ok = false; break; }
        offset += static_cast<std::size_t>(count);
      }
    }
    // Failed or partial creation stays inhibited. Never unlink, replace, or
    // reinterpret a malformed leaf as permission to execute.
    if (ok) ok = fsync(fd) == 0 && fsync(parent) == 0;
    const int saved = errno;
    close(fd);
    close(parent);
    errno = saved;
    return ok;
  }

 private:
  int OpenParent() const {
    const int fd = open(state_, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat metadata {};
    if (fstat(fd, &metadata) == 0 && S_ISDIR(metadata.st_mode) && metadata.st_uid == uid_ &&
        metadata.st_gid == gid_ && (metadata.st_mode & 07777) == 0700) return fd;
    close(fd);
    errno = EPERM;
    return -1;
  }
  const char* state_;
  uid_t uid_;
  gid_t gid_;
};
}  // namespace trillionnium::owner_open
