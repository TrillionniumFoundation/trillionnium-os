#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif

namespace {
constexpr const char* kState = "/data/trillionnium/owner-open/state";
constexpr const char* kMarker = "emergency-stop";

int Fail(std::string_view message) {
  std::fprintf(stderr, "owner-open emergency stop HOLD: %.*s: %s\n",
               static_cast<int>(message.size()), message.data(), std::strerror(errno));
  return 70;
}

bool WriteMarker() {
  const int parent = open(kState, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (parent < 0) return false;
  struct stat directory {};
  if (fstat(parent, &directory) != 0 || !S_ISDIR(directory.st_mode) ||
      directory.st_uid != 0 || directory.st_gid != 0 || (directory.st_mode & 07777) != 0700) {
    close(parent);
    errno = EPERM;
    return false;
  }
  bool created = true;
  int fd = openat(parent, kMarker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0 && errno == EEXIST) {
    created = false;
    fd = openat(parent, kMarker, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
  }
  if (fd < 0) { const int saved = errno; close(parent); errno = saved; return false; }
  struct stat metadata {};
  bool ok = fstat(fd, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
            metadata.st_uid == 0 && metadata.st_gid == 0 && metadata.st_nlink == 1 &&
            (metadata.st_mode & 07777) == 0600;
  if (!ok) errno = EPERM;
  static constexpr char kValue[] = "owner-authorized emergency stop\n";
  if (ok && created) ok = write(fd, kValue, sizeof(kValue) - 1) == static_cast<ssize_t>(sizeof(kValue) - 1);
  // Both an existing inhibit and a newly created one must be durable before
  // success. A failed/short creation stays inhibited for offline reconciliation.
  if (ok) ok = fsync(fd) == 0 && fsync(parent) == 0;
  const int saved = errno;
  close(fd);
  close(parent);
  errno = saved;
  return ok;
}

void ClearReady() {
#ifdef __ANDROID__
  __system_property_set("trillionnium.owner_open.ready", "0");
#endif
}
}  // namespace

int main() {
  // Android init owns the tracked bootstrap service cgroup. Never read a stale
  // numeric PID or signal an unbound PGID from a persistent file.
  ClearReady();
  if (!WriteMarker()) return Fail("cannot durably publish persistent inhibit marker");
  return 0;
}
