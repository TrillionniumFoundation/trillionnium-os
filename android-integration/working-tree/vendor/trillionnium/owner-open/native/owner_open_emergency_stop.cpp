#include <array>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif

namespace {
constexpr const char* kMarker = "/data/trillionnium/owner-open/state/emergency-stop";
constexpr const char* kPidFile = "/data/trillionnium/owner-open/state/supervisor.pid";

int Fail(std::string_view message) {
  std::fprintf(stderr, "owner-open emergency stop HOLD: %.*s: %s\n",
               static_cast<int>(message.size()), message.data(), std::strerror(errno));
  return 70;
}

bool WriteMarker() {
  const int fd = open(kMarker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) return errno == EEXIST;
  static constexpr char kValue[] = "owner-authorized emergency stop\n";
  const bool ok = write(fd, kValue, sizeof(kValue) - 1) == static_cast<ssize_t>(sizeof(kValue) - 1) &&
                  fsync(fd) == 0;
  const int saved = errno;
  close(fd);
  errno = saved;
  return ok;
}

bool ReadPid(pid_t* output) {
  const int fd = open(kPidFile, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return errno == ENOENT;
  struct stat metadata {};
  std::array<char, 64> raw {};
  const ssize_t count = read(fd, raw.data(), raw.size() - 1);
  const int saved = errno;
  const bool valid = fstat(fd, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
                     metadata.st_nlink == 1 && (metadata.st_mode & 0077) == 0 &&
                     count > 0 && count < static_cast<ssize_t>(raw.size());
  close(fd);
  errno = saved;
  if (!valid) return false;
  char* end = nullptr;
  errno = 0;
  const long value = std::strtol(raw.data(), &end, 10);
  if (errno != 0 || end == raw.data() || (*end != '\n' && *end != '\0') ||
      value <= 1 || value > 1'000'000'000L) {
    errno = EINVAL;
    return false;
  }
  *output = static_cast<pid_t>(value);
  return true;
}

void SleepMilliseconds(long milliseconds) {
  struct timespec value {milliseconds / 1000, (milliseconds % 1000) * 1000 * 1000};
  while (nanosleep(&value, &value) != 0 && errno == EINTR) {
  }
}

void SetReady(const char* value) {
#ifdef __ANDROID__
  __system_property_set("trillionnium.owner_open.ready", value);
#else
  (void)value;
#endif
}
}  // namespace

int main() {
  if (!WriteMarker()) return Fail("cannot create persistent emergency-stop marker");
  SetReady("0");
  pid_t pid = -1;
  if (!ReadPid(&pid)) return Fail("cannot read supervisor pid");
  if (pid <= 1) return 0;
  if (kill(-pid, SIGTERM) != 0 && errno != ESRCH) return Fail("cannot signal supervisor process group");
  for (int attempt = 0; attempt < 40; ++attempt) {
    if (kill(-pid, 0) != 0 && errno == ESRCH) return 0;
    SleepMilliseconds(50);
  }
  if (kill(-pid, SIGKILL) != 0 && errno != ESRCH) return Fail("cannot kill supervisor process group");
  for (int attempt = 0; attempt < 40; ++attempt) {
    if (kill(-pid, 0) != 0 && errno == ESRCH) return 0;
    SleepMilliseconds(50);
  }
  errno = ETIMEDOUT;
  return Fail("supervisor process group survived emergency stop");
}
