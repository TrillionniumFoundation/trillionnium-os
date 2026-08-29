#include <array>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <linux/loop.h>
#include <openssl/evp.h>
#include <sched.h>
#include <string>
#include <string_view>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif

namespace {
constexpr const char* kImage = "/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.squashfs";
constexpr const char* kDigest = "/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.squashfs.sha256";
constexpr const char* kMountRoot = "/data/trillionnium/owner-open/root";
constexpr const char* kStateRoot = "/data/trillionnium/owner-open/state";
constexpr const char* kStateTarget = "/var/lib/trillionnium/owner-open";
constexpr const char* kEmergencyStop = "/data/trillionnium/owner-open/state/emergency-stop";
constexpr const char* kSupervisorPid = "/data/trillionnium/owner-open/state/supervisor.pid";
constexpr const char* kPython = "/usr/bin/python3";
constexpr const char* kSupervisor = "/usr/libexec/trillionnium/owner_open_rootlinux_supervisor.py";
constexpr const char* kSupervisorConfig = "/etc/trillionnium/owner-open/rootlinux-supervisor.json";
constexpr std::size_t kMaximumImageBytes = 8ULL * 1024ULL * 1024ULL * 1024ULL;
volatile sig_atomic_t g_child_pid = -1;

int Fail(std::string_view message) {
  std::fprintf(stderr, "owner-open bootstrap HOLD: %.*s: %s\n",
               static_cast<int>(message.size()), message.data(), std::strerror(errno));
  return 70;
}

bool IsHexDigest(std::string_view value) {
  if (value.size() != 64) return false;
  for (const char current : value) {
    if (!((current >= '0' && current <= '9') || (current >= 'a' && current <= 'f'))) return false;
  }
  return true;
}

bool ReadExact(int fd, void* output, std::size_t length) {
  auto* cursor = static_cast<unsigned char*>(output);
  std::size_t offset = 0;
  while (offset < length) {
    const ssize_t count = read(fd, cursor + offset, length - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return false;
    offset += static_cast<std::size_t>(count);
  }
  return true;
}

bool StableRegular(int fd, std::size_t maximum, struct stat* result) {
  if (fstat(fd, result) != 0) return false;
  return S_ISREG(result->st_mode) && result->st_nlink == 1 && result->st_size > 0 &&
         static_cast<unsigned long long>(result->st_size) <= maximum &&
         (result->st_mode & 0022) == 0;
}

bool ReadDigest(std::string* output) {
  const int fd = open(kDigest, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  struct stat metadata {};
  std::array<char, 65> raw {};
  const bool valid = StableRegular(fd, raw.size(), &metadata) && metadata.st_size == 65 &&
                     ReadExact(fd, raw.data(), raw.size()) && raw[64] == '\n';
  const int saved = errno;
  close(fd);
  errno = saved;
  if (!valid || !IsHexDigest(std::string_view(raw.data(), 64))) return false;
  output->assign(raw.data(), 64);
  return true;
}

bool HashImage(int fd, std::string* digest, std::size_t* bytes) {
  struct stat before {};
  if (!StableRegular(fd, kMaximumImageBytes, &before)) return false;
  if (lseek(fd, 0, SEEK_SET) < 0) return false;
  EVP_MD_CTX* context = EVP_MD_CTX_new();
  if (context == nullptr) return false;
  bool ok = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1;
  std::array<unsigned char, 1024 * 1024> buffer {};
  std::size_t count = 0;
  while (ok) {
    const ssize_t current = read(fd, buffer.data(), buffer.size());
    if (current < 0 && errno == EINTR) continue;
    if (current < 0) {
      ok = false;
      break;
    }
    if (current == 0) break;
    count += static_cast<std::size_t>(current);
    if (count > kMaximumImageBytes || EVP_DigestUpdate(context, buffer.data(), current) != 1) {
      ok = false;
      break;
    }
  }
  std::array<unsigned char, EVP_MAX_MD_SIZE> raw {};
  unsigned int raw_size = 0;
  if (ok) ok = EVP_DigestFinal_ex(context, raw.data(), &raw_size) == 1 && raw_size == 32;
  EVP_MD_CTX_free(context);
  struct stat after {};
  if (!ok || fstat(fd, &after) != 0 ||
      before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
      before.st_mode != after.st_mode || before.st_nlink != after.st_nlink ||
      before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
      before.st_mtim.tv_nsec != after.st_mtim.tv_nsec || count != static_cast<std::size_t>(before.st_size)) {
    return false;
  }
  static constexpr char kHex[] = "0123456789abcdef";
  std::string encoded(64, '0');
  for (std::size_t index = 0; index < 32; ++index) {
    encoded[index * 2] = kHex[raw[index] >> 4];
    encoded[index * 2 + 1] = kHex[raw[index] & 0x0f];
  }
  *digest = std::move(encoded);
  *bytes = count;
  return true;
}

bool EnsureDirectory(const char* path, mode_t mode) {
  std::string current;
  for (const char* cursor = path; *cursor != '\0'; ++cursor) {
    current.push_back(*cursor);
    if (*cursor != '/' || current.size() == 1) continue;
    current.pop_back();
    struct stat metadata {};
    if (lstat(current.c_str(), &metadata) != 0) {
      if (errno != ENOENT || mkdir(current.c_str(), mode) != 0) return false;
    } else if (!S_ISDIR(metadata.st_mode) || S_ISLNK(metadata.st_mode)) {
      errno = ENOTDIR;
      return false;
    }
    current.push_back('/');
  }
  struct stat metadata {};
  if (lstat(path, &metadata) != 0) {
    if (errno != ENOENT || mkdir(path, mode) != 0) return false;
  } else if (!S_ISDIR(metadata.st_mode) || S_ISLNK(metadata.st_mode)) {
    errno = ENOTDIR;
    return false;
  }
  return chmod(path, mode) == 0;
}

bool EmergencyStopPresent() {
  struct stat metadata {};
  if (lstat(kEmergencyStop, &metadata) != 0) return errno != ENOENT;
  return true;
}

struct LoopDevice {
  int control = -1;
  int device = -1;
  std::string path;
};

void CloseLoop(LoopDevice* loop) {
  if (loop->device >= 0) {
    ioctl(loop->device, LOOP_CLR_FD, 0);
    close(loop->device);
    loop->device = -1;
  }
  if (loop->control >= 0) {
    close(loop->control);
    loop->control = -1;
  }
}

bool ConfigureLoop(int image_fd, LoopDevice* loop) {
  loop->control = open("/dev/loop-control", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (loop->control < 0) return false;
  const int number = ioctl(loop->control, LOOP_CTL_GET_FREE);
  if (number < 0) return false;
  std::array<char, 128> candidate {};
  std::snprintf(candidate.data(), candidate.size(), "/dev/block/loop%d", number);
  loop->device = open(candidate.data(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (loop->device < 0) {
    std::snprintf(candidate.data(), candidate.size(), "/dev/loop%d", number);
    loop->device = open(candidate.data(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  }
  if (loop->device < 0 || ioctl(loop->device, LOOP_SET_FD, image_fd) != 0) return false;
  struct loop_info64 info {};
  info.lo_flags = LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR;
  std::snprintf(reinterpret_cast<char*>(info.lo_file_name), LO_NAME_SIZE, "%s", kImage);
  if (ioctl(loop->device, LOOP_SET_STATUS64, &info) != 0) return false;
  loop->path = candidate.data();
  return true;
}

bool RequiredPayloadEntriesExist() {
  static constexpr std::array<const char*, 8> kRequired = {
      "/usr/bin/python3",
      "/usr/bin/adb",
      "/usr/libexec/trillionnium/trillionnium-owner-open-r5-host",
      "/usr/libexec/trillionnium/trillionnium-owner-open-r5-core",
      "/usr/libexec/trillionnium/owner_open_rootlinux_supervisor.py",
      "/usr/libexec/trillionnium/owner_open_connection_broker.py",
      "/usr/libexec/trillionnium/codex_owner_open_mcp.py",
      "/etc/trillionnium/owner-open/rootlinux-supervisor.json",
  };
  const int root = open(kMountRoot, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (root < 0) return false;
  bool ok = true;
  for (const char* absolute : kRequired) {
    struct stat metadata {};
    const char* relative = absolute + 1;
    if (fstatat(root, relative, &metadata, AT_SYMLINK_NOFOLLOW) != 0 ||
        S_ISLNK(metadata.st_mode) || (!S_ISREG(metadata.st_mode) && !S_ISDIR(metadata.st_mode)) ||
        (metadata.st_mode & 0022) != 0) {
      ok = false;
      break;
    }
  }
  close(root);
  return ok;
}

bool BindState() {
  const std::string target = std::string(kMountRoot) + kStateTarget;
  struct stat metadata {};
  if (lstat(target.c_str(), &metadata) != 0 || !S_ISDIR(metadata.st_mode) || S_ISLNK(metadata.st_mode)) {
    errno = ENOENT;
    return false;
  }
  if (mount(kStateRoot, target.c_str(), nullptr, MS_BIND | MS_REC, nullptr) != 0) return false;
  return mount(nullptr, target.c_str(), nullptr,
               MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) == 0;
}

bool WritePid(pid_t pid) {
  const int fd = open(kSupervisorPid, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) return false;
  std::array<char, 64> buffer {};
  const int length = std::snprintf(buffer.data(), buffer.size(), "%d\n", pid);
  const bool ok = length > 0 && static_cast<std::size_t>(length) < buffer.size() &&
                  write(fd, buffer.data(), static_cast<std::size_t>(length)) == length && fsync(fd) == 0;
  const int saved = errno;
  close(fd);
  errno = saved;
  return ok;
}

void SetReady(const char* value) {
#ifdef __ANDROID__
  __system_property_set("trillionnium.owner_open.ready", value);
#else
  (void)value;
#endif
}

void ForwardSignal(int signal_number) {
  const pid_t child = static_cast<pid_t>(g_child_pid);
  if (child > 0) kill(-child, signal_number);
}

bool InstallSignalHandlers() {
  struct sigaction action {};
  action.sa_handler = ForwardSignal;
  sigemptyset(&action.sa_mask);
  action.sa_flags = SA_RESTART;
  return sigaction(SIGTERM, &action, nullptr) == 0 &&
         sigaction(SIGINT, &action, nullptr) == 0 &&
         sigaction(SIGHUP, &action, nullptr) == 0;
}
}  // namespace

int main() {
  if (!EnsureDirectory("/data/trillionnium", 0700) ||
      !EnsureDirectory("/data/trillionnium/owner-open", 0700) ||
      !EnsureDirectory(kStateRoot, 0700) || !EnsureDirectory(kMountRoot, 0700)) {
    return Fail("cannot create private owner-open directories");
  }
  if (EmergencyStopPresent()) {
    errno = ECANCELED;
    return Fail("emergency stop inhibits bootstrap");
  }
  std::string expected_digest;
  if (!ReadDigest(&expected_digest)) return Fail("cannot read canonical image digest");
  const int image_fd = open(kImage, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (image_fd < 0) return Fail("cannot open rootfs image");
  std::string actual_digest;
  std::size_t image_bytes = 0;
  if (!HashImage(image_fd, &actual_digest, &image_bytes) || actual_digest != expected_digest) {
    close(image_fd);
    errno = EBADMSG;
    return Fail("rootfs image digest mismatch");
  }
  if (unshare(CLONE_NEWNS) != 0 || mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) {
    close(image_fd);
    return Fail("cannot isolate mount namespace");
  }
  LoopDevice loop;
  if (!ConfigureLoop(image_fd, &loop)) {
    close(image_fd);
    CloseLoop(&loop);
    return Fail("cannot configure read-only loop device");
  }
  close(image_fd);
  if (mount(loop.path.c_str(), kMountRoot, "squashfs", MS_RDONLY | MS_NOSUID | MS_NODEV,
            "errors=continue") != 0) {
    CloseLoop(&loop);
    return Fail("cannot mount rootfs image read-only");
  }
  if (!RequiredPayloadEntriesExist() || !BindState()) {
    umount2(kMountRoot, MNT_DETACH);
    CloseLoop(&loop);
    return Fail("rootfs payload entries or writable state binding are incomplete");
  }
  unlink(kSupervisorPid);
  const pid_t child = fork();
  if (child < 0) {
    umount2(kMountRoot, MNT_DETACH);
    CloseLoop(&loop);
    return Fail("cannot fork Root Linux supervisor");
  }
  if (child == 0) {
    if (setsid() < 0 || chroot(kMountRoot) != 0 || chdir("/") != 0) _exit(126);
    unsetenv("ANDROID_SERIAL");
    setenv("ADB_SERVER_SOCKET", "tcp:127.0.0.1:15038", 1);
    execl(kPython, kPython, kSupervisor, "--execute", "--config", kSupervisorConfig,
          static_cast<char*>(nullptr));
    _exit(127);
  }
  g_child_pid = child;
  if (!WritePid(child) || !InstallSignalHandlers()) {
    kill(-child, SIGKILL);
    waitpid(child, nullptr, 0);
    unlink(kSupervisorPid);
    umount2(kMountRoot, MNT_DETACH);
    CloseLoop(&loop);
    return Fail("cannot publish or supervise Root Linux process identity");
  }
  SetReady("1");
  int status = 0;
  while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
  }
  SetReady("0");
  unlink(kSupervisorPid);
  const std::string state_target = std::string(kMountRoot) + kStateTarget;
  umount2(state_target.c_str(), MNT_DETACH);
  umount2(kMountRoot, MNT_DETACH);
  CloseLoop(&loop);
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return 70;
}
