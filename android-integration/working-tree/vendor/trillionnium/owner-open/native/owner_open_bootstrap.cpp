#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <limits>
#include <openssl/evp.h>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_set>
#include <vector>

#include <json/json.h>

#ifdef __ANDROID__
#include <android/log.h>
#include <sys/system_properties.h>
#endif

namespace {
constexpr const char* kImage = "/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.erofs";
constexpr const char* kDigest = "/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.erofs.sha256";
constexpr const char* kManifest = "/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.image-manifest.json";
constexpr const char* kProfile = "/system_ext/etc/trillionnium/owner-open/profile-codex-host-relay-v1.json";
constexpr const char* kMountRoot = "/data/trillionnium/owner-open/root";
constexpr const char* kStateRoot = "/data/trillionnium/owner-open/state";
constexpr const char* kStateTarget = "/var/lib/trillionnium/owner-open";
constexpr const char* kEmergencyStop = "/data/trillionnium/owner-open/state/emergency-stop";
constexpr const char* kSupervisorPid = "/data/trillionnium/owner-open/state/supervisor.pid";
constexpr const char* kPython = "/usr/bin/python3";
constexpr const char* kSupervisor =
    "/usr/libexec/trillionnium/owner-open/owner_open_rootlinux_supervisor.py";
constexpr const char* kSupervisorConfig =
    "/etc/trillionnium/owner-open/rootlinux-supervisor.json";
constexpr std::size_t kMaximumImageBytes = 8ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMaximumManifestBytes = 16ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMaximumProfileBytes = 1ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMaximumEntryBytes = 512ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMaximumEntries = 4096;
constexpr const char* kImageManifestSchema =
    "org.trillionnium.owner-open.rootfs-image-manifest.v1";
constexpr const char* kStagingManifestSchema =
    "org.trillionnium.owner-open.rootfs-payload-manifest.v1";
constexpr const char* kRuntimeProfileSchema =
    "org.trillionnium.owner-open.android-runtime-profile.v4";
constexpr const char* kRuntimeProfileRevision = "2026-10-08-leap-api37-init-mount-handoff";
constexpr const char* kRuntimeProfileId = "leap-codex-host-relay-v1";
volatile sig_atomic_t g_child_pid = -1;

struct PayloadEntry {
  std::string role;
  std::string path;
  std::string digest;
  mode_t mode = 0;
  uid_t uid = 0;
  gid_t gid = 0;
  std::size_t bytes = 0;
};

struct ImageManifest {
  std::string raw;
  std::string image_digest;
  std::string staging_manifest_digest;
  std::size_t image_bytes = 0;
  std::vector<PayloadEntry> entries;
};

// Diagnostic ABI: stable stage numbers only; never log request/protocol bytes,
// configured paths, tokens, or directory contents.
enum class BootstrapFailure : unsigned {
  ExpectedMode = 1,
  RuntimeProfile = 2,
  ImageManifest = 3,
  DirectoryHandoff = 4,
  EmergencyStop = 5,
  DigestRead = 6,
  DigestAgreement = 7,
  ImageOpen = 8,
  ImageHash = 9,
  MountHandoff = 10,
  SupervisorFork = 11,
  CarrierReadiness = 12,
  SupervisorReap = 13,
  SupervisorChildSetup = 14,
  SupervisorChildExec = 15,
};

int Fail(BootstrapFailure stage) {
  const int saved_errno = errno;
#ifdef __ANDROID__
  __android_log_print(ANDROID_LOG_ERROR, "TrillionniumOwnerOpenBootstrap",
                      "HOLD stage=%u errno=%d", static_cast<unsigned>(stage), saved_errno);
#else
  std::fprintf(stderr, "owner-open bootstrap HOLD: stage=%u errno=%d\n",
               static_cast<unsigned>(stage), saved_errno);
#endif
  errno = saved_errno;
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

bool SameStableMetadata(const struct stat& before, const struct stat& after) {
  return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
         before.st_mode == after.st_mode && before.st_nlink == after.st_nlink &&
         before.st_uid == after.st_uid && before.st_gid == after.st_gid &&
         before.st_size == after.st_size && before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
         before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
         before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
         before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

bool ReadBoundedRegular(const char* path, std::size_t maximum, std::string* output) {
  const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  struct stat before {};
  if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_nlink != 1 ||
      before.st_size <= 0 || static_cast<unsigned long long>(before.st_size) > maximum ||
      (before.st_mode & 0022) != 0) {
    const int saved = errno == 0 ? EINVAL : errno;
    close(fd);
    errno = saved;
    return false;
  }
  output->clear();
  output->reserve(static_cast<std::size_t>(before.st_size));
  std::array<char, 16 * 1024> buffer {};
  bool ok = true;
  while (true) {
    const ssize_t count = read(fd, buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) {
      ok = false;
      break;
    }
    if (count == 0) break;
    if (output->size() + static_cast<std::size_t>(count) > maximum) {
      errno = EFBIG;
      ok = false;
      break;
    }
    output->append(buffer.data(), static_cast<std::size_t>(count));
  }
  struct stat after {};
  const int saved = errno;
  if (fstat(fd, &after) != 0 || !SameStableMetadata(before, after) ||
      output->size() != static_cast<std::size_t>(before.st_size)) {
    ok = false;
  }
  close(fd);
  errno = saved;
  return ok;
}

bool ParseJsonObject(std::string_view raw, Json::Value* value) {
  Json::CharReaderBuilder builder;
  Json::CharReaderBuilder::strictMode(&builder.settings_);
  builder["collectComments"] = false;
  builder["skipBom"] = false;
  builder["rejectDupKeys"] = true;
  builder["stackLimit"] = 128;
  std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  if (reader == nullptr) return false;
  std::string errors;
  if (!reader->parse(raw.data(), raw.data() + raw.size(), value, &errors)) return false;
  return value->isObject();
}

bool JsonString(const Json::Value& object, const char* key, std::string* value) {
  const Json::Value& candidate = object[key];
  if (!candidate.isString()) return false;
  *value = candidate.asString();
  return !value->empty() && value->find('\0') == std::string::npos;
}

bool JsonUnsigned(const Json::Value& object, const char* key, std::uint64_t* value) {
  const Json::Value& candidate = object[key];
  // JsonCpp's isUInt64()/isInt64() deliberately accept integral realValue
  // values.  The manifests use JSON integers only; accepting 13.0 here would
  // diverge from the Python verifier and make numeric type confusion possible.
  if (candidate.type() == Json::uintValue) {
    const auto converted = static_cast<std::uint64_t>(candidate.asUInt64());
    if (converted > std::numeric_limits<std::size_t>::max()) return false;
    *value = converted;
    return true;
  }
  if (candidate.type() == Json::intValue) {
    const auto signed_value = candidate.asInt64();
    if (signed_value < 0) return false;
    const auto converted = static_cast<std::uint64_t>(signed_value);
    if (converted > std::numeric_limits<std::size_t>::max()) return false;
    *value = converted;
    return true;
  }
  return false;
}

bool IsCanonicalPayloadPath(std::string_view path) {
  if (path.empty() || path.front() != '/' || path.back() == '/' ||
      path.find('\0') != std::string_view::npos) {
    return false;
  }
  constexpr std::array<std::string_view, 8> kAllowedPrefixes = {
      "/bin/", "/lib/", "/lib64/", "/usr/bin/", "/usr/lib/", "/usr/lib64/",
      "/usr/libexec/trillionnium/", "/etc/trillionnium/",
  };
  if (std::none_of(kAllowedPrefixes.begin(), kAllowedPrefixes.end(),
                   [path](std::string_view prefix) { return path.starts_with(prefix); })) {
    return false;
  }
  std::size_t begin = 1;
  while (begin < path.size()) {
    const std::size_t end = path.find('/', begin);
    const std::size_t length = end == std::string_view::npos ? path.size() - begin : end - begin;
    if (length == 0 || path.substr(begin, length) == "." || path.substr(begin, length) == "..") {
      return false;
    }
    if (end == std::string_view::npos) break;
    begin = end + 1;
  }
  return true;
}

bool ParseMode(const Json::Value& object, const char* key, mode_t* mode) {
  std::string value;
  if (!JsonString(object, key, &value) || value.size() != 4 || value[0] != '0') return false;
  unsigned parsed = 0;
  for (std::size_t index = 1; index < value.size(); ++index) {
    if (value[index] < '0' || value[index] > '7') return false;
    parsed = (parsed << 3) | static_cast<unsigned>(value[index] - '0');
  }
  if ((parsed & 0022U) != 0) return false;
  *mode = static_cast<mode_t>(parsed);
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

bool ReadImageManifest(ImageManifest* manifest) {
  if (!ReadBoundedRegular(kManifest, kMaximumManifestBytes, &manifest->raw)) return false;
  Json::Value root;
  if (!ParseJsonObject(manifest->raw, &root) || root["schema"] != kImageManifestSchema ||
      root["architecture"] != "aarch64" ||
      (root["libc"] != "glibc" && root["libc"] != "musl") ||
      root["reproducible"] != true || root["claims"].isNull()) {
    errno = EBADMSG;
    return false;
  }
  if (!JsonString(root, "image_sha256", &manifest->image_digest) ||
      !IsHexDigest(manifest->image_digest) ||
      !JsonString(root, "staging_manifest_sha256", &manifest->staging_manifest_digest) ||
      !IsHexDigest(manifest->staging_manifest_digest)) {
    errno = EBADMSG;
    return false;
  }
  std::uint64_t image_bytes = 0;
  if (!JsonUnsigned(root, "image_bytes", &image_bytes) || image_bytes == 0 ||
      image_bytes > kMaximumImageBytes) {
    errno = EBADMSG;
    return false;
  }
  manifest->image_bytes = static_cast<std::size_t>(image_bytes);

  std::uint64_t run_count = 0;
  const Json::Value& runs = root["build_runs"];
  if (!JsonUnsigned(root, "reproducibility_runs", &run_count) || run_count < 2 || run_count > 4 ||
      !runs.isArray() || runs.size() != run_count) {
    errno = EBADMSG;
    return false;
  }
  for (const Json::Value& run : runs) {
    std::uint64_t returncode = 0;
    std::uint64_t run_bytes = 0;
    if (!run.isObject() || !JsonUnsigned(run, "returncode", &returncode) ||
        returncode != 0 || run["image_sha256"] != manifest->image_digest ||
        !JsonUnsigned(run, "image_bytes", &run_bytes) || run_bytes != image_bytes) {
      errno = EBADMSG;
      return false;
    }
  }

  const Json::Value& claims = root["claims"];
  if (!claims.isObject() || claims.size() != 9 || claims["staging_revalidated"] != true ||
      claims["deterministic_options_observed"] != true ||
      claims["independent_builds_byte_identical"] != true ||
      claims["rootfs_image_built"] != true || claims["android_module_bound"] != false ||
      claims["target_files_built"] != false || claims["image_included"] != false ||
      claims["physical_device_observed"] != false || claims["public_release"] != false ||
      root["claim_ceiling"] != "ROOTFS_IMAGE_BUILT_NOT_ANDROID_INCLUDED") {
    errno = EBADMSG;
    return false;
  }
  if (root["runtime_state_directory"] != kStateTarget || root["filesystem"] != "erofs") {
    errno = EBADMSG;
    return false;
  }

  const Json::Value& values = root["entries"];
  std::uint64_t declared_count = 0;
  if (!JsonUnsigned(root, "entry_count", &declared_count) || declared_count == 0 ||
      declared_count > kMaximumEntries || !values.isArray() || values.size() != declared_count) {
    errno = EBADMSG;
    return false;
  }
  std::unordered_set<std::string> roles;
  std::unordered_set<std::string> paths;
  manifest->entries.clear();
  manifest->entries.reserve(values.size());
  for (const Json::Value& item : values) {
    if (!item.isObject()) {
      errno = EBADMSG;
      return false;
    }
    PayloadEntry entry;
    if (!JsonString(item, "role", &entry.role) || !JsonString(item, "destination", &entry.path) ||
        !JsonString(item, "sha256", &entry.digest) || !IsCanonicalPayloadPath(entry.path) ||
        !IsHexDigest(entry.digest) || !roles.insert(entry.role).second ||
        !paths.insert(entry.path).second || !ParseMode(item, "mode", &entry.mode)) {
      errno = EBADMSG;
      return false;
    }
    std::uint64_t uid = 0;
    std::uint64_t gid = 0;
    std::uint64_t bytes = 0;
    if (!JsonUnsigned(item, "uid", &uid) || !JsonUnsigned(item, "gid", &gid) || uid != 0 ||
        gid != 0 || !JsonUnsigned(item, "bytes", &bytes) ||
        bytes > kMaximumEntryBytes) {
      errno = EBADMSG;
      return false;
    }
    entry.uid = static_cast<uid_t>(uid);
    entry.gid = static_cast<gid_t>(gid);
    entry.bytes = static_cast<std::size_t>(bytes);
    manifest->entries.push_back(std::move(entry));
  }

  // The image manifest is the complete pre-Android payload contract, not just
  // a digest envelope. Require every path that the supervisor will execute.
  static constexpr std::array<std::string_view, 10> kRequiredPaths = {
      "/usr/bin/python3",
      "/usr/bin/adb",
      "/usr/libexec/trillionnium/trillionnium-owner-open-r5-host",
      "/usr/libexec/trillionnium/trillionnium-owner-open-r5-core",
      "/usr/libexec/trillionnium/owner-open/owner_open_rootlinux_supervisor.py",
      "/usr/libexec/trillionnium/owner-open/owner_open_connection_broker.py",
      "/usr/libexec/trillionnium/owner-open/adb_smart_socket_relay_release.py",
      "/usr/libexec/trillionnium/provider-adapter",
      "/etc/trillionnium/owner-open/rootlinux-supervisor.json",
      "/etc/trillionnium/owner-open/provider-host-relay-v1.json",
  };
  for (const std::string_view required : kRequiredPaths) {
    if (std::none_of(manifest->entries.begin(), manifest->entries.end(),
                     [required](const PayloadEntry& entry) { return entry.path == required; })) {
      errno = EBADMSG;
      return false;
    }
  }
  return true;
}

bool ValidateRuntimeProfile() {
  std::string raw;
  if (!ReadBoundedRegular(kProfile, kMaximumProfileBytes, &raw)) return false;
  Json::Value root;
  if (!ParseJsonObject(raw, &root) || root["schema"] != kRuntimeProfileSchema ||
      root["revision"] != kRuntimeProfileRevision || root["profile_id"] != kRuntimeProfileId ||
      root["enabled_property"] != "ro.trillionnium.owner_open.enabled" ||
      root["ready_property"] != "trillionnium.owner_open.ready" ||
      root["emergency_stop_property"] != "sys.trillionnium.owner_open.stop") {
    errno = EBADMSG;
    return false;
  }
  const Json::Value& payload = root["rootlinux_payload"];
  if (!payload.isObject() || payload["image"] != kImage || payload["image_sha256"] != kDigest ||
      payload["image_manifest"] != kManifest || payload["mount_root"] != kMountRoot ||
      payload["state_root"] != kStateRoot || payload["read_only_lower"] != true) {
    errno = EBADMSG;
    return false;
  }
  const Json::Value& services = root["android_services"];
  if (!services.isObject() || services["bootstrap"] != "trillionnium-owner-open-bootstrap" ||
      services["ingress"] != "trillionnium-owner-open-ingress" ||
      services["emergency_stop"] != "trillionnium-owner-open-emergency-stop") {
    errno = EBADMSG;
    return false;
  }
  const Json::Value& ingress = root["android_ingress"];
  if (!ingress.isObject() || ingress["abstract_socket"] != "trillionnium_owner_open" ||
      ingress["allowed_peer_domain"] != "u:r:trillionnium_owner_open_client:s0" ||
      ingress["upstream_socket"] != "/data/trillionnium/owner-open/state/broker/owner-open.sock" ||
      ingress["broker_token"] != "/data/trillionnium/owner-open/state/broker/owner-open.token" ||
      ingress["maximum_connections"] != 32 || ingress["automatic_redispatch"] != false) {
    errno = EBADMSG;
    return false;
  }
  const Json::Value& supervisor = root["rootlinux_supervisor"];
  if (!supervisor.isObject() || supervisor["executable"] != kPython ||
      supervisor["entry"] != kSupervisor || supervisor["config"] != kSupervisorConfig) {
    errno = EBADMSG;
    return false;
  }
  const Json::Value& handoff = root["mount_handoff"];
  const Json::Value& provider = root["provider"];
  if (!handoff.isObject() || handoff["owner"] != "android_init" ||
      handoff["verified_property"] != "trillionnium.owner_open.verified" ||
      handoff["mount_ready_property"] != "trillionnium.owner_open.mount_ready" ||
      handoff["service_mount_namespace"] != "mnt" ||
      handoff["bootstrap_mount_operations"] != false || !provider.isObject() ||
      provider["role"] != "host_codex" || provider["automatic_reconnect"] != false ||
      provider["automatic_redispatch"] != false || provider["long_lived_credentials_on_phone"] != false) {
    errno = EBADMSG;
    return false;
  }
  const Json::Value& claims = root["claims"];
  if (!claims.isObject() || claims.size() != 7 || claims["source_modules_authored"] != true ||
      claims["soong_compiled"] != false || claims["selinux_compiled"] != false ||
      claims["target_files_built"] != false || claims["image_included"] != false ||
      claims["physical_device_observed"] != false || claims["public_release"] != false ||
      root["claim_ceiling"] != "LEAP_API37_SOURCE_CANDIDATE_NOT_DEVICE_QUALIFIED") {
    errno = EBADMSG;
    return false;
  }
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
  if (!ok || fstat(fd, &after) != 0 || !SameStableMetadata(before, after) ||
      count != static_cast<std::size_t>(before.st_size)) {
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

// Platform init owns mkdir, chmod and restorecon, including the mountpoint.
// Verification never modifies an already mounted immutable lower.
bool VerifyDirectory(const char* path, mode_t mode) {
  struct stat metadata {};
  if (lstat(path, &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
      S_ISLNK(metadata.st_mode) || metadata.st_uid != 0 || metadata.st_gid != 0 ||
      (metadata.st_mode & 07777) != mode) {
    errno = EPERM;
    return false;
  }
  return true;
}

bool EmergencyStopPresent() {
  struct stat metadata {};
  if (lstat(kEmergencyStop, &metadata) != 0) return errno != ENOENT;
  return true;
}

int OpenPayloadPath(int root, std::string_view absolute, bool directory) {
  if (!IsCanonicalPayloadPath(absolute) && absolute != "/etc/trillionnium/owner-open/rootfs.manifest.json") {
    errno = EINVAL;
    return -1;
  }
  int current = dup(root);
  if (current < 0) return -1;
  std::size_t begin = 1;
  while (begin < absolute.size()) {
    const std::size_t end = absolute.find('/', begin);
    const std::size_t length = end == std::string_view::npos ? absolute.size() - begin : end - begin;
    if (length == 0 || length > 255) {
      close(current);
      errno = EINVAL;
      return -1;
    }
    const bool last = end == std::string_view::npos;
    std::string component(absolute.substr(begin, length));
    int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
    if (!last || directory) flags |= O_DIRECTORY;
    const int next = openat(current, component.c_str(), flags);
    const int saved = errno;
    close(current);
    if (next < 0) {
      errno = saved;
      return -1;
    }
    current = next;
    if (last) return current;
    begin = end + 1;
  }
  close(current);
  errno = EINVAL;
  return -1;
}

bool HashRegularDescriptor(int fd, std::size_t maximum, std::string* digest,
                            std::size_t* bytes, struct stat* metadata_out) {
  struct stat before {};
  if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_nlink != 1 ||
      before.st_size < 0 || static_cast<unsigned long long>(before.st_size) > maximum ||
      (before.st_mode & 0022) != 0 || lseek(fd, 0, SEEK_SET) < 0) {
    return false;
  }
  EVP_MD_CTX* context = EVP_MD_CTX_new();
  if (context == nullptr || EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
    if (context != nullptr) EVP_MD_CTX_free(context);
    return false;
  }
  std::array<unsigned char, 1024 * 1024> buffer {};
  std::size_t count = 0;
  bool ok = true;
  while (true) {
    const ssize_t current = read(fd, buffer.data(), buffer.size());
    if (current < 0 && errno == EINTR) continue;
    if (current < 0) {
      ok = false;
      break;
    }
    if (current == 0) break;
    count += static_cast<std::size_t>(current);
    if (count > maximum || EVP_DigestUpdate(context, buffer.data(), current) != 1) {
      ok = false;
      break;
    }
  }
  std::array<unsigned char, EVP_MAX_MD_SIZE> raw {};
  unsigned int raw_size = 0;
  if (ok) ok = EVP_DigestFinal_ex(context, raw.data(), &raw_size) == 1 && raw_size == 32;
  EVP_MD_CTX_free(context);
  struct stat after {};
  if (!ok || fstat(fd, &after) != 0 || !SameStableMetadata(before, after) ||
      count != static_cast<std::size_t>(before.st_size)) {
    return false;
  }
  static constexpr char kHex[] = "0123456789abcdef";
  digest->assign(64, '0');
  for (std::size_t index = 0; index < 32; ++index) {
    (*digest)[index * 2] = kHex[raw[index] >> 4];
    (*digest)[index * 2 + 1] = kHex[raw[index] & 0x0f];
  }
  *bytes = count;
  if (metadata_out != nullptr) *metadata_out = before;
  return true;
}

bool StagingEntriesMatch(const Json::Value& staging,
                         const std::vector<PayloadEntry>& image_entries) {
  const Json::Value& values = staging["entries"];
  if (!values.isArray() || values.size() != image_entries.size()) return false;
  std::vector<bool> matched(image_entries.size(), false);
  for (const Json::Value& item : values) {
    if (!item.isObject()) return false;
    std::string role;
    std::string path;
    std::string digest;
    mode_t mode = 0;
    std::uint64_t uid = 0;
    std::uint64_t gid = 0;
    std::uint64_t bytes = 0;
    if (!JsonString(item, "role", &role) || !JsonString(item, "destination", &path) ||
        !JsonString(item, "sha256", &digest) || !ParseMode(item, "mode", &mode) ||
        !JsonUnsigned(item, "uid", &uid) || !JsonUnsigned(item, "gid", &gid) ||
        !JsonUnsigned(item, "bytes", &bytes) || !IsCanonicalPayloadPath(path) ||
        !IsHexDigest(digest) || uid != 0 || gid != 0 ||
        bytes > kMaximumEntryBytes) {
      return false;
    }
    for (std::size_t index = 0; index < image_entries.size(); ++index) {
      const PayloadEntry& expected = image_entries[index];
      if (!matched[index] && role == expected.role && path == expected.path &&
          digest == expected.digest && mode == expected.mode && uid == expected.uid &&
          gid == expected.gid && bytes == expected.bytes) {
        matched[index] = true;
        break;
      }
    }
  }
  return std::all_of(matched.begin(), matched.end(), [](bool value) { return value; });
}

bool RequiredPayloadEntriesExist(const ImageManifest& manifest) {
  const int root = open(kMountRoot, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (root < 0) return false;
  bool ok = true;
  for (const PayloadEntry& entry : manifest.entries) {
    const int fd = OpenPayloadPath(root, entry.path, false);
    if (fd < 0) {
      ok = false;
      break;
    }
    struct stat metadata {};
    std::string digest;
    std::size_t bytes = 0;
    if (!HashRegularDescriptor(fd, kMaximumEntryBytes, &digest, &bytes, &metadata) ||
        (metadata.st_mode & 07777) != entry.mode || metadata.st_uid != entry.uid ||
        metadata.st_gid != entry.gid || bytes != entry.bytes || digest != entry.digest) {
      close(fd);
      ok = false;
      break;
    }
    close(fd);
  }
  if (ok) {
    const int embedded = OpenPayloadPath(root, "/etc/trillionnium/owner-open/rootfs.manifest.json", false);
    if (embedded < 0) {
      ok = false;
    } else {
      std::string raw;
      struct stat metadata {};
      std::string digest;
      std::size_t bytes = 0;
      if (!HashRegularDescriptor(embedded, kMaximumManifestBytes, &digest, &bytes, &metadata) ||
          digest != manifest.staging_manifest_digest || lseek(embedded, 0, SEEK_SET) < 0) {
        ok = false;
      } else {
        raw.resize(bytes);
        if (!ReadExact(embedded, raw.data(), raw.size())) {
          ok = false;
        } else {
          Json::Value staging;
          std::uint64_t staging_count = 0;
          bool staging_valid = ParseJsonObject(raw, &staging);
          if (staging_valid) {
            // Keep the claims value const after checking its container type.  With
            // JSON_USE_EXCEPTION=0, nested non-const operator[] on a scalar can
            // abort instead of returning a clean contract failure.
            const Json::Value& claims = staging["claims"];
            staging_valid =
                staging["schema"] == kStagingManifestSchema &&
                staging["runtime_state_directory"] == kStateTarget &&
                JsonUnsigned(staging, "entry_count", &staging_count) &&
                staging_count == manifest.entries.size() && claims.isObject() && claims.size() == 8 &&
                claims["staging_tree_complete"] == true &&
                claims["expected_source_digests_verified"] == true &&
                claims["aarch64_elf_headers_verified_where_required"] == true &&
                claims["rootfs_image_built"] == false &&
                claims["android_module_bound"] == false && claims["image_included"] == false &&
                claims["physical_device_observed"] == false && claims["public_release"] == false;
          }
          if (!staging_valid || !StagingEntriesMatch(staging, manifest.entries)) {
            ok = false;
          }
        }
      }
      close(embedded);
    }
  }
  close(root);
  return ok;
}

// Android init owns all loop, mount and unmount operations. The service is
// launched with `namespace mnt`, established before the SELinux transition.
// The bootstrap validates the resulting immutable lower and writable bind; it
// never requests mount permission or trusts a readiness property by itself.
bool ValidateInitMountedRoot() {
  struct statfs lower {};
  struct statfs state_fs {};
  struct stat source {};
  struct stat target {};
  const std::string target_path = std::string(kMountRoot) + kStateTarget;
  constexpr unsigned long kErofsMagic = 0xE0F5E1E2UL;
  const unsigned long lower_flags = MS_RDONLY | MS_NOSUID | MS_NODEV;
  const unsigned long state_flags = MS_NOSUID | MS_NODEV | MS_NOEXEC;
  if (statfs(kMountRoot, &lower) != 0 ||
      static_cast<unsigned long>(lower.f_type) != kErofsMagic ||
      (static_cast<unsigned long>(lower.f_flags) & lower_flags) != lower_flags ||
      statfs(target_path.c_str(), &state_fs) != 0 ||
      (static_cast<unsigned long>(state_fs.f_flags) & state_flags) != state_flags ||
      (static_cast<unsigned long>(state_fs.f_flags) & MS_RDONLY) != 0 ||
      lstat(kStateRoot, &source) != 0 || lstat(target_path.c_str(), &target) != 0 ||
      !S_ISDIR(source.st_mode) || !S_ISDIR(target.st_mode) ||
      source.st_dev != target.st_dev || source.st_ino != target.st_ino) {
    errno = EPERM;
    return false;
  }
  struct statfs proc_fs {};
  struct statfs dev_fs {};
  struct stat proc_source {}, proc_target {}, dev_source {}, dev_target {};
  const std::string proc_path = std::string(kMountRoot) + "/proc";
  const std::string dev_path = std::string(kMountRoot) + "/dev";
  const unsigned long proc_flags = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC;
  if (statfs(proc_path.c_str(), &proc_fs) != 0 ||
      static_cast<unsigned long>(proc_fs.f_type) != 0x9fa0UL ||
      (static_cast<unsigned long>(proc_fs.f_flags) & proc_flags) != proc_flags ||
      lstat("/proc", &proc_source) != 0 || lstat(proc_path.c_str(), &proc_target) != 0 ||
      proc_source.st_dev != proc_target.st_dev || proc_source.st_ino != proc_target.st_ino ||
      statfs(dev_path.c_str(), &dev_fs) != 0 ||
      (static_cast<unsigned long>(dev_fs.f_flags) & (MS_RDONLY | MS_NOSUID | MS_NOEXEC)) != (MS_RDONLY | MS_NOSUID | MS_NOEXEC) ||
      lstat("/dev", &dev_source) != 0 || lstat(dev_path.c_str(), &dev_target) != 0 ||
      dev_source.st_dev != dev_target.st_dev || dev_source.st_ino != dev_target.st_ino) {
    errno = EPERM;
    return false;
  }
  return true;
}

// Readiness observes this exact unreaped supervisor session and both children.
// An old status file, a mere fork, and provider reachability are not readiness.
bool ProcessIdentityMatches(const Json::Value& identity, pid_t parent, pid_t expected_pid,
                            Json::Int64 expected_start) {
  for (const char* field : {"pid", "parent_pid", "process_group", "session_id", "start_time_ticks"}) {
    if (!identity[field].isInt64() || identity[field].asInt64() <= 0) return false;
  }
  const Json::Int64 pid = identity["pid"].asInt64();
  if (pid > 1000000000 || (expected_pid > 0 && pid != expected_pid) ||
      identity["parent_pid"].asInt64() != parent ||
      identity["process_group"].asInt64() != pid || identity["session_id"].asInt64() != pid ||
      (expected_start > 0 && identity["start_time_ticks"].asInt64() != expected_start)) return false;
  const std::string path = "/proc/" + std::to_string(pid) + "/stat";
  const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  std::array<char, 8193> buffer {};
  const ssize_t count = read(fd, buffer.data(), buffer.size());
  close(fd);
  if (count <= 0 || count >= static_cast<ssize_t>(buffer.size())) return false;
  const std::string raw(buffer.data(), static_cast<std::size_t>(count));
  const auto terminator = raw.rfind(')');
  if (terminator == std::string::npos) return false;
  std::istringstream fields(raw.substr(terminator + 1));
  std::string state;
  Json::Int64 ppid = 0, pgid = 0, sid = 0, start = 0;
  if (!(fields >> state >> ppid >> pgid >> sid) || state == "Z" || state == "X") return false;
  std::string ignored;
  for (int index = 4; index < 19; ++index) if (!(fields >> ignored)) return false;
  if (!(fields >> start)) return false;
  return ppid == parent && pgid == pid && sid == pid && start == identity["start_time_ticks"].asInt64();
}

bool RelayDescriptorPath(const Json::Value& session, const Json::Value& status, std::string* output) {
  const auto& directory = status["children"]["owner-open-adb-relay"]["instance_directory"];
  if (!session["session_id"].isString() || !directory.isString()) return false;
  const std::string session_id = session["session_id"].asString();
  const std::string path = directory.asString();
  const std::string prefix = std::string(kStateTarget) + "/carriers/" + session_id + "/owner-open-adb-relay/";
  const auto hex32 = [](std::string_view value) {
    return value.size() == 32 && std::all_of(value.begin(), value.end(), [](char ch) {
      return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
  };
  if (!hex32(session_id) || path.compare(0, prefix.size(), prefix) != 0 ||
      !hex32(std::string_view(path).substr(prefix.size()))) return false;
  const std::string physical = std::string(kStateRoot) + path.substr(std::strlen(kStateTarget));
  if (!VerifyDirectory(physical.c_str(), 0700)) return false;
  *output = physical + "/descriptor.json";
  return true;
}

bool WaitForSupervisorReady(pid_t child) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
  while (std::chrono::steady_clock::now() < deadline) {
    siginfo_t information {};
    if (waitid(P_PID, child, &information, WEXITED | WNOHANG | WNOWAIT) != 0 ||
        information.si_pid != 0 || EmergencyStopPresent()) return false;
    std::string session_raw, status_raw, descriptor_raw, relay_raw, relay_path;
    Json::Value session, status, descriptor, relay;
    struct stat socket_metadata {}, token_metadata {};
    if (ReadBoundedRegular("/data/trillionnium/owner-open/state/.supervisor-session.json", 65536, &session_raw) &&
        ReadBoundedRegular("/data/trillionnium/owner-open/state/supervisor-status.json", 65536, &status_raw) &&
        ParseJsonObject(session_raw, &session) && ParseJsonObject(status_raw, &status) &&
        session["schema"] == "org.trillionnium.owner-open.rootlinux-supervisor-session.v1" &&
        session["supervisor_pid"].isIntegral() && session["supervisor_pid"].asInt64() == child &&
        status["schema"] == "org.trillionnium.owner-open.rootlinux-supervisor-status.v1" &&
        status["state"] == "running" && session["session_id"].isString() &&
        !session["session_id"].asString().empty() && status["session_id"] == session["session_id"] &&
        status["automatic_effect_redispatch"] == false && status["children"].size() == 2 &&
        status["children"]["owner-open-broker"]["running"] == true &&
        status["children"]["owner-open-adb-relay"]["running"] == true &&
        lstat("/data/trillionnium/owner-open/state/broker/owner-open.sock", &socket_metadata) == 0 &&
        S_ISSOCK(socket_metadata.st_mode) && socket_metadata.st_uid == 0 &&
        lstat("/data/trillionnium/owner-open/state/broker/owner-open.token", &token_metadata) == 0 &&
        S_ISREG(token_metadata.st_mode) && token_metadata.st_uid == 0 &&
        token_metadata.st_nlink == 1 && (token_metadata.st_mode & 07777) == 0600 &&
        token_metadata.st_size == 65 &&
        ReadBoundedRegular("/data/trillionnium/owner-open/state/broker/owner-open.descriptor.json", 262144, &descriptor_raw) &&
        ParseJsonObject(descriptor_raw, &descriptor) &&
        descriptor["schema"] == "org.trillionnium.owner-open.connection-broker.v1" &&
        descriptor["automatic_redispatch"] == false &&
        descriptor["host_hello_ack"]["kind"] == "hello.ack" &&
        descriptor["host_hello_ack"]["payload"]["protocol"] == "trillionnium.agent.turn.v1" &&
        descriptor["host_hello_ack"]["payload"]["protocol_version"] == 1 &&
        descriptor["host_hello_ack"]["payload"]["runtime_ready"] == true &&
        status["children"]["owner-open-broker"]["pid"].isInt64() &&
        status["children"]["owner-open-broker"]["anchor_start_time_ticks"].isInt64() &&
        ProcessIdentityMatches(descriptor["runtime_identity"]["broker"], child,
          status["children"]["owner-open-broker"]["pid"].asInt64(),
          status["children"]["owner-open-broker"]["anchor_start_time_ticks"].asInt64()) &&
        ProcessIdentityMatches(descriptor["runtime_identity"]["host"],
          descriptor["runtime_identity"]["broker"]["pid"].asInt64(), -1, 0) &&
        RelayDescriptorPath(session, status, &relay_path) &&
        ReadBoundedRegular(relay_path.c_str(), 65536, &relay_raw) &&
        ParseJsonObject(relay_raw, &relay) &&
        relay["schema"] == "org.trillionnium.owner-open.adb-smart-socket-relay.v1" &&
        relay["listen_host"] == "127.0.0.1" && relay["listen_port"] == 15038 &&
        relay["upstream_host"] == "127.0.0.1" && relay["upstream_port"] == 15037 &&
        relay["automatic_redispatch"] == false &&
        status["children"]["owner-open-adb-relay"]["pid"].isInt64() &&
        status["children"]["owner-open-adb-relay"]["anchor_start_time_ticks"].isInt64() &&
        ProcessIdentityMatches(relay["runtime_identity"], child,
          status["children"]["owner-open-adb-relay"]["pid"].asInt64(),
          status["children"]["owner-open-adb-relay"]["anchor_start_time_ticks"].asInt64())) return true;
    usleep(50000);
  }
  errno = ETIMEDOUT;
  return false;
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

void SetProperty(const char* name, const char* value) {
#ifdef __ANDROID__
  __system_property_set(name, value);
#else
  (void)name;
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

// Keep the child generation pinned until forwarding signals are blocked. A
// numeric PGID is never signalled after reaping permits its PID to be reused.
bool ReapPinnedChild(pid_t child, int* status) {
  siginfo_t information {};
  int result;
  do { result = waitid(P_PID, child, &information, WEXITED | WNOWAIT); }
  while (result < 0 && errno == EINTR);
  if (result < 0) return false;
  sigset_t blocked, previous;
  sigemptyset(&blocked);
  sigaddset(&blocked, SIGTERM);
  sigaddset(&blocked, SIGINT);
  sigaddset(&blocked, SIGHUP);
  if (sigprocmask(SIG_BLOCK, &blocked, &previous) != 0) return false;
  pid_t waited;
  do { waited = waitpid(child, status, 0); } while (waited < 0 && errno == EINTR);
  const int saved = errno;
  g_child_pid = -1;
  const bool restored = sigprocmask(SIG_SETMASK, &previous, nullptr) == 0;
  errno = saved;
  return waited == child && restored;
}
}  // namespace

int main(int argc, char** argv) {
  const bool verify_only = argc == 2 && std::strcmp(argv[1], "--verify-image") == 0;
  const bool run_mounted = argc == 2 && std::strcmp(argv[1], "--run-mounted") == 0;
  if (!verify_only && !run_mounted) {
    errno = EINVAL;
    return Fail(BootstrapFailure::ExpectedMode);
  }
  if (verify_only) SetProperty("trillionnium.owner_open.verified", "0");
  // init may restart this service after a crash while the old readiness
  // property is still set.  Clear it before any validation so a failed
  // bootstrap can never leave the ingress gate open on stale state.
  SetProperty("trillionnium.owner_open.ready", "0");
  if (!ValidateRuntimeProfile()) return Fail(BootstrapFailure::RuntimeProfile);
  ImageManifest manifest;
  if (!ReadImageManifest(&manifest)) return Fail(BootstrapFailure::ImageManifest);
  if (!VerifyDirectory("/data/trillionnium", 0700) ||
      !VerifyDirectory("/data/trillionnium/owner-open", 0700) ||
      !VerifyDirectory(kStateRoot, 0700) || !VerifyDirectory(kMountRoot, run_mounted ? 0755 : 0700)) {
    return Fail(BootstrapFailure::DirectoryHandoff);
  }
  if (EmergencyStopPresent()) {
    errno = ECANCELED;
    return Fail(BootstrapFailure::EmergencyStop);
  }
  std::string expected_digest;
  if (!ReadDigest(&expected_digest)) return Fail(BootstrapFailure::DigestRead);
  if (expected_digest != manifest.image_digest) {
    errno = EBADMSG;
    return Fail(BootstrapFailure::DigestAgreement);
  }
  const int image_fd = open(kImage, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (image_fd < 0) return Fail(BootstrapFailure::ImageOpen);
  std::string actual_digest;
  std::size_t image_bytes = 0;
  if (!HashImage(image_fd, &actual_digest, &image_bytes) || image_bytes == 0 ||
      image_bytes != manifest.image_bytes || actual_digest != expected_digest ||
      actual_digest != manifest.image_digest) {
    close(image_fd);
    errno = EBADMSG;
    return Fail(BootstrapFailure::ImageHash);
  }
  close(image_fd);
  if (verify_only) {
    SetProperty("trillionnium.owner_open.verified", "1");
    return 0;
  }
  if (!ValidateInitMountedRoot() || !RequiredPayloadEntriesExist(manifest)) {
    return Fail(BootstrapFailure::MountHandoff);
  }
  unlink(kSupervisorPid);
  const pid_t child = fork();
  if (child < 0) {
    return Fail(BootstrapFailure::SupervisorFork);
  }
  if (child == 0) {
    if (setsid() < 0 || chroot(kMountRoot) != 0 || chdir("/") != 0) {
      Fail(BootstrapFailure::SupervisorChildSetup);
      _exit(126);
    }
    setenv("PYTHONHOME", "/usr", 1);
    setenv("PYTHONDONTWRITEBYTECODE", "1", 1);
    unsetenv("ANDROID_SERIAL");
    unsetenv("ADB_SERVER_PORT");
    unsetenv("ANDROID_ADB_SERVER_PORT");
    setenv("ADB_SERVER_SOCKET", "tcp:127.0.0.1:15038", 1);
    execl(kPython, kPython, kSupervisor, "--execute", "--same-domain-proc-observation", "--config", kSupervisorConfig,
          static_cast<char*>(nullptr));
    Fail(BootstrapFailure::SupervisorChildExec);
    _exit(127);
  }
  g_child_pid = child;
  if (!WritePid(child) || !InstallSignalHandlers() || !WaitForSupervisorReady(child)) {
    kill(-child, SIGKILL);
    // Also stop the unreaped direct child if failure preceded its setsid().
    kill(child, SIGKILL);
    int stopped_status = 0;
    ReapPinnedChild(child, &stopped_status);
    unlink(kSupervisorPid);
    return Fail(BootstrapFailure::CarrierReadiness);
  }
  SetProperty("trillionnium.owner_open.ready", "1");
  int status = 0;
  if (!ReapPinnedChild(child, &status)) {
    const int saved = errno;
    SetProperty("trillionnium.owner_open.ready", "0");
    unlink(kSupervisorPid);
    errno = saved;
    return Fail(BootstrapFailure::SupervisorReap);
  }
  SetProperty("trillionnium.owner_open.ready", "0");
  unlink(kSupervisorPid);
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return 70;
}
