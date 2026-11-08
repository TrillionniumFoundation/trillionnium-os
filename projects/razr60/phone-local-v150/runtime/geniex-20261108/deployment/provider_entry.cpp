// A separate init-owned entry for the reviewed local NPU provider.
// It neither changes the original bootstrap/readiness algorithm nor transitions
// itself to another SELinux domain. init must supply the existing bootstrap
// domain and the four explicitly reviewed capabilities below.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <linux/capability.h>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <vector>
#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif
#include "json.hpp"
#include "hash/hash.h"

using J = nlohmann::json;
namespace {
constexpr const char* ROOT = "/data/trillionnium/owner-open/root";
constexpr const char* STATE = "/data/trillionnium/owner-open/state";
constexpr const char* GNU_STATE = "/var/lib/trillionnium/owner-open";
constexpr const char* CONTEXT = "u:r:trillionnium_owner_open_bootstrap:s0";
constexpr const char* STAGE_CONTEXT = "u:object_r:trillionnium_owner_open_geniex_stage_file:s0";
constexpr std::uint64_t CAPS = (1ULL << CAP_CHOWN) | (1ULL << CAP_DAC_OVERRIDE) |
                               (1ULL << CAP_KILL) | (1ULL << CAP_SYS_CHROOT);
constexpr std::size_t MAX_PLAN = 131072;
constexpr std::size_t MAX_SOURCE = 8 * 1024 * 1024;
// The verified EROFS manifest stores the interpreter as immutable 0555.
constexpr mode_t PYTHON_MODE = 0555;

void need(bool value, const char* error) {
    if (!value) throw std::runtime_error(error);
}
bool hex(const std::string& value, std::size_t length) {
    return value.size() == length && value.find_first_not_of("0123456789abcdef") == std::string::npos;
}
bool stable(const struct stat& a, const struct stat& b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid &&
        a.st_gid == b.st_gid && a.st_mode == b.st_mode && a.st_nlink == b.st_nlink &&
        a.st_size == b.st_size && a.st_mtim.tv_sec == b.st_mtim.tv_sec &&
        a.st_mtim.tv_nsec == b.st_mtim.tv_nsec && a.st_ctim.tv_sec == b.st_ctim.tv_sec &&
        a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}
bool canonical(const std::string& path) {
    if (path.empty() || path[0] != '/' || path.back() == '/' || path.find('\0') != std::string::npos ||
        path.find('\n') != std::string::npos || path.find("//") != std::string::npos) return false;
    std::size_t start = 1;
    while (start < path.size()) {
        const auto end = path.find('/', start);
        const auto part = path.substr(start, end == std::string::npos ? end : end - start);
        if (part.empty() || part == "." || part == "..") return false;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return true;
}
void directory_chain(const std::string& path) {
    need(canonical(path), "noncanonical_path");
    for (std::size_t pos = path.find('/', 1); pos != std::string::npos; pos = path.find('/', pos + 1)) {
        struct stat info{};
        need(lstat(path.substr(0, pos).c_str(), &info) == 0 && S_ISDIR(info.st_mode), "non_directory_ancestor");
    }
}
std::string read_file(const std::string& path, std::size_t cap, uid_t uid, mode_t mode) {
    directory_chain(path);
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    need(fd >= 0, "file_open_failed");
    try {
        struct stat before{}, after{}, named{};
        need(fstat(fd, &before) == 0 && S_ISREG(before.st_mode) && before.st_nlink == 1 &&
             before.st_uid == uid && before.st_gid == uid && (before.st_mode & 07777) == mode &&
             before.st_size >= 0 && static_cast<std::uint64_t>(before.st_size) <= cap, "file_metadata_differs");
        std::string raw(static_cast<std::size_t>(before.st_size), '\0');
        std::size_t used = 0;
        while (used < raw.size()) {
            const ssize_t count = read(fd, raw.data() + used, raw.size() - used);
            if (count < 0 && errno == EINTR) continue;
            need(count > 0, "short_file_read");
            used += static_cast<std::size_t>(count);
        }
        char extra;
        need(read(fd, &extra, 1) == 0 && fstat(fd, &after) == 0 && lstat(path.c_str(), &named) == 0 &&
             stable(before, after) && stable(before, named), "file_changed");
        close(fd);
        return raw;
    } catch (...) { close(fd); throw; }
}
std::string kernel_text(const char* path, std::size_t cap) {
    const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    need(fd >= 0, "kernel_observation_unavailable");
    std::string raw;
    std::array<char, 1024> buffer{};
    while (true) {
        const ssize_t count = read(fd, buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 || raw.size() + static_cast<std::size_t>(count) > cap) {
            close(fd); throw std::runtime_error("kernel_observation_invalid");
        }
        if (count == 0) break;
        raw.append(buffer.data(), static_cast<std::size_t>(count));
    }
    close(fd);
    while (!raw.empty() && (raw.back() == '\n' || raw.back() == '\0')) raw.pop_back();
    return raw;
}
std::string property(const char* name) {
#ifdef __ANDROID__
    char value[PROP_VALUE_MAX]{};
    const int count = __system_property_get(name, value);
    need(count >= 0, "property_observation_failed");
    return std::string(value, static_cast<std::size_t>(count));
#else
    (void)name;
    throw std::runtime_error("android_properties_unavailable");
#endif
}
void no_stop() {
    struct stat info{};
    const std::string stop = std::string(STATE) + "/emergency-stop";
    errno = 0;
    need(lstat(stop.c_str(), &info) < 0 && errno == ENOENT, "owner_stop_or_unknown");
    const auto value = property("sys.trillionnium.owner_open.stop");
    need(value.empty() || value == "0", "owner_stop_requested");
}
void keys(const J& value, std::initializer_list<const char*> expected) {
    need(value.is_object() && value.size() == expected.size(), "object_fields_differ");
    for (const auto* key : expected) need(value.contains(key), "object_field_absent");
}
std::uint64_t unsigned_integer(const J& value) {
    need(value.is_number_integer() && !value.is_boolean() &&
         (value.is_number_unsigned() || value.get<std::int64_t>() >= 0), "integer_type_differs");
    return value.get<std::uint64_t>();
}
std::string string(const J& value) {
    need(value.is_string(), "string_type_differs");
    return value.get<std::string>();
}
J parse(const std::string& raw) {
    std::vector<std::set<std::string>> seen;
    auto callback = [&seen](int depth, J::parse_event_t event, J& value) {
        need(depth <= 32, "json_depth_limit");
        if (event == J::parse_event_t::object_start) seen.emplace_back();
        if (event == J::parse_event_t::key) {
            need(!seen.empty() && seen.back().insert(value.get<std::string>()).second, "duplicate_json_key");
        }
        if (event == J::parse_event_t::object_end) { need(!seen.empty(), "invalid_json_nesting"); seen.pop_back(); }
        return true;
    };
    return J::parse(raw, callback, true, false);
}
struct Plan {
    J value;
    std::string instance, native, gnu, sha;
};
Plan plan_contract(const std::string& raw, const std::string& path, const std::string& expected) {
    need(raw.size() <= MAX_PLAN && hex(expected, 64) && hash_sha256_hex(raw.data(), raw.size()) == expected,
         "plan_hash_differs");
    J value = parse(raw);
    keys(value, {"schema", "instance", "rootfs_python", "files", "stage", "retained_claims_sha256", "launch_config_sha256"});
    need(value["schema"] == "hepta.init-owned-geniex-provider.v1", "plan_schema_differs");
    const auto instance = string(value["instance"]);
    need(hex(instance, 32), "instance_invalid");
    const std::string native = std::string(STATE) + "/phone-local-v150/geniex-candidate-" + instance;
    const std::string gnu = std::string(GNU_STATE) + "/phone-local-v150/geniex-candidate-" + instance;
    need(path == native + "/startup/entry-plan.json", "plan_path_not_selected_instance");
    keys(value["rootfs_python"], {"bytes", "sha256"});
    need(unsigned_integer(value["rootfs_python"]["bytes"]) > 0 &&
         unsigned_integer(value["rootfs_python"]["bytes"]) <= 32 * 1024 * 1024 &&
         hex(string(value["rootfs_python"]["sha256"]), 64), "python_pin_invalid");
    keys(value["stage"], {"st_dev", "st_ino"});
    need(unsigned_integer(value["stage"]["st_ino"]) > 0, "stage_inode_invalid");
    (void)unsigned_integer(value["stage"]["st_dev"]);
    need(hex(string(value["retained_claims_sha256"]), 64) && hex(string(value["launch_config_sha256"]), 64),
         "configuration_pin_invalid");
    need(value["files"].is_object() && value["files"].size() >= 6 && value["files"].size() <= 64,
         "source_pin_count_invalid");
    for (auto it = value["files"].begin(); it != value["files"].end(); ++it) {
        const auto name = it.key();
        const bool source = name.rfind("source/", 0) == 0 && name.size() > 10 &&
            name.substr(name.size() - 3) == ".py" && name.find('/', 7) == std::string::npos;
        const bool fixed = name == "startup/provider_entry.py" || name == "startup/provider-start.json" ||
            name == "local-config-base.json" || name == "geniex-config.json" || name == "ARTIFACT-MANIFEST.json";
        need((source || fixed) && canonical(native + "/" + name), "unapproved_source_path");
        keys(it.value(), {"bytes", "sha256"});
        need(unsigned_integer(it.value()["bytes"]) > 0 && unsigned_integer(it.value()["bytes"]) <= MAX_SOURCE &&
             hex(string(it.value()["sha256"]), 64), "source_pin_invalid");
    }
    for (const auto* required : {"source/daily_phone_local.py", "source/native_backend.py", "source/provider_bridge.py",
                                 "startup/provider_entry.py", "startup/provider-start.json", "geniex-config.json",
                                 "local-config-base.json", "ARTIFACT-MANIFEST.json"})
        need(value["files"].contains(required), "required_source_pin_absent");
    need(value["files"]["startup/provider-start.json"]["sha256"] == value["launch_config_sha256"],
         "launch_pin_disagrees");
    return {std::move(value), instance, native, gnu, expected};
}
struct stat directory(const std::string& path, uid_t uid, mode_t mode) {
    directory_chain(path);
    struct stat info{};
    need(lstat(path.c_str(), &info) == 0 && S_ISDIR(info.st_mode) &&
         info.st_uid == uid && info.st_gid == uid && (info.st_mode & 07777) == mode, "directory_identity_differs");
    return info;
}
bool same_inode(const struct stat& a, const struct stat& b) { return a.st_dev == b.st_dev && a.st_ino == b.st_ino; }
void stage_view(const std::string& path, const J& expected) {
    const auto info = directory(path, 2000, 0700);
    need(static_cast<std::uint64_t>(info.st_dev) == unsigned_integer(expected["st_dev"]) &&
         static_cast<std::uint64_t>(info.st_ino) == unsigned_integer(expected["st_ino"]), "stage_inode_differs");
    std::array<char, 256> label{};
    const ssize_t size = lgetxattr(path.c_str(), "security.selinux", label.data(), label.size());
    need(size > 0 && static_cast<std::size_t>(size) < label.size() &&
         std::string(label.data(), strnlen(label.data(), static_cast<std::size_t>(size))) == STAGE_CONTEXT,
         "stage_label_differs");
}
void mounted_root(const Plan& plan) {
    struct statfs lower{}, state{};
    need(statfs(ROOT, &lower) == 0 && static_cast<unsigned long>(lower.f_type) == 0xe0f5e1e2UL &&
         (lower.f_flags & (ST_RDONLY | ST_NOSUID | ST_NODEV)) == (ST_RDONLY | ST_NOSUID | ST_NODEV),
         "immutable_root_not_verified");
    const auto native_state = directory(STATE, 0, 0700);
    const auto gnu_state = directory(std::string(ROOT) + GNU_STATE, 0, 0700);
    need(same_inode(native_state, gnu_state), "state_bind_inode_differs");
    need(statfs((std::string(ROOT) + GNU_STATE).c_str(), &state) == 0 &&
         (state.f_flags & (ST_NOSUID | ST_NODEV | ST_NOEXEC | ST_RDONLY)) == (ST_NOSUID | ST_NODEV | ST_NOEXEC),
         "state_mount_flags_differ");
    need(same_inode(directory(plan.native, 0, 0700), directory(std::string(ROOT) + plan.gnu, 0, 0700)),
         "candidate_state_mapping_differs");
    stage_view(plan.native + "/stage", plan.value["stage"]);
    stage_view(std::string(ROOT) + plan.gnu + "/stage", plan.value["stage"]);
    stage_view("/data/local/tmp/hepta-geniex-stage-" + plan.instance, plan.value["stage"]);
}
std::string boot_id() {
    const auto value = kernel_text("/proc/sys/kernel/random/boot_id", 64);
    need(value.size() == 36, "kernel_boot_id_invalid");
    std::string compact;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) need(value[i] == '-', "kernel_boot_id_invalid");
        else compact.push_back(value[i]);
    }
    need(hex(compact, 32), "kernel_boot_id_invalid");
    return value;
}
void write_once(const std::string& path, const std::string& raw) {
    const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    need(fd >= 0, "startup_already_reserved_or_unknown");
    std::size_t used = 0;
    while (used < raw.size()) {
        const ssize_t count = write(fd, raw.data() + used, raw.size() - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(fd); throw std::runtime_error("startup_intent_write_failed"); }
        used += static_cast<std::size_t>(count);
    }
    const bool synced = fsync(fd) == 0;
    close(fd);
    need(synced, "startup_intent_sync_failed");
    const auto parent = path.substr(0, path.rfind('/'));
    const int dir = open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    need(dir >= 0, "startup_intent_parent_unavailable");
    const bool dir_synced = fsync(dir) == 0;
    close(dir);
    need(dir_synced, "startup_intent_parent_sync_failed");
}
[[maybe_unused]] void run(const Plan& plan) {
    need(getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0 && getppid() == 1,
         "not_init_owned_root_entry");
    need(kernel_text("/proc/self/attr/current", 256) == CONTEXT, "bootstrap_domain_not_supplied_by_init");
    need(kernel_text("/sys/fs/selinux/enforce", 8) == "1", "selinux_not_enforcing");
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    std::array<__user_cap_data_struct, 2> caps{};
    need(syscall(SYS_capget, &header, caps.data()) == 0, "capability_observation_failed");
    const std::uint64_t effective = caps[0].effective | (static_cast<std::uint64_t>(caps[1].effective) << 32);
    const std::uint64_t permitted = caps[0].permitted | (static_cast<std::uint64_t>(caps[1].permitted) << 32);
    need(effective == CAPS && permitted == CAPS, "provider_capabilities_differ");
    directory(STATE, 0, 0700);
    no_stop();
    need(property("trillionnium.owner_open.ready") == "1" && property("trillionnium.owner_open.mount_ready") == "1",
         "existing_bootstrap_not_ready");
    mounted_root(plan);
    const auto python = read_file(std::string(ROOT) + "/usr/bin/python3", 32 * 1024 * 1024, 0, PYTHON_MODE);
    need(python.size() == unsigned_integer(plan.value["rootfs_python"]["bytes"]) &&
         hash_sha256_hex(python.data(), python.size()) == plan.value["rootfs_python"]["sha256"], "python_pin_differs");
    for (auto it = plan.value["files"].begin(); it != plan.value["files"].end(); ++it) {
        const auto raw = read_file(plan.native + "/" + it.key(), MAX_SOURCE, 0, 0600);
        need(raw.size() == unsigned_integer(it.value()["bytes"]) &&
             hash_sha256_hex(raw.data(), raw.size()) == it.value()["sha256"], "selected_source_pin_differs");
    }
    const auto claims = read_file(std::string(STATE) + "/phone-local-v150/retained-claims.json", MAX_SOURCE, 0, 0600);
    need(hash_sha256_hex(claims.data(), claims.size()) == plan.value["retained_claims_sha256"], "retained_claims_differ");
    directory(plan.native + "/startup-evidence", 0, 0700);
    no_stop();
    J intent = {{"schema", "hepta.geniex-provider-entry-intent.v1"}, {"instance", plan.instance},
        {"entry_plan_sha256", plan.sha}, {"pid", getpid()}, {"ppid", getppid()}, {"context", CONTEXT},
        {"effective_capabilities", effective}, {"permitted_capabilities", permitted},
        {"stage", plan.value["stage"]}, {"state", "validated_exec_intent_not_ready"},
        {"automatic_request_replay", false}, {"native_execution_qualified", false}};
    write_once(plan.native + "/startup-evidence/entry-" + boot_id() + ".json", intent.dump() + "\n");
    no_stop();
    need(chroot(ROOT) == 0 && chdir("/") == 0, "chroot_failed");
    need(clearenv() == 0, "environment_reset_failed");
    for (const auto& pair : std::array<std::pair<const char*, const char*>, 10>{{
             {"LANG", "C.UTF-8"}, {"LC_ALL", "C.UTF-8"}, {"PYTHONHOME", "/usr"},
             {"PYTHONDONTWRITEBYTECODE", "1"}, {"PATH", "/usr/bin:/bin:/usr/libexec/trillionnium"},
             {"PYTHONPATH", "/usr/libexec/trillionnium/owner-open"},
             {"LD_LIBRARY_PATH", "/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu"},
             {"NO_COLOR", "1"}, {"TERM", "dumb"}, {"TMPDIR", "/var/lib/trillionnium/owner-open/tmp"}}})
        need(setenv(pair.first, pair.second, 1) == 0, "environment_set_failed");
    const std::string script = plan.gnu + "/startup/provider_entry.py";
    const std::string config = plan.gnu + "/startup/provider-start.json";
    const std::string digest = string(plan.value["launch_config_sha256"]);
    execl("/usr/bin/python3", "/usr/bin/python3", "-B", script.c_str(), "--config", config.c_str(),
          "--config-sha256", digest.c_str(), static_cast<char*>(nullptr));
    throw std::runtime_error("gnu_provider_entry_exec_failed");
}
}  // namespace

int main(int argc, char** argv) {
    try {
#ifdef HEPTA_ENTRY_HOST_FIXTURE
        // Explicit host parser seam only; this binary cannot activate a service.
        if (argc == 4 && std::strcmp(argv[1], "--python-file-fixture") == 0) {
            const auto raw = read_file(argv[2], 32 * 1024 * 1024, getuid(), PYTHON_MODE);
            need(hex(argv[3], 64) && hash_sha256_hex(raw.data(), raw.size()) == argv[3], "python_pin_differs");
            std::puts("HOST_FILE_IDENTITY_ONLY_NO_CHROOT_NO_SERVICE");
            return 0;
        }
        need(argc == 4 && std::strcmp(argv[1], "--parse-fixture") == 0, "host_fixture_parser_only");
        const auto raw = read_file(argv[2], MAX_PLAN, getuid(), 0600);
        const auto value = parse(raw);
        const auto instance = string(value.at("instance"));
        const auto plan = plan_contract(raw, std::string(STATE) + "/phone-local-v150/geniex-candidate-" + instance +
                                        "/startup/entry-plan.json", argv[3]);
        (void)plan;
        std::puts("HOST_CONTRACT_ONLY_NO_CHROOT_NO_SERVICE");
        return 0;
#else
        need(argc == 5 && std::strcmp(argv[1], "--plan") == 0 && std::strcmp(argv[3], "--sha256") == 0,
             "fixed_entry_arguments_required");
        const auto raw = read_file(argv[2], MAX_PLAN, 0, 0600);
        run(plan_contract(raw, argv[2], argv[4]));
        return 127;
#endif
    } catch (const std::exception& error) {
        std::fprintf(stderr, "HEPTA_GENIEX_ENTRY_HOLD %s errno=%d\n", error.what(), errno);
        return 70;
    }
}
