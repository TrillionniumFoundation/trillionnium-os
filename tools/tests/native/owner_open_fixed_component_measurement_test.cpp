// Actual host filesystem/descriptor behavior; no Android property server or phone.
#ifndef OWNER_OPEN_BOOTSTRAP_SOURCE
#define OWNER_OPEN_BOOTSTRAP_SOURCE "../../../android-integration/working-tree/vendor/trillionnium/owner-open/native/owner_open_bootstrap.cpp"
#endif
#include <unistd.h>
#include <cstddef>
#include <cstdlib>
static int mutation_read_fd = -1, mutation_write_fd = -1;
static ssize_t FixtureRead(int fd, void* bytes, std::size_t maximum) {
  const ssize_t result = ::read(fd, bytes, maximum);
  if (fd == mutation_read_fd && result > 0 && mutation_write_fd >= 0) {
    // Deterministic real file change between production fstat snapshots.
    if (ftruncate(mutation_write_fd, 4) != 0) std::abort();
    mutation_read_fd = -1;
  }
  return result;
}
#define read FixtureRead
#define main owner_open_bootstrap_entrypoint
#include OWNER_OPEN_BOOTSTRAP_SOURCE
#undef main
#undef read
#include <filesystem>
#include <fstream>
#include <map>

namespace fs = std::filesystem;
static unsigned checks = 0;
static void Require(bool value, const char* label) {
  if (!value) { std::fprintf(stderr, "FAIL %s errno=%d\n", label, errno); std::exit(1); }
  ++checks;
}
static std::vector<std::pair<std::string, std::string>> writes;
static std::map<std::string, std::string> properties;
static int fail_at = -1;
static bool Setter(const char* name, const char* value) {
  writes.emplace_back(name, value);
  if (static_cast<int>(writes.size()) - 1 == fail_at) return false;
  properties[name] = value;
  return true;
}
static void ResetSetter(int failure = -1) {
  writes.clear(); properties.clear(); fail_at = failure;
  properties["trillionnium.owner_open.measurement.valid"] = "1";
  for (const char* name : kMeasurementDigestProperties) properties[name] = std::string(64, 'a');
}
static void WriteFile(const fs::path& path, std::string_view contents = "abc") {
  fs::create_directories(path.parent_path());
  const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  Require(fd >= 0, "create actual fixture file");
  Require(write(fd, contents.data(), contents.size()) == static_cast<ssize_t>(contents.size()), "write actual fixture bytes");
  Require(fchmod(fd, 0644) == 0 && close(fd) == 0, "close actual fixture file");
}
static void Fixture(const fs::path& root) {
  fs::remove_all(root); fs::create_directories(root); fs::permissions(root, fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec | fs::perms::others_read | fs::perms::others_exec);
  for (const auto& component : kFixedComponents) WriteFile(root / component.relative_path);
  // The host's umask may create group-writable parents. Model the immutable
  // Android directory modes explicitly; the production refusal is unchanged.
  for (const auto& entry : fs::recursive_directory_iterator(root))
    if (entry.is_directory()) Require(chmod(entry.path().c_str(), 0755) == 0, "fixture immutable parent mode");
}
static bool Collect(const fs::path& root) {
  const int fd = open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  FixedMeasurements measured;
  const bool result = CollectFixedComponentMeasurements(fd, &measured);
  close(fd); return result;
}
int main(int argc, char** argv) {
  if (argc != 3) return 2;
  std::ifstream profile_stream(argv[2]);
  const std::string profile_raw((std::istreambuf_iterator<char>(profile_stream)), std::istreambuf_iterator<char>());
  Json::Value profile;
  Require(ParseJsonObject(profile_raw, &profile), "parse actual checked-in JSON profile");
  const Json::Value valid_contract = profile["component_measurement"];
  Require(ValidateComponentMeasurementProfile(valid_contract), "actual native validator accepts fixed profile");
  for (unsigned scenario = 0; scenario < 9; ++scenario) {
    Json::Value wrong = valid_contract;
    switch (scenario) {
      case 0: wrong["additional_components"][0]["relative_path"] = "etc/secret"; break;
      case 1: wrong["additional_components"][0]["property"] = "arbitrary.property"; break;
      case 2: wrong["additional_components"][0]["maximum_bytes"] = true; break;
      case 3: wrong["additional_components"][0]["maximum_bytes"] = 1048577; break;
      case 4: wrong["additional_components"].append(wrong["additional_components"][0]); break;
      case 5: wrong["fixed_root"] = "/data"; break;
      case 6: wrong["core_digest_properties"][0] = "arbitrary.property"; break;
      case 7: wrong["unknown_field"] = true; break;
      case 8: wrong["component_count"] = true; break;
    }
    Require(!ValidateComponentMeasurementProfile(wrong), "actual native profile drift refusal");
  }
  const fs::path root = fs::path(argv[1]) / "fixed-components";
  Fixture(root);
  const int root_fd = open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  Require(root_fd >= 0, "open actual fixture root");
  {
    FixedMeasurements measured;
    Require(CollectFixedComponentMeasurements(root_fd, &measured), "all five actual fixed paths collected");
    for (const auto& digest : measured.digests) Require(digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "actual SHA256 abc");
    Require(OpenFixedComponent(root_fd, 5) < 0, "unknown component index rejected");
    const fs::path leaf = root / kFixedComponents[0].relative_path;
    fs::rename(leaf, leaf.string() + ".retained"); WriteFile(leaf);
    Require(!FixedComponentDescriptorsStillMatch(root_fd, measured), "identical bytes new inode rejected while original fds held");
  }
  close(root_fd);
  for (std::size_t index = 0; index < kFixedComponents.size(); ++index) {
    Fixture(root); const fs::path leaf = root / kFixedComponents[index].relative_path;
    fs::remove(leaf); Require(!Collect(root), "each missing component refuses collection");
    Fixture(root); fs::remove(leaf); fs::create_symlink(root / kFixedComponents[(index + 1) % 5].relative_path, leaf);
    Require(!Collect(root), "each symlink leaf refused");
    Fixture(root); fs::create_hard_link(leaf, leaf.string() + ".alias");
    Require(!Collect(root), "each multiply-linked leaf refused");
    Fixture(root); Require(chmod(leaf.c_str(), 0664) == 0, "make group writable fixture");
    Require(!Collect(root), "each group writable leaf refused");
    Fixture(root); WriteFile(leaf, ""); Require(!Collect(root), "each empty component refused");
    Fixture(root); const int fd = open(leaf.c_str(), O_WRONLY | O_CLOEXEC);
    Require(fd >= 0 && ftruncate(fd, kFixedComponents[index].maximum_bytes + 1) == 0 && close(fd) == 0, "create sparse above bound");
    Require(!Collect(root), "each oversized component refused before read");
    Fixture(root); fs::remove(leaf); Require(mkfifo(leaf.c_str(), 0600) == 0, "create real fifo");
    Require(!Collect(root), "each FIFO refused without blocking open");
  }
  Fixture(root); fs::rename(root / "etc", root / "etc-original"); fs::create_directory_symlink(root / "etc-original", root / "etc");
  Require(!Collect(root), "symlink parent rejected");
  Fixture(root); Require(chmod((root / "etc").c_str(), 0775) == 0, "make writable parent");
  Require(!Collect(root), "writable parent rejected");
  Fixture(root); Require(chmod(root.c_str(), 0775) == 0, "make writable fixed root");
  Require(!Collect(root), "writable fixed root rejected");
  Fixture(root); Require(chmod((root / "bin").c_str(), 0751) == 0, "actual native bin directory mode fixture");
  Require(Collect(root), "safe 0751 parent accepted without gid-zero assumption");
  Fixture(root);
  const int stable_root = open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  {
    FixedMeasurements measured;
    Require(CollectFixedComponentMeasurements(stable_root, &measured), "collect held descriptors before mutation");
    Require(chmod((root / kFixedComponents[3].relative_path).c_str(), 0600) == 0, "actual leaf metadata mutation");
    Require(!FixedComponentDescriptorsStillMatch(stable_root, measured), "metadata mutation refused before valid publication");
  }
  close(stable_root);
  Fixture(root);
  const fs::path race_leaf = root / kFixedComponents[0].relative_path;
  mutation_read_fd = open(race_leaf.c_str(), O_RDONLY | O_CLOEXEC);
  mutation_write_fd = open(race_leaf.c_str(), O_WRONLY | O_CLOEXEC);
  Require(mutation_read_fd >= 0 && mutation_write_fd >= 0, "open actual mutation descriptors");
  std::string race_digest; std::size_t race_bytes = 0; struct stat race_metadata {};
  const int reading = mutation_read_fd;
  Require(!HashRegularDescriptor(reading, 1048576, &race_digest, &race_bytes, &race_metadata), "actual file mutation during descriptor read refused");
  close(reading); close(mutation_write_fd); mutation_write_fd = -1;
  for (int failure = -1; failure < 9; ++failure) {
    ResetSetter(failure);
    const bool clear = ClearComponentMeasurement(Setter);
    Require(clear == (failure < 0), "each clear failure refuses admission");
    Require(writes.size() == 9, "all eight digests attempted even after clear failure");
    Require(writes.front() == std::make_pair(std::string("trillionnium.owner_open.measurement.valid"), std::string("0")), "valid zero always first");
    Require(std::none_of(writes.begin(), writes.end(), [](const auto& row) { return row.first == "trillionnium.owner_open.measurement.valid" && row.second == "1"; }), "clear never publishes valid one");
  }
  std::array<std::string, 8> digests; digests.fill(std::string(64, 'b'));
  for (int failure = -1; failure < 8; ++failure) {
    ResetSetter(); Require(ClearComponentMeasurement(Setter), "clear before property fixture");
    writes.clear(); fail_at = failure;
    Require(PublishMeasurementDigests(digests, Setter) == (failure < 0), "each publication failure refuses completion");
    Require(properties["trillionnium.owner_open.measurement.valid"] == "0", "digest publisher never marks collection valid");
    Require(std::none_of(writes.begin(), writes.end(), [](const auto& row) { return row.first == "trillionnium.owner_open.measurement.valid" && row.second == "1"; }), "failed property path never publishes valid one");
  }
  for (std::size_t index = 0; index < digests.size(); ++index) {
    auto bad = digests; bad[index] = "not-a-digest"; ResetSetter();
    Require(!PublishMeasurementDigests(bad, Setter), "each malformed digest refuses publication");
    Require(properties["trillionnium.owner_open.measurement.valid"] == "0", "malformed digest clears validity");
  }
  fs::remove_all(root);
  std::printf("actual_host_descriptor_property_checks=%u\nphone_operations=0\nandroid_property_server_tested=0\n", checks);
  return 0;
}
