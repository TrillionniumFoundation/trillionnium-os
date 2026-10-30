// Native behavioral checks; uses the production descriptor hashing code.
#ifndef OWNER_OPEN_BOOTSTRAP_SOURCE
#define OWNER_OPEN_BOOTSTRAP_SOURCE "../../../android-integration/working-tree/vendor/trillionnium/owner-open/native/owner_open_bootstrap.cpp"
#endif
#define main owner_open_bootstrap_entrypoint
#include OWNER_OPEN_BOOTSTRAP_SOURCE
#undef main

int main(int argc, char** argv) {
  if (argc != 3) return 2;
  std::string pattern = std::string(argv[1]) + "/measurement-fixture-XXXXXX";
  std::vector<char> path(pattern.begin(), pattern.end());
  path.push_back('\0');
  const int fd = mkstemp(path.data());
  if (fd < 0) return 3;
  bool passed = write(fd, "abc", 3) == 3 && fchmod(fd, 0600) == 0;
  std::string digest;
  std::size_t bytes = 0;
  struct stat metadata {};
  passed = passed && HashRegularDescriptor(fd, 3, &digest, &bytes, &metadata) && bytes == 3 &&
      digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  passed = passed && !HashRegularDescriptor(fd, 2, &digest, &bytes, &metadata);
  passed = passed && fchmod(fd, 0620) == 0 &&
      !HashRegularDescriptor(fd, 3, &digest, &bytes, &metadata);
  passed = passed && fchmod(fd, 0600) == 0;
  const std::string alias = std::string(path.data()) + "-alias";
  passed = passed && link(path.data(), alias.c_str()) == 0 &&
      !HashRegularDescriptor(fd, 3, &digest, &bytes, &metadata);
  unlink(alias.c_str());
  passed = passed && !HashExecutingBootstrap(path.data(), &digest);
  std::string executing_digest;
  passed = passed && HashExecutingBootstrap(argv[2], &executing_digest) &&
      IsHexDigest(executing_digest);
  const std::string self_alias = std::string(path.data()) + "-self-alias";
  passed = passed && symlink(argv[2], self_alias.c_str()) == 0 &&
      !HashExecutingBootstrap(self_alias.c_str(), &digest);
  unlink(self_alias.c_str());
  close(fd);
  unlink(path.data());
  if (!passed) return 4;
  std::printf("behavioral_checks=7\nexecuting_sha256=%s\n", executing_digest.c_str());
  return 0;
}
