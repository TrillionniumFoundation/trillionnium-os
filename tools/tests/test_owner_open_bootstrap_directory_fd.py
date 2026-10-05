"""Compile the actual directory helper and exercise real filesystem substitutions.

Only fstat's root ownership is simulated so unprivileged source CI can exercise
this boundary. The directory syscalls, descriptor lifetimes and races are real;
these tests do not qualify Android ownership, native packaging or installation.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'android-integration/working-tree/vendor/trillionnium/owner-open/native/owner_open_bootstrap.cpp'

PREFIX = r'''
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
static std::string base;
static std::string scenario;
static int chmod_calls = 0;
static int mkdir_calls = 0;
static bool fired = false;
int TestFstat(int fd, struct stat* value) {
  int result = ::fstat(fd, value);
  if (result == 0) {
    value->st_uid = scenario == "wrong-owner" ? 12345 : 0;
    value->st_gid = 0;
  }
  return result;
}
int TestOpenAt(int fd, const char* name, int flags) {
  if (scenario == "ancestor-race" && !fired && std::strcmp(name, "a") == 0) {
    fired = true;
    if (::rename((base + "/a").c_str(), (base + "/old-a").c_str()) != 0) return -1;
    if (::symlink((base + "/victim").c_str(), (base + "/a").c_str()) != 0) return -1;
  }
  return ::openat(fd, name, flags);
}
int TestMkdirAt(int fd, const char* name, mode_t mode) {
  ++mkdir_calls;
  if (scenario == "creation-race" && std::strcmp(name, "leaf") == 0) {
    if (::symlinkat((base + "/victim").c_str(), fd, name) != 0) return -1;
    errno = EEXIST;
    return -1;
  }
  return ::mkdirat(fd, name, mode);
}
int TestFchmod(int fd, mode_t mode) {
  ++chmod_calls;
  if (scenario == "leaf-race" && !fired) {
    fired = true;
    if (::rename((base + "/leaf").c_str(), (base + "/old-leaf").c_str()) != 0) return -1;
    if (::symlink((base + "/victim").c_str(), (base + "/leaf").c_str()) != 0) return -1;
  }
  return ::fchmod(fd, mode);
}
#define fstat TestFstat
#define openat TestOpenAt
#define mkdirat TestMkdirAt
#define fchmod TestFchmod
'''
SUFFIX = r'''
#undef fstat
#undef openat
#undef mkdirat
#undef fchmod
static int count_fds() {
  DIR* directory = ::opendir("/proc/self/fd");
  if (!directory) return -1;
  int count = 0;
  while (auto* entry = ::readdir(directory)) if (entry->d_name[0] != '.') ++count;
  ::closedir(directory);
  return count;
}
static mode_t mode_of(const std::string& path) {
  struct stat value {};
  if (::stat(path.c_str(), &value) != 0) return 0;
  return value.st_mode & 0777;
}
int main(int argc, char** argv) {
  if (argc != 3) return 90;
  scenario = argv[1]; base = argv[2];
  int root = ::open(base.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (root < 0) return 91;
  int before = count_fds();
  int result = 0;
  if (scenario == "valid") {
    if (!EnsureDirectoryAtRoot(root, "/a/leaf", 0700) || mode_of(base + "/a/leaf") != 0700) result = 1;
  } else if (scenario == "canonical") {
    for (std::string_view path : {"relative", "/", "/new/../leaf", "/new/./leaf", "/new//leaf", "/new/leaf/"})
      if (EnsureDirectoryAtRoot(root, path, 0700)) result = 2;
    if (EnsureDirectoryAtRoot(root, std::string_view("/new\0evil", 9), 0700)) result = 3;
    if (mkdir_calls != 0 || chmod_calls != 0) result = 4;
  } else if (scenario == "leaf-race") {
    if (EnsureDirectoryAtRoot(root, "/leaf", 0700)) result = 5;
    if (mode_of(base + "/victim") != 0755 || mode_of(base + "/old-leaf") != 0700) result = 6;
  } else {
    std::string_view path = scenario == "ancestor-race" ? "/a/leaf" : "/leaf";
    for (int i = 0; i < 200; ++i) if (EnsureDirectoryAtRoot(root, path, 0700)) result = 7;
    if (chmod_calls != 0 || mode_of(base + "/victim") != 0755) result = 8;
  }
  if (count_fds() != before) result = 9;
  ::close(root);
  return result;
}
'''


class OwnerOpenBootstrapDirectoryFdTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('c++')
        if compiler is None:
            raise unittest.SkipTest('native C++ compiler unavailable')
        cls.temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary.name)
        source = SOURCE.read_text()
        start = source.index('class DirectoryDescriptor {')
        end = source.index('\nbool EmergencyStopPresent()', start)
        cls.fragment = source[start:end]
        harness = cls.directory / 'harness.cpp'
        harness.write_text(PREFIX + cls.fragment + SUFFIX)
        cls.binary = cls.directory / 'harness'
        built = subprocess.run([compiler, '-std=c++20', '-Wall', '-Wextra', '-Werror', str(harness), '-o', str(cls.binary)], capture_output=True, text=True, timeout=30)
        if built.returncode:
            cls.temporary.cleanup()
            raise AssertionError(built.stdout + built.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_scenario(self, name):
        with tempfile.TemporaryDirectory(dir=self.directory) as directory:
            root = Path(directory)
            (root / 'victim').mkdir(mode=0o755)
            if name in ('leaf-race', 'wrong-owner'):
                (root / 'leaf').mkdir(mode=0o755)
            elif name == 'ancestor-race':
                (root / 'a').mkdir(mode=0o755)
                (root / 'a/leaf').mkdir(mode=0o755)
            elif name == 'symlink':
                (root / 'leaf').symlink_to(root / 'victim', target_is_directory=True)
            result = subprocess.run([str(self.binary), name, directory], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_creates_private_directories_with_real_fchmod(self):
        self.run_scenario('valid')

    def test_rejects_noncanonical_paths_before_creating_anything(self):
        self.run_scenario('canonical')

    def test_leaf_symlink_is_rejected_without_descriptor_leaks(self):
        self.run_scenario('symlink')

    def test_ancestor_substitution_cannot_follow_symlink(self):
        self.run_scenario('ancestor-race')

    def test_mkdir_creation_race_cannot_follow_substituted_symlink(self):
        self.run_scenario('creation-race')

    def test_leaf_replacement_only_chmods_pinned_inode_and_returns_hold(self):
        self.run_scenario('leaf-race')

    def test_nonroot_final_ownership_is_rejected(self):
        self.run_scenario('wrong-owner')
