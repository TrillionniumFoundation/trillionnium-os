"""Execute the production ingress thread-start helper with Android-style flags.

The POSIX threads and descriptor cleanup are real. Failure hooks control thread
setup/allocation; Pump is a native fixture rather than authenticated Android I/O.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'android-integration/working-tree/vendor/trillionnium/owner-open/native/owner_open_ingress_proxy.cpp'
PREFIX = r'''
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <new>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
static const char* scenario = "";
static std::atomic<void*> context_address{nullptr};
static std::atomic<int> live_contexts{0};
static std::atomic<int> pump_calls{0};
static std::atomic<int> complete{0};
static int attr_destroy_calls = 0;
static int expected_client = -1;
constexpr int kMaximumConnections = 32;
std::atomic<int> g_connections{0};
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
  if (std::strcmp(scenario, "allocation") == 0) return nullptr;
  void* value = std::malloc(size);
  if (value) { context_address.store(value); live_contexts.fetch_add(1); }
  return value;
}
void operator delete(void* value) noexcept {
  if (value && value == context_address.load()) live_contexts.fetch_sub(1);
  std::free(value);
}
void operator delete(void* value, std::size_t) noexcept { ::operator delete(value); }
int TestAttrInit(pthread_attr_t* attributes) {
  if (std::strcmp(scenario, "init") == 0) return EAGAIN;
  return ::pthread_attr_init(attributes);
}
int TestAttrSet(pthread_attr_t* attributes, int state) {
  if (state != PTHREAD_CREATE_DETACHED) return EINVAL;
  if (std::strcmp(scenario, "detachstate") == 0) return EINVAL;
  return ::pthread_attr_setdetachstate(attributes, state);
}
int TestCreate(pthread_t* thread, const pthread_attr_t* attributes, void* (*entry)(void*), void* argument) {
  if (std::strcmp(scenario, "create") == 0) return EAGAIN;
  return ::pthread_create(thread, attributes, entry, argument);
}
int TestAttrDestroy(pthread_attr_t* attributes) {
  ++attr_destroy_calls;
  int result = ::pthread_attr_destroy(attributes);
  return std::strcmp(scenario, "destroy") == 0 ? EINVAL : result;
}
#define pthread_attr_init TestAttrInit
#define pthread_attr_setdetachstate TestAttrSet
#define pthread_create TestCreate
#define pthread_attr_destroy TestAttrDestroy
'''
PUMP = r'''
void Pump(int client, struct ucred peer) {
  if (client != expected_client || peer.pid != 77 || peer.uid != 1000 || peer.gid != 1001 || ::fcntl(client, F_GETFD) < 0) {
    complete.store(-1); return;
  }
  pump_calls.fetch_add(1);
  ::close(client);
  ReleaseConnection();
  complete.store(1);
}
'''
SUFFIX = r'''
#undef pthread_attr_init
#undef pthread_attr_setdetachstate
#undef pthread_create
#undef pthread_attr_destroy
int count_fds() {
  DIR* directory = ::opendir("/proc/self/fd");
  if (!directory) return -1;
  int count = 0;
  while (auto* entry = ::readdir(directory)) if (entry->d_name[0] != '.') ++count;
  ::closedir(directory); return count;
}
int main(int argc, char** argv) {
  if (argc != 2) return 90;
  scenario = argv[1];
  int before = count_fds();
  int fds[2]; if (::pipe(fds) != 0) return 91;
  expected_client = fds[0];
  if (!TryAcquireConnection()) return 92;
  struct ucred peer {77, 1000, 1001};
  StartPump(expected_client, peer);
  const bool success = std::strcmp(scenario,"success")==0 || std::strcmp(scenario,"destroy")==0;
  if (success) {
    for (int i=0; i<5000 && complete.load()==0; ++i) ::usleep(1000);
    if (complete.load()!=1 || pump_calls.load()!=1) return 1;
  } else if (pump_calls.load()!=0) return 2;
  if (g_connections.load()!=0 || live_contexts.load()!=0) return 3;
  if (::fcntl(expected_client,F_GETFD)!=-1 || errno!=EBADF) return 4;
  const int expected_destroy = std::strcmp(scenario,"allocation")==0 || std::strcmp(scenario,"init")==0 ? 0 : 1;
  if (attr_destroy_calls!=expected_destroy) return 5;
  ::close(fds[1]);
  if (count_fds()!=before) return 6;
  return 0;
}
'''


class OwnerOpenIngressThreadStartTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('c++')
        if compiler is None:
            raise unittest.SkipTest('native C++ compiler unavailable')
        cls.temporary = tempfile.TemporaryDirectory()
        root = Path(cls.temporary.name)
        source = SOURCE.read_text()
        admission = source[source.index('bool TryAcquireConnection() {'):source.index('\nint Fail(')]
        helper = source[source.index('struct ConnectionContext {'):source.index('\nint Listen() {')]
        harness = root / 'harness.cpp'
        harness.write_text(PREFIX + admission + PUMP + helper + SUFFIX)
        cls.binary = root / 'harness'
        built = subprocess.run([compiler,'-std=c++20','-fno-exceptions','-Wall','-Wextra','-Werror','-pthread',str(harness),'-o',str(cls.binary)],capture_output=True,text=True,timeout=30)
        if built.returncode:
            cls.temporary.cleanup()
            raise AssertionError(built.stdout+built.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def scenario(self, name):
        result = subprocess.run([str(self.binary),name],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_context_allocation_failure_returns_slot_and_closes_client(self):
        self.scenario('allocation')

    def test_attribute_init_failure_returns_slot_and_closes_client(self):
        self.scenario('init')

    def test_detached_state_failure_releases_attributes_slot_and_client(self):
        self.scenario('detachstate')

    def test_create_failure_releases_attributes_context_slot_and_client(self):
        self.scenario('create')

    def test_real_detached_thread_preserves_client_and_peer_then_cleans_up(self):
        self.scenario('success')

    def test_postcreation_attribute_destroy_error_does_not_revoke_live_worker(self):
        self.scenario('destroy')
