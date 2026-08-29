#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

namespace {
constexpr std::string_view kAbstractName = "trillionnium_owner_open";
constexpr const char* kUpstream = "/data/trillionnium/owner-open/state/broker/owner-open.sock";
constexpr std::string_view kAllowedPeer = "u:r:trillionnium_owner_open_client:s0";
constexpr int kMaximumConnections = 32;
constexpr int kIdleTimeoutMilliseconds = 300000;
constexpr std::size_t kBufferBytes = 64 * 1024;
std::atomic<int> g_connections{0};
volatile sig_atomic_t g_stop = 0;

int Fail(std::string_view message) {
  std::fprintf(stderr, "owner-open ingress HOLD: %.*s: %s\n",
               static_cast<int>(message.size()), message.data(), std::strerror(errno));
  return 70;
}

void Stop(int) { g_stop = 1; }

bool InstallSignals() {
  struct sigaction action {};
  action.sa_handler = Stop;
  sigemptyset(&action.sa_mask);
  return sigaction(SIGTERM, &action, nullptr) == 0 &&
         sigaction(SIGINT, &action, nullptr) == 0 &&
         signal(SIGPIPE, SIG_IGN) != SIG_ERR;
}

bool AllowedPeer(int fd) {
#ifdef SO_PEERSEC
  std::array<char, 256> security {};
  socklen_t length = security.size();
  if (getsockopt(fd, SOL_SOCKET, SO_PEERSEC, security.data(), &length) != 0 ||
      length == 0 || length > security.size()) {
    return false;
  }
  std::string_view value(security.data(), strnlen(security.data(), length));
  if (value != kAllowedPeer && !value.starts_with(std::string(kAllowedPeer) + ":")) return false;
#endif
  struct ucred credentials {};
  socklen_t size = sizeof(credentials);
  return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) == 0 &&
         size == sizeof(credentials) && credentials.pid > 1 && credentials.uid >= 10000;
}

int ConnectUpstream() {
  const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  struct sockaddr_un address {};
  address.sun_family = AF_UNIX;
  if (std::strlen(kUpstream) >= sizeof(address.sun_path)) {
    close(fd);
    errno = ENAMETOOLONG;
    return -1;
  }
  std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", kUpstream);
  if (connect(fd, reinterpret_cast<struct sockaddr*>(&address), sizeof(address)) != 0) {
    const int saved = errno;
    close(fd);
    errno = saved;
    return -1;
  }
  return fd;
}

bool WriteAll(int fd, const unsigned char* data, std::size_t length) {
  std::size_t offset = 0;
  while (offset < length) {
    const ssize_t count = send(fd, data + offset, length - offset, MSG_NOSIGNAL);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return false;
    offset += static_cast<std::size_t>(count);
  }
  return true;
}

void Pump(int client) {
  const int upstream = ConnectUpstream();
  if (upstream < 0) {
    close(client);
    --g_connections;
    return;
  }
  std::array<unsigned char, kBufferBytes> buffer {};
  bool client_read = true;
  bool upstream_read = true;
  while (client_read || upstream_read) {
    std::array<struct pollfd, 2> descriptors {{
        {client, static_cast<short>(client_read ? POLLIN : 0), 0},
        {upstream, static_cast<short>(upstream_read ? POLLIN : 0), 0},
    }};
    const int ready = poll(descriptors.data(), descriptors.size(), kIdleTimeoutMilliseconds);
    if (ready < 0 && errno == EINTR) continue;
    if (ready <= 0) break;
    for (std::size_t index = 0; index < descriptors.size(); ++index) {
      if ((descriptors[index].revents & (POLLIN | POLLHUP)) == 0) continue;
      const int source = index == 0 ? client : upstream;
      const int destination = index == 0 ? upstream : client;
      const ssize_t count = read(source, buffer.data(), buffer.size());
      if (count < 0 && errno == EINTR) continue;
      if (count <= 0) {
        if (index == 0) client_read = false;
        else upstream_read = false;
        shutdown(destination, SHUT_WR);
        continue;
      }
      if (!WriteAll(destination, buffer.data(), static_cast<std::size_t>(count))) {
        client_read = false;
        upstream_read = false;
        break;
      }
    }
  }
  shutdown(client, SHUT_RDWR);
  shutdown(upstream, SHUT_RDWR);
  close(client);
  close(upstream);
  --g_connections;
}

int Listen() {
  const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  struct sockaddr_un address {};
  address.sun_family = AF_UNIX;
  if (kAbstractName.size() + 1 > sizeof(address.sun_path)) {
    close(fd);
    errno = ENAMETOOLONG;
    return -1;
  }
  address.sun_path[0] = '\0';
  std::memcpy(address.sun_path + 1, kAbstractName.data(), kAbstractName.size());
  const socklen_t length = static_cast<socklen_t>(
      offsetof(struct sockaddr_un, sun_path) + 1 + kAbstractName.size());
  if (bind(fd, reinterpret_cast<struct sockaddr*>(&address), length) != 0 ||
      listen(fd, 32) != 0) {
    const int saved = errno;
    close(fd);
    errno = saved;
    return -1;
  }
  return fd;
}
}  // namespace

int main() {
  if (!InstallSignals()) return Fail("cannot install signal handlers");
  const int listener = Listen();
  if (listener < 0) return Fail("cannot bind Android abstract ingress socket");
  while (!g_stop) {
    const int client = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    if (client < 0 && errno == EINTR) continue;
    if (client < 0) {
      close(listener);
      return Fail("accept failed");
    }
    if (g_connections.load() >= kMaximumConnections || !AllowedPeer(client)) {
      close(client);
      continue;
    }
    ++g_connections;
    try {
      std::thread(Pump, client).detach();
    } catch (...) {
      --g_connections;
      close(client);
    }
  }
  close(listener);
  return 0;
}
