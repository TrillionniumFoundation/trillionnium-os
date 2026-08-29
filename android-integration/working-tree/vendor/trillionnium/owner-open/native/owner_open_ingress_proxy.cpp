#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

namespace {
constexpr std::string_view kAbstractName = "trillionnium_owner_open";
constexpr const char* kUpstream = "/data/trillionnium/owner-open/state/broker/owner-open.sock";
constexpr const char* kToken = "/data/trillionnium/owner-open/state/broker/owner-open.token";
constexpr std::string_view kAllowedPeer = "u:r:trillionnium_owner_open_client:s0";
constexpr std::string_view kAckMarker = "\"kind\":\"broker.hello.ack\"";
constexpr int kMaximumConnections = 32;
constexpr int kIdleTimeoutMilliseconds = 300000;
constexpr std::size_t kMaximumLineBytes = 1024 * 1024;
constexpr std::size_t kBufferBytes = 64 * 1024;
std::atomic<int> g_connections{0};
std::atomic<unsigned long long> g_client_sequence{1};
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

bool AllowedPeer(int fd, struct ucred* output) {
#ifdef SO_PEERSEC
  std::array<char, 256> security {};
  socklen_t length = security.size();
  if (getsockopt(fd, SOL_SOCKET, SO_PEERSEC, security.data(), &length) != 0 ||
      length == 0 || length > security.size()) {
    return false;
  }
  const std::string_view value(security.data(), strnlen(security.data(), length));
  if (value != kAllowedPeer && !value.starts_with(std::string(kAllowedPeer) + ":")) return false;
#endif
  struct ucred credentials {};
  socklen_t size = sizeof(credentials);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) != 0 ||
      size != sizeof(credentials) || credentials.pid <= 1 || credentials.uid < 10000) {
    return false;
  }
  *output = credentials;
  return true;
}

bool IsHex(char value) {
  return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
}

bool ReadBrokerToken(std::string* output) {
  const int fd = open(kToken, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  struct stat before {};
  std::array<char, 65> raw {};
  bool ok = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) && before.st_uid == 0 &&
            before.st_nlink == 1 && (before.st_mode & 0777) == 0600 && before.st_size == 65;
  std::size_t offset = 0;
  while (ok && offset < raw.size()) {
    const ssize_t count = read(fd, raw.data() + offset, raw.size() - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) {
      ok = false;
      break;
    }
    offset += static_cast<std::size_t>(count);
  }
  struct stat after {};
  ok = ok && fstat(fd, &after) == 0 && offset == raw.size() && raw.back() == '\n' &&
       before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
       before.st_mode == after.st_mode && before.st_uid == after.st_uid &&
       before.st_gid == after.st_gid && before.st_nlink == after.st_nlink &&
       before.st_size == after.st_size && before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
       before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
       before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
       before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
  const int saved = errno;
  close(fd);
  errno = saved;
  if (!ok) return false;
  for (std::size_t index = 0; index < 64; ++index) {
    if (!IsHex(raw[index])) return false;
  }
  output->assign(raw.data(), 64);
  return true;
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

bool WriteAll(int fd, std::string_view value) {
  return WriteAll(fd, reinterpret_cast<const unsigned char*>(value.data()), value.size());
}

bool ReadLine(int fd, std::string* output) {
  output->clear();
  output->reserve(4096);
  while (output->size() <= kMaximumLineBytes) {
    unsigned char current = 0;
    const ssize_t count = recv(fd, &current, 1, 0);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return false;
    if (current == 0) return false;
    output->push_back(static_cast<char>(current));
    if (current == '\n') return output->size() > 1;
  }
  errno = EMSGSIZE;
  return false;
}

std::string BrokerHello(const struct ucred& peer, std::string_view token) {
  const unsigned long long sequence = g_client_sequence.fetch_add(1);
  std::array<char, 1024> encoded {};
  const int count = std::snprintf(
      encoded.data(), encoded.size(),
      "{\"client_id\":\"android.%u.%d.%llu\",\"kind\":\"broker.hello\",\"token\":\"%.*s\"}\n",
      static_cast<unsigned int>(peer.uid), peer.pid, sequence,
      static_cast<int>(token.size()), token.data());
  if (count <= 0 || static_cast<std::size_t>(count) >= encoded.size()) return {};
  return std::string(encoded.data(), static_cast<std::size_t>(count));
}

bool AuthenticateUpstream(int client, int upstream, const struct ucred& peer) {
  std::string token;
  if (!ReadBrokerToken(&token)) return false;
  const std::string hello = BrokerHello(peer, token);
  token.assign(token.size(), '\0');
  if (hello.empty() || !WriteAll(upstream, hello)) return false;
  std::string response;
  if (!ReadLine(upstream, &response)) return false;
  // The upstream broker is the sole trusted JSON producer here. It already
  // performs duplicate-key and schema validation; the ingress only proves the
  // first bounded frame is the broker acknowledgement before enabling relay.
  const bool acknowledged = response.find(kAckMarker) != std::string::npos;
  if (!WriteAll(client, response)) return false;
  return acknowledged;
}

void Pump(int client, struct ucred peer) {
  const int upstream = ConnectUpstream();
  if (upstream < 0 || !AuthenticateUpstream(client, upstream, peer)) {
    if (upstream >= 0) close(upstream);
    shutdown(client, SHUT_RDWR);
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
  if (geteuid() != 0) {
    errno = EPERM;
    return Fail("credential-terminating ingress must run as root");
  }
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
    struct ucred peer {};
    if (g_connections.load() >= kMaximumConnections || !AllowedPeer(client, &peer)) {
      close(client);
      continue;
    }
    ++g_connections;
    try {
      std::thread(Pump, client, peer).detach();
    } catch (...) {
      --g_connections;
      close(client);
    }
  }
  close(listener);
  return 0;
}
