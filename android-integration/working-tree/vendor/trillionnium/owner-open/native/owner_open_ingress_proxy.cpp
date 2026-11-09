#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <cstdint>
#include <limits>
#include <poll.h>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

#include <json/json.h>
#include <selinux/selinux.h>
#include "owner_open_peer_identity.h"
#include "owner_open_emergency_inhibit.h"
#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif

namespace {
constexpr std::string_view kAbstractName = "trillionnium_owner_open";
constexpr const char* kUpstream = "/data/trillionnium/owner-open/state/broker/owner-open.sock";
constexpr const char* kToken = "/data/trillionnium/owner-open/state/broker/owner-open.token";
constexpr std::string_view kWireSchema = "org.trillionnium.owner-open.connection-broker-wire.v1";
constexpr const char* kState = "/data/trillionnium/owner-open/state";
constexpr std::string_view kControlSchema = "org.trillionnium.owner-open.ingress-control.v1";
constexpr std::size_t kMaximumControlBytes = 4096;
constexpr int kMaximumPendingControls = 64;
std::atomic<int> g_pending_controls{0};
std::mutex g_admission;
std::atomic<bool> g_inhibited{false};
std::mutex g_stop_attempts_mutex;
std::mutex g_inhibit_publication;
std::set<std::string> g_stop_attempts;
constexpr std::size_t kMaximumStopAttempts = 4096;
constexpr std::string_view kBrokerId = "owner-open-device";
constexpr int kMaximumConnections = 32;
// Handshake bytes are control-plane authentication, not an unbounded stream.
// Keep one absolute deadline across connect, hello write and ack read so a
// peer that drips one byte at a time cannot pin a connection slot forever.
constexpr int kHandshakeTimeoutMilliseconds = 5000;
constexpr int kIdleTimeoutMilliseconds = 300000;
constexpr std::size_t kMaximumLineBytes = 1024 * 1024;
constexpr std::size_t kBufferBytes = 64 * 1024;
std::atomic<int> g_connections{0};
std::atomic<unsigned long long> g_client_sequence{1};
volatile sig_atomic_t g_stop = 0;

bool TryAcquireConnection() {
  int current = g_connections.load(std::memory_order_relaxed);
  while (current < kMaximumConnections &&
         !g_connections.compare_exchange_weak(current, current + 1,
                                               std::memory_order_acquire,
                                               std::memory_order_relaxed)) {
  }
  return current < kMaximumConnections;
}

bool TryAcquireControlSlot() {
  int current = g_pending_controls.load();
  while (current < kMaximumPendingControls &&
         !g_pending_controls.compare_exchange_weak(current, current + 1)) {}
  return current < kMaximumPendingControls;
}

void ReleaseConnection() {
  g_connections.fetch_sub(1, std::memory_order_release);
}

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

bool ReadPeerCredentials(int fd, struct ucred* output) {
  if (output == nullptr) return false;
  struct ucred credentials {};
  socklen_t size = sizeof(credentials);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) != 0 ||
      size != sizeof(credentials) || credentials.pid <= 1) {
    return false;
  }
  *output = credentials;
  return true;
}

bool AllowedPeer(int fd, struct ucred* output) {
  // getpeercon handles the kernel's non-NUL-terminated SO_PEERSEC shape.
  // Compare the dedicated app identity, retaining kernel-validated MCS user
  // categories instead of requiring the impossible literal app range s0.
  char* security = nullptr;
  if (getpeercon(fd, &security) != 0 || security == nullptr) return false;
  const bool admitted = trillionnium::owner_open::AllowedPeerContext(security);
  freecon(security);
  if (!admitted) return false;
  struct ucred credentials {};
  if (!ReadPeerCredentials(fd, &credentials) || credentials.uid < 10000) {
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

using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;

bool WaitForIo(int fd, short events, Deadline deadline) {
  while (true) {
    const auto now = Clock::now();
    if (now >= deadline) {
      errno = ETIMEDOUT;
      return false;
    }
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    const auto bounded = std::clamp<std::int64_t>(remaining.count(), 1, std::numeric_limits<int>::max());
    struct pollfd descriptor { fd, events, 0 };
    const int result = poll(&descriptor, 1, static_cast<int>(bounded));
    if (result < 0 && errno == EINTR) continue;
    if (result <= 0) {
      if (result == 0) errno = ETIMEDOUT;
      return false;
    }
    if ((descriptor.revents & (events | POLLERR | POLLHUP | POLLNVAL)) == 0) continue;
    if ((descriptor.revents & (events | POLLERR | POLLHUP)) == 0) {
      errno = EBADF;
      return false;
    }
    return true;
  }
}

int ConnectUpstream(Deadline deadline) {
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
  const int original_flags = fcntl(fd, F_GETFL, 0);
  if (original_flags < 0 || fcntl(fd, F_SETFL, original_flags | O_NONBLOCK) != 0) {
    const int saved = errno;
    close(fd);
    errno = saved;
    return -1;
  }
  const int connect_result = connect(fd, reinterpret_cast<struct sockaddr*>(&address), sizeof(address));
  if (connect_result != 0 && errno != EINPROGRESS) {
    const int saved = errno;
    close(fd);
    errno = saved;
    return -1;
  }
  if (connect_result != 0 && !WaitForIo(fd, POLLOUT, deadline)) {
    const int saved = errno;
    close(fd);
    errno = saved;
    return -1;
  }
  int socket_error = 0;
  socklen_t socket_error_size = sizeof(socket_error);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_size) != 0 ||
      socket_error != 0) {
    const int saved = socket_error != 0 ? socket_error : errno;
    close(fd);
    errno = saved;
    return -1;
  }
  if (fcntl(fd, F_SETFL, original_flags) != 0) {
    const int saved = errno;
    close(fd);
    errno = saved;
    return -1;
  }
  return fd;
}

bool WriteAll(int fd, const unsigned char* data, std::size_t length, Deadline deadline) {
  std::size_t offset = 0;
  while (offset < length) {
    const ssize_t count = send(fd, data + offset, length - offset, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      if (!WaitForIo(fd, POLLOUT, deadline)) return false;
      continue;
    }
    if (count <= 0) return false;
    offset += static_cast<std::size_t>(count);
  }
  return true;
}

bool ReadLine(int fd, std::string* output, Deadline deadline,
              std::size_t limit = kMaximumLineBytes) {
  output->clear();
  output->reserve(4096);
  // The bound covers the complete wire line, including its trailing newline.
  // Stop before reading byte max+1 so an unterminated/oversized frame cannot
  // grow the string beyond the advertised limit.
  while (output->size() < limit) {
    if (!WaitForIo(fd, POLLIN, deadline)) return false;
    unsigned char current = 0;
    const ssize_t count = recv(fd, &current, 1, MSG_DONTWAIT);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
    if (count <= 0) return false;
    if (current == 0) return false;
    output->push_back(static_cast<char>(current));
    if (current == '\n') return output->size() > 1;
  }
  errno = EMSGSIZE;
  return false;
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
  return reader->parse(raw.data(), raw.data() + raw.size(), value, &errors) && value->isObject();
}

bool IsLowerHex(std::string_view value, std::size_t expected_size) {
  if (value.size() != expected_size) return false;
  for (char current : value) {
    if (!((current >= '0' && current <= '9') || (current >= 'a' && current <= 'f'))) return false;
  }
  return true;
}

bool IsHexDigest(std::string_view value) { return IsLowerHex(value, 64); }

bool JsonString(const Json::Value& object, const char* key, std::string* value) {
  const Json::Value& candidate = object[key];
  if (!candidate.isString()) return false;
  *value = candidate.asString();
  return !value->empty() && value->find('\0') == std::string::npos;
}

bool JsonInteger(const Json::Value& object, const char* key, std::int64_t expected) {
  const Json::Value& candidate = object[key];
  if (candidate.type() == Json::intValue) return candidate.asInt64() == expected;
  if (candidate.type() == Json::uintValue && expected >= 0) {
    return candidate.asUInt64() == static_cast<std::uint64_t>(expected);
  }
  return false;
}

bool ValidateHelloAck(std::string_view raw, std::string_view expected_client_id,
                      const struct ucred& ingress_peer) {
  Json::Value ack;
  std::string schema;
  std::string kind;
  if (!ParseJsonObject(raw, &ack) || !JsonString(ack, "schema", &schema) ||
      schema != kWireSchema || !JsonString(ack, "kind", &kind) ||
      kind != "broker.hello.ack" || !ack["automatic_redispatch"].isBool() ||
      ack["automatic_redispatch"].asBool()) {
    return false;
  }
  std::string broker_id;
  std::string client_id;
  std::string broker_epoch;
  std::string token_epoch;
  std::string descriptor_digest;
  if (!JsonString(ack, "broker_id", &broker_id) || broker_id != kBrokerId ||
      !JsonString(ack, "client_id", &client_id) || client_id != expected_client_id ||
      !JsonString(ack, "broker_epoch", &broker_epoch) ||
      !JsonString(ack, "token_epoch", &token_epoch) ||
      !JsonString(ack, "descriptor_sha256", &descriptor_digest) ||
      !IsLowerHex(broker_epoch, 32) || !IsLowerHex(token_epoch, 32) ||
      !IsHexDigest(descriptor_digest) || !ack["host_hello_ack"].isObject()) {
    return false;
  }
  const Json::Value& host_ack = ack["host_hello_ack"];
  std::string host_kind;
  if (!JsonString(host_ack, "kind", &host_kind) || host_kind != "hello.ack" ||
      !host_ack["payload"].isObject()) {
    return false;
  }
  const Json::Value& acknowledged_peer = ack["peer"];
  return acknowledged_peer.isObject() &&
         JsonInteger(acknowledged_peer, "pid", ingress_peer.pid) &&
         JsonInteger(acknowledged_peer, "uid", ingress_peer.uid) &&
         JsonInteger(acknowledged_peer, "gid", ingress_peer.gid);
}

std::string BrokerHello(const struct ucred& peer, std::string_view token,
                        std::string* client_id_output) {
  const unsigned long long sequence = g_client_sequence.fetch_add(1);
  std::array<char, 256> client_id_buffer {};
  const int client_id_count = std::snprintf(
      client_id_buffer.data(), client_id_buffer.size(), "android.%u.%d.%llu",
      static_cast<unsigned int>(peer.uid), peer.pid, sequence);
  if (client_id_count <= 0 || static_cast<std::size_t>(client_id_count) >= client_id_buffer.size()) {
    return {};
  }
  *client_id_output = std::string(client_id_buffer.data(), static_cast<std::size_t>(client_id_count));
  std::array<char, 1024> encoded {};
  const int count = std::snprintf(
      encoded.data(), encoded.size(),
      "{\"client_id\":\"%s\",\"kind\":\"broker.hello\",\"token\":\"%.*s\"}\n",
      client_id_output->c_str(),
      static_cast<int>(token.size()), token.data());
  if (count <= 0 || static_cast<std::size_t>(count) >= encoded.size()) return {};
  return std::string(encoded.data(), static_cast<std::size_t>(count));
}

bool AuthenticateUpstream(int client, int upstream, const struct ucred& peer, Deadline deadline) {
  std::string token;
  if (!ReadBrokerToken(&token)) return false;
  // SO_PEERCRED is directional.  On this connected client socket it reports
  // the broker (the server), while the broker's acknowledgement `peer` reports
  // this root ingress process (the broker's client).  Validate both identities
  // independently; comparing the acknowledgement with the Android peer or
  // with this socket's broker peer would reject every valid handshake.
  struct ucred broker_peer {};
  if (!ReadPeerCredentials(upstream, &broker_peer) || broker_peer.uid != 0) return false;
  struct ucred ingress_peer {
      getpid(),
      geteuid(),
      getegid(),
  };
  std::string expected_client_id;
  const std::string hello = BrokerHello(peer, token, &expected_client_id);
  token.assign(token.size(), '\0');
  if (hello.empty() ||
      !WriteAll(upstream, reinterpret_cast<const unsigned char*>(hello.data()), hello.size(),
                deadline)) {
    return false;
  }
  std::string response;
  if (!ReadLine(upstream, &response, deadline)) return false;
  // Do not forward any upstream bytes until the first frame is a strict,
  // identity-bound broker acknowledgement.  This prevents a malformed or
  // stale broker response from being mistaken for an authenticated session.
  if (!ValidateHelloAck(response, expected_client_id, ingress_peer)) return false;
  return WriteAll(client, reinterpret_cast<const unsigned char*>(response.data()), response.size(),
                  deadline);
}

enum class ControlKind { Connect, Stop, Status };
struct ControlRequest { ControlKind kind; std::string operation_id; };

bool ParseControl(std::string_view raw, ControlRequest* request) {
  Json::Value frame;
  std::string schema, kind, operation;
  if (raw.size() > kMaximumControlBytes || !ParseJsonObject(raw, &frame) ||
      !JsonString(frame, "schema", &schema) || schema != kControlSchema ||
      !JsonInteger(frame, "version", 1) || !JsonString(frame, "kind", &kind)) return false;
  if (kind == "ingress.connect") {
    if (frame.size() != 3) return false;
    *request = {ControlKind::Connect, {}};
    return true;
  }
  if (!JsonString(frame, "operation_id", &operation) || operation.empty() || operation.size() > 96) return false;
  for (char c : operation) {
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
  }
  if (kind == "emergency.status" && frame.size() == 4) {
    *request = {ControlKind::Status, operation};
    return true;
  }
  if (kind == "emergency.stop" && frame.size() == 5 &&
      frame["explicit_user"].isBool() && frame["explicit_user"].asBool()) {
    *request = {ControlKind::Stop, operation};
    return true;
  }
  return false;
}

bool RequestInitStop() {
#ifdef __ANDROID__
  return __system_property_set("sys.trillionnium.owner_open.stop", "1") == 0;
#else
  errno = ENOTSUP;
  return false;  // Host compilation cannot claim Android init cancellation.
#endif
}

bool NormalAdmissionAllowed(const trillionnium::owner_open::EmergencyInhibit& inhibit) {
  // Filesystem/property observation must stay outside the short send fence.
  // Every leaf and every unreadable state fail closed.
#ifdef __ANDROID__
  char ready[PROP_VALUE_MAX] {};
  if (__system_property_get("trillionnium.owner_open.ready", ready) != 1 || ready[0] != '1')
    return false;
#endif
  return !g_inhibited && inhibit.Observe() ==
      trillionnium::owner_open::InhibitObservation::Absent;
}

std::string ControlReply(const ControlRequest& request,
                         const trillionnium::owner_open::EmergencyInhibit& inhibit,
                         bool (*request_stop)()) {
  bool durable = false, stop_requested = false;
  std::string attempt = "status_only";
  if (request.kind == ControlKind::Stop) {
    {
      std::lock_guard<std::mutex> fence(g_admission);
      g_inhibited = true;  // No filesystem I/O can delay this send fence.
    }
    {
      std::lock_guard<std::mutex> dedup(g_stop_attempts_mutex);
      if (g_stop_attempts.count(request.operation_id) != 0) {
        attempt = "duplicate_in_this_ingress_process";
      } else if (g_stop_attempts.size() >= kMaximumStopAttempts) {
        attempt = "capacity_refused";  // Never evict accepted IDs to admit a retry.
      } else {
        g_stop_attempts.insert(request.operation_id);
        attempt = "submitted";
        // A present marker does not prove init cancellation ever succeeded.
        // A new explicit user operation may request mechanical stop again.
        stop_requested = request_stop();
      }
    }
    {
      std::lock_guard<std::mutex> publication(g_inhibit_publication);
      bool created = false;
      durable = inhibit.Publish(&created);
    }
  }
  const auto observed = inhibit.Observe();
  const char* state = observed == trillionnium::owner_open::InhibitObservation::Absent ?
      "absent" : observed == trillionnium::owner_open::InhibitObservation::Present ?
      "present" : "unknown";
  Json::Value response(Json::objectValue);
  response["schema"] = std::string(kControlSchema);
  response["version"] = 1;
  response["kind"] = "emergency.result";
  response["operation_id"] = request.operation_id;
  response["inhibit_observation"] = state;
  response["durable_inhibit_confirmed"] = durable;
  response["dispatch_inhibited"] = g_inhibited || observed !=
      trillionnium::owner_open::InhibitObservation::Absent;
  response["request_attempt"] = attempt;
  response["stop_requested"] = stop_requested;
  response["process_quiescence"] = "unknown";
  response["prior_effect_outcome"] = "unknown";
  response["automatic_redispatch"] = false;
  Json::StreamWriterBuilder writer;
  writer["indentation"] = "";
  return Json::writeString(writer, response) + "\n";
}

bool WriteAdmitted(int fd, const unsigned char* data, std::size_t length,
                   Deadline deadline, const trillionnium::owner_open::EmergencyInhibit& inhibit) {
  std::size_t offset = 0;
  while (offset < length) {
    if (!NormalAdmissionAllowed(inhibit)) return false;
    ssize_t count;
    {
      std::lock_guard<std::mutex> fence(g_admission);
      if (g_inhibited) return false;
      // Never hold the emergency fence while waiting for a wedged broker.
      count = send(fd, data + offset, length - offset, MSG_NOSIGNAL | MSG_DONTWAIT);
    }
    if (count < 0 && errno == EINTR) continue;
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      if (!WaitForIo(fd, POLLOUT, std::min(deadline, Clock::now() +
             std::chrono::milliseconds(100)))) return false;
      continue;
    }
    if (count <= 0) return false;
    offset += static_cast<std::size_t>(count);
  }
  return true;
}

void Pump(int client, struct ucred peer) {
  const Deadline handshake_deadline =
      Clock::now() + std::chrono::milliseconds(kHandshakeTimeoutMilliseconds);
  std::string first;
  ControlRequest request {};
  const trillionnium::owner_open::EmergencyInhibit inhibit(kState, 0, 0);
  bool normal_reserved = false;
  int upstream = -1;
  if (!ReadLine(client, &first, handshake_deadline, kMaximumControlBytes) ||
      !ParseControl(first, &request)) goto cleanup;
  if (request.kind != ControlKind::Connect) {
    const std::string reply = ControlReply(request, inhibit, RequestInitStop);
    WriteAll(client, reinterpret_cast<const unsigned char*>(reply.data()), reply.size(),
             handshake_deadline);
    goto cleanup;
  }
  if (!NormalAdmissionAllowed(inhibit)) goto cleanup;
  {
    std::lock_guard<std::mutex> fence(g_admission);
    if (g_inhibited || !TryAcquireConnection()) goto cleanup;
    normal_reserved = true;
  }
  // Reserve control capacity independently from long-lived ordinary sessions.
  g_pending_controls.fetch_sub(1);
  upstream = ConnectUpstream(handshake_deadline);
  if (upstream < 0 || !AuthenticateUpstream(client, upstream, peer, handshake_deadline))
    goto cleanup;
  {
    std::array<unsigned char, kBufferBytes> buffer {};
    bool client_read = true, upstream_read = true;
    auto last_activity = Clock::now();
    while (client_read || upstream_read) {
      if (!NormalAdmissionAllowed(inhibit)) break;
      if (Clock::now() - last_activity >= std::chrono::milliseconds(kIdleTimeoutMilliseconds)) break;
      std::array<struct pollfd, 2> descriptors {{{client, static_cast<short>(client_read ? POLLIN : 0), 0},
          {upstream, static_cast<short>(upstream_read ? POLLIN : 0), 0}}};
      const int ready = poll(descriptors.data(), descriptors.size(), 100);
      if (ready < 0 && errno == EINTR) continue;
      if (ready < 0) break;
      if (ready == 0) continue;
      last_activity = Clock::now();
      for (std::size_t index = 0; index < descriptors.size(); ++index) {
        if ((descriptors[index].revents & (POLLIN | POLLHUP)) == 0) continue;
        const int source = index == 0 ? client : upstream;
        const int destination = index == 0 ? upstream : client;
        const ssize_t count = read(source, buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
          if (index == 0) client_read = false; else upstream_read = false;
          shutdown(destination, SHUT_WR);
          continue;
        }
        if (!WriteAdmitted(destination, buffer.data(), static_cast<std::size_t>(count),
              Clock::now() + std::chrono::milliseconds(kIdleTimeoutMilliseconds), inhibit)) {
          client_read = false; upstream_read = false; break;
        }
      }
    }
  }
cleanup:
  shutdown(client, SHUT_RDWR);
  close(client);
  if (upstream >= 0) { shutdown(upstream, SHUT_RDWR); close(upstream); }
  if (normal_reserved) ReleaseConnection(); else g_pending_controls.fetch_sub(1);
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
    if (!AllowedPeer(client, &peer) || !TryAcquireControlSlot()) {
      close(client);
      continue;
    }
    try {
      std::thread(Pump, client, peer).detach();
    } catch (...) {
      g_pending_controls.fetch_sub(1);
      close(client);
    }
  }
  close(listener);
  return 0;
}
