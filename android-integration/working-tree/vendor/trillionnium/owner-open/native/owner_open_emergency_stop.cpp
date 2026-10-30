#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include "owner_open_emergency_inhibit.h"

#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif

namespace {
constexpr const char* kState = "/data/trillionnium/owner-open/state";

int Fail(std::string_view message) {
  std::fprintf(stderr, "owner-open emergency stop HOLD: %.*s: %s\n",
               static_cast<int>(message.size()), message.data(), std::strerror(errno));
  return 70;
}

bool WriteMarker() {
  bool created = false;
  return trillionnium::owner_open::EmergencyInhibit(kState, 0, 0).Publish(&created);
}

void ClearReady() {
#ifdef __ANDROID__
  __system_property_set("trillionnium.owner_open.ready", "0");
#endif
}
}  // namespace

int main() {
  // Android init owns the tracked bootstrap service cgroup. Never read a stale
  // numeric PID or signal an unbound PGID from a persistent file.
  ClearReady();
  if (!WriteMarker()) return Fail("cannot durably publish persistent inhibit marker");
  return 0;
}
