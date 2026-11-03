#include "owner_open_peer_identity.h"
#include <cassert>
#include <string>
int main() {
  using trillionnium::owner_open::AllowedPeerContext;
  assert(AllowedPeerContext("u:r:trillionnium_owner_open_client:s0"));
  assert(AllowedPeerContext("u:r:trillionnium_owner_open_client:s0:c512,c768"));
  assert(AllowedPeerContext("u:r:trillionnium_owner_open_client:s0:c0.c1023"));
  for (const auto* value : {"u:r:untrusted_app:s0:c512,c768", "u:r:trillionnium_owner_open_client_extra:s0",
      "u:r:trillionnium_owner_open_client:s0_extra", "x:r:trillionnium_owner_open_client:s0",
      "u:x:trillionnium_owner_open_client:s0", "u:r:trillionnium_owner_open_client:s1",
      "u:r:trillionnium_owner_open_client:s0:", "u:r:trillionnium_owner_open_client:s0:c1024",
      "u:r:trillionnium_owner_open_client:s0:c2.c1", "u:r:trillionnium_owner_open_client:s0:c0,",
      "u:r:trillionnium_owner_open_client:s0:c0:evil"}) assert(!AllowedPeerContext(value));
  assert(!AllowedPeerContext(std::string(256, 'c')));
}
