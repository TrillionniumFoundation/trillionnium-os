#pragma once
#include <string_view>

namespace trillionnium::owner_open {
// SO_PEERSEC is supplied by the kernel. Check its complete app identity and
// canonical Android MCS categories, without relying on unexported libselinux
// context_* helpers or accepting adjacent/prefix-matching domain names.
inline bool AllowedPeerContext(std::string_view value) {
  constexpr std::string_view base = "u:r:trillionnium_owner_open_client:s0";
  if (value == base) return true;
  if (value.size() > 255 || !value.starts_with(base) || value.size() <= base.size() + 1 ||
      value[base.size()] != ':') return false;
  value.remove_prefix(base.size() + 1);
  auto category = [](std::string_view* source, unsigned* number) {
    if (source->empty() || source->front() != 'c') return false;
    source->remove_prefix(1);
    if (source->empty() || source->front() < '0' || source->front() > '9') return false;
    unsigned parsed = 0;
    unsigned digits = 0;
    while (!source->empty() && source->front() >= '0' && source->front() <= '9') {
      if (++digits > 4) return false;
      parsed = parsed * 10 + static_cast<unsigned>(source->front() - '0');
      source->remove_prefix(1);
    }
    if (parsed > 1023) return false;
    *number = parsed;
    return true;
  };
  while (!value.empty()) {
    unsigned first = 0;
    if (!category(&value, &first)) return false;
    if (!value.empty() && value.front() == '.') {
      value.remove_prefix(1);
      unsigned last = 0;
      if (!category(&value, &last) || last < first) return false;
    }
    if (value.empty()) return true;
    if (value.front() != ',') return false;
    value.remove_prefix(1);
    if (value.empty()) return false;
  }
  return false;
}
}  // namespace trillionnium::owner_open
