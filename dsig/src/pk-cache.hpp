#pragma once

#include <deque>
#include <memory>
#include <optional>
#include <functional>

#include "config.hpp"
#include "types.hpp"
#include "pk/pk.hpp"

namespace dory::dsig {

// Thread-unsafe: must ensure exclusive access
class PkCache {
  using UniquePks = std::unique_ptr<BgPublicKeys>;
  using OptionalPks = std::optional<std::reference_wrapper<BgPublicKeys>>;
  struct Entry {
    Entry(UniquePks&& pks): pks{std::move(pks)} {}
    size_t accessed{0};
    UniquePks pks;
  };
  std::deque<Entry> deque;
  size_t lookup_start{0};
public:
  size_t size() const { return deque.size(); }

  UniquePks& back() {
    return deque.back().pks;
  }

  void emplaceBack(UniquePks&& pks) {
    if (deque.size() == CachedPkBatchesPerProcess) {
      if (lookup_start > 0) lookup_start--;
      deque.pop_front();
    }
    deque.emplace_back(std::move(pks));
  }

  OptionalPks associatedTo(Signature const &sig) {
    for (size_t i = 0; i < deque.size(); i++) {
      auto& entry = deque.at((lookup_start + i) % deque.size());
      if (entry.pks->associatedTo(sig)) {
        entry.accessed++;
        if (entry.accessed == BgPublicKeys::Size)
          lookup_start++;
        return std::ref(*entry.pks);
      }
    }
    return std::nullopt;
  }

  size_t virgins() const {
    size_t count{0};
    for (auto& entry : deque) {
      if (entry.accessed < BgPublicKeys::Size) {
        count += BgPublicKeys::Size - entry.accessed;
      }
    }
    return count;
  }

  void prefetch() {
    if (deque.empty()) return;
    auto &entry = deque.at(lookup_start % deque.size());
    entry.pks->prefetch();
    if constexpr (HbssScheme == HorsMerkle) {
      if (entry.accessed < BgPublicKeys::Size) {
        entry.pks->prefetch_hors_tree(entry.accessed);
      }
    }
  }
};
}  // namespace dory::dsig
