#pragma once

#include <array>
#include <vector>

#include <dory/third-party/siphash/siphash.h>
#include <dory/shared/concepts.hpp>

namespace dory::crypto::hash {
static constexpr size_t SipHashLength = 16;

using SipHash = std::array<uint8_t, SipHashLength>;

static inline SipHash siphash(uint8_t const *const begin,
                              uint8_t const *const end,
                              uint8_t const* const key) {
  SipHash hash;
  tp_siphash(begin, end - begin, key, hash.data(), SipHashLength);
  return hash;
}

template <typename ContiguousIt,
          concepts::IsRandomIterator<ContiguousIt> = true>
static inline SipHash siphash(ContiguousIt begin, ContiguousIt end, uint8_t const* const key) {
  return siphash(reinterpret_cast<uint8_t const *const>(&*begin),
                reinterpret_cast<uint8_t const *const>(&*end),
                key);
}

static inline SipHash siphash(std::vector<uint8_t> const &message, uint8_t const* const key) {
  return siphash(message.begin(), message.end(), key);
}

template <typename Hash = SipHash, typename T, concepts::IsTrivial<T> = true, std::enable_if_t<std::is_same_v<Hash, SipHash>, bool> = true>
static inline SipHash siphash(T const &value, uint8_t const* const key) {
  auto const *const begin = reinterpret_cast<uint8_t const *const>(&value);
  return siphash(begin, begin + sizeof(T), key);
}

template <typename Hash, typename T, concepts::IsTrivial<T> = true, std::enable_if_t<!std::is_same_v<Hash, SipHash>, bool> = true>
static inline Hash siphash(T const &value, uint8_t const* const key) {
  throw std::runtime_error("The only valid output is SipHash!");
}

}  // namespace dory::crypto::hash
