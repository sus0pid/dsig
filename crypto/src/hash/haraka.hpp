#pragma once

#include <array>

#include <dory/third-party/haraka/haraka.h>
#include <dory/shared/concepts.hpp>

namespace dory::crypto::hash {
// 256-bit output
static constexpr size_t HarakaHashLength = 32;

using HarakaHash = std::array<uint8_t, HarakaHashLength>;
template <typename Hash, typename T, concepts::IsSame<Hash, HarakaHash> = true, concepts::SizeOfIs<T, 32, 64> = true>
static inline HarakaHash haraka(T const &in) {
  HarakaHash hash;
  if constexpr (sizeof(T) == 32) {
    haraka256(reinterpret_cast<unsigned char*>(&hash), reinterpret_cast<unsigned char const*>(&in));
  } else {
    haraka512(reinterpret_cast<unsigned char*>(&hash), reinterpret_cast<unsigned char const*>(&in));
  }
  return hash;
}

using HarakaHash4x = std::array<HarakaHash, 4>;
template <typename Hash, typename T, concepts::IsSame<Hash, HarakaHash4x> = true, concepts::SizeOfIs<T, 32 * 4, 64 * 4> = true>
static inline HarakaHash4x haraka_4x(T const &in) {
  HarakaHash4x hash;
  if constexpr (sizeof(T) == 32 * 4) {
    haraka256_4x(reinterpret_cast<unsigned char*>(hash.data()), reinterpret_cast<unsigned char const*>(&in));
  } else {
    haraka512_4x(reinterpret_cast<unsigned char*>(hash.data()), reinterpret_cast<unsigned char const*>(&in));
  }
  return hash;
}

// 128-bit output
static constexpr size_t HalfHarakaHashLength = 16;
using HalfHarakaHash = std::array<uint8_t, HalfHarakaHashLength>;
template <typename Hash, typename T, concepts::IsSame<Hash, HalfHarakaHash> = true, concepts::SizeOfIs<T, 32, 64> = true>
static inline HalfHarakaHash haraka(T const &in) {
  HalfHarakaHash hash;
  if constexpr (sizeof(T) == 32) {
    half_haraka256(reinterpret_cast<unsigned char*>(&hash), reinterpret_cast<unsigned char const*>(&in));
  } else {
    half_haraka512(reinterpret_cast<unsigned char*>(&hash), reinterpret_cast<unsigned char const*>(&in));
  }
  return hash;
}

using HalfHarakaHash4x = std::array<HalfHarakaHash, 4>;
template <typename Hash, typename T, concepts::IsSame<Hash, HalfHarakaHash4x> = true, concepts::SizeOfIs<T, 32 * 4, 64 * 4> = true>
static inline HalfHarakaHash4x haraka_4x(T const &in) {
  HalfHarakaHash4x hash;
  if constexpr (sizeof(T) == 32 * 4) {
    half_haraka256_4x(reinterpret_cast<unsigned char*>(&hash), reinterpret_cast<unsigned char const*>(&in));
  } else {
    half_haraka512_4x(reinterpret_cast<unsigned char*>(&hash), reinterpret_cast<unsigned char const*>(&in));
  }
  return hash;
}

// 144-bit output
static constexpr size_t HarakaMidLength = 18;
using MidHarakaHash = std::array<uint8_t, HarakaMidLength>;
template <typename Hash, typename T, concepts::IsSame<Hash, MidHarakaHash> = true, concepts::SizeOfIs<T, 32, 64> = true>
static inline MidHarakaHash haraka(T const &in) {
  MidHarakaHash hash;
  if constexpr (sizeof(T) == 32) {
    mid_haraka256(reinterpret_cast<unsigned char*>(&hash), reinterpret_cast<unsigned char const*>(&in));
  } else {
    mid_haraka512(reinterpret_cast<unsigned char*>(&hash), reinterpret_cast<unsigned char const*>(&in));
  }
  return hash;
}

using MidHarakaHash4x = std::array<MidHarakaHash, 4>;
template <typename Hash, typename T, concepts::IsSame<Hash, MidHarakaHash4x> = true, concepts::SizeOfIs<T, 32 * 4, 64 * 4> = true>
static inline MidHarakaHash4x haraka_4x(T const &in) {
  MidHarakaHash4x hash;
  if constexpr (sizeof(T) == 32 * 4) {
    mid_haraka256_4x(reinterpret_cast<unsigned char*>(&hash), reinterpret_cast<unsigned char const*>(&in));
  } else {
    mid_haraka512_4x(reinterpret_cast<unsigned char*>(&hash), reinterpret_cast<unsigned char const*>(&in));
  }
  return hash;
}

}  // namespace dory::crypto::hash