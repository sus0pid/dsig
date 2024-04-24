#pragma once

#include <array>
#include <cstring>

#include <dory/third-party/sha256/sha256.h>
#include <dory/shared/concepts.hpp>

namespace dory::crypto::hash {
// 256-bit output
static constexpr size_t Sha256HashLength = 32;
using Sha256Hash = std::array<uint8_t, Sha256HashLength>;

template <typename Hash = Sha256Hash, typename T, concepts::IsSame<Hash, Sha256Hash> = true, concepts::SizeOfIs<T, 32, 64> = true>
static inline Sha256Hash sha256(T const& in) {
  if constexpr (sizeof(T) == 64) {
    Sha256Hash hash;
    ::sha256(reinterpret_cast<unsigned char*>(&hash), reinterpret_cast<unsigned char const*>(&in));
    return hash;
  } else {
    std::array<uint8_t, 64> padded{};
    std::memcpy(padded.data(), &in, sizeof(in));
    return sha256<Hash>(padded);
  }
}

// 128-bit output
static constexpr size_t HalfSha256HashLength = 16;
using HalfSha256Hash = std::array<uint8_t, HalfSha256HashLength>;

template <typename Hash, typename T, concepts::IsSame<Hash, HalfSha256Hash> = true, concepts::SizeOfIs<T, 32, 64> = true>
static inline HalfSha256Hash sha256(T const& in) {
  auto const full_hash = sha256<Sha256Hash>(in);
  return *reinterpret_cast<HalfSha256Hash const*>(&full_hash);
}

// 144-bit output
static constexpr size_t MidSha256HashLength = 18;
using MidSha256Hash = std::array<uint8_t, MidSha256HashLength>;

template <typename Hash, typename T, concepts::IsSame<Hash, MidSha256Hash> = true, concepts::SizeOfIs<T, 32, 64> = true>
static inline MidSha256Hash sha256(T const& in) {
  auto const full_hash = sha256<Sha256Hash>(in);
  return *reinterpret_cast<MidSha256Hash const*>(&full_hash);
}

}  // namespace dory::crypto::hash