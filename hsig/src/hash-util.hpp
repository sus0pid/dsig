#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include <xxhash.h>
#include <fmt/core.h>

#include <dory/crypto/hash/blake3.hpp>
#include <dory/crypto/hash/sha256.hpp>
#include <dory/crypto/hash/siphash.hpp>
#include <dory/crypto/hash/haraka.hpp>

#include "hsig-types.hpp"

namespace hsig {
template <typename Duration>
static void busy_sleep(Duration duration) {
  auto const start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start < duration)
    ;
}

template <typename T>
void prefetch(T const& t) {
  static size_t constexpr CacheLineSize{64};
  for (size_t offset = 0; offset < sizeof(T); offset += CacheLineSize) {
    volatile auto load = *(reinterpret_cast<uint8_t const*>(&t) + offset);
  }
}

// Blake3
struct SaltedBlake3Secret {
  Nonce nonce;
  Secret secret;
  uint32_t suffix;
};

template <HashingSchemes hs = HashingScheme, std::enable_if_t<hs == Blake3, bool> = true>
static SecretHash hash_secret(Secret const& secret, Nonce const& nonce, size_t const index, size_t const depth = 0) {
  SaltedBlake3Secret to_hash {nonce, secret, static_cast<uint32_t>(index + SecretsPerSecretKey * depth)};
  return crypto::hash::blake3<SecretHash>(to_hash);
}

// SHA256
union PaddedSaltedSha256Secret {
  std::array<uint8_t, 64> padding;
  struct SaltedSha256Secret {
    Nonce nonce;
    Secret secret;
  } salted_secret;
};

static thread_local PaddedSaltedSha256Secret cached_sha256_secret { 0 };
template <HashingSchemes hs = HashingScheme, std::enable_if_t<hs == SHA256, bool> = true>
static SecretHash hash_secret(Secret const& secret, Nonce const& nonce, size_t const index, size_t const depth = 0) {
  auto& [cached_nonce, cached_secret] = cached_sha256_secret.salted_secret;
  cached_nonce = nonce;
  *reinterpret_cast<uint32_t*>(&cached_nonce) += static_cast<uint32_t>(index + SecretsPerSecretKey * depth);
  cached_secret = secret;
  return crypto::hash::sha256<SecretHash>(cached_sha256_secret);
}

// Haraka
union PaddedSaltedHarakaSecret {
  std::array<uint8_t, 64> padding;
  struct SaltedHarakaSecret {
    Nonce nonce;
    Secret secret;
  } salted_secret;
};

static thread_local PaddedSaltedHarakaSecret cached_haraka_secret { 0 };
template <HashingSchemes hs = HashingScheme, std::enable_if_t<hs == Haraka, bool> = true>
static SecretHash hash_secret(Secret const& secret, Nonce const& nonce, size_t const index, size_t const depth = 0) {
  auto& [cached_nonce, cached_secret] = cached_haraka_secret.salted_secret;
  cached_nonce = nonce;
  *reinterpret_cast<uint32_t*>(&cached_nonce) += static_cast<uint32_t>(index + SecretsPerSecretKey * depth);
  cached_secret = secret;
  return crypto::hash::haraka<SecretHash>(cached_haraka_secret);
}

using Secret4x = std::array<Secret, 4>;
using SecretHash4x = std::array<SecretHash, 4>;
static thread_local std::array<PaddedSaltedHarakaSecret, 4> cached_haraka_secrets { 0 };
static SecretHash4x hash_secret_haraka_4x(Secret4x const& secrets, Nonce const& nonce, size_t const index, size_t const depth = 0) {
  for (size_t i = 0; i < 4; i++) {
    auto& [cached_nonce, cached_secret] = cached_haraka_secrets.at(i).salted_secret;
    cached_nonce = nonce;
    *reinterpret_cast<uint32_t*>(&cached_nonce) += static_cast<uint32_t>(index + i + SecretsPerSecretKey * depth);
    cached_secret = secrets.at(i);
  }
  return crypto::hash::haraka_4x<SecretHash4x>(cached_haraka_secrets);
}

// SipHash
struct SuffixedNonce {
  Nonce nonce;
  uint32_t suffix;
};

template <HashingSchemes hs = HashingScheme, std::enable_if_t<hs == SipHash, bool> = true>
static SecretHash hash_secret(Secret const& secret, Nonce const& nonce, size_t const index, size_t const depth = 0) {
  SuffixedNonce msg {nonce, static_cast<uint32_t>(index + SecretsPerSecretKey * depth)};
  return crypto::hash::siphash<SecretHash>(msg, secret.data());
}

static Nonce sk_nonce(Seed const& seed) {
  auto hasher = crypto::hash::blake3_init();
  crypto::hash::blake3_update(hasher, 0x5EED);
  crypto::hash::blake3_update(hasher, seed);
  return crypto::hash::blake3_final<Nonce>(hasher);
}

static Nonce sig_nonce(Seed const& seed) {
  auto hasher = crypto::hash::blake3_init();
  crypto::hash::blake3_update(hasher, 0xC0CA);
  crypto::hash::blake3_update(hasher, seed);
  return crypto::hash::blake3_final<Nonce>(hasher);
}

static Hash full_hash(SecretHash const& secret_hash) {
  Hash hash;
  memcpy(hash.data(), secret_hash.data(), sizeof(SecretHash));
  memset(hash.data() + sizeof(SecretHash), 0, sizeof(Hash) - sizeof(SecretHash));
  return hash;
}

template <size_t DestSize, typename T, size_t SrcSize>
std::array<uint8_t, DestSize> pad(std::array<T, SrcSize> const& src) {
  std::array<T, DestSize> dst{};
  std::copy(src.begin(), src.end(), dst.begin());
  return dst;
}
}  // namespace dory::dsig

