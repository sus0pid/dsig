#ifndef HSIG_HSIG_TYPES_HPP
#define HSIG_HSIG_TYPES_HPP

#include <array>
#include <chrono>

#include "config.hpp"

namespace dory::hsig {

  enum HashingSchemes { Blake3 = 0, SipHash = 1, Haraka = 2, SHA256 = 3 };
  HashingSchemes constexpr HashingScheme = static_cast<HashingSchemes>(HASHING_SCHEME);
  static_assert(HashingScheme == Blake3 || HashingScheme == SipHash || HashingScheme == Haraka || HashingScheme == SHA256);

  // Configuration
  struct HsigConfig {
    size_t key_size;         // Key size in bytes
    size_t fetch_threshold;  // Receiver threshold for remaining PKs
    size_t fetch_batch_size;  // Number of PKs to fetch when threshold is reached
    std::chrono::milliseconds sender_interval;  // Interval for sender's key generation
  };

  struct Prefix {
    Hash pk_hash;
    Nonce nonce;
  };

  using Seed = std::array<uint8_t, 32>; /*seed for sk generation*/
  using Hash = std::array<uint8_t, 32>;
  using Nonce = std::array<uint8_t, 16>;
  using Secret = std::array<uint8_t, 18>; /*wotsplus sk_i*/
  using SecretHash = Secret;
}
#endif  // HSIG_HSIG_TYPES_HPP
