#ifndef HSIG_HSIG_TYPES_HPP
#define HSIG_HSIG_TYPES_HPP

#include <array>
#include "config.hpp"



namespace hsig {

  enum HashingSchemes { Blake3 = 0, SipHash = 1, Haraka = 2, SHA256 = 3 };
  HashingSchemes constexpr HashingScheme = static_cast<HashingSchemes>(HASHING_SCHEME);
  static_assert(HashingScheme == Blake3 || HashingScheme == SipHash || HashingScheme == Haraka || HashingScheme == SHA256);

  // Configuration
  struct HsigConfig {
    size_t key_size;         // Key size in bytes
    size_t fetch_threshold;  // Receiver threshold for remaining PKs
    size_t fetch_batch_size;  // Number of PKs to fetch when threshold is reached
    std::chrono::milliseconds sender_interval;  // Interval for sender's key generation
//    HashingScheme hash_func; /*wots hash function*/
//    size_t wots_n;    /*hash output in bytes*/
//    size_t wots_w;    /*wots params*/
//    size_t wots_log_w;
//    size_t wots_len1;
//    size_t wots_len2;
//    size_t wots_len;
  };

  using Seed = std::array<uint8_t, 32>; /*seed for sk generation*/
  using Nonce = std::array<uint8_t, 16>;
  using Secret = std::array<uint8_t, 18>; /*wotsplus sk_i*/
  using SecretHash = Secret;
}
#endif  // HSIG_HSIG_TYPES_HPP
