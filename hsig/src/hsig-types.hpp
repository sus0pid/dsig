#ifndef HSIG_HSIG_TYPES_HPP
#define HSIG_HSIG_TYPES_HPP

#include <array>
#include <chrono>

#include "hsig-config.hpp"
#include "inf-crypto/crypto.hpp"

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

  using ProcId = int;
  using Seed = std::array<uint8_t, 32>; /*seed for sk generation*/
  using Hash = std::array<uint8_t, 32>;
  using Nonce = std::array<uint8_t, 16>;
  using Secret = std::array<uint8_t, 18>; /*wotsplus sk_i*/
  using SecretHash = Secret;

  using InfSignature = typename InfCrypto::Signature;
  using BatchedInfSignature = typename InfCrypto::BatchedSignature;

  /*common fileds of signature*/
  /*remove batch BatchedInfSignature pk_sig;*/
#define ExtendBase(Signature) \
  Nonce pk_nonce; \
  InfSignature pk_sig; \
  Nonce nonce; \
  Signature() = default; \
  Signature(Nonce const& _pk_nonce, InfSignature const& _pk_sig, Nonce const& _nonce): \
    pk_sig{_pk_sig} { \
    std::memcpy(pk_nonce.data(), _pk_nonce.data(), pk_nonce.size()); \
    std::memcpy(nonce.data(), _nonce.data(), nonce.size()); \
  }\
  bool operator==(const Signature& other) const { \
    return std::memcmp(this, &other, sizeof(Signature)) == 0; \
  }

  // WOTS+
  /*additional fields specific to wots signature*/
  struct __attribute__((__packed__)) WotsSignature {
    static constexpr std::string_view Scheme{"WOTS+"};
    ExtendBase(WotsSignature);
    std::array<Secret, SecretsPerSignature> sig;
  };


}
#endif  // HSIG_HSIG_TYPES_HPP
