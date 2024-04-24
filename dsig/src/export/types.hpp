#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <type_traits>

#include "../inf-crypto/crypto.hpp"
#include "../merkle.hpp"
#include "base-types.hpp"
#include "config.hpp"

namespace dory::dsig {

using ProcId = int;

using InfSignature = typename InfCrypto::Signature;
using BatchedInfSignature = typename InfCrypto::BatchedSignature;

using Seed = std::array<uint8_t, 32>;
using Nonce = std::array<uint8_t, 16>;

template<HbssSchemes> struct SchemeToSecret;
template<> struct SchemeToSecret<HorsMerkle> { using Secret = std::array<uint8_t, 16>; };
template<> struct SchemeToSecret<HorsCompleted> { using Secret = std::array<uint8_t, 16>; };
template<> struct SchemeToSecret<Wots> { using Secret = std::array<uint8_t, 18>; };
using Secret = SchemeToSecret<HbssScheme>::Secret;
using SecretHash = Secret;

#define ExtendBase(Signature) \
  Nonce pk_nonce; \
  BatchedInfSignature pk_sig; \
  Nonce nonce; \
  Signature() = default; \
  Signature(Nonce const& _pk_nonce, BatchedInfSignature const& _pk_sig, Nonce const& _nonce): \
    pk_sig{_pk_sig} { \
    std::memcpy(pk_nonce.data(), _pk_nonce.data(), pk_nonce.size()); \
    std::memcpy(nonce.data(), _nonce.data(), nonce.size()); \
  }\
  bool operator==(const Signature& other) const { \
    return std::memcmp(this, &other, sizeof(Signature)) == 0; \
  }

// HORS Merkle
struct SecretAndNeighborHash {
  Secret secret;
  SecretHash neighborHash;
};
struct HorsMerkleTree: public MerkleTree<hors::LogSecretsPerSecretKey - 1, hors::LogNbRoots> {
  using MT = MerkleTree<hors::LogSecretsPerSecretKey - 1, hors::LogNbRoots>;
  using PublicKey = std::array<SecretHash, SecretsPerSecretKey>;
  static_assert(sizeof(SecretHash) * 2 >= sizeof(MT::Hash));
  HorsMerkleTree(PublicKey const& pk, bool const build=true): MT{*reinterpret_cast<MT::Leaves const*>(&pk), build} {}
};
using HorsMerkleProof = MerkleProof<HorsMerkleTree>;
struct /* __attribute__((__packed__)) */ HorsMerkleSignature {
  static constexpr std::string_view Scheme{"Merkle HORS"};
  ExtendBase(HorsMerkleSignature);
  std::array<SecretAndNeighborHash, SecretsPerSignature> secretsAndNeighborsHash;
  HorsMerkleTree::Roots roots;
  std::array<HorsMerkleProof, SecretsPerSignature> proofs;
};

// HORS Completed
struct __attribute__((__packed__)) HorsCompletedSignature {
  static constexpr std::string_view Scheme{"Completed HORS"};
  ExtendBase(HorsCompletedSignature);
  static_assert(std::is_same_v<Secret, SecretHash>);
  using SecretOrSecretHash = Secret;
  std::array<SecretOrSecretHash, SecretsPerSecretKey> fused_secrets;
};

// WOTS+
struct __attribute__((__packed__)) WotsSignature {
  static constexpr std::string_view Scheme{"WOTS+"};
  ExtendBase(WotsSignature);
  std::array<Secret, SecretsPerSignature> secrets;
};

template<HbssSchemes> struct SchemeToSignature;
template<> struct SchemeToSignature<HorsMerkle> { using Signature = HorsMerkleSignature; };
template<> struct SchemeToSignature<HorsCompleted> { using Signature = HorsCompletedSignature; };
template<> struct SchemeToSignature<Wots> { using Signature = WotsSignature; };
using Signature = SchemeToSignature<HbssScheme>::Signature;

}  // namespace dory::dsig
