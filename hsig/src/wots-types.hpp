#ifndef HSIG_WOTS_TYPES_HPP
#define HSIG_WOTS_TYPES_HPP

#include "hsig-types.hpp"
#include "hsig-config.hpp"
#include "inf-crypto/crypto.hpp"


namespace dory::hsig{

using Seed = std::array<uint8_t, 32>; /*seed for sk generation*/
using Nonce = std::array<uint8_t, 16>;
using Secret = std::array<uint8_t, 18>; /*wotsplus sk_i*/
using SecretHash = Secret;

using InfSignature = typename InfCrypto::Signature;
using BatchedInfSignature = typename InfCrypto::BatchedSignature;

struct Prefix {
  Hash pk_hash;
  Nonce nonce;
};

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


#endif  // HSIG_WOTS_TYPES_HPP
