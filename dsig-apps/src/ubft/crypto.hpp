#pragma once

#include <memory>
#include <cstdint>
#include <stdexcept>
#include <unordered_map>

#include "crypto/dalek.hpp"
#include "crypto/free.hpp"
#include "crypto/large.hpp"
#include "crypto/dsig.hpp"
#include "crypto/sodium.hpp"

#define CRYPTO_SCHEME_Dalek 0
#define CRYPTO_SCHEME_Sodium 1
#define CRYPTO_SCHEME_Dsig 2
#define CRYPTO_SCHEME_Large 3
#define CRYPTO_SCHEME_Free 4

namespace dory::ubft {

// By default, behaves like Dalek
class Crypto {
 public:
  DalekCrypto dalek;
  SodiumCrypto sodium;
  DsigCrypto dsig;
  LargeCrypto large;
  FreeCrypto free;

  using Signature = DalekCrypto::Signature;

  Crypto(ProcId local_id, std::vector<ProcId> const &all_ids,
         bool disabled = false)
      : dalek{local_id, all_ids}, sodium{local_id, all_ids}, dsig{local_id} { }

  inline Signature sign(uint8_t const *msg,      // NOLINT
                        size_t const msg_len) {  // NOLINT
    return dalek.sign(msg, msg_len);
  }

  inline bool verify(Signature const &sig, uint8_t const *msg,
                     size_t const msg_len, int const node_id) {
    return dalek.verify(sig, msg, msg_len, node_id);
  }

  inline ProcId myId() const { return dalek.myId(); }

  bool disabled() const { return dalek.disabled(); }

  // Structs used for templates
  struct Dalek {
    using Signature = dory::ubft::DalekCrypto::Signature;
    static DalekCrypto& crypto(Crypto& crypto) { return crypto.dalek; }
  };

  struct Sodium {
    using Signature = dory::ubft::SodiumCrypto::Signature;
    static SodiumCrypto& crypto(Crypto& crypto) { return crypto.sodium; }
  };

  struct Dsig {
    using Signature = dory::ubft::DsigCrypto::Signature;
    static DsigCrypto& crypto(Crypto& crypto) { return crypto.dsig; }
  };

  struct Large {
    using Signature = dory::ubft::LargeCrypto::Signature;
    static LargeCrypto& crypto(Crypto& crypto) { return crypto.large; }
  };

  struct Free {
    using Signature = dory::ubft::FreeCrypto::Signature;
    static FreeCrypto& crypto(Crypto& crypto) { return crypto.free; }
  };
};
}  // namespace dory::ubft
