#pragma once

#include <array>
#include <cstdint>

#include <dory/dsig/export/dsig.hpp>

#include "../types.hpp"

namespace dory::ubft {

class LargeCrypto {
 public:
  using Signature = std::array<uint8_t, sizeof(dsig::Signature)>;

  LargeCrypto() = default;

  inline Signature sign(uint8_t const *msg,      // NOLINT
                        size_t const msg_len) {  // NOLINT
    Signature sig = {};
    // auto &eddsa_sig = *reinterpret_cast<DalekCrypto::Signature*>(sig.data());
    // eddsa_sig = eddsa.sign(msg, msg_len);
    return sig;
  }

  inline bool verify(Signature const &sig, uint8_t const *msg,
                     size_t const msg_len, int const node_id) {
    return true;
    // auto const& eddsa_sig = *reinterpret_cast<DalekCrypto::Signature const*>(sig.data());
    // return eddsa.verify(eddsa_sig, msg, msg_len, node_id);
  }
};
}  // namespace dory::ubft
