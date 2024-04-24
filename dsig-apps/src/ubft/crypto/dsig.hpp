#pragma once

#include <memory>
#include <cstdint>
#include <stdexcept>

#include <fmt/core.h>

#include <dory/dsig/export/dsig.hpp>

#include "../types.hpp"

namespace dory::ubft {
class DsigCrypto {
 public:
  using Signature = dsig::Signature;

  DsigCrypto(ProcId local_id, bool disabled = false)
      : my_id{local_id}, disabled_{disabled} {
    if (!disabled) dsig = std::make_unique<dory::dsig::DsigLib>(local_id);
  }

  inline Signature sign(uint8_t const *msg,      // NOLINT
                        size_t const msg_len) {  // NOLINT
    if (disabled_) throw std::logic_error("Cannot call sign!");
    Signature sig; // Uninitialized
    dsig->sign(sig, msg, msg_len);
    return sig;
  }

  inline bool verify(Signature const &sig, uint8_t const *msg,
                     size_t const msg_len, int const node_id) {
    if (disabled_) throw std::logic_error("Cannot call verify!");
    if (node_id == my_id) throw std::runtime_error("Attempts to verify its own sig! SHould have been cached.");
    return dsig->verify(sig, msg, msg_len, node_id);
  }

  inline ProcId myId() const { return my_id; }

  bool disabled() const { return disabled_; }

 private:
  ProcId const my_id;
  bool disabled_;
  std::unique_ptr<dory::dsig::DsigLib> dsig;
};
}  // namespace dory::ubft
