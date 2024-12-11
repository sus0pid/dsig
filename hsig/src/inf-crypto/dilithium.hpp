#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <unordered_map>

#include <fmt/core.h>
#include <fmt/ranges.h>

#include <dory/memstore/store.hpp>
#include <dory/shared/logger.hpp>

#include <dory/crypto/asymmetric/dilithium.hpp>

#include "batch.hpp"
#include "../hsig-types.hpp"
#include "../hsig-config.hpp"

namespace dory::hsig {
class DilithiumCrypto {
 public:
  using Signature = std::array<uint8_t, crypto::asymmetric::dilithium::SignatureLength>;
  using BatchedSignature = Batched<Signature>;

  DilithiumCrypto(ProcId local_id, std::vector<ProcId> const &all_ids)
      : my_id{local_id}, store{nspace}, LOGGER_INIT(logger, "Hsig") {
    crypto::asymmetric::dilithium::init();

    LOGGER_INFO(logger, "Publishing my Dilithium key (process {})", my_id);
    crypto::asymmetric::dilithium::publish_pub_key(fmt::format("{}-pubkey", local_id));

    LOGGER_INFO(logger, "Waiting for all processes ({}) to publish their keys",
                all_ids);
    store.barrier("public_keys_announced", all_ids.size());

    for (auto id : all_ids) {
      public_keys.emplace(
          id, crypto::asymmetric::dilithium::get_public_key(fmt::format("{}-pubkey", id)));
    }
  }

  inline Signature sign(uint8_t const *msg,      // NOLINT
                        size_t const msg_len) {  // NOLINT
    Signature sig;
    crypto::asymmetric::dilithium::sign(sig.data(), msg, msg_len);
    return sig;
  }

  inline bool verify(Signature const &sig, uint8_t const *msg,
                     size_t const msg_len, ProcId const node_id) {
    auto pk_it = public_keys.find(node_id);
    if (pk_it == public_keys.end()) {
      throw std::runtime_error(
          fmt::format("Missing public key for {}!", node_id));
    }

    return crypto::asymmetric::dilithium::verify(sig.data(), msg, msg_len, pk_it->second);
  }

  inline bool verify(BatchedSignature const &sig, ProcId const node_id) {
    auto const root = sig.proof.root(sig.signed_hash, sig.index);
    return verify(sig.root_sig, reinterpret_cast<uint8_t const*>(root.data()), sizeof(root), node_id);
  }

  inline ProcId myId() const { return my_id; }

 private:
  ProcId const my_id;
  memstore::MemoryStore store;

  // Map: NodeId (ProcId) -> Node's Public Key
  /*In hsig, this public key should be CA's public key.*/
  std::unordered_map<ProcId, crypto::asymmetric::dilithium::pub_key> public_keys;
  LOGGER_DECL(logger);
};

}  // namespace dory::dsig
