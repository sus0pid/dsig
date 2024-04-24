#pragma once

#include <memory>
#include <cstdint>
#include <stdexcept>
#include <unordered_map>

#include <fmt/core.h>

#include <dory/crypto/asymmetric/dalek.hpp>
#define EddsaDalekImpl dory::crypto::asymmetric::dalek
#include <dory/memstore/store.hpp>

#include "../types.hpp"

namespace dory::ubft {

class DalekCrypto {
 public:
  using Signature = std::array<uint8_t, EddsaDalekImpl::SignatureLength>;

  DalekCrypto(ProcId local_id, std::vector<ProcId> const &all_ids,
         bool disabled = false)
      : my_id{local_id}, disabled_{disabled} {
    if (!disabled) {
      auto &store = dory::memstore::MemoryStore::getInstance();
      EddsaDalekImpl::init();
      EddsaDalekImpl::publish_pub_key(fmt::format("dalek-{}-pubkey", local_id));
      store.barrier("dalek_public_keys_announced", all_ids.size());

      for (auto id : all_ids) {
        public_keys.emplace(
            id, EddsaDalekImpl::get_public_key(fmt::format("dalek-{}-pubkey", id)));
      }
    }
  }

  // WARNING: THIS IS NOT THREAD SAFE
  void fetchPublicKey(ProcId const id) {
    public_keys.emplace(
        id, EddsaDalekImpl::get_public_key(fmt::format("dalek-{}-pubkey", id)));
  }

  inline Signature sign(uint8_t const *msg,      // NOLINT
                        size_t const msg_len) {  // NOLINT
    if (disabled_) {
      throw std::logic_error("Cannot call sign!");
    }

    Signature sig;
    EddsaDalekImpl::sign(sig.data(), msg, msg_len);
    return sig;
  }

  inline bool verify(Signature const &sig, uint8_t const *msg,
                     size_t const msg_len, int const node_id) {
    if (disabled_) {
      throw std::logic_error("Cannot call verify!");
    }

    auto pk_it = public_keys.find(node_id);
    if (pk_it == public_keys.end()) {
      throw std::runtime_error(
          fmt::format("Missing public key for {}!", node_id));
    }

    return EddsaDalekImpl::verify(sig.data(), msg, msg_len, pk_it->second);
  }

  inline ProcId myId() const { return my_id; }

  bool disabled() const { return disabled_; }

 private:
  ProcId const my_id;
  bool disabled_;
  // Map: NodeId (ProcId) -> Node's Public Key
  std::unordered_map<ProcId, EddsaDalekImpl::pub_key> public_keys;
};

}  // namespace dory::ubft
