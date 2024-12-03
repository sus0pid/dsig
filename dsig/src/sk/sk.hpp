#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <optional>

#include "../merkle.hpp"
#include "../types.hpp"
#include "../util.hpp"
#include "../workers.hpp"

#include "../hors.hpp"
#include "../wots.hpp"

namespace dory::dsig {

class SecretKey {
  using SecretRow = std::array<Secret, SecretsPerSecretKey>;
  using Secrets = std::array<SecretRow, SecretsDepth>;
public:
  enum State {
    Initializing,
    Initialized,
  };

  SecretKey(Seed const seed, Workers& workers): seed{seed} {
    workers.schedule([this]{ generate(); });
  }

  SecretKey(SecretKey const&) = delete;
  SecretKey& operator=(SecretKey const&) = delete;
  SecretKey(SecretKey&&) = delete;
  SecretKey& operator=(SecretKey&&) = delete;

  template <typename S = Signature, std::enable_if_t<std::is_same_v<S, HorsMerkleSignature>, bool> = true>
  HorsMerkleSignature sign(uint8_t const* msg, size_t const msg_len) const {
    HorsMerkleSignature sig{pk_nonce, pk_sig.value(), nonce};
    sig.roots = hors_pk_tree->roots();
    HorsHash h(pk_hash, nonce, msg, msg + msg_len);
    for (size_t i = 0; i < SecretsPerSignature; i++) {
      auto const secret_index = h.getSecretIndex(i);
      SecretAndNeighborHash const secretAndNeighborHash = {secrets.front()[secret_index], secrets.back()[secret_index ^ 1]};
      sig.secretsAndNeighborsHash.at(i) = secretAndNeighborHash;
      sig.proofs.at(i) = HorsMerkleProof(*hors_pk_tree, secret_index >> 1);
    }
    return sig;
  }

  template <typename S = Signature, std::enable_if_t<std::is_same_v<S, HorsCompletedSignature>, bool> = true>
  HorsCompletedSignature sign(uint8_t const* msg, size_t const msg_len) const {
    HorsCompletedSignature sig{pk_nonce, pk_sig.value(), nonce};
    std::memcpy(sig.fused_secrets.data(), secrets.back().data(), sizeof(sig.fused_secrets));
    HorsHash h(pk_hash, nonce, msg, msg + msg_len);
    for (size_t i = 0; i < SecretsPerSignature; i++) {
      auto const secret_index = h.getSecretIndex(i);
      sig.fused_secrets[secret_index] = secrets.front()[secret_index];
    }
    return sig;
  }

  /*wotsplus signature generation*/
  template <typename S = Signature, std::enable_if_t<std::is_same_v<S, WotsSignature>, bool> = true>
  WotsSignature sign(uint8_t const* msg, size_t const msg_len) const {
    WotsSignature sig{pk_nonce, pk_sig.value(), nonce};
    WotsHash h(pk_hash, nonce, msg, msg + msg_len);
    for (size_t i = 0; i < SecretsPerSignature; i++) {
      auto const secret_depth = h.getSecretDepth(i);
      std::memcpy(sig.secrets[i].data(), secrets[secret_depth][i].data(), sig.secrets[i].size());
    }
    return sig;
  }

  std::atomic<State> state{Initializing};
  std::optional<BatchedInfSignature> pk_sig;

  SecretRow const& getPk() const {
    return secrets.back();
  }

  Hash const& getPkHash() const {
    return pk_hash;
  }

  void prefetch() {
    dsig::prefetch(*this);
    if constexpr (HbssScheme == HorsMerkle) {
      dsig::prefetch(*hors_pk_tree);
    }
  }

private:
  Secrets secrets; /*generate pk*/
  std::unique_ptr<HorsMerkleTree> hors_pk_tree;
  Seed seed;

  Nonce pk_nonce;
  Hash pk_hash;

  Nonce nonce;

  /*generate pks from sks and store the intermediate results*/
  void generate_secrets() {
    secrets.front() = crypto::hash::blake3<SecretRow>(seed);
    for (size_t i = 0; i + 1 < SecretsDepth; i++) {
      if constexpr (HashingScheme == Haraka) {
        // 4x speedup
        auto const speedup_until = SecretsPerSecretKey - SecretsPerSecretKey % 4;
        for (size_t j = 0; j < speedup_until; j += 4) {
          auto& secret_hash_4x = *reinterpret_cast<SecretHash4x*>(&secrets[i + 1][j]);
          auto& secret_4x = *reinterpret_cast<Secret4x*>(&secrets[i][j]);
          secret_hash_4x = hash_secret_haraka_4x(secret_4x, pk_nonce, j, i);
        }
        for (size_t j = speedup_until; j < SecretsPerSecretKey; j++) {
          secrets[i + 1][j] = hash_secret(secrets[i][j], pk_nonce, j, i);
        }
      } else {
        for (size_t j = 0; j < SecretsPerSecretKey; j++) {
          secrets[i + 1][j] = hash_secret(secrets[i][j], pk_nonce, j, i);
        }
      }
    }
  }

  void generate_hors_pk_tree() {
    hors_pk_tree = std::make_unique<HorsMerkleTree>(secrets.back(), true);
  }

  void generate_pk_nonce() {
    pk_nonce = sk_nonce(seed);
  }

  /*hash pk*/
  void generate_pk_hash() {
    auto hasher = crypto::hash::blake3_init();
    crypto::hash::blake3_update(hasher, pk_nonce);
    if constexpr (HbssScheme == HorsMerkle) {
      crypto::hash::blake3_update(hasher, hors_pk_tree->roots());
    } else {
      crypto::hash::blake3_update(hasher, secrets.back()); /*hash the pk*/
    }
    pk_hash = crypto::hash::blake3_final(hasher);
  }

  void generate_nonce() {
    nonce = sig_nonce(seed);
  }

  void generate() {
    generate_pk_nonce();
    generate_secrets();
    if constexpr (HbssScheme == HorsMerkle) {
      generate_hors_pk_tree();
    }
    generate_pk_hash();
    generate_nonce();
    state = Initialized;
  }
};

}