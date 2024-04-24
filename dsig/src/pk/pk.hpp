#pragma once

#include <array>
#include <atomic>

#include "../inf-crypto/batch.hpp"
#include "../merkle.hpp"
#include "../types.hpp"
#include "../workers.hpp"

#include "../hors.hpp"
#include "../wots.hpp"

namespace dory::dsig {

class BgPublicKeys {
public:
  static size_t constexpr Size = InfBatchSize;

  struct Compressed {
    BatchMerkleTree::Leaves pk_hashes;
    BatchedInfSignature::InfSignature root_sig;
    #if HBSS_SCHEME == HORS_MERKLE
    std::array<HorsMerkleTree::PublicKey, InfBatchSize> hors_pk_leaves;
    #endif
  };

  enum State {
    Initializing,
    Ready,
    Invalid,
    LAST_STATE = Ready
  };
  std::atomic<State> state{Initializing};

  BgPublicKeys(Workers& workers, InfCrypto& inf_crypto, ProcId const src, Compressed const& compressed):
    tree{compressed.pk_hashes, false}, root_sig{compressed.root_sig} {
    #if HBSS_SCHEME == HORS_MERKLE
    hors_pk_trees.reserve(InfBatchSize);
    for (auto const& pk_leaves : compressed.hors_pk_leaves) {
      hors_pk_trees.emplace_back(pk_leaves, false);
    }
    #endif
    workers.schedule([this, &inf_crypto, src]{
      tree.compute();
      if constexpr (HbssScheme == HorsMerkle) {
        compute_hors_pk_trees();
      }
      check_root_sig(inf_crypto, src);
    });
  }

  BgPublicKeys(BgPublicKeys const&) = delete;
  BgPublicKeys& operator=(BgPublicKeys const&) = delete;
  BgPublicKeys(BgPublicKeys&&) = delete;
  BgPublicKeys& operator=(BgPublicKeys&&) = delete;

  /**
   * @brief Verify if a signature is valid.
   *
   */
  bool verify(Signature const& sig, uint8_t const* msg,
              size_t const msg_len) const {
    if (!verifyPkSig(sig.pk_sig)) {
      fmt::print(stderr, "Invalid PK sig!\n");
      return false;
    }

    if (!verifyHbss(sig, msg, msg + msg_len)) {
      fmt::print(stderr, "Invalid HBSS!\n");
      return false;
    }

    return true;
  }

  bool associatedTo(Signature const &sig) {
    return std::memcmp(&sig.pk_sig.root_sig, &root_sig, sizeof(root_sig)) == 0;
  }

  void prefetch() {
    dsig::prefetch(*this);
  }

  void prefetch_hors_tree(size_t const pk_idx) {
    dsig::prefetch(hors_pk_trees.at(pk_idx));
  }

private:
  void compute_hors_pk_trees() {
    for (auto &pk_tree : hors_pk_trees) {
      pk_tree.compute();
    }
  }

  void check_root_sig(InfCrypto& inf_crypto, ProcId const src) {
    if (!inf_crypto.verify(root_sig, reinterpret_cast<uint8_t const*>(tree.root().data()), tree.root().size(), src)) {
      state = Invalid;
      throw std::runtime_error("Invalid bg pk signature!");
    }
    state = Ready;
  }

  bool verifyPkSig(BatchedInfSignature const& pk_sig) const {
    if (std::memcmp(&pk_sig.root_sig, &root_sig, sizeof(root_sig)) != 0) {
      fmt::print(stderr, "Pk root sig does not match: {} vs {}!\n",
        pk_sig.root_sig, root_sig);
      return false;
    }

    if (!pk_sig.proof.in_tree(pk_sig.signed_hash, pk_sig.index, tree)) {
      fmt::print(stderr, "Pk element and proof not found in precomputed tree!\n");
      return false;
    }

    return true;
  }

  bool verifyHbss(HorsMerkleSignature const& sig, uint8_t const* const begin,
                  uint8_t const* const end) const {
    auto const pk_idx = sig.pk_sig.index;
    auto const& exp_pk_hash = tree.leaves().at(pk_idx);
    // 1. Verify that the roots match the tree
    auto const& pk_tree = hors_pk_trees.at(pk_idx);
    if (std::memcmp(pk_tree.roots().data(), sig.roots.data(), sizeof(sig.roots)) != 0) {
      fmt::print(stderr, "Pk roots do not match the precomputed tree!\n");
      return false;
    }
    // 2. For each secret, verify it is part of the tree
    HorsHash h(exp_pk_hash, sig.nonce, begin, end);
    for (size_t secret = 0; secret < hors::SecretsPerSignature; secret++) {
      auto const secret_index = h.getSecretIndex(secret);
      auto const hashed_secret = hash_secret(sig.secretsAndNeighborsHash.at(secret).secret, sig.pk_nonce, secret_index);
      auto const neighbor_hashed_secret = sig.secretsAndNeighborsHash.at(secret).neighborHash;
      std::array<SecretHash, 2> leaf;
      if(secret_index & 1){
        leaf = std::array<SecretHash, 2>{neighbor_hashed_secret, hashed_secret};
      } else {
        leaf = std::array<SecretHash, 2>{hashed_secret, neighbor_hashed_secret};
      }
      static_assert(sizeof(SecretHash) * 2 >= sizeof(Hash));
      if (!sig.proofs.at(secret).in_tree(*reinterpret_cast<Hash*>(&leaf), secret_index >> 1, pk_tree)) {
        fmt::print(stderr, "Pk tree does not match proof #{}!\n", secret);
        return false;
      }
    }
    // 3. Verify that the pk_nonce matches the eddsa-signed one
    auto hasher = crypto::hash::blake3_init();
    crypto::hash::blake3_update(hasher, sig.pk_nonce);
    crypto::hash::blake3_update(hasher, pk_tree.roots());
    if (crypto::hash::blake3_final(hasher) != tree.leaves().at(pk_idx)) {
      fmt::print(stderr, "Pk nonce does not match!\n");
      return false;
    }
    return true;
  }

  bool verifyHbss(HorsCompletedSignature const& sig, uint8_t const* const begin,
                  uint8_t const* const end) const {
    auto sig_hashes = sig.fused_secrets;
    auto const& exp_pk_hash = tree.leaves().at(sig.pk_sig.index);

    HorsHash h(exp_pk_hash, sig.nonce, begin, end);

    for (size_t secret = 0; secret < hors::SecretsPerSignature; secret++) {
      auto const secret_index = h.getSecretIndex(secret);
      sig_hashes.at(secret_index) = hash_secret(sig.fused_secrets.at(secret_index), sig.pk_nonce, secret_index);
    }

    auto hasher = crypto::hash::blake3_init();
    crypto::hash::blake3_update(hasher, sig.pk_nonce);
    crypto::hash::blake3_update(hasher, sig_hashes);
    return std::memcmp(crypto::hash::blake3_final(hasher).data(), exp_pk_hash.data(), exp_pk_hash.size()) == 0;
  }

  bool verifyHbss(WotsSignature const& sig, uint8_t const* const begin,
                  uint8_t const* const end) const {
    auto sig_hashes = sig.secrets;
    auto const& exp_pk_hash = tree.leaves().at(sig.pk_sig.index);

    WotsHash h(exp_pk_hash, sig.nonce, begin, end);

    for (size_t secret = 0; secret < wots::SecretsPerSignature; secret++) {
      // fmt::print("Secret {} has depth {}: {}\n", secret, h.getSecretDepth(secret), sig_hashes[secret]);
      for (size_t d = h.getSecretDepth(secret); d + 1 < SecretsDepth; d++) {
        // fmt::print("Hashing secret {} (l={}), {} -> {}\n", secret, d, sig_hashes[secret], hash_secret(sig_hashes[secret], sig.pk_nonce, secret, d));
        sig_hashes[secret] = hash_secret(sig_hashes[secret], sig.pk_nonce, secret, d);
      }
      // fmt::print("Secret {} should have hashed to {}\n", secret, hashes[secret]);
    }

    auto hasher = crypto::hash::blake3_init();
    crypto::hash::blake3_update(hasher, sig.pk_nonce);
    crypto::hash::blake3_update(hasher, sig_hashes);
    return std::memcmp(crypto::hash::blake3_final(hasher).data(), exp_pk_hash.data(), exp_pk_hash.size()) == 0;
  }

  BatchMerkleTree tree;
  BatchedInfSignature::InfSignature root_sig;
  std::vector<HorsMerkleTree> hors_pk_trees;
};

} // namespace dory::dsig
