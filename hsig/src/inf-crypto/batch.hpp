#pragma once

#include <array>

#include "../hsig-types.hpp"
#include "../merkle.hpp"


namespace dory::hsig {

using BatchMerkleTree = MerkleTree<LogInfBatchSize>;
using BatchMerkleProof = MerkleProof<BatchMerkleTree>;

template <typename Signature>
struct __attribute__((__packed__)) Batched {
  using InfSignature = Signature;

  Batched() = default;

  Hash signed_hash;
  BatchMerkleProof proof;
  Signature root_sig;
  size_t index;

  Batched(Hash const& signed_hash, BatchMerkleTree const& tree, size_t const index, Signature const& root_sig)
   : signed_hash{signed_hash}, proof{tree, index}, root_sig{root_sig}, index{index} {}
};
}