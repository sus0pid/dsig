#pragma once

#include <array>
#include <type_traits>

#include <fmt/core.h>

#include <dory/crypto/hash/blake3.hpp>
#include <dory/shared/branching.hpp>

#include "export/config.hpp"

namespace dory::dsig {

template <size_t _LogNbLeaves, size_t _LogNbRoots = 0>
struct MerkleTree {
  using Hash = std::array<uint8_t, 32>;
  static size_t constexpr LogNbLeaves{_LogNbLeaves};
  static size_t constexpr NbLeaves{1 << LogNbLeaves};
  static size_t constexpr LogNbRoots{_LogNbRoots};
  static size_t constexpr NbRoots{1 << LogNbRoots};
  using Leaves = std::array<Hash, NbLeaves>;
  using Root = Hash;
  using Roots = std::array<Root, NbRoots>;

  std::array<Hash, NbLeaves * 2 - 1> nodes;

  MerkleTree(Leaves const& l, bool build=true) {
    memcpy(leaves().data(), l.data(), sizeof(l));
    if (build) compute();
  }

  void compute() {
    if constexpr (NbLeaves == 1) return;
    for (size_t left_child = nodes.size() - 2, parent = NbLeaves - 2;;
      left_child -= 2, parent--) {
      auto &children = *reinterpret_cast<std::array<Hash, 2>*>(&nodes.at(left_child));
      nodes.at(parent) = crypto::hash::blake3(children);
      if (parent == 0) break;
    }
  }

  template <size_t _NbRoots = NbRoots, std::enable_if_t<_NbRoots == 1, bool> = true>
  Root const& root() const {
    return nodes.front();
  }

  Roots const& roots() const {
    return *reinterpret_cast<Roots const*>(&nodes.at(NbRoots - 1));
  }

  Leaves& leaves() {
    return *reinterpret_cast<Leaves*>(nodes.at(NbLeaves - 1).data());
  }

  Leaves const& leaves() const {
    return *reinterpret_cast<Leaves const*>(nodes.at(NbLeaves - 1).data());
  }
};

template <typename MerkleTree>
struct __attribute__((__packed__)) MerkleProof {
  using Hash = typename MerkleTree::Hash;

  MerkleProof() = default;

  std::array<Hash, MerkleTree::LogNbLeaves - MerkleTree::LogNbRoots> path;

  MerkleProof(MerkleTree const& tree, size_t const index) {
    // Starting from the root
    size_t node = 0;
    for (size_t i = 0; i < path.size(); i++) {
      auto depth = i + MerkleTree::LogNbRoots;
      auto const leaf_direction =
          (index >> (path.size() - depth - 1)) & 1;
      auto left_child = (node << 1) + 1;
      auto child_in_path = left_child + (1 - leaf_direction);
      path[path.size() - i - 1] = tree.nodes.at(child_in_path);
      node = left_child + leaf_direction;
    }
  }

  Hash root(Hash const& leaf, size_t const index) const {
    auto directions = index >> MerkleTree::LogNbRoots;
    auto acc = leaf;
    for (size_t i = 0; i < path.size(); i++) {
      auto direction = directions & 1;
      directions >>= 1;
      auto hs = crypto::hash::blake3_init();
      if (direction == 0) {
        crypto::hash::blake3_update(hs, acc);
        crypto::hash::blake3_update(hs, path[i]);
      } else {
        crypto::hash::blake3_update(hs, path[i]);
        crypto::hash::blake3_update(hs, acc);
      }
      acc = crypto::hash::blake3_final(hs);
    }
    return acc;
  }

  bool in_tree(Hash const& leaf, size_t const index, MerkleTree const& tree) const {
    if (std::memcmp(tree.leaves().at(index).data(), leaf.data(), leaf.size()) != 0) {
      fmt::print(stderr, "Invalid leaf: {} vs {}", leaf, tree.leaves().at(index));
      return false;
    }

    // Starting from the root
    size_t node = 0;
    for (size_t i = 0; i < path.size(); i++) {
      auto depth = i + MerkleTree::LogNbRoots;
      auto const leaf_direction =
          (index >> (path.size() - depth - 1)) & 1;
      auto left_child = (node << 1) + 1;
      auto child_in_path = left_child + (1 - leaf_direction);
      auto const& expected_node = tree.nodes.at(child_in_path);
      if (unlikely(std::memcmp(&path[path.size() - i - 1], &expected_node, sizeof(expected_node)) != 0)) {
        fmt::print(stderr, "Invalid path node #{}: {} vs {}", i, path[path.size() - i - 1], expected_node);
        return false;
      }

      node = left_child + leaf_direction;
    }
    // return leaf(proof.leaf_index) == proof.leaf;
    return true;
  }
};

}