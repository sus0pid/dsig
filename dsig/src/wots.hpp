#pragma once

#include <array>
#include <type_traits>

#include <dory/crypto/hash/blake3.hpp>
#include <dory/shared/branching.hpp>

#include "config.hpp"
#include "types.hpp"

namespace dory::dsig {

/**
 * @brief A hash large enough know which secrets to reveal.
 *
 */
class WotsHash {
  struct Prefix {
    Hash pk_hash;
    Nonce nonce;
  };
 public:
  WotsHash(Hash const& pk_hash, Nonce const& nonce, uint8_t const* const begin,
           uint8_t const* const end) {
    // Deviation from the original WOTS: we compute a larger hash
    // and use a subset of the bits aligned on bytes.
    static_assert(wots::LogSecretsDepth <= 8);
    std::array<uint8_t, wots::L1> hash;
    std::array<uint8_t, 8> checksum = {};  // 8 is more than necessary

    // Computing the secret depths for L1
    auto hasher = crypto::hash::blake3_init();
    Prefix prefix = {pk_hash, nonce};
    crypto::hash::blake3_update(hasher, prefix);
    crypto::hash::blake3_update(hasher, begin, end);
    crypto::hash::blake3_final_there(hasher, hash.data(), hash.size());
    uint64_t& csum = *reinterpret_cast<uint64_t*>(checksum.data());
    for (size_t secret = 0; secret < wots::L1; secret++) {
      static uint8_t constexpr SecretsDepthMask = SecretsDepth - 1;
      secret_depths[secret] = hash[secret] & SecretsDepthMask;
      csum += secret_depths[secret];
    }

    // Computing the secret depths for L2
    for (size_t secret = wots::L1, bit_offset = 0;
      secret < wots::SecretsPerSecretKey;
      secret++, bit_offset += wots::LogSecretsDepth) {
      static uint16_t constexpr SecretsDepthMask = SecretsDepth - 1;
      auto const byte_offset = bit_offset / 8ul;
      auto const remaining_bit_offset = bit_offset % 8ul;
      // Due to Intel's little endianness, the initialized bytes hold the LSBs.
      // Given that C++'s shift operator work on the value and not on the memory
      // representation, we need to read the LSB
      secret_depths[secret] = (*reinterpret_cast<uint16_t const*>(&checksum[byte_offset]) >>
            remaining_bit_offset) & SecretsDepthMask;
    }
  }

  inline uint8_t getSecretDepth(size_t const index) const {
    return secret_depths[index];
  }

 private:
  std::array<uint8_t, wots::SecretsPerSignature> secret_depths;
};

}  // namespace dory::dsig
