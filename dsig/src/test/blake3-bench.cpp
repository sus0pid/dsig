#include <array>
#include <chrono>
#include <cstdint>
#include <vector>

#include <dory/crypto/hash/blake3.hpp>

#include <fmt/core.h>
#include <fmt/chrono.h>

#include "../latency.hpp"

size_t constexpr Secrets = 64;
size_t constexpr Runs = 1024;

using Salt = std::array<uint8_t, 32>;
using HalfSalt = std::array<uint8_t, 16>;
using Secret = std::array<uint8_t, 32>;
using HalfSecret = std::array<uint8_t, 16>;
using Suffix = uint32_t;
using Hash = dory::crypto::hash::Blake3Hash;
using HalfHash = dory::crypto::hash::Blake3HalfHash;

struct SaltedSecret {
  Salt salt;
  HalfSecret secret;
  Suffix suffix;
};

struct HalfSaltedSecret {
  HalfSalt salt;
  HalfSecret secret;
  Suffix suffix;
};


int main() {
  std::vector<Secret> secrets(Secrets);
  std::vector<HalfSecret> half_secrets(Secrets);
  std::vector<Hash> hashes(Secrets);
  std::vector<HalfHash> half_hashes(Secrets);

  Salt salt = dory::crypto::hash::blake3<Salt>("seed");
  HalfSalt half_salt = dory::crypto::hash::blake3<HalfSalt>("seed");
  Suffix suffix = 0;

  dory::dsig::LatencyProfiler nature, salted_simple, pre_salted_struct, salted_struct, salted_cp, half_salted_simple, half_pre_salted_struct, half_salted_struct, half_salted_cp;

  for (size_t run = 0; run < Runs; run++) {
    {
      // Nature
      auto const start = std::chrono::steady_clock::now();
      for (size_t s = 0; s < Secrets; s++) {
        hashes[s] = dory::crypto::hash::blake3(secrets[s]);
      }
      auto const end = std::chrono::steady_clock::now();
      nature.addMeasurement(end - start);
    }
    {
      // Salted Simple
      auto const start = std::chrono::steady_clock::now();
      for (size_t s = 0; s < Secrets; s++) {
        auto hasher = dory::crypto::hash::blake3_init();
        dory::crypto::hash::blake3_update(hasher, salt);
        dory::crypto::hash::blake3_update(hasher, half_secrets[s]);
        dory::crypto::hash::blake3_update(hasher, suffix++);
        half_hashes[s] = dory::crypto::hash::blake3_final<HalfHash>(hasher);
      }
      auto const end = std::chrono::steady_clock::now();
      salted_simple.addMeasurement(end - start);
    }
    {
      // Pre-salted Struct
      auto const start = std::chrono::steady_clock::now();
      SaltedSecret to_hash{ salt, {}, suffix };
      for (size_t s = 0; s < Secrets; s++) {
        to_hash.secret = half_secrets[s];
        half_hashes[s] = dory::crypto::hash::blake3<HalfHash>(to_hash);
        to_hash.suffix++;
      }
      auto const end = std::chrono::steady_clock::now();
      pre_salted_struct.addMeasurement(end - start);
    }
    {
      // Salted Struct
      auto const start = std::chrono::steady_clock::now();
      for (size_t s = 0; s < Secrets; s++) {
        SaltedSecret to_hash{ salt, half_secrets[s], suffix++ };
        half_hashes[s] = dory::crypto::hash::blake3<HalfHash>(to_hash);
      }
      auto const end = std::chrono::steady_clock::now();
      salted_struct.addMeasurement(end - start);
    }
    {
      // Salted Cp
      auto const start = std::chrono::steady_clock::now();
      auto base_hasher = dory::crypto::hash::blake3_init();
      dory::crypto::hash::blake3_update(base_hasher, salt);
      for (size_t s = 0; s < Secrets; s++) {
        auto hasher = base_hasher;
        dory::crypto::hash::blake3_update(hasher, half_secrets[s]);
        dory::crypto::hash::blake3_update(hasher, suffix++);
        half_hashes[s] = dory::crypto::hash::blake3_final<HalfHash>(hasher);
      }
      auto const end = std::chrono::steady_clock::now();
      salted_cp.addMeasurement(end - start);
    }
        {
      // Half-salted Simple
      auto const start = std::chrono::steady_clock::now();
      for (size_t s = 0; s < Secrets; s++) {
        auto hasher = dory::crypto::hash::blake3_init();
        dory::crypto::hash::blake3_update(hasher, half_salt);
        dory::crypto::hash::blake3_update(hasher, half_secrets[s]);
        dory::crypto::hash::blake3_update(hasher, suffix++);
        half_hashes[s] = dory::crypto::hash::blake3_final<HalfHash>(hasher);
      }
      auto const end = std::chrono::steady_clock::now();
      half_salted_simple.addMeasurement(end - start);
    }
    {
      // Half-pre-salted Struct
      auto const start = std::chrono::steady_clock::now();
      HalfSaltedSecret to_hash{ half_salt, {}, suffix };
      for (size_t s = 0; s < Secrets; s++) {
        to_hash.secret = half_secrets[s];
        half_hashes[s] = dory::crypto::hash::blake3<HalfHash>(to_hash);
        to_hash.suffix++;
      }
      auto const end = std::chrono::steady_clock::now();
      half_pre_salted_struct.addMeasurement(end - start);
    }
    {
      // Half-Salted Struct
      auto const start = std::chrono::steady_clock::now();
      for (size_t s = 0; s < Secrets; s++) {
        HalfSaltedSecret to_hash{ half_salt, half_secrets[s], suffix++ };
        half_hashes[s] = dory::crypto::hash::blake3<HalfHash>(to_hash);
      }
      auto const end = std::chrono::steady_clock::now();
      half_salted_struct.addMeasurement(end - start);
    }
    {
      // Salted Cp
      auto const start = std::chrono::steady_clock::now();
      auto base_hasher = dory::crypto::hash::blake3_init();
      dory::crypto::hash::blake3_update(base_hasher, half_salt);
      for (size_t s = 0; s < Secrets; s++) {
        auto hasher = base_hasher;
        dory::crypto::hash::blake3_update(hasher, half_secrets[s]);
        dory::crypto::hash::blake3_update(hasher, suffix++);
        half_hashes[s] = dory::crypto::hash::blake3_final<HalfHash>(hasher);
      }
      auto const end = std::chrono::steady_clock::now();
      half_salted_cp.addMeasurement(end - start);
    }
  }

  fmt::print("Nature:\n");
  nature.report();
  fmt::print("Simple salt:\n");
  salted_simple.report();
  fmt::print("Salted struct:\n");
  salted_struct.report();
  fmt::print("Pre-salted struct:\n");
  pre_salted_struct.report();
  fmt::print("Salted cp:\n");
  salted_cp.report();
  fmt::print("Simple half-salt:\n");
  half_salted_simple.report();
  fmt::print("Half-salted struct:\n");
  half_salted_struct.report();
  fmt::print("Pre-half-salted struct:\n");
  half_pre_salted_struct.report();
  fmt::print("Half-salted cp:\n");
  half_salted_cp.report();

  return 0;
}