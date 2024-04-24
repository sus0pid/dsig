#include <array>
#include <chrono>
#include <cstdint>
#include <vector>

#include <dory/crypto/hash/blake3.hpp>
#include <dory/crypto/hash/siphash.hpp>
#include <dory/crypto/hash/haraka.hpp>

#include <fmt/core.h>
#include <fmt/chrono.h>

#include "../latency.hpp"

size_t constexpr Secrets = 64;
size_t constexpr Runs = 1024;

using Salt = std::array<uint8_t, 16>;
using Secret = std::array<uint8_t, 16>;

using Hash = dory::crypto::hash::Blake3Hash;
using SipHash = dory::crypto::hash::SipHash;
using HarakaHash = dory::crypto::hash::HarakaHash;
using HarakaHash4x = dory::crypto::hash::HarakaHash4x;
using HalfHarakaHash = dory::crypto::hash::HalfHarakaHash;

struct SaltedSecret {
  Salt salt;
  Secret secret;
};

struct DoubleSaltedSecret {
  Salt salt;
  Secret secret;
  HarakaHash hash;
};

int main() {
  std::vector<Secret> secrets(Secrets);
  std::vector<Secret> half_secrets(Secrets);
  std::vector<Hash> hashes(Secrets);
  std::vector<SipHash> sip_hashes(Secrets);
  std::vector<HarakaHash> haraka_hashes(Secrets);
  std::vector<HalfHarakaHash> half_haraka_hashes(Secrets);
  std::vector<HarakaHash> haraka_512_hashes(Secrets);
  std::vector<HarakaHash4x> haraka_4x_hashes(Secrets / 4);
  std::vector<HarakaHash4x> haraka_512_4x_hashes(Secrets / 4);

  std::array<uint8_t, 16> seed {};

  Salt salt = dory::crypto::hash::siphash(seed, seed.data());

  dory::dsig::LatencyProfiler nature, salted_simple, salted_struct, salted_cp, sip, haraka, half_haraka,
      haraka_512, haraka_4x, haraka_512_4x;

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
        hashes[s] = dory::crypto::hash::blake3_final(hasher);
      }
      auto const end = std::chrono::steady_clock::now();
      salted_simple.addMeasurement(end - start);
    }
    {
      // Salted Struct
      auto const start = std::chrono::steady_clock::now();
      for (size_t s = 0; s < Secrets; s++) {
        SaltedSecret to_hash{ salt, half_secrets[s] };
        hashes[s] = dory::crypto::hash::blake3(to_hash);
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
        hashes[s] = dory::crypto::hash::blake3_final(hasher);
      }
      auto const end = std::chrono::steady_clock::now();
      salted_cp.addMeasurement(end - start);
    }
    {
      // Sip
      auto const start = std::chrono::steady_clock::now();
      for (size_t s = 0; s < Secrets; s++) {
        sip_hashes[s] = dory::crypto::hash::siphash(salt, secrets[s].data());
      }
      auto const end = std::chrono::steady_clock::now();
      sip.addMeasurement(end - start);
    }
    {
      // Haraka
      auto const start = std::chrono::steady_clock::now();
      for (size_t s = 0; s < Secrets; s++) {
        SaltedSecret to_hash{ salt, half_secrets[s] };
        haraka_hashes[s] = dory::crypto::hash::haraka<HarakaHash>(to_hash);
      }
      auto const end = std::chrono::steady_clock::now();
      haraka.addMeasurement(end - start);
    }
    {
      // Half-haraka
      auto const start = std::chrono::steady_clock::now();
      for (size_t s = 0; s < Secrets; s++) {
        SaltedSecret to_hash{ salt, half_secrets[s] };
        half_haraka_hashes[s] = dory::crypto::hash::haraka<HalfHarakaHash>(to_hash);
      }
      auto const end = std::chrono::steady_clock::now();
      half_haraka.addMeasurement(end - start);
    }
    {
      // Haraka 512
      auto const start = std::chrono::steady_clock::now();
      for (size_t s = 0; s < Secrets; s++) {
        DoubleSaltedSecret to_hash{ salt, half_secrets[s], haraka_hashes[s] };
        haraka_512_hashes[s] = dory::crypto::hash::haraka<HarakaHash>(to_hash);
      }
      auto const end = std::chrono::steady_clock::now();
      haraka_512.addMeasurement(end - start);
    }
    {
      // Haraka 4x
      auto const start = std::chrono::steady_clock::now();
      for (size_t s = 0; s < Secrets / 4; s++) {
        SaltedSecret to_hash[4] = {
          { salt, half_secrets[4*s + 0] },
          { salt, half_secrets[4*s + 1] },
          { salt, half_secrets[4*s + 2] },
          { salt, half_secrets[4*s + 3] }
        };
        haraka_4x_hashes[s] = dory::crypto::hash::haraka_4x<HarakaHash4x>(to_hash);
      }
      auto const end = std::chrono::steady_clock::now();
      haraka_4x.addMeasurement(end - start);
    }
    {
      // Haraka 512 4x
      auto const start = std::chrono::steady_clock::now();
      for (size_t s = 0; s < Secrets / 4; s++) {
        DoubleSaltedSecret to_hash[4] = {
          { salt, half_secrets[4*s + 0], haraka_hashes[4*s + 0] },
          { salt, half_secrets[4*s + 1], haraka_hashes[4*s + 1] },
          { salt, half_secrets[4*s + 2], haraka_hashes[4*s + 2] },
          { salt, half_secrets[4*s + 3], haraka_hashes[4*s + 3] }
        };
        haraka_512_4x_hashes[s] = dory::crypto::hash::haraka_4x<HarakaHash4x>(to_hash);
      }
      auto const end = std::chrono::steady_clock::now();
      haraka_512_4x.addMeasurement(end - start);
    }
  }

  fmt::print("Nature:\n");
  nature.report();
  fmt::print("Simple salt:\n");
  salted_simple.report();
  fmt::print("Salted struct:\n");
  salted_struct.report();
  fmt::print("Salted cp:\n");
  salted_cp.report();
  fmt::print("Sip:\n");
  sip.report();
  fmt::print("Haraka:\n");
  haraka.report();
  fmt::print("Half-haraka:\n");
  half_haraka.report();
  fmt::print("Haraka 512:\n");
  haraka_512.report();
  fmt::print("Haraka x4:\n");
  haraka_4x.report();
  fmt::print("Haraka 512 x4:\n");
  haraka_512_4x.report();

  return 0;
}