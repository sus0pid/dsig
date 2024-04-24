#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <type_traits>

#include <fmt/chrono.h>
#include <fmt/core.h>

#include <dory/crypto/asymmetric/switchable-crypto.hpp>
#include <dory/crypto/hash/blake3.hpp>

#include "../../dsig.hpp"
#include "validity.hpp"

namespace dory::dsig {
struct SignedMessage {
  union {
    std::chrono::nanoseconds remote_sign;
    std::chrono::nanoseconds local_sign;
  };
  std::chrono::nanoseconds remote_verify;

  Signature sig;

  uint8_t msg;

  std::chrono::nanoseconds fill(size_t const p, size_t const msg_size,
                                Dsig& dsig,
                                Validity const validity = Validity::Valid) {
    std::memset(&msg, 0, msg_size);
    *reinterpret_cast<size_t*>(&msg) = p;

    auto const start = std::chrono::steady_clock::now();
    dsig.sign(sig, &msg, msg_size);
    auto const end = std::chrono::steady_clock::now();

    damage(sig, validity);

    return end - start;
  }

  bool verify(size_t const msg_size, Dsig& dsig, Path const path,
              ProcId const remote_id, Validity const validity = Validity::Valid) const {
    auto const valid = path == Fast
                           ? dsig.verify(sig, &msg, msg_size, remote_id)
                           : dsig.slow_verify(sig, &msg, msg_size, remote_id);
    return (validity == Validity::Valid) ^ !valid;
  }

  void print(size_t const msg_size) const {
    auto const& siga =
        *reinterpret_cast<std::array<uint8_t, sizeof(Signature)> const*>(&sig);
    auto const& msga = *reinterpret_cast<std::array<uint8_t, 8> const*>(&msg);
    if (msg_size < 8) {
      throw std::runtime_error("msg size should be >= 8");
    }
    fmt::print("<Sig: {}, Msg: {}...>\n", siga, msga);
  }

  size_t static constexpr size(size_t const msg_size) {
    return offsetof(SignedMessage, msg) + msg_size;
  }

  size_t static constexpr tput_pong_size() {
    return offsetof(SignedMessage, sig);
  }

 private:
  template <typename S>
  bool damage_base(S& sig, Validity const validity) {
    switch (validity) {
      case Validity::Valid:
        return true;
      case Validity::InvalidPkNonce:
        sig.pk_nonce.back() ^= 1;
        return true;
      case Validity::InvalidPkSig:
        sig.pk_sig.root_sig.back() ^= 1;
        return true;
      case Validity::InvalidNonce:
        sig.nonce.back() ^= 1;
        return true;
      default:
        return false;
    }
  }

  void damage(HorsMerkleSignature& sig, Validity const validity) {
    if (damage_base(sig, validity))
      return;
    switch (validity) {
      case Validity::InvalidSecret:
        sig.secretsAndNeighborsHash.back().secret.back() ^= 1;
        break;
      case Validity::InvalidHorsMerkleRoot:
        sig.roots.back().back() ^= 1;
        break;
      case Validity::InvalidHorsMerkleProof:
        sig.proofs.back().path.back().back() ^= 1;
        break;
      default:
        throw std::runtime_error("Unknown");
    }
  }

  void damage(HorsCompletedSignature& sig, Validity const validity) {
    if (damage_base(sig, validity))
      return;
    switch (validity) {
      case Validity::InvalidSecret:
        sig.fused_secrets.back().back() ^= 1;
        break;
      default:
        throw std::runtime_error("Unknown");
    }
  }

  void damage(WotsSignature& sig, Validity const validity) {
    if (damage_base(sig, validity))
      return;
    switch (validity) {
      case Validity::InvalidSecret:
        sig.secrets.back().back() ^= 1;
        break;
      default:
        throw std::runtime_error("Unknown");
    }
  }
};

struct InfMessage {
  union {
    std::chrono::nanoseconds remote_sign;
    std::chrono::nanoseconds local_sign;
  };
  std::chrono::nanoseconds remote_verify;

  crypto::asymmetric::AsymmetricCrypto::Signature sig;

  uint8_t msg;

  template <bool Prehash=false>
  std::chrono::nanoseconds fill(size_t const p, size_t const msg_size,
                                crypto::asymmetric::AsymmetricCrypto& crypto,
                                const bool bypass) {
    auto sig_view = crypto.signatureView(sig);
    std::memset(&msg, 0, msg_size);
    *reinterpret_cast<size_t*>(&msg) = p;
    if (bypass) return std::chrono::nanoseconds(0);
    auto const start = std::chrono::steady_clock::now();
    if constexpr (Prehash) {
      auto const hash = crypto::hash::blake3(&msg, &msg + msg_size);
      crypto.sign(sig_view, hash.data(), hash.size());
    } else {
      crypto.sign(sig_view, &msg, msg_size);
    }
    return std::chrono::steady_clock::now() - start;
  }

  template <bool Prehash=false>
  bool verify(size_t const msg_size, crypto::asymmetric::AsymmetricCrypto& crypto,
              crypto::asymmetric::AsymmetricCrypto::PublicKey& pk,
              const bool bypass) const {
    if (bypass) return true;
    if constexpr (Prehash) {
      auto const hash = crypto::hash::blake3(&msg, &msg + msg_size);
      return crypto.verify(sig, hash.data(), hash.size(), pk);
    } else {
      return crypto.verify(sig, &msg, msg_size, pk);
    }
  }

  size_t static constexpr size(size_t const msg_size) {
    return offsetof(InfMessage, msg) + msg_size;
  }

  size_t static constexpr tput_pong_size() {
    return offsetof(InfMessage, sig);
  }
};
}