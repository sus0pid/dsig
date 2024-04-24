#pragma once

#include <array>

#include "../../export/config.hpp"

namespace dory::dsig {
enum Validity {
  Valid,
  InvalidPkNonce,
  InvalidPkSig,
  InvalidNonce,
  InvalidSecret,
  InvalidHorsMerkleRoot,
  InvalidHorsMerkleProof,
};

static char const* to_string(Validity const validity) {
  switch (validity) {
    case Valid:
      return "VALID";
    case InvalidPkNonce:
      return "INVALID_PK_NONCE";
    case InvalidPkSig:
      return "INVALID_PK_SIG";
    case InvalidNonce:
      return "INVALID_NONCE";
    case InvalidSecret:
      return "INVALID_SECRET";
    case InvalidHorsMerkleRoot:
      return "INVALID_HORS_MERKLE_ROOT";
    case InvalidHorsMerkleProof:
      return "INVALID_HORS_MERKLE_PROOF";
    default:
      return "UNKNOWN";
  }
}

template<dory::dsig::HbssSchemes> struct SchemeToInvalid;
template<> struct SchemeToInvalid<dory::dsig::HorsMerkle> {
  std::array<Validity, 5> static constexpr Fast = {
    Validity::InvalidPkNonce, Validity::InvalidNonce, Validity::InvalidSecret,
    Validity::InvalidHorsMerkleRoot, Validity::InvalidHorsMerkleProof};
  std::array<Validity, 1> static constexpr Slow = {Validity::InvalidPkSig};
};
template<> struct SchemeToInvalid<dory::dsig::HorsCompleted> {
  std::array<Validity, 3> static constexpr Fast = {
    Validity::InvalidPkNonce, Validity::InvalidNonce, Validity::InvalidSecret};
  std::array<Validity, 1> static constexpr Slow = {Validity::InvalidPkSig};
};
template<> struct SchemeToInvalid<dory::dsig::Wots> {
  std::array<Validity, 3> static constexpr Fast = {
    Validity::InvalidPkNonce, Validity::InvalidNonce, Validity::InvalidSecret};
  std::array<Validity, 1> static constexpr Slow = {Validity::InvalidPkSig};
};
}