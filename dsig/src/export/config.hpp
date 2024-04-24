#pragma once

#include <algorithm>
#include <array>
#include <cstddef>

// Non-standard directive, but both gcc and clang provide it
#if defined __has_include
#if __has_include("internal/compile-time-config.hpp")
#include "internal/compile-time-config.hpp"
#endif
#else
#warning "Cannot export as a shared library"
#endif

#ifndef HBSS_SCHEME
#error "Define HBSS_SCHEME"
#endif

#ifndef HASHING_SCHEME
#error "Define HASHING_SCHEME"
#endif

#ifndef LOG_INF_BATCH_SIZE
#error "Define LOG_INF_BATCH_SIZE"
#endif

namespace dory::dsig {

#define HORS_MERKLE 0
#define HORS_COMPLETED 1
#define WOTS 2
enum HbssSchemes { HorsMerkle = HORS_MERKLE, HorsCompleted = HORS_COMPLETED, Wots = WOTS };
HbssSchemes constexpr HbssScheme = static_cast<HbssSchemes>(HBSS_SCHEME);
static_assert(HbssScheme == HorsMerkle || HbssScheme == HorsCompleted || HbssScheme == Wots);

enum HashingSchemes { Blake3 = 0, SipHash = 1, Haraka = 2, SHA256 = 3 };
HashingSchemes constexpr HashingScheme = static_cast<HashingSchemes>(HASHING_SCHEME);
static_assert(HashingScheme == Blake3 || HashingScheme == SipHash || HashingScheme == Haraka || HashingScheme == SHA256);

namespace hors {
#if HBSS_SCHEME == HORS_MERKLE || HBSS_SCHEME == HORS_COMPLETED
#ifndef HORS_SECRETS_PER_SIGNATURE
#error "Define HORS_SECRETS_PER_SIGNATURE"
#endif
#else
#define HORS_SECRETS_PER_SIGNATURE 19
#endif
size_t constexpr SecretsPerSignature = HORS_SECRETS_PER_SIGNATURE;
std::array<size_t, 65> constexpr PrecomputedLogSecretsPerSecretKey = {
   0,
   0,  0,  0,  0,  0,  0,  0, 19,
  18, 17, 16, 15, 14, 13,  0, 12,
   0,  0, 11,  0,  0,  0,  0, 10,
   0,  0,  0,  0,  0,  0,  0,  9,
   0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  8,
};
std::array<size_t, 65> constexpr PrecomputedLogNbRoots = {
   0,
   0,  0,  0,  0,  0,  0,  0,  3,
   4,  4,  4,  4,  4,  4,  0,  4,
   0,  0,  5,  0,  0,  0,  0,  5,
   0,  0,  0,  0,  0,  0,  0,  5,
   0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  6,
};
size_t constexpr LogSecretsPerSecretKey = PrecomputedLogSecretsPerSecretKey[SecretsPerSignature];
static_assert(LogSecretsPerSecretKey != 0);
size_t constexpr SecretsPerSecretKey = 1 << LogSecretsPerSecretKey;
size_t constexpr LogNbRoots = PrecomputedLogNbRoots[SecretsPerSignature];
size_t constexpr NbRoots = 1 << LogNbRoots;
}

namespace wots {
#if HBSS_SCHEME == WOTS
#ifndef WOTS_LOG_SECRETS_DEPTH
#error "Define WOTS_LOG_SECRETS_DEPTH"
#endif
#else
#define WOTS_LOG_SECRETS_DEPTH 2
#endif
size_t constexpr LogSecretsDepth = WOTS_LOG_SECRETS_DEPTH;
size_t constexpr SecretsDepth = 1 << LogSecretsDepth;

// Old version with security less < 128bit
// std::array<size_t, 9> constexpr PrecomputedL1 = {0,  128, 64, 43, 32,
//                                                  26, 22,  19, 16};
std::array<size_t, 7> constexpr PrecomputedL1 = {0, 128, 64, 43, 32, 26, 22};
std::array<size_t, 7> constexpr PrecomputedL2 = {0,   8,  4,  3,  3,  2,  2};
size_t constexpr L1 = PrecomputedL1[LogSecretsDepth];
size_t constexpr L2 = PrecomputedL2[LogSecretsDepth];

size_t constexpr SecretsPerSecretKey = L1 + L2;
size_t constexpr SecretsPerSignature = SecretsPerSecretKey;
}  // namespace dory::wots

size_t constexpr SecretsPerSecretKey = HbssScheme == Wots ? wots::SecretsPerSecretKey : hors::SecretsPerSecretKey;
size_t constexpr SecretsPerSignature = HbssScheme == Wots ? wots::SecretsPerSignature : hors::SecretsPerSignature;

size_t constexpr SecretsDepth = HbssScheme == Wots ? wots::SecretsDepth : 2;
// There should be at least 2 levels.
static_assert(SecretsDepth > 1);

size_t constexpr LogInfBatchSize = LOG_INF_BATCH_SIZE;
size_t constexpr InfBatchSize = 1 << LogInfBatchSize;
size_t constexpr PreparedSks = std::max(InfBatchSize, 512ul);
}  // namespace dory::dsig

#if defined __has_include
#if __has_include("internal/compile-time-config.hpp")
// Clear the preprocessor namespace
#undef HBSS_SCHEME
#undef HASHING_SCHEME
#undef LOG_INF_BATCH_SIZE
#undef WOTS_LOG_SECRETS_DEPTH
#undef HORS_SECRETS_PER_SIGNATURE
#endif
#endif
