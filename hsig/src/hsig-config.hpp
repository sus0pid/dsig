#pragma once

#include <array>

// Non-standard directive, but both gcc and clang provide it
#if defined __has_include
#if __has_include("internal/compile-time-config.hpp")
#include "internal/compile-time-config.hpp"
#endif
#else
#warning "Cannot export as a shared library"
#endif

#ifndef HASHING_SCHEME
#error "Define HASHING_SCHEME"
#endif

#ifndef WOTS_LOG_SECRETS_DEPTH
#define WOTS_LOG_SECRETS_DEPTH 2
#endif

#ifndef LOG_INF_BATCH_SIZE
#error "Define LOG_INF_BATCH_SIZE"
#endif

namespace dory::hsig {

char constexpr nspace[] = "dsig-";

enum HashingSchemes { Blake3 = 0, SipHash = 1, Haraka = 2, SHA256 = 3 };
HashingSchemes constexpr HashingScheme = static_cast<HashingSchemes>(HASHING_SCHEME);
static_assert(HashingScheme == Blake3 || HashingScheme == SipHash || HashingScheme == Haraka || HashingScheme == SHA256);

size_t constexpr LogSecretsDepth = WOTS_LOG_SECRETS_DEPTH; /*log_w*/
size_t constexpr SecretsDepth = 1 << LogSecretsDepth; /*w*/

// Old version with security less < 128bit
// std::array<size_t, 9> constexpr PrecomputedL1 = {0,  128, 64, 43, 32,
//                                                  26, 22,  19, 16};
/*n = 256 bit*/
std::array<size_t, 7> constexpr PrecomputedL1 = {0, 128, 64, 43, 32, 26, 22};
std::array<size_t, 7> constexpr PrecomputedL2 = {0,   8,  4,  3,  3,  2,  2};
size_t constexpr L1 = PrecomputedL1[LogSecretsDepth];
size_t constexpr L2 = PrecomputedL2[LogSecretsDepth];

size_t constexpr SecretsPerSecretKey = L1 + L2; /*L*/
size_t constexpr SecretsPerSignature = SecretsPerSecretKey; /*L*/

// There should be at least 2 levels.
static_assert(SecretsDepth > 1);
size_t constexpr LogInfBatchSize = LOG_INF_BATCH_SIZE;
size_t constexpr InfBatchSize = 1 << LogInfBatchSize;
size_t constexpr PreparedSks = std::max(InfBatchSize, 512ul);

size_t constexpr CachedPkBatchesPerProcess = 8 * PreparedSks / InfBatchSize;

///*copy from dsig/src/export/config.hpp*/
//std::array<size_t, 65> constexpr PrecomputedLogNbRoots = {
//    0,
//    0,  0,  0,  0,  0,  0,  0,  3,
//    4,  4,  4,  4,  4,  4,  0,  4,
//    0,  0,  5,  0,  0,  0,  0,  5,
//    0,  0,  0,  0,  0,  0,  0,  5,
//    0,  0,  0,  0,  0,  0,  0,  0,
//    0,  0,  0,  0,  0,  0,  0,  0,
//    0,  0,  0,  0,  0,  0,  0,  0,
//    0,  0,  0,  0,  0,  0,  0,  6,
//};
//size_t constexpr LogNbRoots = PrecomputedLogNbRoots[SecretsPerSignature];
//size_t constexpr NbRoots = 1 << LogNbRoots;
}

#if defined __has_include
#if __has_include("internal/compile-time-config.hpp")
#undef HASHING_SCHEME
#undef LOG_INF_BATCH_SIZE
#undef WOTS_LOG_SECRETS_DEPTH
#endif
#endif
