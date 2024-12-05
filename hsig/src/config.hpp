#pragma once

#ifndef HASHING_SCHEME
#error "Define HASHING_SCHEME"
#endif

#ifndef WOTS_LOG_SECRETS_DEPTH
#define WOTS_LOG_SECRETS_DEPTH 2
#endif


namespace dory::hsig {

size_t constexpr LogSecretsDepth = WOTS_LOG_SECRETS_DEPTH; /*log_w*/
size_t constexpr SecretsDepth = 1 << LogSecretsDepth; /*w*/

// Old version with security less < 128bit
// std::array<size_t, 9> constexpr PrecomputedL1 = {0,  128, 64, 43, 32,
//                                                  26, 22,  19, 16};
/*n = 128 bit*/
std::array<size_t, 7> constexpr PrecomputedL1 = {0, 128, 64, 43, 32, 26, 22};
std::array<size_t, 7> constexpr PrecomputedL2 = {0,   8,  4,  3,  3,  2,  2};
size_t constexpr L1 = PrecomputedL1[LogSecretsDepth];
size_t constexpr L2 = PrecomputedL2[LogSecretsDepth];

size_t constexpr SecretsPerSecretKey = L1 + L2; /*L*/
size_t constexpr SecretsPerSignature = SecretsPerSecretKey; /*L*/


}
