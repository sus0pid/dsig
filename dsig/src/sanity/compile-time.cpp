#include <cstddef>

namespace dory::dsig::sanity {
// These should be filled by the preprocessor during compilation
// IMPORTANT: Also edit `run-time.cpp`

size_t HbssScheme = HBSS_SCHEME;
size_t HashingScheme = HASHING_SCHEME;
size_t LogInfBatchSize = LOG_INF_BATCH_SIZE;
#ifndef WOTS_LOG_SECRETS_DEPTH
#define WOTS_LOG_SECRETS_DEPTH 2
#endif
size_t WotsLogSecretsDepth = WOTS_LOG_SECRETS_DEPTH;
#ifndef HORS_SECRETS_PER_SIGNATURE
#define HORS_SECRETS_PER_SIGNATURE 19
#endif
size_t HorsSecretsPerSignature = HORS_SECRETS_PER_SIGNATURE;
}  // namespace dory::dsig::sanity
