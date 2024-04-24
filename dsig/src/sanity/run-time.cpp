#include <cstddef>
#include <stdexcept>

#include "../config.hpp"
#include "check.hpp"

namespace dory::dsig::sanity {
// These should be filled by the preprocessor during compilation
extern size_t HbssScheme;
extern size_t HashingScheme;
extern size_t LogInfBatchSize;
extern size_t WotsLogSecretsDepth;
extern size_t HorsSecretsPerSignature;

void check() {
  if (HbssScheme != HBSS_SCHEME
    || HashingScheme != HASHING_SCHEME
    || LogInfBatchSize != LOG_INF_BATCH_SIZE
    || WotsLogSecretsDepth != WOTS_LOG_SECRETS_DEPTH
    || HorsSecretsPerSignature != HORS_SECRETS_PER_SIGNATURE) {
    throw std::logic_error(
        "Mismatch of compile-time config vs run-time config of header files");
  }
}
}  // namespace dory::dsig::sanity
