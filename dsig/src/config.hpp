#pragma once

#include "export/config.hpp"

namespace dory::dsig {

char constexpr nspace[] = "dsig-";

size_t constexpr CachedPkBatchesPerProcess = 8 * PreparedSks / InfBatchSize;

}  // namespace dory::dsig
