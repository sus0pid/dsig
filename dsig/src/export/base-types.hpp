#pragma once

#include <array>

namespace dory::dsig {

using ProcId = int;
using Hash = std::array<uint8_t, 32>;
using HalfHash = std::array<uint8_t, 16>;

}  // namespace dory::dsig
