#ifndef HSIG_HSIG_TYPES_HPP
#define HSIG_HSIG_TYPES_HPP

#include <array>
#include <chrono>


namespace dory::hsig {

  // Configuration
  struct HsigConfig {
    size_t key_size;         // Key size in bytes
    size_t fetch_threshold;  // Receiver threshold for remaining PKs
    size_t fetch_batch_size;  // Number of PKs to fetch when threshold is reached
    std::chrono::milliseconds sender_interval;  // Interval for sender's key generation
  };

  using ProcId = int;
  using Hash = std::array<uint8_t, 32>;
  using HalfHash = std::array<uint8_t, 16>;

}
#endif  // HSIG_HSIG_TYPES_HPP
