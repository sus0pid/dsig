#include <iostream>
#include <chrono>
#include <string>
#include <vector>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <fmt/core.h>

#include <dory/crypto/asymmetric/switchable-crypto.hpp>
#include "../hsig.hpp"

using namespace dory;
using namespace hsig;
using namespace crypto;

template <typename F>
std::vector<long long> benchmark(size_t iterations, F function) {
  std::vector<long long> times;
  times.reserve(iterations);

  for (size_t i = 0; i < iterations; ++i) {
    auto start = std::chrono::steady_clock::now();
    function();
    auto end = std::chrono::steady_clock::now();

    times.push_back(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());
  }
  return times;
}

template <typename T>
void print_statistics(const std::string& label, const std::vector<T>& times) {
  if (times.empty()) {
    std::cerr << "No data to compute statistics for " << label << std::endl;
    return;
  }

  auto sum = std::accumulate(times.begin(), times.end(), 0LL);
  auto average = static_cast<double>(sum) / static_cast<double>(times.size());
  auto min_time = *std::min_element(times.begin(), times.end());
  auto max_time = *std::max_element(times.begin(), times.end());

  double variance = 0.0;
  for (auto time : times) {
    variance += (static_cast<double>(time) - average) * (static_cast<double>(time) - average);
  }
  variance /= static_cast<double>(times.size());
  double stddev = std::sqrt(variance);

  std::cout << label << " Statistics:\n";
  std::cout << "  Average: " << average << " microseconds\n";
  std::cout << "  Min: " << min_time << " microseconds\n";
  std::cout << "  Max: " << max_time << " microseconds\n";
  std::cout << "  Std Dev: " << stddev << " microseconds\n";
}

int main() {
  HsigConfig config;
  config.key_size = 32; // Example key size in bytes
  config.fetch_threshold = 10; // Receiver PK threshold
  config.fetch_batch_size = 20; // Number of PKs to fetch
  config.sender_interval = std::chrono::milliseconds(100); // 100ms interval

  // Start a memcache instance
  auto& store = dory::memstore::MemoryStore::getInstance();

  // Example arguments for DilithiumCrypto
  ProcId local_id = 1; // Example local process ID
  std::vector<ProcId> all_ids = {1}; // Example list of process IDs
  InfCrypto crypto(local_id, all_ids); // Dilithium crypto

  Hsig hsig(config, local_id, crypto);
  std::string data = "Test message";
  uint8_t const* msg = reinterpret_cast<const uint8_t*>(data.data());
  size_t msg_len = data.size();

  size_t iterations = 1000;

  // Benchmarking wots_sign
  auto sign_times = benchmark(iterations, [&]() {
    hsig.wots_sign(msg, msg_len);
  });
  print_statistics("wots_sign", sign_times);

  // Generate a WOTS signature for verification benchmarking
  WotsSignature w_sig = hsig.wots_sign(msg, msg_len);

  // Benchmarking wots_verify
  auto verify_times = benchmark(iterations, [&]() {
    hsig.wots_verify(w_sig, msg, msg + msg_len);
  });
  print_statistics("wots_verify", verify_times);

  return 0;
}
