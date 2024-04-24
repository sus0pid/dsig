#include <atomic>
#include <fstream>
#include <stdexcept>

#include <dory/crypto/hash/blake3.hpp>

#include "../types.hpp"

namespace dory::dsig {

class RandomGenerator {
 public:
  RandomGenerator() {
    std::ifstream random(dev, std::ios::in | std::ios::binary);
    random.read(reinterpret_cast<char*>(seed.data()), sizeof(seed));
    if (!random) {
      throw std::runtime_error("Could not initialize the random seed!");
    }
  }

  Seed generate() {
    auto hasher = crypto::hash::blake3_init();
    crypto::hash::blake3_update(hasher, generated++);
    crypto::hash::blake3_update(hasher, seed);
    return crypto::hash::blake3_final<Seed>(hasher);
  }

 private:
  Seed seed;
  std::atomic<size_t> generated{0};
  static constexpr char const* dev = "/dev/random";
};

}  // namespace dory::dsig
