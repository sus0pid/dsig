#include "hsig.hpp"

int main() {
  hybrid_sig::HybridSigConfig config{256, 5, 10, std::chrono::milliseconds(1000)};
  hybrid_sig::HybridSignature hs(config);

  hs.start_background();

  const uint8_t message[] = "Hello, World!";
  auto signature = hs.sign(message, sizeof(message));
  bool valid = hs.verify(message, sizeof(message), signature);

  std::cout << "Signature valid: " << std::boolalpha << valid << "\n";

  hs.stop_background();

  return 0;
}
