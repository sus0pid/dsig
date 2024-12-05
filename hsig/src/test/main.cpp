#include <iostream>
#include <chrono>
#include <string>
#include "../hsig.hpp"

int main() {

  dory::hsig::HsigConfig config;
  config.key_size = 32; // Example key size in bytes
  config.fetch_threshold = 10; // Receiver PK threshold
  config.fetch_batch_size = 20; // Number of PKs to fetch
  config.sender_interval = std::chrono::milliseconds(100); // 100ms interval
  int service_id = 42;

  dory::hsig::Hsig hsig(config, service_id);

  std::string data = "Test message";
  std::string signature = hsig.sign(data);

  if (hsig.verify(data, signature)) {
    std::cout << "Verification succeeded!" << std::endl;
  } else {
    std::cout << "Verification failed!" << std::endl;
  }

  return 0;
}



//#include <iostream>
//
//#include "../hsig.hpp"
//
//int main() {
//  hybrid_sig::HybridSigConfig config{256, 5, 10, std::chrono::milliseconds(1000)};
//  hybrid_sig::HybridSignature hs(config);
//
//  hs.start_background();
//
//  const uint8_t message[] = "Hello, World!";
//  auto signature = hs.sign(message, sizeof(message));
//  bool valid = hs.verify(message, sizeof(message), signature);
//
//  std::cout << "Signature valid: " << std::boolalpha << valid << "\n";
//
//  hs.stop_background();
//
//  return 0;
//}
