#include <iostream>
#include <chrono>
#include <string>
#include "../hsig.hpp"

#define HASHING_SCHEME 0 /*set to blake3*/
#define WOTS_LOG_SECRETS_DEPTH 2 /*w = 4*/

int main() {

  HsigConfig config;
  config.key_size = 32; // Example key size in bytes
  config.fetch_threshold = 10; // Receiver PK threshold
  config.fetch_batch_size = 20; // Number of PKs to fetch
  config.sender_interval = std::chrono::milliseconds(100); // 100ms interval
  int service_id = 42;

  hsig::Hsig hsig(config, service_id);

  std::string data = "Test message";
  std::string signature = hsig.sign(data);

  if (hsig.verify(data, signature)) {
    std::cout << "Verification succeeded!" << std::endl;
  } else {
    std::cout << "Verification failed!" << std::endl;
  }

  // Test PK generation
  std::cout << "Generating PK..." << std::endl;
  hsig.wots_pkgen();

  // Test PK hashing
  std::cout << "Hashing PK..." << std::endl;
  hsig.wots_pkhash();

  // Test nonce generation for signing
  std::cout << "Generating signing nonce..." << std::endl;
  hsig.gen_signonce();

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
