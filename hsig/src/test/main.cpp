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

  // Example arguments for DilithiumCrypto
  dory::hsig::ProcId local_id = 1; // Example local process ID
  std::vector<dory::hsig::ProcId> all_ids = {1, 2, 3}; // Example list of process IDs
  dory::hsig::InfCrypto crypto(local_id, all_ids); // dilithium crypto

  dory::hsig::Hsig hsig(config, local_id, crypto);

  std::string data = "Test message";
  std::string signature = hsig.sign(data);

  if (hsig.verify(data, signature)) {
    std::cout << "Verification succeeded!" << std::endl;
  } else {
    std::cout << "Verification failed!" << std::endl;
  }

  uint8_t const* msg = reinterpret_cast<const uint8_t*>(data.data());
  size_t msg_len = data.size();
  dory::hsig::WotsSignature w_sig = hsig.wots_sign(msg, msg_len);
  for (size_t i = 0; i < dory::hsig::SecretsPerSignature; i++) {
    std::cout << "Secret " << i << ": ";
    for (auto byte : w_sig.secrets[i]) {
      std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;
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
