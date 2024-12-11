#include <iostream>
#include <chrono>
#include <string>

#include <dory/crypto/asymmetric/switchable-crypto.hpp>

#include "../hsig.hpp"

using namespace dory;
using namespace hsig;
using namespace crypto;

int main() {

  HsigConfig config;
  config.key_size = 32; // Example key size in bytes
  config.fetch_threshold = 10; // Receiver PK threshold
  config.fetch_batch_size = 20; // Number of PKs to fetch
  config.sender_interval = std::chrono::milliseconds(100); // 100ms interval

  /*start a memcache instance*/
  auto& store = dory::memstore::MemoryStore::getInstance();

  // Example arguments for DilithiumCrypto
  ProcId local_id = 1; // Example local process ID
  std::vector<ProcId> all_ids = {1, 2, 3}; // Example list of process IDs
  InfCrypto crypto(local_id, all_ids); // dilithium crypto

  Hsig hsig(config, local_id, crypto);

  std::string data = "Test message";
  std::string signature = hsig.sign(data);

  if (hsig.verify(data, signature)) {
    std::cout << "Verification succeeded!" << std::endl;
  } else {
    std::cout << "Verification failed!" << std::endl;
  }

  uint8_t const* msg = reinterpret_cast<const uint8_t*>(data.data());
  size_t msg_len = data.size();
  WotsSignature w_sig = hsig.wots_sign(msg, msg_len);
  for (size_t i = 0; i < SecretsPerSignature; i++) {
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
