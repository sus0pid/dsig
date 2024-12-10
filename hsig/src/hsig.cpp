#include <iostream>

#include <dory/crypto/hash/blake3.hpp>
#include "hsig.hpp"
#include "hash-util.hpp"
#include "random.hpp"

namespace dory::hsig {

Hsig::Hsig(HsigConfig const &config, int service_id)
    : config(config),
      seed(RandomGenerator().generate()),  // Use RandomGenerator to initialize the seed
      pk_nonce{}, pk_hash{}, nonce{}, secret_depths{} {

  std::cout << "Initializing Hsig with ServiceID: " << service_id << std::endl;
  service_id = service_id;
  wots_pkgen();
  wots_pkhash();
  gen_signonce();

}

Hsig::~Hsig() {
  std::cout << "Destroying Hsig instance." << std::endl;
}


std::string Hsig::sign(const std::string &data) {
  // Dummy implementation
  std::cout << "Signing data: " << data << std::endl;
  return "signature_" + data;
}

WotsSignature Hsig::wots_sign(uint8_t const* msg, size_t const msg_len) {
  /*Initialize the wots signature*/
  WotsSignature sig{pk_nonce, pk_sig.value(), nonce};
  /*compute the secret depths of the given message*/
  wots_msg2depth(pk_hash, nonce, msg, msg + msg_len);
  for (size_t i = 0; i < SecretsPerSignature; i++) {
    auto const secret_depth = msg_secret_depths[i];
    std::memcpy(sig.secrets[i].data(), secrets[secret_depth][i].data(), sig.secrets[i].size());
  }
  return sig;
}

bool Hsig::verify(const std::string &data, const std::string &signature) {
  // Dummy implementation
  std::cout << "Verifying data: " << data << " with signature: " << signature << std::endl;
  return signature == "signature_" + data;
}

/*generate pks from sks and store the intermediate results*/
void Hsig::wots_pkgen() {
  std::cout << "Wots key generation..." << std::endl;
  pk_nonce = sk_nonce(seed);
  secrets.front() = crypto::hash::blake3<SecretRow>(seed);
  for (size_t i = 0; i + 1 < SecretsDepth; i++) {
    if constexpr (HashingScheme == Haraka) {
      // 4x speedup
      auto const speedup_until = SecretsPerSecretKey - SecretsPerSecretKey % 4;
      for (size_t j = 0; j < speedup_until; j += 4) {
        auto& secret_hash_4x = *reinterpret_cast<SecretHash4x*>(&secrets[i + 1][j]);
        auto& secret_4x = *reinterpret_cast<Secret4x*>(&secrets[i][j]);
        secret_hash_4x = hash_secret_haraka_4x(secret_4x, pk_nonce, j, i);
      }
      for (size_t j = speedup_until; j < SecretsPerSecretKey; j++) {
        secrets[i + 1][j] = hash_secret(secrets[i][j], pk_nonce, j, i);
      }
    } else {
      for (size_t j = 0; j < SecretsPerSecretKey; j++) {
        secrets[i + 1][j] = hash_secret(secrets[i][j], pk_nonce, j, i);
      }
    }
  }
}

void Hsig::wots_pkhash() {
  std::cout << "wots hashing pk..." << std::endl;

  auto hasher = crypto::hash::blake3_init();
  crypto::hash::blake3_update(hasher, pk_nonce);
//  if constexpr (HbssScheme == HorsMerkle) {
//    crypto::hash::blake3_update(hasher, hors_pk_tree->roots());
//  } else {
  crypto::hash::blake3_update(hasher, secrets.back()); /*hash the pk*/
//  }
  pk_hash = crypto::hash::blake3_final(hasher);
}

void Hsig::gen_signonce() {
  std::cout << "wots signature nonce..." << std::endl;
  nonce = sig_nonce(seed);
}


void Hsig::wots_msg2depth(uint8_t const* const begin,
                            uint8_t const* const end) {
  // Deviation from the original WOTS: we compute a larger hash
  // and use a subset of the bits aligned on bytes.
  static_assert(LogSecretsDepth <= 8);
  std::array<uint8_t, L1> hash;
  std::array<uint8_t, 8> checksum = {};  // 8 is more than necessary

  // Computing the secret depths for L1
  auto hasher = crypto::hash::blake3_init();
  Prefix prefix = {pk_hash, nonce};
  crypto::hash::blake3_update(hasher, prefix);
  crypto::hash::blake3_update(hasher, begin, end);
  crypto::hash::blake3_final_there(hasher, hash.data(), hash.size());
  uint64_t& csum = *reinterpret_cast<uint64_t*>(checksum.data());
  for (size_t secret = 0; secret < L1; secret++) {
    static uint8_t constexpr SecretsDepthMask = SecretsDepth - 1;
    msg_secret_depths[secret] = hash[secret] & SecretsDepthMask;
    csum += msg_secret_depths[secret];
  }

  // Computing the secret depths for L2
  for (size_t secret = L1, bit_offset = 0;
       secret < SecretsPerSecretKey;
       secret++, bit_offset += LogSecretsDepth) {
    static uint16_t constexpr SecretsDepthMask = SecretsDepth - 1;
    auto const byte_offset = bit_offset / 8ul;
    auto const remaining_bit_offset = bit_offset % 8ul;
    // Due to Intel's little endianness, the initialized bytes hold the LSBs.
    // Given that C++'s shift operator work on the value and not on the memory
    // representation, we need to read the LSB
    msg_secret_depths[secret] = (*reinterpret_cast<uint16_t const*>(&checksum[byte_offset]) >>
                             remaining_bit_offset) & SecretsDepthMask;
  }
}

}

//void HybridSignature::start_background() {
//  background.start_sender_background();
//  background.start_receiver_background();
//}
//
//void HybridSignature::stop_background() {
//  background.stop();
//}

} // namespace hybrid_sig



//#include <iostream>
//#include <thread>
//#include <stdexcept>
//
//#include "hsig.hpp"
//
//namespace hybrid_sig {
//
//// Foreground Implementation
//Foreground::Foreground(HybridSigConfig const &config) : config(config) {}
//
//Signature Foreground::sign(const uint8_t *message, size_t message_len, const PrivateKey &sk) {
//  Signature sig;
//  sig.data.assign(message, message + message_len); // Placeholder signing logic
//  return sig;
//}
//
//bool Foreground::verify(const uint8_t *message, size_t message_len, const Signature &sig, const PublicKey &pk) {
//  return sig.data == std::vector<uint8_t>(message, message + message_len); // Placeholder verification logic
//}
//
//// Background Implementation
//Background::Background(HybridSigConfig const &config) : config(config), running(false) {}
//
//Background::~Background() {
//  stop();
//}
//
//void Background::start_sender_background() {
//  running = true;
//  sender_thread = std::thread([this]() { sender_loop(); });
//}
//
//void Background::start_receiver_background() {
//  running = true;
//  receiver_thread = std::thread([this]() { receiver_loop(); });
//}
//
//void Background::stop() {
//  running = false;
//  if (sender_thread.joinable()) {
//    sender_thread.join();
//  }
//  if (receiver_thread.joinable()) {
//    receiver_thread.join();
//  }
//}
//
//void Background::sender_loop() {
//  while (running) {
//    // Simulate key pair generation
//    PrivateKey sk{std::vector<uint8_t>(config.key_size, 0)};
//    PublicKey pk{std::vector<uint8_t>(config.key_size, 1)};
//
//    {
//      std::lock_guard<std::mutex> lock(sender_mutex);
//      sender_sks.push_back(sk);
//      sender_pks.push_back(pk);
//    }
//    sender_cond.notify_all();
//
//    // Distribute keys to KDC
//    distribute_keys_to_kdc({pk});
//
//    std::this_thread::sleep_for(config.sender_interval);
//  }
//}
//
//void Background::receiver_loop() {
//  while (running) {
//    {
//      std::unique_lock<std::mutex> lock(receiver_mutex);
//      if (receiver_pks.size() >= config.fetch_threshold) {
//        receiver_cond.wait_for(lock, std::chrono::milliseconds(500));
//        continue;
//      }
//    }
//
//    // Fetch keys from KDC
//    auto fetched_keys = fetch_keys_from_kdc(config.fetch_batch_size);
//
//    {
//      std::lock_guard<std::mutex> lock(receiver_mutex);
//      for (const auto &pk : fetched_keys) {
//        receiver_pks.push_back(pk);
//      }
//    }
//  }
//}
//
//void Background::distribute_keys_to_kdc(const std::vector<PublicKey> &keys) {
//  std::cout << "Distributing " << keys.size() << " keys to KDC.\n";
//}
//
//std::vector<PublicKey> Background::fetch_keys_from_kdc(size_t count) {
//  std::vector<PublicKey> keys;
//  for (size_t i = 0; i < count; ++i) {
//    keys.push_back(PublicKey{std::vector<uint8_t>(config.key_size, 1)});
//  }
//  std::cout << "Fetched " << keys.size() << " keys from KDC.\n";
//  return keys;
//}
//
//// Integration Implementation
//HybridSignature::HybridSignature(HybridSigConfig const &config)
//    : config(config), foreground(config), background(config) {}
//
//HybridSignature::~HybridSignature() {
//  stop_background();
//}
//
//Signature HybridSignature::sign(const uint8_t *message, size_t message_len) {
//  PrivateKey sk;
//  {
//    std::unique_lock<std::mutex> lock(background.sender_mutex);
//    if (background.sender_sks.empty()) {
//      throw std::runtime_error("No private keys available for signing.");
//    }
//    sk = std::move(background.sender_sks.front());
//    background.sender_sks.pop_front();
//  }
//  return foreground.sign(message, message_len, sk);
//}
//
//bool HybridSignature::verify(const uint8_t *message, size_t message_len, const Signature &sig) {
//  PublicKey pk;
//  {
//    std::unique_lock<std::mutex> lock(background.receiver_mutex);
//    if (background.receiver_pks.empty()) {
//      throw std::runtime_error("No public keys available for verification.");
//    }
//    pk = background.receiver_pks.front();
//    background.receiver_pks.pop_front();
//  }
//  return foreground.verify(message, message_len, sig, pk);
//}
//
//void HybridSignature::start_background() {
//  background.start_sender_background();
//  background.start_receiver_background();
//}
//
//void HybridSignature::stop_background() {
//  background.stop();
//}
//
//}  // namespace hybrid_sig
