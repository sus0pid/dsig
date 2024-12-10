#ifndef HSIG_HPP
#define HSIG_HPP

#include <string>

#include "hsig-config.hpp"
#include "wots-types.hpp"

namespace dory::hsig {

class Hsig {
  /*a row of chain([sk0-skl1+l2], i)*/
  using SecretRow = std::array<Secret, SecretsPerSecretKey>;
  /*secrets: 2d array that records intermediate results in sk-->pk*/
  using Secrets = std::array<SecretRow, SecretsDepth>; /*secretdepth == w*/

 public:
  Hsig(HsigConfig const &config, int service_id);
  ~Hsig();

  // As Hsig manages a thread, it should not be moved.
//  Hsig(Hsig const &) = delete;
//  Hsig &operator=(Hsig const &) = delete;
//  Hsig(Hsig &&) = delete;
//  Hsig &operator=(Hsig &&) = delete;

  // Simplified methods
  std::string sign(const std::string &data);
  bool verify(const std::string &data, const std::string &signature);
  WotsSignature wots_sign(uint8_t const* msg, size_t const msg_len);



//  Signature sign(const uint8_t *message, size_t message_len);
//  bool verify(const uint8_t *message, size_t message_len, const Signature &sig);

//  void start_background();
//  void stop_background();

 private:
  int service_id;
  HsigConfig config;
  Secrets secrets; /*one sk(secrets.front()) + one pk(pk = secrets.back())*/
  Seed seed;

  Nonce pk_nonce; /*a nonce for pk generation*/
  Hash pk_hash; /*hash(pk)*/
  Nonce nonce; /*one unique nonce per signature*/

  std::array<uint8_t, SecretsPerSignature> msg_secret_depths;

  // pk generation
  void wots_pkgen();

  // hash pk
  void wots_pkhash();

  // unique signature nonce
  void gen_signonce();

  // calculate secret depth for given message
  void wots_msg2depth(uint8_t const* const begin, uint8_t const* const end);


//  Foreground foreground;
//  Background background;

};


} // namespace hybrid_sig

#endif // HSIG_HPP



//#pragma once
//
//#include <vector>
//#include <deque>
//#include <map>
//#include <cstdint>
//#include <mutex>
//#include <condition_variable>
//#include <thread>
//#include <atomic>
//#include <functional>
//#include <chrono>
//
//namespace hybrid_sig {
//
//// Configuration
//struct HybridSigConfig {
//  size_t key_size;               // Key size in bytes
//  size_t fetch_threshold;        // Receiver threshold for remaining PKs
//  size_t fetch_batch_size;       // Number of PKs to fetch when threshold is reached
//  std::chrono::milliseconds sender_interval; // Interval for sender's key generation
//};
//
//// Public Key and Private Key
//struct PublicKey {
//  std::vector<uint8_t> data;
//};
//
//struct PrivateKey {
//  std::vector<uint8_t> data;
//};
//
//// Signature
//struct Signature {
//  std::vector<uint8_t> data;
//};
//
//// Foreground (Sign and Verify)
//class Foreground {
// public:
//  Foreground(HybridSigConfig const &config);
//
//  Signature sign(const uint8_t *message, size_t message_len, const PrivateKey &sk);
//  bool verify(const uint8_t *message, size_t message_len, const Signature &sig, const PublicKey &pk);
//
// private:
//  HybridSigConfig config;
//};
//
//// Background (Key Management)
//class Background {
// public:
//  Background(HybridSigConfig const &config);
//  ~Background();
//
//  void start_sender_background();
//  void start_receiver_background();
//  void stop();
//
// private:
//  // Sender background task
//  void sender_loop();
//
//  // Receiver background task
//  void receiver_loop();
//
//  HybridSigConfig config;
//
//  // Shared state
//  std::deque<PublicKey> sender_pks;
//  std::deque<PrivateKey> sender_sks;
//  std::deque<PublicKey> receiver_pks;
//
//  // Synchronization
//  std::mutex sender_mutex;
//  std::condition_variable sender_cond;
//
//  std::mutex receiver_mutex;
//  std::condition_variable receiver_cond;
//
//  // Thread management
//  std::atomic<bool> running;
//  std::thread sender_thread;
//  std::thread receiver_thread;
//
//  // Simulation of Key Distribution Center interaction
//  void distribute_keys_to_kdc(const std::vector<PublicKey> &keys);
//  std::vector<PublicKey> fetch_keys_from_kdc(size_t count);
//};
//
//// Integration
//class HybridSignature {
// public:
//  HybridSignature(HybridSigConfig const &config);
//  ~HybridSignature();
//
//  Signature sign(const uint8_t *message, size_t message_len);
//  bool verify(const uint8_t *message, size_t message_len, const Signature &sig);
//
//  void start_background();
//  void stop_background();
//
// private:
//  HybridSigConfig config;
//  Foreground foreground;
//  Background background;
//};
//
//}  // namespace hybrid_sig
