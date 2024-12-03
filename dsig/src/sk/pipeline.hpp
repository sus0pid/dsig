#pragma once

#include <array>
#include <atomic>
#include <deque>
#include <exception>
#include <map>
#include <memory>
#include <optional>
#include <vector>

#include <dory/shared/logger.hpp>
#include <dory/shared/types.hpp>

#include "../config.hpp"
#include "../mutex.hpp"
#include "../network.hpp"
#include "../pk/pk.hpp"
#include "../types.hpp"
#include "../workers.hpp"
#include "random.hpp"
#include "sk.hpp"

namespace dory::dsig {

class SkPipeline {
 protected:
  class SigningBatch {
   public:
    static size_t constexpr Size = InfBatchSize;
    enum State {
      Initialized,
      Computed,
    };
    std::array<std::unique_ptr<SecretKey>, Size> sks;
    Delayed<BatchMerkleTree> tree;
    BgPublicKeys::Compressed to_send;
    std::atomic<State> state{Initialized};
    void schedule(Workers& workers, InfCrypto& inf_crypto) {
      workers.schedule([this, &inf_crypto] {
        sign(inf_crypto);
        #if HBSS_SCHEME == HORS_MERKLE
        for (size_t sk_idx = 0; sk_idx < Size; sk_idx++) {
          to_send.hors_pk_leaves.at(sk_idx) = sks.at(sk_idx)->getPk();
        }
        #endif
      });
    }
   private:
    /*eddsa sign the merkle tree root*/
    void sign(InfCrypto& inf_crypto) {
      for (size_t i = 0; i < Size; i++)
        to_send.pk_hashes[i] = sks[i]->getPkHash();
      tree.emplace(to_send.pk_hashes);
      to_send.root_sig = inf_crypto.sign(reinterpret_cast<uint8_t const*>(tree->root().data()), tree->root().size());
      for (size_t i = 0; i < Size; i++)
        sks[i]->pk_sig.emplace(to_send.pk_hashes[i], tree.value(), i, to_send.root_sig);
      state = Computed;
    }
  };
 public:
  SkPipeline(Network& net, InfCrypto& inf, Workers& workers)
      : net{net}, inf_crypto{inf}, workers{workers} { }

  SkPipeline(SkPipeline const&) = delete;
  SkPipeline& operator=(SkPipeline const&) = delete;
  SkPipeline(SkPipeline&&) = delete;
  SkPipeline& operator=(SkPipeline&&) = delete;

  void tick() {
    schedule_new_sks();
    batch_sign_computed_sks();
    send_signed_sks();
  }

  std::unique_ptr<SecretKey> extract_ready() {
    std::scoped_lock<Mutex> lock(ready_sks_mutex);
    if (ready_sks.empty()) {
      return nullptr;
    }
    auto sk = std::move(ready_sks.front());
    ready_sks.pop_front();
    // fmt::print("Sk popped: #ready_sks={}\n", ready_sks.size());
    return sk;
  }

 protected:
  void schedule_new_sks() {
    while (initializing_sks.size() != PreparedSks) {
      auto seed = seed_generator.generate();
      initializing_sks.emplace_back(std::make_unique<SecretKey>(seed, workers));
      // fmt::print("Sk emplaced: #initializing_sks={}\n", initializing_sks.size());
    }
  }

  void batch_sign_computed_sks() {
    while (true) {
      if (sks_batchs.size() * InfBatchSize >= PreparedSks) return;
      // Count the prefix so that they are all initialized
      size_t done = 0;
      for (auto& sk : initializing_sks) {
        if (sk->state == SecretKey::State::Initializing) break;
        done++;
        if (done == InfBatchSize) break;
      }
      if (done < InfBatchSize) break;
      // The first InfBatchSize sks are all initialized
      sks_batchs.emplace_back();
      for (size_t i = 0; i < InfBatchSize; i++) {
        sks_batchs.back().sks[i] = std::move(initializing_sks.front());
        initializing_sks.pop_front();
      }
      // fmt::print("Sks moved to batch: #initializing_sks={}, #sks_batchs={}\n", initializing_sks.size(), sks_batchs.size());
      sks_batchs.back().schedule(workers, inf_crypto);
    }
  }

  void send_signed_sks() {
    while (!sks_batchs.empty() && sks_batchs.front().state == SigningBatch::State::Computed) {
      if (ready_sks.size() >= PreparedSks) return;
      auto& batch = sks_batchs.front();
      net.send(batch.to_send);
      std::scoped_lock<Mutex> lock(ready_sks_mutex);
      for (auto& sk : batch.sks)
        ready_sks.push_back(std::move(sk));
      sks_batchs.pop_front();
      // fmt::print("Sks moved to ready:#sks_batchs={}, #ready_sks={}\n", sks_batchs.size(), ready_sks.size());
    }
  }

  std::deque<std::unique_ptr<SecretKey>> initializing_sks;
  std::deque<SigningBatch> sks_batchs;
  std::deque<std::unique_ptr<SecretKey>> ready_sks;
  Mutex ready_sks_mutex;

  Network& net;
  InfCrypto& inf_crypto;
  Workers& workers;
  RandomGenerator seed_generator;

  LOGGER_DECL_INIT(logger, "Dsig::SkPipeline");
};

}  // namespace dory::dsig
