#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>

#include <dory/conn/ud.hpp>
#include <dory/ctrl/block.hpp>
#include <dory/ctrl/device.hpp>
#include <dory/memory/pool/pool-allocator.hpp>
#include <dory/shared/dynamic-bitset.hpp>
#include <dory/shared/logger.hpp>

#include "mutex.hpp"
#include "network.hpp"
#include "parser.hpp"
#include "pk/pipeline.hpp"
#include "pk-cache.hpp"
#include "sk/pipeline.hpp"
#include "sk/sk.hpp"
#include "types.hpp"
#include "workers.hpp"

namespace dory::dsig {

class DsigInit {
  LOGGER_DECL_INIT(logger, "Dsig::Init");

  ctrl::OpenDevice open_device;
  ctrl::ResolvedPort resolved_port;
  ctrl::ControlBlock control_block;

 public:
  DsigInit(std::string const &dev_name);

 private:
  ctrl::OpenDevice get_device(std::string const &dev_name);
  ctrl::ControlBlock build_block(std::string const &dev_name,
                                 ctrl::OpenDevice open_dev,
                                 ctrl::ResolvedPort reslv_port);

 public:
  ctrl::ControlBlock *operator->() { return &control_block; }
  ctrl::ControlBlock &operator*() { return control_block; }
};

class Dsig {
 public:
  Dsig(ProcId id);
  ~Dsig();

  // As Dsig manages a thread, it should not be moved.
  Dsig(Dsig const &) = delete;
  Dsig &operator=(Dsig const &) = delete;
  Dsig(Dsig &&) = delete;
  Dsig &operator=(Dsig &&) = delete;

  void sign(Signature &sig, uint8_t const *m, size_t mlen);
  bool verify(Signature const &sig, uint8_t const *m, size_t mlen, ProcId pid);
  std::optional<bool> try_fast_verify(Signature const &sig, uint8_t const *m,
                                      size_t mlen, ProcId pid);

  bool slow_verify(HorsMerkleSignature const &sig, uint8_t const *m, size_t mlen,
                   ProcId pid);

  bool slow_verify(HorsCompletedSignature const &sig, uint8_t const *m, size_t mlen,
                   ProcId pid);

  bool slow_verify(WotsSignature const &sig, uint8_t const *m, size_t mlen,
                   ProcId pid);

  void enable_slow_path(bool const enable) { slow_path = enable; }

  void prefetch_sk();

  void prefetch_pk(ProcId const pid);

  bool replenished_sks(size_t replenished = PreparedSks);

  bool replenished_pks(ProcId const pid, size_t replenished = PreparedSks);

 private:
  RuntimeConfig config;
  InfCrypto inf;
  DsigInit cb;
  Network net;

  // Scheduling thread logic
  void scheduling_loop();
  Workers workers;

  PkPipeline pk_pipeline;
  void fetch_ready_pks();

  SkPipeline sk_pipeline;
  void fetch_ready_sks();

  // Scheduling thread control
  std::thread scheduler;
  void stop_scheduler() {
    stop = true;
    scheduler.join();
  }
  std::atomic<bool> stop = false;

  // Keys exposed to the application threads via sign/verify
  std::map<ProcId, PkCache> public_keys;
  Mutex pk_mutex;
  std::deque<std::unique_ptr<SecretKey>> secret_keys;
  Mutex sk_mutex;
  std::condition_variable_any sk_cond_var;

  bool slow_path = false;

  LOGGER_DECL_INIT(logger, "Dsig");
};
}  // namespace dory::dsig
