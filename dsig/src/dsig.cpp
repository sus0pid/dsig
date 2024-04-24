#include <algorithm>
#include <chrono>
#include <iostream>
#include <memory>
#include <optional>
#include <string>

#include <fmt/core.h>

#include <dory/conn/ud.hpp>
#include <dory/crypto/hash/blake3.hpp>
#include <dory/ctrl/block.hpp>
#include <dory/ctrl/device.hpp>
#include <dory/shared/pinning.hpp>

#include "mutex.hpp"
#include "network.hpp"
#include "pinning.hpp"
#include "dsig.hpp"
#include "sanity/check.hpp"
#include "util.hpp"

namespace dory::dsig {

DsigInit::DsigInit(std::string const &dev_name)
    : open_device{get_device(dev_name)},
      resolved_port{open_device},
      control_block{build_block(dev_name, open_device, resolved_port)} {
  LOGGER_INFO(
    logger,
    "HBSS Scheme: {}, sig size: {}B, secrets/sig: {}, "
    "bg traffic: {}B/batch, prepared SK: {}",
    Signature::Scheme, sizeof(Signature), SecretsPerSignature,
    sizeof(BgPublicKeys::Compressed), PreparedSks);
}

ctrl::OpenDevice DsigInit::get_device(std::string const &dev_name) {
  bool device_found = false;

  ctrl::Devices d;
  ctrl::OpenDevice open_dev;
  for (auto &dev : d.list()) {
    if (dev_name == std::string(dev.name())) {
      open_dev = std::move(dev);
      device_found = true;
      break;
    }
  }

  if (!device_found) {
    LOGGER_ERROR(logger,
                 "Could not find the RDMA device {}. Run `ibv_devices` to get "
                 "the device names.",
                 dev_name);
    std::abort();
  }

  LOGGER_INFO(logger, "Device: {} / {}, {}, {}", open_dev.name(),
              open_dev.devName(),
              ctrl::OpenDevice::typeStr(open_dev.nodeType()),
              ctrl::OpenDevice::typeStr(open_dev.transportType()));

  return open_dev;
}

ctrl::ControlBlock DsigInit::build_block(std::string const &dev_name,
                                         ctrl::OpenDevice open_dev,
                                         ctrl::ResolvedPort reslv_port) {
  size_t binding_port = 0;
  LOGGER_INFO(logger, "Binding to port {} of opened device {}", binding_port,
              open_dev.name());

  auto binded = reslv_port.bindTo(binding_port);

  if (!binded) {
    LOGGER_ERROR(logger, "Could not bind the RDMA device {}", dev_name);
    std::abort();
  }

  LOGGER_INFO(logger, "Binded successfully (port_id, port_lid) = ({}, {})",
              +resolved_port.portId(), +resolved_port.portLid());

  LOGGER_INFO(logger, "Configuring the control block");
  return ctrl::ControlBlock(reslv_port);
}

Dsig::Dsig(ProcId id)
    : config(id),
      inf(config.myId(), config.allIds()),
      cb{config.deviceName()},
      net{*cb, config.myId(), config.remoteIds(), config.verifierIds()},
      pk_pipeline{net, inf, workers},
      sk_pipeline{net, inf, workers} {
  // Check that the macro config matches the compilation config
  sanity::check();

  // Create a list of verified pks for each id
  for (auto const id : config.remoteIds()) {
    public_keys.try_emplace(id);
  }

  scheduler = std::thread([this]() { this->scheduling_loop(); });
  auto const thread_name("bg");
  set_thread_name(scheduler, thread_name);
  if (auto const core = get_core(thread_name)) {
    pin_thread_to_core(scheduler, *core);
  }
}

Dsig::~Dsig() { stop_scheduler(); }

void Dsig::sign(Signature &sig, uint8_t const *const m, size_t const mlen) {
  std::unique_lock<Mutex> lock(sk_mutex);
  LOGGER_TRACE(logger, "{} SKs available.", secret_keys.size());
  // sk_cond_var.wait(lock, [this]() { return !secret_keys.empty(); });
  while (secret_keys.empty()) {
    sk_mutex.unlock();
    busy_sleep(std::chrono::nanoseconds(100));
    sk_mutex.lock();
  }
  auto &sk = secret_keys.front();
  sig = sk->sign(m, mlen);
  secret_keys.pop_front();
}

bool Dsig::verify(Signature const &sig, uint8_t const *const m,
                  size_t const mlen, ProcId const pid) {
  while (true) {
    auto const fast_verif = try_fast_verify(sig, m, mlen, pid);
    if (likely(fast_verif)) {
      return *fast_verif;
    }
    if (slow_path) {
      LOGGER_WARN(logger, "No PK available for {}: slow verification.", pid);
      return slow_verify(sig, m, mlen, pid);
    }
    // We repeat until we can verify.
    // TODO: spin a bit to improve the latency percentiles as it helps
    // rebuilding the PK cache.
  }
}

std::optional<bool> Dsig::try_fast_verify(Signature const &sig,
                                          uint8_t const *const m,
                                          size_t const mlen, ProcId const pid) {
  // Try to find a matching PK to fast verify the signature.
  if (likely(pid == config.myId()))
    throw std::runtime_error("Attempt to fast verify own signature.");

  std::scoped_lock<Mutex> lock(pk_mutex);
  LOGGER_TRACE(logger, "{} PKs available for process {}.",
                public_keys[pid].size(), pid);
  auto opt_pks = public_keys[pid].associatedTo(sig);
  if (likely(opt_pks)) {
    auto& pks = opt_pks->get();
    return pks.verify(sig, m, mlen);
  }

  // The public key is not available, thus we abort the verification.
  return std::nullopt;
}

bool Dsig::slow_verify(HorsMerkleSignature const &sig, uint8_t const *const m,
                       size_t const mlen, ProcId const pid) {
  throw std::runtime_error("Unimplemented Dsig::slow_verify(HorsMerkleSignature)");
}

bool Dsig::slow_verify(HorsCompletedSignature const &sig, uint8_t const *const m,
                       size_t const mlen, ProcId const pid) {
  throw std::runtime_error("Unimplemented Dsig::slow_verify(HorsCompletedSignature)");
}

bool Dsig::slow_verify(WotsSignature const &sig, uint8_t const *const m,
                       size_t const mlen, ProcId const pid) {
  auto const& pk_hash = sig.pk_sig.signed_hash;

  // 1. Verify the Inf signature.
  if (!inf.verify(sig.pk_sig, pid)) {
    LOGGER_WARN(logger, "Invalid Inf batched sig.");
    return false;
  }

  // 2. Verify WOST secrets (i.e., that the right secrets were revealed).
  auto sig_hashes = sig.secrets;

  WotsHash h(pk_hash, sig.nonce, m, m + mlen);

  for (size_t secret = 0; secret < SecretsPerSignature; secret++) {
    auto const depth = h.getSecretDepth(secret);
    for (size_t d = h.getSecretDepth(secret); d < SecretsDepth - 1; d++) {
      sig_hashes[secret] = hash_secret(sig_hashes[secret], sig.pk_nonce, secret, d);
    }
  }

  auto hasher = crypto::hash::blake3_init();
  crypto::hash::blake3_update(hasher, sig.pk_nonce);
  crypto::hash::blake3_update(hasher, sig_hashes);
  return crypto::hash::blake3_final(hasher) == pk_hash;
}

void Dsig::scheduling_loop() {
  while (!stop) {
    net.tick();
    pk_pipeline.tick();
    fetch_ready_pks();
    sk_pipeline.tick();
    fetch_ready_sks();
  }
}

void Dsig::prefetch_sk() {
  std::unique_lock<Mutex> lock(sk_mutex);
  if (secret_keys.empty()) return;
  secret_keys.front()->prefetch();
}

void Dsig::prefetch_pk(ProcId const pid) {
  std::scoped_lock<Mutex> lock(pk_mutex);
  public_keys.at(pid).prefetch();
}

void Dsig::fetch_ready_pks() {
  while (auto opt_id_pks = pk_pipeline.extract_ready()) {
    auto& [id, pks] = opt_id_pks.value();
    std::scoped_lock<Mutex> lock(pk_mutex);
    public_keys[id].emplaceBack(std::move(pks));
  }
}

void Dsig::fetch_ready_sks() {
  // Move the sks that are ready (they should mostly get ready in order).
  std::scoped_lock<Mutex> lock(sk_mutex);
  while (secret_keys.size() < PreparedSks) {
    auto sk = sk_pipeline.extract_ready();
    if (!sk) return;
    secret_keys.emplace_back(std::move(sk));
    sk_cond_var.notify_all();
  }
}

bool Dsig::replenished_sks(size_t const replenished) {
  std::scoped_lock<Mutex> lock(sk_mutex);
  return secret_keys.size() >= replenished;
}

bool Dsig::replenished_pks(ProcId const pid, size_t const replenished) {
  auto const& verifiers = config.verifierIds();
  if (std::find(verifiers.begin(), verifiers.end(), config.myId()) == verifiers.end())
    return true; // not a verifier, nothing to replenish
  auto const& signers = config.signerIds();
  if (std::find(signers.begin(), signers.end(), pid) == signers.end())
    return true; // pid is no signer, nothing to replenish
  std::scoped_lock<Mutex> lock(pk_mutex);
  return public_keys[pid].virgins() >= replenished;
}

}  // namespace dory::dsig
