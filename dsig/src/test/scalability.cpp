#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <optional>
#include <random>
#include <thread>
#include <vector>

#include <fmt/chrono.h>
#include <fmt/core.h>
#include <lyra/lyra.hpp>
#include <hipony/enumerate.hpp>

#include <dory/crypto/asymmetric/switchable-crypto.hpp>
#include <dory/shared/logger.hpp>
#include <dory/shared/pinning.hpp>
#include <dory/shared/types.hpp>
#include <dory/shared/units.hpp>
#include <dory/shared/unused-suppressor.hpp>

#include "../dsig.hpp"

#include "common/helpers.hpp"
#include "common/p2p.hpp"
#include "common/measurements.hpp"
#include "common/path.hpp"
#include "common/requests.hpp"
#include "common/signed-message.hpp"

using namespace dory;
using namespace dsig;
using namespace crypto;

using ProcId = int;
using Clock = std::chrono::steady_clock;

enum Role { Signer, Verifier };

static bool run_test(Role const role, size_t& dummy_msg, size_t const pings,
                     size_t const msg_size, P2p& p2p, Dsig& dsig,
                     Requests& reqs, Path const path,
                     std::chrono::seconds const timeout,
                     std::vector<ProcId> const& signers,
                     std::vector<ProcId> const& verifiers) {
  auto& senders = p2p.senders;
  auto& receivers = p2p.receivers;

  std::vector<std::reference_wrapper<tail_p2p::Receiver>> verif_receivers;
  std::vector<std::reference_wrapper<tail_p2p::Sender>> verif_senders;
  for (auto const [idx, id] : hipony::enumerate(p2p.remote_ids)) {
    if (std::find(verifiers.begin(), verifiers.end(), id) == verifiers.end())
      continue; // No verifier
    verif_receivers.emplace_back(receivers.at(idx));
    verif_senders.emplace_back(senders.at(idx));
  }

  std::vector<std::reference_wrapper<tail_p2p::Receiver>> signer_receivers;
  std::vector<std::reference_wrapper<tail_p2p::Sender>> signer_senders;
  for (auto const [idx, id] : hipony::enumerate(p2p.remote_ids)) {
    if (std::find(signers.begin(), signers.end(), id) == signers.end())
      continue; // No verifier
    signer_receivers.emplace_back(receivers.at(idx));
    signer_senders.emplace_back(senders.at(idx));
  }

  size_t done = 0;
  std::vector<uint8_t> msg_buffer;
  msg_buffer.resize(SignedMessage::size(msg_size));
  auto& sm = *reinterpret_cast<SignedMessage*>(msg_buffer.data());

  auto const nb_signers = signers.size();
  auto const nb_verifiers = verifiers.size();
  auto const start = std::chrono::steady_clock::now();

  if (role == Signer) {
    size_t sent{0};
    // Master: signer + measurer
    while (done < pings * nb_verifiers) {
      if (sent < pings && reqs.poll()) {
        // fmt::print("Should send a sig!\n");
        sm.local_sign = sm.fill(dummy_msg++, msg_size, dsig);
        for (auto sender : verif_senders) {
          auto* const slot =
              sender.get().getSlot(static_cast<tail_p2p::Size>(msg_buffer.size()));
          memcpy(slot, &sm, msg_buffer.size());
          sender.get().send();
        }
        sent++;
      }
      for (auto [idx, receiver] : hipony::enumerate(verif_receivers)) {
        if (auto polled = receiver.get().poll()) {
          auto& sm = *reinterpret_cast<SignedMessage const*>(polled->msg());
          reqs.done(idx, Requests::Measure{sm.local_sign, sm.remote_verify});
          done++;
        }
      }
      for (auto& sender : senders) {
        sender.tick();
      }
      if (std::chrono::steady_clock::now() - start > timeout) {
        return true;
      }
    }
  } else {
    // Slave: verify + ack
    while (done < pings * nb_signers) {
      for (auto [idx, receiver] : hipony::enumerate(signer_receivers)) {
        if (auto polled = receiver.get().poll()) {
          auto& sm1 = *reinterpret_cast<SignedMessage const*>(polled->msg());
          auto const verify_start = std::chrono::steady_clock::now();
          sm1.verify(msg_size, dsig, path, receiver.get().procId());
          auto const verify_end = std::chrono::steady_clock::now();
          auto& sender = signer_senders.at(idx).get();
          auto& sm2 = *reinterpret_cast<SignedMessage*>(sender.getSlot(
              static_cast<tail_p2p::Size>(SignedMessage::tput_pong_size())));
          sm2.local_sign = sm1.local_sign;
          sm2.remote_verify = verify_end - verify_start;
          sender.send();
          done++;
        }
      }
      for (auto& sender : signer_senders) {
        sender.get().tick();
      }
      if (std::chrono::steady_clock::now() - start > timeout) {
        return true;
      }
    }
  }
  return false;
}

static bool run_test_inf(Role const role, size_t& dummy_msg, size_t const pings,
                     size_t const msg_size, P2p& p2p,
                     asymmetric::AsymmetricCrypto& crypto,
                     std::vector<asymmetric::AsymmetricCrypto::PublicKey>& signer_pks,
                     bool const bypass,
                     Requests& reqs,
                     std::chrono::seconds const timeout,
                     std::vector<ProcId> const& signers,
                     std::vector<ProcId> const& verifiers) {
  auto& senders = p2p.senders;
  auto& receivers = p2p.receivers;

  std::vector<std::reference_wrapper<tail_p2p::Receiver>> verif_receivers;
  std::vector<std::reference_wrapper<tail_p2p::Sender>> verif_senders;
  for (auto const [idx, id] : hipony::enumerate(p2p.remote_ids)) {
    if (std::find(verifiers.begin(), verifiers.end(), id) == verifiers.end())
      continue; // No verifier
    verif_receivers.emplace_back(receivers.at(idx));
    verif_senders.emplace_back(senders.at(idx));
  }

  std::vector<std::reference_wrapper<tail_p2p::Receiver>> signer_receivers;
  std::vector<std::reference_wrapper<tail_p2p::Sender>> signer_senders;
  for (auto const [idx, id] : hipony::enumerate(p2p.remote_ids)) {
    if (std::find(signers.begin(), signers.end(), id) == signers.end())
      continue; // No verifier
    signer_receivers.emplace_back(receivers.at(idx));
    signer_senders.emplace_back(senders.at(idx));
  }

  size_t done = 0;
  std::vector<uint8_t> msg_buffer;
  msg_buffer.resize(InfMessage::size(msg_size));
  auto& sm = *reinterpret_cast<InfMessage*>(msg_buffer.data());

  auto const nb_signers = signers.size();
  auto const nb_verifiers = verifiers.size();
  auto const start = std::chrono::steady_clock::now();

  if (role == Signer) {
    size_t sent{0};
    // Master: signer + measurer
    while (done < pings * nb_verifiers) {
      if (sent < pings && reqs.poll()) {
        // fmt::print("Should send a sig!\n");
        sm.local_sign = sm.fill(dummy_msg++, msg_size, crypto, bypass);
        for (auto sender : verif_senders) {
          auto* const slot =
              sender.get().getSlot(static_cast<tail_p2p::Size>(msg_buffer.size()));
          memcpy(slot, &sm, msg_buffer.size());
          sender.get().send();
        }
        sent++;
      }
      for (auto [idx, receiver] : hipony::enumerate(verif_receivers)) {
        if (auto polled = receiver.get().poll()) {
          auto& sm = *reinterpret_cast<InfMessage const*>(polled->msg());
          reqs.done(idx, Requests::Measure{sm.local_sign, sm.remote_verify});
          done++;
        }
      }
      for (auto& sender : senders) {
        sender.tick();
      }
      if (std::chrono::steady_clock::now() - start > timeout) {
        return true;
      }
    }
  } else {
    // Slave: verify + ack
    while (done < pings * nb_signers) {
      for (auto [idx, receiver] : hipony::enumerate(signer_receivers)) {
        if (auto polled = receiver.get().poll()) {
          auto& sm1 = *reinterpret_cast<InfMessage const*>(polled->msg());
          auto const verify_start = std::chrono::steady_clock::now();
          sm1.verify(msg_size, crypto, signer_pks.at(idx), bypass);
          auto const verify_end = std::chrono::steady_clock::now();
          auto& sender = signer_senders.at(idx).get();
          auto& sm2 = *reinterpret_cast<InfMessage*>(sender.getSlot(
              static_cast<tail_p2p::Size>(InfMessage::tput_pong_size())));
          sm2.local_sign = sm1.local_sign;
          sm2.remote_verify = verify_end - verify_start;
          sender.send();
          done++;
        }
      }
      for (auto& sender : signer_senders) {
        sender.get().tick();
      }
      if (std::chrono::steady_clock::now() - start > timeout) {
        return true;
      }
    }
  }
  return false;
}

int main(int argc, char* argv[]) {
  fmt::print("WARNING: ACK ESTIMATION IS HARDCODED TO 1us!!!\n");
  fmt::print("Build Time: {}\n", BINARY_BUILD_TIME);

  lyra::cli cli;
  bool get_help = false;
  int local_id;
  size_t pings = 1 << 16;
  tail_p2p::Size msg_size = units::bytes(8);
  bool test_slow_path = false;
  int core_id = -1;
  std::string scheme;
  std::string ingress;
  size_t ingress_distance_ns = 15000;
  size_t timeout_s = 15;

  std::vector<ProcId> signers;
  std::vector<ProcId> verifiers;

  cli.add_argument(lyra::help(get_help))
      .add_argument(lyra::opt(scheme, "dsig,sodium,dalek,none")
                        .required()
                        .choices("dsig", "sodium", "dalek", "none")
                        .name("--scheme")
                        .help("Which crypto scheme to use"))
      .add_argument(lyra::opt(local_id, "id")
                        .required()
                        .name("-l")
                        .name("--local-id")
                        .help("ID of the present process"))
      .add_argument(lyra::opt(signers, "signers")
                        .required()
                        .name("-s")
                        .name("--signer")
                        .help("ID of one of the signers"))
      .add_argument(lyra::opt(verifiers, "verifiers")
                        .required()
                        .name("-v")
                        .name("--verifiers")
                        .help("ID of one of the verifiers"))
      .add_argument(
          lyra::opt(pings, "pings").name("-p").name("--pings").help("Pings"))
      .add_argument(lyra::opt(msg_size, "msg_size")
                        .name("-s")
                        .name("--msg_size")
                        .help("Size of messages"))
      .add_argument(lyra::opt(test_slow_path)
                        .name("-S")
                        .name("--test-slow-path")
                        .help("Benchmark the slow path"))
      .add_argument(lyra::opt(core_id, "core_id")
                        .name("--core-pinning")
                        .help("Pin main thread to a particular core"))
      .add_argument(lyra::opt(ingress, "auto,constant,exponential")
                        .required()
                        .choices("auto", "constant", "exponential")
                        .name("-i")
                        .name("--ingress")
                        .help("When to issue new signatures"))
      .add_argument(
          lyra::opt(ingress_distance_ns, "distance between two requests in ns")
              .name("-d")
              .name("--ingress_distance")
              .help("Average distance between two requests in ns"))
      .add_argument(lyra::opt(timeout_s, "timeout")
                        .name("-t")
                        .name("--timeout")
                        .help("Seconds before stopping the experiment"));

  // Parse the program arguments.
  auto result = cli.parse({argc, argv});

  if (get_help) {
    std::cout << cli;
    return 0;
  }

  if (!result) {
    std::cerr << "Error in command line: " << result.errorMessage()
              << std::endl;
    return 1;
  }

  for (auto const& signer : signers) {
    if (std::find(verifiers.begin(), verifiers.end(), signer) !=
        verifiers.end()) {
      throw std::runtime_error(
          fmt::format("{} is both a signer and verifier!", signer));
    }
  }
  if (std::find(verifiers.begin(), verifiers.end(), local_id) ==
          verifiers.end() &&
      std::find(signers.begin(), signers.end(), local_id) == signers.end()) {
    throw std::runtime_error(fmt::format(
        "local id {} is neither a signer nor a verifier!", local_id));
  }
  if (signers.size() != 1 && verifiers.size() != 1) {
    throw std::runtime_error("cannot scale both signers and verifiers!");
  }
  auto role =
      std::find(verifiers.begin(), verifiers.end(), local_id) != verifiers.end()
          ? Verifier
          : Signer;

  std::vector<ProcId> remote_ids;
  for (auto const id : verifiers) {
    if (id != local_id) remote_ids.push_back(id);
  }
  for (auto const id : signers) {
    if (id != local_id) remote_ids.push_back(id);
  }

  Path const path = test_slow_path ? Slow : Fast;

  auto& store = dory::memstore::MemoryStore::getInstance();

  size_t const max_outstanding = scheme == "dsig" ? dsig::PreparedSks : 128;
  std::chrono::nanoseconds const ingress_distance{ingress_distance_ns};
  std::chrono::seconds const timeout(timeout_s);

  std::optional<Dsig> dsig{local_id};
  pin_main(core_id);

  size_t dummy_msg = 0;
  bool timed_out;
  std::chrono::nanoseconds duration;

  std::unique_ptr<Requests> requests;
  if (ingress == "auto") {
    requests = std::make_unique<AutoRequests>(dsig, verifiers, max_outstanding);
  } else if (ingress == "constant") {
    requests = std::make_unique<ConstantRequests>(dsig, verifiers, max_outstanding,
                                                  ingress_distance);
  } else if (ingress == "exponential") {
    requests = std::make_unique<ExponentialRequests>(dsig, verifiers, max_outstanding,
                                                    ingress_distance);
  } else {
    throw std::runtime_error("Unsupported ingress");
  }

  if (scheme == "sodium" || scheme == "dalek" || scheme == "none") {
    std::unique_ptr<asymmetric::AsymmetricCrypto> crypto;
    if (scheme == "dalek") {
      crypto = std::make_unique<asymmetric::DalekAsymmetricCrypto>(true);
      bool avx =
          dynamic_cast<asymmetric::DalekAsymmetricCrypto*>(crypto.get())->avx();
      fmt::print("Dalek {} AVX\n", avx ? "uses" : "does not use");
    } else {
      crypto = std::make_unique<asymmetric::SodiumAsymmetricCrypto>(true);
    }
    crypto->publishPublicKey(fmt::format("p{}-pk", local_id));
    store.barrier("public_keys_announced", remote_ids.size() + 1);
    std::vector<asymmetric::AsymmetricCrypto::PublicKey> signer_pks;
    for (auto const signer : signers) {
      signer_pks.emplace_back(crypto->getPublicKey(fmt::format("p{}-pk", signer)));
    }
    P2p p2p(local_id, remote_ids, InfMessage::size(msg_size), max_outstanding);
    auto start = std::chrono::steady_clock::now();
    timed_out =
        run_test_inf(role, dummy_msg, pings, msg_size, p2p, *crypto,
                     signer_pks, scheme == "none", *requests, timeout,
                     signers, verifiers);
    duration = std::chrono::steady_clock::now() - start;
  } else {
    P2p p2p(local_id, remote_ids, SignedMessage::size(msg_size), max_outstanding);
    sync_start(p2p, *dsig, store, "single", signers);
    auto start = std::chrono::steady_clock::now();
    timed_out = run_test(role, dummy_msg, pings, msg_size, p2p, *dsig,
                         *requests, path, timeout, signers, verifiers);
    duration = std::chrono::steady_clock::now() - start;
    sync_end(p2p, *dsig, store);
  }

  // Print the measurements
  if (local_id == 1) {
    if (timed_out) {
      fmt::print(
          "[Size={}/Path={}, Pings={}, Signers={}, Verifiers={}] Timed-out\n",
          msg_size, to_string(path), pings, signers.size(), verifiers.size());
    } else {
      requests->msrs.report();
      fmt::print(
          "[Size={}/Path={}/Pings={}/Signers={}/Verifiers={}] "
          "throughput: {} sig/s\n",
          msg_size, to_string(path), pings, signers.size(), verifiers.size(),
          pings * 1000 * 1000 * 1000 / duration.count());
    }
  }

  fmt::print("###DONE###\n");
  return timed_out ? 1 : 0;
}
