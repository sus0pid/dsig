#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <random>
#include <thread>
#include <vector>

#include <fmt/chrono.h>
#include <fmt/core.h>
#include <lyra/lyra.hpp>

#include <dory/crypto/asymmetric/switchable-crypto.hpp>
#include <dory/shared/logger.hpp>
#include <dory/shared/pinning.hpp>
#include <dory/shared/types.hpp>
#include <dory/shared/units.hpp>
#include <dory/shared/unused-suppressor.hpp>

#include "../dsig.hpp"

#include "tail-p2p/types.hpp"

#include "common/helpers.hpp"
#include "common/p2p.hpp"
#include "common/measurements.hpp"
#include "common/path.hpp"
#include "common/requests.hpp"
#include "common/signed-message.hpp"

using namespace dory;
using namespace dsig;
using namespace crypto;

static bool run_test(size_t& dummy_msg, size_t const pings,
                     size_t const msg_size, P2p& p2p, Dsig& dsig,
                     Requests& reqs, Path const path,
                     std::chrono::seconds const timeout) {
  auto& sender = p2p.senders.front();
  auto& receiver = p2p.receivers.front();
  size_t done = 0;
  auto const start = std::chrono::steady_clock::now();

  if (p2p.local_id == 1) {
    // Master: signer + measurer
    while (done < pings) {
      if (reqs.poll()) {
        auto& sm = *reinterpret_cast<SignedMessage*>(sender.getSlot(
            static_cast<tail_p2p::Size>(SignedMessage::size(msg_size))));
        sm.local_sign = sm.fill(dummy_msg++, msg_size, dsig);
        sender.send();
      }
      if (auto polled = receiver.poll()) {
        auto& sm = *reinterpret_cast<SignedMessage const*>(polled->msg());
        reqs.done(0, Requests::Measure{sm.local_sign, sm.remote_verify});
        done++;
      }
      sender.tick();
      if (std::chrono::steady_clock::now() - start > timeout) {
        return true;
      }
    }
  } else {
    // Slave: verify + ack
    while (done < pings) {
      if (auto polled = receiver.poll()) {
        auto& sm1 = *reinterpret_cast<SignedMessage const*>(polled->msg());
        auto const verify_start = std::chrono::steady_clock::now();
        sm1.verify(msg_size, dsig, path, p2p.remote_ids.front());
        auto const verify_end = std::chrono::steady_clock::now();
        auto& sm2 = *reinterpret_cast<SignedMessage*>(sender.getSlot(
            static_cast<tail_p2p::Size>(SignedMessage::tput_pong_size())));
        sm2.local_sign = sm1.local_sign;
        sm2.remote_verify = verify_end - verify_start;
        sender.send();
        done++;
      }
      sender.tick();
      if (std::chrono::steady_clock::now() - start > timeout) {
        return true;
      }
    }
  }
  return false;
}

static bool run_test_inf(size_t& dummy_msg, size_t const pings,
                         size_t const msg_size, P2p& p2p,
                         asymmetric::AsymmetricCrypto& crypto,
                         asymmetric::AsymmetricCrypto::PublicKey& signer_pk,
                         bool const bypass,
                         Requests& reqs,
                         std::chrono::seconds const timeout) {
  auto& sender = p2p.senders.front();
  auto& receiver = p2p.receivers.front();
  size_t done = 0;
  auto const start = std::chrono::steady_clock::now();

  if (p2p.local_id == 1) {
    // Master: signer + measurer
    while (done < pings) {
      if (reqs.poll()) {
        auto& sm = *reinterpret_cast<InfMessage*>(sender.getSlot(
            static_cast<tail_p2p::Size>(InfMessage::size(msg_size))));
        sm.local_sign = sm.fill(dummy_msg++, msg_size, crypto, bypass);
        sender.send();
      }
      if (auto polled = receiver.poll()) {
        auto& sm = *reinterpret_cast<InfMessage const*>(polled->msg());
        reqs.done(0, Requests::Measure{sm.local_sign, sm.remote_verify});
        done++;
      }
      sender.tick();
      if (std::chrono::steady_clock::now() - start > timeout) {
        return true;
      }
    }
  } else {
    // Slave: verify + ack
    while (done < pings) {
      if (auto polled = receiver.poll()) {
        auto& sm1 = *reinterpret_cast<InfMessage const*>(polled->msg());
        auto const verify_start = std::chrono::steady_clock::now();
        sm1.verify(msg_size, crypto, signer_pk, bypass);
        auto const verify_end = std::chrono::steady_clock::now();
        auto& sm2 = *reinterpret_cast<InfMessage*>(sender.getSlot(
            static_cast<tail_p2p::Size>(InfMessage::tput_pong_size())));
        sm2.local_sign = sm1.local_sign;
        sm2.remote_verify = verify_end - verify_start;
        sender.send();
        done++;
      }
      sender.tick();
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

  cli.add_argument(lyra::help(get_help))
      .add_argument(lyra::opt(scheme, "dsig,sodium,dalek")
                        .required()
                        .choices("dsig", "sodium", "dalek")
                        .name("--scheme")
                        .help("Which crypto scheme to use"))
      .add_argument(lyra::opt(local_id, "id")
                        .required()
                        .name("-l")
                        .name("--local-id")
                        .help("ID of the present process"))
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

  Path const path = test_slow_path ? Slow : Fast;

  auto& store = dory::memstore::MemoryStore::getInstance();
  ProcId const remote_id = local_id == 1 ? 2 : 1;
  std::vector<ProcId> remote_ids{remote_id};

  size_t const max_outstanding = scheme == "dsig" ? dsig::PreparedSks : 128;
  std::chrono::nanoseconds const ingress_distance{ingress_distance_ns};
  std::chrono::seconds const timeout(timeout_s);

  fmt::print("Used crypto scheme: {}\n", scheme);

  size_t dummy_msg = 0;
  std::unique_ptr<Requests> requests;
  std::optional<Dsig> dsig;
  if (scheme == "dsig") {
    dsig.emplace(local_id);
  }
  pin_main(core_id);
  if (ingress == "auto") {
    requests = std::make_unique<AutoRequests>(dsig, remote_ids, max_outstanding);
  } else if (ingress == "constant") {
    requests = std::make_unique<ConstantRequests>(dsig, remote_ids, max_outstanding,
                                                  ingress_distance);
  } else if (ingress == "exponential") {
    requests = std::make_unique<ExponentialRequests>(dsig, remote_ids, max_outstanding,
                                                    ingress_distance);
  } else {
    throw std::runtime_error("Unsupported ingress");
  }

  bool timed_out;
  std::chrono::nanoseconds duration;

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
    store.barrier("public_keys_announced", 2);
    auto signer_pk = crypto->getPublicKey(fmt::format("p{}-pk", 1));

    P2p p2p(local_id, remote_ids, InfMessage::size(msg_size), max_outstanding);
    auto start = std::chrono::steady_clock::now();
    timed_out =
        run_test_inf(dummy_msg, pings, msg_size, p2p, *crypto, signer_pk, scheme == "none", *requests, timeout);
    duration = std::chrono::steady_clock::now() - start;
  } else {
    P2p p2p(local_id, remote_ids, SignedMessage::size(msg_size), max_outstanding);
    sync_start(p2p, *dsig, store, "single", {1});
    auto start = std::chrono::steady_clock::now();
    timed_out =
        run_test(dummy_msg, pings, msg_size, p2p, *dsig, *requests, path, timeout);
    duration = std::chrono::steady_clock::now() - start;
    sync_end(p2p, *dsig, store);
  }

  if (local_id == 1) {
    if (timed_out) {
      fmt::print("[Sig={}/Size={}/Path={}/Pings={}] Timed-out\n",
                scheme, msg_size, to_string(path), pings);
    } else {
      requests->msrs.report();
      fmt::print(
          "[Sig={}/Size={}/Path={}/Pings={}] "
          "throughput: {} sig/s\n",
          scheme, msg_size, to_string(path), pings,
          pings * 1000 * 1000 * 1000 / duration.count());
    }
  }
  fmt::print("###DONE###\n");
  return timed_out ? 1 : 0;
}
