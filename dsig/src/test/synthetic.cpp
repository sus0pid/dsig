#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
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

class Barrier {
 public:
  Barrier(size_t const wait_for): wait_for{wait_for} {}

  void wait() {
    wait_for--;
    while (wait_for != 0);
  }
 private:
  std::atomic<size_t> wait_for;
};

struct Client {
  Client(tail_p2p::Sender& sender, tail_p2p::Receiver& receiver): sender{sender}, receiver{receiver} {}
  tail_p2p::Sender& sender;
  tail_p2p::Receiver& receiver;
};
using ClientBatch = std::vector<Client>;
static ClientBatch batch(P2p &p2p, size_t const batch_index, size_t const nb_batches) {
  ClientBatch client_batch;
  for (size_t idx = batch_index; idx < p2p.receivers.size(); idx += nb_batches) {
    client_batch.emplace_back(p2p.senders.at(idx), p2p.receivers.at(idx));
  }
  return client_batch;
}

class ServerDsigWorker: public std::thread {
 public:
  ServerDsigWorker(Dsig& dsig, Path path, ClientBatch clients, size_t const msg_size, size_t const pings,
                   std::chrono::nanoseconds const processing, std::chrono::seconds const timeout, Barrier& barrier)
   : std::thread{[this, &dsig, path, clients, msg_size, pings, processing, timeout, &barrier](){
    fmt::print("Starting a worker with #clients={}\n", clients.size());
    size_t done{0};
    barrier.wait();
    auto const start = std::chrono::steady_clock::now();
    while (done < pings * clients.size()) {
      for (auto [idx, client] : hipony::enumerate(clients)) {
        if (auto polled = client.receiver.poll()) {
          auto& sm1 = *reinterpret_cast<SignedMessage const*>(polled->msg());
          auto const verify_start = std::chrono::steady_clock::now();
          if (!sm1.verify(msg_size, dsig, path, client.receiver.procId()))
            throw std::runtime_error("Invalid sig!");
          auto const verify_end = std::chrono::steady_clock::now();
          busy_sleep(processing);
          auto& sm2 = *reinterpret_cast<SignedMessage*>(client.sender.getSlot(
              static_cast<tail_p2p::Size>(SignedMessage::tput_pong_size())));
          sm2.local_sign = sm1.local_sign;
          sm2.remote_verify = verify_end - verify_start;
          client.sender.send();
          done++;
        }
        client.sender.tick();
      }
      if (std::chrono::steady_clock::now() - start > timeout) {
        timed_out = true;
        return;
      }
    }
   }} {}
   bool timed_out{false};
};

static bool run_test(size_t& dummy_msg, size_t const pings,
                     size_t const msg_size, P2p& p2p, Dsig& dsig,
                     Requests& reqs, std::chrono::nanoseconds const processing,
                     Path const path, std::chrono::seconds const timeout, std::vector<int> const& worker_cores) {
  if (p2p.local_id == 1) {
    size_t const nb_workers = 3;
    Barrier barrier{nb_workers};
    // Server: spawns workers, dispatches the connections.
    std::vector<ServerDsigWorker> workers;
    for (size_t i = 0; i < nb_workers; i++) {
      workers.emplace_back(dsig, path, batch(p2p, i, nb_workers), msg_size, pings, processing, timeout, barrier);
      pin_thread_to_core(workers.back(), worker_cores.at(i));
    }
    for (auto& worker : workers) {
      worker.join();
    }
    return std::any_of(workers.begin(), workers.end(), [](auto &w) { return w.timed_out; });
  } else {
    // Client
    auto& sender = p2p.senders.front();
    auto& receiver = p2p.receivers.front();
    size_t done = 0;
    auto const start = std::chrono::steady_clock::now();
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
  }
  return false;
}

using PkBatch = std::vector<std::reference_wrapper<asymmetric::AsymmetricCrypto::PublicKey>>;
static PkBatch batch(std::vector<asymmetric::AsymmetricCrypto::PublicKey>& pks, size_t const batch_index, size_t const nb_batches) {
  PkBatch pk_batch;
  for (size_t idx = batch_index; idx < pks.size(); idx += nb_batches) {
    pk_batch.emplace_back(pks.at(idx));
  }
  return pk_batch;
}
class ServerEddsaWorker: public std::thread {
 public:
  ServerEddsaWorker(asymmetric::AsymmetricCrypto& crypto, PkBatch const& client_pks,
                    bool const bypass, ClientBatch clients, size_t const msg_size, size_t const pings,
                    std::chrono::nanoseconds const processing, std::chrono::seconds const timeout, Barrier &barrier)
   : std::thread{[this, &crypto, client_pks, bypass, clients, msg_size, pings, processing, timeout, &barrier](){
    fmt::print("Starting a worker with #clients={}\n", clients.size());
    size_t done{0};
    barrier.wait();
    auto const start = std::chrono::steady_clock::now();
    while (done < pings * clients.size()) {
      for (auto [idx, client] : hipony::enumerate(clients)) {
        if (auto polled = client.receiver.poll()) {
          auto& sm1 = *reinterpret_cast<InfMessage const*>(polled->msg());
          auto const verify_start = std::chrono::steady_clock::now();
          if (!sm1.verify<true>(msg_size, crypto, client_pks.at(idx), bypass))
            throw std::runtime_error("Invalid sig!");
          auto const verify_end = std::chrono::steady_clock::now();
          busy_sleep(processing);
          auto& sm2 = *reinterpret_cast<InfMessage*>(client.sender.getSlot(
              static_cast<tail_p2p::Size>(InfMessage::tput_pong_size())));
          sm2.local_sign = sm1.local_sign;
          sm2.remote_verify = verify_end - verify_start;
          client.sender.send();
          done++;
        }
        client.sender.tick();
      }
      if (std::chrono::steady_clock::now() - start > timeout) {
        timed_out = true;
        return;
      }
    }
   }} {}
   bool timed_out{false};
};

static bool run_test_inf(size_t& dummy_msg, size_t const pings,
                         size_t const msg_size, P2p& p2p,
                         asymmetric::AsymmetricCrypto& crypto,
                         std::vector<asymmetric::AsymmetricCrypto::PublicKey>& client_pks,
                         bool const bypass,
                         Requests& reqs, std::chrono::nanoseconds const processing,
                         std::chrono::seconds const timeout,
                         std::vector<int> const& worker_cores) {
  if (p2p.local_id == 1) {
    size_t const nb_workers = 4;
    Barrier barrier{nb_workers};
    // Server: spawns workers, dispatches the connections.
    std::vector<ServerEddsaWorker> workers;
    for (size_t i = 0; i < nb_workers; i++) {
      workers.emplace_back(crypto, batch(client_pks, i, nb_workers), bypass, batch(p2p, i, nb_workers), msg_size, pings, processing, timeout, barrier);
      pin_thread_to_core(workers.back(), worker_cores.at(i));
    }
    for (auto& worker : workers) {
      worker.join();
    }
    return std::any_of(workers.begin(), workers.end(), [](auto &w) { return w.timed_out; });
  } else {
    // Client
    auto& sender = p2p.senders.front();
    auto& receiver = p2p.receivers.front();
    size_t done = 0;
    auto const start = std::chrono::steady_clock::now();
    while (done < pings) {
      if (reqs.poll()) {
        auto& sm = *reinterpret_cast<InfMessage*>(sender.getSlot(
            static_cast<tail_p2p::Size>(InfMessage::size(msg_size))));
        sm.local_sign = sm.fill<true>(dummy_msg++, msg_size, crypto, bypass);
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
  std::vector<int> worker_cores;
  std::string scheme;
  std::string ingress;
  size_t ingress_distance_ns = 15000;
  size_t timeout_s = 15;
  size_t clients = 1;
  size_t processing_ns = 1000;

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
                        .help("Seconds before stopping the experiment"))
      .add_argument(lyra::opt(clients, "clients")
                        .name("-c")
                        .name("--clients")
                        .help("Number of clients"))
      .add_argument(lyra::opt(processing_ns, "processing time in ns")
                        .name("-P")
                        .name("--processing")
                        .help("Processing time in ns"))
      .add_argument(lyra::opt(worker_cores, "worker-cores")
                        .name("-w")
                        .name("--worker-core")
                        .help("ID of one of the worker cores"));

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

  auto& store = memstore::MemoryStore::getInstance();

  auto const last_client = static_cast<ProcId>(clients + 1);
  std::vector<ProcId> remote_ids;
  for (ProcId i = 1; i <= last_client; i++) {
    if (i != local_id)
      remote_ids.push_back(i);
  }

  size_t const max_outstanding = scheme == "dsig" ? dsig::PreparedSks : 128;
  std::chrono::nanoseconds const ingress_distance{ingress_distance_ns};
  std::chrono::nanoseconds const processing{processing_ns};
  std::chrono::seconds const timeout(timeout_s);

  for (int core = 0; worker_cores.size() != 4; core += 2) {
    if (core == 8 || core == 10) continue; // Usual cores
    if (std::find(worker_cores.begin(), worker_cores.end(), core) != worker_cores.end()) continue;
    fmt::print("Completing worker core list with core {}.\n", core);
    worker_cores.push_back(core);
  }

  fmt::print("Used crypto scheme: {}\n", scheme);

  size_t dummy_msg = 0;
  std::unique_ptr<Requests> requests;
  std::optional<Dsig> dsig;
  if (scheme == "dsig") {
    dsig.emplace(local_id);
  }
  pin_main(core_id);
  std::vector<ProcId> server_id{{1}};
  if (ingress == "auto") {
    requests = std::make_unique<AutoRequests>(dsig, server_id, max_outstanding);
  } else if (ingress == "constant") {
    requests = std::make_unique<ConstantRequests>(dsig, server_id, max_outstanding,
                                                  ingress_distance);
  } else if (ingress == "exponential") {
    requests = std::make_unique<ExponentialRequests>(dsig, server_id, max_outstanding,
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
    store.barrier("public_keys_announced", last_client);
    std::vector<asymmetric::AsymmetricCrypto::PublicKey> client_pks;
    for (ProcId i = 2; i <= last_client; i++) {
      client_pks.emplace_back(crypto->getPublicKey(fmt::format("p{}-pk", i)));
    }
    P2p p2p(local_id, remote_ids, InfMessage::size(msg_size), max_outstanding);
    auto start = std::chrono::steady_clock::now();
    timed_out =
        run_test_inf(dummy_msg, pings, msg_size, p2p, *crypto, client_pks, scheme == "none", *requests, processing, timeout, worker_cores);
    duration = std::chrono::steady_clock::now() - start;
  } else {
    P2p p2p(local_id, remote_ids, SignedMessage::size(msg_size), max_outstanding);
    std::vector<ProcId> measurers;
    for (ProcId c = 2; c <= last_client; c++) {
      measurers.push_back(c);
    }
    sync_start(p2p, *dsig, store, "single", measurers);
    auto start = std::chrono::steady_clock::now();
    timed_out =
        run_test(dummy_msg, pings, msg_size, p2p, *dsig, *requests, processing, path, timeout, worker_cores);
    duration = std::chrono::steady_clock::now() - start;
    sync_end(p2p, *dsig, store);
  }

  if (local_id != 1) {
    if (timed_out) {
      fmt::print("[Sig={}/Size={}/Path={}/Processing={}/Pings={}] Timed-out\n",
                scheme, msg_size, to_string(path), processing, pings);
    } else {
      requests->msrs.report();
      fmt::print(
          "[Sig={}/Size={}/Path={}/Processing={}/Pings={}] "
          "(local) throughput: {} sig/s\n",
          scheme, msg_size, to_string(path), processing, pings,
          pings * 1000 * 1000 * 1000 / duration.count());
    }
  } else {
    fmt::print(timed_out ? "timeout\n" : "success\n");
  }
  fmt::print("###DONE###\n");
  return timed_out ? 1 : 0;
}
