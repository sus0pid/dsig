#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <optional>
#include <random>
#include <vector>

#include <fmt/chrono.h>
#include <fmt/core.h>
#include <lyra/lyra.hpp>

#include <dory/crypto/asymmetric/switchable-crypto.hpp>
#include <dory/shared/logger.hpp>
#include <dory/shared/types.hpp>
#include <dory/shared/units.hpp>
#include <dory/shared/unused-suppressor.hpp>

#include "../dsig.hpp"

#include "common/helpers.hpp"
#include "common/p2p.hpp"
#include "common/measurements.hpp"
#include "common/path.hpp"
#include "common/signed-message.hpp"
#include "common/validity.hpp"

using namespace dory;
using namespace dsig;
using namespace crypto;

using Clock = std::chrono::steady_clock;

class PathRandomizer {
 public:
  PathRandomizer(Path const path, std::optional<double> const miss_rate): path{path}, miss_rate{miss_rate} {}

  Path gen() {
    if (!miss_rate) return path;
    return (dist(eng) < *miss_rate) ? Path::Slow : Path::Fast;
  }

 private:
  Path path;
  std::optional<double> miss_rate;
  std::minstd_rand eng{std::random_device{}()};
  std::uniform_real_distribution<double> dist{0, 1};
};

static void ping_test(size_t& dummy_msg, size_t const pings,
                      size_t const msg_size, P2p& p2p, Dsig& dsig,
                      LatencyMeasurements& msr, Path const path,
                      Validity const validity, bool const prefetch,
                      std::optional<double> miss_rate) {
  auto& sender = p2p.senders.front();
  auto& receiver = p2p.receivers.front();
  PathRandomizer path_randomizer{path, miss_rate};

  for (size_t p = 0; p < pings; p++) {
    Clock::time_point left_sender;
    Clock::time_point arrived_sender;

    std::chrono::nanoseconds aggregate{0};

    if (prefetch) {
      dsig.prefetch_pk(p2p.remote_ids.front());
      dsig.prefetch_sk();
    }

    // Sign + Send for measurer
    if (p2p.local_id == 1) {
      auto& sm = *reinterpret_cast<SignedMessage*>(sender.getSlot(
          static_cast<tail_p2p::Size>(SignedMessage::size(msg_size))));
      auto time_to_sign = sm.fill(dummy_msg++, msg_size, dsig, validity);
      aggregate += time_to_sign;
      msr.local_sign_profiling.addMeasurement(time_to_sign);
      left_sender = Clock::now();
      sender.send();
    }

    // Used by proc 1 and 2
    std::chrono::nanoseconds time_to_verify;

    // Recv + Verify
    {
      auto polled = receiver.poll();
      while (!polled) {
        sender.tick();
        polled = receiver.poll();
      }

      arrived_sender = Clock::now();

      auto& sm = *reinterpret_cast<SignedMessage const*>(polled->msg());
      auto const random_path = path_randomizer.gen();
      auto const verify_start = std::chrono::steady_clock::now();
      if (!sm.verify(msg_size, dsig, random_path, p2p.remote_ids.front(), validity)) {
        throw std::runtime_error(fmt::format(
            "[Ping: {}/{}, Path: {}, Validity: {}] TEST FAILED", p, pings,
            to_string(random_path), to_string(validity)));
      }
      time_to_verify = (std::chrono::steady_clock::now() - verify_start);
      if (p2p.local_id == 1) {
        msr.local_verify_profiling.addMeasurement(time_to_verify);
        msr.remote_sign_profiling.addMeasurement(sm.remote_sign);
        msr.remote_verify_profiling.addMeasurement(sm.remote_verify);

        auto full_rtt =
            arrived_sender - left_sender - sm.remote_sign - sm.remote_verify;
        msr.full_rtt_profiling.addMeasurement(full_rtt);

        aggregate += full_rtt / 2;
        aggregate += time_to_verify;

        msr.overall_profiling.addMeasurement(aggregate);
      }
    }

    // Sign + Send for measurer
    if (p2p.local_id == 2) {
      auto& sm = *reinterpret_cast<SignedMessage*>(sender.getSlot(
          static_cast<tail_p2p::Size>(SignedMessage::size(msg_size))));
      auto time_to_sign = sm.fill(dummy_msg++, msg_size, dsig, validity);
      // Proc 2 sends the that it spent to sign and verify to Proc 1
      sm.remote_sign = time_to_sign;
      sm.remote_verify = time_to_verify;
      sender.send();
    }
  }
}

static void ping_test_inf(size_t& dummy_msg, size_t const pings,
                            size_t const msg_size, P2p& p2p,
                            asymmetric::AsymmetricCrypto& crypto,
                            asymmetric::AsymmetricCrypto::PublicKey& remote_pk,
                            bool const bypass, LatencyMeasurements& msr) {
  auto& sender = p2p.senders.front();
  auto& receiver = p2p.receivers.front();
  Clock::time_point const start = Clock::now();

  for (size_t p = 0; p < pings; p++) {
    Clock::time_point left_sender;
    Clock::time_point arrived_sender;

    std::chrono::nanoseconds aggregate{0};

    // Sign + Send for measurer
    if (p2p.local_id == 1) {
      auto* slot = sender.getSlot(
          static_cast<tail_p2p::Size>(InfMessage::size(msg_size)));
      auto& sm = *reinterpret_cast<InfMessage*>(slot);
      auto time_to_sign = sm.fill(dummy_msg++, msg_size, crypto, bypass);
      aggregate += time_to_sign;
      msr.local_sign_profiling.addMeasurement(time_to_sign);
      left_sender = Clock::now();
      sender.send();
    }

    // Used by proc 1 and 2
    std::chrono::nanoseconds time_to_verify;

    // Recv + Verify
    {
      auto polled = receiver.poll();
      while (!polled) {
        sender.tickForCorrectness();
        polled = receiver.poll();
      }

      arrived_sender = Clock::now();

      auto& sm = *reinterpret_cast<InfMessage const*>(polled->msg());
      auto const verify_start = std::chrono::steady_clock::now();
      if (!sm.verify(msg_size, crypto, remote_pk, bypass)) {
        throw std::runtime_error(
            fmt::format("[Ping: {}/{}] TEST FAILED", p, pings));
      }
      time_to_verify = (std::chrono::steady_clock::now() - verify_start);
      msr.local_verify_profiling.addMeasurement(time_to_verify);
      msr.remote_sign_profiling.addMeasurement(sm.remote_sign);
      msr.remote_verify_profiling.addMeasurement(sm.remote_verify);

      auto full_rtt =
          arrived_sender - left_sender - sm.remote_sign - sm.remote_verify;
      msr.full_rtt_profiling.addMeasurement(full_rtt);

      aggregate += full_rtt / 2;
      aggregate += time_to_verify;

      msr.overall_profiling.addMeasurement(aggregate);
    }

    // Sign + Send for measurer
    if (p2p.local_id == 2) {
      auto* slot = sender.getSlot(
          static_cast<tail_p2p::Size>(InfMessage::size(msg_size)));
      auto& sm = *reinterpret_cast<InfMessage*>(slot);
      auto time_to_sign = sm.fill(dummy_msg++, msg_size, crypto, bypass);

      // Proc 2 sends the that it spent to sign and verify to Proc 1
      sm.remote_sign = time_to_sign;
      sm.remote_verify = time_to_verify;

      sender.send();
    }
  }
}

static std::vector<Validity> dsig_validity_tests(Path const path, bool const test_invalid, bool const test_slow_path) {
  std::vector<Validity> tests = {Validity::Valid};
  if (test_invalid) {
    for (auto const invalid : SchemeToInvalid<dory::dsig::HbssScheme>::Fast) {
      tests.push_back(invalid);
    }
    if (path == Slow) {
      for (auto const invalid : SchemeToInvalid<dory::dsig::HbssScheme>::Slow) {
        tests.push_back(invalid);
      }
    }
  }
  return tests;
}

int main(int argc, char* argv[]) {
  fmt::print("Build Time: {}\n", BINARY_BUILD_TIME);

  lyra::cli cli;
  bool get_help = false;
  int local_id;
  size_t pings = dsig::PreparedSks;
  size_t runs = 32;
  tail_p2p::Size msg_size = units::bytes(8);
  bool test_invalid = false;
  bool test_slow_path = false;
  int core_id = -1;
  std::string scheme;
  bool prefetch = false;
  std::optional<double> miss_rate;

  cli.add_argument(lyra::help(get_help))
      .add_argument(lyra::opt(scheme, "dsig,sodium,dalek")
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
      .add_argument(
          lyra::opt(runs, "runs").name("-r").name("--runs").help("Runs"))
      .add_argument(lyra::opt(msg_size, "msg_size")
                        .name("-s")
                        .name("--msg_size")
                        .help("Size of messages"))
      .add_argument(lyra::opt(test_invalid)
                        .name("-i")
                        .name("--test-invalid")
                        .help("Benchmark invalid signatures"))
      .add_argument(lyra::opt(test_slow_path)
                        .name("-S")
                        .name("--test-slow-path")
                        .help("Benchmark the slow path"))
      .add_argument(lyra::opt(core_id, "core_id")
                        .name("--core-pinning")
                        .help("Pin main thread to a particular core"))
      .add_argument(lyra::opt(prefetch)
                        .name("-c")
                        .name("--prefetch")
                        .help("Prefetch PKs and SKs"))
      .add_argument(lyra::opt(miss_rate, "(0, 1)")
                        .name("-m")
                        .name("--miss-rate")
                        .help("Fast path miss rate"));

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

  if (miss_rate) {
    if (*miss_rate < 0. || *miss_rate > 1.) {
      std::cerr << "Error in command line: miss rate must be in range (0, 1)" << std::endl;
      return 1;
    }
    if (test_slow_path) {
      std::cerr << "Error in command line: miss rate incompatible with slow path" << std::endl;
      return 1;
    }
    if (test_invalid) {
      std::cerr << "Error in command line: miss rate incompatible with invalid sigs" << std::endl;
      return 1;
    }
  }

  auto& store = dory::memstore::MemoryStore::getInstance();
  ProcId const remote_id = local_id == 1 ? 2 : 1;

  fmt::print("Used crypto scheme: {}\n", scheme);

  if (scheme == "sodium" || scheme == "dalek" || scheme == "none") {
    pin_main(core_id);
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

    auto remote_pk = crypto->getPublicKey(fmt::format("p{}-pk", remote_id));

    P2p p2p(local_id, {remote_id}, InfMessage::size(msg_size), 1);

    size_t dummy_msg = 0;
    LatencyMeasurements msr;
    for (size_t run = 0; run < runs; run++) {
      ping_test_inf(dummy_msg, pings, msg_size, p2p, *crypto,
                      remote_pk, scheme == "none", msr);
    }
    fmt::print("[Size={}/EdDSA/Runs={}/Pings={}] done.\n", msg_size, runs, pings);
    if (local_id == 1)
      msr.report();
  } else if (scheme == "dsig") {
    Dsig dsig(local_id);
    pin_main(core_id);
    P2p p2p(local_id, {remote_id}, SignedMessage::size(msg_size), 1);

    std::vector<Path> paths = {Fast};
    if (test_slow_path) {
      paths.insert(paths.end(), {Slow});
    }

    size_t dummy_msg = 0;
    for (auto const path : paths) {
      auto const tests = dsig_validity_tests(path, test_invalid, test_slow_path);
      for (auto const validity : tests) {
        LatencyMeasurements msr;
        for (size_t run = 0; run < runs; run++) {
          sync_start(p2p, dsig, store, fmt::format("{}-{}-{}", run, validity, path), {1});
          ping_test(dummy_msg, pings, msg_size, p2p, dsig, msr, path, validity, prefetch, miss_rate);
        }
        fmt::print(
          "[Size={}/Path={}/Validity={}/MissRate={}/Runs={}/Pings={}] done.\n",
          msg_size, to_string(path), to_string(validity), miss_rate.value_or(0.), runs, pings);
        if (local_id == 1)
          msr.report();
      }
    }
    sync_end(p2p, dsig, store);
  }

  fmt::print("###DONE###\n");

  return 0;
}