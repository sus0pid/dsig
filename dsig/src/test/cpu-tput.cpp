#include <array>
#include <chrono>
#include <deque>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>

#include <fmt/chrono.h>
#include <fmt/core.h>
#include <lyra/lyra.hpp>

#include "../export/config.hpp"
#include "../export/types.hpp"
#include "../sk/pipeline.hpp"
#include "../pk/pk.hpp"
#include "../inf-crypto/crypto.hpp"
#include "../workers.hpp"

using namespace dory::dsig;
static std::chrono::nanoseconds constexpr NowOverhead{18};

class BenchmarkSkPipeline: SkPipeline {
  std::unique_ptr<SigningBatch> gen_sk_batch() {
    auto batch = std::make_unique<SigningBatch>();
    for (auto &sk : batch->sks) {
      auto const seed{seed_generator.generate()};
      sk = std::make_unique<SecretKey>(seed, workers);
      while (sk->state != SecretKey::Initialized);
    }
    return batch;
  }

 public:
  BenchmarkSkPipeline(InfCrypto &inf, Workers &workers) : SkPipeline{*reinterpret_cast<Network*>(0), inf, workers} { }

  struct Results {
    constexpr Results() noexcept {};
    std::chrono::nanoseconds sk_gen{0}, pk_sign{0}, pk_check{0}, sign{0}, verify{0};
  };

  Results run(size_t const iters) {
    if (iters % SigningBatch::Size != 0)
      throw std::runtime_error("`iters` must be a multiple of `SigningBatch::Size`");

    Results res;
    for (size_t i = 0; i < iters; i += SigningBatch::Size) {
      auto const sk_gen_start = std::chrono::steady_clock::now();
      auto sk_batch = gen_sk_batch();
      res.sk_gen += std::chrono::steady_clock::now() - sk_gen_start - NowOverhead;

      auto const pk_sign_start = std::chrono::steady_clock::now();
      sk_batch->schedule(workers, inf_crypto);
      while (sk_batch->state != SigningBatch::Computed);
      res.pk_sign += std::chrono::steady_clock::now() - pk_sign_start - NowOverhead;

      auto const pk_check_start = std::chrono::steady_clock::now();
      BgPublicKeys pks{workers, inf_crypto, 1, sk_batch->to_send};
      while (pks.state != BgPublicKeys::Ready);
      res.pk_check += std::chrono::steady_clock::now() - pk_check_start - NowOverhead;

      std::array<uint8_t, 8> msg = {0xC0, 0xCA, 0xC0, 0x1A, 0xDE, 0xAD, 0xBE, 0xEF};
      static_assert(msg.size() >= sizeof(size_t));

      for (size_t j = 0; j < SigningBatch::Size; j++, ++*reinterpret_cast<size_t*>(&msg)) {
        auto& sk = sk_batch->sks.at(j);
        auto const sign_start = std::chrono::steady_clock::now();
        auto const sig = sk->sign(msg.data(), msg.size());
        res.sign += std::chrono::steady_clock::now() - sign_start - NowOverhead;
        auto const verify_start = std::chrono::steady_clock::now();
        volatile auto const valid = pks.verify(sig, msg.data(), msg.size());
        res.verify += std::chrono::steady_clock::now() - verify_start - NowOverhead;
      }
    }
    return res;
  }
};

struct EddsaResults {
  constexpr EddsaResults() noexcept {};
  std::chrono::nanoseconds sign{0}, verify{0};
};

static EddsaResults eddsa_bench(InfCrypto& eddsa, size_t const iters) {
  EddsaResults res;
  std::array<uint8_t, 8> msg = {0xC0, 0xCA, 0xC0, 0x1A, 0xDE, 0xAD, 0xBE, 0xEF};
  static_assert(msg.size() >= sizeof(size_t));
  for (size_t i = 0; i < iters; i++) {
    ++*reinterpret_cast<size_t*>(&msg);
    auto const sign_start = std::chrono::steady_clock::now();
    auto const sig = eddsa.sign(msg.data(), msg.size());
    res.sign += std::chrono::steady_clock::now() - sign_start - NowOverhead;
    auto const verify_start = std::chrono::steady_clock::now();
    volatile auto const valid = eddsa.verify(sig, msg.data(), msg.size(), eddsa.myId());
    res.verify += std::chrono::steady_clock::now() - verify_start - NowOverhead;
  }
  return res;
}

int main(int argc, char *argv[]) {
  lyra::cli cli;

  bool get_help = false;
  size_t iters = 2048 << 10;
  bool eddsa = false;

  cli.add_argument(lyra::help(get_help))
      .add_argument(
          lyra::opt(iters, "iters")
              .name("-i")
              .name("--iters")
              .help("How many times an object should be populated/copied"))
      .add_argument(
          lyra::opt(eddsa)
              .name("-e")
              .name("--eddsa")
              .help("Benchmark EdDSA instead of Dsig"));

  auto const result = cli.parse({argc, argv});

  if (get_help) {
    std::cout << cli;
    return 0;
  }

  if (!result)
    throw std::runtime_error("Error in command line: " + result.errorMessage());


  InfCrypto inf{1, {1}};
  Workers workers;
  auto const gop = iters * 1000 * 1000 * 1000;
  if (!eddsa) {
    fmt::print("[SECRETS/SK={}, SK={}B, Signature={}B ITERS={}]\n",
              SecretsPerSecretKey, sizeof(SecretKey), sizeof(Signature), iters);
    BenchmarkSkPipeline benchmark{inf, workers};
    auto const res = benchmark.run(iters);
    fmt::print("[DSIG][BG][SK][GEN] tput: {} sk/s latency: {} ns\n", gop / res.sk_gen.count(), res.sk_gen.count() / iters);
    fmt::print("[DSIG][BG][PK][SIGN] tput: {} pk/s latency: {} ns\n", gop / res.pk_sign.count(), res.pk_sign.count() / iters);
    fmt::print("[DSIG][BG][PK][CHECK] tput: {} pk/s latency: {} ns\n", gop / res.pk_check.count(), res.pk_check.count() / iters);
    fmt::print("[DSIG][FG][SIGN] tput: {} sig/s latency: {} ns\n", gop / res.sign.count(), res.sign.count() / iters);
    fmt::print("[DSIG][FG][VERIF] tput: {} sig/s latency: {} ns\n", gop / res.verify.count(), res.verify.count() / iters);
    fmt::print("[DSIG][TOTAL][SIGN] tput: {} sig/s latency: {} ns\n", gop / (res.sk_gen + res.pk_sign + res.sign).count(), (res.sk_gen + res.pk_sign + res.sign).count() / iters);
    fmt::print("[DSIG][TOTAL][VERIF] tput: {} sig/s latency: {} ns\n", gop / (res.pk_check + res.verify).count(), (res.pk_check + res.verify).count() / iters);
  } else {
    auto const eddsa_res = eddsa_bench(inf, iters);
    fmt::print("[EDDSA][SIGN] tput: {} sig/s latency: {} ns\n", gop / eddsa_res.sign.count(), eddsa_res.sign.count() / iters);
    fmt::print("[EDDSA][VERIF] tput: {} sig/s latency: {} ns\n", gop / eddsa_res.verify.count(), eddsa_res.verify.count() / iters);
  }
  fmt::print("###DONE###\n");
  return 0;
}
