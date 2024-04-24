#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include <fmt/chrono.h>
#include <fmt/core.h>
#include <lyra/lyra.hpp>

#include <dory/ctrl/block.hpp>
#include <dory/ctrl/device.hpp>

#include <dory/memstore/store.hpp>

#include <dory/shared/logger.hpp>
#include <dory/shared/units.hpp>
#include <dory/dsig/latency.hpp>
#include <utility>

#include "../replicated-swmr/host-builder.hpp"
#include "../types.hpp"
#include "broadcaster-builder.hpp"
#include "broadcaster.hpp"
#include "message.hpp"
#include "receiver-builder.hpp"
#include "receiver.hpp"

#include "../thread-pool/tail-thread-pool.hpp"

static auto main_logger = dory::std_out_logger("Init");

int main(int argc, char *argv[]) {
  int const measurer_id = 1;
  int const responder_id = 2;
  int const witness_id = 3;
  std::vector<int> const hosts_ids = {measurer_id, responder_id, witness_id};
  std::vector<int> const &all_ids = hosts_ids;

  //// Parse Arguments ////
  lyra::cli cli;
  bool get_help = false;
  dory::ubft::ProcId local_id;
  size_t pings = 64;
  size_t experiments = 128;
  size_t message_size = dory::units::bytes(8);
  size_t tail = 200;
  bool fast_path = false;
  std::optional<int> pinned_core_id;
  size_t tp_threads = 1;
  std::vector<int> pinned_tp_core_ids;

  cli.add_argument(lyra::help(get_help))
      .add_argument(lyra::opt(local_id, "id")
                        .required()
                        .name("-l")
                        .name("--local-id")
                        .choices(measurer_id, responder_id, witness_id)
                        .help("ID of the present process"))
      .add_argument(
          lyra::opt(pings, "pings").name("-p").name("--pings").help("Pings"))
      .add_argument(lyra::opt(experiments, "experiments")
                        .name("-e")
                        .name("--experiments")
                        .help("Experiments"))
      .add_argument(lyra::opt(message_size, "message_size")
                        .name("-s")
                        .name("--message_size")
                        .help("Size of messages"))
      .add_argument(
          lyra::opt(tail, "tail").name("-t").name("--tail").help("Tail window"))
      .add_argument(lyra::opt(fast_path)
                        .name("-f")
                        .name("--fast-path")
                        .choices(measurer_id, responder_id, witness_id)
                        .help("Enable the fast path"))
      .add_argument(lyra::opt(pinned_core_id, "pinned_core_id")
                        .name("-c")
                        .name("--core")
                        .help("Id of the core to pin the application to"))
      .add_argument(lyra::opt(tp_threads, "tp_threads")
                        .name("-x")
                        .name("--tp-threads")
                        .help("Nb of thread pool threads"))
      .add_argument(lyra::opt(pinned_tp_core_ids, "pinned_tp_core_ids")
                        .name("-X")
                        .name("--tp-core")
                        .help("Ids of the cores to pin the thread pool to"));

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

  if (pinned_core_id) {
    LOGGER_INFO(main_logger, "Pinning the main thread to core {}",
                *pinned_core_id);
    dory::pin_main_to_core(*pinned_core_id);
  }

  //// Initialize the crypto library ////
  dory::ubft::Crypto crypto(local_id, all_ids);

  //// Initialize the thread pool ////
  dory::ubft::TailThreadPool thread_pool("consensus-pool", tp_threads,
                                         pinned_tp_core_ids);

  //// Setup RDMA ////
  LOGGER_INFO(main_logger, "Opening RDMA device ...");
  auto open_device = std::move(dory::ctrl::Devices().list().back());
  LOGGER_INFO(main_logger, "Device: {} / {}, {}, {}", open_device.name(),
              open_device.devName(),
              dory::ctrl::OpenDevice::typeStr(open_device.nodeType()),
              dory::ctrl::OpenDevice::typeStr(open_device.transportType()));

  size_t binding_port = 0;
  LOGGER_INFO(main_logger, "Binding to port {} of opened device {}",
              binding_port, open_device.name());
  dory::ctrl::ResolvedPort resolved_port(open_device);
  auto binded = resolved_port.bindTo(binding_port);
  if (!binded) {
    throw std::runtime_error("Couldn't bind the device.");
  }
  LOGGER_INFO(main_logger, "Binded successfully (port_id, port_lid) = ({}, {})",
              +resolved_port.portId(), +resolved_port.portLid());

  LOGGER_INFO(main_logger, "Configuring the control block");
  dory::ctrl::ControlBlock cb(resolved_port);

  // //// Create Memory Regions and QPs ////
  cb.registerPd("standard");
  cb.registerCq("unused");

  auto &store = dory::memstore::MemoryStore::getInstance();

  std::vector<uint8_t> msg(message_size, 0);
  using Clock = std::chrono::steady_clock;

  // Everyone is a memory host
  // For the ping, measurer_id broadcasts while responder_id and witness_id are
  // receivers. The latter must thus have their own replicated SWMR.
  std::vector<dory::ubft::replicated_swmr::HostBuilder> ping_host_builders;
  for (auto const writer_id : {responder_id, witness_id}) {
    std::vector<int> const accessors = {responder_id, witness_id};
    ping_host_builders.emplace_back(
        cb, local_id, writer_id, accessors, "ping", tail,
        dory::ubft::tail_cb::Receiver::RegisterValueSize);
    ping_host_builders.back().announceQps();
    ping_host_builders.emplace_back(
        cb, local_id, writer_id, accessors, "hash-ping", tail,
        dory::ubft::tail_cb::Receiver::HashRegisterValueSize);
    ping_host_builders.back().announceQps();
  }
  // For the pong, the measurer and the responder swap their roles.
  std::vector<dory::ubft::replicated_swmr::HostBuilder> pong_host_builders;
  for (auto const writer_id : {measurer_id, witness_id}) {
    std::vector<int> const accessors = {measurer_id, witness_id};
    pong_host_builders.emplace_back(
        cb, local_id, writer_id, accessors, "pong", tail,
        dory::ubft::tail_cb::Receiver::RegisterValueSize);
    pong_host_builders.back().announceQps();
    pong_host_builders.emplace_back(
        cb, local_id, writer_id, accessors, "hash-pong", tail,
        dory::ubft::tail_cb::Receiver::HashRegisterValueSize);
    pong_host_builders.back().announceQps();
  }

  if (local_id == measurer_id) {
    dory::ubft::tail_cb::BroadcasterBuilder ping_broadcaster_builder(
        cb, local_id, {responder_id, witness_id}, "ping", crypto, thread_pool,
        0, tail, message_size);
    dory::ubft::tail_cb::ReceiverBuilder pong_receiver_builder(
        cb, local_id, responder_id, {local_id, witness_id}, hosts_ids, "pong",
        crypto, thread_pool, 0, tail, message_size);

    ping_broadcaster_builder.announceQps();
    pong_receiver_builder.announceQps();
    store.barrier("qp_announced", 3);
    for (auto &builder : ping_host_builders) {
      builder.connectQps();
    }
    for (auto &builder : pong_host_builders) {
      builder.connectQps();
    }
    ping_broadcaster_builder.connectQps();
    pong_receiver_builder.connectQps();
    store.barrier("qp_connected", 3);
    auto ping_broadcaster = ping_broadcaster_builder.build();
    auto pong_receiver = pong_receiver_builder.build();
    pong_receiver.toggleFastPath(fast_path);
    ping_broadcaster.toggleSlowPath(!fast_path);
    pong_receiver.toggleSlowPath(!fast_path);
    store.barrier("abstractions_initialized", 3);

    dory::dsig::LatencyProfiler latency_profiler(fast_path ? 2048 : 128);

    for (size_t e = 0; e < experiments; e++) {
      if constexpr(TCB_SCHEME == CRYPTO_SCHEME_Dsig) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
      size_t nb_ticks = 0;
#undef BETTER_BENCHMARK
#ifdef BETTER_BENCHMARK
      std::chrono::nanoseconds broadcast{};
      std::chrono::nanoseconds broadcaster_ticks{};
      std::chrono::nanoseconds receiver_ticks{};
      std::chrono::nanoseconds polls{};
      std::chrono::nanoseconds poll{};
#endif
      // auto const start = Clock::now();
      auto last = Clock::now();
      for (size_t p = 0; p < pings; p++) {
#ifdef BETTER_BENCHMARK
        auto const broadcast_start = Clock::now();
#endif
        ping_broadcaster.broadcast(
            msg.data(),
            static_cast<dory::ubft::tail_cb::Broadcaster::Size>(msg.size()));
#ifdef BETTER_BENCHMARK
        broadcast += Clock::now() - broadcast_start;
#endif
        std::optional<dory::ubft::tail_cb::Message> opt_polled;
        while (!opt_polled) {
#ifdef BETTER_BENCHMARK
          nb_ticks++;
          auto const broadcaster_tick_start = Clock::now();
#endif
          ping_broadcaster.tick();
#ifdef BETTER_BENCHMARK
          auto const receiver_tick_start = Clock::now();
#endif
          pong_receiver.tick();
#ifdef BETTER_BENCHMARK
          auto const tick_over = Clock::now();
          broadcaster_ticks += receiver_tick_start - broadcaster_tick_start;
          receiver_ticks += tick_over - receiver_tick_start;
#endif
          opt_polled = pong_receiver.poll();
#ifdef BETTER_BENCHMARK
          auto const poll_over = Clock::now();
          polls += poll_over - tick_over;
          if (opt_polled) {
            poll += poll_over - tick_over;
          }
#endif
        }
        auto end = Clock::now();
        latency_profiler.addMeasurement(end - last);
        last = end;
      }
      // std::chrono::nanoseconds duration(Clock::now() - start);
      // fmt::print("[Size={}] {} pings in {}, measured one-way latency: {}\n",
      //            message_size, pings, duration, duration / pings / 2);
#ifdef BETTER_BENCHMARK
      fmt::print(
          "{} ticks per ping, one bcst tick: {}, one recv tick: {}, one poll: "
          "{}\n",
          nb_ticks / pings, broadcaster_ticks / nb_ticks,
          receiver_ticks / nb_ticks, polls / nb_ticks);
      fmt::print("one bcst: {}, one final poll: {}\n", broadcast / pings,
                 poll / pings);
#endif
    }
    latency_profiler.report();
    fmt::print("done.\n");
#if LATENCY_HOOKS
    fmt::print("SWMR writing:\n");
    hooks::swmr_write_latency.report();
    fmt::print("SWMR reading:\n");
    hooks::swmr_read_latency.report();
    fmt::print("Comp. sig strict:\n");
    hooks::sig_computation_real_latency.report();
    fmt::print("Comp. sig + scheduling, etc.:\n");
    hooks::sig_computation_latency.report();
    fmt::print("Check sig strict:\n");
    hooks::sig_check_real_latency.report();
    fmt::print("Check sig + scheduling, etc.:\n");
    hooks::sig_check_latency.report();
#endif
  } else if (local_id == responder_id) {
    dory::ubft::tail_cb::ReceiverBuilder ping_receiver_builder(
        cb, local_id, measurer_id, {local_id, witness_id}, hosts_ids, "ping",
        crypto, thread_pool, 0, tail, message_size);
    dory::ubft::tail_cb::BroadcasterBuilder pong_broadcaster_builder(
        cb, local_id, {measurer_id, witness_id}, "pong", crypto, thread_pool, 0,
        tail, message_size);

    ping_receiver_builder.announceQps();
    pong_broadcaster_builder.announceQps();
    store.barrier("qp_announced", 3);
    for (auto &builder : ping_host_builders) {
      builder.connectQps();
    }
    for (auto &builder : pong_host_builders) {
      builder.connectQps();
    }
    ping_receiver_builder.connectQps();
    pong_broadcaster_builder.connectQps();
    store.barrier("qp_connected", 3);
    auto ping_receiver = ping_receiver_builder.build();
    auto pong_broadcaster = pong_broadcaster_builder.build();
    ping_receiver.toggleFastPath(fast_path);
    ping_receiver.toggleSlowPath(!fast_path);
    pong_broadcaster.toggleSlowPath(!fast_path);
    store.barrier("abstractions_initialized", 3);

    for (size_t i = 0; i < experiments * pings; i++) {
      std::optional<dory::ubft::tail_cb::Message> opt_polled;
      while (!opt_polled) {
        ping_receiver.tick();
        pong_broadcaster.tick();
        opt_polled = ping_receiver.poll();
      }
      pong_broadcaster.broadcast(
          msg.data(),
          static_cast<dory::ubft::tail_cb::Broadcaster::Size>(msg.size()));
    }
    for (auto i = 0; i < 100000; i++) {
      pong_broadcaster.tick();
    }
    fmt::print("done.\n");
  } else if (local_id == witness_id) {
    dory::ubft::tail_cb::ReceiverBuilder ping_receiver_builder(
        cb, local_id, measurer_id, {local_id, responder_id}, hosts_ids, "ping",
        crypto, thread_pool, 0, tail, message_size);
    dory::ubft::tail_cb::ReceiverBuilder pong_receiver_builder(
        cb, local_id, responder_id, {local_id, measurer_id}, hosts_ids, "pong",
        crypto, thread_pool, 0, tail, message_size);

    ping_receiver_builder.announceQps();
    pong_receiver_builder.announceQps();
    store.barrier("qp_announced", 3);
    for (auto &builder : ping_host_builders) {
      builder.connectQps();
    }
    for (auto &builder : pong_host_builders) {
      builder.connectQps();
    }
    ping_receiver_builder.connectQps();
    pong_receiver_builder.connectQps();
    store.barrier("qp_connected", 3);
    auto ping_receiver = ping_receiver_builder.build();
    auto pong_receiver = pong_receiver_builder.build();
    ping_receiver.toggleFastPath(fast_path);
    pong_receiver.toggleFastPath(fast_path);
    ping_receiver.toggleSlowPath(!fast_path);
    pong_receiver.toggleSlowPath(!fast_path);
    store.barrier("abstractions_initialized", 3);

    // In the slow path, the witness doesn't participate.
    while (!fast_path) {
    }

    while (true) {
      ping_receiver.tick();
      pong_receiver.tick();
    }
  }

  return 0;
}
