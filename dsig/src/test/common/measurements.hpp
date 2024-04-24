#pragma once

#include <fmt/core.h>

#include "../../latency.hpp"

namespace dory::dsig {
struct Measurements {
  Measurements() = default;

  LatencyProfiler local_sign_profiling{1024};
  LatencyProfiler local_verify_profiling{1024};
  LatencyProfiler remote_sign_profiling{1024};
  LatencyProfiler remote_verify_profiling{1024};
  LatencyProfiler full_rtt_profiling{1024};
  LatencyProfiler overall_profiling{1024};

  virtual void report() const = 0;
};

struct LatencyMeasurements: public Measurements {
  virtual void report() const override {
    fmt::print("\nOne-way\n");
    overall_profiling.report();

    fmt::print("\nSign\n");
    local_sign_profiling.report();

    fmt::print("\nVerify\n");
    local_verify_profiling.report();

    fmt::print("\nRemote Sign\n");
    remote_sign_profiling.report();

    fmt::print("\nRemote Verify\n");
    remote_verify_profiling.report();

    fmt::print("\nRTT\n");
    full_rtt_profiling.report();

    fmt::print(
      "[Summary (50th %iles)] "
      "one-way: {}, local sign: {}, local verify: {}, remote sign: {}, remote verify: {}, rtt: {}\n",
      overall_profiling.percentile(50),
      local_sign_profiling.percentile(50),
      local_verify_profiling.percentile(50),
      remote_sign_profiling.percentile(50),
      remote_verify_profiling.percentile(50),
      full_rtt_profiling.percentile(50));
  }
};

struct ThroughputMeasurements: public Measurements {
  LatencyProfiler in_buffer_profiling{1024};
  LatencyProfiler network_profiling{1024};

  virtual void report() const override {
    fmt::print("\nOne-way\n");
    overall_profiling.report();

    fmt::print("\nBuffer\n");
    in_buffer_profiling.report();

    fmt::print("\nSign\n");
    local_sign_profiling.report();

    fmt::print("\nVerify\n");
    remote_verify_profiling.report();

    fmt::print("\nNetwork+remote buffer\n");
    network_profiling.report();

    fmt::print(
      "[Summary (50th %iles)] "
      "one-way: {}, local sign: {}, local verify: {}, remote sign: {}, remote verify: {}, rtt: {}\n",
      overall_profiling.percentile(50),
      local_sign_profiling.percentile(50),
      local_verify_profiling.percentile(50),
      remote_sign_profiling.percentile(50),
      remote_verify_profiling.percentile(50),
      full_rtt_profiling.percentile(50));
  }
};
}