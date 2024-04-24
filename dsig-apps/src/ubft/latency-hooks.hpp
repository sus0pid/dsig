#pragma once
#include <dory/dsig/latency.hpp>
#include <chrono>

namespace hooks {
  using Clock = std::chrono::steady_clock;
  using Timepoint = Clock::time_point;

  extern Timepoint smr_start;
  extern dory::dsig::LatencyProfiler smr_latency;

  extern Timepoint swmr_write_start;
  extern dory::dsig::LatencyProfiler swmr_write_latency;

  extern Timepoint swmr_read_start;
  extern dory::dsig::LatencyProfiler swmr_read_latency;

  extern Timepoint sig_computation_start;
  extern dory::dsig::LatencyProfiler sig_computation_latency;

  extern Timepoint sig_computation_real_start;
  extern dory::dsig::LatencyProfiler sig_computation_real_latency;

  extern Timepoint sig_check_start;
  extern dory::dsig::LatencyProfiler sig_check_latency;

  extern Timepoint sig_check_real_start;
  extern dory::dsig::LatencyProfiler sig_check_real_latency;

  extern Timepoint tcb_sp_start;
  extern dory::dsig::LatencyProfiler tcb_sp_latency;
}