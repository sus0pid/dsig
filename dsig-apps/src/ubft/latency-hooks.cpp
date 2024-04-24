#include "latency-hooks.hpp"

hooks::Timepoint hooks::smr_start;
dory::dsig::LatencyProfiler hooks::smr_latency(10000);

hooks::Timepoint hooks::swmr_read_start;
dory::dsig::LatencyProfiler hooks::swmr_read_latency(10000);

hooks::Timepoint hooks::swmr_write_start;
dory::dsig::LatencyProfiler hooks::swmr_write_latency(10000);

hooks::Timepoint hooks::sig_computation_start;
dory::dsig::LatencyProfiler hooks::sig_computation_latency(10000);

hooks::Timepoint hooks::sig_computation_real_start;
dory::dsig::LatencyProfiler hooks::sig_computation_real_latency(10000);

hooks::Timepoint hooks::sig_check_start;
dory::dsig::LatencyProfiler hooks::sig_check_latency(10000);

hooks::Timepoint hooks::sig_check_real_start;
dory::dsig::LatencyProfiler hooks::sig_check_real_latency(10000);

hooks::Timepoint hooks::tcb_sp_start;
dory::dsig::LatencyProfiler hooks::tcb_sp_latency(10000);