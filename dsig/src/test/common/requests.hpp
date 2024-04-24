#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <optional>
#include <random>

#include "../../dsig.hpp"
#include "measurements.hpp"

namespace dory::dsig {
class Requests {
 public:
  using OptionalDsig = std::optional<Dsig>;
  Requests(OptionalDsig &dsig, std::vector<ProcId> const& verifiers, size_t const max_outstanding)
      : dsig{dsig}, max_outstanding{max_outstanding} {
    for (auto const& _ : verifiers) {
      outstanding.emplace_back();
      outstanding.back().resize(max_outstanding);
      outstanding.back().resize(0);
    }
  }

  virtual bool poll() = 0;

  struct Measure {
    std::chrono::nanoseconds local_sign;
    std::chrono::nanoseconds remote_verify;
  };
  void done(size_t const index, Measure const& msr) {
    static constexpr std::chrono::nanoseconds ack{1000};
    auto const ponged_at = std::chrono::steady_clock::now();
    auto const& completed = outstanding.at(index).front();
    auto const ping_pong = ponged_at - completed.received_at;
    auto const in_buffer = completed.polled_at - completed.received_at;
    // Warning: Includes the remote ingress buffer, and ack is HARDCODED.
    auto const network =
        ping_pong - in_buffer - msr.local_sign - msr.remote_verify - ack;
    auto const end_to_end = ping_pong - ack;

    msrs.in_buffer_profiling.addMeasurement(in_buffer);
    msrs.local_sign_profiling.addMeasurement(msr.local_sign);
    msrs.remote_verify_profiling.addMeasurement(msr.remote_verify);
    msrs.network_profiling.addMeasurement(network);
    msrs.overall_profiling.addMeasurement(end_to_end);
    outstanding.at(index).pop_front();
  }

  struct Request {
    std::chrono::steady_clock::time_point received_at;
    std::chrono::steady_clock::time_point polled_at;
  };
  std::vector<std::deque<Request>> outstanding;

  ThroughputMeasurements msrs;
  static constexpr std::chrono::microseconds DropAfter =
      std::chrono::microseconds(200);

  OptionalDsig &dsig;
  size_t const max_outstanding;

 protected:
  bool any_full() const {
    for (auto const& out : outstanding) {
      if (out.size() >= max_outstanding) {
        return true;
      }
    }
    return false;
  }
};

// Requests that arrive
class AutoRequests : public Requests {
 public:
  AutoRequests(OptionalDsig &dsig, std::vector<ProcId> const& verifiers, size_t const max_outstanding)
      : Requests{dsig, verifiers, max_outstanding} {}

  bool poll() override {
    if (any_full()) {
      return false;
    }
    auto const now = std::chrono::steady_clock::now();
    for (auto &out : outstanding) {
      out.emplace_back(Request{now, now});
    }
    return true;
  }
};

struct ConstantRequests : public Requests {
 public:
  ConstantRequests(OptionalDsig &dsig, std::vector<ProcId> const& verifiers, size_t const max_outstanding,
                   std::chrono::nanoseconds const distance)
      : Requests{dsig, verifiers, max_outstanding}, distance{distance} {}

  bool poll() override {
    if (any_full()) {
      // if (dsig)
      //   while (!dsig->replenished_sks()) {}
      return false;
    }
    auto const now = std::chrono::steady_clock::now();
    if (last_received && now - *last_received < distance) {
      return false;
    }
    auto const received =
        (last_received && now - (*last_received + distance) < DropAfter)
            ? *last_received + distance
            : now;
    for (auto &out : outstanding) {
      out.emplace_back(Request{received, now});
    }
    last_received = received;
    return true;
  }

  std::chrono::nanoseconds const distance;
  std::optional<std::chrono::steady_clock::time_point> last_received;
  std::optional<std::chrono::steady_clock::time_point> to_poll;
};

struct ExponentialRequests : public Requests {
 public:
  ExponentialRequests(OptionalDsig &dsig, std::vector<ProcId> const& verifiers, size_t const max_outstanding,
                      std::chrono::nanoseconds const distance)
      : Requests{dsig, verifiers, max_outstanding},
        exp{1. / static_cast<double>(distance.count())} {}

  bool poll() override {
    if (any_full()) {
      // if (dsig)
      //   while (!dsig->replenished_sks()) {}
      return false;
    }
    auto const now = std::chrono::steady_clock::now();
    if (!to_poll) {
      auto const distance =
          std::chrono::nanoseconds(static_cast<size_t>(exp(gen)));
      to_poll = (last_received && now - (*last_received + distance) < DropAfter)
                    ? *last_received + distance
                    : now;
    }
    if (*to_poll > now) {
      return false;
    }
    for (auto &out : outstanding) {
      out.emplace_back(Request{*to_poll, now});
    }
    last_received = *to_poll;
    to_poll.reset();
    return true;
  }

  std::mt19937 gen{std::random_device()()};
  std::exponential_distribution<> exp;
  std::optional<std::chrono::steady_clock::time_point> last_received;
  std::optional<std::chrono::steady_clock::time_point> to_poll;
};
}