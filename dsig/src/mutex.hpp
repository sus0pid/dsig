#pragma once

#include <atomic>
#include <mutex>

#include <dory/shared/branching.hpp>

namespace dory::dsig {

// Implements the Lockable interface so that it is compatible with std::scoped_lock
class SpinMutex {
  SpinMutex(SpinMutex const&) = delete;
  SpinMutex& operator=(SpinMutex const&) = delete;
  SpinMutex(SpinMutex&&) = delete;
  SpinMutex& operator=(SpinMutex&&) = delete;

 public:
  SpinMutex() {}

  inline bool try_lock() {
    return flag.exchange(true, std::memory_order_acquire) == 0;
  }

  inline void lock() {
    auto const my_ticket = ticket_machine++;
    while (next_customer.load(std::memory_order_relaxed) != my_ticket);
    while (unlikely(!try_lock()));
    next_customer.fetch_add(1, std::memory_order_relaxed);
  }

  inline void unlock() { flag.store(false, std::memory_order_release); }

 private:
  std::atomic<uint64_t> ticket_machine{0};
  std::atomic<uint64_t> next_customer{0};
  std::atomic<bool> flag = ATOMIC_FLAG_INIT;
};

// using Mutex = std::mutex;
using Mutex = SpinMutex;

}  // namespace dory::dsig
