#pragma once

#include <string>

#include "../../dsig.hpp"
#include "p2p.hpp"

#include <dory/memstore/store.hpp>
#include <dory/shared/pinning.hpp>

namespace dory::dsig {
// Note: to call after instanciating Dsig so that its threads don't inherit the
// sched affinity.
static void pin_main(int const core_id) {
  if (core_id >= 0) {
    fmt::print("Pinning main thread to core {}\n", core_id);
    pin_main_to_core(core_id);
  } else {
    fmt::print("Main thread is not pinned to a specific core\n");
  }
}

static void sync_start(P2p &p2p, Dsig& dsig, memstore::MemoryStore &store, std::string const& iteration, std::vector<ProcId> const& measurers) {
  std::string barrier{""};
  while (!dsig.replenished_sks());
  for (auto const id : p2p.remote_ids) {
    while(!dsig.replenished_pks(id));
  }
  auto const is_measurer = std::find(measurers.begin(), measurers.end(), p2p.local_id) != measurers.end();
  if (!is_measurer) {
    // Will help for all measurers to be done.
    for (size_t i = 0; i < p2p.senders.size(); i++) {
      auto const id = p2p.receivers.at(i).procId();
      if (std::find(measurers.begin(), measurers.end(), id) == measurers.end()) {
        continue;
      }
      while (!store.get(fmt::format("br-{}-{}", p2p.remote_ids.at(i), iteration), barrier)) {
        barrier.resize(0);
        p2p.senders.at(i).tick();
      }
    }
    store.set(fmt::format("br-{}-{}", p2p.local_id, iteration), "1");
  } else {
    store.set(fmt::format("br-{}-{}", p2p.local_id, iteration), "1");
    for (size_t i = 0; i < p2p.senders.size(); i++) {
      while (!store.get(fmt::format("br-{}-{}", p2p.remote_ids.at(i), iteration), barrier)) {
        barrier.resize(0);
        p2p.senders.at(i).tick();
      }
    }
  }
}

static void sync_end(P2p &p2p, Dsig& dsig, memstore::MemoryStore &store) {
  store.set(fmt::format("br-{}-end", p2p.local_id), "1");
  std::string barrier{""};
  for (size_t i = 0; i < p2p.senders.size(); i++) {
    while (!store.get(fmt::format("br-{}-end", p2p.remote_ids.at(i)), barrier)) {
      barrier.resize(0);
      p2p.senders.at(i).tick();
    }
  }
}
}