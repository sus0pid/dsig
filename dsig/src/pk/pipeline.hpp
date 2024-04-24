#pragma once

#include <deque>
#include <exception>
#include <map>
#include <memory>
#include <vector>

#include <dory/shared/logger.hpp>

#include "../config.hpp"
#include "../network.hpp"
#include "../types.hpp"
#include "../mutex.hpp"
#include "../workers.hpp"

namespace dory::dsig {

class PkPipeline {
 public:
  PkPipeline(Network &net, InfCrypto &inf, Workers& workers)
      : inf_crypto{inf}, net{net}, workers{workers} {
    for (auto const &id : net.remote_ids) {
      wip_pks.try_emplace(id);
      ready_pks.try_emplace(id);
    }
  }

  PkPipeline(PkPipeline const &) = delete;
  PkPipeline &operator=(PkPipeline const &) = delete;
  PkPipeline(PkPipeline &&) = delete;
  PkPipeline &operator=(PkPipeline &&) = delete;

  void tick() {
    poll_recv_pks();
    put_ready_pks_aside();
  }

  std::optional<std::pair<ProcId, std::unique_ptr<BgPublicKeys>>> extract_ready() {
    std::scoped_lock<Mutex> lock{ready_pks_mutex};
    for (auto &[id, queue] : ready_pks) {
      if (!queue.empty()) {
        auto bg_pks = std::move(queue.front());
        queue.pop_front();
        return std::make_pair(id, std::move(bg_pks));
      }
    }
    return std::nullopt;
  }

 private:
  void poll_recv_pks() {
    while (auto opt_id_pks = net.poll_recv()) {
      auto const& [id, pks] = *opt_id_pks;
      wip_pks.at(id).emplace_back(std::make_unique<BgPublicKeys>(workers, inf_crypto, id, pks.get()));
    }
  }

  void put_ready_pks_aside() {
    for (auto &[id, queue] : wip_pks) {
      while (!queue.empty() && queue.front()->state == BgPublicKeys::State::Ready) {
        std::scoped_lock<Mutex> lock{ready_pks_mutex};
        ready_pks.at(id).push_back(std::move(queue.front()));
        queue.pop_front();
      }
    }
  }

  std::map<ProcId, std::deque<std::unique_ptr<BgPublicKeys>>> wip_pks;
  std::map<ProcId, std::deque<std::unique_ptr<BgPublicKeys>>> ready_pks;
  Mutex ready_pks_mutex;

  InfCrypto& inf_crypto;
  Network &net;
  Workers& workers;

  LOGGER_DECL_INIT(logger, "Dsig::PkPipeline");
};

}  // namespace dory::dsig
