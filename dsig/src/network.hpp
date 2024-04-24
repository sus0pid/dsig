#pragma once

#include <algorithm>
#include <deque>
#include <exception>
#include <memory_resource>
#include <optional>
#include <vector>

#include <dory/conn/rc-exchanger.hpp>
#include <dory/conn/rc.hpp>
#include <dory/conn/ud.hpp>
#include <dory/ctrl/block.hpp>
#include <dory/ctrl/device.hpp>
#include <dory/shared/logger.hpp>

#include <fmt/core.h>
#include <fmt/ranges.h>

#include "config.hpp"
#include "types.hpp"
#include "util.hpp"
#include "pk/pk.hpp"

namespace dory::dsig {

class Network {
  static size_t constexpr MaxId = 31;
  using Armed = std::array<size_t, MaxId + 1>;
  class Connection {
   public:
    Connection(ProcId const local_id, ProcId const remote_id, conn::ReliableConnection&& rc, conn::ReliableConnection&& ack_rc, std::pmr::polymorphic_allocator<uint8_t>& rdma_allocator, size_t const hw_credits)
      : local_id{local_id}, remote_id{remote_id}, rc{std::move(rc)}, ack_rc{std::move(ack_rc)},
        my_notified_armed{&reinterpret_cast<Armed*>(this->ack_rc.getMr().addr + sizeof(Armed))->at(remote_id)},
        my_notified_armed_dest{&reinterpret_cast<Armed*>(this->ack_rc.remoteBuf())->at(local_id)},
        remote_notified_armed{&reinterpret_cast<Armed*>(this->ack_rc.getMr().addr)->at(remote_id)},
        armed_notif_credits{hw_credits} {
      if (static_cast<size_t>(remote_id) > MaxId) throw std::runtime_error("Remote id > MaxId");
      for (size_t i = 0; i < hw_credits; i++) {
        take_send_buffer(rdma_allocator.allocate(sizeof(BgPublicKeys::Compressed)));
        take_recv_buffer(rdma_allocator.allocate(sizeof(BgPublicKeys::Compressed)));
      }
    }

    void tick() {
      rearm_recvs();
      send_queued();
    }

    void send(BgPublicKeys::Compressed const& compressed) {
      if (!try_send(compressed)) {
        to_send.emplace_back(compressed);
      }
    }

    void take_send_buffer(void* buf) {
      free_send_bufs.emplace_back(buf);
    }

    void take_recv_buffer(void* buf) {
      free_recv_bufs.emplace_back(buf);
    }

    static size_t constexpr MaxHardwareCredits = 8;
    static_assert(MaxHardwareCredits < static_cast<size_t>(dory::conn::ReliableConnection::WrDepth));

   private:
    void send_queued() {
      while (!to_send.empty()) {
        if (!try_send(to_send.front())) {
          return;
        }
        to_send.pop_front();
      }
    }

    bool try_send(BgPublicKeys::Compressed const& compressed) {
      if (free_send_bufs.empty() || armed_before() <= sent)
        return false;
      auto const buf = free_send_bufs.front();
      free_send_bufs.pop_front();
      std::memcpy(buf, &compressed, sizeof(compressed));
      if (!rc.postSendSingleSend(pack(remote_id, buf), buf, sizeof(compressed)))
        throw std::runtime_error(fmt::format("Error while sending to {}", remote_id));
      sent++;
      return true;
    }

    void rearm_recvs() {
      while (!free_recv_bufs.empty()) {
        auto *const buf = free_recv_bufs.front();
        free_recv_bufs.pop_front();
        void *arr[] { buf };
        auto const posted =
          rc.postRecvMany(pack(remote_id, buf), arr, 1, sizeof(BgPublicKeys::Compressed));
        if (!posted)
          throw std::runtime_error(fmt::format("Error while arming for {}", remote_id));
        armed++;
      }

      if (armed < *my_notified_armed + 4) return; // notify every 4

      // Poll written armed
      while (armed_notif_credits == 0) {
        wce.resize(16);
        if (!ack_rc.pollCqIsOk(conn::ReliableConnection::Cq::SendCq, wce))
          throw std::runtime_error("Ack polling error.");
        for (auto& wc : wce) {
          if (wc.status != IBV_WC_SUCCESS)
            throw std::runtime_error(fmt::format(
              "Dsig RCs try_poll_recv. WC not successful ({}).", wc.status));
          reinterpret_cast<Connection*>(wc.wr_id)->armed_notif_credits++;
        }
      }

      *my_notified_armed = armed;
      ack_rc.postSendSingle(conn::ReliableConnection::RdmaWrite,
        reinterpret_cast<uint64_t>(this), my_notified_armed, sizeof(size_t),
        reinterpret_cast<uintptr_t>(my_notified_armed_dest));
      armed_notif_credits--;
    }

    size_t armed_before() {
      return *remote_notified_armed;
    }

    ProcId local_id, remote_id;

    conn::ReliableConnection rc;
    std::deque<void*> free_send_bufs, free_recv_bufs;

    conn::ReliableConnection ack_rc;
    size_t armed{0};
    size_t *my_notified_armed, *my_notified_armed_dest, *remote_notified_armed;

    size_t sent{0};
    std::deque<BgPublicKeys::Compressed> to_send;
    size_t armed_notif_credits;
    std::vector<struct ibv_wc> wce;
  };
 public:
  Network(ctrl::ControlBlock &cb, ProcId my_id,
          std::vector<ProcId> const &remote_ids,
          std::vector<ProcId> const &verifier_ids)
      : cb{cb}, store{nspace}, remote_ids{remote_ids}, verifier_ids{verifier_ids} {
    auto const hw_credits =
        std::min(static_cast<size_t>(dory::ctrl::ControlBlock::CqDepth /
                                     remote_ids.size()),
                 Connection::MaxHardwareCredits);
    auto [ce, ack_ce] = build_ces(my_id, remote_ids, cb, hw_credits);
    auto const rdma_mr = cb.mr(namespaced("send-recv-mr"));
    std::pmr::monotonic_buffer_resource rdma_buffer{reinterpret_cast<void*>(rdma_mr.addr), rdma_mr.size};
    std::pmr::polymorphic_allocator<uint8_t> rdma_allocator{&rdma_buffer};
    for (auto &id : remote_ids) {
      connections.try_emplace(id, my_id, id, ce.extract(id), ack_ce.extract(id), rdma_allocator, hw_credits);
    }
  }

  void tick() {
    for (auto& [_, co] : connections) {
      co.tick();
    }
    poll_send();
  }

  // Note: we eschew a copy by returning a ref that is valid till next tick
  std::optional<std::pair<ProcId, std::reference_wrapper<BgPublicKeys::Compressed>>> poll_recv() {
    wce.resize(1);
    if (!cb.pollCqIsOk(recv_cq->get(), wce))
      throw std::runtime_error("Polling error.");
    if (wce.empty()) return std::nullopt;
    auto &wc = wce.front();
    if (wc.status != IBV_WC_SUCCESS)
      throw std::runtime_error(fmt::format(
        "Dsig RCs try_poll_recv. WC not successful ({}).", wc.status));
    auto const [id, buf] = unpack(wc.wr_id);
    connections.at(id).take_recv_buffer(buf);
    return std::make_pair(id, std::ref(*reinterpret_cast<BgPublicKeys::Compressed*>(buf)));
  }

  void send(BgPublicKeys::Compressed const& compressed) {
    for (auto& [id, co] : connections) {
      if (std::find(verifier_ids.begin(), verifier_ids.end(), id) == verifier_ids.end())
        continue; // This process is not interrested in verifying signatures.
      co.send(compressed);
    }
  }

 private:
  void poll_send() {
    wce.resize(128);
    if (!cb.pollCqIsOk(send_cq->get(), wce))
      throw std::runtime_error("Polling error.");
    for (auto &wc : wce) {
      if (wc.status != IBV_WC_SUCCESS)
        throw std::runtime_error(fmt::format(
            "Dsig RCs poll_send. WC not successful ({}).", wc.status));
      auto const [id, buf] = unpack(wc.wr_id);
      connections.at(id).take_send_buffer(buf);
    }
  }

  static uint64_t pack(ProcId id, void *const buf) {
    auto ptr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(buf));
    return (static_cast<uint64_t>(id) << 48) | ptr;
  }

  static std::pair<ProcId, void*> unpack(uint64_t const wr_id) {
    auto const id = static_cast<ProcId>(wr_id >> 48);
    auto const ptr = reinterpret_cast<void*>((wr_id << 16) >> 16);
    return {id, ptr};
  }

  std::pair<conn::RcConnectionExchanger<ProcId>, conn::RcConnectionExchanger<ProcId>> build_ces(
      ProcId my_id, std::vector<ProcId> const &remote_ids,
      ctrl::ControlBlock &cb, size_t const hw_credits) {
    // Common
    cb.registerPd(namespaced("primary"));

    // Send/Recv
    cb.allocateBuffer(namespaced("send-recv-buf"), sizeof(BgPublicKeys::Compressed) * hw_credits * 2 * remote_ids.size(), 64);
    cb.registerMr(
        namespaced("send-recv-mr"), namespaced("primary"), namespaced("send-recv-buf"),
        ctrl::ControlBlock::LOCAL_READ | ctrl::ControlBlock::LOCAL_WRITE);
    cb.registerCq(namespaced("send-cq"));
    cb.registerCq(namespaced("recv-cq"));
    recv_cq = cb.cq(namespaced("recv-cq"));
    send_cq = cb.cq(namespaced("send-cq"));
    conn::RcConnectionExchanger<ProcId> ce(my_id, remote_ids, cb);
    ce.configureAll(namespaced("primary"), namespaced("send-recv-mr"),
                    namespaced("send-cq"), namespaced("recv-cq"));
    ce.announceAll(store, namespaced("qps"));

    // Ack - back pressure
    cb.allocateBuffer(namespaced("ack-buf"), sizeof(Armed) * 2, 64);
    cb.registerMr(
        namespaced("ack-mr"), namespaced("primary"), namespaced("ack-buf"),
        ctrl::ControlBlock::LOCAL_READ | ctrl::ControlBlock::LOCAL_WRITE |
            ctrl::ControlBlock::REMOTE_READ | ctrl::ControlBlock::REMOTE_WRITE);
    cb.registerCq(namespaced("ack-cq"));
    conn::RcConnectionExchanger<ProcId> ack_ce(my_id, remote_ids, cb);
    ack_ce.configureAll(namespaced("primary"), namespaced("ack-mr"),
                        namespaced("ack-cq"), namespaced("ack-cq"));
    ack_ce.announceAll(store, namespaced("ack-qps"));

    // Connect
    store.barrier("qps-announced", remote_ids.size() + 1);
    ce.connectAll(
        store, namespaced("qps"),
        ctrl::ControlBlock::LOCAL_READ | ctrl::ControlBlock::LOCAL_WRITE);
    ack_ce.connectAll(
        store, namespaced("ack-qps"),
        ctrl::ControlBlock::LOCAL_READ | ctrl::ControlBlock::LOCAL_WRITE |
            ctrl::ControlBlock::REMOTE_READ | ctrl::ControlBlock::REMOTE_WRITE);

    return {std::move(ce), std::move(ack_ce)};
  }

  std::string namespaced(std::string const &name) {
    return fmt::format("{}rcs-{}", nspace, name);
  }

  LOGGER_DECL_INIT(logger, "Dsig::Network");

  ctrl::ControlBlock &cb;
  memstore::MemoryStore store;

  std::map<ProcId, Connection> connections;
  std::optional<std::reference_wrapper<deleted_unique_ptr<struct ibv_cq>>> recv_cq, send_cq;

  std::vector<struct ibv_wc> wce;

 public:
  std::vector<ProcId> remote_ids;
 private:
  std::vector<ProcId> verifier_ids;
};
}  // namespace dory::dsig
