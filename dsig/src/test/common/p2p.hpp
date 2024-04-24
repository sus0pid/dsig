#pragma once

#include <cstdint>
#include <exception>
#include <vector>

#include <dory/ctrl/block.hpp>
#include <dory/ctrl/device.hpp>

#include <dory/shared/logger.hpp>
#include <dory/shared/types.hpp>
#include <dory/shared/units.hpp>

#include "../tail-p2p/receiver-builder.hpp"
#include "../tail-p2p/receiver.hpp"
#include "../tail-p2p/sender-builder.hpp"
#include "../tail-p2p/sender.hpp"

namespace dory::dsig {
using ProcId = int;

/**
 * @brief A struct that encapsulates RDMA initialization.
 *
 */
struct P2p {
  P2p(ProcId const local_id, std::vector<ProcId> const& remote_ids,
      size_t const msg_size, size_t const slots)
      : local_id{local_id}, remote_ids{remote_ids} {
    //// Setup RDMA ////
    LOGGER_INFO(logger, "Opening last RDMA device");
    open_device.emplace(std::move(ctrl::Devices().list().back()));
    LOGGER_INFO(logger, "Device: {} / {}, {}, {}", open_device->name(),
                open_device->devName(),
                ctrl::OpenDevice::typeStr(open_device->nodeType()),
                ctrl::OpenDevice::typeStr(open_device->transportType()));

    size_t binding_port = 0;
    LOGGER_INFO(logger, "Binding to port {} of opened device {}", binding_port,
                open_device->name());
    resolved_port.emplace(*open_device);
    if (!resolved_port->bindTo(binding_port)) {
      throw std::runtime_error("Couldn't bind the device.");
    }
    LOGGER_INFO(logger, "Binded successfully (port_id, port_lid) = ({}, {})",
                +resolved_port->portId(), +resolved_port->portLid());

    LOGGER_INFO(logger, "Configuring the control block");
    cb.emplace(*resolved_port);

    // //// Create Memory Regions and QPs ////
    cb->registerPd("standard");
    cb->registerCq("unused");

    auto& store = memstore::MemoryStore::getInstance();

    std::vector<tail_p2p::AsyncSenderBuilder> sender_builders;
    std::vector<tail_p2p::ReceiverBuilder> receiver_builders;
    for (auto const& remote_id : remote_ids) {
      sender_builders.emplace_back(*cb, local_id, remote_id, "main", slots,
                                   msg_size);
      sender_builders.back().announceQps();
      receiver_builders.emplace_back(*cb, local_id, remote_id, "main", slots,
                                     msg_size);
      receiver_builders.back().announceQps();
    }

    store.barrier("qp_announced", remote_ids.size() + 1);

    for (auto& sender_builder : sender_builders) {
      sender_builder.connectQps();
    }
    for (auto& receiver_builder : receiver_builders) {
      receiver_builder.connectQps();
    }

    store.barrier("qp_connected", remote_ids.size() + 1);

    for (auto& sender_builder : sender_builders) {
      senders.emplace_back(sender_builder.build());
    }
    for (auto& receiver_builder : receiver_builders) {
      receivers.emplace_back(receiver_builder.build());
    }

    store.barrier("abstractions_initialized", remote_ids.size() + 1);
  }

  ProcId local_id;
  std::vector<ProcId> remote_ids;

 private:
  Delayed<ctrl::OpenDevice> open_device;
  Delayed<ctrl::ResolvedPort> resolved_port;
  Delayed<ctrl::ControlBlock> cb;

 public:  // Order matters for destruction
  std::vector<tail_p2p::Sender> senders;
  std::vector<tail_p2p::Receiver> receivers;

  LOGGER_DECL_INIT(logger, "P2p");
};
}