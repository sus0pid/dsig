#pragma once

#include <deque>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <tuple>

#include <fmt/core.h>

#include <dory/crypto/hash/blake2b.hpp>
#include <dory/shared/logger.hpp>

#include "sig-switch.hpp"
#include "../buffer.hpp"
#include "../crypto.hpp"
#include "../tail-p2p/sender.hpp"
#include "../tail-queue/tail-queue.hpp"
#include "../thread-pool/tail-thread-pool.hpp"
#include "internal/signature-message.hpp"
#include "message.hpp"

#include "../latency-hooks.hpp"

namespace dory::ubft::tail_cb {

class Broadcaster {
  auto static constexpr SlowPathEnabled = true;

  using Signature = internal::SignatureMessage::Signature;

 public:
  using Index = Message::Index;
  using Size = tail_p2p::Size;

 private:
  struct ComputedSignature {
    Index index;
    Buffer signature_buffer;
    Buffer buffer;  // So that the buffer can be returned to the main thread.
  };

 public:
  Broadcaster(Crypto &crypto, TailThreadPool &thread_pool,
              size_t const borrowed_messages, size_t const tail,
              size_t const max_msg_size,
              std::vector<tail_p2p::AsyncSender> &&message_senders,
              std::vector<tail_p2p::AsyncSender> &&signature_senders)
      : crypto{crypto},
        tail{tail},
        max_msg_size{max_msg_size},
        message_senders{std::move(message_senders)},
        signature_senders{std::move(signature_senders)},
        message_buffer_pool{borrowed_messages + tail + 1,
                            Message::bufferSize(max_msg_size)},
        signature_buffer_pool{
            tail + 1 +
                TailThreadPool::TaskQueue::maxOutstanding(tail, thread_pool),
            sizeof(Signature)},
        buffer_pool{
            tail + 1 +
                TailThreadPool::TaskQueue::maxOutstanding(tail, thread_pool),
            max_msg_size},
        queued_signature_computations{tail},
        task_queue{thread_pool, tail} {}

  Message broadcast(uint8_t const *const data, Size const size) {
    auto const index = next_index++;
    LOGGER_DEBUG(logger, "Broadcasting message #{}", index);

    // Send message
    for (auto &sender : message_senders) {
      auto *slot = sender.getSlot(static_cast<Size>(Message::bufferSize(size)));
      auto *message = reinterpret_cast<Message::BufferLayout *>(slot);
      message->header.index = index;
      std::memcpy(&message->data, data, size);
      sender.send();
    }

    if constexpr (SlowPathEnabled) {
      // As the computation of the hash can be slow, we move it to the
      // threadpool.
      // We need to extend the lifetime of the data so that it doesn't get
      // destroyed. This implies creating a copy, in our case we allocate on the
      // heap. We preallocate buffers to speedup.
      auto opt_buffer = buffer_pool.take(size);
      if (unlikely(!opt_buffer)) {
        throw std::logic_error("Cb broadcaster ran out of free buffers.");
      }
      auto opt_sig_buffer = signature_buffer_pool.take();
      if (unlikely(!opt_sig_buffer)) {
        throw std::logic_error("Cb broadcaster ran out of free sig buffers.");
      }
      std::copy(data, data + size, opt_buffer->data());

      queued_signature_computations.emplaceBack(index, std::move(*opt_buffer), std::move(*opt_sig_buffer));
    }

    // As the sender is probably not part of the receivers, we return a buffer
    // that he can use himself, "as if" he had received it.
    // TODO(Antoine): save the copy, although we did most of the work.
    auto opt_buffer = message_buffer_pool.take(Message::bufferSize(size));
    if (unlikely(!opt_buffer)) {
      throw std::runtime_error("Ran out of buffers while CB-broadcasting.");
    }
    auto &raw = *reinterpret_cast<Message::BufferLayout *>(opt_buffer->data());
    raw.header.index = index;
    std::memcpy(&raw.data, data, size);
    auto opt_msg = Message::tryFrom(std::move(*opt_buffer));
    return std::get<Message>(std::move(opt_msg));
  }

  void tick() {
    for (auto &sender : message_senders) {
      sender.tickForCorrectness();
    }
    if (likely(!shouldRunSlowPath())) {
      return;
    }
    offloadSignatureComputation();
    pollSignatures();
    for (auto &sender : signature_senders) {
      sender.tickForCorrectness();
    }
  }

  void toggleSlowPath(bool const enable) {
    if (enable && !SlowPathEnabled) {
      throw std::runtime_error("Slow path was disabled at compilation.");
    }
    slow_path_on = enable;
  }

  inline Index nextIndex() const { return next_index; }

  inline size_t getTail() const { return tail; }

 private:
  void offloadSignatureComputation() {
    for (auto &&[i, buffer, buffer_sig] : queued_signature_computations) {
      #ifdef LATENCY_HOOKS
        hooks::sig_computation_start = hooks::Clock::now();
      #endif
      auto const index = i;  // structured bindings cannot be captured
      // task_queue.enqueue([this, index, buffer = std::move(buffer), buffer_sig = std::move(buffer_sig)]() mutable {
        // The hash includes both the index and the message.
        // TODO(Ant.): also include the identifier of the broadcaster instance
        // to prevent replay attacks.
        #ifdef LATENCY_HOOKS
          hooks::sig_computation_real_start = hooks::Clock::now();
        #endif
        auto acc = crypto::hash::blake3_init();
        crypto::hash::blake3_update(acc, index);
        crypto::hash::blake3_update(acc, buffer.cbegin(), buffer.cend());
        auto const hash = crypto::hash::blake3_final(acc);
        *reinterpret_cast<Signature*>(buffer_sig.data()) = TcbCrypto::crypto(crypto).sign(hash.data(), hash.size());
        #ifdef LATENCY_HOOKS
          hooks::sig_computation_real_latency.addMeasurement(hooks::Clock::now() - hooks::sig_computation_real_start);
        #endif
        computed_signatures.emplace_back(ComputedSignature{
            index, std::move(buffer_sig), std::move(buffer)});
      // });
    }
    queued_signature_computations.clear();
  }

  void pollSignatures() {
    // try_dequeue does not use the optional, hence the need for manual reset to
    // recycle the buffer.
    while (!computed_signatures.empty()) {
      ComputedSignature computed_signature{std::move(computed_signatures.front())};
      computed_signatures.pop_front();
      #ifdef LATENCY_HOOKS
        hooks::sig_computation_latency.addMeasurement(hooks::Clock::now() - hooks::sig_computation_start);
      #endif
      auto &[index, signature, _] = computed_signature;
      // Note: This is an optimisation, not to send signatures that are not
      // required as they are not part of the tail.
      auto const in_tail = next_index - index <= tail;
      if (!in_tail) {
        continue;
      }
      for (auto &sender : signature_senders) {
        auto *slot = sender.getSlot(
            static_cast<Size>(internal::SignatureMessage::BufferSize));
        auto *sig_slot =
            reinterpret_cast<internal::SignatureMessage::BufferLayout *>(slot);
        sig_slot->index = index;
        std::memcpy(&sig_slot->signature, signature.data(), sizeof(Signature));
        sender.send();
      }
    }
  }
  
  inline bool shouldRunSlowPath() const {
    return SlowPathEnabled && slow_path_on;
  }

  bool slow_path_on = false;
  size_t next_index = 0;
  Crypto &crypto;
  size_t const tail;
  size_t const max_msg_size;
  std::vector<tail_p2p::AsyncSender> message_senders;
  std::vector<tail_p2p::AsyncSender> signature_senders;
  std::deque<ComputedSignature>
      computed_signatures;  // TODO(Antoine): define a max depth?
  Pool message_buffer_pool;
  Pool signature_buffer_pool;
  Pool buffer_pool;
  TailQueue<std::tuple<Index, Buffer, Buffer>> queued_signature_computations;
  TailThreadPool::TaskQueue task_queue;
  LOGGER_DECL_INIT(logger, "CbBroadcaster");
};

}  // namespace dory::ubft::tail_cb
