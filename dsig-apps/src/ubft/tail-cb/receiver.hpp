#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <stdexcept>
#include <unordered_set>
#include <variant>
#include <chrono>

#include <fmt/core.h>
#include <fmt/ranges.h>
#include <xxhash.h>
#include <hipony/enumerate.hpp>

#include <dory/conn/rc.hpp>
#include <dory/crypto/hash/blake3.hpp>
#include <dory/shared/branching.hpp>
#include <dory/shared/dynamic-bitset.hpp>
#include <dory/shared/match.hpp>
#include <dory/shared/optimistic-find.hpp>
#include <dory/shared/units.hpp>
#include <dory/shared/unused-suppressor.hpp>

#include "sig-switch.hpp"
#include "../buffer.hpp"
#include "../crypto.hpp"
#include "../replicated-swmr/reader.hpp"
#include "../replicated-swmr/writer.hpp"
#include "../tail-p2p/receiver.hpp"
#include "../tail-p2p/sender.hpp"
#include "../thread-pool/tail-thread-pool.hpp"
#include "../types.hpp"
#include "../unsafe-at.hpp"

#include "../latency-hooks.hpp"

namespace dory::ubft::tail_cb {

class Receiver {
  std::chrono::steady_clock::time_point message_polled, signature_polled, write_started, signature_verify, signature_verified, write_completed, reads_started, reads_completed, cb_message_polled, debug0, debug1, debug2, debug3, debug4, debug5, debug6, debug7;

  auto static constexpr SlowPathEnabled = true;
  // When to switch from raw echo to hashed echo.
  auto static constexpr HashThreshold = units::kibibytes(8);
  using Hash = crypto::hash::Blake3Hash;
  auto static constexpr HashLength = crypto::hash::Blake3HashLength;

 public:
  using Index = Message::Index;
  using Size = tail_p2p::Size;

 private:
  using SignatureMessage = internal::SignatureMessage;
  using Signature = SignatureMessage::Signature;

  auto static constexpr CustomIncarnationsEnabled = true;

  struct VerifiedSignature {
    Index index;
    bool ok;
    enum Origin { Broadcaster, ReceiverRegister } origin;
  };

  struct Register {
    crypto::hash::Blake3Hash hash;
    Signature signature;
  };
  struct HashRegister {
    crypto::hash::Blake3Hash hash; // hash of the signature
  };

 public:
  static size_t constexpr maxEchoSize(size_t max_msg_size) {
    return Message::bufferSize(std::min(max_msg_size, HashThreshold - 1));
  }

  size_t static constexpr RegisterValueSize = sizeof(Register);
  size_t static constexpr HashRegisterValueSize = sizeof(HashRegister);

  Receiver(Crypto &crypto, TailThreadPool &thread_pool,
           const ProcId broadcaster_id, size_t const borrowed_messages,
           size_t const tail, size_t const max_msg_size,
           tail_p2p::Receiver &&message_receiver,
           tail_p2p::Receiver &&signature_receiver,
           std::vector<tail_p2p::Receiver> &&echo_receivers,
           std::vector<tail_p2p::AsyncSender> &&echo_senders,
           std::vector<replicated_swmr::Reader> &&swmr_readers,
           replicated_swmr::Writer &&swmr_writer,
           std::vector<replicated_swmr::Reader> &&hash_swmr_readers,
           replicated_swmr::Writer &&hash_swmr_writer)
      : crypto{crypto},
        broadcaster_id{broadcaster_id},
        tail{tail},
        message_receiver(std::move(message_receiver)),
        signature_receiver(std::move(signature_receiver)),
        echo_senders{std::move(echo_senders)},
        echo_receivers{std::move(echo_receivers)},
        swmr_writer{std::move(swmr_writer)},
        swmr_readers{std::move(swmr_readers)},
        hash_swmr_writer{std::move(hash_swmr_writer)},
        hash_swmr_readers{std::move(hash_swmr_readers)},
        message_buffer_pool{borrowed_messages + tail + 1,
                            Message::bufferSize(max_msg_size)},
        signature_buffer_pool{tail + 1, SignatureMessage::BufferSize},
        echo_buffer_pool{this->echo_receivers.size() * (tail + 1),
                         maxEchoSize(max_msg_size)},
        recv_check_task_queue{thread_pool, tail} {
    for (auto &_ : this->swmr_readers) {
      read_check_task_queues.emplace_back(thread_pool, tail);
    }
    always_assert(
        ("For each other receiver, we should have 1 p2p-sender, 1 p2p-receiver "
         "and 1 swmr-reader.",
         this->echo_receivers.size() == this->echo_senders.size() &&
             this->echo_senders.size() == this->swmr_readers.size()));

    for (auto &_ : this->echo_receivers) {
      buffered_echoes.emplace_back();
    }
  }

  void tick() {
    // We help others make progress, even if we delivered ourselves.
    if (shouldRunFastPath()) {
      for (auto &sender : echo_senders) {
        sender.tickForCorrectness();
      }
    }

    // We poll messages from the broadcaster and only continue the tick if we
    // have something to deliver.
    pollBroadcasterMessage();
    if (msg_tail.empty()) {
      return;
    }

    // We will try to deliver it via echoes.
    if (shouldRunFastPath()) pollEchoes();

    // Otherwise, if enabled, we will run the slow path.
    if (likely(!shouldRunSlowPath())) {
      return;
    }
    pollBroadcasterSignature();
    pollSignatureVerifications();
    swmr_writer.tick();
    hash_swmr_writer.tick();
    pollWriteCompletions();
    for (auto &reader : swmr_readers) {
      reader.tick();
    }
    for (auto &reader : hash_swmr_readers) {
      reader.tick();
    }
    pollReadCompletions();
  }

  /**
   * @brief Poll a message if any is available.
   *        At most `tail` messages can be held by the upper-level abstraction.
   *
   * @return std::optional<Message>
   */
  std::optional<Message> poll() {
    if (msg_tail.empty() || !msg_tail.begin()->second.pollable()) {
      return std::nullopt;
    }
    // We bump the 'latest_polled_message' marker to enforce FIFO ordering.
    latest_polled_message = msg_tail.begin()->first;
    auto to_ret = msg_tail.begin()->second.extractMessage();
    // Pop the entry from the map;
    msg_tail.erase(msg_tail.begin());
    cb_message_polled = std::chrono::steady_clock::now();
    // fmt::print("Timeline: msg polled at 0ns, sign polled at {}, write started at {}, debug0 {}, debug1 {}, debug2 {}, debug3 {}, debug4 {}, debug5 {}, debug6 {}, debug7 {}, sign verify started at {}, sign verified at {}, write completed at {}, reads started at {}, reads completed at {}, cb msg polled at {}\n", signature_polled-message_polled, write_started-message_polled,

    // debug0-message_polled, debug1-message_polled, debug2-message_polled, debug3-message_polled, 
    // debug4-message_polled, debug5-message_polled, debug6-message_polled, debug7-message_polled, 
    
    // signature_verify-message_polled, signature_verified-message_polled, write_completed-message_polled, reads_started-message_polled, reads_completed-message_polled, cb_message_polled-message_polled);
    return to_ret;
  }

  void toggleFastPath(bool const enable) { fast_path_on = enable; }
  inline bool shouldRunFastPath() const {
    return fast_path_on;
  }
  bool fast_path_on = true;

  void toggleSlowPath(bool const enable) {
    if (enable && !SlowPathEnabled) {
      throw std::runtime_error("Slow path was disabled at compilation.");
    }
    slow_path_on = enable;
  }

  ProcId procId() const { return message_receiver.procId(); }

  ProcId broadcasterId() const { return broadcaster_id; }

 private:
  void pollBroadcasterMessage() {
    auto opt_buffer = message_buffer_pool.borrowNext();
    if (unlikely(!opt_buffer)) {
      throw std::runtime_error("User is retaining all buffers in Messages.");
    }
    auto opt_polled = message_receiver.poll(opt_buffer->get().data());
    if (!opt_polled) {
      return;
    }
    message_polled = std::chrono::steady_clock::now();
    auto msg = Message::tryFrom(*message_buffer_pool.take(*opt_polled));
    match{msg}(
        [](std::invalid_argument &e) {
          throw std::logic_error(fmt::format("Unimplemented: {}", e.what()));
        },
        [this](Message &m) { handleMessage(std::move(m)); });
  }

  void pollBroadcasterSignature() {
    auto opt_buffer = signature_buffer_pool.borrowNext();
    if (unlikely(!opt_buffer)) {
      throw std::logic_error("Error, buffers not recycled correctly.");
    }
    auto opt_polled = signature_receiver.poll(opt_buffer->get().data());
    if (!opt_polled) {
      return;
    }
    signature_polled = std::chrono::steady_clock::now();
    auto msg = internal::SignatureMessage::tryFrom(
        *signature_buffer_pool.take(*opt_polled));
    match{msg}(
        [](std::invalid_argument &e) {
          throw std::logic_error(fmt::format("Unimplemented: {}", e.what()));
        },
        [this](SignatureMessage &m) { handleSignature(std::move(m)); });
  }

  /**
   * @brief Poll echoes received from other receivers (via p2p).
   *
   */
  void pollEchoes() {
    for (auto &&[r, receiver] : hipony::enumerate(echo_receivers)) {
      auto opt_buffer = echo_buffer_pool.borrowNext();
      if (unlikely(!opt_buffer)) {
        throw std::logic_error("Error, buffers not recycled correctly.");
      }
      auto const polled = receiver.poll(opt_buffer->get().data());
      if (!polled) {
        continue;
      }
      auto echo = Message::tryFrom(*echo_buffer_pool.take(*polled));
      auto &replica = r;  // bug: structured bindings cannot be captured
      match{echo}(
          [&](std::invalid_argument &e) {
            fmt::print("Malformed echo from {}: {}.\n", replica, e.what());
          },
          [&](Message &m) { handleEcho(std::move(m), replica); });
    }
  }

  /**
   * @brief Handle a Data message (i.e., containing the actual cb-broadcast
   * message).
   *
   * @param message
   */
  void handleMessage(Message &&message) {
    auto const index = message.index();
    // fmt::print("Polled Message #{} from broadcaster (size = {})\n", index,
    //            message.size());
    // We create an entry in the tail_msg map to store data about this message.
    if (unlikely(pessimistic_find(msg_tail, index) != msg_tail.end() ||
                 latest_polled_message >= index)) {
      throw std::logic_error(
          "Unimplemented (Byzantine Broadcaster sent the same message more "
          "than once)!");
    }
    if (unlikely(!msg_tail.empty() && msg_tail.rbegin()->first >= index)) {
      fmt::print(
          "Message dropped as it was received out of order (Byzantine).\n");
      return;
    }
    auto &msg_data =
        msg_tail.try_emplace(index, std::move(message), echo_receivers.size())
            .first->second;
    if (msg_tail.size() > tail) {
      msg_tail.erase(msg_tail.begin());
    }

    if (!shouldRunFastPath()) return;

    // We replay all buffered echoes
    for (auto &&[replica, echo_buffer] : hipony::enumerate(buffered_echoes)) {
      while (unlikely(!echo_buffer.empty() &&
                      echo_buffer.front().index() < index)) {
        echo_buffer.pop_front();
      }
      if (unlikely(!echo_buffer.empty() &&
                   echo_buffer.front().index() == index)) {
        if (unlikely(!msg_data.echoed(replica, echo_buffer.front()))) {
          throw std::logic_error(
              "Unimplemented (Byzantine behavior, replica Echoed twice)!");
        }
        echo_buffer.pop_front();
      }
    }

    // We send all echoes
    for (auto &sender : echo_senders) {
      auto &message = msg_data.getMessage();
      if (likely(message.size() < HashThreshold)) {
        // If the message is small enough, we send a raw copy.
        const auto &raw_buffer = message.rawBuffer();
        auto *echo_buffer = reinterpret_cast<uint8_t *>(
            sender.getSlot(static_cast<Size>(raw_buffer.size())));
        std::copy(raw_buffer.cbegin(), raw_buffer.cend(), echo_buffer);
      } else {
        // Otherwise we send its hash.
        auto &echo_buffer = *reinterpret_cast<Message::BufferLayout *>(
            sender.getSlot(static_cast<Size>(Message::bufferSize(HashLength))));
        echo_buffer.header.index = message.index();
        *reinterpret_cast<Hash *>(&echo_buffer.data) = msg_data.hash();
      }
      sender.send();
    }
  }

  /**
   * @brief Handle an echo message.
   *
   * @param message
   */
  void handleEcho(Message &&echo, size_t const replica) {
    // fmt::print("Polled echo #{} from replica {}\n", echo.index, replica);
    // We discard echoes that aren't useful.
    if (latest_polled_message > echo.index() ||
        (!msg_tail.empty() && msg_tail.begin()->first > echo.index())) {
      return;
    }
    // If we already received the message, we take the echo into account.
    auto md_it = optimistic_find_front(msg_tail, echo.index());
    if (md_it != msg_tail.end()) {
      if (unlikely(!md_it->second.echoed(replica, echo))) {
        throw std::logic_error(
            "Unimplemented (Byzantine behavior, replica Echoed twice)!");
      }
      return;
    }
    // Otherwise, we buffer it.
    auto &echo_buffer = buffered_echoes[replica];
    if (unlikely(!echo_buffer.empty() &&
                 echo_buffer.back().index() > echo.index())) {
      throw std::logic_error(
          "Unimplemented (Byzantine behavior, Echoes sent out of order)!");
    }
    echo_buffer.emplace_back(std::move(echo));
    if (echo_buffer.size() > tail) {
      echo_buffer.pop_front();
    }
  }

  /**
   * @brief Handle a Signature message that should have been p2p-sent by the
   * broadcaster after the associated Data message.
   *
   * @param message
   */
  void handleSignature(SignatureMessage &&signature_message) {
    auto index = signature_message.index();
    auto msg_data_it = optimistic_find_front(msg_tail, index);

    // If the associated message is not in the tail anymore, the signature is
    // useless.
    if (msg_data_it == msg_tail.end()) {
      // We get back the buffer that was storing the signature.
      return;
    }
    auto &msg_data = msg_data_it->second;
    if (msg_data.hasSignature()) {
      throw std::logic_error(fmt::format(
          "Unimplemented (Byzantine Broadcaster {} sent the signature more "
          "than once)!",
          broadcaster_id));
    }

    msg_data.setSignature(std::move(signature_message));
    // It is actually safe to first write the sig and only then verify it.
    // Worst case we write an incorrect sig: we would not have delivered it anyway,
    // others can indeed ignore it. This hides latency.
    // ---We verify the signature in the background. Only after its verification
    // will we write it to our SWMR register.---
    // void writeSignature(Index const index, MessageData &mdg_data)
    {
      // We now write the received signature to our SWMR.
      write_started = std::chrono::steady_clock::now();
      auto swmr_index = index % tail;
      if (outstanding_writes.find(swmr_index) != outstanding_writes.end()) {
        throw std::logic_error(
            "Unimplemented: recycled swmr before completion of the "
            "previous WRITE.");
      }
      // debug0 = std::chrono::steady_clock::now();
      auto opt_slot = swmr_writer.getSlot(swmr_index);
      auto opt_hash_slot = hash_swmr_writer.getSlot(swmr_index);
      if (!opt_slot || !opt_hash_slot) {
        throw std::logic_error(
            "Called getSlot before the previous WRITE completed.");
      }
      auto &slot = *reinterpret_cast<Register *>(*opt_slot);
      // debug1 = std::chrono::steady_clock::now();
      slot.hash = msg_data.hash();
      // debug2 = std::chrono::steady_clock::now();
      std::memcpy(&slot.signature, &msg_data.getSignature(), sizeof(slot.signature));
      // slot.signature = msg_data.getSignature();
      // debug3 = std::chrono::steady_clock::now();
      auto &hash_slot = *reinterpret_cast<HashRegister*>(*opt_hash_slot);
      hash_slot.hash = msg_data.hash();
      // debug4 = std::chrono::steady_clock::now();
      auto const incarnation = index / tail + 1;
      // debug5 = std::chrono::steady_clock::now(); // 12200
      swmr_writer.write(swmr_index, incarnation);
      // debug6 = std::chrono::steady_clock::now();
      hash_swmr_writer.write(swmr_index, incarnation);
      // debug7 = std::chrono::steady_clock::now();
      outstanding_writes.try_emplace(swmr_index, index);
    }
    #ifdef LATENCY_HOOKS
      hooks::sig_check_start = hooks::Clock::now();
    #endif
    // recv_check_task_queue.enqueue([this, index, hash = msg_data.hash(),
    //                                signature = msg_data.getSignature()] {
      auto const& hash = msg_data.hash();
      auto const& signature = msg_data.getSignature();
      #ifdef LATENCY_HOOKS
      hooks::sig_check_real_start = hooks::Clock::now();
      #endif
      signature_verify = std::chrono::steady_clock::now();
      auto ok =
          TcbCrypto::crypto(crypto).verify(signature, hash.data(), hash.size(), broadcaster_id);
      #ifdef LATENCY_HOOKS
      hooks::sig_check_real_latency.addMeasurement(hooks::Clock::now() - hooks::sig_check_real_start);
      #endif

      verified_signatures.emplace_back(VerifiedSignature{index, ok, VerifiedSignature::Broadcaster});
    //});
  }

  /**
   * @brief Poll the completion of signature verifications that were running in
   * in the thread pool.
   *
   */
  void pollSignatureVerifications() {
    while (!verified_signatures.empty()) {
      VerifiedSignature verified_signature{std::move(verified_signatures.front())};
      verified_signatures.pop_front();
      signature_verified = std::chrono::steady_clock::now();
      #ifdef LATENCY_HOOKS
        hooks::sig_check_latency.addMeasurement(hooks::Clock::now() - hooks::sig_check_start);
      #endif
      auto [index, ok, origin] = verified_signature;
      // fmt::print("In pollSignatureVerifications, index: {}, ok: {}, origin:
      // {}\n", index, ok, origin);
      auto md_it = optimistic_find_front(msg_tail, index);
      // If the associated message is not in the tail anymore, the signature is
      // useless.
      if (md_it == msg_tail.end()) {
        continue;
      }
      auto &msg_data = md_it->second;
      switch (origin) {
        case VerifiedSignature::Broadcaster: {
          // If a signature comes from the broadcaster, it should be valid.
          #ifdef LATENCY_HOOKS
            hooks::swmr_write_start = hooks::Clock::now();
          #endif
          if (!ok) {
            throw std::logic_error(fmt::format(
                "Unimplemented: Byzantine broadcaster {} sent an invalid "
                "signature for {}.",
                broadcaster_id, index));
          }
          break;
        }
        case VerifiedSignature::ReceiverRegister: {
          // Signatures found in a receiver's SWMR are only checked if they
          // do not match the one received directly from the broadcaster.
          // In this case, a valid signature implies an equivocation.
          if (ok) {
            throw std::logic_error(
                fmt::format("Unimplemented: Byzantine broadcaster {} "
                            "equivocated for index {}.",
                            broadcaster_id, index));
          }
          // We mark this receiver as being safe from equivocation.
          msg_data.checkedAReceiver();
          break;
        }
        default:
          throw std::runtime_error("Uncaught switch statement case");
      }
    }
  }

  void pollWriteCompletions() {
    // We iterate over the map of reads while removing its elements.
    for (auto it = outstanding_writes.begin(); it != outstanding_writes.end();
         /* in body */) {
      auto &[swmr_index, ihf] = *it;
      auto const index = ihf.index;
      if (!ihf.hash_completed) ihf.hash_completed = hash_swmr_writer.completed(swmr_index);
      if (!ihf.full_completed) ihf.full_completed = swmr_writer.completed(swmr_index);
      if (!ihf.hash_completed || !ihf.full_completed) {
        ++it;
        continue;
      }
      write_completed = std::chrono::steady_clock::now();
      #ifdef LATENCY_HOOKS
        hooks::swmr_write_latency.addMeasurement(hooks::Clock::now() - hooks::swmr_write_start);
      #endif
      it = outstanding_writes.erase(it);
      // If the message is not in the tail anymore, we discard the WRITE.
      auto md_it = optimistic_find_front(msg_tail, index);
      if (md_it == msg_tail.end()) {
        continue;
      }
      // Otherwise, we enqueue READs.
      auto &vec = outstanding_reads.try_emplace(index).first->second;
      #ifdef LATENCY_HOOKS
        hooks::swmr_read_start = hooks::Clock::now();
      #endif
      reads_started = std::chrono::steady_clock::now();
      for (auto &hash_reader : hash_swmr_readers) {
        // TODO: also read the full sig when necessary
        vec.emplace_back(hash_reader.read(swmr_index));
      }
    }
  }

  void pollReadCompletions() {
    // We iterate over the map of reads while removing its elements.
    for (auto it = outstanding_reads.begin(); it != outstanding_reads.end();
         /* in body */) {
      auto [index, opt_job_handles] = *it;
      size_t completed_reads = 0;
      for (auto &&[replica, hash_swmr_reader] : hipony::enumerate(hash_swmr_readers)) {
        // We fetch the handle for this specific replica.
        auto &opt_job_handle = opt_job_handles[replica];
        // If the (optional) handle is empty, then it already completed.
        if (!opt_job_handle) {
          completed_reads++;
          continue;
        }
        // Otherwise, we check its completion.
        auto opt_polled = hash_swmr_reader.poll(*opt_job_handle);
        if (!opt_polled) {
          continue;
        }
        auto const expected_incarnation = index / tail + 1;
        if (opt_polled->second > expected_incarnation) {
          throw std::logic_error(
              fmt::format("Unimplemented: SWMR was recycled: incarnation {} "
                          "found, {} expected.",
                          opt_polled->second, expected_incarnation));
        }
        completed_reads++;
        opt_job_handle.reset();
        // If the message is not in the tail anymore, we discard the READ.
        auto md_it = optimistic_find_front(msg_tail, index);
        if (md_it == msg_tail.end()) {
          continue;
        }
        // Otherwise, we compare the read signature against the one we received.
        auto &hash =
            reinterpret_cast<HashRegister *>(opt_polled->first.get())->hash;
        auto &msg_data = md_it->second;
        // if it is the same, then the receiver is "safe".
        if (opt_polled->second < expected_incarnation ||
            msg_data.hashMatches(hash)) {
          msg_data.checkedAReceiver();
        } else {
          // // Otherwise, someone acted Byzantine, we need to determine who it is.
          // uat(read_check_task_queues, replica)
          //     .enqueue([this, index = index,
          //               buffer = std::move(opt_polled->first)]() {
          //       auto const &reg = *reinterpret_cast<Register *>(buffer.get());
          //       auto ok = TcbCrypto::crypto(crypto).verify(reg.signature, reg.hash.data(),
          //                               reg.hash.size(), broadcaster_id);
          //       verified_signatures.enqueue(
          //           {index, ok, VerifiedSignature::ReceiverRegister});
          //     });
          throw std::logic_error("Unimplemented: sig hashes don't match, read the full slot to see what happened.");
        }
      }
      if (completed_reads == hash_swmr_readers.size()) {
        reads_completed = std::chrono::steady_clock::now();
        it = outstanding_reads.erase(it);
        #ifdef LATENCY_HOOKS
          hooks::swmr_read_latency.addMeasurement(hooks::Clock::now() - hooks::swmr_read_start);
        #endif
      } else {
        ++it;
      }
    }
  }

  inline bool shouldRunSlowPath() const {
    return SlowPathEnabled && slow_path_on;
  }

  bool slow_path_on = false;

  Crypto &crypto;
  ProcId const broadcaster_id;
  size_t const tail;

  // Receivers for messages and signature from the broadcaster
  tail_p2p::Receiver message_receiver;
  tail_p2p::Receiver signature_receiver;

  // Echo to everyone the message from the broadcaster
  std::vector<tail_p2p::AsyncSender> echo_senders;

  // Receive the echoes from everyone
  std::vector<tail_p2p::Receiver> echo_receivers;

  // Write the messages with is (verified) signature to your indestructible
  // register
  replicated_swmr::Writer swmr_writer;

  // Scan the indestructible registers of others
  std::vector<replicated_swmr::Reader> swmr_readers;

  // Faster path only to check the hash of the big signature
  replicated_swmr::Writer hash_swmr_writer;
  std::vector<replicated_swmr::Reader> hash_swmr_readers;

  class MessageData {
   public:
    MessageData(Message &&message, size_t const other_receivers)
        : message{std::move(message)},
          other_receivers{other_receivers},
          echoes{other_receivers} {}

    /**
     * @brief Mark this message as having been echoed.
     *
     * @param replica that echoed the message.
     * @param echo the echo message.
     * @return true if it is the first time this replica echoed the message,
     * @return false otherwise.
     */
    bool echoed(size_t const replica, Message const &echo) {
      // If the message is small enough, we expect to have received a raw copy.
      if (likely(message.size() < HashThreshold)) {
        if (unlikely(message != echo)) {
          fmt::print("Messages didn't match.\n");
          echoes_match = false;
        }
        return echoes.set(replica);
      }
      // Otherwise, we expect to have received a hash.
      if (unlikely(echo.size() != HashLength)) {
        fmt::print("Echo size does not matches a hash.\n");
        echoes_match = false;
        return echoes.set(replica);
      }
      auto const &hsh = *reinterpret_cast<Hash const *>(echo.data());
      if (unlikely(hsh != hash())) {
        fmt::print("Received hash did not match.\n");
        echoes_match = false;
      }
      return echoes.set(replica);
    }

    bool hasSignature() const { return signature.has_value(); }

    /**
     * @brief Set the Signature object.
     *
     * @param sgn
     * @return true if it is the first time the signature is set,
     * @return false otherwise.
     */
    bool setSignature(internal::SignatureMessage &&sgn) {
      if (signature) {
        return false;
      }
      signature.emplace(std::move(sgn));
      return true;
    }

    bool hashMatches(Hash const &o) {
      return std::memcmp(o.data(), hash().data(), hash().size()) == 0;
    }

    bool signatureMatches(Signature const &sign) const {
      return signature && std::memcmp(&sign, &signature->signature(), sizeof(sign)) == 0;
      // sign == signature->signature();
    }

    bool signatureHashMatches(Hash const &hash) {
      return signature && std::memcmp(hash.data(), signatureHash().data(), hash.size()) == 0;
    }

    Signature const &getSignature() const {
      if (!signature) {
        throw std::logic_error("Cannot get the signature before receiving it.");
      }
      return signature->signature();
    }

    void checkedAReceiver() {
      checked_receivers++;
      // TODO(Ant.): improve with echoes: a process that echoed does not need to
      // be further checked.
    }

    bool pollable() const {
      return (echoes.full() && echoes_match) ||     // Fast Path
             checked_receivers == other_receivers;  // Slow path
    }

    Message const &getMessage() const { return message; }

    Message extractMessage() {
      if (message.moved) {
        throw std::logic_error("The message was already moved.");
      }
      return std::move(message);
    }

    Hash const &hash() {
      if (!computed_hash) {
        computed_hash.emplace(message.hash());
      }
      return *computed_hash;
    }

    Hash const &signatureHash() {
      if (!computed_signature_hash) {
        computed_signature_hash.emplace(signature->hash());
      }
      return *computed_signature_hash;
    }

   private:
    Message message;                    // Message itself
    std::optional<Hash> computed_hash;  // Message's hash.
    std::optional<Hash> computed_signature_hash;  // Message + sig hash.
    size_t const other_receivers;
    DynamicBitset echoes;  // Echoes received on this message
    bool echoes_match = true;

    std::optional<internal::SignatureMessage>
        signature;  // Signature received from the broadcaster
    size_t checked_receivers = 0;
  };

  Pool message_buffer_pool;
  Pool signature_buffer_pool;
  Pool echo_buffer_pool;

  std::map<Index, MessageData> msg_tail;
  std::optional<Index> latest_polled_message;
  std::vector<std::deque<Message>> buffered_echoes;

  std::deque<VerifiedSignature>
      verified_signatures;  // TODO(Antoine): define a max depth?
  // Map: Index to the register in the array of registers that I own -> The
  // index of the CB message (i.e., k).
  struct IndexHashFull {
    IndexHashFull(Index const index):
      index{index},
      hash_completed{false},
      full_completed{false} {}
    Index index;
    bool hash_completed;
    bool full_completed;
  };
  std::map<replicated_swmr::Writer::Index, IndexHashFull> outstanding_writes;

  // Map: Index of the CB message -> The job handle for each register in the
  // register arrays owned from all the others. The job handle is optional to
  // mark the read as completed.
  std::map<Index,
           std::vector<std::optional<replicated_swmr::Reader::JobHandle>>>
      outstanding_reads;  // TODO(Antoine): limit growth?

  TailThreadPool::TaskQueue recv_check_task_queue;
  std::vector<TailThreadPool::TaskQueue> read_check_task_queues;
};

}  // namespace dory::ubft::tail_cb
