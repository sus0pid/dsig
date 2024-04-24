#pragma once

#include "../sig-switch.hpp"
#include "../../buffer.hpp"
#include "../../message.hpp"

namespace dory::ubft::tail_cb::internal {

class SignatureMessage : public ubft::Message {
 public:
  using Signature = TcbCrypto::Signature;
  using Message::Message;
  using Index = size_t;

  struct BufferLayout {
    Index index;
    Signature signature;
  };

  // static_assert(sizeof(BufferLayout) ==
  //                   sizeof(Index) + sizeof(Signature),
  //               "The BufferLayout struct is not packed. Use "
  //               "`__attribute__((__packed__))` to pack it");

  auto static constexpr BufferSize = sizeof(BufferLayout);

  static std::variant<std::invalid_argument, SignatureMessage> tryFrom(
      Buffer &&buffer) {
    if (buffer.size() != BufferSize) {
      return std::invalid_argument("Buffer is not of size BufferSize.");
    }
    return SignatureMessage(std::move(buffer));
  }

  Index index() const {
    return *reinterpret_cast<Index const *>(rawBuffer().data());
  }

  Signature const &signature() const {
    return *reinterpret_cast<Signature const *>(
        rawBuffer().data() + offsetof(BufferLayout, signature));
  }
};

}  // namespace dory::ubft::tail_cb::internal
