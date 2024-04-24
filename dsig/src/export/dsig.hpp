#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

#include "config.hpp"
#include "types.hpp"

namespace dory::dsig {
class Dsig;

class DsigLib {
 public:
  DsigLib(ProcId id);

  void sign(Signature &sig, uint8_t const *m, size_t mlen);

  bool verify(Signature const &sig, uint8_t const *m, size_t mlen, ProcId pid);
  std::optional<bool> tryFastVerify(Signature const &sig, uint8_t const *m,
                                    size_t mlen, ProcId pid);
  bool slowVerify(Signature const &sig, uint8_t const *m, size_t mlen,
                  ProcId pid);

  void enableSlowPath(bool enable);

  bool replenishedSks(size_t replenished = PreparedSks);

  bool replenishedPks(ProcId pid, size_t replenished = PreparedSks);

 private:
  struct DsigDeleter {
    void operator()(Dsig *) const;
  };
  std::unique_ptr<Dsig, DsigDeleter> impl;
};
}  // namespace dory::dsig
