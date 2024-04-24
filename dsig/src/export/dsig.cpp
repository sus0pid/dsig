
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <type_traits>

#include "../dsig.hpp"
#include "dsig.hpp"

namespace dory::dsig {
__attribute__((visibility("default"))) void DsigLib::DsigDeleter::operator()(
    Dsig *ptr) const {
  delete ptr;
}

__attribute__((visibility("default"))) DsigLib::DsigLib(ProcId id)
    : impl{std::unique_ptr<Dsig, DsigDeleter>(new Dsig(id), DsigDeleter())} {}

__attribute__((visibility("default"))) void DsigLib::sign(Signature &sig,
                                                          uint8_t const *m,
                                                          size_t mlen) {
  impl->sign(sig, m, mlen);
}

__attribute__((visibility("default"))) bool DsigLib::verify(
    Signature const &sig, uint8_t const *m, size_t mlen, ProcId pid) {
  return impl->verify(sig, m, mlen, pid);
}

__attribute__((visibility("default"))) std::optional<bool>
DsigLib::tryFastVerify(Signature const &sig, uint8_t const *m, size_t mlen,
                       ProcId pid) {
  return impl->try_fast_verify(sig, m, mlen, pid);
}

__attribute__((visibility("default"))) bool DsigLib::slowVerify(
    Signature const &sig, uint8_t const *m, size_t mlen, ProcId pid) {
  return impl->slow_verify(sig, m, mlen, pid);
}

__attribute__((visibility("default"))) void DsigLib::enableSlowPath(
    bool const enable) {
  impl->enable_slow_path(enable);
}

__attribute__((visibility("default"))) bool DsigLib::replenishedSks(
    size_t replenished) {
  return impl->replenished_sks(replenished);
}

__attribute__((visibility("default"))) bool DsigLib::replenishedPks(
    ProcId const pid, size_t replenished) {
  return impl->replenished_pks(pid, replenished);
}

}  // namespace dory::dsig
