#include <algorithm>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <fmt/core.h>
#include <toml.hpp>

#include "types.hpp"

namespace dory::dsig {

class RuntimeConfig {
 public:
  RuntimeConfig(ProcId id, std::string const& default_config_path = "dsig.toml")
      : my_id{id} {
    char const* env_config_path = getenv("DSIG_CONFIG");
    char const* config_path =
        env_config_path ? env_config_path : default_config_path.c_str();

    toml::table tbl;
    try {
      tbl = toml::parse_file(config_path);
    } catch (const toml::parse_error& err) {
      // throw std::runtime_error(fmt::format("Failed to parse DSIG_CONFIG
      // ({})", err));
      throw std::runtime_error("Failed to parse DSIG_CONFIG");
    }

    std::optional<std::string> opt_nic = tbl["nic"].value<std::string>();
    if (!opt_nic) {
      throw std::runtime_error("You must provide the `nic` in the DSIG_CONFIG");
    }
    nic = *opt_nic;

    if (toml::array* arr = tbl["procs"].as_array()) {
      ids = parse_ids(arr);
    } else {
      throw std::runtime_error(
          "You must provide the `procs` in the DSIG_CONFIG");
    }

    if (std::find(ids.begin(), ids.end(), id) == ids.end()) {
      throw std::runtime_error(fmt::format(
        "Your id (i.e., {}) is not in `procs` of DSIG_CONFIG", id));
    }

    std::copy_if(ids.begin(), ids.end(), std::back_inserter(remote_ids),
                 [this](ProcId x) { return x != my_id; });

    if (toml::array* arr = tbl["signers"].as_array()) {
      signer_ids = parse_ids(arr);
      if (!contained_in(signer_ids, ids)) {
        throw std::runtime_error("Unknown signer id in the DSIG_CONFIG");
      }
    } else {
      fmt::print("[DSIG_CONFIG] No signers specified, assuming all processes sign.\n");
      signer_ids = remote_ids;
    }

    if (toml::array* arr = tbl["verifiers"].as_array()) {
      verifier_ids = parse_ids(arr);
      if (!contained_in(verifier_ids, ids)) {
        throw std::runtime_error("Unknown verifier id in the DSIG_CONFIG");
      }
    } else {
      fmt::print("[DSIG_CONFIG] No verifiers specified, assuming all processes verify.\n");
      verifier_ids = remote_ids;
    }
  }

  std::string deviceName() const { return nic; }

  ProcId myId() const { return my_id; }
  std::vector<ProcId> const& allIds() { return ids; }
  std::vector<ProcId> const& remoteIds() { return remote_ids; }
  std::vector<ProcId> const& signerIds() { return signer_ids; }
  std::vector<ProcId> const& verifierIds() { return verifier_ids; }

 private:
  ProcId my_id;
  std::vector<ProcId> ids;
  std::vector<ProcId> remote_ids;
  std::vector<ProcId> signer_ids;
  std::vector<ProcId> verifier_ids;
  std::string nic;

  bool contained_in(std::vector<ProcId> const& a, std::vector<ProcId> const& b) {
    for (auto const id : a) {
      if (std::find(b.begin(), b.end(), id) == b.end())
        return false;
    }
    return true;
  }

  std::vector<ProcId> parse_ids(toml::array* const arr) {
    std::vector<ProcId> ret;
    arr->for_each([&ret](auto&& el) {
      if constexpr (toml::is_number<decltype(el)>) {
        if (*el <= 0) {
          throw std::runtime_error(
              "Process ids have to be positive in `procs` of DSIG_CONFIG");
        }
        ret.push_back(static_cast<ProcId>(*el));
      } else {
        throw std::runtime_error(
            "Process ids have to be integers in `procs` of DSIG_CONFIG");
      }
    });

    std::set<ProcId> ids_dups(ids.begin(), ids.end());
    if (ids_dups.size() != ids.size()) {
      throw std::runtime_error(
          "There are duplicate entries in `procs` of DSIG_CONFIG");
    }

    return ret;
  }
};

}  // namespace dory::dsig
