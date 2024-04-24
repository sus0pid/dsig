#pragma once

#include <cstddef>
#include <string>

static size_t roundUp(size_t numToRound, size_t multiple) {
  return ((numToRound + multiple - 1) / multiple) * multiple;
}

enum class Scheme { None, Dalek, Sodium, Dsig };

static Scheme get_scheme(std::string const &str) {
  if (str == "none") {
    return Scheme::None;
  }

  if (str == "dalek") {
    return Scheme::Dalek;
  }

  if (str == "sodium") {
    return Scheme::Sodium;
  }

  if (str == "dsig") {
    return Scheme::Dsig;
  }

  return Scheme::None;
}
