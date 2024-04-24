#pragma once

namespace dory::dsig {
enum Path { Fast, Slow };
char const* to_string(Path);
char const* to_string(Path const path) {
  switch (path) {
    case Fast:
      return "FAST";
    case Slow:
      return "SLOW";
    default:
      return "UNKNOWN";
  }
}
}