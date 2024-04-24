#pragma once

#include <functional>

namespace dory::dsig {

class Workers {
public:
  void schedule(std::function<void()>work) {
    work();
  }
};

}