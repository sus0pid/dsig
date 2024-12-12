#include <iostream>
#include <string>
#include <thread>

#include <dory/memstore/store.hpp>

int main() {
  try {
    // Initialize MemoryStore
    dory::memstore::MemoryStore &store = dory::memstore::MemoryStore::getInstance();

    // Test 1: Setting a key-value pair
    std::cout << "Test 1: Setting a key-value pair..." << std::endl;
    try {
      store.set("test_key", "test_value");
      std::cout << "Set operation succeeded!" << std::endl;
    } catch (std::exception &e) {
      std::cerr << "Set operation failed: " << e.what() << std::endl;
    }

    // Test 2: Getting the value for a key
    std::cout << "Test 2: Getting the value for a key..." << std::endl;
    std::string value;
    try {
      if (store.get("test_key", value)) {
        std::cout << "Get operation succeeded! Value: " << value << std::endl;
      } else {
        std::cout << "Key not found!" << std::endl;
      }
    } catch (std::exception &e) {
      std::cerr << "Get operation failed: " << e.what() << std::endl;
    }

    // Test 3: Trying to set a duplicate key
    std::cout << "Test 3: Trying to set a duplicate key..." << std::endl;
    try {
      store.set("test_key", "new_value");
      std::cerr << "Duplicate set operation did not throw an error!" << std::endl;
    } catch (std::exception &e) {
      std::cout << "Duplicate set operation failed as expected: " << e.what() << std::endl;
    }

    // Test 4: Barrier synchronization
    std::cout << "Test 4: Barrier synchronization..." << std::endl;
    try {
      size_t wait_for = 3;
      std::cout << "Waiting for " << wait_for << " increments on barrier 'test_barrier'..." << std::endl;

      // Simulate another process incrementing the barrier
      std::thread incrementer([&store]() {
        for (size_t i = 0; i < 3; ++i) {
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
          store.barrier("test_barrier", 3);
        }
      });

      store.barrier("test_barrier", wait_for);
      incrementer.join();

      std::cout << "Barrier synchronization succeeded!" << std::endl;
    } catch (std::exception &e) {
      std::cerr << "Barrier synchronization failed: " << e.what() << std::endl;
    }

  } catch (std::exception &e) {
    std::cerr << "Test failed with exception: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
