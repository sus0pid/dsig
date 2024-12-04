#include <iostream>

#include "../hsig.hpp"


int main() {
  hybrid_sig::HybridSignature hsig;

  std::string data = "example_data";
  std::string signature = hsig.sign(data);

  if (hsig.verify(data, signature)) {
    std::cout << "Verification succeeded!" << std::endl;
  } else {
    std::cout << "Verification failed!" << std::endl;
  }

  return 0;
}



//#include <iostream>
//
//#include "../hsig.hpp"
//
//int main() {
//  hybrid_sig::HybridSigConfig config{256, 5, 10, std::chrono::milliseconds(1000)};
//  hybrid_sig::HybridSignature hs(config);
//
//  hs.start_background();
//
//  const uint8_t message[] = "Hello, World!";
//  auto signature = hs.sign(message, sizeof(message));
//  bool valid = hs.verify(message, sizeof(message), signature);
//
//  std::cout << "Signature valid: " << std::boolalpha << valid << "\n";
//
//  hs.stop_background();
//
//  return 0;
//}
