#include <chrono>
#include <thread>

#include <fmt/core.h>
#include <lyra/lyra.hpp>

#include <dory/dsig/dsig.hpp>
#include <dory/shared/unused-suppressor.hpp>

int main(int argc, char* argv[]) {
  // dory::ignore(argc);
  // dory::ignore(argv);

  lyra::cli cli;
  bool get_help = false;
  int local_id;

  cli.add_argument(lyra::help(get_help))
      .add_argument(lyra::opt(local_id, "id")
                        .required()
                        .name("-l")
                        .name("--local-id")
                        .help("ID of the present process"));

  // Parse the program arguments.
  auto result = cli.parse({argc, argv});

  if (get_help) {
    std::cout << cli;
    return 0;
  }

  if (!result) {
    std::cerr << "Error in command line: " << result.errorMessage()
              << std::endl;
    return 1;
  }

  unsigned char sm = 'a';
  unsigned long long smlen_p = 0;
  const unsigned char m = 'b';
  unsigned long long mlen = 1;
  const unsigned char sk = 'c';

  fmt::print("Hi dsig!\n");
  dsig_sign(&sm, smlen_p, &m, mlen, &sk);
  dory::dsig::sign(&sm, smlen_p, &m, mlen, &sk);

  fmt::print("Dsig class\n");
  dory::dsig::Dsig dsig(local_id);
  dory::dsig::Signature signature;
  while (true) {
    dsig.sign(signature, &m, mlen);
    fmt::print("Signed.\n");
    {
      auto const valid = dsig.verify(signature, &m, mlen, local_id);
      fmt::print("Signature is valid: {}.\n", valid);
    }
    {
      auto const valid = dsig.slow_verify(signature, &m, mlen, local_id);
      fmt::print("[slow] Signature is valid: {}.\n", valid);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  std::this_thread::sleep_for(std::chrono::seconds(10));

  // if (local_id == 1 || local_id == 2) {
  //   std::this_thread::sleep_for(std::chrono::seconds(4));
  //   dsig.send(static_cast<uint8_t>(local_id));
  // }

  // while (true) {
  //   dsig.receive();
  // }

  return 0;
}
