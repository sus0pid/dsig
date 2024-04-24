add_library(
  dorythirdpartysha256
  sha256.c
  sha256avx.c)

target_compile_options(dorythirdpartysha256 PRIVATE -mavx2 -g -funroll-all-loops -Wall)

target_link_libraries(dorythirdpartysha256 ${CONAN_LIBS})