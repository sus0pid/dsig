add_library(
  dorythirdpartyharaka
  haraka.c)

target_compile_options(dorythirdpartyharaka PRIVATE -march=native -funroll-all-loops -fomit-frame-pointer)

target_link_libraries(dorythirdpartyharaka ${CONAN_LIBS})
