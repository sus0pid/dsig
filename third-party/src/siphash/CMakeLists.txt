add_library(
  dorythirdpartysiphash
  siphash.c)

target_link_libraries(dorythirdpartysiphash ${CONAN_LIBS})
