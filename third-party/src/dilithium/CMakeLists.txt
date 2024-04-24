add_library(
  dorythirdpartydilithium
  sign.c packing.c polyvec.c poly.c ntt.S invntt.S pointwise.S randombytes.c
  rng.c shuffle.S f1600x4.S fips202x4.c consts.c rejsample.c rounding.c fips202.c
  aes256ctr.c symmetric-shake.c)

target_compile_options(dorythirdpartydilithium PUBLIC -mavx2 -mpopcnt -maes
-march=native -mtune=native)

target_compile_definitions(dorythirdpartydilithium PRIVATE DILITHIUM_MODE=2 DILITHIUM_USE_AES)

target_link_libraries(dorythirdpartydilithium ${CONAN_LIBS})
