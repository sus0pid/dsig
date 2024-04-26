cmake_minimum_required(VERSION 3.9)
project(dorydsig CXX)

include(${CMAKE_BINARY_DIR}/setup.cmake)
dory_setup_cmake()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-strict-overflow -Wno-packed")

string(TIMESTAMP BUILD_TIME "%Y-%m-%d %H:%M")
add_definitions(-DBINARY_BUILD_TIME="${BUILD_TIME}")

set(HBSS_SCHEMES "hors-merkle" "hors-completed" "wots")
set(HASHING_SCHEMES "blake3" "siphash" "haraka" "sha256")

set(DSIG_TESTS "ping" "cpu-tput" "tput" "scalability" "synthetic")

# We don't want to rebuild pinning.o every time, so we create a library.
add_library(CommonLib pinning.cpp)
set(COMMON_LIBRARIES CommonLib)

set(COMMON_SOURCE
    dsig.cpp
    sanity/compile-time.cpp
    sanity/run-time.cpp)


# cmake-format: off
set(HASHING_SCHEME 2)
set(LOG_INF_BATCH_SIZE 7)
set(WOTS_LOG_SECRETS_DEPTH 2)
set(HBSS_SCHEME 2)
set(HORS_SECRETS_PER_SIGNATURE 19)
# cmake-format: on

foreach(test ${DSIG_TESTS})
  if(DALEK_AVX)
    set(SLIM_BINARY dsig-${test}-slim-avx)
  else()
    set(SLIM_BINARY dsig-${test}-slim)
  endif()

  add_executable(${SLIM_BINARY} ${HEADER_TIDER} test/${test}.cpp
                                ${COMMON_SOURCE})
  target_compile_definitions(
    ${SLIM_BINARY}
    PUBLIC HASHING_SCHEME=${HASHING_SCHEME}
            LOG_INF_BATCH_SIZE=${LOG_INF_BATCH_SIZE}
            WOTS_LOG_SECRETS_DEPTH=${WOTS_LOG_SECRETS_DEPTH}
            HORS_SECRETS_PER_SIGNATURE=${HORS_SECRETS_PER_SIGNATURE}
            HBSS_SCHEME=${HBSS_SCHEME})
  target_link_libraries(
    ${SLIM_BINARY}
    rt
    pthread
    dl
    ${CONAN_LIBS}
    ${COMMON_LIBRARIES})
endforeach()

add_library(dorydsig ${HEADER_TIDER} ${COMMON_SOURCE} pinning.cpp export/dsig.cpp)

target_compile_definitions(
  dorydsig
  PUBLIC HASHING_SCHEME=${HASHING_SCHEME}
          LOG_INF_BATCH_SIZE=${LOG_INF_BATCH_SIZE}
          WOTS_LOG_SECRETS_DEPTH=${WOTS_LOG_SECRETS_DEPTH}
          HORS_SECRETS_PER_SIGNATURE=${HORS_SECRETS_PER_SIGNATURE}
          HBSS_SCHEME=${HBSS_SCHEME})

configure_file(export/internal/compile-time-config.hpp.in
                export/internal/compile-time-config.hpp)

if(SHARED_LIB)
  # --exclude-libs tells the linker that the symbols of the .a linked together
  # should not be automatically exported
  target_link_libraries(dorydsig ${CONAN_LIBS} "-Wl,--no-whole-archive"
                        "-Wl,--exclude-libs,ALL")
endif()

if(NOT SLIM_BUILD)
  ### main benchmarks
  # Merkle HORS
  # cmake-format: off
  set(HASHING_SCHEME 0 2 3)
  set(LOG_INF_BATCH_SIZE 7)
  set(HORS_SECRETS_PER_SIGNATURE 12 16 32 64)
  # cmake-format: on
  foreach(hash ${HASHING_SCHEME})
  foreach(logb ${LOG_INF_BATCH_SIZE})
  foreach(k ${HORS_SECRETS_PER_SIGNATURE})
    foreach(test ${DSIG_TESTS})
      list(GET HASHING_SCHEMES ${hash} readable_hash)
      set(BINARY dsig-${test}-hors-merkle-${readable_hash}-${logb}-${k})
      add_executable(${BINARY}
                     ${HEADER_TIDER} test/${test}.cpp ${COMMON_SOURCE})
      target_compile_definitions(
        ${BINARY}
        PUBLIC HASHING_SCHEME=${hash}
               LOG_INF_BATCH_SIZE=${logb}
               HORS_SECRETS_PER_SIGNATURE=${k}
               HBSS_SCHEME=0)
      target_link_libraries(
        ${BINARY}
        rt
        pthread
        dl
        ${CONAN_LIBS}
        ${COMMON_LIBRARIES})
    endforeach()
  endforeach()
  endforeach()
  endforeach()

  # HORS Completed (AKA. Fused)
  # cmake-format: off
  set(HASHING_SCHEME 0 2 3)
  set(LOG_INF_BATCH_SIZE 7)
  set(HORS_SECRETS_PER_SIGNATURE 12 16 32 64)
  # cmake-format: on
  foreach(hash ${HASHING_SCHEME})
  foreach(logb ${LOG_INF_BATCH_SIZE})
  foreach(k ${HORS_SECRETS_PER_SIGNATURE})
    foreach(test ${DSIG_TESTS})
      list(GET HASHING_SCHEMES ${hash} readable_hash)
      set(BINARY dsig-${test}-hors-completed-${readable_hash}-${logb}-${k})
      add_executable(${BINARY}
                     ${HEADER_TIDER} test/${test}.cpp ${COMMON_SOURCE})
      target_compile_definitions(
        ${BINARY}
        PUBLIC HASHING_SCHEME=${hash}
               LOG_INF_BATCH_SIZE=${logb}
               HORS_SECRETS_PER_SIGNATURE=${k}
               HBSS_SCHEME=1)
      target_link_libraries(
        ${BINARY}
        rt
        pthread
        dl
        ${CONAN_LIBS}
        ${COMMON_LIBRARIES})
    endforeach()
  endforeach()
  endforeach()
  endforeach()

  # WOTS
  # cmake-format: off
  set(HASHING_SCHEME 0 2 3)
  set(LOG_INF_BATCH_SIZE 7)
  set(WOTS_LOG_SECRETS_DEPTH 1 2 3 4)
  # cmake-format: on
  foreach(hash ${HASHING_SCHEME})
  foreach(logb ${LOG_INF_BATCH_SIZE})
  foreach(logw ${WOTS_LOG_SECRETS_DEPTH})
    foreach(test ${DSIG_TESTS})
      list(GET HASHING_SCHEMES ${hash} readable_hash)
      set(BINARY dsig-${test}-wots-${readable_hash}-${logb}-${logw})
      add_executable(${BINARY}
                     ${HEADER_TIDER} test/${test}.cpp ${COMMON_SOURCE})
      target_compile_definitions(
        ${BINARY}
        PUBLIC HASHING_SCHEME=${hash}
               LOG_INF_BATCH_SIZE=${logb}
               WOTS_LOG_SECRETS_DEPTH=${logw}
               HBSS_SCHEME=2)
      target_link_libraries(
        ${BINARY}
        rt
        pthread
        dl
        ${CONAN_LIBS}
        ${COMMON_LIBRARIES})
    endforeach()
  endforeach()
  endforeach()
  endforeach()

  # WOTS - other batch sizes (note: 7 is already covered above)
  # cmake-format: off
  set(HASHING_SCHEME 2)
  set(LOG_INF_BATCH_SIZE 0 1 2 3 4 5 6 8 9 10 11 12 13 14 15 16)
  set(WOTS_LOG_SECRETS_DEPTH 2)
  # cmake-format: on
  foreach(hash ${HASHING_SCHEME})
  foreach(logb ${LOG_INF_BATCH_SIZE})
  foreach(logw ${WOTS_LOG_SECRETS_DEPTH})
    foreach(test ${DSIG_TESTS})
      list(GET HASHING_SCHEMES ${hash} readable_hash)
      set(BINARY dsig-${test}-wots-${readable_hash}-${logb}-${logw})
      add_executable(${BINARY}
                     ${HEADER_TIDER} test/${test}.cpp ${COMMON_SOURCE})
      target_compile_definitions(
        ${BINARY}
        PUBLIC HASHING_SCHEME=${hash}
               LOG_INF_BATCH_SIZE=${logb}
               WOTS_LOG_SECRETS_DEPTH=${logw}
               HBSS_SCHEME=2)
      target_link_libraries(
        ${BINARY}
        rt
        pthread
        dl
        ${CONAN_LIBS}
        ${COMMON_LIBRARIES})
    endforeach()
  endforeach()
  endforeach()
  endforeach()

  ### other benchmarks
  add_executable(hash-bench test/hash-bench.cpp)
  target_link_libraries(
    hash-bench
    ${CONAN_LIBS}
    ${COMMON_LIBRARIES})

  add_executable(dsig-blake3-bench test/blake3-bench.cpp)
  target_link_libraries(
    dsig-blake3-bench
    rt
    pthread
    dl
    ${CONAN_LIBS}
    ${COMMON_LIBRARIES})
endif()
