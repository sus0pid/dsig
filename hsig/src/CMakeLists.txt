cmake_minimum_required(VERSION 3.9)
project(hsig CXX)

include(${CMAKE_BINARY_DIR}/setup.cmake)
dory_setup_cmake()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-packed")

# Set build time as a preprocessor definition
string(TIMESTAMP BUILD_TIME "%Y-%m-%d %H:%M")
add_definitions(-DBINARY_BUILD_TIME="${BUILD_TIME}")
message(STATUS "Conan libraries: ${CONAN_LIBS}")

set(HASHING_SCHEMES "blake3" "siphash" "haraka" "sha256")
set(HASHING_SCHEME 0)
set(LOG_INF_BATCH_SIZE 7)
set(WOTS_LOG_SECRETS_DEPTH 2)

# Add executable
add_executable(test-hsig ${HEADER_TIDER}  test/main.cpp hsig.cpp)
# Apply compile definitions to the executable
target_compile_definitions(
        test-hsig
        PUBLIC HASHING_SCHEME=${HASHING_SCHEME}
        WOTS_LOG_SECRETS_DEPTH=${WOTS_LOG_SECRETS_DEPTH}
        LOG_INF_BATCH_SIZE=${LOG_INF_BATCH_SIZE})
# Link the library to the executable
target_link_libraries(
        test-hsig
        ${CONAN_LIBS}
)

add_executable(test-memstore ${HEADER_TIDER} test/test-memstore.cpp)
target_link_libraries(
        test-memstore
        ${CONAN_LIBS}
)

# benchmark_wots with different hash algo
add_executable(bench_wots ${HEADER_TIDER} test/test-memstore.cpp)
target_link_libraries(
        test-memstore
        ${CONAN_LIBS}
)

# WOTS
# cmake-format: off
# HashingSchemes { Blake3 = 0, SipHash = 1, Haraka = 2, SHA256 = 3 };

set(HASHING_SCHEME 0 2 3)
set(LOG_INF_BATCH_SIZE 7)
set(WOTS_LOG_SECRETS_DEPTH 2)
# cmake-format: on
foreach(hash ${HASHING_SCHEME})
    foreach(logb ${LOG_INF_BATCH_SIZE})
        foreach(logw ${WOTS_LOG_SECRETS_DEPTH})
                list(GET HASHING_SCHEMES ${hash} readable_hash)
                set(BINARY bench-wots-${readable_hash}-${logb}-${logw})
                message(STATUS "Creating target: ${BINARY}")
                add_executable(${BINARY}
                        ${HEADER_TIDER} test/wots_bench.cpp)
                target_compile_definitions(
                        ${BINARY}
                        PUBLIC HASHING_SCHEME=${hash}
                        LOG_INF_BATCH_SIZE=${logb}
                        WOTS_LOG_SECRETS_DEPTH=${logw})
                target_link_libraries(
                        ${BINARY}
                        ${CONAN_LIBS})
        endforeach()
    endforeach()
endforeach()