cmake_minimum_required(VERSION 3.9)
project(hsig CXX)

include(${CMAKE_BINARY_DIR}/setup.cmake)
dory_setup_cmake()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-packed")

string(TIMESTAMP BUILD_TIME "%Y-%m-%d %H:%M")
add_definitions(-DBINARY_BUILD_TIME="${BUILD_TIME}")

add_library(hsig STATIC hsig.cpp)
add_executable(test-hsig test/main.cpp)
target_link_libraries(
        test-hsig
        ${CONAN_LIBS}
        PRIVATE hsig)