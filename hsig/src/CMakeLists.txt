cmake_minimum_required(VERSION 3.9)
project(hsig CXX)

include(${CMAKE_BINARY_DIR}/setup.cmake)
dory_setup_cmake()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-packed")

# Set build time as a preprocessor definition
string(TIMESTAMP BUILD_TIME "%Y-%m-%d %H:%M")
add_definitions(-DBINARY_BUILD_TIME="${BUILD_TIME}")

# Add library
add_library(hsig STATIC hsig.cpp)

# Add executable
add_executable(test-hsig test/main.cpp)

# Apply compile definitions to the executable
target_compile_definitions(test-hsig PRIVATE HASHING_SCHEME=0 WOTS_LOG_SECRETS_DEPTH=2)

# Link the library to the executable
target_link_libraries(test-hsig PRIVATE hsig)
