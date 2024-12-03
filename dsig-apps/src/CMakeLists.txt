cmake_minimum_required(VERSION 3.9)
project(dorydsigapps CXX)

include(${CMAKE_BINARY_DIR}/setup.cmake)
dory_setup_cmake()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-packed")

string(TIMESTAMP BUILD_TIME "%Y-%m-%d %H:%M")
add_definitions(-DBINARY_BUILD_TIME="${BUILD_TIME}")

add_executable(audit-client ${HEADER_TIDER} auditable/client.cpp)
target_link_libraries(audit-client ${CONAN_LIBS})

add_executable(audit-server ${HEADER_TIDER} auditable/server.cpp)
target_link_libraries(audit-server ${CONAN_LIBS})

add_executable(dsigdemo ${HEADER_TIDER} main.cpp)
target_link_libraries(dsigdemo ${CONAN_LIBS})

# add_executable(dsig-ping ${HEADER_TIDER} ping.cpp)
# target_link_libraries(dsig-ping ${CONAN_LIBS})

set(schemes_n "dalek" "sodium" "dsig" "large" "free")
set(schemes_v 0       1        2      3       4)
foreach(scheme_v ${schemes_v})
  list(GET schemes_n ${scheme_v} scheme_n)
  add_executable(ubft-tcb-${scheme_n} ${HEADER_TIDER} ubft/tail-cb/ping.cpp ubft/latency-hooks.cpp)
  target_link_libraries(ubft-tcb-${scheme_n} ${CONAN_LIBS})
  target_compile_definitions(ubft-tcb-${scheme_n} PRIVATE TCB_SCHEME=${scheme_v} LATENCY_HOOKS=0)

  add_executable(ubft-certifier-${scheme_n} ${HEADER_TIDER} ubft/certifier/ping.cpp)
  target_link_libraries(ubft-certifier-${scheme_n} ${CONAN_LIBS})
  target_compile_definitions(ubft-certifier-${scheme_n} PRIVATE CERTIFIER_SCHEME=${scheme_v} TCB_SCHEME=${scheme_v})

  add_executable(ubft-${scheme_n} ${HEADER_TIDER} ubft/consensus/test.cpp)
  target_link_libraries(ubft-${scheme_n} ${CONAN_LIBS})
  target_compile_definitions(ubft-${scheme_n} PRIVATE TCB_SCHEME=${scheme_v} PREPARE_CERTIFIER_SCHEME=${scheme_v})
endforeach()