# SPDX-FileCopyrightText: Copyright 2026 Securosys SA
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.23)

project(primussamples)

include_directories(
  /usr/include/botan-2
  /usr/local/primus/include
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Set shared requirements
# https://cmake.org/cmake/help/latest/command/add_library.html#interface-libraries
add_library(common_deps INTERFACE)
target_sources(common_deps INTERFACE src/primus_common.c)
target_link_libraries(common_deps INTERFACE botan-2 primusP11)

function(enable_asan target)
  target_compile_options(${target} PRIVATE
    -fsanitize=address
    -fno-omit-frame-pointer
    -O0
    -g
  )
  target_link_options(${target} PRIVATE -fsanitize=address)
endfunction()
#enable_asan(ska_modify)

# ------- Executables -------

add_executable(attestation src/attestation.cpp)
target_link_libraries(attestation PRIVATE common_deps)

add_executable(ml_dsa src/ml_dsa.c)
target_link_libraries(ml_dsa PRIVATE common_deps)

add_executable(multithreading src/multithreading.c)
target_link_libraries(multithreading PRIVATE common_deps)

add_executable(rsa src/rsa.c)
target_link_libraries(rsa PRIVATE common_deps)

add_executable(ska_block src/ska_block.cpp src/ska_create_common.cpp src/ska_create_approval.cpp)
target_link_libraries(ska_block PRIVATE common_deps)

#add_executable(ska_create_approval src/ska_create_approval.cpp)
#target_link_libraries(ska_create_approval PRIVATE common_deps)

add_executable(ska_create_policy src/ska_create_policy.cpp)
target_link_libraries(ska_create_policy PRIVATE common_deps)

add_executable(ska_generate_key src/ska_generate_key.cpp)
target_link_libraries(ska_generate_key PRIVATE common_deps)

add_executable(ska_modify src/ska_modify.cpp src/ska_create_common.cpp src/ska_create_approval.cpp)
target_link_libraries(ska_modify PRIVATE common_deps)

add_executable(ska_sign_with_timestamp src/ska_sign_with_timestamp.cpp src/ska_create_common.cpp src/ska_create_approval.cpp)
target_link_libraries(ska_sign_with_timestamp PRIVATE common_deps)

add_executable(ska_sign src/ska_sign.cpp src/ska_create_common.cpp src/ska_create_approval.cpp)
target_link_libraries(ska_sign PRIVATE common_deps)

add_executable(slip10 src/slip10.cpp)
target_link_libraries(slip10 PRIVATE common_deps)
