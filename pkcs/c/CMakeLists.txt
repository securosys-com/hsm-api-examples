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

# ------- Executables -------

add_executable(attestation src/attestation.cpp)
target_link_libraries(attestation PRIVATE common_deps)

add_executable(rsa src/rsa.c)
target_link_libraries(rsa PRIVATE common_deps)

add_executable(slip10 src/slip10.cpp)
target_link_libraries(slip10 PRIVATE common_deps)
