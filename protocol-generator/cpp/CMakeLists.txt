# entity-core-protocol-cpp — CMake build (the slate build system, A-CPP-003).
#
# Targets:
#   entity_core_protocol  (static + shared)  — the codec library
#   conformance           — the ECF wire-conformance harness (CTest-registered),
#                           built under ASan/LSan/UBSan (memory/UB = test failure)
#
# Build:  cmake -S . -B build -G Ninja && cmake --build build
# Test:   ctest --test-dir build --output-on-failure
#
# C++ standard: C++23. The profile (A-CPP-007) targeted C++20, but GCC 15.2.1 /
# Clang 21's libstdc++ gates <expected> behind __cplusplus > 202002L (C++23 only)
# — std::expected is NOT usable under -std=c++20 there. Bumping to C++23 keeps the
# headline std::expected idiom with ZERO new deps (vs vendoring tl::expected).
# See SPEC-AMBIGUITY-LOG A-CPP-009. <span>/<format> work under C++20; only
# <expected> forces the bump.
#
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.28)

project(EntityCoreProtocol
        VERSION 0.1.0
        DESCRIPTION "entity-core-protocol-cpp — native C++ ECF codec + Ed25519/SHA-256"
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# libsodium via pkg-config (the one authorized runtime dep, D1).
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

# ── the codec library (S2) + the peer machinery (S3) ─────────────────────────
set(CODEC_SOURCES
    src/ecf.cpp
    src/varint.cpp
    src/base58.cpp
    src/crypto.cpp
    src/identity.cpp)

# S3 peer machinery (L1–L4 + foundation) on top of the S2 codec.
set(PEER_SOURCES
    src/entity.cpp
    src/peer_identity.cpp
    src/store.cpp
    src/wire.cpp
    src/capability.cpp
    src/core_typedefs.cpp
    src/dispatch.cpp
    src/transport.cpp)

set(ALL_SOURCES ${CODEC_SOURCES} ${PEER_SOURCES})

find_package(Threads REQUIRED)

add_library(entity_core_protocol STATIC ${ALL_SOURCES})
add_library(entity_core::protocol ALIAS entity_core_protocol)
target_include_directories(entity_core_protocol PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(entity_core_protocol PUBLIC PkgConfig::SODIUM Threads::Threads)
target_compile_options(entity_core_protocol PRIVATE
    -Wall -Wextra -Werror -pedantic -fvisibility=hidden)

# the shared lib stays codec-only (the public S2 artifact); the peer machinery is the
# static lib + the in-tree test/host targets for S3.
add_library(entity_core_protocol_shared SHARED ${CODEC_SOURCES})
set_target_properties(entity_core_protocol_shared PROPERTIES
    OUTPUT_NAME entity_core_protocol)
target_include_directories(entity_core_protocol_shared PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(entity_core_protocol_shared PUBLIC PkgConfig::SODIUM)
target_compile_options(entity_core_protocol_shared PRIVATE
    -Wall -Wextra -Werror -pedantic -fvisibility=hidden)

# ── conformance harness (the codec gate) under ASan/LSan/UBSan ───────────────
# The codec sources are compiled directly into the harness so the sanitizers
# instrument the codec too (the C++ memory-correctness conformance bonus).
option(EC_SANITIZE "Build tests under ASan/LSan/UBSan" ON)

add_executable(conformance test/conformance.cpp ${CODEC_SOURCES})
target_include_directories(conformance PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(conformance PRIVATE PkgConfig::SODIUM)
target_compile_options(conformance PRIVATE -Wall -Wextra -Werror -pedantic)
if(EC_SANITIZE)
  target_compile_options(conformance PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer -g)
  target_link_options(conformance PRIVATE -fsanitize=address,undefined)
endif()

# Vendored normative fixtures live under the repo's shared/ tree.
set(EC_VECTORS_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../shared/test-vectors/v0.8.0"
    CACHE PATH "Directory holding conformance-vectors-v1.cbor")

enable_testing()
add_test(NAME ecf_conformance
         COMMAND conformance "${EC_VECTORS_DIR}/conformance-vectors-v1.cbor")
add_test(NAME ecf_spike
         COMMAND conformance "${EC_VECTORS_DIR}/conformance-vectors-v1.cbor" --spike)
set_tests_properties(ecf_conformance ecf_spike PROPERTIES
    ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1;UBSAN_OPTIONS=halt_on_error=1")

# ── S3 peer machinery: smoke (two-peer loopback) + typereg + multisig accept ──
# Built directly from ALL_SOURCES so the sanitizers instrument the whole peer.
function(ec_s3_target name srcfile)
  add_executable(${name} ${srcfile} ${ALL_SOURCES})
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
  target_compile_options(${name} PRIVATE -Wall -Wextra -Werror -pedantic)
  target_link_libraries(${name} PRIVATE PkgConfig::SODIUM Threads::Threads)
  if(EC_SANITIZE)
    target_compile_options(${name} PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer -g)
    target_link_options(${name} PRIVATE -fsanitize=address,undefined)
  endif()
endfunction()

ec_s3_target(smoke test/smoke.cpp)
ec_s3_target(typereg test/typereg.cpp)
ec_s3_target(multisig_accept test/multisig_accept.cpp)

# ── S4 conformance host: the standalone peer the Go validate-peer oracle drives ──
# Built WITHOUT the sanitizers (a long-running, load-driven conformance host — the
# sanitized memory-safety coverage is the smoke target's job; this is the wire host
# the oracle hammers). Pure scaffolding, no protocol logic. Not a CTest target — it
# is launched by run-s4.sh / run-origination-core.sh.
add_executable(host test/host.cpp ${ALL_SOURCES})
target_include_directories(host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(host PRIVATE -Wall -Wextra -Werror -pedantic)
target_link_libraries(host PRIVATE PkgConfig::SODIUM Threads::Threads)

add_test(NAME smoke COMMAND smoke)
add_test(NAME typereg
         COMMAND typereg "${EC_VECTORS_DIR}/type-registry-vectors-v1.cbor")
add_test(NAME multisig_accept COMMAND multisig_accept)
set_tests_properties(smoke typereg multisig_accept PROPERTIES
    ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1;UBSAN_OPTIONS=halt_on_error=1")

# ── optional: FFI cross-check against the sibling C-ABI libentitycore_codec ──
# A free byte-for-byte cross-check (A-CPP-001) — NOT the conformance gate. Enable
# with -DEC_FFI_XCHECK_LIBDIR=<dir containing libentitycore_codec.so>.
set(EC_FFI_XCHECK_LIBDIR "" CACHE PATH
    "Directory holding the sibling libentitycore_codec.so for the FFI cross-check")
if(EC_FFI_XCHECK_LIBDIR)
  add_executable(ffi_xcheck test/ffi_xcheck.cpp ${CODEC_SOURCES})
  target_include_directories(ffi_xcheck PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
  target_compile_options(ffi_xcheck PRIVATE -Wall -Wextra -Werror -pedantic)
  target_link_libraries(ffi_xcheck PRIVATE PkgConfig::SODIUM entitycore_codec)
  target_link_directories(ffi_xcheck PRIVATE ${EC_FFI_XCHECK_LIBDIR})
  set_target_properties(ffi_xcheck PROPERTIES
      BUILD_RPATH "${EC_FFI_XCHECK_LIBDIR}")
  add_test(NAME ffi_xcheck COMMAND ffi_xcheck)
endif()

# ── install + CMake package config (S5 packaging — A-CPP-016) ─────────────────
# Lays down the static + shared lib, the public umbrella header, and an
# EntityCoreProtocolConfig.cmake so a consumer does:
#   find_package(EntityCoreProtocol 0.1.0 REQUIRED)
#   target_link_libraries(myapp PRIVATE entity_core::protocol)
# Consumed via system install, FetchContent, add_subdirectory, vcpkg, or conan.
# `--target package` (CPack) produces a versioned source/binary package. NONE of
# this is pushed to any registry — publishing is an operator action (lifecycle
# §Publishing). The shared lib carries the libsodium runtime dependency
# (Requires: libsodium via the find_dependency below); the static lib + a
# fully-static consumer pull libsodium in too.
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set_target_properties(entity_core_protocol entity_core_protocol_shared PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})

install(TARGETS entity_core_protocol entity_core_protocol_shared
        EXPORT  EntityCoreProtocolTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/entity_core
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT EntityCoreProtocolTargets
        FILE        EntityCoreProtocolTargets.cmake
        NAMESPACE   entity_core::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/EntityCoreProtocol)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/EntityCoreProtocolConfigVersion.cmake"
    VERSION       ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/cmake/EntityCoreProtocolConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/EntityCoreProtocolConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/EntityCoreProtocol)

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/EntityCoreProtocolConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/EntityCoreProtocolConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/EntityCoreProtocol)

# ── CPack: a versioned source/binary package (`cmake --build build --target package`) ──
set(CPACK_PACKAGE_NAME    "entity-core-protocol-cpp")
set(CPACK_PACKAGE_VENDOR  "Entity Core Protocol contributors")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")  # numeric; the -pre marker lives in CHANGELOG/README (A-CPP-015)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Entity Core protocol (V7) core peer — native C++23 ECF codec + Ed25519/SHA-256")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_GENERATOR "TGZ")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES "/build.*/;/\\.git/;/status/CONFORMANCE-REPORT\\.json$")
include(CPack)
