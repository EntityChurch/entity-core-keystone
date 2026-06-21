# entity-core-codec-ffi-c — builds libentitycore_codec.{so,a} (same artifact
# names as the Rust impl; provenance via ec_impl_info()) + the conformance
# harness + the encoder regression test. C11, -fPIC, libsodium statically and
# privately linked. Build only inside containers/c-toolchain/ (S1).
cmake_minimum_required(VERSION 3.20)
project(entity_core_codec_ffi_c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
# NOTE: do NOT use -fvisibility=hidden here. The canonical entitycore_codec.h is
# shipped verbatim (no visibility attributes), so the ec_* exports rely entirely
# on the linker version script (export.map). A symbol compiled hidden cannot be
# promoted back to global by the version script, which would leave the .so with
# ZERO exports. The version script (global: ec_*; local: *;) is the single source
# of export control — it exports ec_* and localizes everything else (libsodium).
add_compile_options(-Wall -Wextra -pedantic)

# libsodium: prefer the STATIC archive (libsodium-static) so the artifact is
# self-contained (spec sec.7). Header from libsodium-devel.
find_path(SODIUM_INCLUDE_DIR sodium.h)
find_library(SODIUM_STATIC NAMES libsodium.a PATHS /usr/lib64 /usr/lib /usr/local/lib)
find_library(SODIUM_SHARED NAMES sodium)
if(NOT SODIUM_INCLUDE_DIR)
  message(FATAL_ERROR "sodium.h not found (install libsodium-devel)")
endif()
if(SODIUM_STATIC)
  set(SODIUM_LIB ${SODIUM_STATIC})
  message(STATUS "libsodium: static archive ${SODIUM_STATIC}")
else()
  set(SODIUM_LIB ${SODIUM_SHARED})
  message(WARNING "libsodium static archive not found; falling back to shared ${SODIUM_SHARED} (artifact will NOT be self-contained)")
endif()

# Core sources, compiled once as an object library and reused by every target.
# sha384.c is the hand-rolled SHA-384 for the agility surface (content_hash_format
# 0x01) — libsodium has no SHA-384; kept dependency-free + self-contained (S7).
add_library(core_obj OBJECT src/ecf.c src/base58.c src/codec.c src/sha384.c)
target_include_directories(core_obj
  PRIVATE ${SODIUM_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include)

# ── Ed448 (crypto agility): the SHAKE256 wrapper + glue, plus the vendored,
# library-free OpenSSL 3.3.2 curve448 (constant-time Goldilocks) and keccak1600
# sponge — all compiled into the codec, NOT linked from any OpenSSL library, so
# the artifact stays self-contained. Kept in its own object lib with warnings
# suppressed (third-party source) and its own include roots: the compat/ shims
# stand in for the OpenSSL-internal headers the vendored .c files expect.
# Provenance + pins: src/ed448/PROVENANCE.md.
add_library(ed448_obj OBJECT
  src/ed448/ec_shake256.c
  src/ed448/ed448_glue.c
  src/ed448/vendor/keccak/keccak1600.c
  src/ed448/vendor/curve448/curve448.c
  src/ed448/vendor/curve448/curve448_tables.c
  src/ed448/vendor/curve448/eddsa.c
  src/ed448/vendor/curve448/f_generic.c
  src/ed448/vendor/curve448/scalar.c
  src/ed448/vendor/curve448/arch_64/f_impl64.c)
target_include_directories(ed448_obj PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src/ed448
  ${CMAKE_CURRENT_SOURCE_DIR}/src/ed448/vendor/curve448
  ${CMAKE_CURRENT_SOURCE_DIR}/src/ed448/vendor/compat)
# Vendored third-party arithmetic uses GNU __int128 / attributes; suppress the
# -Wall -Wextra -pedantic noise that applies to our own code.
target_compile_options(ed448_obj PRIVATE -w)

# ── shared library: the dlopen artifact. Version script exports only ec_*,
# localizes libsodium. --exclude-libs hides archive symbols belt-and-suspenders.
add_library(entitycore_codec SHARED $<TARGET_OBJECTS:core_obj> $<TARGET_OBJECTS:ed448_obj>)
set_target_properties(entitycore_codec PROPERTIES OUTPUT_NAME entitycore_codec)
target_link_libraries(entitycore_codec PRIVATE ${SODIUM_LIB})
target_link_options(entitycore_codec PRIVATE
  "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/export.map"
  "-Wl,--exclude-libs,ALL")

# ── static library: our objects + (bundled) libsodium objects merged into one
# self-contained archive via an `ar` MRI script (post-build).
add_library(entitycore_codec_static STATIC $<TARGET_OBJECTS:core_obj> $<TARGET_OBJECTS:ed448_obj>)
set_target_properties(entitycore_codec_static PROPERTIES OUTPUT_NAME entitycore_codec)
if(SODIUM_STATIC)
  set(MERGED $<TARGET_FILE:entitycore_codec_static>)
  add_custom_command(TARGET entitycore_codec_static POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "CREATE ${MERGED}"           >  ${CMAKE_CURRENT_BINARY_DIR}/merge.mri
    COMMAND ${CMAKE_COMMAND} -E echo "ADDLIB ${MERGED}"           >> ${CMAKE_CURRENT_BINARY_DIR}/merge.mri
    COMMAND ${CMAKE_COMMAND} -E echo "ADDLIB ${SODIUM_STATIC}"    >> ${CMAKE_CURRENT_BINARY_DIR}/merge.mri
    COMMAND ${CMAKE_COMMAND} -E echo "SAVE"                       >> ${CMAKE_CURRENT_BINARY_DIR}/merge.mri
    COMMAND ${CMAKE_COMMAND} -E echo "END"                        >> ${CMAKE_CURRENT_BINARY_DIR}/merge.mri
    COMMAND ${CMAKE_AR} -M < ${CMAKE_CURRENT_BINARY_DIR}/merge.mri
    COMMENT "Bundling libsodium into libentitycore_codec.a (self-contained)"
    VERBATIM)
endif()

# ── conformance harness + regression test: link the core objects directly (they
# use internal cc_*/ecf_* helpers the .so does not export) + libsodium.
add_executable(conformance_harness src/conformance_harness.c $<TARGET_OBJECTS:core_obj> $<TARGET_OBJECTS:ed448_obj>)
target_include_directories(conformance_harness
  PRIVATE ${SODIUM_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(conformance_harness PRIVATE ${SODIUM_LIB})

add_executable(regression_test src/regression_test.c $<TARGET_OBJECTS:core_obj> $<TARGET_OBJECTS:ed448_obj>)
target_include_directories(regression_test
  PRIVATE ${SODIUM_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(regression_test PRIVATE ${SODIUM_LIB})
