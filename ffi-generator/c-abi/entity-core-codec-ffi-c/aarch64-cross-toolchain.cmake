# CMake cross-toolchain — build libentitycore_codec.{so,a} for AArch64 (Linux) with the
# fedora gcc-aarch64-linux-gnu cross driver, resolving sodium.h + libsodium.a from the aarch64
# libsodium unpacked into the cross sysroot (see containers/asm-arm64-toolchain/Containerfile).
# Used by the asm-arm64 peer (the FFI×ISA cost, ISA-MAP Axis A). Host-arch (x86_64) build is
# unaffected — it does not pass -DCMAKE_TOOLCHAIN_FILE.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
# The glibc sysroot ships under the aarch64-REDHAT-linux triple (not the driver's default
# aarch64-linux-gnu one); aarch64 libsodium is unpacked into it too. See the Containerfile.
set(CMAKE_SYSROOT /usr/aarch64-redhat-linux/sys-root/fc43)
set(CMAKE_FIND_ROOT_PATH /usr/aarch64-redhat-linux/sys-root/fc43)

# Toolchain binaries come from the host prefix; headers/libs/packages only from the sysroot.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
