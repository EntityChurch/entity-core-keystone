# CMake cross-toolchain — build libentitycore_codec.{so,a} for RISC-V (RV64GC, Linux) with the
# fedora gcc-riscv64-linux-gnu cross driver, resolving sodium.h + libsodium.a from a Debian trixie
# riscv64 sysroot (see containers/riscv64-toolchain/Containerfile — riscv64 is a Fedora secondary
# arch with no forcearch/sysroot path, so glibc+libsodium come from Debian's first-class riscv64
# port). Used by the riscv64 peer (the FFI×ISA cost, ISA-MAP Axis A). Host-arch (x86_64) build is
# unaffected — it does not pass -DCMAKE_TOOLCHAIN_FILE.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR riscv64)

set(CMAKE_C_COMPILER riscv64-linux-gnu-gcc)

# Debian sysroot (baked into the container at /opt/riscv64-sysroot). Overridable via env for a
# non-default location.
if(DEFINED ENV{RISCV_SYSROOT})
  set(CMAKE_SYSROOT $ENV{RISCV_SYSROOT})
else()
  set(CMAKE_SYSROOT /opt/riscv64-sysroot)
endif()
set(CMAKE_FIND_ROOT_PATH ${CMAKE_SYSROOT})

# Debian is multiarch + merged-usr; fedora cross-gcc is not multiarch-aware, so point it at the
# arch subdir for BOTH:
#   -I …/usr/include/riscv64-linux-gnu  → arch headers (bits/libc-header-start.h etc.)
#   -B …/usr/lib/riscv64-linux-gnu      → startfiles (crt1.o/crti.o/crtn.o) + the -L search that
#                                         resolves -lc/-lgcc_s (Debian keeps them in the arch dir,
#                                         not the default <sysroot>/usr/lib the driver probes).
# C_FLAGS ride CMake's link line too, so -B covers link as well as compile. The container also
# symlinks usr/lib64 -> lib/riscv64-linux-gnu so find_library(libsodium.a PATHS /usr/lib64)
# resolves, and lib -> usr/lib so the DT_INTERP /lib/ld-linux-riscv64-lp64d.so.1 resolves.
set(CMAKE_C_FLAGS_INIT "-I${CMAKE_SYSROOT}/usr/include/riscv64-linux-gnu -B${CMAKE_SYSROOT}/usr/lib/riscv64-linux-gnu")
# Executables (conformance_harness, regression_test) need the guest loader path made explicit.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-Wl,--dynamic-linker,/lib/ld-linux-riscv64-lp64d.so.1")

# Toolchain binaries come from the host prefix; headers/libs/packages only from the sysroot.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
