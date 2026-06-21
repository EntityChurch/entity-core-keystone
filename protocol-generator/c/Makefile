# entity-core-protocol-c — Makefile (GNU make).
#
# Targets:
#   make            -> libentity_core_protocol.a + .so + conformance + the peer host
#   make test       -> build + run the conformance harness under ASan/LSan/UBSan
#   make smoke      -> build + run the S3 two-peer loopback smoke under ASan/LSan/UBSan
#   make spike      -> build + run the S2 codec spike (float + map_keys)
#   make pc         -> render entity-core-protocol.pc from the .pc.in template
#   make install    -> install .a + .so + header + .pc under PREFIX (default /usr/local)
#   make dist       -> versioned source tarball (the C "publish" artifact; S5/publish)
#   make clean
#
# Idiom: -std=c11 -pedantic -Wall -Wextra -Werror (widest embedding reach).
# libsodium is the one runtime dep (Ed25519 + SHA-256); statically linked.
# SPDX-License-Identifier: Apache-2.0

CC       ?= gcc
# -std=c11 with POSIX.1-2008 exposed: the peer needs strdup/strndup/strtok_r,
# pthread_rwlock_t, clock_gettime, shutdown/MSG_NOSIGNAL. _DEFAULT_SOURCE keeps the
# BSD extras (TCP_NODELAY visibility) while staying strict-c11 elsewhere.
STD       = -std=c11 -pedantic -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
WARN      = -Wall -Wextra -Werror
INC       = -Iinclude
# the peer-internal headers (peer_internal.h / capability.h / wire.h / transport.h)
# live alongside the .c files in src/; tests + host include them via -Isrc.
PEER_INC  = -Iinclude -Isrc
LIB_NAME  = entity_core_protocol
# Release line (S5): 0.1.0-pre — promotion to 0.1.0 is gated on arch v0.1 sign-off +
# a first external C consumer. The pkg-config Version: field is dotted-numeric-only by
# convention, so PC_VERSION carries the numeric core and VERSION carries the full -pre
# marker for the dist tarball name + the .pc comment (mirrors the CL ASDF split, A-CL-010).
PC_VERSION = 0.1.0
VERSION    = 0.1.0-pre
PKGNAME    = entity-core-protocol
PC_NAME    = $(PKGNAME)
# Install layout (override on the command line, e.g. `make install PREFIX=/opt/ec`).
PREFIX     ?= /usr/local
LIBDIR     ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
PCDIR      ?= $(LIBDIR)/pkgconfig
INSTALL    ?= install
DISTNAME   = entity-core-protocol-c-$(VERSION)

# Sanitizer flags for the test pass (manual-memory conformance bonus).
SAN       = -fsanitize=address,undefined -fno-omit-frame-pointer -g

# Release hardening.
HARDEN    = -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fvisibility=hidden

# S2 codec sources (the canonical layer + crypto).
CODEC_SRC = src/ecf.c src/varint.c src/base58.c src/content_hash.c \
            src/peer_id.c src/crypto.c
# S3 peer-machinery sources (L1–L4 + foundation), on top of the codec.
PEER_SRC  = src/entity.c src/store.c src/identity.c src/capability.c \
            src/wire.c src/dispatch.c src/transport.c src/core_typedefs.c
SRC       = $(CODEC_SRC) $(PEER_SRC)
OBJ       = $(SRC:.c=.o)

# pthreads for the peer concurrency (one reader thread per connection).
PTHREAD   = -pthread

# libsodium linkage.
#  - Static archive for the conformance harness + the .a consumer path (fully
#    self-contained artifact). The distro libsodium.a is NOT built -fPIC.
#  - The shared .so links the shared libsodium (-lsodium): the distro static .a
#    cannot be linked into a PIC shared object (R_X86_64_PC32 relocation error),
#    so the .so depends on the system libsodium.so. A -fPIC libsodium.a would let
#    the .so be self-contained too; the .a path already is.
SODIUM_A  = $(shell ls /usr/lib64/libsodium.a 2>/dev/null || ls /usr/lib/libsodium.a 2>/dev/null)
ifeq ($(SODIUM_A),)
  SODIUM_LINK = -lsodium
else
  SODIUM_LINK = $(SODIUM_A)
endif
SODIUM_SO_LINK = -lsodium

.PHONY: all test smoke spike clean dist install uninstall pc typereg

all: lib$(LIB_NAME).a lib$(LIB_NAME).so conformance entity-peer-c

src/%.o: src/%.c include/entity_core/protocol.h
	$(CC) $(STD) $(WARN) $(HARDEN) $(INC) -fPIC -c $< -o $@

lib$(LIB_NAME).a: $(OBJ)
	ar rcs $@ $(OBJ)

lib$(LIB_NAME).so: $(OBJ)
	$(CC) -shared -o $@ $(OBJ) $(SODIUM_SO_LINK) $(PTHREAD)

# The conformance harness (S2 codec corpus) is built WITH sanitizers (codec sources
# compiled directly so ASan instruments the codec too).
conformance: $(CODEC_SRC) test/conformance.c include/entity_core/protocol.h
	$(CC) $(STD) $(WARN) $(SAN) $(INC) $(CODEC_SRC) test/conformance.c \
	    -o conformance $(SODIUM_LINK)

# The S3 two-peer loopback smoke (peer machinery), built WITH sanitizers — a memory
# bug (leak/UAF/overflow/UB) anywhere in the peer FAILS the run.
smoke-bin: $(SRC) test/smoke.c
	$(CC) $(STD) $(WARN) $(SAN) $(PEER_INC) $(SRC) test/smoke.c \
	    -o smoke-bin $(SODIUM_LINK) $(PTHREAD) -lm

# The standalone S4-ready peer host (hardened release build).
entity-peer-c: $(SRC) src/host.c include/entity_core/protocol.h
	$(CC) $(STD) $(WARN) $(HARDEN) $(PEER_INC) $(SRC) src/host.c \
	    -o entity-peer-c $(SODIUM_LINK) $(PTHREAD)

# §9.5 type-registry render-from-model byte-diff harness (sanitized): renders all 53
# core types and prints their content_hash; the runner diffs vs type-registry-vectors-v1.
typereg-bin: $(CODEC_SRC) src/entity.c src/core_typedefs.c test/typereg.c
	$(CC) $(STD) $(WARN) $(SAN) $(PEER_INC) $(CODEC_SRC) src/entity.c \
	    src/core_typedefs.c test/typereg.c -o typereg-bin $(SODIUM_LINK) $(PTHREAD) -lm

typereg: typereg-bin
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 ./typereg-bin

spike: $(CODEC_SRC) test/spike.c include/entity_core/protocol.h
	$(CC) $(STD) $(WARN) $(SAN) $(INC) $(CODEC_SRC) test/spike.c -o spike $(SODIUM_LINK) -lm
	ASAN_OPTIONS=detect_leaks=1 ./spike

test: conformance
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 ./conformance

smoke: smoke-bin
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 ./smoke-bin

# Render the pkg-config file from the template (PREFIX + numeric PC_VERSION substituted).
# Version: is dotted-numeric-only (pkg-config convention) -> PC_VERSION; the -pre marker
# lives in the tarball name + CHANGELOG/README (A-CL-010-style split).
$(PC_NAME).pc: $(PC_NAME).pc.in
	sed -e 's|@PREFIX@|$(PREFIX)|g' -e 's|@VERSION@|$(PC_VERSION)|g' $< > $@

pc: $(PC_NAME).pc

# Install the static + shared lib, the public header, and the rendered .pc under PREFIX.
install: lib$(LIB_NAME).a lib$(LIB_NAME).so $(PC_NAME).pc
	$(INSTALL) -d $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)/entity_core $(DESTDIR)$(PCDIR)
	$(INSTALL) -m 644 lib$(LIB_NAME).a  $(DESTDIR)$(LIBDIR)/
	$(INSTALL) -m 755 lib$(LIB_NAME).so $(DESTDIR)$(LIBDIR)/
	$(INSTALL) -m 644 include/entity_core/protocol.h $(DESTDIR)$(INCLUDEDIR)/entity_core/
	$(INSTALL) -m 644 $(PC_NAME).pc $(DESTDIR)$(PCDIR)/
	@echo "installed entity-core-protocol $(VERSION) -> $(DESTDIR)$(PREFIX)"

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/lib$(LIB_NAME).a \
	      $(DESTDIR)$(LIBDIR)/lib$(LIB_NAME).so \
	      $(DESTDIR)$(INCLUDEDIR)/entity_core/protocol.h \
	      $(DESTDIR)$(PCDIR)/$(PC_NAME).pc

# Versioned SOURCE tarball — the C "publish" artifact (no central registry; distro
# packagers / vendoring consume it). Carries the sources + public header + Makefile +
# the .pc template + LICENSE + README + CHANGELOG. `make` inside the unpacked tree
# rebuilds the libs; `make install` lays them down with the rendered .pc.
dist:
	rm -rf $(DISTNAME) $(DISTNAME).tar.gz
	$(INSTALL) -d $(DISTNAME)
	cp -r src include test tools Makefile $(PC_NAME).pc.in LICENSE README.md CHANGELOG.md $(DISTNAME)/
	tar czf $(DISTNAME).tar.gz $(DISTNAME)
	rm -rf $(DISTNAME)
	@echo "dist: $(DISTNAME).tar.gz (source tarball + pkg-config template; VERSION=$(VERSION))"

clean:
	rm -f $(OBJ) lib$(LIB_NAME).a lib$(LIB_NAME).so conformance smoke-bin \
	    entity-peer-c typereg-bin spike *.o $(PC_NAME).pc
	rm -rf $(DISTNAME) $(DISTNAME).tar.gz
