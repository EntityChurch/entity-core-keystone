# entity-core-protocol-rexx — S2 codec build + conformance (container-bound; run-s2.sh).
# Pure-Rexx canonical CBOR (the decimal-number-model probe) + base58/varint/peer_id;
# crypto via the C external-function extension over libentitycore_codec (A-RX-005).
# Regina has no test framework — the harness is hand-rolled Rexx.

REXX        ?= rexx
CODEC_SRC   := ../../ffi-generator/c-abi/entity-core-codec-ffi-c
CODEC_BUILD := $(CODEC_SRC)/build
SPEC        := ../../ffi-generator/c-abi/spec
HELPER      := src/ext/eccrypto
NET         := src/ext/ecnet
CORPUS      := ../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor
# "Link" order: harness main (with EXIT) first, then the routine library files.
LIB         := src/util.rex src/varint.rex src/base58.rex src/peerid.rex src/cbor.rex src/tv.rex src/crypto.rex
# S3 peer machinery: the full routine library (codec + protocol + transport).
S3LIB       := src/util.rex src/varint.rex src/base58.rex src/peerid.rex src/cbor.rex \
               src/tv.rex src/crypto.rex src/col.rex src/ecf.rex src/hash.rex src/entity.rex \
               src/envelope.rex src/wire.rex src/store.rex src/identity.rex src/coretypes.rex \
               src/capability.rex src/conn.rex src/peer.rex src/handlers.rex src/transport.rex

.PHONY: all test spike ext net codec s3 selftest smoke s4peer dist clean
all: test

# ── S5 packaging ──
# Classic Rexx has NO package registry and no module system — the "package" is a source
# tarball of the .rex tree + the two C ext RECIPES + a single pre-concatenated runnable
# peer (entity-core-peer.rex = bin/peer.rex ahead of the routine library, the classic-Rexx
# global-label link model) + the LOAD.md stub. A source distribution, not a binary
# registry (mirrors COBOL/C `make dist`). libentitycore_codec is a documented runtime dep
# (LOAD.md), not bundled. Built binaries (ext/eccrypto, ext/ecnet) are NOT shipped — the
# .c recipes are, rebuilt by the consumer with the image gcc.
VERSION  ?= 0.1.0-pre
DISTNAME := entity-core-protocol-rexx-$(VERSION)
DISTDIR  := dist/$(DISTNAME)
dist:
	rm -rf $(DISTDIR) dist/$(DISTNAME).tar.gz
	mkdir -p $(DISTDIR)/src/ext $(DISTDIR)/bin $(DISTDIR)/test $(DISTDIR)/status $(DISTDIR)/arch
	cp src/*.rex $(DISTDIR)/src/
	cp src/ext/*.c $(DISTDIR)/src/ext/
	cp bin/peer.rex $(DISTDIR)/bin/
	cp test/*.rex test/*.sh $(DISTDIR)/test/
	cp status/PHASE-S*.md status/CONFORMANCE-REPORT.md status/CONFORMANCE-REPORT.json \
	   status/SPEC-AMBIGUITY-LOG.md $(DISTDIR)/status/
	cp arch/*.md $(DISTDIR)/arch/ 2>/dev/null || true
	cp Makefile profile.toml LOAD.md run-s2.sh run-s3.sh run-s4.sh run-origination-core.sh $(DISTDIR)/
	cp ../../LICENSE $(DISTDIR)/
	cat bin/peer.rex $(S3LIB) > $(DISTDIR)/entity-core-peer.rex
	tar czf dist/$(DISTNAME).tar.gz -C dist $(DISTNAME)
	rm -rf $(DISTDIR)
	@echo "dist: dist/$(DISTNAME).tar.gz  (source + pre-concatenated entity-core-peer.rex; VERSION=$(VERSION))"

# ── S4 conformance ──
# The standalone host binary run-s4.sh launches: bin/peer.rex (the --name/--port CLI
# main, with EXIT) concatenated ahead of the full routine library, exactly as the S3
# combined mains are built. The ecnet daemon + eccrypto helper are its prerequisites.
S4PEER := /tmp/rexx-peer.rex
s4peer: ext net
	cat bin/peer.rex $(S3LIB) > $(S4PEER)

# Build the codec C-ABI (libentitycore_codec) if absent — its CMake, offline
# (libsodium is in the toolchain image). Provenance queried via ec_impl_info().
codec: $(CODEC_BUILD)/libentitycore_codec.so
$(CODEC_BUILD)/libentitycore_codec.so:
	cd $(CODEC_SRC) && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build build >/dev/null

# The crypto helper BINARY (A-RX-005): a standalone executable binding the codec's
# Ed25519 + SHA entry points, driven over a hex stem-pipe (fedora Regina cannot dlopen
# a function library, so the crypto crosses the C-ABI at the process boundary).
ext: $(HELPER)
$(HELPER): src/ext/eccrypto.c | codec
	gcc -O2 -I$(SPEC) -o $@ $< -L$(CODEC_BUILD) -Wl,--no-as-needed -lentitycore_codec -Wl,-rpath,$(CODEC_BUILD)

# The ecnet transport CO-PROCESS daemon (A-RX-008): a standalone C process owning the
# real sockets + select() loop + §1.6 de-framing, driven by the Rexx peer over FIFOs.
# It ALSO carries crypto (A-RX-011): Regina cannot ADDRESS SYSTEM the eccrypto helper
# while the evt FIFO is open (the fork/exec corrupts the FIFO read), so the networked
# peer's §9.1 crypto crosses the C-ABI HERE, over the same FIFO channel — hence the
# libentitycore_codec link.
net: $(NET)
$(NET): src/ext/ecnet.c | codec
	gcc -O2 -I$(SPEC) -o $@ $< -L$(CODEC_BUILD) -Wl,--no-as-needed -lentitycore_codec -Wl,-rpath,$(CODEC_BUILD)

# Full pinned-corpus conformance gate (69 vectors, byte-identical).
test: ext
	cat test/conformance.rex $(LIB) > /tmp/rexx-conf.rex
	LD_LIBRARY_PATH=$(CODEC_BUILD) $(REXX) /tmp/rexx-conf.rex $(CORPUS) $(HELPER)

# The pure-Rexx codec spike (no crypto / helper needed) — the decimal-float probe.
spike:
	cat test/spike.rex $(LIB) > /tmp/rexx-spike.rex
	$(REXX) /tmp/rexx-spike.rex $(CORPUS)

# ── S3 peer machinery ──
# The S3 gate: the peer-layer foundation self-test + the two-peer loopback smoke
# (handshake + 404 + authority-gated tree get + capability request + 8-way request_id
# demux). Loopback is intra-container 127.0.0.1 — works under --network=none, so the
# whole S3 gate stays dependency-sealed and offline.
s3: selftest smoke

selftest: ext
	cat test/s3_selftest.rex $(S3LIB) > /tmp/rexx-s3sel.rex
	LD_LIBRARY_PATH=$(CODEC_BUILD) $(REXX) /tmp/rexx-s3sel.rex $(HELPER)

smoke: ext net
	cat test/s3_responder.rex $(S3LIB) > /tmp/rexx-s3resp.rex
	cat test/s3_initiator.rex $(S3LIB) > /tmp/rexx-s3init.rex
	LD_LIBRARY_PATH=$(CODEC_BUILD) REXX="$(REXX)" HELPER="$(HELPER)" NET="$(PWD)/$(NET)" \
	    RESP=/tmp/rexx-s3resp.rex INIT=/tmp/rexx-s3init.rex bash test/smoke.sh

clean:
	rm -f $(HELPER) $(NET)
	rm -rf dist
