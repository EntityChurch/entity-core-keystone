# entity-core-protocol-sql — build + S2 codec-seam gate (container-bound; see
# run-s2.sh). The authority-as-query probe. This Makefile builds the ONE delegated
# seam layer (S2): the thin C bridge (src/host/ec_seam.c) over libentitycore_codec
# — canonical CBOR + content_hash + peer-id + Ed25519/SHA — plus the SQLite
# application-defined crypto functions (crypto callable FROM SQL). The §5/§6.6
# authority interior is authored as .sql at S3; the socket/framing/dispatch shell
# is the S3 host. Nothing above the codec/crypto seam is built here.
#
# All targets run INSIDE containers/sqlite-toolchain/ (SQLite amalgamation at
# $(SQLITE_DIR); libentitycore_codec + header at $(CODEC_DIR)). Not for the host.

SQLITE_DIR ?= /opt/sqlite
CODEC_DIR  ?= /opt/codec
# The CANONICAL C-ABI header (ffi-generator/c-abi/spec) is the authority every
# conforming impl ships unchanged. We build against it, NOT the impl's bundled
# include/ copy baked into the image — that copy lags the spec (it omits
# ec_ed25519_seed_to_pubkey, which the .so nonetheless exports; A-SQL-006).
CODEC_HDR  ?= ../../ffi-generator/c-abi/spec

# Ephemeral build artifacts go to a CONTAINER-LOCAL scratch dir, NOT the mounted
# tree: (a) they are disposable intermediates rebuilt every run, and (b) large
# object writes to the :Z-relabelled bind mount fail on some rootless-podman /
# SELinux hosts (the 1.4 MB sqlite3.o create is refused; /tmp is unaffected).
# Override BUILD=build to keep artifacts in-tree where the mount permits it.
BUILD   ?= /tmp/ec-sql-build
VECTORS := ../shared/test-vectors/ecf-conformance/conformance-vectors.cbor

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
INCS    := -I$(CODEC_HDR) -I$(SQLITE_DIR) -Isrc/host
# libentitycore_codec is a shared lib; rpath it so the test binary self-locates it.
LDFLAGS := -L$(CODEC_DIR)/lib -Wl,-rpath,$(CODEC_DIR)/lib
LDLIBS  := -lentitycore_codec -lpthread -ldl -lm

.PHONY: all seam check authority-check peer dist clean
all: check

# SQLite amalgamation compiled once to an object (slow to compile; cache it).
$(BUILD)/sqlite3.o: $(SQLITE_DIR)/sqlite3.c | $(BUILD)
	$(CC) -O2 -I$(SQLITE_DIR) -c $< -o $@

# The codec/crypto seam object (thin ec_* wrappers + SQL function registration).
seam: $(BUILD)/ec_seam.o
$(BUILD)/ec_seam.o: src/host/ec_seam.c src/host/ec_seam.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCS) -c $< -o $@

# S2 GATE — the ECF wire-conformance differential (71-vector byte-identity) +
# N1–N4 self-tests + Ed25519 RFC-8032 KAT + the crypto-callable-FROM-SQL KAT.
# Links the delegated codec .so + the SQLite amalgamation. Green == oracle PASS.
check: $(BUILD)/codec_test
	$(BUILD)/codec_test $(VECTORS)

$(BUILD)/codec_test: src/test/codec_test.c $(BUILD)/ec_seam.o $(BUILD)/sqlite3.o | $(BUILD)
	$(CC) $(CFLAGS) $(INCS) src/test/codec_test.c $(BUILD)/ec_seam.o $(BUILD)/sqlite3.o \
	    $(LDFLAGS) $(LDLIBS) -o $@

# S3 AUTHORITY GATE — the authority-as-query harness: run the VERBATIM authored src/sql/*.sql
# (verify_ladder / resolve / k_of_n) over real Ed25519-signed facts, asserting the §5.2a verdict
# trichotomy + the §4.10 depth-400 pre-check + the §6.6 longest-prefix walk + the mandatory
# 2-of-3 multisig ACCEPT (A-SQL-004). Reads the .sql files at runtime (cwd = this dir).
authority-check: $(BUILD)/authority_test
	$(BUILD)/authority_test

$(BUILD)/authority_test: src/test/authority_test.c $(BUILD)/ec_seam.o $(BUILD)/sqlite3.o | $(BUILD)
	$(CC) $(CFLAGS) $(INCS) src/test/authority_test.c $(BUILD)/ec_seam.o $(BUILD)/sqlite3.o \
	    $(LDFLAGS) $(LDLIBS) -o $@

# S3 PEER — the C host imperative shell (sockets + §1.6 framing + frame-cap + §6.5 dispatch
# scaffold + §4 handshake state machine + the SQLite store running the authored SQL verdict).
peer: $(BUILD)/ec-sql-peer
$(BUILD)/ec-sql-peer: src/host/peer.c src/host/handlers.inc.c $(BUILD)/ec_seam.o $(BUILD)/sqlite3.o | $(BUILD)
	$(CC) $(CFLAGS) $(INCS) src/host/peer.c $(BUILD)/ec_seam.o $(BUILD)/sqlite3.o \
	    $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD):
	mkdir -p $(BUILD)

# ── S5 packaging ── source distribution. SQLite has no peer registry for a
# C+SQL peer of this shape, so the "package" is a source tarball (the cohort
# convention): the .sql authority interior + the C seam host + the run/conformance
# scripts + profile + status + LICENSE. libentitycore_codec + the SQLite
# amalgamation are documented, SHA-pinned runtime/build deps (built in the
# container image), NOT bundled. Registry publish is deferred (0.1.0-pre).
VERSION  ?= 0.1.0-pre
DISTNAME := entity-core-protocol-sql-$(VERSION)
DISTDIR  := dist/$(DISTNAME)
dist:
	rm -rf $(DISTDIR) dist/$(DISTNAME).tar.gz
	mkdir -p $(DISTDIR)/src/sql $(DISTDIR)/src/host $(DISTDIR)/src/test $(DISTDIR)/status $(DISTDIR)/arch
	cp src/sql/*.sql $(DISTDIR)/src/sql/
	cp src/host/*.c src/host/*.h $(DISTDIR)/src/host/
	cp src/test/*.c $(DISTDIR)/src/test/
	cp status/PHASE-S*.md status/CONFORMANCE-REPORT.md status/CONFORMANCE-REPORT.json \
	   status/SPEC-AMBIGUITY-LOG.md $(DISTDIR)/status/ 2>/dev/null || true
	cp arch/*.md $(DISTDIR)/arch/ 2>/dev/null || true
	cp Makefile profile.toml README.md CHANGELOG.md LICENSE \
	   run-s2.sh run-s3.sh run-s4.sh run-origination-core.sh $(DISTDIR)/ 2>/dev/null || true
	tar czf dist/$(DISTNAME).tar.gz -C dist $(DISTNAME)
	rm -rf $(DISTDIR)
	@echo "dist: dist/$(DISTNAME).tar.gz (VERSION=$(VERSION))"

clean:
	rm -rf $(BUILD) dist
