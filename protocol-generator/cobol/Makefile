# entity-core-protocol-cobol — build + test (GnuCOBOL, FFI-hybrid).
# Run inside containers/cobol-toolchain (S1). The codec C-ABI lib must be on
# LD_LIBRARY_PATH at runtime; CODEC points at a built impl (c or rust).
#
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 \
#     --rm --network=none -v "$PWD":/work:Z \
#     -w /work/protocol-generator/cobol \
#     -e LD_LIBRARY_PATH=/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build \
#     entity-core-keystone/cobol-toolchain:latest make test

COBC      := cobc
COBFLAGS  := -free -fno-binary-truncate -fstatic-call -Wno-repository-checks
CODEC_DIR ?= /work/ffi-generator/c-abi/entity-core-codec-ffi-c/build
LINK      := -L$(CODEC_DIR) -lentitycore_codec

CODEC_SRC := src/cbor.cob
MODEL_SRC := src/model.cob src/cbor.cob
XPORT_SRC := src/model.cob src/cbor.cob src/wire.cob src/netshim.c
IDENT_SRC := src/ident.cob src/util.cob src/build.cob src/model.cob src/cbor.cob
PEER_SRC  := src/peer.cob src/connect.cob src/capability.cob src/handlers.cob \
             src/types.cob src/grants.cob src/peerstate.cob src/wirebld.cob \
             src/access.cob src/store.cob src/ident.cob src/util.cob \
             src/build.cob src/model.cob src/cbor.cob src/netshim.c

BIN := build
$(shell mkdir -p $(BIN))

.PHONY: test cbor-unit codec-selftest model-test transport-test ident-test \
        dispatch-test connect-test host clean

host:
	$(COBC) -x $(COBFLAGS) -o $(BIN)/host bin/host.cob $(PEER_SRC) $(LINK)

test: cbor-unit codec-selftest model-test transport-test ident-test \
      dispatch-test connect-test
	@echo "=== entity-core-protocol-cobol: all S2/S3-foundation tests passed ==="

connect-test:
	$(COBC) -x $(COBFLAGS) -o $(BIN)/connect-test \
	    test/connect-test.cob $(PEER_SRC) $(LINK)
	$(BIN)/connect-test

ident-test:
	$(COBC) -x $(COBFLAGS) -o $(BIN)/ident-test \
	    test/ident-test.cob $(IDENT_SRC) $(LINK)
	$(BIN)/ident-test

dispatch-test:
	$(COBC) -x $(COBFLAGS) -o $(BIN)/dispatch-test \
	    test/dispatch-test.cob $(PEER_SRC) $(LINK)
	$(BIN)/dispatch-test

cbor-unit:
	$(COBC) -x $(COBFLAGS) -o $(BIN)/cbor-unit test/cbor-unit.cob $(CODEC_SRC)
	$(BIN)/cbor-unit

codec-selftest:
	$(COBC) -x $(COBFLAGS) -o $(BIN)/codec-selftest \
	    test/codec-selftest.cob $(CODEC_SRC) test/fileio.c $(LINK)
	$(BIN)/codec-selftest

model-test:
	$(COBC) -x $(COBFLAGS) -o $(BIN)/model-test \
	    test/model-test.cob $(MODEL_SRC) $(LINK)
	$(BIN)/model-test

transport-test:
	$(COBC) -x $(COBFLAGS) -o $(BIN)/transport-test \
	    test/transport-test.cob $(XPORT_SRC) $(LINK)
	$(BIN)/transport-test

clean:
	rm -rf $(BIN)
