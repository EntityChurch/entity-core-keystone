# entity-core-protocol-io — build + gates (container-bound; run via run-s2.sh /
# run-s4.sh inside containers/io-toolchain). The prototype-OO peer (#34-track).
# The §6.5/§6.6 protocol logic is authored in Io (src/*.io); this Makefile builds
# the ONE delegated seam: the EntityCodec Io addon over libentitycore_codec
# (canonical CBOR + crypto + peer-id), installed addon-style at
# ~/.eerie/base/addons/EntityCodec (the same layout as the hand-built Socket
# addon in the image).

CODEC_SRC   := ../../ffi-generator/c-abi/entity-core-codec-ffi-c
CODEC_BUILD := $(CODEC_SRC)/build
SPEC        := ../../ffi-generator/c-abi/spec
IO_INC      := /usr/local/include/io
ADDON_HOME  := $(HOME)/.eerie/base/addons/EntityCodec
BUILD       := build
CODEC_SO    := $(BUILD)/libentitycore_codec.so

# Every file the codec compiles from -- DERIVED with `find`, never a hand-listed
# set, because a second copy of a dependency list is a second thing that can
# drift.  Without these prerequisites the rule below is a BARE file target, so
# make runs it only when the .so is ABSENT and a codec source change never
# reaches this peer: that is how two ISA peers shipped a 2026-07-15 codec.
CODEC_DEPS := $(shell find $(CODEC_SRC)/src $(CODEC_SRC)/include \
                          $(CODEC_SRC)/CMakeLists.txt -type f 2>/dev/null)

ADDON_SO    := $(BUILD)/libIoEntityCodec.so

.PHONY: all addon codec install-addon smoke s2 sweep unit clean

all: addon

# The C-ABI codec (libentitycore_codec.so). Shared lib, ec_* exports only,
# libsodium statically + privately linked (the same recipe as the pd peer).
codec: $(CODEC_SO)
$(CODEC_SO): $(CODEC_DEPS)
	cd $(CODEC_SRC) && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null \
	    && cmake --build build --target entitycore_codec >/dev/null
	mkdir -p $(BUILD)
	cp $(CODEC_BUILD)/libentitycore_codec.so $(CODEC_SO)

# The EntityCodec Io addon (.so following the Io<Name>Init convention), linked to
# the co-located codec .so via $$ORIGIN rpath.
addon: install-addon
$(ADDON_SO): src/entitycodec/IoEntityCodec.c src/entitycodec/IoEntityCodecInit.c | codec
	gcc -shared -fPIC -Wall -O2 \
	    -I$(IO_INC) -I$(SPEC) \
	    src/entitycodec/IoEntityCodec.c src/entitycodec/IoEntityCodecInit.c \
	    -L$(BUILD) -lentitycore_codec -Wl,-rpath,'$$ORIGIN' -lm \
	    -o $@

# AddonLoader layout: {_build/dll/libIoEntityCodec.so, io/, protos, depends}.
# The codec .so sits next to the addon dll so the $$ORIGIN rpath resolves.
install-addon: $(ADDON_SO)
	mkdir -p $(ADDON_HOME)/_build/dll
	cp $(ADDON_SO) $(ADDON_HOME)/_build/dll/libIoEntityCodec.so
	cp $(CODEC_SO) $(ADDON_HOME)/_build/dll/libentitycore_codec.so
	rm -rf $(ADDON_HOME)/io
	cp -r src/entitycodec/io $(ADDON_HOME)/io
	cp src/entitycodec/protos src/entitycodec/depends $(ADDON_HOME)/

# S2.0 seam smoke: the addon loads headless + provenance + SHA-256("abc") KAT.
smoke: install-addon
	io test/smoke.io

# S2 gate: the pinned v0.8.0 corpus (71 vectors) byte-identical + the §9.5
# type-floor render-from-model drift check (53/53 byte-identical to the oracle).
s2: install-addon sweep
	io test/s2-corpus.io ../shared/test-vectors/ecf-conformance/conformance-vectors.cbor
	io test/typecheck.io ../shared/test-vectors/type-registry/type-registry-vectors.cbor

# genuine §3.6 K-of-N multisig ACCEPT-path unit test (the oracle-uncoverable
# direction) + M3/M4/M6 negatives, + the 0.8.2.25 sweep unit gate (the 3.3 ladder,
# 6.3's path check + listing filter, 5.4's sentinel scoping, 5.5a's scope typing,
# and 4.11's code-belongs-to-the-cause classification, driven from real bytes).
unit: install-addon sweep
	io test/multisig-accept.io

# The 0.8.2.25 sweep unit gate. A separate target so it can be driven alone while
# diagnosing, and a PREREQUISITE of both `unit` and `s2` so it cannot rot unrun --
# an axis's per-peer gates rot exactly where no cohort runner reaches, and `s2` is
# what this peer's run-s2.sh actually invokes.
# `io` EXITS 0 ON AN UNCAUGHT EXCEPTION (measured in this image: a script referencing a
# missing slot prints the exception and exits 0), so the exit code alone cannot tell a
# green suite from one that raised on its third case. The recipe asserts the POSITIVE
# verdict line the script prints only after every case has run.
sweep: install-addon
	@out=$$(io test/sweep-0-8-2-25.io 2>&1); echo "$$out"; \
	  echo "$$out" | grep -q '^SWEEP-0.8.2.25 OK$$' || { echo "SWEEP GATE FAILED (no OK verdict line)"; exit 1; }

clean:
	rm -rf $(BUILD)
