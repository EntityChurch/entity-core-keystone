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
ADDON_SO    := $(BUILD)/libIoEntityCodec.so

.PHONY: all addon codec install-addon smoke s2 clean

all: addon

# The C-ABI codec (libentitycore_codec.so). Shared lib, ec_* exports only,
# libsodium statically + privately linked (the same recipe as the pd peer).
codec: $(CODEC_SO)
$(CODEC_SO):
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
s2: install-addon
	io test/s2-corpus.io ../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor
	io test/typecheck.io ../shared/test-vectors/v0.8.0/type-registry-vectors-v1.cbor

# genuine §3.6 K-of-N multisig ACCEPT-path unit test (the oracle-uncoverable
# direction) + M3/M4/M6 negatives.
unit: install-addon
	io test/multisig-accept.io

clean:
	rm -rf $(BUILD)
