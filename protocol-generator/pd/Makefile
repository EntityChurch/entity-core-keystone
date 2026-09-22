# entity-core-protocol-pd — build + smoke (container-bound; see run-s2.sh).
# The reactive-patch peer (#33). The §6.5/§6.6 dispatch logic is authored in .pd
# patches (S3); this Makefile builds the ONE delegated seam: the [ecodec] Pd C
# external over libentitycore_codec (canonical CBOR + crypto + peer-id).
#
# All targets run INSIDE containers/puredata-toolchain/ (pd + m_pd.h at $PD_SRC,
# libsodium for the codec CMake). Not meant to run on the host.

PD_SRC      ?= /opt/pure-data/src
PD          ?= pd
CODEC_SRC   := ../../ffi-generator/c-abi/entity-core-codec-ffi-c
CODEC_BUILD := $(CODEC_SRC)/build
SPEC        := ../../ffi-generator/c-abi/spec
BUILD       := build
EXTERNAL    := $(BUILD)/ecodec.pd_linux
CODEC_SO    := $(BUILD)/libentitycore_codec.so

# Every file the codec compiles from -- DERIVED with `find`, never a hand-listed
# set, because a second copy of a dependency list is a second thing that can
# drift.  Without these prerequisites the rule below is a BARE file target, so
# make runs it only when the .so is ABSENT and a codec source change never
# reaches this peer: that is how two ISA peers shipped a 2026-07-15 codec.
CODEC_DEPS := $(shell find $(CODEC_SRC)/src $(CODEC_SRC)/include \
                          $(CODEC_SRC)/CMakeLists.txt -type f 2>/dev/null)


.PHONY: all external patchlint codec smoke frametest decodetest responsetest treewalktest hellotest authkat authzkat authzdenykat authzpeerskat treegetkat clean
all: external

# PROSE IN A COMMENT IS CODE IN THIS FILE FORMAT. A Pd record ends at an
# unescaped `,` or `;`, INCLUDING inside a `#X text` comment — so ordinary
# punctuation in an English sentence breaks out of the comment and Pd dispatches
# the remainder as messages at load time. Measured 2026-09-02 on the RT-6 comment
# in src/main.pd: four unescaped separators produced three load-time errors
# (`canvas: no method for 'not'` from "REJECTED, not re-processed", and two
# `established_ok: no such object` from "auth_decode; established_ok 0 -> 401").
#
# Those three were harmless ONLY because the words after the separators happened
# to name nothing. The same defect one word over sends a real message to a real
# receiver at load — `; net_listen`, `; buf_reset` — and nothing would report it.
# That is why this is a build gate and not a style note.
#
# It was invisible for months because pd writes to stderr and run-s4.sh sent that
# to a path inside a --rm container, so the errors died with every run. They are
# captured now; this keeps them from coming back.
# The check lives in tools/patchlint.py, NOT inline here: the pattern needs a
# backslash class, and Make + shell + python quoting mangled it into one that
# flagged already-escaped separators. A gate that reports the wrong answer is
# worse than none, and inline escaping is how it got there.
patchlint:
	@python3 tools/patchlint.py

# The C-ABI codec (libentitycore_codec.so). PIC shared lib, exports only ec_*
# (export.map version script), libsodium privately localized. We link the SHARED
# lib — NOT the static .a: the distro libsodium.a is non-PIC and won't link into
# a shared .pd_linux (A-PD-005). Offline: libsodium is in the toolchain image.
codec: $(CODEC_SO)
$(CODEC_SO): $(CODEC_DEPS)
	cd $(CODEC_SRC) && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null \
	    && cmake --build build --target entitycore_codec >/dev/null
	mkdir -p $(BUILD)
	cp $(CODEC_BUILD)/libentitycore_codec.so $(CODEC_SO)

# The [ecodec] Pd external. Compiled against m_pd.h + the verbatim C-ABI header;
# linked to the co-located codec .so via an $$ORIGIN rpath so the shipped pair
# (ecodec.pd_linux + libentitycore_codec.so) is self-locating in Pd's -path dir.
external: patchlint $(EXTERNAL)
$(EXTERNAL): src/ecodec/ecodec.c | codec
	gcc -DPD -fPIC -shared -Wall \
	    -I$(PD_SRC) -I$(SPEC) \
	    $< -L$(BUILD) -lentitycore_codec -Wl,-rpath,'$$ORIGIN' -lm \
	    -o $@

# S2 codec-seam smoke: load [ecodec] in headless pd; assert provenance + a real
# SHA-256 round-trip (SHA-256("abc")[0] == 186 == 0xba). The codec-seam GO gate —
# FATAL if [ecodec] doesn't load or the crypto answer is wrong.
smoke: external
	@$(PD) -nogui -noaudio -stderr -path $(BUILD) -open src/ecodec/smoke.pd >$(BUILD)/smoke.log 2>&1 & \
	  PDPID=$$!; sleep 2; kill $$PDPID 2>/dev/null; wait $$PDPID 2>/dev/null; true
	@cat $(BUILD)/smoke.log
	@grep -q "ecodec: entity-core codec/crypto seam loaded" $(BUILD)/smoke.log \
	  || { echo "SMOKE FAIL: [ecodec] external did not load"; exit 1; }
	@grep -q "^ECODEC: 186$$" $(BUILD)/smoke.log \
	  || { echo "SMOKE FAIL: SHA-256(abc)[0] != 186 (codec crypto round-trip wrong)"; exit 1; }
	@echo "SMOKE OK: [ecodec] seam reaches libentitycore_codec (provenance + SHA-256 verified)"

# S3.2 frame-assembler gate: real pd runs frame-assembler.pd; a Python client
# asserts §1.6 header→body reassembly byte-exact (single + back-to-back + binary).
FRAMEPORT ?= 15100
frametest: external
	@$(PD) -nogui -noaudio -stderr -path $(BUILD) -open src/frame-assembler.pd >$(BUILD)/frame.log 2>&1 & \
	  PDPID=$$!; sleep 2; \
	  python3 test/frame-roundtrip.py $(FRAMEPORT); RC=$$?; \
	  kill $$PDPID 2>/dev/null; wait $$PDPID 2>/dev/null; \
	  exit $$RC

# S3.3 envelope-decode gate: real pd runs decode-test.pd; a Python client sends a
# spec-shaped §3.1 envelope frame; assert [ecodec] surfaced the dispatch fields.
DECODEPORT ?= 15101
decodetest: external
	@$(PD) -nogui -noaudio -stderr -path $(BUILD) -open src/decode-test.pd >$(BUILD)/decode.log 2>&1 & \
	  PDPID=$$!; sleep 2; \
	  python3 test/decode-roundtrip.py $(DECODEPORT); \
	  sleep 0.3; kill $$PDPID 2>/dev/null; wait $$PDPID 2>/dev/null; true
	@grep -q "DECODED: system/protocol/execute" $(BUILD)/decode.log || { echo "DECODETEST FAIL: root_type"; cat $(BUILD)/decode.log; exit 1; }
	@grep -q "RID: req-123"          $(BUILD)/decode.log || { echo "DECODETEST FAIL: request_id"; exit 1; }
	@grep -q "URI: alice/local/nope" $(BUILD)/decode.log || { echo "DECODETEST FAIL: uri"; exit 1; }
	@grep -q "OP: get"               $(BUILD)/decode.log || { echo "DECODETEST FAIL: operation"; exit 1; }
	@echo "DECODETEST OK: §3.1 envelope -> root_type + request_id/uri/operation on the canvas"

# S3.3 respond gate: real pd runs spine-test.pd; a Python client sends an EXECUTE
# and decodes the built §3.3 EXECUTE_RESPONSE (status 404 / not_found / rid echo).
RESPPORT ?= 15102
responsetest: external
	@$(PD) -nogui -noaudio -stderr -path $(BUILD) -open src/spine-test.pd >$(BUILD)/spine.log 2>&1 & \
	  PDPID=$$!; sleep 2; \
	  python3 test/response-roundtrip.py $(RESPPORT); RC=$$?; \
	  sleep 0.3; kill $$PDPID 2>/dev/null; wait $$PDPID 2>/dev/null; \
	  exit $$RC

# S3.3 §6.6 tree-walk gate: real pd runs treewalk-test.pd; a known handler prefix
# resolves (501 placeholder), an unknown path 404s — the visible canvas tree-walk.
WALKPORT ?= 15103
treewalktest: external
	@$(PD) -nogui -noaudio -stderr -path $(BUILD) -open src/treewalk-test.pd >$(BUILD)/walk.log 2>&1 & \
	  PDPID=$$!; sleep 2; \
	  python3 test/treewalk-roundtrip.py $(WALKPORT); RC=$$?; \
	  sleep 0.3; kill $$PDPID 2>/dev/null; wait $$PDPID 2>/dev/null; \
	  exit $$RC

# S3.4 handshake leg-1 gate: real pd runs handshake-test.pd; a Python client sends
# an EXECUTE hello and decodes the §4.4 hello response (200 + peer_id + protocols).
HELLOPORT ?= 15104
hellotest: external
	@$(PD) -nogui -noaudio -stderr -path $(BUILD) -open src/handshake-test.pd >$(BUILD)/hello.log 2>&1 & \
	  PDPID=$$!; sleep 2; \
	  python3 test/hello-roundtrip.py $(HELLOPORT); RC=$$?; \
	  sleep 0.3; kill $$PDPID 2>/dev/null; wait $$PDPID 2>/dev/null; \
	  exit $$RC

# §4.6 authenticate-verification offline KAT: link the codec .so, replay a REAL
# validate-peer authenticate frame (test/vectors/, real Ed25519 crypto), and
# exercise the exact seam path (hash recompute + signature find/verify + peer_id
# binding) the [ecodec] auth_* primitives use. The oracle-uncoverable accept path.
authkat: external
	gcc -Wall -I$(SPEC) test/auth-verify-offline.c \
	    -L$(BUILD) -lentitycore_codec -Wl,-rpath,'$$ORIGIN' -o $(BUILD)/auth-offline
	./$(BUILD)/auth-offline test/vectors/authenticate-frame.bin

# §5.2 verify_request offline KAT (steps 1-4): replay a REAL authenticated EXECUTE
# (test/vectors/, real Ed25519 crypto over a real capability) and exercise the seam
# path the [ecodec] authz_* rungs use (content-hash integrity + request signature +
# grantee-match + single-link cap-chain signature).
authzkat: external
	gcc -Wall -I$(SPEC) test/authz-verify-offline.c \
	    -L$(BUILD) -lentitycore_codec -Wl,-rpath,'$$ORIGIN' -o $(BUILD)/authz-offline
	./$(BUILD)/authz-offline test/vectors/authenticated-execute-frame.bin

# §5.2 verify_request DENY-path offline KAT: replay REAL DENY frames captured from
# validate-peer's `authz` category (test/vectors/authz-deny-*.bin) and assert each
# discriminating rung condition pins the §5.2a (status, code): deny_default → 403
# (check_permission), grantee → 401 unresolvable_grantee, no_catchall → 403
# (granter unresolvable), expired → 403 (temporal validity).
authzdenykat: external
	gcc -Wall -I$(SPEC) test/authz-deny-offline.c \
	    -L$(BUILD) -lentitycore_codec -Wl,-rpath,'$$ORIGIN' -o $(BUILD)/authz-deny-offline
	./$(BUILD)/authz-deny-offline

# §5.2 `peers` grant-dimension offline KAT (structural, no wire vector — the
# conformance oracle has ZERO coverage of this dimension, see
# protocol-generator/shared/findings/peers-grant-dimension-oracle-gap.md, so there is no captured frame to
# replay). Hand-builds synthetic capability-grant CBOR and exercises cap_permits'
# peers scope directly: explicit include/exclude, bare "*", and the
# omitted-`peers`-defaults-to-local-only fallback (the regression this closes).
authzpeerskat:
	mkdir -p $(BUILD)
	gcc -Wall test/authz-peers-offline.c -o $(BUILD)/authz-peers-offline
	./$(BUILD)/authz-peers-offline

# §6.3 system/tree:get accept-path offline KAT: the ENTITY-mode direction the live
# oracle doesn't cover (it lists, and fetches only compute types) — the 8 primitive
# type entities' canonical-ECF encoding + content_hash, and the listing's canonical
# key order. Mirrors tree_get_serve's store_entity_data / build_listing_data.
treegetkat: external
	gcc -Wall -I$(SPEC) test/tree-get-offline.c \
	    -L$(BUILD) -lentitycore_codec -Wl,-rpath,'$$ORIGIN' -o $(BUILD)/tree-get-offline
	./$(BUILD)/tree-get-offline

clean:
	rm -rf $(BUILD)
