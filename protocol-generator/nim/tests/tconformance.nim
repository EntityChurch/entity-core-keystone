## ECF wire-conformance harness — entity-core-protocol-nim (S2 gate).
##
## Loads the normative fixture (conformance-vectors.cbor) and runs every
## vector through the hand-rolled Nim codec, checking byte-identity
## (`encode_equal`) or rejection (`decode_reject`) per Appendix E §E.3. The
## fixture carries its own cross-blessed `canonical` bytes (produced + 3-way
## cross-blessed by the Go/Rust/Python oracles), so this is self-contained — no
## running Go oracle needed at S2 (the Go `wire-conformance` binary is the fixture
## producer, not a runtime checker). Exits non-zero on any FAIL (the S2 gate).
##
## Also runs the MANDATORY fixed-width [2^63, 2^64-1] head-form self-test
## (A-NIM-002): the uint64 carrier round-trips the >int64-max band a signed-int64
## carrier would silently overflow.
##
## Reproduce (in-container, sealed offline):
##   podman run $PODMAN_RUN_CAPS --rm --network=none -v $PWD:/work:Z \
##     -w /work/protocol-generator/nim entity-core-keystone/nim-toolchain:latest \
##     nim c -r --mm:orc --overflowChecks:on -d:release --hints:off \
##       -o:/tmp/tconformance tests/tconformance.nim \
##       /work/protocol-generator/shared/test-vectors/ecf-conformance/conformance-vectors.cbor
##
## SPDX-License-Identifier: Apache-2.0

import std/[os, tables, strutils, strformat]
import ../src/entity_core_protocol

proc readBytes(path: string): seq[byte] =
  let s = readFile(path)
  result = newSeq[byte](s.len)
  if s.len > 0:
    copyMem(addr result[0], unsafeAddr s[0], s.len)

proc mapGet(v: EcValue; name: string): EcValue =
  doAssert v.kind == ekMap
  for p in v.pairs:
    if p.key.kind == ekText and p.key.t == name:
      return p.val
  return nil

proc asText(v: EcValue): string =
  doAssert v.kind == ekText
  v.t

proc asBytes(v: EcValue): seq[byte] =
  doAssert v.kind == ekBytes
  v.b

proc asUint(v: EcValue): uint64 =
  doAssert v.kind == ekUint
  v.u

proc category(id: string): string =
  let i = id.find('.')
  if i >= 0: id[0 ..< i] else: id

proc hexOf(b: openArray[byte]): string =
  result = newStringOfCap(b.len * 2)
  for x in b: result.add toHex(x, 2).toLowerAscii()

type Outcome = object
  ok: bool
  msg: string

proc runVector(vm: EcValue): Outcome =
  let id = asText(mapGet(vm, "id"))
  let kind = asText(mapGet(vm, "kind"))
  let canon = asBytes(mapGet(vm, "canonical"))
  let cat = category(id)

  if kind == "decode_reject":
    try:
      discard decode(canon)
      return Outcome(ok: false, msg: "decoder accepted a reject vector")
    except EcCodecError:
      return Outcome(ok: true)

  # encode_equal: produce bytes per category, compare to canon.
  var produced: seq[byte]
  if cat == "content_hash":
    let input = mapGet(vm, "input")
    let typ = asText(mapGet(input, "type"))
    let data = mapGet(input, "data")
    let fcv = mapGet(input, "format_code")
    let fc = if fcv != nil: asUint(fcv) else: 0'u64
    produced = contentHash(fc, typ, data)
  elif cat == "peer_id":
    let input = mapGet(vm, "input")
    let keyType = asUint(mapGet(input, "key_type"))
    let hashType = asUint(mapGet(input, "hash_type"))
    let digest = asBytes(mapGet(input, "digest"))
    let pid = peerIdFormat(keyType, hashType, digest)
    # canonical bytes = the ECF encoding of the peer-id TEXT string.
    produced = encode(textV(pid))
  elif cat == "signature":
    let input = mapGet(vm, "input")
    let seed = asBytes(mapGet(input, "seed"))
    let entity = mapGet(input, "entity")
    let typ = asText(mapGet(entity, "type"))
    let data = mapGet(entity, "data")
    let sig = signEntity(seed, typ, data)
    produced = @sig
  else:
    # float / int / map_keys / length / primitive / nested / envelope:
    # re-encode the decoded input value canonically.
    produced = encode(mapGet(vm, "input"))

  if produced == canon:
    Outcome(ok: true)
  else:
    Outcome(ok: false, msg: &"want {hexOf(canon)} got {hexOf(produced)}")

proc headFormSelfTest(): bool =
  ## MANDATORY fixed-width [2^63, 2^64-1] round-trip (A-NIM-002). A signed-int64
  ## carrier would overflow this band; the uint64 carrier does not.
  var ok = true
  proc chk(v: EcValue; wantHex: string) =
    let got = hexOf(encode(v))
    if got != wantHex:
      echo &"  SELFTEST FAIL encode: want {wantHex} got {got}"
      ok = false
    else:
      let rt = decode(encode(v))
      let re = hexOf(encode(rt))
      if re != wantHex:
        echo &"  SELFTEST FAIL round-trip: want {wantHex} got {re}"
        ok = false
  chk(uintV(0x8000000000000000'u64), "1b8000000000000000")  # 2^63
  chk(uintV(0xfffffffffffffffe'u64), "1bfffffffffffffffe")  # 2^64-2
  chk(uintV(0xffffffffffffffff'u64), "1bffffffffffffffff")  # 2^64-1
  chk(nintV(0xffffffffffffffff'u64), "3bffffffffffffffff")  # -(2^64)
  ok

when isMainModule:
  let path =
    if paramCount() >= 1: paramStr(1)
    else: "../shared/test-vectors/ecf-conformance/conformance-vectors.cbor"

  let fixture = decode(readBytes(path))
  doAssert fixture.kind == ekArray, "fixture root must be an array"

  var
    passCount = 0
    failCount = 0
    cats = initOrderedTable[string, array[2, int]]()  # [pass, total]

  for vraw in fixture.arr:
    let id = asText(mapGet(vraw, "id"))
    let cat = category(id)
    let o = runVector(vraw)
    if not cats.hasKey(cat): cats[cat] = [0, 0]
    var c = cats[cat]
    inc c[1]
    if o.ok:
      inc passCount
      inc c[0]
    else:
      inc failCount
      echo &"FAIL {id}  {o.msg}"
    cats[cat] = c

  echo "-- by category --"
  for cat, pt in cats:
    echo &"  {cat:<14} {pt[0]}/{pt[1]}"

  echo ""
  echo "-- fixed-width head-form self-test (A-NIM-002, [2^63, 2^64-1]) --"
  let selfOk = headFormSelfTest()
  echo (if selfOk: "  PASS (uint64 carrier, no signed-int64 overflow)"
        else: "  FAIL")

  echo ""
  echo &"TOTAL: {passCount} passed, {failCount} failed (of {passCount + failCount})"

  if failCount > 0 or not selfOk:
    quit(1)
