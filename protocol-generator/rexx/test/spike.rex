/* entity-core-protocol-rexx — S2 codec SPIKE (pure Rexx, NO crypto).
 *
 * Isolates the decimal-number-model codec probe (A-RX-002) from the FFI crypto: walks
 * the pinned v0.8.0 corpus (decoded with OUR OWN decoder — the corpus is trusted
 * canonical ECF) and, for every NON-crypto vector, asserts encode(reconstructed) ==
 * canonical bytes and decode(canonical) rejects (EC.!OK = 0) where kind=decode_reject.
 * content_hash / signature (Class B) are SKIPPED here (test/conformance.rex covers the
 * full 69 with the crypto ext). Rejects use the RC-flag EC.!OK (Regina does not
 * propagate a SYNTAX across CALL); a MAIN-level trap catches a genuine Rexx bug. */

parse arg corpus
numeric digits 200
signal on syntax name Fatal
EC.!PASS = 0; EC.!FAIL = 0; EC.!SKIP = 0; EC.!FAILS.0 = 0

sz = stream(corpus, 'c', 'query size')
data = charin(corpus, 1, sz)
call stream corpus, 'c', 'close'

top = Cbor_Decode(data)
if \EC.!OK then do; say 'FATAL: corpus did not decode ('EC.!ERRKIND')'; exit 2; end
if Tv_Tag(top) \== 'a' then do; say 'FATAL: corpus top-level is not an array'; exit 2; end
n = c2d(substr(top, 2, 4))
p = 6
do v = 1 to n
  vl = Tv_NodeLen(top, p)
  vec = substr(top, p, vl)
  p = p + vl
  call ProcessVec vec
end

say ''
say '=== spike: 'n' vectors — 'EC.!PASS' pass / 'EC.!FAIL' fail / 'EC.!SKIP' skip ==='
do i = 1 to EC.!FAILS.0
  say '  FAIL ' EC.!FAILS.i
end
if EC.!FAIL > 0 then exit 1
exit 0

Fatal:
  say 'FATAL SYNTAX rc='rc' line='sigl' ('errortext(rc)')'
  exit 3

/* ---- process one vector ---- */
ProcessVec: procedure expose EC.
  parse arg vec
  numeric digits 200
  id = Tv_Text(Tv_MapGet(vec, 'id'))
  kind = Tv_Text(Tv_MapGet(vec, 'kind'))
  parse var id cat '.' .
  canon = Tv_Bytes(Tv_MapGet(vec, 'canonical'))
  input = Tv_MapGet(vec, 'input')

  if kind == 'decode_reject' then do
    call Cbor_Decode canon
    if \EC.!OK then call Ok
    else call Bad id, 'expected decode reject, but decoded'
    return
  end

  /* encode_equal — reconstruct per category */
  select
    when cat == 'peer_id' then do
      kt = Tv_Int(Tv_MapGet(input, 'key_type'))
      ht = Tv_Int(Tv_MapGet(input, 'hash_type'))
      dg = Tv_Bytes(Tv_MapGet(input, 'digest'))
      got = Cbor_Encode(Peerid_Format(kt, ht, dg))
    end
    when cat == 'content_hash' | cat == 'signature' then do
      EC.!SKIP = EC.!SKIP + 1
      say 'SKIP ' id ' — crypto (Class B; see conformance.rex)'
      return
    end
    otherwise
      got = Cbor_Encode(input)
  end

  if \EC.!OK then do; call Bad id, 'unexpected encode reject ('EC.!ERRKIND')'; return; end
  if got == canon then call Ok
  else call Bad id, 'encode mismatch want=' || c2x(canon) || ' got=' || c2x(got)
  return

Ok: procedure expose EC.
  EC.!PASS = EC.!PASS + 1
  return
Bad: procedure expose EC.
  parse arg id, why
  EC.!FAIL = EC.!FAIL + 1
  k = EC.!FAILS.0 + 1
  EC.!FAILS.0 = k
  EC.!FAILS.k = id': 'why
  return
