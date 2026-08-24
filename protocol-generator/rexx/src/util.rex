/* entity-core-protocol-rexx — shared codec utilities.
 *
 * The REJECT mechanism (profile [error_model]): a hard canonical/crypto reject sets
 * the RC-style flag EC.!OK = 0 (plus EC.!ERRKIND / EC.!ERRDETAIL) and returns; the
 * codec's decode path checks `if \EC.!OK then return` at each recursion/consume
 * boundary to unwind, and every public entry sets EC.!OK = 1 on entry. Callers test
 * EC.!OK after a codec call (the harness's decode_reject probe, the peer's dispatch
 * 400 mapping). Regina does NOT propagate a SYNTAX condition across a CALL boundary
 * to a caller's `SIGNAL ON SYNTAX` (it only traps a syntax raised in the SAME
 * routine), so the classic-Rexx flag/RC model — not exceptions — is the portable
 * unwind, and it is the analogue of the Tcl `throw {ENTITY_CORE KIND detail}`.
 *
 * KEYCMP: byte-wise unsigned compare (length-then-lexicographic). Rexx's native
 * string comparison space-pads the shorter operand, which corrupts a binary compare,
 * so canonical map-key ordering (§4.2.1) is done here byte-by-byte via C2D.
 */

/* Ec_Init: reset the per-process global counters + constants. Called first thing in
 * every main entry (after `numeric digits 200`), before any Peer/Store/Conn/Id/Sess. */
Ec_Init: procedure expose EC.
  EC.!STORE_CTR = 0
  EC.!PEER_CTR  = 0
  EC.!CONN_CTR  = 0
  EC.!ID_CTR    = 0
  EC.!SESS_CTR  = 0
  EC.!MAX_CHAIN_DEPTH = 64
  EC.!OK  = 1
  EC.!EXC = ''
  EC.!DBG = ''
  EC.!EVQH = 1                 /* deferred-event queue: head/tail stem ring (O(1) — a */
  EC.!EVQT = 1                 /* packed-list queue is O(n^2) under a sustained flood) */
  EC.!CRYPTO_VIA = 'helper'
  return

/* Reject KIND, detail  — set the reject flag + kind; callers unwind on \EC.!OK. */
Reject: procedure expose EC.
  EC.!OK = 0
  EC.!ERRKIND = arg(1)
  EC.!ERRDETAIL = arg(2)
  return

/* Throw KIND, detail — the PEER-layer recoverable-throw analogue (the Tcl `throw
 * {ENTITY_CORE KIND ...}`). Regina does NOT propagate a SYNTAX condition across a
 * CALL boundary (A-RX-010), so — as with the codec's EC.!OK reject — a "throw" is a
 * global flag (EC.!EXC) set by the raising layer and inspected at the dispatch
 * top-level (Peer_Dispatch), which maps the kind to a status (UNRESOLVABLE_GRANTEE ->
 * 401, a codec/canonicalize kind -> 400). Deep callers need NOT thread the check: once
 * EC.!EXC is set the top-level discards their (now-irrelevant) result and re-maps. */
Throw: procedure expose EC.
  EC.!EXC = arg(1)
  EC.!EXCDETAIL = arg(2)
  return

/* clear the peer-layer exception flag (called at each dispatch entry). */
Throw_Clear: procedure expose EC.
  EC.!EXC = ''
  return

/* length-then-lexicographic byte compare of two byte strings -> -1 | 0 | 1 */
Keycmp: procedure
  parse arg a, b
  la = length(a); lb = length(b)
  if la \= lb then do; if la < lb then return -1; else return 1; end
  do i = 1 to la
    x = c2d(substr(a, i, 1)); y = c2d(substr(b, i, 1))
    if x \= y then do; if x < y then return -1; else return 1; end
  end
  return 0
