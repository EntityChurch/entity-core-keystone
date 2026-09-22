/* entity-core-protocol-rexx — wire framing (§1.6) + the two message builders (§3.2
 * EXECUTE, §3.3 EXECUTE_RESPONSE). Frame := [4-byte BE length][CBOR payload]; the
 * payload is a canonical-ECF-encoded system/protocol/envelope (§3.1).
 *
 * Only EXECUTE and EXECUTE_RESPONSE are wire message types (§3.3). hello /
 * authenticate are OPERATIONS on system/protocol/connect, NOT message types — any
 * other root type is ignored server-side (the dispatcher returns '').
 */

/* §1.6 / §4.10(a) 16-MiB frame bound is enforced in the ecnet C daemon (which owns the
 * de-framing), so the Rexx layer never sees the BYTES of an oversize frame — but since
 * 0.8.2.25 it does see the EVENT: §4.11 makes a pre-admission refusal owe a coded
 * EXECUTE_RESPONSE, and only the Rexx side can build one, so ecnet emits `PREADM <id>
 * <kind>` and Transport_HandleEvent answers it. See ext/ecnet.c. */

Wire_NowMs: procedure expose EC.
  return Crypto_NowMs()

/* ── envelope <-> frame ── */
Wire_FrameOfEnvelope: procedure expose EC.
  parse arg env
  return Cbor_Encode(Env_ToCbor(env))

Wire_EnvelopeOfFrame: procedure expose EC.
  parse arg payload
  v = Cbor_Decode(payload)
  if \EC.!OK then return ''
  if Tv_Tag(v) \== 'm' then do; call Throw 'not_a_map', 'frame: not a map'; return ''; end
  return Env_OfCbor(v)

/* §6.3 rejection reporting: recover ONLY the request_id from a frame the strict decoder
 * rejected, so the rejection can be delivered as a correlated `400 non_canonical_ecf`
 * response instead of silence. The frame stays rejected -- nothing else is read out of
 * it. Returns '' when even the request_id is unrecoverable (an unattributable frame,
 * where silence is the only option left).
 *
 * The envelope and entity-wrapper shapes are fixed maps with no legal tag position
 * (§6.3), so a frame whose ONLY defect is a tag inside some entity's `data` still has a
 * structurally sound root -- which is exactly the case this recovers. */
Wire_SalvageRequestId: procedure expose EC.
  parse arg payload
  v = Cbor_DecodeSalvage(payload)
  if v == '' then return ''
  root = Ecf_Get(v, 'root')
  if root == '' then return ''
  data = Ecf_Get(root, 'data')
  if data == '' then return ''
  rid = Ecf_Get(data, 'request_id')
  if rid == '' then return ''
  if Tv_Tag(rid) \== 't' then return ''
  return Tv_Payload(rid)

/* ── §4.11 pre-admission refusal classification (0.8.2.25) ──
 *
 * Wire_PreAdmissionRefusal <kind> -> "status code message", the triple §4.11 assigns a
 * pre-admission failure's CAUSE. Parse it with `parse var r status code message`.
 *
 * "The frame obligation belongs to the class; the CODE belongs to the cause [MUST]" -- a
 * single code for the class would answer an honest caller under the wrong reason and send
 * them to the wrong layer.
 *
 *   connect-auth proof-of-possession      401 authentication_failed  (4.6/4.7 -- the
 *                                            connect handler's, not here)
 *   envelope over the configured maximum  413 payload_too_large      (4.10(a), N14)
 *   resolution integrity (mis-keyed inc.) 400 hash_mismatch          (5.2a, 1.8)
 *   framing / never becomes an Envelope   400 invalid_request        (4.7, 4.11)
 *   root is neither EXECUTE nor E_R       400 invalid_request        (3.3, 4.11 -- in
 *                                            Peer_Dispatch, not here)
 *
 * THE TAG ARM KEEPS non_canonical_ecf AND THAT IS DELIBERATE. 4.11 rules that code
 * non-conformant "on the framing arm" and gives its reason in the same sentence:
 * ENTITY-CBOR-ENCODING defines it for CBOR tag-policy violations specifically, which that
 * document still MUSTs at decode time (6.3). The two rows are disjoint by CAUSE rather
 * than in conflict. Everything else this decoder calls non-canonical (a non-minimal head,
 * an indefinite length, mis-ordered keys) is genuinely "non-canonical CBOR that never
 * becomes an Envelope".
 *
 * THE INPUT IS A STRUCTURED KIND, never the exception's prose. This peer has TWO unwind
 * channels -- EC.!ERRKIND (the codec's Reject) and EC.!EXC (the peer layer's Throw) --
 * and Wire_RefusalKind below reads them in that order, so a classifier can never be
 * pointed at the wrong one. A classifier that recognised a cause by matching on a message
 * would be one string edit away from silently re-collapsing the codes.
 *
 * The messages are a FIXED TABLE, never an internal detail string: a wire-visible string
 * stays ASCII (two peers in this cohort have been killed at runtime by a non-ASCII byte in
 * an encoded string, on two unrelated compilers), the internal details carry section
 * signs, and nothing here echoes attacker-supplied bytes back. */
Wire_PreAdmissionRefusal: procedure expose EC.
  parse arg kind
  if kind == 'payload_too_large' then return '413 payload_too_large inbound frame exceeds the configured maximum size'
  if kind == 'included_key_mismatch' | kind == 'content_hash_mismatch' then ,
    return '400 hash_mismatch an entity was addressed by a hash that does not bind to it'
  if kind == 'TAG_REJECTED' then return '400 non_canonical_ecf CBOR tags are forbidden anywhere in an entity data field'
  return '400 invalid_request frame did not decode into an envelope'

/* Wire_RefusalKind -- the cause of the refusal that just unwound, read off whichever of
 * the two unwind channels carries it. The codec's Reject (EC.!ERRKIND) is tested FIRST
 * because the peer-layer Throw flag may still hold a kind from an earlier frame; both are
 * cleared by their own entry points, and a decode that fails in the codec never reaches a
 * Throw site. */
Wire_RefusalKind: procedure expose EC.
  if \EC.!OK then return EC.!ERRKIND
  return EC.!EXC

/* prefix `payload` with its 4-byte big-endian length (§1.6). */
Wire_Frame: procedure
  parse arg payload
  return d2c(length(payload), 4) || payload

/* ── EXECUTE builder (§3.2) ── author/capability are raw hash octets ('' to omit);
 * resource is a map TV ('' to omit); params is a materialized entity. */
Wire_MakeExecute: procedure expose EC.
  parse arg request_id, uri, operation, params, author, capability, resource
  m = Ecf_Map('request_id', Ecf_Str(request_id), 'uri', Ecf_Str(uri))
  m = Ecf_MapPut(m, 'operation', Ecf_Str(operation))
  m = Ecf_MapPut(m, 'params', Ent_ToCbor(params))
  if author \== '' then m = Ecf_MapPut(m, 'author', Ecf_Bytes(author))
  if capability \== '' then m = Ecf_MapPut(m, 'capability', Ecf_Bytes(capability))
  if resource \== '' then m = Ecf_MapPut(m, 'resource', resource)
  return Ent_Make('system/protocol/execute', m)

/* ── EXECUTE_RESPONSE builder (§3.3) ── */
Wire_MakeResponse: procedure expose EC.
  parse arg request_id, status, result
  m = Ecf_Map('request_id', Ecf_Str(request_id), 'status', Ecf_Int(status))
  m = Ecf_MapPut(m, 'result', Ent_ToCbor(result))
  return Ent_Make('system/protocol/execute/response', m)

Wire_ErrorResult: procedure expose EC.
  parse arg code, message
  if message \== '' then data = Ecf_Map('code', Ecf_Str(code), 'message', Ecf_Str(message))
  else data = Ecf_Map('code', Ecf_Str(code))
  return Ent_Make('system/protocol/error', data)

/* empty-params (§3.2): a primitive/any whose data is the canonical empty map. */
Wire_EmptyParams: procedure expose EC.
  return Ent_Make('primitive/any', Ecf_EmptyMap())

/* a resource map {targets: [target]} for a single target path string. */
Wire_ResourceTarget: procedure expose EC.
  parse arg target
  lst = Lst_Add('', target)
  return Ecf_Map('targets', Ecf_TextArray(lst))

/* ── response decode helpers (initiator side) ── */
Wire_ResponseStatus: procedure expose EC.
  parse arg env
  s = Ent_Uint(Env_Root(env), 'status')
  if s == '' then return 0
  return s
Wire_ResponseResult: procedure expose EC.
  parse arg env
  m = Ent_MapField(Env_Root(env), 'result')
  if m == '' then return ''
  return Ent_OfCbor(m)
