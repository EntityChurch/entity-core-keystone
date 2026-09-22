/* entity-core-protocol-rexx — wire framing (§1.6) + the two message builders (§3.2
 * EXECUTE, §3.3 EXECUTE_RESPONSE). Frame := [4-byte BE length][CBOR payload]; the
 * payload is a canonical-ECF-encoded system/protocol/envelope (§3.1).
 *
 * Only EXECUTE and EXECUTE_RESPONSE are wire message types (§3.3). hello /
 * authenticate are OPERATIONS on system/protocol/connect, NOT message types — any
 * other root type is ignored server-side (the dispatcher returns '').
 */

/* §1.6 / §4.10(a) 16-MiB frame bound is enforced in the ecnet C daemon (which owns
 * the de-framing), so the Rexx layer never sees an oversize frame — see ext/ecnet.c. */

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
