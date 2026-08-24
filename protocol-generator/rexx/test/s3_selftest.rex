/* entity-core-protocol-rexx — S3 foundation self-test (offline, no network).
 * Exercises the value model + entity + identity + store + coretypes layers against the
 * eccrypto helper. Usage: rexx <combined> <eccrypto-helper-path>
 */
parse arg eccrypto
numeric digits 200
signal on syntax name Fatal
call Ec_Init
call Crypto_Init eccrypto
EC.!PASS = 0; EC.!FAIL = 0; EC.!EMIT = 0

/* ── entity hashing determinism + wire round-trip ── */
e1 = Ent_Make('primitive/string', Ecf_Str('hello'))
e2 = Ent_Make('primitive/string', Ecf_Str('hello'))
call Check 'entity hash deterministic', (Ent_Hash(e1) == Ent_Hash(e2))
call Check 'content_hash is 33 bytes (fmt byte + sha256)', (length(Ent_Hash(e1)) == 33)
wire = Ent_ToCbor(e1)
back = Ent_OfCbor(wire)
call Check 'wire round-trip preserves type', (Ent_Type(back) == 'primitive/string')
call Check 'wire round-trip preserves hash', (Ent_Hash(back) == Ent_Hash(e1))

/* tamper the content_hash -> §1.8 fidelity reject */
call Throw_Clear
bad = Ecf_Map('type', Ecf_Str('primitive/string'), 'data', Ecf_Str('hello'), 'content_hash', Ecf_Bytes(copies('00'x, 33)))
junk = Ent_OfCbor(bad)
call Check 'tampered content_hash rejected (§1.8)', (EC.!EXC \== '')
call Throw_Clear

/* ── identity: seed -> pubkey -> peer_id -> peer entity ── */
seedA = copies('11'x, 32)
seedB = copies('22'x, 32)
idA = Id_OfSeed(seedA)
idB = Id_OfSeed(seedB)
call Check 'peer_id is Base58 non-empty', (length(Id_PeerId(idA)) >= 32)
call Check 'distinct seeds -> distinct peer_ids', (Id_PeerId(idA) \== Id_PeerId(idB))
call Check 'id_hash is 33 bytes', (length(Id_IdHash(idA)) == 33)
call Check 'peer_id derivable from pubkey matches', (Id_PeerIdOfPubkey(Id_Pub(idA)) == Id_PeerId(idA))

/* ── sign / verify round-trip ── */
target = Ent_Make('primitive/any', Ecf_Map('ping', Ecf_Int(42)))
sigA = Id_Sign(idA, target)
call Check 'signature entity type', (Ent_Type(sigA) == 'system/signature')
call Check 'signature verifies against signer peer', (Id_VerifySignature(sigA, Id_PeerEntity(idA)) == 1)
call Check 'signature FAILS against wrong peer', (Id_VerifySignature(sigA, Id_PeerEntity(idB)) == 0)
call Check 'signature signer == author id_hash', (Ent_Bytes(sigA, 'signer') == Id_IdHash(idA))

/* ── wire: EXECUTE + envelope frame round-trip ── */
res = Wire_ResourceTarget('system/handler/system/tree')
exec = Wire_MakeExecute('req-1', '/peer/system/tree', 'get', Wire_EmptyParams(), Id_IdHash(idA), '', res)
envx = Env_Make(exec, Lst_Add(Lst_Add('', Id_PeerEntity(idA)), Id_Sign(idA, exec)))
payload = Wire_FrameOfEnvelope(envx)
framed = Wire_Frame(payload)
call Check 'frame prefix is 4-byte BE length', (substr(framed, 1, 4) == d2c(length(payload), 4))
envx2 = Wire_EnvelopeOfFrame(payload)
call Check 'envelope frame round-trips root type', (Ent_Type(Env_Root(envx2)) == 'system/protocol/execute')
call Check 'envelope round-trips included count (2)', (Lst_Count(Env_Included(envx2)) == 2)
call Check 'included_get by hash resolves the signer peer', (Env_IncludedGet(envx2, Id_IdHash(idA)) \== '')

/* ── response builder + decode ── */
resp = Wire_MakeResponse('req-1', 404, Wire_ErrorResult('not_found', 'here'))
renv = Env_Make(resp, '')
rback = Wire_EnvelopeOfFrame(Wire_FrameOfEnvelope(renv))
call Check 'response status decodes to 404', (Wire_ResponseStatus(rback) == 404)
call Check 'response result is system/protocol/error', (Ent_Type(Wire_ResponseResult(rback)) == 'system/protocol/error')

/* ── store: bind / get / listing + emit seam ── */
sh = Store_New()
call Store_RegisterTreeConsumer sh, 'BumpEmit'
call Store_Bind sh, '/p/system/tree/a', e1
call Store_Bind sh, '/p/system/tree/b', e2
call Check 'emit hook fired on each new bind', (EC.!EMIT == 2)
call Check 'get_at resolves a bound entity', (Ent_Hash(Store_GetAt(sh, '/p/system/tree/a')) == Ent_Hash(e1))
call Check 'get_by_hash resolves content', (Store_GetByHash(sh, Ent_Hash(e1)) \== '')
call Check 'listing sees 2 children under /p/system/tree/', (Lst_Count(Store_Listing(sh, '/p/system/tree')) == 2)

/* ── core types: 53-type floor, publish + determinism ── */
call Check '53-type core floor present', (Ct_Count() == 53)
sh2 = Store_New()
call Ct_Publish sh2, 'PEERX'
call Check 'publish binds system/type/system/peer', (Store_GetAt(sh2, '/PEERX/system/type/system/peer') \== '')

/* ── §4.5 hello negotiation: present-empty vs absent (review lock) ── */
npeer = Peer_Create(seedA)
m_abs = Ecf_Map('peer_id', Ecf_Str(Id_PeerId(idA)))
call Check 'hello: absent hash_formats accepted', (Hello_Status(npeer, m_abs) == 200)
m_empty = Ecf_Map('hash_formats', Ecf_TextArray(''))
call Check 'hello: present-empty hash_formats -> 400', (Hello_Status(npeer, m_empty) == 400)
m_ekt = Ecf_Map('key_types', Ecf_TextArray(''))
call Check 'hello: present-empty key_types -> 400', (Hello_Status(npeer, m_ekt) == 400)
m_ok = Ecf_Map('hash_formats', Ecf_TextArray(_pl('ecfv1-sha256')))
call Check 'hello: hash_formats with ecfv1-sha256 accepted', (Hello_Status(npeer, m_ok) == 200)
m_dis = Ecf_Map('hash_formats', Ecf_TextArray(_pl('sha3-512')))
call Check 'hello: disjoint hash_formats -> 400', (Hello_Status(npeer, m_dis) == 400)

/* ── Ecf_Map key robustness: a text key literally "int" ── */
km = Ecf_Map('int', Ecf_Str('v'))
k0 = Ecf_MapKey(km, 1)
call Check 'Ecf_Map: bare key ''int'' encodes as a TEXT key', (Tv_Tag(k0) == 't' & Tv_Payload(k0) == 'int')

say ''
say '=== S3 foundation: ' EC.!PASS ' pass / ' EC.!FAIL ' fail ==='
if EC.!FAIL > 0 then exit 1
exit 0

Fatal:
  say 'FATAL SYNTAX rc='rc' line='sigl' ('errortext(rc)')'
  say '  ->' condition('D')
  exit 3

Check: procedure expose EC.
  parse arg name, cond
  if cond then do; EC.!PASS = EC.!PASS + 1; say '  [PASS]' name; end
  else do; EC.!FAIL = EC.!FAIL + 1; say '  [FAIL]' name; end
  return

BumpEmit: procedure expose EC.
  EC.!EMIT = EC.!EMIT + 1
  return

Hello_Status: procedure expose EC.
  parse arg peer, fields
  hello = Ent_Make('system/protocol/connect/hello', fields)
  exec = Wire_MakeExecute('rq', 'system/protocol/connect', 'hello', hello, '', '', '')
  conn = Conn_New()
  ctx = Ctx_Make(conn, '', Env_Make(exec, ''))
  out = Hnd_Connect(peer, 'hello', ctx)
  return Out_Status(out)
