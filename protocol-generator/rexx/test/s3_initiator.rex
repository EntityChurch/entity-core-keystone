/* entity-core-protocol-rexx — S3 smoke INITIATOR process (the phase exit gate).
 *
 * Boots a second peer, dials the responder over REAL loopback TCP through the full
 * §6.5 dispatch chain (both peers on their own single-threaded ecnet select-pump),
 * drives the §4.1 forward handshake (hello -> authenticate), then:
 *   - 404 on an unregistered path (no handler resolved);
 *   - an authority-gated tree get (200) over the §4.4 discovery floor, returning a
 *     system/handler/interface entity;
 *   - a capability request (200);
 *   - 8-way request_id demux of concurrently-issued replies (N7, §6.11) — 8 requests
 *     in flight on the one connection, resolved out of order by the pump.
 * Args: seedbyte port base opengrants conformance eccrypto ecnet expected_peerid
 */
parse arg seedbyte port base opengrants conformance eccrypto ecnet expected_peerid
numeric digits 200
signal on syntax name Fatal
call Ec_Init
EC.!DBG = value('EC_DBG', , 'ENVIRONMENT')
EC.!ECNET_BIN = ecnet
if opengrants == '' then opengrants = 0
if conformance == '' then conformance = 0
seed = copies(x2c(seedbyte), 32)
/* Start the daemon FIRST — it carries crypto too (A-RX-011), and Peer_Create hashes. */
call Transport_Start base
EC.!CRYPTO_VIA = 'daemon'
peer = Peer_Create(seed, opengrants, conformance)
EC.!PASS = 0; EC.!FAIL = 0

s = Transport_Dial(peer, port)
if s == '' then do; say 'DIAL FAILED'; exit 1; end
remote = Sess_Get(s, 'remote_peer_id')
call Check 'session established (capability minted)', (Sess_Get(s, 'capability') \== '')
call Check 'remote peer_id is a base58 peer id', (Cap_IsPeerId(remote))
if expected_peerid \== '' then call Check 'remote peer_id matches responder', (remote == expected_peerid)

/* 404 on an unregistered path */
r404 = Sess_Execute(s, '/' || remote || '/does/not/exist', 'noop', Wire_EmptyParams(), '')
call Check 'unregistered path -> 404', (Wire_ResponseStatus(r404) == 404)

/* authority-gated tree get (200) over the discovery floor */
itgt = Wire_ResourceTarget('system/handler/system/tree')
rget = Sess_Execute(s, '/' || remote || '/system/tree', 'get', Wire_EmptyParams(), itgt)
call Check 'granted tree get -> 200', (Wire_ResponseStatus(rget) == 200)
call Check 'tree get returns a system/handler/interface entity', (_rtype(rget) == 'system/handler/interface')

/* capability request (200) */
reqg = Cap_Grant(_pl('system/tree'), _pl('system/type/*'), _pl('get'), '')
reqp = Ent_Make('system/capability/request', Ecf_Map('grants', Ecf_Array(Lst_Add('', reqg))))
rcap = Sess_Execute(s, '/' || remote || '/system/capability', 'request', reqp, '')
call Check 'capability request -> 200', (Wire_ResponseStatus(rcap) == 200)

/* 8-way request_id demux (N7, §6.11) — 8 requests in flight at once */
rids = ''
do i = 1 to 8
  rid = Sess_ExecuteAsync(s, '/' || remote || '/system/tree', 'get', Wire_EmptyParams(), Wire_ResourceTarget('system/handler/system/tree'))
  rids = Lst_Add(rids, rid)
end
do i = 1 to 8
  call Sess_Await Lst_Item(rids, i)
end
correlated = 0
do i = 1 to 8
  rid = Lst_Item(rids, i)
  env = EC.!PENDING.rid
  if env == '' then iterate
  if Wire_ResponseStatus(env) \== 200 then iterate
  if _rtype(env) == 'system/handler/interface' & Ent_Text(Env_Root(env), 'request_id') == rid then correlated = correlated + 1
end
call Check '8 interleaved requests each correlated', (correlated == 8)

call Sess_Close s
call Transport_Stop
say ''
if EC.!FAIL > 0 then do; say 'SMOKE: FAIL (' || EC.!PASS || '/' || (EC.!PASS + EC.!FAIL) || ')'; exit 1; end
say 'SMOKE: PASS (' || EC.!PASS || '/' || (EC.!PASS + EC.!FAIL) || ')'
exit 0

Fatal:
  say 'INIT FATAL SYNTAX rc='rc' line='sigl' ('errortext(rc)')'
  exit 3

Check: procedure expose EC.
  parse arg name, cond
  if cond then do; EC.!PASS = EC.!PASS + 1; say '  [PASS]' name; end
  else do; EC.!FAIL = EC.!FAIL + 1; say '  [FAIL]' name; end
  return

_rtype: procedure expose EC.
  parse arg env
  r = Wire_ResponseResult(env)
  if r == '' then return ''
  return Ent_Type(r)
