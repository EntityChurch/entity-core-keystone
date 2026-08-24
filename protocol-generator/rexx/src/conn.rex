/* entity-core-protocol-rexx — per-connection state carried through the §6.5 dispatch
 * chain: the §4.1/§4.6 handshake state (issued nonce + hello-declared peer_id), the
 * `established` post-authenticate gate, the §6.11 reentry OUTBOUND seam (the transport
 * io handle the handler dispatches an outbound EXECUTE over), and an outbound
 * request_id counter.
 *
 * A conn is a HANDLE ("conn<n>") into the EC. stem. Fields at EC.!CONN.h.<key> (the
 * literal !CONN + value(h) + value(key) tail — collision-free).
 */

Conn_New: procedure expose EC.
  EC.!CONN_CTR = EC.!CONN_CTR + 1
  h = 'conn' || EC.!CONN_CTR
  k = 'established';   EC.!CONN.h.k = 0
  k = 'issued_nonce';  EC.!CONN.h.k = ''
  k = 'hello_peer_id'; EC.!CONN.h.k = ''
  k = 'out_counter';   EC.!CONN.h.k = 0
  k = 'io';            EC.!CONN.h.k = ''
  return h

Conn_Get: procedure expose EC.
  parse arg h, key
  return EC.!CONN.h.key

Conn_Set: procedure expose EC.
  parse arg h, key, value
  EC.!CONN.h.key = value
  return

Conn_NextOut: procedure expose EC.
  parse arg h
  k = 'out_counter'
  EC.!CONN.h.k = EC.!CONN.h.k + 1
  return EC.!CONN.h.k
