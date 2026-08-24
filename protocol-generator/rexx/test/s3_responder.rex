/* entity-core-protocol-rexx — S3 smoke RESPONDER process.
 * Boots a peer, starts its ecnet daemon, listens on 127.0.0.1:<port> (0 = ephemeral),
 * writes the bound port + its peer_id to <portfile>, then serves inbound EXECUTEs on
 * the single-threaded select-pump until its ecnet daemon exits (evt-FIFO EOF).
 * Args: seedbyte port base opengrants conformance eccrypto ecnet portfile
 */
parse arg seedbyte port base opengrants conformance eccrypto ecnet portfile
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
bound = Transport_Listen(peer, port)
call lineout portfile, bound
call lineout portfile, Peer_LocalPeer(peer)
call stream portfile, 'c', 'close'
call Transport_Serve peer
exit 0

Fatal:
  say 'RESP FATAL SYNTAX rc='rc' line='sigl' ('errortext(rc)')'
  say '  src=['strip(sourceline(sigl))']'
  say '  D=['condition('D')']'
  call lineout portfile, '-1'
  call stream portfile, 'c', 'close'
  exit 3
