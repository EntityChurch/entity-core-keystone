/* entity-core-protocol-rexx — standalone S4-ready host (bin/peer.rex).
 *
 * Boots ONE peer on a localhost port, prints a `LISTENING <port>` readiness line so a
 * harness (run-s4.sh) can scrape the bound port, then runs the single-threaded ecnet
 * select-pump forever (Transport_Serve — the §4.9 serve loop). This is s3_responder.rex
 * generalized: the identity comes from a persistent on-disk keypair (--name) instead of
 * a repeated seed byte, and flags are parsed from the one Regina arg string.
 *
 * Flags (classic Rexx delivers ALL args as ONE string → parse the word stream):
 *   --port N               bind port (0 = ephemeral, the default)
 *   --name NAME            load the Ed25519 identity from ~/.entity/peers/NAME/keypair
 *                          (entity-core PEM = base64 of a 32-byte seed between the
 *                          BEGIN/END ENTITY PRIVATE KEY lines — the Go entity-peer
 *                          --name / peer-manager convention). Lets the validator's
 *                          multisig accept-path probe co-sign AS the peer
 *                          (crypto.LookupKeypairByPeerID).
 *   --seed HH              fallback: a hex byte repeated 32× for a deterministic seed.
 *   --net PATH             the ecnet co-process daemon binary (default src/ext/ecnet).
 *   --base PATH            the FIFO base path (default /tmp/ecnet-peer.<port>).
 *   --debug-open-grants    degenerate [default → *] admin seed policy (non-conformant).
 *   --validate             bootstrap the §7a system-validate conformance handlers.
 *
 * The §7a handlers are OFF by default (a standing dispatch-outbound originator must
 * never ship live); --validate opts in (the keystone cohort mechanism).
 *
 * Crypto is DAEMON-mode (A-RX-011): Transport_Start MUST run BEFORE Peer_Create (whose
 * §6.9a bootstrap hashes cross the C-ABI inside the ecnet daemon over the same FIFO).
 */
parse arg argline
numeric digits 200
signal on syntax name Fatal
call Ec_Init

/* ── defaults ── */
port        = 0
name        = ''
seedhex     = ''
netbin      = 'src/ext/ecnet'
base        = ''
opengrants  = 0
conformance = 0

/* ── flag parse (word stream; classic Rexx has no per-arg vector) ── */
rest = strip(argline)
do while rest \== ''
  parse var rest tok rest
  select
    when tok == '--port'              then parse var rest port rest
    when tok == '--name'              then parse var rest name rest
    when tok == '--seed'              then parse var rest seedhex rest
    when tok == '--net'               then parse var rest netbin rest
    when tok == '--base'              then parse var rest base rest
    when tok == '--debug-open-grants' then opengrants = 1
    when tok == '--validate'          then conformance = 1
    otherwise do
      call lineout '<stderr>', 'peer: unknown flag' tok
      exit 2
    end
  end
end
if port == '' then port = 0
if base == '' then base = '/tmp/ecnet-peer.' || port

EC.!DBG = value('EC_DBG', , 'ENVIRONMENT')
EC.!ECNET_BIN = netbin

/* ── resolve the 32-byte seed ── */
if name \== '' then seed = Load_Seed_From_Name(name)
else if seedhex \== '' then seed = copies(x2c(seedhex), 32)
else seed = copies('11'x, 32)

/* ── boot: daemon (which carries crypto, A-RX-011) BEFORE the peer ── */
call Transport_Start base
EC.!CRYPTO_VIA = 'daemon'
peer = Peer_Create(seed, opengrants, conformance)
bound = Transport_Listen(peer, port)
if bound == -1 then do
  call lineout '<stderr>', 'peer: LISTEN failed on port' port
  exit 1
end
say 'LISTENING' bound
call stream 'STDOUT', 'c', 'flush'

/* serve forever — the single-threaded select-pump (returns only on daemon EOF). */
call Transport_Serve peer
exit 0

/* Load the entity-core PEM keypair (~/.entity/peers/NAME/keypair): strip the BEGIN/END
 * armor lines, base64-decode the body, and require exactly a 32-byte seed. */
Load_Seed_From_Name: procedure expose EC.
  parse arg nm
  home = value('HOME', , 'ENVIRONMENT')
  if home == '' then home = '/root'
  path = home || '/.entity/peers/' || nm || '/keypair'
  if stream(path, 'c', 'query exists') == '' then do
    call lineout '<stderr>', 'peer: --name' nm '— cannot read keypair at' path
    exit 2
  end
  body = ''
  do while lines(path) > 0
    line = strip(linein(path))
    if line == '' then iterate
    if left(line, 1) == '-' then iterate      /* BEGIN/END armor */
    body = body || line
  end
  call stream path, 'c', 'close'
  seed = B64_Decode(body)
  if length(seed) \== 32 then do
    call lineout '<stderr>', 'peer: --name' nm '— expected a 32-byte seed, got' length(seed)
    exit 2
  end
  return seed

/* RFC-4648 base64 decode → raw byte string. Regina has no built-in; this is the
 * shortest correct form (6 bits per symbol, take only whole output bytes, stop at
 * padding). Returns '' on an out-of-alphabet symbol. */
B64_Decode: procedure
  parse arg s
  alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  bits = ''
  do i = 1 to length(s)
    c = substr(s, i, 1)
    if c == '=' then leave
    v = pos(c, alpha) - 1
    if v < 0 then return ''
    bits = bits || right(x2b(d2x(v)), 6, '0')
  end
  out = ''
  do i = 1 to length(bits) - 7 by 8
    out = out || x2c(b2x(substr(bits, i, 8)))
  end
  return out

Fatal:
  call lineout '<stderr>', 'PEER FATAL SYNTAX rc='rc 'line='sigl '('errortext(rc)')'
  call lineout '<stderr>', '  src=['strip(sourceline(sigl))']'
  call lineout '<stderr>', '  D=['condition('D')']'
  exit 3
