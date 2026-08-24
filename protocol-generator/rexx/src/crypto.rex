/* entity-core-protocol-rexx — crypto (§9.1 floor) with TWO carriers (A-RX-005/011):
 *
 *  - HELPER mode (EC.!CRYPTO_VIA = 'helper'): the standalone `eccrypto` binary over
 *    `ADDRESS SYSTEM ... WITH INPUT/OUTPUT STEM` (a HEX stem-pipe). Used OFFLINE — the
 *    S2 codec conformance + the S3 foundation self-test — where no FIFO stream is open.
 *
 *  - DAEMON mode (EC.!CRYPTO_VIA = 'daemon'): crypto crosses the C-ABI INSIDE the ecnet
 *    co-process daemon, over the SAME cmd/evt FIFO channel as the transport. The
 *    NETWORKED peer MUST use this: Regina's `ADDRESS SYSTEM` fork/exec CORRUPTS an open
 *    FIFO read stream (A-RX-011), so it cannot spawn the helper while serving. A crypto
 *    command (SHA256/SIGN/…) is answered by an "R <hex>" event the caller demuxes out of
 *    the event stream (network FRAME/ACCEPT/CLOSED events read meanwhile are queued for
 *    the main pump — see transport.rex _await_result).
 *
 * All byte I/O is C2X on the way in, X2C on the way out; verify returns 1|0.
 */

Crypto_Init: procedure expose EC.
  EC.!ECCRYPTO = arg(1)
  return

Crypto_Sha256: procedure expose EC.
  parse arg data
  if EC.!CRYPTO_VIA == 'daemon' then return x2c(_crypto_daemon('SHA256' c2x(data)))
  return x2c(_crypto_call('sha256', c2x(data)))
Crypto_Sha384: procedure expose EC.
  parse arg data
  if EC.!CRYPTO_VIA == 'daemon' then return x2c(_crypto_daemon('SHA384' c2x(data)))
  return x2c(_crypto_call('sha384', c2x(data)))
Crypto_Ed25519Pubkey: procedure expose EC.
  parse arg seed
  if EC.!CRYPTO_VIA == 'daemon' then return x2c(_crypto_daemon('PUB' c2x(seed)))
  return x2c(_crypto_call('ed25519_pubkey', c2x(seed)))
Crypto_Ed25519Sign: procedure expose EC.
  parse arg seed, msg
  if EC.!CRYPTO_VIA == 'daemon' then return x2c(_crypto_daemon('SIGN' c2x(seed) c2x(msg)))
  return x2c(_crypto_call('ed25519_sign', c2x(seed), c2x(msg)))
/* returns 1 (valid) | 0 */
Crypto_Ed25519Verify: procedure expose EC.
  parse arg pub, msg, sig
  if EC.!CRYPTO_VIA == 'daemon' then return (_crypto_daemon('VERIFY' c2x(pub) c2x(msg) c2x(sig)) == '1')
  return (_crypto_call('ed25519_verify', c2x(pub), c2x(msg), c2x(sig)) == '1')
Crypto_ImplInfo: procedure expose EC.
  return _crypto_call('impl_info')
/* current epoch time in milliseconds (§5.5 temporal validity). */
Crypto_NowMs: procedure expose EC.
  if EC.!CRYPTO_VIA == 'daemon' then return _crypto_daemon('NOW')
  out.0 = 0
  cmd = EC.!ECCRYPTO 'now'
  address system cmd with output stem out.
  return strip(out.1)
/* n cryptographic-quality random bytes (§4.6 nonce). */
Crypto_Random: procedure expose EC.
  parse arg n
  if EC.!CRYPTO_VIA == 'daemon' then return x2c(_crypto_daemon('RND' n))
  out.0 = 0
  cmd = EC.!ECCRYPTO 'random' n
  address system cmd with output stem out.
  return x2c(strip(out.1))

/* DAEMON crypto: send the command over the cmd FIFO, await the "R <hex>" result event
 * (transport.rex demuxes interleaved network events into the main pump's queue). */
_crypto_daemon: procedure expose EC.
  parse arg cmdline
  call Transport_Cmd cmdline
  return _await_result()

/* HELPER crypto: run the helper binary; pipe the hex args (one per line) to stdin,
 * read one hex/text line. Only valid OFFLINE (no open FIFO stream). */
_crypto_call: procedure expose EC.
  op = arg(1)
  in.0 = arg() - 1
  do i = 2 to arg()
    j = i - 1
    in.j = arg(i)
  end
  out.0 = 0
  cmd = EC.!ECCRYPTO op
  address system cmd with input stem in. output stem out.
  return strip(out.1)
