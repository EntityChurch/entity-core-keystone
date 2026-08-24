"entity-core-protocol-smalltalk — the peer CLI entry doit (loaded against the peer image).

Boot convention (matches the cohort — study forth bin/peer.fs):
  pharo --headless entity-core.image eval <this doit>   (options via ENV, see below)

A headless `eval` appends extra argv tokens to the SOURCE (the S2 A-ST note: argv is NOT
passed as args to the doit), so the peer reads its options from ENV VARS (the run scripts
export them):
  EC_PEER_PORT      listen port (0 => ephemeral). Default 0.
  EC_PEER_SEED      a single hex byte, repeated x32, as the seed (test convenience). Default 11.
  EC_PEER_NAME      loads the Ed25519 identity from ~/.entity/peers/NAME/keypair. Overrides SEED.
  EC_PEER_VALIDATE  '1' enables the §7a system/validate/* handlers (OFF by default; --validate).
  EC_PEER_OPEN_GRANTS '1' seeds the degenerate default→* open-grants policy (--debug-open-grants,
                    grant-gated categories need it; deprecated in production, OFF by default).

On success prints exactly `LISTENING <bound-port>` on stdout (the harness scrapes this), then
serves the single-event-loop forever. Runs against a SNAPSHOTTED peer image (A-ST-010) so the
EntityCore-* classes are compile-time visible to this doit."

| env portEnv seedEnv nameEnv peer seed hexByte port validate openGrants |
env := Smalltalk os environment.
portEnv := env at: 'EC_PEER_PORT' ifAbsent: [ '0' ].
seedEnv := env at: 'EC_PEER_SEED' ifAbsent: [ '11' ].
nameEnv := env at: 'EC_PEER_NAME' ifAbsent: [ '' ].
validate := (env at: 'EC_PEER_VALIDATE' ifAbsent: [ '0' ]) = '1'.
openGrants := (env at: 'EC_PEER_OPEN_GRANTS' ifAbsent: [ '0' ]) = '1'.

seed := nameEnv isEmpty
	ifTrue: [
		hexByte := Integer readFrom: (seedEnv first: (2 min: seedEnv size)) readStream base: 16.
		ByteArray new: 32 withAll: hexByte ]
	ifFalse: [ EcPeer loadSeedForName: nameEnv ].

port := Integer readFrom: portEnv readStream.

peer := EcPeer new.
peer validate: validate; openGrants: openGrants.
peer bootstrapWithSeed: seed.
port := peer listenOn: port.
Stdio stdout << 'LISTENING '; << port printString; << (String with: Character lf); flush.
peer serveForever.
'served'
