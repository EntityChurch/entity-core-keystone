"entity-core-protocol-smalltalk — the UFFI crypto binding to libentitycore_codec (§9.1 floor).

A-ST-005 (the KEY differentiator, like Forth): Pharo's Unified FFI (ffiCall:module:) is a
GENUINE IN-PROCESS libffi binding — the VM dlopen's the .so and marshals call-outs via
libffi. Crypto is a direct in-process call; NO subprocess / FIFO / co-process daemon (Rexx's
A-RX-011 transport pain does NOT arise). SHA-256/384 + Ed25519 are unified on this one
audited C-ABI source (libsodium, statically linked into the .so) — A-ST-009.

Convention: buffers are (ptr,len); UFFI marshals a ByteArray argument as void*, size passed
as a uint64. Out buffers are caller-allocated ByteArrays. All fallible calls return int32
(EC_OK = 0); a non-zero status raises EntityCryptoError. The .so soname resolves from
LD_LIBRARY_PATH (the same placement verified at S1).

`moduleName` is a class-side accessor so an operator can point at an absolute .so path if it
is not on LD_LIBRARY_PATH; default is the bare soname."

| pkg cls |
pkg := 'EntityCore-Crypto'.

cls := (Object << #EcLibEntityCoreCodec package: pkg) install.

cls class compile: 'moduleName
	"The libentitycore_codec shared object. Bare soname → resolved via LD_LIBRARY_PATH."
	^ ''libentitycore_codec.so'''.

"── raw ffiCall: bindings, one method per ec_* symbol (instance-side; the idiom expects
    the FFI method on an instance whose class answers #ffiLibraryName or via module:). ──"
cls compile: 'ec_sha256: dataPtr len: n out: outPtr
	^ self ffiCall: #( int32 ec_sha256( void* dataPtr, uint64 n, void* outPtr ) )
		module: EcLibEntityCoreCodec moduleName'.
cls compile: 'ec_sha384: dataPtr len: n out: outPtr
	^ self ffiCall: #( int32 ec_sha384( void* dataPtr, uint64 n, void* outPtr ) )
		module: EcLibEntityCoreCodec moduleName'.
cls compile: 'ec_ed25519_seed_to_pubkey: seedPtr out: outPtr
	^ self ffiCall: #( int32 ec_ed25519_seed_to_pubkey( void* seedPtr, void* outPtr ) )
		module: EcLibEntityCoreCodec moduleName'.
cls compile: 'ec_ed25519_sign: privPtr msg: msgPtr len: n out: outPtr
	^ self ffiCall: #( int32 ec_ed25519_sign( void* privPtr, void* msgPtr, uint64 n, void* outPtr ) )
		module: EcLibEntityCoreCodec moduleName'.
cls compile: 'ec_ed25519_verify: pubPtr msg: msgPtr len: n sig: sigPtr
	^ self ffiCall: #( int32 ec_ed25519_verify( void* pubPtr, void* msgPtr, uint64 n, void* sigPtr ) )
		module: EcLibEntityCoreCodec moduleName'.
cls compile: 'ec_impl_info
	^ self ffiCall: #( String ec_impl_info( void ) )
		module: EcLibEntityCoreCodec moduleName'.

"── high-level surface (return ByteArrays / Booleans; raise on non-zero status). ──"
cls compile: 'check: status
	status ~= 0 ifTrue: [ ^ EntityCryptoError signal: ''C-ABI status '', status printString ].
	^ status'.

cls compile: 'sha256: aByteArray
	| out |
	out := ByteArray new: 32.
	self check: (self ec_sha256: aByteArray len: aByteArray size out: out).
	^ out'.
cls compile: 'sha384: aByteArray
	| out |
	out := ByteArray new: 48.
	self check: (self ec_sha384: aByteArray len: aByteArray size out: out).
	^ out'.
cls compile: 'ed25519PubkeyFromSeed: seedByteArray
	| out |
	seedByteArray size = 32 ifFalse: [ ^ BadSeedError signal: ''seed must be 32 bytes'' ].
	out := ByteArray new: 32.
	self check: (self ec_ed25519_seed_to_pubkey: seedByteArray out: out).
	^ out'.
cls compile: 'ed25519Sign: msgByteArray withSeed: seedByteArray
	"The C-ABI priv is the 32-byte seed for RFC 8032."
	| out |
	seedByteArray size = 32 ifFalse: [ ^ BadSeedError signal: ''seed must be 32 bytes'' ].
	out := ByteArray new: 64.
	self check: (self ec_ed25519_sign: seedByteArray msg: msgByteArray len: msgByteArray size out: out).
	^ out'.
cls compile: 'ed25519Verify: msgByteArray sig: sigByteArray pubkey: pubByteArray
	"1 valid / 0 invalid -> Boolean; a non-zero non-(-6) status is an error."
	| status |
	status := self ec_ed25519_verify: pubByteArray msg: msgByteArray len: msgByteArray size sig: sigByteArray.
	^ status = 0'.
cls compile: 'implInfo
	^ self ec_impl_info'.

"── a shared default instance (single-event-loop peer; one op at a time). ──"
cls class compile: 'default
	^ self new'.

'EntityCore-Crypto:EcLibEntityCoreCodec installed'
