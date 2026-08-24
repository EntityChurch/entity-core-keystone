"entity-core-protocol-smalltalk — crypto ACCEPT-path unit test (through the FFI).

The corpus's signature category asserts sign() produces the expected bytes; it never
exercises the VERIFY accept path, and content_hash never checks a hash we produced. Per the
keystone guidance (conformance-green can be vacuous — always add an accept-path test the
oracle can't cover), this signs a message, VERIFIES it (must accept), tampers a signature
byte and verifies again (must reject), derives the pubkey from the seed, and pins a SHA-256
KAT (empty string). Crypto crosses the UFFI binding to libentitycore_codec.

Prints OK / FAILED. Requires libentitycore_codec.so on LD_LIBRARY_PATH."

| out fails lib seed msg sig pub tampered okAccept okReject sha256empty expectedSha |
out := WriteStream on: String new.
fails := 0.
lib := EcLibEntityCoreCodec default.
seed := ByteArray new: 32 withAll: 0.        "deterministic all-zero seed"
msg := 'AAAA' asByteArray.

"sign -> verify (must accept)."
sig := lib ed25519Sign: msg withSeed: seed.
pub := lib ed25519PubkeyFromSeed: seed.
okAccept := lib ed25519Verify: msg sig: sig pubkey: pub.
okAccept
	ifTrue: [ out nextPutAll: 'PASS accept-path sign->verify VALID'; nextPut: Character lf ]
	ifFalse: [ fails := fails + 1. out nextPutAll: 'FAIL verify returned INVALID'; nextPut: Character lf ].

"tamper one signature byte -> verify must REJECT."
tampered := sig copy.
tampered at: 1 put: ((tampered at: 1) bitXor: 1).
okReject := lib ed25519Verify: msg sig: tampered pubkey: pub.
okReject
	ifTrue: [ fails := fails + 1. out nextPutAll: 'FAIL tampered signature verified VALID'; nextPut: Character lf ]
	ifFalse: [ out nextPutAll: 'PASS tampered signature rejected'; nextPut: Character lf ].

"SHA-256 KAT: sha256('') = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
sha256empty := lib sha256: (ByteArray new: 0).
expectedSha := ByteArray readHexFrom: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'.
sha256empty = expectedSha
	ifTrue: [ out nextPutAll: 'PASS sha256 empty-string KAT'; nextPut: Character lf ]
	ifFalse: [ fails := fails + 1. out nextPutAll: 'FAIL sha256 KAT mismatch'; nextPut: Character lf ].

out nextPut: Character lf.
fails = 0
	ifTrue: [ out nextPutAll: '=== crypto-accept: OK ('; nextPutAll: (lib implInfo); nextPutAll: ') ===' ]
	ifFalse: [ out nextPutAll: '=== crypto-accept: FAILED ('; print: fails; nextPutAll: ') ===' ].
out contents
