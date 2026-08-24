"entity-core-protocol-smalltalk — integer head-form boundary self-test ([2^63, 2^64-1]).

BIGNUM class (A-ST-001): Smalltalk integers are arbitrary-precision, so the full uint64
range is carried FREE — there is NO fixed-width signed/unsigned boundary hazard (contrast
Forth/Zig/C#/OCaml, the fixed-width class, which must self-test the [2^63, 2^64-1] wrap).
But the canonical minimal HEAD form is still emitted explicitly, so this test pins the head
across the boundary anyway (the encode + a decode round-trip), plus the mt1 negative floor
(-2^64, which needs argument 2^64-1). A pure-codec test — no FFI.

Prints OK / FAILED and each mismatch. Run against the loaded peer image."

| out fails check toHex |
out := WriteStream on: String new.
fails := 0.
toHex := [ :ba | | s | s := WriteStream on: String new.
	ba do: [ :b | s nextPutAll: (b printPaddedWith: $0 to: 2 base: 16) ]. s contents ].

"check: value expectedHex — encode EcInt value, compare, then decode round-trip."
check := [ :val :expectedHex | | produced back |
	produced := EcCborEncoder encode: (EcInt value: val).
	(toHex value: produced) asUppercase = expectedHex asUppercase
		ifFalse: [ fails := fails + 1.
			out nextPutAll: 'FAIL enc '; print: val; nextPutAll: ' want='; nextPutAll: expectedHex;
				nextPutAll: ' got='; nextPutAll: (toHex value: produced); nextPut: Character lf ].
	"decode round-trip must recover the exact value."
	back := (EcCborDecoder decode: produced) value.
	back = val ifFalse: [ fails := fails + 1.
		out nextPutAll: 'FAIL dec '; print: val; nextPutAll: ' got='; print: back; nextPut: Character lf ] ].

"the boundary battery — the fixed-width class's danger zone, carried free here."
check value: (2 raisedTo: 63) value: '1B8000000000000000'.        "2^63 (bit 63 set)"
check value: ((2 raisedTo: 63) - 1) value: '1B7FFFFFFFFFFFFFFF'.   "max signed i64"
check value: ((2 raisedTo: 63) + 1) value: '1B8000000000000001'.
check value: ((2 raisedTo: 64) - 1) value: '1BFFFFFFFFFFFFFFFF'.   "max uint64"
check value: (2 raisedTo: 32) value: '1B0000000100000000'.        "first 8-byte arg"
check value: ((2 raisedTo: 32) - 1) value: '1AFFFFFFFF'.          "last 4-byte arg"
"mt1 negative floor: -2^64 encodes as major 1 with argument 2^64-1."
check value: (0 - (2 raisedTo: 64)) value: '3BFFFFFFFFFFFFFFFF'.
check value: -1 value: '20'.

out nextPut: Character lf.
fails = 0
	ifTrue: [ out nextPutAll: '=== int-boundary: OK (bignum uint64 head-form + round-trip) ===' ]
	ifFalse: [ out nextPutAll: '=== int-boundary: FAILED ('; print: fails; nextPutAll: ') ===' ].
out contents
