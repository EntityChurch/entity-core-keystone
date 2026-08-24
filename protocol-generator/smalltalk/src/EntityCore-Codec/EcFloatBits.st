"entity-core-protocol-smalltalk — the shortest-float ladder bit arithmetic (EntityCore-Codec).

f32/f64 come from native Float>>asIEEE64BitWord / fromIEEE64Bit: (A-ST-002). This class is
the HAND-ROLLED remainder: the f16 half-float leg + the ladder predicates
(does an f64 bit pattern round-trip EXACTLY through f16 / f32?). Every method operates on
REAL IEEE-754 bits (an arbitrary-precision Integer), via bitShift:/bitAnd:/bitOr:. Mirrors
the cohort's shortest-float ladder (Forth A-FT-002); returns nil for 'not representable in
this width' (rather than a -1 sentinel — nil is the idiomatic Smalltalk absent-answer).

LIVE-IMAGE NOTE: the class is captured in a temp (`cls`); class-side methods compile onto
`cls class` (all these are class-side utilities, no instances)."

| pkg cls |
pkg := 'EntityCore-Codec'.
cls := (Object << #EcFloatBits package: pkg) install.

"── f64 field extractors ──"
cls class compile: 'signBits: bits  ^ bits bitShift: -63'.
cls class compile: 'expBits: bits  ^ (bits bitShift: -52) bitAnd: 16r7FF'.
cls class compile: 'mantBits: bits  ^ bits bitAnd: ((1 bitShift: 52) - 1)'.

cls class compile: 'isInfOrNanBits: bits
	^ (self expBits: bits) = 16r7FF'.
cls class compile: 'isNanBits: bits
	^ (self expBits: bits) = 16r7FF and: [ (self mantBits: bits) ~= 0 ]'.

"── f64 bits -> f16 bits, or nil if not EXACTLY representable in f16. ──"
cls class compile: 'f64ToF16: bits
	| s16 e m ue full sh |
	s16 := (self signBits: bits) bitShift: 15.
	e := self expBits: bits.
	m := self mantBits: bits.
	e = 0 ifTrue: [
		m = 0 ifTrue: [ ^ s16 ].
		^ nil ].
	e = 16r7FF ifTrue: [ ^ nil ].
	ue := e - 1023.
	ue > 15 ifTrue: [ ^ nil ].
	ue >= -14 ifTrue: [
		((m bitShift: -42) bitShift: 42) = m ifFalse: [ ^ nil ].
		^ (m bitShift: -42) bitOr: (((ue + 15) bitShift: 10) bitOr: s16) ].
	ue >= -24 ifTrue: [
		full := (1 bitShift: 52) bitOr: m.
		sh := 42 + (-14 - ue).
		((full bitShift: 0 - sh) bitShift: sh) = full ifFalse: [ ^ nil ].
		^ (full bitShift: 0 - sh) bitOr: s16 ].
	^ nil'.

"── f64 bits -> f32 bits, or nil if not EXACTLY representable in f32. ──"
cls class compile: 'f64ToF32: bits
	| s32 e m ue full sh |
	s32 := (self signBits: bits) bitShift: 31.
	e := self expBits: bits.
	m := self mantBits: bits.
	e = 0 ifTrue: [
		m = 0 ifTrue: [ ^ s32 ].
		^ nil ].
	e = 16r7FF ifTrue: [ ^ nil ].
	ue := e - 1023.
	ue > 127 ifTrue: [ ^ nil ].
	ue >= -126 ifTrue: [
		((m bitShift: -29) bitShift: 29) = m ifFalse: [ ^ nil ].
		^ (m bitShift: -29) bitOr: (((ue + 127) bitShift: 23) bitOr: s32) ].
	ue >= -149 ifTrue: [
		full := (1 bitShift: 52) bitOr: m.
		sh := 29 + (-126 - ue).
		((full bitShift: 0 - sh) bitShift: sh) = full ifFalse: [ ^ nil ].
		^ (full bitShift: 0 - sh) bitOr: s32 ].
	^ nil'.

"── decode-side widen: f16/f32 bit pattern -> f64 bit pattern (store f64 internally). ──"
cls class compile: 'f16ToF64: h
	| s e m ue |
	s := (h bitShift: -15) bitShift: 63.
	e := (h bitShift: -10) bitAnd: 16r1F.
	m := h bitAnd: 16r3FF.
	e = 0 ifTrue: [
		m = 0 ifTrue: [ ^ s ].
		ue := -14.
		[ m < 1024 ] whileTrue: [ m := m * 2. ue := ue - 1 ].
		m := m bitAnd: 16r3FF.
		^ ((ue + 1023) bitShift: 52) bitOr: ((m bitShift: 42) bitOr: s) ].
	e = 16r1F ifTrue: [
		^ (s bitOr: (16r7FF bitShift: 52)) bitOr: (m bitShift: 42) ].
	^ (((e - 15 + 1023) bitShift: 52) bitOr: (m bitShift: 42)) bitOr: s'.

cls class compile: 'f32ToF64: f
	| s e m ue |
	s := (f bitShift: -31) bitShift: 63.
	e := (f bitShift: -23) bitAnd: 16rFF.
	m := f bitAnd: 16r7FFFFF.
	e = 0 ifTrue: [
		m = 0 ifTrue: [ ^ s ].
		ue := -126.
		[ m < 16r800000 ] whileTrue: [ m := m * 2. ue := ue - 1 ].
		m := m bitAnd: 16r7FFFFF.
		^ ((ue + 1023) bitShift: 52) bitOr: ((m bitShift: 29) bitOr: s) ].
	e = 16rFF ifTrue: [
		^ (s bitOr: (16r7FF bitShift: 52)) bitOr: (m bitShift: 29) ].
	^ (((e - 127 + 1023) bitShift: 52) bitOr: (m bitShift: 29)) bitOr: s'.

"── ladder re-validation predicates (used on decode). ──"
cls class compile: 'wouldBeF16: bits
	(self isInfOrNanBits: bits) ifTrue: [ ^ true ].
	^ (self f64ToF16: bits) notNil'.
cls class compile: 'wouldBeF32: bits
	(self isInfOrNanBits: bits) ifTrue: [ ^ true ].
	^ (self f64ToF32: bits) notNil'.

'EntityCore-Codec:EcFloatBits installed'
