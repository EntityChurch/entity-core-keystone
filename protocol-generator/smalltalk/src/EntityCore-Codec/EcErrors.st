"entity-core-protocol-smalltalk — the Error subclass hierarchy (EntityCore-Codec).

Smalltalk's idiomatic error mechanism is EXCEPTIONS: an Error subclass raised with signal:
and caught with [ ... ] on: SomeError do: [ :ex | ... ]. Reject-KINDs map to a namespaced
Error tree under EntityCoreError (per profile [error_model]). A decode-canonical violation
is one of these, first-class objects carrying a class + message.

LIVE-IMAGE NOTE: a single doit cannot both install a class AND reference it by its global
name (the whole doit compiles before it runs). So each newly-installed class is captured in
a temp and subclassed from the temp; cross-file references by global name are fine (the
class is globally registered once this doit completes)."

| pkg core codec crypto |
pkg := 'EntityCore-Codec'.

core := (Error << #EntityCoreError package: pkg) install.

codec := (core << #EntityCodecError package: pkg) install.
(codec << #NonCanonicalEcfError package: pkg) install.
(codec << #TruncatedInputError package: pkg) install.
(codec << #TagRejectedError package: pkg) install.
(codec << #BadVarintError package: pkg) install.
(codec << #BadBase58Error package: pkg) install.

crypto := (core << #EntityCryptoError package: pkg) install.
(crypto << #BadSeedError package: pkg) install.
(crypto << #UnsupportedContentHashFormatError package: pkg) install.

'EntityCore-Codec:EcErrors installed'
