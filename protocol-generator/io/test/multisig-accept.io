// Multisig ACCEPT-path unit test (the oracle-uncoverable direction).
//
// The keystone lesson: conformance-green can be VACUOUS — a rejection-only
// oracle category (multisig, historically 100% malformed→deny) lets a
// fail-closed peer pass WITHOUT ever exercising the accept path. This test
// constructs a GENUINE valid 2-of-3 K-of-N root capability, co-signs it with
// TWO of the three constituent identities (one of which is the LOCAL peer, per
// §5.5 M6 root-at-local), and asserts verify_capability_chain ALLOWs it — the
// direction the oracle's reject probes structurally cannot cover.
//
// Exercises §3.6 M3 (root-only, N≥2, 2≤K≤N, distinct signers), §5.5 M4 (K valid
// signatures from the signer set) and M6 (local peer in signers AND signed).
// Run: io test/multisig-accept.io

EntityCodec
srcDir := Path with(File thisSourceFile parentDirectory parentDirectory path, "src")
loadSrc := method(n, Lobby doFile(Path with(srcDir, n)))
loadSrc("Ec.io"); loadSrc("Entity.io"); loadSrc("Envelope.io"); loadSrc("Identity.io")
loadSrc("Wire.io"); loadSrc("Store.io"); loadSrc("Capability.io")

fails := 0
check := method(name, ok,
    if(ok, ("ok   " .. name) println, fails = fails + 1; ("FAIL " .. name) println))

// three constituent identities; the LOCAL peer is A (M6 requires local in signers)
idA := Identity ofSeed(EntityCodec hexDecode("aa" repeated(32)))
idB := Identity ofSeed(EntityCodec hexDecode("bb" repeated(32)))
idC := Identity ofSeed(EntityCodec hexDecode("cc" repeated(32)))
localPeer := idA peerId
grantee := idA        // grantee resolves to a present system/peer entity

store := Store clone
list(idA, idB, idC) foreach(id, store putEntity(id peerEntity))

// a valid 2-of-3 multi-granter root cap: parent null, threshold 2, 3 distinct signers
multiGranter := EcMap with(
    "signers", list(EcBytes with(idA idHash), EcBytes with(idB idHash), EcBytes with(idC idHash)),
    "threshold", 2)
grants := list(Capability grant(list("system/tree" asSymbol),
                                list("system/type/*" asSymbol),
                                list("get" asSymbol), nil))
capData := EcMap with(
    "granter", multiGranter,       // polymorphic granter = the multi-granter (M1/M2)
    "grantee", EcBytes with(grantee idHash),
    "grants", grants,
    "created_at", Capability nowMs)
cap := Entity with("system/capability/token", capData)

// TWO of three constituents co-sign the cap's content_hash (A and B).
// Each is a system/signature whose signer == the constituent's idHash.
sigA := idA sign(cap)
sigB := idB sign(cap)

included := list(idA peerEntity, idB peerEntity, idC peerEntity, cap, sigA, sigB)

// ── the ACCEPT assertion ──
verdict := Capability verifyCapabilityChain(localPeer, store, cap, included)
check("valid 2-of-3 peer-cosigned root ALLOWs", verdict == "ALLOW")

// ── negative controls (the primitive is not vacuously permissive) ──
// only ONE signature present → below threshold → DENY
included1 := list(idA peerEntity, idB peerEntity, idC peerEntity, cap, sigA)
check("1-of-3 (below K=2) DENYs", Capability verifyCapabilityChain(localPeer, store, cap, included1) == "DENY")

// local peer NOT in the signer set (B,C only) → M6 fails → DENY
mgNoLocal := EcMap with(
    "signers", list(EcBytes with(idB idHash), EcBytes with(idC idHash)),
    "threshold", 2)
capNoLocal := Entity with("system/capability/token", EcMap with(
    "granter", mgNoLocal, "grantee", EcBytes with(grantee idHash),
    "grants", grants, "created_at", Capability nowMs))
inclNoLocal := list(idB peerEntity, idC peerEntity, idA peerEntity, capNoLocal,
    idB sign(capNoLocal), idC sign(capNoLocal))
check("local-not-in-signers (M6) DENYs", Capability verifyCapabilityChain(localPeer, store, capNoLocal, inclNoLocal) == "DENY")

// M3: a multi-granter with parent != null is invalid (root-only) → DENY
capWithParent := Entity with("system/capability/token", EcMap with(
    "granter", multiGranter, "grantee", EcBytes with(grantee idHash),
    "grants", grants, "created_at", Capability nowMs,
    "parent", EcBytes with(idC idHash)))
inclParent := list(idA peerEntity, idB peerEntity, idC peerEntity, capWithParent,
    idA sign(capWithParent), idB sign(capWithParent))
check("multi-sig with parent (M3 root-only) DENYs", Capability verifyCapabilityChain(localPeer, store, capWithParent, inclParent) == "DENY")

if(fails > 0, ("MULTISIG-ACCEPT FAIL (" .. fails .. ")") println; System exit(1))
"MULTISIG-ACCEPT OK: genuine 2-of-3 K-of-N accept path + M3/M4/M6 negatives" println
System exit(0)
