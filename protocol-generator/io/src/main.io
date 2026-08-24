// entity-core-protocol-io — peer entry point.
//
//   io src/main.io --port <p> --name <NAME> [--validate] [--debug-open-grants]
//
// --name loads the persistent Ed25519 identity from
//   ~/.entity/peers/<NAME>/keypair  (entity-core PEM = base64 of a 32-byte seed).
// --validate enables the §7a system/validate/* conformance handlers (off by
//   default). --debug-open-grants sets the degenerate default->* seed policy
//   (deprecated; the conformance harness uses it, per the cohort convention).
//
// Prints "listening on TCP :<port>" once bound (the harness readiness line).

EntityCodec
Lobby doRelativeFile := method(p, self doFile(Path with(System launchPath, p)))

srcDir := Path with(File thisSourceFile parentDirectory path)
loadSrc := method(name, Lobby doFile(Path with(srcDir, name)))
loadSrc("Ec.io")
loadSrc("Entity.io")
loadSrc("Envelope.io")
loadSrc("Identity.io")
loadSrc("Wire.io")
loadSrc("Store.io")
loadSrc("Capability.io")
loadSrc("CoreTypes.io")
loadSrc("Handlers.io")
loadSrc("Peer.io")
loadSrc("Transport.io")

// ── argv ──
args := System args
port := 7777
name := nil
validate := false
openGrants := false
i := 1
while(i < args size,
    a := args at(i)
    if(a == "--port", i = i + 1; port = args at(i) asNumber)
    if(a == "--name", i = i + 1; name = args at(i))
    if(a == "--validate", validate = true)
    if(a == "--debug-open-grants", openGrants = true)
    i = i + 1
)

// ── identity: --name keypair, else a deterministic dev seed ──
ident := if(name != nil,
    kp := Path with(System getEnvironmentVariable("HOME"), ".entity/peers/" .. name .. "/keypair")
    Identity ofKeypairFile(kp)
,
    Identity ofSeed(EntityCodec hexDecode("1111111111111111111111111111111111111111111111111111111111111111"))
)

peer := Peer createFromIdentity(ident, openGrants, validate)

("peer " .. peer localPeer) println
("codec " .. EntityCodec implInfo) println
("listening on TCP :" .. port) println
File standardOutput flush

Transport with(peer) start(port)
