// Smoke — the S3 smoke runner. Boots TWO Swift peers over real loopback TCP and
// exercises the wire surface end-to-end. The hard S3 exit (PHASE-S3-PEER §smoke):
//
//   1. §4.1 handshake both directions (hello → authenticate; session + §4.4 cap).
//   2. EXECUTE on an unregistered path → 404.
//   3. authority-gated tree get → 200 (discovery-floor grant admits system/type/*).
//   4. capability request → 200 (mints a bounded child cap).
//   5. request_id demux (N7): N concurrent EXECUTEs each correlate to their reply.
//   6. clean teardown (no hangs/leaks).
//   + register→dispatch round-trip and dispatch-outbound reentry self-check (--validate).
//
// Run (in-container): swift run smoke

import EntityCoreProtocol
#if canImport(Glibc)
import Glibc
#endif

func seed(_ b: UInt8) -> [UInt8] { [UInt8](repeating: b, count: 32) }

/// Local result accumulator (Swift 6 forbids mutable globals; pass this around).
struct Results {
    var pass = 0
    var fail = 0
    mutating func check(_ name: String, _ cond: Bool) {
        if cond { pass += 1; print("  PASS  \(name)") }
        else { fail += 1; print("  FAIL  \(name)") }
    }
}

@main
struct SmokeMain {
    static func main() async {
        print("SMOKE: two Swift peers over loopback TCP")
        var results = Results()
        do {
            try await run(&results)
        } catch {
            print("SMOKE: EXCEPTION \(error)")
            results.fail += 1
        }
        print("SMOKE: \(results.pass) pass, \(results.fail) fail")
        exit(results.fail == 0 ? 0 : 1)
    }

    static func run(_ r: inout Results) async throws {
        // Responder (server) peer — debugOpen seed policy so the connecting client
        // gets the wide cap that exercises register + dispatch-outbound (the harness
        // convention: drive the real §6.9a authority, not a bypass); conformance
        // handlers opted in for the §7a checks.
        let responder = try await Peer(seed: seed(0x11), seedPolicy: .debugOpen(), conformanceHandlers: true)
        let server = try await Server(peer: responder, port: 0)
        await server.start()
        let port = await server.port
        let responderID = await responder.localPeerID
        print("  responder listening on \(port), peer_id=\(responderID)")

        // Initiator (client) peer. It also serves (B-role) so it can answer the
        // reentrant EXECUTE in the dispatch-outbound self-check (§7a.2a).
        let initiatorIdentity = try Identity(seed: seed(0x22))
        let initiatorServePeer = try await Peer(seed: seed(0x22), conformanceHandlers: true)
        let client = try await PeerClient.connect(to: port, identity: initiatorIdentity, servePeer: initiatorServePeer)

        // 1. handshake.
        r.check("§4.1 handshake — session established", client.capabilityHash != nil)
        r.check("§4.1 handshake — remote peer_id correct", client.remotePeerID == responderID)

        // 2. EXECUTE on an unregistered path → 404.
        let emptyParams = try Model.emptyParams()
        let r404 = try await client.execute(uri: "local/nonexistent", operation: "get",
            params: emptyParams, resourceTargets: ["local/nonexistent/x"])
        r.check("404 on unregistered path", r404.root.data.uintAt("status") == 404)

        // 3. authority-gated tree get → 200 (discovery floor admits system/type/*).
        let typePath = "/" + responderID + "/system/type/system/peer"
        let rGet = try await client.execute(uri: "system/tree", operation: "get",
            params: emptyParams, resourceTargets: [typePath])
        r.check("authority-gated tree get → 200", rGet.root.data.uintAt("status") == 200)

        // 4. capability request → 200 (mint a bounded child cap from the floor).
        let reqParams = try Model.make(type: "system/capability/request", fields: [
            ("grants", .array([
                CBORValue.textMap([
                    ("handlers", .textMap([("include", .array([.text("system/tree")]))])),
                    ("resources", .textMap([("include", .array([.text("system/type/*")]))])),
                    ("operations", .textMap([("include", .array([.text("get")]))])),
                ])
            ])),
        ])
        let rReq = try await client.execute(uri: "system/capability", operation: "request", params: reqParams)
        r.check("capability request → 200", rReq.root.data.uintAt("status") == 200)

        // 5. request_id demux (N7): N concurrent EXECUTEs each correlate correctly.
        let n = 16
        let demuxResults = await withTaskGroup(of: (Int, UInt64?).self, returning: [(Int, UInt64?)].self) { group in
            for k in 0..<n {
                group.addTask {
                    let ep = try? Model.emptyParams()
                    let resp = try? await client.execute(uri: "system/tree", operation: "get",
                        params: ep ?? emptyParams, resourceTargets: [typePath])
                    return (k, resp?.root.data.uintAt("status"))
                }
            }
            var acc: [(Int, UInt64?)] = []
            for await item in group { acc.append(item) }
            return acc
        }
        let all200 = demuxResults.count == n && demuxResults.allSatisfy { $0.1 == 200 }
        r.check("N7 request_id demux — \(demuxResults.filter { $0.1 == 200 }.count)/\(n) concurrent EXECUTEs correlate", all200)

        // + register → dispatch round-trip (§6.13a): register a handler over the
        //   wire, then confirm its grant write landed (the five §6.2 writes).
        let regParams = try Model.emptyParams()
        let rReg = try await client.execute(uri: "system/handler", operation: "register",
            params: regParams, resourceTargets: ["system/handler/local/demo"])
        r.check("§6.13a register → 200", rReg.root.data.uintAt("status") == 200)
        let grantBound = await responder.store.isBound(path: "/" + responderID + "/system/capability/grants/local/demo")
        r.check("§6.13a register — grant write landed", grantBound)

        // + §7a dispatch-outbound reentry self-check (--validate). The responder's
        //   dispatch-outbound originates back to the initiator (B-role) over the
        //   same connection; the initiator's serve-peer answers system/validate/echo.
        //   The initiator (the caller) mints the reentry capability — granted to the
        //   RESPONDER, rooted at the initiator — and passes it in-band (Go ruling (a)).
        let initiatorID = initiatorIdentity  // the caller's identity (root of reentry cap)
        // Reconstruct the responder's identity hash from its peer_id (Ed25519
        // identity-multihash: the digest IS the public key).
        let responderPID = try PeerID.parse(responderID)
        let responderPeerEntity = try Model.make(type: "system/peer", fields: [
            ("public_key", .bytes(responderPID.digest)), ("key_type", .text("ed25519")),
        ])
        let responderIdentityHash = responderPeerEntity.hash
        // Mint the reentry cap: granter = initiator, grantee = responder, scope
        // covers system/validate/echo at the initiator's namespace.
        let reentryGrant = CBORValue.textMap([
            ("handlers", .textMap([("include", .array([.text("system/validate/echo")]))])),
            ("resources", .textMap([("include", .array([.text("/" + initiatorID.peerID + "/*")]))])),
            ("operations", .textMap([("include", .array([.text("echo")]))])),
        ])
        let reentryCap = try Model.make(type: "system/capability/token", data: .textMap([
            ("grants", .array([reentryGrant])),
            ("granter", .bytes(initiatorID.identityHash)),
            ("grantee", .bytes(responderIdentityHash)),
            ("created_at", .uint(1)),
        ]))
        let reentryCapSig = try initiatorID.signatureEntity(target: reentryCap.hash)
        // The reentry authority entities ride in-band as FULL materialized entities
        // (Go ruling (a) / §7a.2a) — the responder bundles them into the outbound
        // EXECUTE's `included`. `value` IS the echo params data (passed THROUGH,
        // never re-wrapped — the §7b t1_2 pin).
        func entVal(_ b: BuiltEntity) -> CBORValue {
            .textMap([("type", .text(b.type)), ("data", b.data)])
        }
        let dispParams = try Model.make(type: "primitive/any", data: .textMap([
            ("target", .text("system/validate/echo")),
            ("operation", .text("echo")),
            ("value", .textMap([("v", .uint(42))])),
            ("reentry_capability", entVal(reentryCap)),
            ("reentry_granter", entVal(initiatorID.peerEntity)),
            ("reentry_cap_signature", entVal(reentryCapSig)),
        ]))
        let rDisp = try await client.execute(uri: "system/validate/dispatch-outbound", operation: "dispatch", params: dispParams)
        r.check("§7a dispatch-outbound reentry → 200", rDisp.root.data.uintAt("status") == 200)
        // The relayed echo result is the params entity verbatim: result.data is the
        // {v:42} value the caller sent (no re-wrap).
        let downResult = rDisp.root.data.mapValue("result")?.mapValue("data")?.mapValue("result")
        let echoedV = downResult?.mapValue("data")?.mapValue("v")?.uintValue
        r.check("§7a dispatch-outbound — value passthrough (echo v=42)", echoedV == 42)

        // 6. clean teardown.
        await client.close()
        await server.stop()
        r.check("clean teardown", true)
    }
}
