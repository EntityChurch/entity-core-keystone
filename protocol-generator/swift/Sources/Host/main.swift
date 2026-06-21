// Host — the S4-ready standalone peer host. Boots a single Peer listener on a TCP
// port and blocks, so an external oracle (entity-core-go validate-peer) can drive
// the live wire surface. Twin of the C# Host / TS host.ts / Zig host.zig / OCaml host.
//
//   --port N               listen port (default 7777; 0 = auto-assign)
//   --name NAME            load a persistent Ed25519 identity from the standard
//                          on-disk location ~/.entity/peers/NAME/keypair (the
//                          entity-core PEM keypair: base64 of a 32-byte seed
//                          between BEGIN/END ENTITY PRIVATE KEY lines — the same
//                          convention the Go entity-peer --name + peer-manager use).
//                          Without --name a fresh random seed is used.
//   --seed-policy <file>   seed-policy JSON (§6.9a; not yet parsed — S4 land)
//   --owner-identity <id>  owner identity for the `self` entry (default: self)
//   --debug-open-grants    degenerate `default → *` seed policy (DEPRECATED v7.74,
//                          removed v7.75; routed through the real §6.9a mechanism)
//   --validate             register the §7a system/validate/* conformance handlers
//                          (off by default — dispatch-outbound is a standing dialer)
//
// Loopback (127.0.0.1) only; one `LISTENING …` line on stdout once bound.

import EntityCoreProtocol
import Foundation
#if canImport(Glibc)
import Glibc
#endif

func randomSeed() -> [UInt8] {
    var s = [UInt8](repeating: 0, count: 32)
    for i in 0..<32 { s[i] = UInt8.random(in: 0...255) }
    return s
}

// Load the 32-byte Ed25519 seed from the standard on-disk keypair (Go entity-peer
// --name / peer-manager convention): ~/.entity/peers/NAME/keypair, a PEM whose body
// is base64(seed) between BEGIN/END ENTITY PRIVATE KEY lines. Missing/malformed → exit(2).
func loadSeedFromName(_ name: String) -> [UInt8] {
    let home = ProcessInfo.processInfo.environment["HOME"] ?? "/root"
    let path = "\(home)/.entity/peers/\(name)/keypair"
    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
        FileHandle.standardError.write(Data("error: --name \(name): cannot read \(path)\n".utf8))
        exit(2)
    }
    // Keep only the base64 body lines (those not starting with '-').
    let body = text
        .split(whereSeparator: { $0 == "\n" || $0 == "\r" })
        .filter { !$0.hasPrefix("-") }
        .joined()
    guard let data = Data(base64Encoded: body), data.count == 32 else {
        FileHandle.standardError.write(Data("error: --name \(name): expected a base64 32-byte seed in \(path)\n".utf8))
        exit(2)
    }
    return [UInt8](data)
}

@main
struct HostMain {
    static func main() async {
        var port: UInt16 = 7777
        var openGrants = false
        var validate = false
        var seed = randomSeed()

        var args = Array(CommandLine.arguments.dropFirst())
        var i = 0
        while i < args.count {
            switch args[i] {
            case "--port":
                i += 1
                if i < args.count, let p = UInt16(args[i]) { port = p }
            case "--name":
                i += 1
                if i < args.count { seed = loadSeedFromName(args[i]) }
            case "--debug-open-grants":
                openGrants = true
                FileHandle.standardError.write(Data("warning: --debug-open-grants is DEPRECATED (v7.74), removed v7.75; prefer --seed-policy with a wide-open default entry\n".utf8))
            case "--validate":
                validate = true
            case "--seed-policy", "--owner-identity":
                i += 1  // consume the value (S4: parse the file)
            case "-h", "--help":
                print("usage: entity-peer-swift [--port N] [--name NAME] [--seed-policy F] [--owner-identity ID] [--debug-open-grants] [--validate]")
                return
            default:
                FileHandle.standardError.write(Data("error: unknown argument '\(args[i])'\n".utf8))
                exit(2)
            }
            i += 1
        }

        let policy: SeedPolicy = openGrants ? .debugOpen() : .standard()
        do {
            let peer = try await Peer(seed: seed, seedPolicy: policy, conformanceHandlers: validate)
            let server = try await Server(peer: peer, port: port)
            await server.start()
            let bound = await server.port
            let pid = await peer.localPeerID
            // Write the readiness line via FileHandle so it is unbuffered (a run
            // script waits on it); Swift 6 forbids touching the global `stdout`.
            let line = "LISTENING 127.0.0.1:\(bound) peer_id=\(pid) open_grants=\(openGrants) validate=\(validate)\n"
            FileHandle.standardOutput.write(Data(line.utf8))
            // Block forever (the oracle drives the wire; killed externally).
            try await Task.sleep(nanoseconds: .max)
            _ = server
        } catch {
            FileHandle.standardError.write(Data("host error: \(error)\n".utf8))
            exit(1)
        }
    }
}
