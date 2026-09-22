// PeerHandlers.swift — the handler bodies (§6.2/§6.3): connect, tree, handlers,
// capability, type, and the §7a conformance handlers. Extension of `Peer`.
//
// Each handler is a method on the Peer actor (so it has isolated access to the
// store + identity). Bodies are derived spec-first from §4.1/§4.4/§4.6 (connect),
// §6.3 (tree), §6.2/§6.13a (handlers register/unregister), §6.2 (capability),
// and GUIDE-CONFORMANCE §7a (echo / dispatch-outbound).

import Crypto

extension Peer {

    // MARK: - Connection handler (§4.1/§4.4/§4.6)

    func handleConnect(root: Entity, env: Envelope, operation: String, requestID: String, session: Session) async -> BuiltEntity {
        switch operation {
        case "hello":
            // §4.5 negotiation: a hello advertising hash_formats / key_types with no
            // overlap with our accept-set MUST be rejected up front (NEGOTIATE-*-1 b).
            if let p = params(root) {
                if let fmts = p.arrayAt("hash_formats")?.compactMap({ $0.textValue }),
                   !fmts.contains("ecfv1-sha256") {
                    return (try? errorResponse(requestID: requestID, status: 400, code: "incompatible_hash_format")) ?? fallbackError()
                }
                if let kts = p.arrayAt("key_types")?.compactMap({ $0.textValue }),
                   !kts.contains("ed25519") {
                    return (try? errorResponse(requestID: requestID, status: 400, code: "unsupported_key_type")) ?? fallbackError()
                }
            }
            // §4.2 ordering: hello establishes the connection's claimed identity.
            session.helloReceived = true
            // Issue a fresh ≥32-byte nonce (§4.6 hardening) — single-use per conn.
            var nonce = [UInt8](repeating: 0, count: 32)
            for i in 0..<32 { nonce[i] = UInt8.random(in: 0...255) }
            session.issuedNonce = nonce
            session.remotePeerID = params(root)?.textAt("peer_id")
            // §4.4/§4.5 hello response: carry our hello data + the negotiation
            // accept-sets (hash_formats / key_types MUST be non-empty — the
            // NEGOTIATE-*-1 a advertisement gate).
            let hello = (try? Model.make(type: "system/protocol/connect/hello", fields: [
                ("peer_id", .text(localPeerID)),
                ("nonce", .bytes(nonce)),
                ("protocols", .array([.text("entity-core/1.0")])),
                ("hash_formats", .array([.text("ecfv1-sha256")])),
                ("key_types", .array([.text("ed25519")])),
                ("timestamp", .uint(nowMillis())),
            ]))
            guard let hello else { return fallbackError() }
            return (try? okResponse(requestID: requestID, result: hello)) ?? fallbackError()

        case "authenticate":
            guard session.helloReceived else {
                // FM-1 (§4.2, §4.7 row 6, 0.8.2.1): a pre-hello authenticate is a
                // captured authenticate replayed onto a fresh connection — an
                // authentication failure, not a malformed request.
                return (try? errorResponse(requestID: requestID, status: 401, code: "invalid_nonce")) ?? fallbackError()
            }
            guard let p = params(root) else {
                return (try? errorResponse(requestID: requestID, status: 401, code: "authentication_failed")) ?? fallbackError()
            }
            // Reconstruct the authenticate entity from params; compute its hash.
            guard let peerIDClaim = p.textAt("peer_id"), let pubkey = p.bytesAt("public_key"),
                  let keyType = p.textAt("key_type"), let nonce = p.bytesAt("nonce") else {
                return (try? errorResponse(requestID: requestID, status: 401, code: "authentication_failed")) ?? fallbackError()
            }
            // §4.4 / v7.66 surface-6 / AGILITY-UNKNOWN-1: reject an unsupported
            // key_type at authenticate with 400 unsupported_key_type (the core floor
            // is ed25519 only; Ed448 is the deferred agility higher bar, A-SW-001).
            // The unsupported code can ride in THREE places: the key_type field, a
            // non-32-byte public_key, OR the claimed peer_id's leading key_type byte
            // (the 0xfd case — the field still reads "ed25519"). Reject all three —
            // BEFORE the 401 identity-mismatch path.
            let peerIDKeyType = (try? PeerID.parse(peerIDClaim).keyType)
            if keyType != "ed25519" || pubkey.count != 32 || (peerIDKeyType != nil && peerIDKeyType != 0x01) {
                return (try? errorResponse(requestID: requestID, status: 400, code: "unsupported_key_type")) ?? fallbackError()
            }
            // Step 1: nonce-echo.
            guard let issued = session.issuedNonce, issued.elementsEqual(nonce) else {
                return (try? errorResponse(requestID: requestID, status: 401, code: "invalid_nonce")) ?? fallbackError()
            }
            // Recompute authenticate entity hash (§4.6 hardening — don't trust wire hash).
            guard let authEntity = try? Model.make(type: "system/protocol/connect/authenticate", fields: [
                ("peer_id", .text(peerIDClaim)), ("public_key", .bytes(pubkey)),
                ("key_type", .text(keyType)), ("nonce", .bytes(nonce)),
            ]) else { return fallbackError() }
            // Step 2: proof-of-possession — find signature over the authenticate hash.
            guard let sig = Wire.findSignature(target: authEntity.hash, in: env.included) else {
                return (try? errorResponse(requestID: requestID, status: 401, code: "authentication_failed")) ?? fallbackError()
            }
            guard let sigBytes = sig.data.bytesAt("signature"),
                  Signing.verify(publicKey: pubkey, message: authEntity.hash, signature: sigBytes) else {
                return (try? errorResponse(requestID: requestID, status: 401, code: "authentication_failed")) ?? fallbackError()
            }
            // Step 3: identity binding — peer_id derived from public_key.
            guard let derived = try? PeerID.fromEd25519(publicKey: pubkey).format(), derived == peerIDClaim else {
                return (try? errorResponse(requestID: requestID, status: 401, code: "identity_mismatch")) ?? fallbackError()
            }
            // Build the remote's system/peer entity; its hash is the identity hash.
            guard let remotePeer = try? Model.make(type: "system/peer", fields: [
                ("public_key", .bytes(pubkey)), ("key_type", .text(keyType)),
            ]) else { return fallbackError() }
            session.remoteIdentityHash = remotePeer.hash
            session.remotePeerID = peerIDClaim
            session.remotePeerEntity = remotePeer.entity
            session.established = true
            await store.putEntity(remotePeer.entity)
            await store.bind(path: "/" + peerIDClaim + "/system/peer/" + Hex.encode(remotePeer.hash), remotePeer.entity)

            // §4.4 / §6.9a.2: mint the initial capability from the seed policy
            // (UNION discovery floor + matched policy entry per v7.62 §8).
            return await mintAuthenticateGrant(requestID: requestID, remoteIdentityHash: remotePeer.hash, remotePeerID: peerIDClaim)

        default:
            return (try? errorResponse(requestID: requestID, status: 501, code: "unsupported_operation")) ?? fallbackError()
        }
    }

    /// §4.4 authenticate response: a system/capability/grant whose token + granter
    /// peer + signature ride in `included`. The grant scope = discovery floor ∪
    /// matched seed-policy entry (v7.62 §8 union / §6.9a.2).
    func mintAuthenticateGrant(requestID: String, remoteIdentityHash: [UInt8], remotePeerID: String) async -> BuiltEntity {
        let hex = Hex.encode(remoteIdentityHash)
        let matched = seedPolicy.grantsFor(identityHashHex: hex, peerIDBase58: remotePeerID)
        // UNION discovery floor with the matched policy grants.
        let floor = SeedPolicy.discoveryFloor
        let unioned = floor + matched
        let grantValues = unioned.map { $0.toValue() }
        // Mint a token granted TO the remote identity, rooted at our authority.
        guard let token = try? Model.make(type: "system/capability/token", data: .textMap([
            ("grants", .array(grantValues)),
            ("granter", .bytes(identity.identityHash)),
            ("grantee", .bytes(remoteIdentityHash)),
            ("created_at", .uint(nowMillis())),
        ])) else { return fallbackError() }
        guard let tokenSig = try? identity.signatureEntity(target: token.hash) else { return fallbackError() }
        guard let grant = try? Model.make(type: "system/capability/grant", fields: [("token", .bytes(token.hash))]) else {
            return fallbackError()
        }
        // included: token, granter identity (our peer entity), signature.
        guard let resp = try? Wire.buildResponse(requestID: requestID, status: 200, result: grant) else { return fallbackError() }
        // Carry the token/peer/sig in the response envelope's included — the
        // transport encodes via encodeResponseEnvelope below.
        pendingIncluded = [token, identity.peerEntity, tokenSig]
        return resp
    }

    // MARK: - Tree handler (§6.3)

    func treeHandler(operation: String, requestID: String, ctx: HandlerContext) async throws -> BuiltEntity {
        switch operation {
        case "get":
            // §6.3: empty resource → list the local peer root.
            guard let target = ctx.resourceTarget?.targets.first else {
                return try await buildListing(requestID: requestID, path: "/" + localPeerID + "/")
            }
            // §1.4 / CORE-TREE-PATH-FLEX-1: reject malformed caller paths.
            guard pathFlexOK(target) else {
                return try errorResponse(requestID: requestID, status: 400, code: "invalid_path")
            }
            let canon = Capability.canonicalize(target, frame: localPeerID)
            if target.isEmpty || canon.hasSuffix("/") {
                // listing (§3.9).
                return try await buildListing(requestID: requestID, path: canon)
            }
            guard let entity = await store.getAt(path: canon) else {
                return try errorResponse(requestID: requestID, status: 404, code: "not_found")
            }
            // §6.3 mode=hash → return the bare system/hash, not the entity.
            if params(ctx.execute)?.textAt("mode") == "hash", let h = entity.contentHash {
                let hashEntity = try Model.make(type: "system/hash", data: .bytes(h))
                return try okResponse(requestID: requestID, result: hashEntity)
            }
            let result = BuiltEntity(entity: entity, hash: entity.contentHash ?? [], bytes: (try? entity.encode()) ?? [])
            return try okResponse(requestID: requestID, result: result)

        case "put":
            guard let target = ctx.resourceTarget?.targets.first else {
                return try errorResponse(requestID: requestID, status: 400, code: "ambiguous_resource")
            }
            guard pathFlexOK(target) else {
                return try errorResponse(requestID: requestID, status: 400, code: "invalid_path")
            }
            let canon = Capability.canonicalize(target, frame: localPeerID)
            // params is a system/tree/put-request: the entity to bind lives at
            // params.data.entity (§6.3); expected_hash drives §3.9 CAS.
            guard let p = params(ctx.execute) else {
                return try errorResponse(requestID: requestID, status: 400, code: "bad_request")
            }
            guard let rawEntity = p.mapValue("entity") else {
                return try errorResponse(requestID: requestID, status: 400, code: "bad_request")
            }
            let entity: Entity
            switch admitPut(rawEntity) {
            case let .refused(code, message):
                return try errorResponse(requestID: requestID, status: 400, code: code, message: message)
            case let .admitted(e):
                entity = e
            }
            // §3.9 CAS: expected_hash present → must match current binding (zero =
            // create-only). Mismatch → 409 conflict.
            if let expected = p.bytesAt("expected_hash") {
                let current = await store.hashAt(path: canon)
                let isZero = expected.allSatisfy { $0 == 0 }
                if isZero {
                    if current != nil {
                        return try errorResponse(requestID: requestID, status: 409, code: "cas_mismatch")
                    }
                } else if !(current?.elementsEqual(expected) ?? false) {
                    return try errorResponse(requestID: requestID, status: 409, code: "cas_mismatch")
                }
            }
            await store.bind(path: canon, entity)
            // §6.3 put result: the bound entity's hash.
            let result = try Model.make(type: "system/hash", data: .bytes(entity.contentHash ?? []))
            return try okResponse(requestID: requestID, result: result)

        default:
            return try errorResponse(requestID: requestID, status: 501, code: "unsupported_operation")
        }
    }

    /// Build a `system/tree/listing` (§3.9) over `path` (ending in "/"): entries
    /// keyed by child segment as a map of `system/tree/listing-entry`, with the
    /// `count`/`offset`/`path` carriers. Deletion-marker-bound leaves are omitted
    /// (§6.3 / CORE-TREE-DELETE-1).
    func buildListing(requestID: String, path: String) async throws -> BuiltEntity {
        let raw = await store.listing(prefix: path)
        var entryPairs: [(key: CBORValue, value: CBORValue)] = []
        var count: UInt64 = 0
        for e in raw {
            // omit a leaf bound to a deletion marker.
            if !e.hasChildren, let h = e.hash, let bound = await store.getByHash(h),
               bound.type == "system/deletion-marker" { continue }
            var fields: [(String, CBORValue)] = [("has_children", .bool(e.hasChildren))]
            if let h = e.hash { fields.append(("hash", .bytes(h))) }
            entryPairs.append((.text(e.segment), .textMap(fields)))
            count += 1
        }
        let listing = try Model.make(type: "system/tree/listing", data: .textMap([
            ("path", .text(path)),
            ("entries", .map(entryPairs)),
            ("count", .uint(count)),
            ("offset", .uint(0)),
        ]))
        return try okResponse(requestID: requestID, result: listing)
    }

    /// §1.4 / §5.4 / CORE-TREE-PATH-FLEX-1: validate a caller-supplied resource
    /// target before canonicalize. Reject null byte, a leading slash whose first
    /// segment is not a peer_id, and `.`/`..`/interior-empty (`//`) segments. A
    /// single trailing "/" is the listing marker (allowed).
    func pathFlexOK(_ target: String) -> Bool {
        if target.utf8.contains(0) { return false }
        var segs = target.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        if target.hasPrefix("/") {
            // segs[0] == "" (leading slash); segs[1] must be a peer_id.
            guard segs.count >= 2, Capability.isPeerID(segs[1]) else { return false }
            segs = Array(segs.dropFirst(2))
        }
        // A single trailing "/" leaves a trailing empty segment — drop it.
        if segs.last == "" { segs.removeLast() }
        for s in segs where s.isEmpty || s == "." || s == ".." { return false }
        return true
    }

    /// Decode a `core/entity` materialized `{type, data, content_hash?}` map into
    /// an `Entity`, recomputing the content_hash (§7.1; do not trust the wire hash).
    /// The outcome of §6.3's `put` admission ladder — an admitted entity, or the
    /// 400-row the submission fell on.
    enum PutAdmission {
        case admitted(Entity)
        case refused(code: String, message: String)
    }

    /// Digest byte length for a `content_hash_format` code per the §1.2 seed
    /// table, or nil when this peer cannot VERIFY that code. The total wire
    /// length is this plus the varint prefix, which is not a constant of the
    /// code (§7.3): codes ≥ 0x80 occupy more than one byte.
    func hashDigestLen(_ formatCode: UInt64) -> Int? {
        switch formatCode {
        case 0x00: return 32
        case 0x01: return 48
        case 0x02: return 64
        default: return nil
        }
    }

    /// §6.3's `put` admission ladder (normative, 0.8.2.11).
    ///
    /// `put` is a RECEIPT path: the submitter authors the entity, the peer
    /// validates what it received (§1.8 item 1) and MUST NOT author a submitted
    /// entity's `content_hash` on the submitter's behalf. Two ordered steps:
    ///
    /// 1. STRUCTURE — a map carrying a non-empty text `type`, a PRESENT `data`
    ///    (any CBOR value; null is a legal payload), and a `content_hash` that is
    ///    a well-formed `system/hash` whose total byte length matches its format
    ///    code (§1.2). Any failure → 400 `invalid_request`. A well-formed hash
    ///    naming a format code this peer cannot verify is the separate §1.2
    ///    ingest-dispatch case → 400 `unsupported_content_hash_format`.
    /// 2. HASH — carried `content_hash` vs `content_hash({type, data})`.
    ///    Disagreement → 400 `hash_mismatch`.
    ///
    /// Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step
    /// 2's inputs are exactly what step 1 establishes, so a submission that is
    /// both malformed and mis-hashed is step 1's and answers `invalid_request`.
    ///
    /// Structural admission is not semantic validation: `data` is never checked
    /// against the type named by `type`.
    func admitPut(_ v: CBORValue) -> PutAdmission {
        guard case .map = v else {
            return .refused(code: "invalid_request", message: "put: entity is not a map")
        }
        guard let type = v.mapValue("type")?.textValue, !type.isEmpty else {
            return .refused(code: "invalid_request",
                            message: "put: entity.type absent, empty or not a text string")
        }
        guard let data = v.mapValue("data") else {
            return .refused(code: "invalid_request", message: "put: entity.data absent")
        }
        guard let carried = v.mapValue("content_hash")?.bytesValue, !carried.isEmpty else {
            return .refused(code: "invalid_request",
                            message: "put: entity.content_hash absent or not a byte string")
        }
        guard let (formatCode, next) = try? Varint.decode(carried, at: 0) else {
            return .refused(code: "invalid_request",
                            message: "put: entity.content_hash is not a well-formed system/hash")
        }
        guard let digestLen = hashDigestLen(formatCode) else {
            // §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it.
            // NOT invalid_request: the shape is fine, the algorithm is what we lack.
            return .refused(code: "unsupported_content_hash_format",
                            message: "put: unsupported content_hash_format")
        }
        guard carried.count == next + digestLen else {
            return .refused(code: "invalid_request",
                            message: "put: content_hash length does not match its format code")
        }
        guard let computed = try? ContentHash.contentHash(formatCode: formatCode, type: type, data: data),
              computed.elementsEqual(carried) else {
            return .refused(code: "hash_mismatch",
                            message: "put: content_hash does not match content_hash({type, data})")
        }
        // The carried hash IS the entity's address; recomputing it into the store
        // would be the authoring arm §6.3 forbids.
        return .admitted(Entity(type: type, data: data, contentHash: carried))
    }

    func decodeEntity(_ v: CBORValue?) -> Entity? {
        guard let v, let type = v.textAt("type") else { return nil }
        let data = v.mapValue("data") ?? .map([])
        let hash = try? ContentHash.contentHash(type: type, data: data)
        return Entity(type: type, data: data, contentHash: hash)
    }

    // MARK: - Type handler (§6.2)

    func typeHandler(operation: String, requestID: String, ctx: HandlerContext) async throws -> BuiltEntity {
        switch operation {
        case "validate":
            // Minimal core: accept (the full §7.6 validation is REFERENCE; S4 land).
            let ok = try Model.make(type: "system/type/validate-result", fields: [("valid", .bool(true))])
            return try okResponse(requestID: requestID, result: ok)
        default:
            return try errorResponse(requestID: requestID, status: 501, code: "unsupported_operation")
        }
    }

    // MARK: - small helpers

    /// Extract the params entity's data map from an EXECUTE (params is a
    /// materialized `{type, data, content_hash}` entity per §3.4).
    func params(_ execute: Entity) -> CBORValue? {
        execute.data.mapValue("params")?.mapValue("data")
    }
    func paramsType(_ execute: Entity) -> String? {
        execute.data.mapValue("params")?.textAt("type")
    }
}
