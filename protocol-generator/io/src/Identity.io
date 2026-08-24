// entity-core-protocol-io — L1 identity (§1.5, §3.5, §7.3). Everything derives
// from a 32-byte Ed25519 seed. peer_id is the §1.5 CANONICAL identity-multihash
// form: Base58(varint(0x01) || varint(0x00) || raw 32-byte pubkey) — the digest
// IS the public key (cohort-settled; never SHA256(pubkey)). Signing is over the
// full 33-byte content_hash (§7.3). Crypto crosses the EntityCodec addon seam.

Identity := Object clone do(
    seed ::= nil          // 32-byte Sequence
    pub ::= nil           // 32-byte Sequence
    peerId ::= nil        // Base58 text Sequence
    peerEntity ::= nil    // system/peer Entity (v7.65: NO peer_id in the basis)
    idHash ::= nil        // content_hash(peerEntity), raw 33-byte Sequence

    ofSeed := method(s,
        if(s size != 32, Exception raise("identity: seed must be 32 bytes"))
        i := self clone
        i setSeed(s)
        i setPub(EntityCodec ed25519SeedToPub(s))
        i setPeerId(Identity peerIdOfPubkey(i pub))
        i setPeerEntity(Identity peerEntityOfPubkey(i pub))
        i setIdHash(i peerEntity hash)
        i
    )

    peerIdOfPubkey := method(pk,
        // §1.5 size-cutoff: <=32B -> identity-multihash (hash_type 0, digest = pubkey)
        if(pk size <= 32,
            EntityCodec peeridFormat(1, 0, pk)
        ,
            EntityCodec peeridFormat(1, 1, EntityCodec sha256(pk))
        )
    )

    peerEntityOfPubkey := method(pk,
        Entity with("system/peer", EcMap with(
            "public_key", EcBytes with(pk),
            "key_type", "ed25519"))
    )

    // sign a target entity's content_hash -> a system/signature Entity (§3.5)
    sign := method(target,
        sig := EntityCodec ed25519Sign(seed, target hash)
        Entity with("system/signature", EcMap with(
            "target", EcBytes with(target hash),
            "signer", EcBytes with(idHash),
            "algorithm", "ed25519",
            "signature", EcBytes with(sig)))
    )

    // verify a system/signature Entity against a signer's system/peer Entity.
    // The §5.2 signer-hash binding is the caller's responsibility.
    verifySignature := method(sigEntity, signerPeer,
        target := sigEntity bytes("target")
        sig := sigEntity bytes("signature")
        pk := signerPeer bytes("public_key")
        if(target == nil or(sig == nil) or(pk == nil), return false)
        if(sig size != 64 or(pk size != 32), return false)
        EntityCodec ed25519Verify(pk, target, sig)
    )

    // load the --name NAME persistent identity: ~/.entity/peers/NAME/keypair
    // (entity-core PEM = base64 of the 32-byte Ed25519 seed)
    ofKeypairFile := method(path,
        f := File with(path)
        if(f exists not, Exception raise("identity: no keypair at " .. path))
        body := Sequence clone
        f contents split("\n") foreach(line,
            if(line beginsWithSeq("-----") not, body appendSeq(line strip))
        )
        seed := EntityCodec base64Decode(body)
        if(seed size != 32, Exception raise("identity: keypair body is not a 32-byte seed"))
        ofSeed(seed)
    )
)
