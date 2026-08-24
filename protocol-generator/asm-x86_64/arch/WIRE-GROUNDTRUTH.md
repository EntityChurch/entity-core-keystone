# Wire ground-truth — decoded captures from the reference entity-peer

Captured with `tools/teeproxy.c` + `tools/capture.sh` (throwaway dev aids) tee-ing
`validate-peer` ↔ the reference `entity-peer`. These are the EXACT bytes on the wire —
the authority for the asm parser/builder. Frame = `[4-byte BE len][canonical-CBOR]`.

CBOR is canonical: **map keys ordered by (length, then bytewise)**. Every entity on the
wire is a 3-key map `{ "data": <value>, "type": <text>, "content_hash": <bytes 33> }`
(keys: data=4, type=4, content_hash=12 → that order). `content_hash` =
`varint(0x00) ‖ sha256(ECF(type, data))` = 33 bytes, prefix byte `0x00`, recomputed by
the validator (§1.8) — so our emitted maps MUST be canonical and the hashes real
(`ec_content_hash`).

## Hello REQUEST (client → peer), len 451
```
a1                                       map(1)
 64 "root"                               "root" →
  a3                                     entity map(3)  [data, type, content_hash]
   64 "data"  a4                         EXECUTE data map(4)  [uri, params, operation, request_id]
     63 "uri"        77 "system/protocol/connect"
     66 "params"     a3                  params entity {data,type,content_hash}
        64 "data" a6                     [nonce, peer_id, key_types, protocols, timestamp, hash_formats]
          65 "nonce"        58 20 <32 bytes>
          67 "peer_id"      78 2e <46-char base58>          (client's peer_id)
          69 "key_types"    82 67"ed25519" 65"ed448"
          69 "protocols"    81 6f"entity-core/1.0"
          69 "timestamp"    1b <uint64 ms>
          6c "hash_formats" 81 6c"ecfv1-sha256"
        64 "type"          78 1d "system/protocol/connect/hello"
        6c "content_hash"  58 21 00 <32>
     69 "operation"  65 "hello"
     6a "request_id" 6d "connect-hello"
   64 "type"          77 "system/protocol/execute"
   6c "content_hash"  58 21 00 <32>
```

## Hello RESPONSE (peer → client), len 426  — what the asm peer must BUILD
```
a1 "root"
  a3                                     entity {data, type, content_hash}
   64 "data" a3                          response data(3)  [result, status, request_id]
     66 "result"  a3                     result entity {data,type,content_hash}
        64 "data" a6                     [nonce, peer_id, key_types, protocols, timestamp, hash_formats]
          65 "nonce"        58 20 <32 bytes, fresh CSPRNG>
          67 "peer_id"      78 2e <THIS peer's 46-char base58>
          69 "key_types"    82 67"ed25519" 65"ed448"
          69 "protocols"    81 6f"entity-core/1.0"
          69 "timestamp"    1b <uint64 ms>
          6c "hash_formats" 81 6c"ecfv1-sha256"
        64 "type"          78 1d "system/protocol/connect/hello"
        6c "content_hash"  58 21 00 <32>   = ec_content_hash("system/protocol/connect/hello", data-a6)
     66 "status"     18 c8                 uint 200
     6a "request_id" 6d "connect-hello"    (echo of the request's request_id)
   64 "type"         78 20 "system/protocol/execute/response"
   6c "content_hash" 58 21 00 <32>         = ec_content_hash("system/protocol/execute/response", data-a3)
```
No `included` key (map(1), root only) for hello.

## Authenticate REQUEST (client → peer), len 905
Envelope `a2` = `{root, included}`. root EXECUTE data(4) = [uri="system/protocol/connect",
params, operation="authenticate", request_id]. params entity data(4) =
[nonce(32, echo), peer_id, key_type="ed25519", public_key(32)]. `included` (a2) carries:
a `system/signature` entity {data:{signer(33), target(33), algorithm:"ed25519",
signature(64)}, ...} and the client's `system/peer` entity {data:{key_type, public_key(32)}}.

## Authenticate RESPONSE (peer → client), len 1170
root response data(3) = [result, status=200, request_id]. result =
`system/capability/grant` {data:{token(33)}}. `included` (a3) carries: the peer's
`system/signature` over the token, the peer's `system/peer`, and the
`system/capability/token` entity {data:{grants:[...2 discovery grants...], grantee(33 =
client identity_hash), granter(33 = peer identity_hash), created_at(uint ms)}}.

The two default grants minted (from `-verbose`):
- `handlers=[system/tree] resources=[system/type/* system/handler/*] operations=[get]`
- `handlers=[system/capability] resources=[] operations=[request]`

## Signed-message format (EMPIRICALLY CONFIRMED — `tools/sigprobe.c`)

An entity signature signs the target entity's **33-byte content_hash** (`0x00` prefix +
32-byte SHA-256 digest), NOT the bare 32-byte digest and NOT the ECF bytes. Proven:
`ec_ed25519_verify(client_pubkey, content_hash_33, sig)` returns `0` on a captured
authenticate PoP signature; the 32-byte-digest variant returns `-6`
(EC_SIGNATURE_INVALID). So:
- **verify** a PoP: `ec_ed25519_verify(signer_pubkey, target_content_hash[33], 33, sig[64])`.
- **sign** the minted token: `ec_ed25519_sign(seed[32], token_content_hash[33], 33, out_sig[64])`.

`identity_hash` (used as author/signer/granter/grantee bytes) = the 33-byte content_hash
of the `system/peer` entity `{type:"system/peer", data:{key_type:"ed25519",
public_key:<32>}}` (keys canonical: key_type(8), public_key(10)).

## Notes for the builder
- `ec_content_hash(type_ptr, type_len, data_cbor_ptr, data_cbor_len, out33)` — pass the
  canonical CBOR of the `data` value; get the 33-byte `0x00`-prefixed hash back.
- Build inner entities first (compute their content_hash), embed, then hash the parent.
- Fixed-shape maps → emit keys in pre-sorted (length,lex) order; no general sort needed.
- `18 c8` = uint 200; status is a plain uint. `1b ........` = uint64 timestamp ms.
