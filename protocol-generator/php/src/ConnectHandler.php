<?php

declare(strict_types=1);

namespace EntityCore;

/** §4.1 / §4.6 — the connect handler (hello / authenticate). */
final class ConnectHandler implements Handler
{
    public function __construct(private readonly Peer $peer)
    {
    }

    public function handle(string $operation, HandlerContext $ctx): Outcome
    {
        return match ($operation) {
            'hello' => $this->hello($ctx),
            'authenticate' => $this->authenticate($ctx),
            // §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
            // 400 invalid_request, not the 501 every other handler answers. The table
            // separates a STATE conflict from an UNKNOWN operation because they select
            // different remedies — "an unknown connect operation is not out of order at
            // all; it exists in no state", so connection_sequence_error would point the
            // caller at its ORDERING when the defect is its OPERATION NAME. Row 10 is
            // scoped "in any state", so this arm covers pre-handshake AND established;
            // the genuine sequence cases are refused in hello()/authenticate(), 409.
            //
            // SCOPED TO THIS HANDLER DELIBERATELY. The generic registered-handler rule
            // (§3.3's 501 row, §6.2) is a different contract and is separately gated;
            // moving the shared 501 would trade one green check for another.
            default => Outcome::err(400, 'invalid_request', 'connect: unknown operation ' . $operation),
        };
    }

    /** @return list<string>|null */
    private function strArray(Entity $exec, string $key): ?array
    {
        $p = $exec->entityField('params');
        return $p === null ? null : Ecf::textList($p->data(), $key);
    }

    private function hello(HandlerContext $ctx): Outcome
    {
        $conn = $ctx->conn;
        $exec = $ctx->exec;
        if ($conn->established) {
            return Outcome::err(409, 'connection_already_established');
        }
        // §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a
        // HALF-OPEN connection (hello done, authenticate not yet) is an operation we
        // implement arriving in a state that forbids it — the same class as
        // connection_already_established above, taking the same 409. A half-open
        // connection is NOT established, so the guard above cannot reach it; §4.7
        // names this gap explicitly because two adjacent rules each look like they
        // cover it and neither does.
        if ($conn->issuedNonce !== null) {
            return Outcome::err(409, 'connection_sequence_error');
        }
        // §4.5 negotiation: reject disjoint hash_formats / key_types up front.
        $hf = $this->strArray($exec, 'hash_formats');
        $kt = $this->strArray($exec, 'key_types');
        if ($hf !== null && !\in_array('ecfv1-sha256', $hf, true)) {
            return Outcome::err(400, 'incompatible_hash_format');
        }
        if ($kt !== null && !\in_array('ed25519', $kt, true)) {
            return Outcome::err(400, 'unsupported_key_type');
        }
        $params = $exec->entityField('params');
        $helloPid = $params?->text('peer_id');
        // §4.5 mutual verifiability, the direction that is NOT the array. `key_types`
        // is an ACCEPT-SET; the initiator's OWN key_type is not in it — it rides in
        // its `peer_id` — so a hello may advertise a perfectly good accept-set and
        // still name an identity we cannot verify. Checking only the array leaves
        // that MUST unenforced at hello, which is where §4.5 wants it; authenticate
        // catches it one leg later, which is conformant but non-canonical.
        //
        // An UNPARSEABLE peer_id is deliberately left alone: that is a malformed
        // field, not a key_type we lack, and authenticate already refuses it.
        if ($helloPid !== null) {
            try {
                [$helloKeyType] = PeerId::parse($helloPid);
                if ($helloKeyType !== KeyType::Ed25519->value) {
                    return Outcome::err(400, 'unsupported_key_type');
                }
            } catch (\Throwable) {
                // unparseable peer_id → not our question; authenticate refuses it
            }
        }
        // §4.5 `protocols` — the one negotiated field Required with NO default, so
        // there is no floor to fall back to, and its two failure modes carry
        // different codes on purpose (§4.5 table row / §4.7 row 1):
        //
        //   absent or empty     -> 400 invalid_request       (a malformed hello)
        //   non-empty, disjoint -> 400 incompatible_protocol (we compared)
        //
        // "a caller that named no version cannot be told the comparison failed" —
        // the remedies differ (send the field vs change the version) and §4.7 exists
        // so the code selects the remedy. The vocabulary is §8.4's protocol version
        // identifiers, today the single entity-core/1.0.
        //
        // ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. §4.5 states no
        // precedence between the three, so a hello disjoint in more than one
        // dimension may be refused on any of them — but the choice is OBSERVABLE,
        // and the reference peer refuses key_types first. Checking protocols first
        // is equally spec-legal and makes AGILITY-UNKNOWN-1 answer
        // incompatible_protocol, because that probe's own hello carries protocols
        // ["entity-core/v7"] — a spec-line name, not a §8.4 identifier (F56).
        $protos = $this->strArray($exec, 'protocols');
        if ($protos === null || $protos === []) {
            return Outcome::err(400, 'invalid_request', 'hello: protocols absent or empty');
        }
        if (!\in_array('entity-core/1.0', $protos, true)) {
            return Outcome::err(400, 'incompatible_protocol');
        }
        $conn->helloPeerId = $helloPid;
        $nonce = $this->peer->randomBytes(32);
        $conn->issuedNonce = $nonce;
        return Outcome::ok(Entity::make('system/protocol/connect/hello', Ecf::map(
            'peer_id', $this->peer->localPeer,
            'nonce', new ByteString($nonce),
            'protocols', ['entity-core/1.0'],
            'timestamp', Capability::nowMs(),
            'hash_formats', ['ecfv1-sha256'],
            'key_types', ['ed25519'],
        )));
    }

    private function authenticate(HandlerContext $ctx): Outcome
    {
        $conn = $ctx->conn;
        $exec = $ctx->exec;
        if ($conn->established) {
            // RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
            // single-use nonce — pinned to 401 invalid_nonce, not a 409 state-conflict
            // which under-signals the replay.
            return Outcome::err(401, 'invalid_nonce');
        }
        $issuedNonce = $conn->issuedNonce;
        if ($issuedNonce === null) {
            return Outcome::err(401, 'invalid_nonce'); // before hello
        }
        $auth = $exec->entityField('params');
        if ($auth === null) {
            return Outcome::err(401, 'authentication_failed');
        }
        // §4.6 hardening: reject unsupported key_type / non-32-byte pubkey / non-ed25519 peer_id.
        $badKt = false;
        $ktField = $auth->text('key_type');
        if ($ktField !== null && $ktField !== 'ed25519') {
            $badKt = true;
        }
        $pub = $auth->bytes('public_key');
        if (!$badKt && $pub !== null && \strlen($pub) !== 32) {
            $badKt = true;
        }
        $claimed = $auth->text('peer_id');
        if (!$badKt && $claimed !== null) {
            try {
                [$keyType] = PeerId::parse($claimed);
                if ($keyType !== KeyType::Ed25519->value) {
                    $badKt = true;
                }
            } catch (\Throwable) {
                // unparseable peer_id → fall through to the step checks below
            }
        }
        if ($badKt) {
            return Outcome::err(400, 'unsupported_key_type');
        }
        // step 1: nonce-echo
        $echoed = $auth->bytes('nonce');
        if (!($echoed !== null && \hash_equals($issuedNonce, $echoed))) {
            return Outcome::err(401, 'invalid_nonce');
        }
        if ($pub === null) {
            return Outcome::err(401, 'authentication_failed');
        }
        // step 2: proof of possession
        $sgn = Capability::findSignature($auth->hash(), $ctx->included);
        $sigOk = false;
        if ($sgn !== null) {
            $sb = $sgn->bytes('signature');
            if ($sb !== null && \strlen($sb) === 64) {
                $sigOk = Signature::verifyRaw($pub, $auth->hash(), $sb);
            }
        }
        if (!$sigOk) {
            return Outcome::err(401, 'authentication_failed');
        }
        // step 3: identity binding
        if ($claimed !== Identity::peerIdOfPublicKey($pub)) {
            return Outcome::err(401, 'identity_mismatch');
        }
        if ($conn->helloPeerId !== null && $conn->helloPeerId !== $claimed) {
            return Outcome::err(401, 'identity_mismatch');
        }
        // success: mint the initial capability for the remote (§4.4 / §6.9a)
        $remotePeer = Identity::peerEntityOfPublicKey($pub);
        $grants = $this->peer->deriveSeedGrants($remotePeer, $claimed);
        $m = $this->peer->mintToken($remotePeer->hash(), $grants, null);
        $conn->established = true;
        return Outcome::ok(
            Entity::make('system/capability/grant', Ecf::map('token', new ByteString($m['token']->hash()))),
            $this->peer->capIncluded($m),
        );
    }
}
