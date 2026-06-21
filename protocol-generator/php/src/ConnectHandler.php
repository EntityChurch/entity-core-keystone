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
            default => Outcome::err(501, 'unsupported_operation', $operation),
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
        $conn->helloPeerId = $params?->text('peer_id');
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
            return Outcome::err(409, 'connection_already_established');
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
