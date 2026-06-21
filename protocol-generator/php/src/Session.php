<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * A dialed, authenticated session (§4.4): the {@see Io}, the minted cap + granter
 * + signature, and the §4.1 forward handshake driver. {@see send} originates a
 * request and pumps the loop until the correlated EXECUTE_RESPONSE arrives (§6.11
 * request_id demux).
 */
final class Session
{
    private int $reqCounter = 0;
    public ?string $remotePeerId = null;
    public ?Entity $capability = null;
    /** The remote peer identity that granted the session cap (the §4.4 granter). */
    public ?Entity $granterPeer = null;
    /** The signature over the session cap (travels with it in `included`). */
    public ?Entity $capSignature = null;

    public function __construct(
        private readonly EventLoop $loop,
        private readonly Io $io,
        private readonly Identity $local,
    ) {
    }

    public function nextRequestId(): string
    {
        return 'req-' . (++$this->reqCounter);
    }

    /** Send a request envelope and await its correlated EXECUTE_RESPONSE. */
    public function send(Envelope $request): ?Envelope
    {
        return $this->io->outbound($this->loop, $request);
    }

    /**
     * Build, sign, and send an authenticated EXECUTE; await the response. The full
     * §5.8 authority chain travels in `included`.
     */
    public function execute(string $uri, string $operation, Entity $params, ?EcfMap $resource = null): ?Envelope
    {
        $cap = $this->capability;
        $exec = Wire::makeExecute($this->nextRequestId(), $uri, $operation, $params,
            $this->local->identityHash(), $cap->hash(), $resource);
        $execSig = $this->local->sign($exec);
        $inc = [
            Envelope::inc($cap),
            Envelope::inc($this->granterPeer),
            Envelope::inc($this->local->peerEntity),
            Envelope::inc($this->capSignature),
            Envelope::inc($execSig),
        ];
        return $this->send(new Envelope($exec, $inc));
    }

    /**
     * Build + sign + send an authenticated EXECUTE WITHOUT awaiting it; return the
     * request_id. Lets the caller put many requests in flight on the one
     * connection, then {@see awaitAll} for the §6.11 out-of-order demux check.
     */
    public function executeAsync(string $uri, string $operation, Entity $params, ?EcfMap $resource = null): string
    {
        $rid = $this->nextRequestId();
        $exec = Wire::makeExecute($rid, $uri, $operation, $params,
            $this->local->identityHash(), $this->capability->hash(), $resource);
        $execSig = $this->local->sign($exec);
        $inc = [
            Envelope::inc($this->capability),
            Envelope::inc($this->granterPeer),
            Envelope::inc($this->local->peerEntity),
            Envelope::inc($this->capSignature),
            Envelope::inc($execSig),
        ];
        $this->io->sendAsync(new Envelope($exec, $inc));
        return $rid;
    }

    /**
     * Pump the loop until every request_id in $rids resolves, then return them as
     * a request_id → response-envelope map (the §6.11 request_id demux of
     * out-of-order replies; N7).
     *
     * @param list<string> $rids
     * @return array<string,?Envelope>
     */
    public function awaitAll(array $rids, int $timeoutMs = 30000): array
    {
        $this->loop->runUntil(function () use ($rids): bool {
            foreach ($rids as $rid) {
                if (!$this->io->isResolved($rid)) {
                    return false;
                }
            }
            return true;
        }, $timeoutMs);
        $out = [];
        foreach ($rids as $rid) {
            $out[$rid] = $this->io->take($rid);
        }
        return $out;
    }

    public function close(): void
    {
        $this->io->close();
    }

    /** Drive the §4.1 forward handshake as initiator: hello then authenticate. */
    public function handshake(): void
    {
        // ── hello ──
        $hello = Entity::make('system/protocol/connect/hello', Ecf::map(
            'peer_id', $this->local->peerId,
            'nonce', new ByteString(\random_bytes(32)),
            'protocols', ['entity-core/1.0'],
            'timestamp', Capability::nowMs(),
            'hash_formats', ['ecfv1-sha256'],
            'key_types', ['ed25519'],
        ));
        $r1 = $this->send(new Envelope(
            Wire::makeExecute($this->nextRequestId(), 'system/protocol/connect', 'hello', $hello)));
        $this->requireOk($r1, 'hello');
        $remoteHello = Wire::responseResult($r1);
        $this->remotePeerId = $remoteHello?->text('peer_id');
        $remoteNonce = $remoteHello?->bytes('nonce');
        if ($remoteNonce === null) {
            throw new TransportException('hello: missing remote nonce');
        }

        // ── authenticate ──
        $auth = Entity::make('system/protocol/connect/authenticate', Ecf::map(
            'peer_id', $this->local->peerId,
            'public_key', new ByteString($this->local->publicKey()),
            'key_type', 'ed25519',
            'nonce', new ByteString($remoteNonce),
        ));
        $authSig = $this->local->sign($auth);
        $authInc = [
            Envelope::inc($this->local->peerEntity),
            Envelope::inc($authSig),
        ];
        $r2 = $this->send(new Envelope(
            Wire::makeExecute($this->nextRequestId(), 'system/protocol/connect', 'authenticate', $auth), $authInc));
        $this->requireOk($r2, 'authenticate');

        // parse the §4.4 initial capability grant
        $grant = Wire::responseResult($r2);
        $tokenH = $grant?->bytes('token');
        $token = $tokenH !== null ? $r2->includedGet($tokenH) : null;
        if ($token === null) {
            throw new TransportException('authenticate grant omits the capability token');
        }
        $granterH = $token->bytes('granter');
        $granterPeer = $granterH !== null ? $r2->includedGet($granterH) : null;
        if ($granterPeer === null) {
            throw new TransportException('authenticate grant omits the granter identity');
        }
        $capSig = Capability::findSignature($token->hash(), $r2->included);
        if ($capSig === null) {
            throw new TransportException('authenticate grant omits the capability signature');
        }
        $this->capability = $token;
        $this->granterPeer = $granterPeer;
        $this->capSignature = $capSig;
    }

    private function requireOk(?Envelope $env, string $step): void
    {
        if ($env === null) {
            throw new TransportException("{$step} failed: no response");
        }
        $status = Wire::responseStatus($env);
        if ($status !== 200) {
            $r = Wire::responseResult($env);
            $code = $r?->text('code');
            $msg = $r?->text('message');
            throw new TransportException("{$step} failed: {$status} {$code} {$msg}");
        }
    }
}
