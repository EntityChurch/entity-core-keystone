<?php

declare(strict_types=1);

namespace EntityCore\Tests;

use EntityCore\Cbor;
use EntityCore\Conn;
use EntityCore\Ecf;
use EntityCore\EcfMap;
use EntityCore\Entity;
use EntityCore\Envelope;
use EntityCore\HashMismatchException;
use EntityCore\NonCanonicalEcfException;
use EntityCore\PayloadTooLargeException;
use EntityCore\Peer;
use EntityCore\ProtocolException;
use EntityCore\TagRejectedException;
use EntityCore\TruncatedFrameException;
use EntityCore\Wire;
use PHPUnit\Framework\TestCase;

/**
 * §4.11 pre-admission refusals (0.8.2.25) — the half a unit CAN pin.
 *
 * §4.11 has two halves that fail differently. "A peer that refuses a frame pre-admission
 * MUST put a coded EXECUTE_RESPONSE on the wire" is a RUNTIME property decided by the
 * stream layer, and only a socket can measure it — that is the wire driver's job. "The
 * frame obligation belongs to the class; the CODE belongs to the cause" is a MAPPING, and
 * it is pinned here, one assertion per cause.
 */
final class PreAdmissionTest extends TestCase
{
    public function testTheCodeBelongsToTheCause(): void
    {
        // §5.2a: "A peer that refuses at the decode boundary MUST answer
        // `400 hash_mismatch` [MUST] ... `400 non_canonical_ecf` is NOT conformant here
        // [MUST]." A mis-keyed `included` entry carries no tag; its encoding is
        // canonical, and what is false is the claim the KEY makes. This peer answered
        // `non_canonical_ecf` for every decode-boundary refusal until 0.8.2.24 — measured
        // on the wire, `arc-probe` B1/B2.
        self::assertSame(
            [400, 'hash_mismatch'],
            \array_slice(Wire::preAdmissionRefusal(new HashMismatchException('x')), 0, 2),
            'a resolution-integrity failure is hash_mismatch',
        );

        // THE TAG ARM KEEPS `non_canonical_ecf`, and that is the differential rather than
        // an exception: `ENTITY-CBOR-ENCODING` defines that code for CBOR tag-policy
        // violations specifically, which §6.3 still MUSTs. If this answered the same code
        // as the arm below, the peer would not be classifying, it would just be refusing.
        self::assertSame(
            [400, 'non_canonical_ecf'],
            \array_slice(Wire::preAdmissionRefusal(new TagRejectedException('x')), 0, 2),
            'a CBOR tag keeps non_canonical_ecf',
        );

        // §4.10(a)'s mood was raised SHOULD -> MUST at 0.8.2.25 (N14).
        self::assertSame(
            [413, 'payload_too_large'],
            \array_slice(Wire::preAdmissionRefusal(new PayloadTooLargeException('x')), 0, 2),
            'an over-limit frame prefix is 413 payload_too_large',
        );

        // Everything else that never becomes an Envelope is the framing arm, where §4.11
        // rules `non_canonical_ecf` NOT conformant.
        foreach ([
            new TruncatedFrameException('x'),
            new NonCanonicalEcfException('x'),
            new ProtocolException('x'),
            new \RuntimeException('x'),
        ] as $e) {
            self::assertSame(
                [400, 'invalid_request'],
                \array_slice(Wire::preAdmissionRefusal($e), 0, 2),
                'a framing failure is 400 invalid_request, never non_canonical_ecf: ' . $e::class,
            );
        }

        // ORDER IS LOAD-BEARING and this is the assertion that says so: TagRejected
        // EXTENDS NonCanonicalEcf and HashMismatch EXTENDS ProtocolException, so a
        // classifier that tested the superclass first could never reach either specific
        // arm — and the two assertions above would both answer `invalid_request` while
        // reading as perfectly sensible code.
        self::assertInstanceOf(NonCanonicalEcfException::class, new TagRejectedException('x'));
        self::assertInstanceOf(ProtocolException::class, new HashMismatchException('x'));

        // Every message is wire-visible and therefore ASCII-only: two peers in this
        // cohort have been killed at runtime by a non-ASCII byte in an encoded string, on
        // two unrelated compilers. Note what is asserted — the FIXED TABLE, never the
        // internal exception text, which carries section signs and may echo input.
        foreach ([
            new HashMismatchException("\u{00a7}1.8 fidelity"),
            new TagRejectedException("\u{00a7}6.3"),
            new PayloadTooLargeException("\u{00a7}4.10"),
            new TruncatedFrameException("\u{00a7}4.11"),
        ] as $e) {
            [, $code, $message] = Wire::preAdmissionRefusal($e);
            self::assertSame($message, \mb_convert_encoding($message, 'ASCII', 'UTF-8'),
                'a wire-visible message must be ASCII-only');
            self::assertSame($code, \mb_convert_encoding($code, 'ASCII', 'UTF-8'),
                'a wire-visible code must be ASCII-only');
            self::assertStringNotContainsString('1.8', $message, 'the table never echoes the internal text');
        }
    }

    /**
     * §1.8 / §3.1 resolution integrity raises the type the classifier needs, from both of
     * the two sites that can detect it. A decode boundary that raised a bare
     * ProtocolException here would fall through to `invalid_request` above and the whole
     * mapping would be dead code.
     */
    public function testResolutionIntegrityFailuresRaiseHashMismatch(): void
    {
        // (a) an entity whose CARRIED content_hash is not content_hash({type, data}).
        $wrong = Ecf::map('type', 'primitive/any', 'data', Ecf::map('n', 1),
            'content_hash', new \EntityCore\ByteString(\str_repeat("\x00", 33)));
        try {
            Entity::ofCbor($wrong);
            self::fail('a carried content_hash mismatch must be refused');
        } catch (HashMismatchException) {
            self::assertTrue(true);
        }

        // (b) an `included` entry whose MAP KEY does not bind to the entity under it —
        // mechanism (a) "bind the key", which fails the envelope closed at ONE site.
        $ent = Entity::make('primitive/any', Ecf::map('n', 1));
        // EcfMap::put returns void, so the fluent form silently yields null and the
        // `included` key parses as absent — the decoder then refuses nothing and this
        // deny assertion passes for a reason that is not the peer's. Caught by running
        // it; building the map first is the fix, and the control below is what would
        // have caught the same mistake on the accept side.
        $badIncluded = new EcfMap();
        $badIncluded->put(new \EntityCore\ByteString(\str_repeat("\x01", 33)), $ent->toCbor());
        $env = Ecf::map(
            'root', Entity::make('system/protocol/execute', Ecf::map('request_id', 'r'))->toCbor(),
            'included', $badIncluded,
        );
        try {
            Envelope::ofCbor($env);
            self::fail('a mis-keyed included entry must be refused');
        } catch (HashMismatchException) {
            self::assertTrue(true);
        }

        // THE CONTROL: the same envelope with the RIGHT key is accepted. Without it, both
        // assertions above are equally explained by an envelope decoder that refuses
        // everything.
        $goodIncluded = new EcfMap();
        $goodIncluded->put(new \EntityCore\ByteString($ent->hash()), $ent->toCbor());
        $good = Ecf::map(
            'root', Entity::make('system/protocol/execute', Ecf::map('request_id', 'r'))->toCbor(),
            'included', $goodIncluded,
        );
        self::assertCount(1, Envelope::ofCbor($good)->included, 'control: a correctly keyed entry is accepted');
    }

    /**
     * §6.5's "Other type?" arm, as rewritten at 0.8.2.25 (N12/N17): a root that is
     * neither EXECUTE nor EXECUTE_RESPONSE gets a CODED REFUSAL, not a bare close and not
     * silence.
     *
     * §3.3 read "the connection MUST be closed", assigning no code and requiring no
     * frame, and §9.1's floor row that MANDATED the bare close was REPLACED at the same
     * revision (N18). This peer did something weaker still: `dispatch` returned null, the
     * transport wrote NOTHING, and the connection stayed open — §4.11's OTHER
     * non-conformant behaviour, the silent drop, "the weaker of the two precisely because
     * nothing surfaces it".
     */
    public function testNonExecuteRootIsACodedRefusalNotSilence(): void
    {
        $peer = Peer::create(\str_repeat("\x88", 32));
        $root = Entity::make('system/nope', Ecf::map('request_id', 'rX'));
        $resp = $peer->dispatch(new Conn(), new Envelope($root));

        self::assertInstanceOf(Envelope::class, $resp, 'a non-EXECUTE root is owed a frame, not silence');
        self::assertSame(400, Wire::responseStatus($resp));
        self::assertSame('invalid_request', Wire::responseResult($resp)?->text('code'));
        // Correlated where the id happens to be available — §4.11 asks for that "where
        // the id is available" and licenses the uncorrelated form where it is not.
        self::assertSame('rX', $resp->root->text('request_id'));

        // AND THE UNCORRELATED FORM IS STILL A FRAME. An arbitrary root type is under no
        // obligation to carry a request_id, and answering nothing because we could not
        // correlate is the silent drop wearing a justification.
        $anon = $peer->dispatch(new Conn(), new Envelope(Entity::make('system/nope', Ecf::emptyMap())));
        self::assertInstanceOf(Envelope::class, $anon);
        self::assertSame(400, Wire::responseStatus($anon));
        self::assertSame('', $anon->root->text('request_id'));

        // THE CONTROL: an ordinary EXECUTE still routes. Without it, "everything gets a
        // 400" satisfies the assertions above.
        $exec = Entity::make('system/protocol/execute', Ecf::map(
            'request_id', 'ok', 'uri', 'system/protocol/connect', 'operation', 'bogus',
        ));
        $ctl = $peer->dispatch(new Conn(), new Envelope($exec));
        self::assertInstanceOf(Envelope::class, $ctl);
        self::assertSame('ok', $ctl->root->text('request_id'), 'control: an EXECUTE is still dispatched');
    }

    /**
     * A ZERO-LENGTH frame is COMPLETE, not truncated: it reaches the decoder and is
     * refused there as bytes that never become an Envelope. Stated as a test because the
     * two are one `if` apart in the frame reader and collapsing them would answer 400 to
     * an ordinary hangup.
     */
    public function testAnEmptyPayloadIsADecodeFailureNotATruncation(): void
    {
        try {
            Wire::envelopeOfFrame('');
            self::fail('an empty payload cannot decode into an envelope');
        } catch (\Throwable $e) {
            self::assertNotInstanceOf(TruncatedFrameException::class, $e,
                'an empty COMPLETE frame is not a framing truncation');
            self::assertSame([400, 'invalid_request'],
                \array_slice(Wire::preAdmissionRefusal($e), 0, 2));
        }

        // A CBOR TAG in a data field is the one decode failure that keeps its own code.
        $tagged = "\xa1" . "\x64root" . "\xa2" . "\x64data" . "\xc0\x00" . "\x64type" . "\x76system/protocol/execute";
        try {
            Cbor::decode($tagged);
            self::fail('a CBOR tag must be rejected');
        } catch (\Throwable $e) {
            self::assertSame([400, 'non_canonical_ecf'],
                \array_slice(Wire::preAdmissionRefusal($e), 0, 2),
                'the tag arm keeps non_canonical_ecf while its siblings move to invalid_request');
        }
    }
}
