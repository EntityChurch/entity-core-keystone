"""§4.11 pre-admission refusals (0.8.2.25) — classification AND emission.

§4.11's rule has two halves and they fail differently.

  * *"The frame obligation belongs to the class"* is WIRE-VISIBLE, and the two
    non-conformant behaviours it names are distinct: **dropping** the frame (no
    response, no close — "the weaker of the two precisely because nothing surfaces
    it") and **closing with no coded frame** (indistinguishable from a network fault,
    and on a multiplexed connection it destroys unrelated ADMITTED requests).  This
    peer had one of each before 0.8.2.25.
  * *"The CODE belongs to the cause ``[MUST]``"* is a MAPPING, and a mapping is
    exactly the thing that regresses silently when a new failure joins an existing
    branch.

So both halves are covered here: the mapping at the unit level, and the emission over
a real socket, because a green mapping over a transport that never calls it is the
`check_path_permission` shape all over again.

THE PINNED CHECK SET (778) HAS NO VECTOR ON THIS SURFACE, which is why the coverage is
authored here rather than inherited.

EVERY SOCKET CASE CARRIES A POSITIVE CONTROL in the same connection or the same run.
A probe fails in the direction of the answer it is looking for: a malformed frame that
is malformed in a SECOND way answers the code under measurement for the wrong reason,
and without the control that publishes as a peer finding.
"""

from __future__ import annotations

import socket
import struct

import pytest

from entity_core import ByteKey, NonCanonicalEcfError, TagRejectedError, TruncatedError
from entity_core import _cbor
from entity_core.peer import Identity, Peer, listen, response_result, response_status
from entity_core.peer.model import (
    BadEntityError,
    Entity,
    Envelope,
    HashMismatchError,
    entity_of_cbor,
    envelope_of_cbor,
)
from entity_core.peer.wire import (
    FrameTooLargeError,
    MAX_FRAME,
    TruncatedFrameError,
    envelope_of_frame,
    error_result,
    framing_refusal,
    make_execute,
    make_response,
    pre_admission_refusal,
    read_frame,
)

LOCAL_SEED = bytes([0x7B] * 32)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Framing: a close at a frame boundary is not a refusal; a close mid-frame is
# ══════════════════════════════════════════════════════════════════════════════
class _Chunks:
    """A socket-shaped reader over a fixed byte string, so ``read_frame`` can be
    driven without a listener.  ``recv`` answering ``b""`` is the close."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def recv(self, n: int) -> bytes:
        chunk, self._data = self._data[:n], self._data[n:]
        return chunk


def test_read_frame_distinguishes_close_from_truncation() -> None:
    """A clean EOF at a FRAME BOUNDARY is an ordinary close and is owed nothing; a
    stream that ends MID-FRAME is a §4.11 framing refusal and is owed a coded frame.

    Both surface as ``recv`` answering ``b""``, so the distinction can only be made
    where the frame boundary is known — and getting it wrong in the other direction
    would answer 400 to every peer that simply hangs up.
    """
    with pytest.raises(ConnectionError):
        read_frame(_Chunks(b""))  # nothing read: an ordinary close
    with pytest.raises(TruncatedFrameError):
        read_frame(_Chunks(b"\x00\x00"))  # partial length prefix
    with pytest.raises(TruncatedFrameError):
        read_frame(_Chunks(b"\x00\x00\x10\x00\xa1"))  # declared 4096, sent 1
    with pytest.raises(FrameTooLargeError):
        read_frame(_Chunks(b"\x02\x00\x00\x00"))  # 32 MiB > the 16 MiB default

    # A ZERO-LENGTH frame is COMPLETE, not truncated: it reaches the decoder and is
    # refused there as bytes that never become an Envelope.
    assert read_frame(_Chunks(b"\x00\x00\x00\x00")) == b""


# ══════════════════════════════════════════════════════════════════════════════
# 2. The mapping: §4.11's table, one row at a time
# ══════════════════════════════════════════════════════════════════════════════
def test_pre_admission_code_is_the_causes() -> None:
    """*"A single code for the class would answer an honest caller under the wrong
    reason and send them to the wrong layer."*"""
    rows = [
        # §4.10(a), mood raised to MUST at 0.8.2.25 (N14).
        (FrameTooLargeError("x"), 413, "payload_too_large"),
        # §5.2a / §1.8 resolution integrity. 0.8.2.24 pins this and rules
        # non_canonical_ecf NON-CONFORMANT here.
        (HashMismatchError("x"), 400, "hash_mismatch"),
        # ENTITY-CBOR-ENCODING §6.3 — the tag-policy arm keeps its own code.
        (TagRejectedError("x"), 400, "non_canonical_ecf"),
        # §4.7 / §4.11 framing arm: bytes that never become an Envelope.
        (TruncatedFrameError("x"), 400, "invalid_request"),
        (TruncatedError("x"), 400, "invalid_request"),
        (BadEntityError("x"), 400, "invalid_request"),
        # The one that makes the subclass ordering load-bearing: a non-minimal head
        # is "non-canonical CBOR" by name and is NOT the tag-policy arm.
        (NonCanonicalEcfError("x"), 400, "invalid_request"),
    ]
    assert len(rows) == 7  # examined-N, not merely "no failures"
    for exc, status, code in rows:
        got_status, got_code, message = pre_admission_refusal(exc)
        assert (got_status, got_code) == (status, code), f"{type(exc).__name__}: {got_code}"
        assert message and message.isascii(), "a wire-visible message stays ASCII"


def test_framing_refusal_separates_owed_from_ended() -> None:
    """Which read failures are owed a frame at all.  A closed or reset socket is not
    a refusal of anything and there is nobody left to answer."""
    assert framing_refusal(FrameTooLargeError("x")) is True
    assert framing_refusal(TruncatedFrameError("x")) is True
    assert framing_refusal(ConnectionError("closed")) is False
    assert framing_refusal(OSError("reset")) is False


# ══════════════════════════════════════════════════════════════════════════════
# 3. The decode boundary: the two causes must arrive as DIFFERENT exceptions
# ══════════════════════════════════════════════════════════════════════════════
def _good_entity() -> Entity:
    return Entity.make("primitive/any", {"x": 1})


def _root_execute() -> Entity:
    return make_execute("t1", "system/tree", "get", Entity.make("primitive/any", {}))


def test_decode_boundary_cause_split() -> None:
    """Before 0.8.2.24 this peer answered ``400 non_canonical_ecf`` for every one of
    these, which is the code-under-the-wrong-reason defect §5.2a names: a mis-keyed
    ``included`` entry carries no tag, its encoding is canonical, and *re-encode* is
    not the caller's remedy."""
    good, root = _good_entity(), _root_execute()

    # (a) MIS-KEYED included entry -> resolution integrity.
    mis_keyed = {"root": root.to_cbor(), "included": {bytes([0x11] * 33): good.to_cbor()}}
    with pytest.raises(HashMismatchError):
        envelope_of_cbor(mis_keyed)
    assert pre_admission_refusal(HashMismatchError("x"))[1] == "hash_mismatch"

    # (b) A CORRECTLY keyed entry whose entity carries a wrong content_hash is the
    # same class (§1.8 item 1) and takes the same code.
    with pytest.raises(HashMismatchError):
        entity_of_cbor({"type": good.type, "data": good.data, "content_hash": bytes([0x22] * 33)})

    # (c) STRUCTURAL faults stay BadEntityError -> invalid_request. THIS IS THE
    # DISCRIMINATOR: if both causes collapsed into one type the split above would
    # pass vacuously. `HashMismatchError` subclasses `BadEntityError`, so the test
    # has to assert the NEGATIVE direction too.
    for bad in ({"data": 1}, {"type": 7, "data": 1}, {"type": "primitive/any"}):
        with pytest.raises(BadEntityError) as ei:
            entity_of_cbor(bad)
        assert not isinstance(ei.value, HashMismatchError), bad
    with pytest.raises(BadEntityError) as ei:
        envelope_of_cbor({"nope": 1})
    assert not isinstance(ei.value, HashMismatchError)

    # (d) And the WELL-FORMED envelope must still decode, or every case above is
    # satisfied by a decoder that refuses everything.
    env = envelope_of_cbor({"root": root.to_cbor(), "included": {good.hash: good.to_cbor()}})
    assert good.hash.hex() in env.included


def test_tag_is_the_only_non_canonical_ecf() -> None:
    """``ENTITY-CBOR-ENCODING`` §6.3 is the sole definition of that code in the corpus
    and assigns it to a major-type-6 item in a data-field position.  Everything else
    this decoder calls non-canonical is §4.11's framing arm."""
    with pytest.raises(TagRejectedError):
        _cbor.decode(b"\xc1\x00")  # tag 1 over a uint
    try:
        _cbor.decode(b"\x18\x01")  # non-minimal 1-byte integer head
    except NonCanonicalEcfError as exc:
        non_tag = exc
    else:
        raise AssertionError("a non-minimal integer head must be refused")
    assert not isinstance(non_tag, TagRejectedError)
    assert pre_admission_refusal(non_tag)[1] == "invalid_request"


# ══════════════════════════════════════════════════════════════════════════════
# 4. Over the wire: the frame obligation, with a positive control per run
# ══════════════════════════════════════════════════════════════════════════════
def _framed(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def _hello_frame() -> bytes:
    """A well-formed EXECUTE the peer MUST answer 200 — the positive control."""
    ident = Identity.of_seed(bytes([0x2A] * 32))
    hello = Entity.make("system/protocol/connect/hello", {
        "peer_id": ident.peer_id,
        "nonce": bytes([0x01] * 32),
        "protocols": ["entity-core/1.0"],
        "timestamp": 1,
        "hash_formats": ["ecfv1-sha256"],
        "key_types": ["ed25519"],
    })
    env = Envelope.of(make_execute("ctl-1", "system/protocol/connect", "hello", hello))
    return _framed(_cbor.encode(env.to_cbor()))


def _tagged_execute_payload() -> bytes:
    """A frame whose ONLY defect is a CBOR tag inside an entity's ``data`` map.

    Hand-spliced, because this peer's encoder cannot emit a tag by construction — and
    THE SPLICE IS ASSERTED.  The first cut of this helper used the wrong text-string
    header (`0x63` for a five-character key) so the replacement silently matched
    nothing, the frame stayed perfectly well-formed, and the peer answered
    `401 authentication_failed` to an unauthenticated `system/tree:get`.  That is a
    correct answer to a question this test was not asking, and it is exactly the
    "a wire probe fails in the direction of the answer it is looking for" shape: a
    no-op mutation reads as a peer that does not implement the branch.  A mutation
    that is not verified to have landed is not a mutation.
    """
    root = Entity.make("system/protocol/execute", {
        "request_id": "tag-1", "uri": "system/tree", "operation": "get",
        "params": Entity.make("primitive/any", {}).to_cbor(), "extra": 0,
    })
    payload = _cbor.encode({"root": root.to_cbor()})
    marker = b"\x65extra\x00"           # text(5) "extra", then uint 0
    assert payload.count(marker) == 1, "the splice target moved; the mutation is not a mutation"
    tagged = payload.replace(marker, b"\x65extra\xc1\x00")   # 0xc1 = tag 1
    assert tagged != payload
    with pytest.raises(TagRejectedError):
        _cbor.decode(tagged)           # the frame really does carry a rejectable tag
    return tagged


def _drive(frames: list[bytes], expect: int, port: int) -> list[tuple[int, str, str]]:
    """Send ``frames`` on one connection and read ``expect`` responses.

    Returns ``(status, code, request_id)`` per response.  A missing response is the
    §4.11 silent drop and shows up as a socket timeout, which is the failure this
    whole file exists to catch — so it is raised, never swallowed.
    """
    s = socket.create_connection(("127.0.0.1", port))
    s.settimeout(5.0)
    try:
        for f in frames:
            s.sendall(f)
        out = []
        for _ in range(expect):
            env = envelope_of_frame(read_frame(s))
            res = response_result(env)
            out.append((
                response_status(env),
                (res.text("code") or "") if res is not None else "",
                env.root.text("request_id") or "",
            ))
        return out
    finally:
        s.close()


@pytest.fixture(scope="module")
def peer_port():
    ln = listen(Peer(LOCAL_SEED), 0)
    try:
        yield ln.port
    finally:
        ln.close()


def test_positive_control_answers_200(peer_port) -> None:
    """The control on its own, first.  If this ever fails, nothing below is a reading
    about the peer — it is a reading about this file."""
    assert _drive([_hello_frame()], 1, peer_port) == [(200, "", "ctl-1")]


def test_correlated_refusals_keep_the_connection_serving(peer_port) -> None:
    """A COMPLETE frame the decoder refused: the framing is intact, so the peer
    answers and KEEPS SERVING.  Each refusal is followed by the control on the SAME
    connection — which is the differential that says the answer was a refusal of the
    frame and not the connection collapsing."""
    good, root = _good_entity(), _root_execute()

    # (a) mis-keyed `included` entry -> 400 hash_mismatch, correlated (§5.2a).
    mis_keyed = _framed(_cbor.encode({
        "root": root.to_cbor(),
        "included": {ByteKey(bytes([0x11] * 33)): good.to_cbor()},
    }))
    tagged = _framed(_tagged_execute_payload())
    # (c) a root that is neither EXECUTE nor EXECUTE_RESPONSE -> 400 invalid_request
    #     (§3.3/§6.5 "Other type?", N12/N17). NOT a bare close.
    other_root = _framed(_cbor.encode(
        Envelope.of(Entity.make("primitive/any", {"request_id": "x-1"})).to_cbor()))

    got = _drive([mis_keyed, tagged, other_root, _hello_frame()], 4, peer_port)
    assert got[0] == (400, "hash_mismatch", "t1")
    assert got[1] == (400, "non_canonical_ecf", "tag-1")
    assert got[2] == (400, "invalid_request", "x-1")
    assert got[3] == (200, "", "ctl-1"), "the connection is still serving after three refusals"


def test_uncorrelated_refusals_are_best_effort_frames(peer_port) -> None:
    """Where no ``request_id`` can be recovered, §4.11 prescribes *"a best-effort coded
    frame carrying no correlation"* — an empty ``request_id`` IS that form.  Guessing
    one would correlate the refusal to somebody else's in-flight request."""
    # (a) canonical CBOR that is not envelope-shaped.
    not_an_envelope = _framed(_cbor.encode({"nope": 1}))
    # (b) bytes that are not CBOR at all.
    garbage = _framed(b"\xff\xff\xff\xff")
    got = _drive([not_an_envelope, garbage, _hello_frame()], 3, peer_port)
    assert got[0] == (400, "invalid_request", "")
    assert got[1] == (400, "invalid_request", "")
    assert got[2] == (200, "", "ctl-1"), "the connection is still serving"


def test_oversize_frame_is_answered_before_the_close(peer_port) -> None:
    """§4.10(a) N14: SHOULD -> MUST.  The over-size condition is detected at the length
    prefix with the connection intact and nothing spent, so the 413 goes out FIRST and
    the close comes after — the close is now in addition to the frame, not instead of
    it.  The peer's own listener is the control: it keeps serving other connections."""
    s = socket.create_connection(("127.0.0.1", peer_port))
    s.settimeout(5.0)
    try:
        s.sendall(struct.pack(">I", MAX_FRAME + 1))  # prefix only; no body ever sent
        env = envelope_of_frame(read_frame(s))
        res = response_result(env)
        assert response_status(env) == 413
        assert res is not None and res.text("code") == "payload_too_large"
        assert env.root.text("request_id") == "", "no id was ever readable: best-effort"
    finally:
        s.close()
    # The listener survived the refusal (§4.10(a) "rejection is clean, not collapse").
    assert _drive([_hello_frame()], 1, peer_port) == [(200, "", "ctl-1")]


def test_truncated_frame_is_answered(peer_port) -> None:
    """A length prefix that never completes — §4.11's framing arm names this input
    outright.  The write side is shut down so the peer sees EOF mid-frame rather than
    an idle connection; the ordinary-hangup arm is covered at the unit level above."""
    s = socket.create_connection(("127.0.0.1", peer_port))
    s.settimeout(5.0)
    try:
        s.sendall(struct.pack(">I", 4096) + b"\xa1")  # declared 4096, sent 1
        s.shutdown(socket.SHUT_WR)
        env = envelope_of_frame(read_frame(s))
        res = response_result(env)
        assert response_status(env) == 400
        assert res is not None and res.text("code") == "invalid_request"
    finally:
        s.close()
    assert _drive([_hello_frame()], 1, peer_port) == [(200, "", "ctl-1")]


def test_a_refusal_is_never_silence(peer_port) -> None:
    """The class obligation, stated once as its own assertion rather than inferred
    from the rows above: EVERY pre-admission cause puts a frame on the wire.

    Dropping is §4.11's other non-conformant behaviour and is *"the weaker of the two
    precisely because nothing surfaces it"* — a `continue` with no write looks exactly
    like a peer that is merely slow, and the caller learns nothing until its own
    §6.11(c) deadline.  A timeout here IS that failure.
    """
    causes = [
        _framed(_cbor.encode({"nope": 1})),
        _framed(b"\xff\xff\xff\xff"),
        _framed(b""),
        _framed(_cbor.encode(Envelope.of(Entity.make("primitive/any", {})).to_cbor())),
    ]
    assert len(causes) == 4
    got = _drive(causes, len(causes), peer_port)
    assert len(got) == 4
    for status, code, _ in got:
        assert status == 400 and code, "every pre-admission refusal is coded, none is silence"


def test_make_response_and_error_result_round_trip() -> None:
    """The refusal builder itself, off the socket: the shape the transport writes when
    it has no envelope to work from at all."""
    env = Envelope.of(make_response("", 413, error_result("payload_too_large", "too big")))
    assert env.root.type == "system/protocol/execute/response"
    assert env.root.text("request_id") == ""
    assert response_status(env) == 413
