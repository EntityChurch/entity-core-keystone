"""The peer's host as a LIBRARY FUNCTION — keystone peer contract ``embed.host_main``.

``run_host(argv, configure)`` parses the contract's CLI (``run.cli``), loads the named
identity (``run.identity``), applies the seed policy (``run.posture``) and frame budget
(``run.limits``), calls ``configure(peer)`` BEFORE listening, emits the readiness record
(``run.ready``), and serves until SIGTERM/SIGINT (``run.stop``).  The standalone host
``python -m entity_core.host`` is ``run_host(argv, no-op)``; a composing program (an
extension host, the keystone contract host) passes its own ``configure``.

Flags — exactly these, anything else exits 2 before listening with no record::

    --port N  --bind ADDR  --name NAME  --validate  --seed-policy PATH
    --max-frame-bytes N  --ready-file PATH  --debug-open-grants  --help

``--seed HEX`` (the pre-contract host's alternative to ``--name``) is NOT accepted: the
contract's flag set is closed.  Without ``--name`` the peer runs on the fixed dev seed
``0x01 x 32``, as before.

The readiness record is one stdout line::

    LISTENING {"record":"keystone-peer-ready/1","transport":"tcp","addr":"<host:port>",
               "peer_id":"...","posture":"standard|debug-open|file","posture_digest":"...",
               "limits":{"max_frame_bytes":N,"max_chain_depth":M},"validate":bool}

``--ready-file PATH`` writes the same JSON object followed by a newline.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import sys
import threading
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

from .capability import MAX_CHAIN_DEPTH
from .peer import Peer
from .seed_policy import SeedPolicy, SeedPolicyError
from .transport import listen
from .wire import MAX_FRAME

#: The readiness record's schema name.
READY_RECORD = "keystone-peer-ready/1"
#: The fields every readiness record carries; ``extra_record_fields`` may not name one.
READY_RECORD_FIELDS = (
    "record", "transport", "addr", "peer_id", "posture", "posture_digest", "limits", "validate",
)

USAGE = """usage: python -m entity_core.host [--port N] [--bind ADDR] [--name NAME] [--validate]
                               [--seed-policy PATH] [--max-frame-bytes N]
                               [--ready-file PATH] [--debug-open-grants] [--help]

  --port N             TCP port (0 = auto-assign; default 0)
  --bind ADDR          listen address (default 127.0.0.1)
  --name NAME          load the Ed25519 identity from ~/.entity/peers/NAME/keypair
  --validate           bootstrap the section 7a system/validate/* conformance handlers
  --seed-policy PATH   the section 6.9a seed policy, keystone seed-policy JSON
  --max-frame-bytes N  the section 4.10(a) inbound frame budget (default 16 MiB)
  --ready-file PATH    also write the readiness record's JSON to PATH
  --debug-open-grants  DEPRECATED: the degenerate [default -> *] seed policy
                       (ignored when --seed-policy is given)
  --help               show this help
"""


class HostUsageError(ValueError):
    """An argument ``run_host`` refuses (exit 2, nothing listens)."""


@dataclass(slots=True)
class HostArgs:
    port: int = 0
    bind: str = "127.0.0.1"
    name: str | None = None
    validate: bool = False
    seed_policy_path: str | None = None
    max_frame_bytes: int | None = None
    ready_file: str | None = None
    open_grants: bool = False
    help: bool = False


def parse_args(argv: Iterable[str]) -> HostArgs:
    """Parse the contract flag set.  Raises :class:`HostUsageError` on anything else or on
    a flag missing its value."""
    a = HostArgs()
    it = iter(list(argv))

    def value(flag: str) -> str:
        try:
            return next(it)
        except StopIteration:
            raise HostUsageError(f"{flag} requires a value") from None

    for arg in it:
        if arg == "--port":
            v = value("--port")
            if not v.isdigit() or int(v) > 65535:
                raise HostUsageError(f"bad --port value {v!r}")
            a.port = int(v)
        elif arg == "--bind":
            a.bind = value("--bind")
        elif arg == "--name":
            a.name = value("--name")
        elif arg == "--validate":
            a.validate = True
        elif arg == "--seed-policy":
            a.seed_policy_path = value("--seed-policy")
        elif arg == "--max-frame-bytes":
            v = value("--max-frame-bytes")
            if not v.isdigit() or int(v) == 0:
                raise HostUsageError(f"--max-frame-bytes must be a positive integer, got {v!r}")
            a.max_frame_bytes = int(v)
        elif arg == "--ready-file":
            a.ready_file = value("--ready-file")
        elif arg == "--debug-open-grants":
            a.open_grants = True
        elif arg in ("-h", "--help"):
            a.help = True
        else:
            raise HostUsageError(f"unknown argument {arg!r}")
    return a


def fixed_dev_seed() -> bytes:
    return bytes([0x01] * 32)


def load_named_seed(name: str) -> bytes:
    """``run.identity``: the 32-byte seed from ``$HOME/.entity/peers/NAME/keypair`` — an
    entity-core PEM whose body is base64(seed).  Raises ``ValueError`` with the path."""
    path = os.path.join(os.path.expanduser("~"), ".entity", "peers", name, "keypair")
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise ValueError(f"--name {name}: cannot read {path}: {exc}") from exc
    body = b"".join(
        line.strip() for line in raw.splitlines() if line.strip() and not line.strip().startswith(b"-")
    )
    try:
        seed = base64.b64decode(body, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"--name {name}: {path}: not valid base64: {exc}") from exc
    if len(seed) != 32:
        raise ValueError(f"--name {name}: {path}: decoded seed is {len(seed)} bytes, want 32")
    return seed


def ready_record(peer: Peer, addr: str, posture: str, posture_digest: str, validate: bool) -> dict:
    """The ``keystone-peer-ready/1`` record as a dict."""
    return {
        "record": READY_RECORD,
        "transport": "tcp",
        "addr": addr,
        "peer_id": peer.local_peer,
        "posture": posture,
        "posture_digest": posture_digest,
        "limits": {"max_frame_bytes": peer.max_frame_bytes, "max_chain_depth": MAX_CHAIN_DEPTH},
        "validate": validate,
    }


def _addr(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def run_host(
    argv: Sequence[str] | None,
    configure: Callable[[Peer], Any] | None = None,
    *,
    extra_record_fields: dict[str, Any] | None = None,
) -> int:
    """Run the peer's host; return the process exit code.

    ``argv`` excludes the program name (``None`` -> ``sys.argv[1:]``).  ``configure(peer)``
    is called after the peer is built and BEFORE anything listens — install handlers,
    consumers, types and an evaluator there.  If it raises, startup is aborted with the
    message on stderr and exit ``1``.  ``extra_record_fields`` are added to the readiness
    record (JSON-serializable values; a key naming a standard field is refused, exit 1).

    Exit codes: ``0`` after a clean stop or ``--help``; ``2`` for a usage or configuration
    error (unknown flag, unreadable keypair, a seed policy that cannot be materialized);
    ``1`` when ``configure`` refuses or the listener cannot be bound.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        args = parse_args(argv)
    except HostUsageError as exc:
        print(f"host: error: {exc}", file=sys.stderr)
        print(USAGE, file=sys.stderr, end="")
        return 2
    if args.help:
        print(USAGE, end="", flush=True)
        return 0

    extra = dict(extra_record_fields or {})
    clash = sorted(set(extra) & set(READY_RECORD_FIELDS))
    if clash:
        print(f"host: error: extra readiness-record fields name standard fields: {clash}", file=sys.stderr)
        return 1

    if args.name is not None:
        try:
            seed = load_named_seed(args.name)
        except ValueError as exc:
            print(f"host: error: {exc}", file=sys.stderr)
            return 2
    else:
        seed = fixed_dev_seed()

    seed_policy: SeedPolicy | None = None
    if args.seed_policy_path is not None:
        path = args.seed_policy_path
        try:
            with open(path, "rb") as fh:
                policy_bytes = fh.read()
            seed_policy = SeedPolicy.from_json(policy_bytes.decode("utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            # Refuse before binding anything: a policy that cannot be materialized as
            # written must not fall back to some other policy and listen anyway.
            print(f"host: error: --seed-policy: {path}: {exc}", file=sys.stderr)
            return 2
        except SeedPolicyError as exc:
            print(f"host: error: --seed-policy: {path}: {exc}", file=sys.stderr)
            return 2
        posture, posture_digest = "file", hashlib.sha256(policy_bytes).hexdigest()
    elif args.open_grants:
        posture, posture_digest = "debug-open", "debug-open"
    else:
        posture, posture_digest = "standard", "standard"

    open_grants = args.open_grants
    if open_grants:
        if seed_policy is not None:
            print("host: WARNING --debug-open-grants is DEPRECATED and is IGNORED because "
                  "--seed-policy was given (a declared policy wins)", file=sys.stderr)
            open_grants = False
        else:
            print("host: WARNING --debug-open-grants is deprecated (v7.74); "
                  "prefer --seed-policy with a wide-open default "
                  "(protocol-generator/shared/seed-policy/examples/debug-open.json "
                  "is the file form)", file=sys.stderr)
    if seed_policy is not None:
        print(f"seed-policy: {args.seed_policy_path} (default entry: "
              f"{len(seed_policy.default_grants)} grant(s), "
              f"{len(seed_policy.named_entries)} named entr(ies))", file=sys.stderr)

    peer = Peer(
        seed,
        open_grants=open_grants,
        seed_policy=seed_policy,
        conformance=args.validate,
        max_frame_bytes=args.max_frame_bytes if args.max_frame_bytes is not None else MAX_FRAME,
    )

    if configure is not None:
        try:
            configure(peer)
        except Exception as exc:  # noqa: BLE001 — refuse startup, name the cause
            print(f"host: error: configure refused: {exc}", file=sys.stderr)
            return 1

    try:
        ln = listen(peer, args.port, host=args.bind)
    except OSError as exc:
        print(f"host: error: cannot listen on {_addr(args.bind, args.port)}: {exc}", file=sys.stderr)
        return 1

    stop = threading.Event()
    if threading.current_thread() is threading.main_thread():
        # Python only lets the main thread install handlers. A program running run_host on
        # another thread keeps the default dispositions, under which SIGTERM still ends the
        # process (and releases the port) — just without the clean listener close.
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        signal.signal(signal.SIGTERM, lambda *_: stop.set())

    record = ready_record(peer, _addr(ln.host, ln.port), posture, posture_digest, args.validate)
    record.update(extra)
    body = json.dumps(record, separators=(",", ":"))
    if args.ready_file is not None:
        try:
            with open(args.ready_file, "w", encoding="utf-8") as fh:
                fh.write(body + "\n")
        except OSError as exc:
            ln.close()
            print(f"host: error: --ready-file: {exc}", file=sys.stderr)
            return 1
    print(f"LISTENING {body}", flush=True)
    print(f"host: peer {peer.local_peer} on {_addr(ln.host, ln.port)}", file=sys.stderr, flush=True)

    stop.wait()
    ln.close()
    return 0
