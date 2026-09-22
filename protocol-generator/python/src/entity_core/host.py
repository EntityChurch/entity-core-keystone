"""Standalone entity-core-protocol-python peer host — the S4 conformance / oracle
driver (``python -m entity_core.host``).  ``validate-peer`` dials it.

Flags:

    --name NAME          load the Ed25519 identity from
                         ~/.entity/peers/NAME/keypair (entity-core PEM = base64
                         of a 32-byte seed).  Enables the multisig accept-path +
                         a stable cross-run identity.
    --port N             TCP port to listen on (0 = auto-assign)
    --seed HEX           hex 32-byte Ed25519 seed (alternative to --name;
                         default: a fixed dev seed)
    --seed-policy PATH   the §6.9a seed policy, read from a keystone seed-policy
                         JSON file (protocol-generator/shared/seed-policy/).
                         Without it the standard policy applies (default = the
                         §4.4 discovery floor).  A file that cannot be
                         materialized as written is refused: stderr + exit 2,
                         nothing is bound.
    --debug-open-grants  DEPRECATED.  The degenerate [default -> *] seed policy,
                         routed through the real §6.9a mechanism.  Still accepted,
                         with a warning; IGNORED when --seed-policy is also given
                         (a declared policy wins).
    --validate           bootstrap the §7a system/validate/* conformance handlers
    --help               show this help

On startup it prints ``LISTENING <port>`` on stdout so a harness can learn the
bound port, then serves until killed (SIGINT / SIGTERM).
"""

from __future__ import annotations

import argparse
import base64
import os
import signal
import sys
import threading

from .peer import Peer, SeedPolicy, SeedPolicyError, listen


def _fixed_dev_seed() -> bytes:
    return bytes([0x01] * 32)


def _load_named_seed(name: str) -> bytes:
    """Load the Ed25519 seed for peer ``NAME`` from
    ``~/.entity/peers/NAME/keypair`` (PEM = base64 of a 32-byte seed)."""
    path = os.path.join(os.path.expanduser("~"), ".entity", "peers", name, "keypair")
    if not os.path.exists(path):
        raise SystemExit(f"host: identity not found: {path}")
    with open(path, "rb") as fh:
        raw = fh.read().strip()
    # The keypair file is base64 of a 32-byte seed (entity-core PEM convention);
    # tolerate PEM armor if present.
    body = b"".join(
        line for line in raw.splitlines() if not line.startswith(b"-----")
    )
    try:
        seed = base64.b64decode(body)
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"host: {path}: not valid base64: {exc}")
    if len(seed) != 32:
        raise SystemExit(f"host: {path}: decoded seed is {len(seed)} bytes, want 32")
    return seed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="entity_core.host",
        description="Standalone entity-core-protocol-python peer (S4 conformance host).",
    )
    parser.add_argument("--name", help="load identity from ~/.entity/peers/NAME/keypair")
    parser.add_argument("--port", type=int, default=0, help="TCP port (0 = auto-assign)")
    parser.add_argument("--seed", help="hex 32-byte Ed25519 seed (default: fixed dev seed)")
    parser.add_argument(
        "--seed-policy", metavar="PATH",
        help="load the §6.9a seed policy from a keystone seed-policy JSON file",
    )
    parser.add_argument(
        "--debug-open-grants", action="store_true",
        help="DEPRECATED: the degenerate [default -> *] seed policy "
             "(ignored when --seed-policy is given)",
    )
    parser.add_argument(
        "--validate", action="store_true",
        help="bootstrap the §7a system/validate/* conformance handlers",
    )
    args = parser.parse_args(argv)

    if args.name:
        seed = _load_named_seed(args.name)
    elif args.seed:
        try:
            seed = bytes.fromhex(args.seed)
        except ValueError:
            print("host: --seed must be 64 hex chars (32 bytes)", file=sys.stderr)
            return 2
        if len(seed) != 32:
            print("host: --seed must be 64 hex chars (32 bytes)", file=sys.stderr)
            return 2
    else:
        seed = _fixed_dev_seed()

    seed_policy = None
    if args.seed_policy is not None:
        try:
            seed_policy = SeedPolicy.from_file(args.seed_policy)
        except SeedPolicyError as exc:
            # Refuse before binding anything: a policy that cannot be materialized as
            # written must not fall back to some other policy and listen anyway.
            print(f"host: error: --seed-policy: {exc}", file=sys.stderr)
            return 2

    open_grants = args.debug_open_grants
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
        print(f"seed-policy: {args.seed_policy} (default entry: "
              f"{len(seed_policy.default_grants)} grant(s), "
              f"{len(seed_policy.named_entries)} named entr(ies))", file=sys.stderr)

    peer = Peer(seed, open_grants=open_grants, seed_policy=seed_policy,
                conformance=args.validate)
    ln = listen(peer, args.port)

    print(f"LISTENING {ln.port}", flush=True)
    print(f"host: peer {peer.local_peer} on 127.0.0.1:{ln.port}", file=sys.stderr)

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    stop.wait()
    ln.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
