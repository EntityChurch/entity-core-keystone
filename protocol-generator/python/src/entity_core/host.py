"""Standalone entity-core-protocol-python peer host (``python -m entity_core.host``,
console script ``entity-core-peer``) — the S4 conformance host ``validate-peer`` dials, and
the keystone peer contract's BARE HOST.

It is ``run_host(argv, no-op)``: every flag, the readiness record and the stop behaviour
live in :mod:`entity_core.peer.host`, so a composing program that calls
``run_host(argv, configure)`` is this host plus its ``configure`` and nothing else
(keystone peer contract ``embed.host_main``).  See that module for the flag set.

On startup it prints ``LISTENING <readiness-record JSON>`` on stdout, then serves until
SIGTERM / SIGINT.
"""

from __future__ import annotations

import sys

from .peer.host import run_host


def main(argv: list[str] | None = None) -> int:
    return run_host(sys.argv[1:] if argv is None else argv, None)


if __name__ == "__main__":
    raise SystemExit(main())
