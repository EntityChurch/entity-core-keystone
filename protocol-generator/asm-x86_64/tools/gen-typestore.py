#!/usr/bin/env python3
# gen-typestore.py — emit src/typestore.s from the harvested type-entity blobs.
#
# The blobs under reference/typestore/*.bin are the byte-exact `result` entities the
# reference entity-peer serves for `system/tree` get on each `system/type/<name>` path
# (and the one `system/type/` listing). They were captured live through tools/teeproxy.c
# against output/s4-oracles/entity-peer at oracle pin cc1970f — see status/PHASE-S3.md
# and SPEC-AMBIGUITY-LOG A-ASM-006. In an assembly peer there is no data model to reflect
# a type registry over, so these bootstrap entities are harvested byte-exact rather than
# rendered (the keystone "render natively" lesson does not transfer to asm).
#
# Regenerate:  python3 tools/gen-typestore.py > src/typestore.s
#
# The generated store is READ-ONLY (.rodata), so it is shared across the fork-per-connection
# workers for free — no epoll/shared-store refit is needed to serve it.
#
# SCOPE — the harvest is deliberately WIDER than what we publish, and CORE_FLOOR is the
# gate between the two. The blobs were captured from the reference peer, which is a FULL
# peer: it serves the standard-extension vocabularies (compute/*, system/registry/*,
# system/clock/*, system/continuation/*, system/relay/*, system/query/*, …) alongside the
# core registry. A CORE peer must not pre-publish those — extensions bring their own types
# when they are installed (ENTITY-NATIVE-TYPE-SYSTEM.md §2.7: compute/* is "reserved for
# that extension's expression-node types"; system/* is "open per extension", each claiming
# its own sub-prefixes). Publishing them anyway is not a harmless superset: the oracle
# scores non-floor types matched-if-present, so it converts ~283 type_system WARNs into
# PASSes and the peer reads as better-conforming than the cohort while violating scope.
#
# The harvest stays intact on disk — it is evidence of what the reference peer serves, and
# re-harvesting to prune it would destroy that. The filter lives here instead.
#
# CORE_FLOOR is a KEEP-LIST, not a drop-list, and that direction is load-bearing. A drop
# list fails OPEN: a vocabulary added to a future harvest publishes silently. A keep-list
# fails CLOSED: a core type accidentally omitted is a hard FAIL in the oracle's type_system
# gate, i.e. loud on the next run. Prefer the failure mode that shouts.

import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REFDIR = os.path.join(HERE, '..', 'reference', 'typestore')

# The core type-registry floor: core + operational + the type-system bootstrap.
# Cross-checked against the cohort — this is the same set every non-ISA peer publishes.
CORE_FLOOR = frozenset('''
core/entity
core/envelope
entity
primitive/any
primitive/bool
primitive/bytes
primitive/float
primitive/int
primitive/null
primitive/string
primitive/uint
system/bounds
system/capability/delegate-request
system/capability/delegation-caveats
system/capability/grant
system/capability/grant-entry
system/capability/id-scope
system/capability/multi-granter
system/capability/path-scope
system/capability/policy-entry
system/capability/request
system/capability/revocation
system/capability/revoke-request
system/capability/token
system/deletion-marker
system/delivery-spec
system/envelope
system/handler
system/handler/interface
system/handler/manifest
system/handler/operation-spec
system/handler/register-request
system/handler/register-result
system/hash
system/peer
system/peer-id
system/protocol/connect/authenticate
system/protocol/connect/hello
system/protocol/envelope
system/protocol/error
system/protocol/execute
system/protocol/execute/response
system/protocol/resource-target
system/resource-limits
system/signature
system/tree/get-request
system/tree/listing
system/tree/listing-entry
system/tree/path
system/tree/put-request
system/type
system/type/field-spec
system/type/name
'''.split())


def in_scope(path):
    """True if this harvested path belongs in a CORE peer's store.

    Three kinds of path live in the manifest:
      - "system/type/<name>"  — a type entity; published only if <name> is in CORE_FLOOR.
      - "system/type/"        — the registry listing (see the listing note in emit()).
      - "system/handler/..."  — this peer's own handler tree entities, always core.
    """
    if path == 'system/type/':
        return True
    if path.startswith('system/type/'):
        return path[len('system/type/'):] in CORE_FLOOR
    return True


def load():
    entries = []
    dropped = 0
    with open(os.path.join(REFDIR, 'manifest.tsv')) as f:
        for line in f:
            path, fn, ln = line.rstrip('\n').split('\t')
            blob = open(os.path.join(REFDIR, fn), 'rb').read()
            assert len(blob) == int(ln), (fn, len(blob), ln)
            if not in_scope(path):
                dropped += 1
                continue
            entries.append((path, blob))

    # Fail closed: every floor type must have been present in the harvest. A name that
    # silently vanishes here would be a hard type_system FAIL discovered only at S4.
    got = {p[len('system/type/'):] for p, _ in entries if p.startswith('system/type/')}
    missing = CORE_FLOOR - got
    assert not missing, 'harvest is missing core floor types: %s' % sorted(missing)
    print('# gen-typestore: %d in scope, %d extension entities dropped'
          % (len(entries), dropped), file=sys.stderr)
    return entries

def esc(path):
    # asciz-safe: paths are printable ASCII with no quotes/backslashes
    assert '"' not in path and '\\' not in path and '\n' not in path
    return path

def emit(entries, out):
    w = out.write
    w('# GENERATED by tools/gen-typestore.py — DO NOT HAND-EDIT.\n')
    w('# Byte-exact type-registry bootstrap entities harvested from the reference peer\n')
    w('# (oracle cc1970f) via tools/teeproxy.c. See tools/gen-typestore.py header + A-ASM-006.\n')
    w('# Filtered to the CORE floor — the harvest also carries the standard-extension\n')
    w('# vocabularies the full reference peer serves, which a core peer must not publish.\n')
    w('# %d entities (%d payload bytes).\n\n' % (len(entries), sum(len(b) for _, b in entries)))
    w('\t.section .rodata\n')
    w('\t.globl type_table\n\t.globl type_table_count\n\n')

    # path strings
    for i, (path, _) in enumerate(entries):
        w('.Ltp%d: .asciz "%s"\n' % (i, esc(path)))
    w('\n')

    # blobs
    w('\t.balign 1\n')
    for i, (_, blob) in enumerate(entries):
        w('.Ltb%d:\n' % i)
        for off in range(0, len(blob), 16):
            chunk = blob[off:off+16]
            w('\t.byte ' + ','.join('0x%02x' % c for c in chunk) + '\n')
    w('\n')

    # table: quad path_ptr, quad path_len(no NUL), quad blob_ptr, quad blob_len
    w('\t.balign 8\n')
    w('type_table:\n')
    for i, (path, blob) in enumerate(entries):
        w('\t.quad .Ltp%d, %d, .Ltb%d, %d\n' % (i, len(path.encode()), i, len(blob)))
    w('type_table_count: .quad %d\n' % len(entries))
    w('\n\t.section .note.GNU-stack,"",@progbits\n')

if __name__ == '__main__':
    emit(load(), sys.stdout)
