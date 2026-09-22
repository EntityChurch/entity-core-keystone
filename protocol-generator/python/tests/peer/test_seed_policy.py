"""§6.9a seed policy as a DECLARED VALUE (K-7) and the host's ``--seed-policy`` (K-6).

The file format is the keystone convention (``protocol-generator/shared/seed-policy/``).
The refusal set mirrors the rust peer's reader so the cohort's hosts refuse the same
files.  The enforcement tests are the half a parser test cannot supply: a narrow named
grant must be ENFORCED for the identity it names and NOT for another identity, over a
real loopback -- a policy that parses and is never consulted passes every parse
assertion.  Each enforcement test asserts ACCEPT first: it is the assertion that
validates the fixture (a policy that never matched would deny all three and satisfy every
deny assertion for free).
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile

from entity_core.peer import (
    Identity,
    Peer,
    SeedPolicy,
    SeedPolicyError,
    dial,
    empty_params,
    listen,
    resource_target,
    response_status,
)
from entity_core.peer.model import Entity
from entity_core.peer.seed_policy import _discovery_floor, _grants_cbor

_HERE = pathlib.Path(__file__).resolve()
_PY_ROOT = _HERE.parents[2]
_EXAMPLES = _HERE.parents[3] / "shared" / "seed-policy" / "examples"


def _seed(b: int) -> bytes:
    return bytes([b] * 32)


# ── the shipped examples ──────────────────────────────────────────────────────
def test_default_floor_example_is_the_discovery_floor():
    p = SeedPolicy.from_file(str(_EXAMPLES / "default-floor.json"))
    assert p.default_grants == _grants_cbor(*_discovery_floor())
    assert p.named_entries == ()


def test_debug_open_example_parses_and_skips_comment():
    p = SeedPolicy.from_file(str(_EXAMPLES / "debug-open.json"))
    assert len(p.default_grants) == 1
    assert p.default_grants[0]["resources"]["include"] == ["*", "/*/*"]
    assert p.named_entries == ()


def test_operator_admin_example_has_one_named_entry():
    p = SeedPolicy.from_file(str(_EXAMPLES / "operator-admin.json"))
    assert len(p.named_entries) == 1
    assert p.named_entries[0].key == "0" * 64 + "ab"
    assert p.named_entries[0].grants[0]["peers"] == {"include": ["self"]}
    assert p.default_grants == _grants_cbor(*_discovery_floor())


def test_no_default_entry_means_the_discovery_floor():
    p = SeedPolicy.from_json('{"version":1,"entries":[]}')
    assert p.default_grants == _grants_cbor(*_discovery_floor())


def test_exclude_survives_and_constraints_carry_verbatim():
    p = SeedPolicy.from_json(
        '{"version":1,"entries":[{"grantee":"default","grants":[{"handlers":{"include":["app/x"]},'
        '"resources":{"include":["app/x/*"],"exclude":["app/x/secret"]},"operations":{"include":["get"]},'
        '"constraints":{"max":18446744073709551615,"min":-5,"nested":{"ok":true,"none":null}}}]}]}'
    )
    g = p.default_grants[0]
    assert g["resources"]["exclude"] == ["app/x/secret"]
    assert g["constraints"] == {"max": (1 << 64) - 1, "min": -5, "nested": {"ok": True, "none": None}}
    assert "peers" not in g


def test_empty_exclude_is_preserved_as_present():
    p = SeedPolicy.from_json(
        '{"version":1,"entries":[{"grantee":"default","grants":[{"handlers":{"include":["a"]},'
        '"resources":{"include":["b"],"exclude":[]},"operations":{"include":["get"]}}]}]}'
    )
    assert p.default_grants[0]["resources"] == {"include": ["b"], "exclude": []}


def test_empty_grants_is_the_cap2_withdrawal_form():
    p = SeedPolicy.from_json('{"version":1,"entries":[{"grantee":"default","grants":[]}]}')
    assert p.default_grants == []


def test_base58_and_98_hex_grantees_are_named_entries():
    peer_id = Identity.of_seed(_seed(0x42)).peer_id
    hex98 = "01" + "ab" * 48
    p = SeedPolicy.from_json(json.dumps(
        {"version": 1, "entries": [{"grantee": peer_id, "grants": []}, {"grantee": hex98, "grants": []}]}
    ))
    assert [e.key for e in p.named_entries] == [peer_id, hex98]


def test_underscore_keys_are_comments_at_every_level():
    p = SeedPolicy.from_json(
        '{"_a":1,"version":1,"entries":[{"_b":[],"grantee":"default","grants":[{"_c":{},'
        '"handlers":{"_d":0,"include":["x"]},"resources":{"include":["y"]},"operations":{"include":["get"]}}]}]}'
    )
    assert len(p.default_grants) == 1


# ── refusals ──────────────────────────────────────────────────────────────────
_G = '"grants":[]'
_SCOPE = '{"include":["x"]}'


def _wrap(entry: str) -> str:
    return '{"version":1,"entries":[' + entry + "]}"


def _grant_with(extra: str) -> str:
    return _wrap(
        '{"grantee":"default","grants":[{"handlers":' + _SCOPE + ',"resources":' + _SCOPE
        + ',"operations":' + _SCOPE + extra + "}]}"
    )


_REFUSALS = [
    ("version 2", '{"version":2,"entries":[]}'),
    ("version missing", '{"entries":[]}'),
    ("version as float 1.0", '{"version":1.0,"entries":[]}'),
    ("version true", '{"version":true,"entries":[]}'),
    ("entries missing", '{"version":1}'),
    ("entries not an array", '{"version":1,"entries":{}}'),
    ("unknown root key", '{"version":1,"entries":[],"extra":1}'),
    ("root not an object", "[]"),
    ("grantee self", _wrap('{"grantee":"self",' + _G + "}")),
    ("bounds", _wrap('{"grantee":"default",' + _G + ',"bounds":{"expires_at":1}}')),
    ("bad grantee *", _wrap('{"grantee":"*",' + _G + "}")),
    ("hex grantee of the wrong length", _wrap('{"grantee":"' + "ab" * 20 + '",' + _G + "}")),
    ("empty grantee", _wrap('{"grantee":"",' + _G + "}")),
    ("unknown entry key", _wrap('{"grantee":"default",' + _G + ',"ttl":1}')),
    ("second default", _wrap('{"grantee":"default",' + _G + '},{"grantee":"default",' + _G + "}")),
    ("duplicate named grantee",
     _wrap('{"grantee":"' + "ab" * 33 + '",' + _G + '},{"grantee":"' + "ab" * 33 + '",' + _G + "}")),
    ("grants not an array", _wrap('{"grantee":"default","grants":{}}')),
    ("grant missing operations",
     _wrap('{"grantee":"default","grants":[{"handlers":' + _SCOPE + ',"resources":' + _SCOPE + "}]}")),
    ("unknown grant key", _grant_with(',"ttl_ms":5')),
    ("unknown scope key", _wrap('{"grantee":"default","grants":[{"handlers":{"include":[],"only":[]},'
                                '"resources":' + _SCOPE + ',"operations":' + _SCOPE + "}]}")),
    ("scope missing include", _wrap('{"grantee":"default","grants":[{"handlers":{"exclude":[]},'
                                    '"resources":' + _SCOPE + ',"operations":' + _SCOPE + "}]}")),
    ("non-string include entry", _wrap('{"grantee":"default","grants":[{"handlers":{"include":[1]},'
                                       '"resources":' + _SCOPE + ',"operations":' + _SCOPE + "}]}")),
    ("constraints not an object", _grant_with(',"constraints":[]')),
    ("float inside constraints", _grant_with(',"constraints":{"max":1.5}')),
    ("exponent inside allowances", _grant_with(',"allowances":{"n":1e3}')),
    ("NaN inside constraints", _grant_with(',"constraints":{"n":NaN}')),
    ("duplicate JSON key", '{"version":1,"version":1,"entries":[]}'),
    ("trailing content", '{"version":1,"entries":[]} x'),
    ("trailing comma", '{"version":1,"entries":[],}'),
    ("unpaired surrogate", _wrap('{"grantee":"default","_c":"\\ud800",' + _G + "}")),
    ("integer out of range", _grant_with(',"constraints":{"n":18446744073709551616}')),
]


def test_refusals():
    # One assertion per case, and the count is asserted so a list that silently lost its
    # entries cannot pass.
    assert len(_REFUSALS) == 31
    accepted = []
    for why, text in _REFUSALS:
        try:
            SeedPolicy.from_json(text)
        except SeedPolicyError:
            continue
        accepted.append(why)
    assert accepted == [], f"accepted what must be refused: {accepted}"


# ── the peer surface ──────────────────────────────────────────────────────────
def test_open_grants_bool_still_selects_debug_open_and_a_declared_policy_wins():
    assert Peer(_seed(0x61), open_grants=True).seed_policy == SeedPolicy.debug_open()
    assert Peer(_seed(0x62)).seed_policy == SeedPolicy.standard()
    declared = SeedPolicy.of(_grants_cbor(*_discovery_floor()))
    assert Peer(_seed(0x63), open_grants=True, seed_policy=declared).seed_policy is declared


def test_named_entry_is_bound_as_a_policy_entry():
    key = "ab" * 33
    p = SeedPolicy.from_json(json.dumps({"version": 1, "entries": [{"grantee": key, "grants": []}]}))
    peer = Peer(_seed(0x64), seed_policy=p)
    e = peer.store.get_at("/" + peer.local_peer + "/system/capability/policy/" + key)
    assert e is not None and e.type == "system/capability/policy-entry"
    assert e.field("peer_pattern") == key and e.field("grants") == []


def _narrow_statuses(named_key) -> tuple[int, int, int]:
    a = Identity.of_seed(_seed(0x51))
    b = Identity.of_seed(_seed(0x52))
    policy = SeedPolicy.from_json(json.dumps({"version": 1, "entries": [{
        "grantee": named_key(a),
        "grants": [{
            "handlers": {"include": ["system/tree"]},
            "resources": {"include": ["app/*"], "exclude": ["app/secret"]},
            "operations": {"include": ["get"]},
        }],
    }]}))
    responder = Peer(_seed(0x50), seed_policy=policy)
    payload = Entity.make("primitive/any", {"v": "x"})
    responder.store.bind("/" + responder.local_peer + "/app/data", payload)
    responder.store.bind("/" + responder.local_peer + "/app/secret", payload)
    ln = listen(responder, 0)
    try:
        ca = dial("127.0.0.1", ln.port)
        cb = dial("127.0.0.1", ln.port)
        try:
            ca.handshake(a)
            cb.handshake(b)
            tree = "/" + responder.local_peer + "/system/tree"

            def get(cc, ident, path):
                r = cc.execute(ident, tree, "get", empty_params(), resource_target(path))
                return response_status(r) if r is not None else 0

            return get(ca, a, "app/data"), get(ca, a, "app/secret"), get(cb, b, "app/data")
        finally:
            ca.close()
            cb.close()
    finally:
        ln.close()


def test_narrow_named_grant_by_identity_hex_is_enforced_for_that_identity_only():
    a_data, a_secret, b_data = _narrow_statuses(lambda ident: ident.identity_hash.hex())
    assert a_data == 200, "named identity reads inside its grant"
    assert a_secret == 403, "named identity refused on its excluded path"
    assert b_data == 403, "another identity falls to the discovery floor"


def test_narrow_named_grant_by_base58_peer_id_is_enforced_for_that_identity_only():
    a_data, a_secret, b_data = _narrow_statuses(lambda ident: ident.peer_id)
    assert (a_data, a_secret, b_data) == (200, 403, 403)


# ── the host binary ───────────────────────────────────────────────────────────
def _run_host(*args: str) -> tuple[int, str, str]:
    """Run the host; return (exit code, stdout, stderr).  Once it prints LISTENING it is
    terminated, so a listening host reports the signal's return code."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_PY_ROOT / "src")
    proc = subprocess.Popen(
        [sys.executable, "-m", "entity_core.host", "--port", "0", *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True,
    )
    assert proc.stdout is not None
    line = proc.stdout.readline()  # blocks until LISTENING or EOF (exit before listening)
    if line.startswith("LISTENING"):
        proc.terminate()
    out, err = proc.communicate(timeout=30)
    return proc.returncode, line + out, err


def test_host_invalid_policy_exits_2_without_listening():
    with tempfile.TemporaryDirectory() as d:
        bad = os.path.join(d, "bad.json")
        with open(bad, "w") as fh:
            fh.write(_wrap('{"grantee":"self",' + _G + "}"))
        code, out, err = _run_host("--seed-policy", bad)
    assert code == 2
    assert "LISTENING" not in out
    assert "--seed-policy:" in err and "self" in err


def test_host_policy_loads_reports_counts_and_wins_over_debug_open_grants():
    path = str(_EXAMPLES / "operator-admin.json")
    code, out, err = _run_host("--seed-policy", path, "--debug-open-grants")
    first = out.splitlines()[0]
    assert first.startswith("LISTENING ") and first.split()[1].isdigit(), first
    assert "--debug-open-grants is DEPRECATED and is IGNORED because --seed-policy was given" in err
    assert f"seed-policy: {path} (default entry: 2 grant(s), 1 named entr(ies))" in err


def test_host_debug_open_grants_alone_still_works_and_warns():
    code, out, err = _run_host("--debug-open-grants")
    assert out.startswith("LISTENING ")
    assert "--debug-open-grants is deprecated (v7.74)" in err
    assert "seed-policy:" not in err
