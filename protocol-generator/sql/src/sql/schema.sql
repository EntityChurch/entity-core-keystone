-- schema.sql — the RELATIONAL PROJECTION of the entity store (the authority-as-query probe).
--
-- THE WRAPPER-GUARD (profile [authored]): the §5/§6.6 authority INTERIOR is authored as
-- legible SQL over these tables. The C host owns only what SQL genuinely cannot do — sockets,
-- §1.6 framing, canonical CBOR bytes, Ed25519/SHA (the S2 seam), the store's byte I/O, and the
-- §6.5 dispatch SEQUENCING + §4 handshake state machine. Everything the host can decode into a
-- readable field (paths, scopes, timestamps, depths, thresholds, hashes) is a REAL COLUMN here;
-- values SQL can't hold (raw signatures, public keys, CBOR bytes) ride as opaque BLOB columns
-- and are only ever fed back to the app-defined crypto functions (sha256/content_hash/
-- ed25519_verify — registered by ec_seam_register_sql_functions, callable FROM SQL).
--
-- Fact-binding model: the host decodes an inbound envelope, then INSERTs the request's
-- capability chain / signatures / identities / grant scopes into these tables (a fresh
-- per-request projection — see the §6.5 dispatch scaffold), binds the request row + :now +
-- :local_peer_id, and runs verify_ladder.sql. The verdict is a pure function of (bound facts,
-- :now) — §5.10 determinism (N8). All numbers here are authority-domain (depth<=64, K-of-N
-- counts/thresholds, ms timestamps, path lengths) — comfortably int64 (A-SQL-002).

PRAGMA foreign_keys = OFF;   -- the projection is host-curated + per-request; no referential
                            -- enforcement wanted (a missing parent IS a finding, not an error).

-- ── Identities (§3.5 system/peer). hash = content_hash(peer entity); peer_id is the §1.5
--    Base58 presentation handle (NOT in the hashable basis — v7.65). public_key rides opaque. ──
CREATE TABLE peer (
  hash        BLOB PRIMARY KEY,   -- 33-byte content_hash (0x00 || SHA-256)
  peer_id     TEXT,               -- Base58(key_type || hash_type || digest) — §1.5 routing handle
  public_key  BLOB,               -- raw key bytes (opaque; only fed to ed25519_verify)
  key_type    TEXT                -- "ed25519" etc. (§1.5 seed table)
);

-- ── Capability tokens (§3.6 system/capability/token). One row per cap in the presented chain. ──
CREATE TABLE cap (
  hash        BLOB PRIMARY KEY,   -- recomputed content_hash (host validates before binding, §5.2 step-1 discipline)
  grantee     BLOB,               -- hash of grantee's peer entity
  granter     BLOB,               -- single-sig: hash of granter's peer entity; multi-sig: NULL (see multi_signer)
  parent      BLOB,               -- delegation parent cap hash; NULL = root (§3.6 optional-field default)
  created_at  INTEGER,            -- ms since epoch (§3.6; ms precision — A-PD-016)
  expires_at  INTEGER,            -- ms; NULL = no expiration
  -- §6.2 CAP-6a: 1 iff SOME temporal field (expires_at / not_before / created_at) is
  -- PRESENT on the received token but NOT representable as a uint64 (negative, bignum,
  -- non-integer). The three columns above cannot carry that state: an unrepresentable
  -- field projects as NULL, which is byte-identical to ABSENT -- and absent is legal.
  -- Collapsing the two is the CAP-6a fail-open, so the distinction gets its own column
  -- rather than a sentinel value in expires_at.
  temporal_malformed INTEGER DEFAULT 0,
  not_before  INTEGER,            -- ms; NULL = immediately valid
  is_multi    INTEGER NOT NULL DEFAULT 0,   -- 1 = granter is a system/capability/multi-granter (K-of-N root, M1/M2)
  multi_threshold INTEGER,        -- K (multi-sig only)
  -- delegation caveats (§5.7), all optional → NULL = unconstrained
  no_delegation        INTEGER,   -- 1 = cannot delegate further
  max_delegation_depth INTEGER,
  max_delegation_ttl   INTEGER
);

-- ── multi-granter signer set (§3.6 system/capability/multi-granter). K-of-N roots only (M3). ──
CREATE TABLE multi_signer (
  cap_hash  BLOB,                 -- the multi-sig cap
  signer    BLOB                  -- an allowed signer identity hash (∈ signers[])
);

-- ── grant entries (§3.6 system/capability/grant-entry). One row per grant on a cap. ──
CREATE TABLE cap_grant (
  cap_hash    BLOB,
  grant_idx   INTEGER,            -- position in the cap's grants[] array
  PRIMARY KEY (cap_hash, grant_idx)
);

-- ── grant scope patterns, fully normalized (§3.6 path-scope / id-scope; §5.4 matches_pattern).
--    dim  ∈ {handlers, resources, operations, peers}; kind ∈ {include, exclude}.
--    pattern is the RAW authored pattern; granter_peer_id is the frame it canonicalizes against
--    (§5.5a: cap resources are GRANTER-local, not verifier-local — the foreign-granter subtlety). ──
CREATE TABLE grant_scope (
  cap_hash        BLOB,
  grant_idx       INTEGER,
  dim             TEXT,           -- 'handlers' | 'resources' | 'operations' | 'peers'
  kind            TEXT,           -- 'include' | 'exclude'
  pattern         TEXT,           -- authored pattern (e.g. "system/tree", "*", "/*/*", "local/files/home/*")
  granter_peer_id TEXT            -- the granter's peer_id (§5.5a canonicalization frame for this link)
);

-- ── domain-specific narrowing/expanding maps (§5.6 constraints/allowances). Opaque bytes; the
--    core only checks key-retention + byte-equality across a delegation link. ──
-- ── the grants a `system/capability` request/delegate ASKS FOR (§6.2 mint-bound). Same
--    shape as cap_grant/grant_scope so one projection walk serves both, and the §6.2
--    rung is a subset query between two tables rather than a second matcher. Cleared and
--    re-projected per request like every other request fact. Both frames are LOCAL here:
--    the mint is self-issued, so §5.5a's granter frame is the local peer on BOTH sides --
--    passing the caller's frame to either side is the swift over-scoping bug (ded3e07).
CREATE TABLE requested_grant (
  cap_hash    BLOB,               -- the EXECUTE's content_hash (the request's identity)
  grant_idx   INTEGER
);

CREATE TABLE requested_scope (
  cap_hash        BLOB,
  grant_idx       INTEGER,
  dim             TEXT,
  kind            TEXT,
  pattern         TEXT,
  granter_peer_id TEXT
);

CREATE TABLE grant_kv (
  cap_hash    BLOB,
  grant_idx   INTEGER,
  kind        TEXT,               -- 'constraint' | 'allowance'
  k           TEXT,               -- map key
  v           BLOB                -- canonical CBOR of the value (byte-compared, never interpreted)
);

-- ── signatures (§3.5 system/signature), projected from envelope.included. `valid` is computed
--    by the host (or in-query via ed25519_verify) — 1 iff ed25519_verify(signer.pubkey, target, sig). ──
CREATE TABLE signature (
  target      BLOB,               -- content_hash of the signed entity
  signer      BLOB,               -- hash of the signer's peer entity (§3.5 signer field is NORMATIVE)
  algorithm   TEXT,               -- "ed25519"
  sig         BLOB                -- raw signature bytes (opaque; fed to ed25519_verify)
);

-- ── registered handlers (§3.7 system/handler entities in the tree). path is the canonical
--    registration prefix (literal, no trailing /* — §6.6 "Registration paths vs patterns"). ──
CREATE TABLE handler (
  path        TEXT PRIMARY KEY    -- e.g. "/{P}/system/tree", "/{P}/system/capability"
);

-- ── revocation markers (§5.1 / §6.2). Presence at system/capability/revocations/{root_hex}
--    means the root (or the cap) is revoked. Host binds the roots it finds markers for. ──
CREATE TABLE revocation (
  cap_hash    BLOB PRIMARY KEY    -- a revoked cap/root content_hash
);

-- ── the single in-flight request (§3.2 EXECUTE) + the Layer-1 verdict inputs. One row. ──
CREATE TABLE request (
  content_hash    BLOB,           -- recomputed content_hash of the EXECUTE entity (host validates vs wire, §5.2 step 1)
  wire_hash       BLOB,           -- the content_hash the wire CLAIMED (step-1 tamper check: must equal content_hash)
  author          BLOB,           -- execute.data.author (identity hash)
  capability      BLOB,           -- execute.data.capability (leaf cap hash)
  uri             TEXT,           -- canonicalized absolute dispatch path (/{peer}/...)
  operation       TEXT,           -- execute.data.operation
  now_ms          INTEGER,        -- §5.10 evaluation timestamp, sampled ONCE at request entry (ms — A-PD-016)
  local_peer_id   TEXT,           -- this peer's Base58 id (the verifier frame; root-trust + peer-scope default)
  supports_revocation INTEGER NOT NULL DEFAULT 1
);

-- ── resource targets (§3.2 system/protocol/resource-target). Present only when the EXECUTE
--    carries a `resource` field; targets[]/exclude[] each a row. Absent → no dispatch resource check. ──
CREATE TABLE request_resource (
  kind        TEXT,               -- 'target' | 'exclude'
  path        TEXT
);
