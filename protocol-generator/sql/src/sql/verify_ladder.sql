-- verify_ladder.sql — §5.2 verify_request + §6.5 dispatch decision as ONE legible verdict query.
--
-- THE PROBE'S CENTERPIECE (profile [authored].verify_ladder = "sql-query"). The whole §6.5
-- dispatch DECISION — verify_request (§5.2 steps 1-4), the §4.10 chain-depth structural pre-
-- check, §6.6 handler resolution, and §5.2 check_permission — is authored as a single CASE
-- ladder over CTEs, returning the (status, code) trichotomy the host renders into an
-- EXECUTE_RESPONSE. The crypto rungs (ed25519_verify) are called INLINE from SQL (the S2 seam
-- app-defined functions), so even the verify SEQUENCING lives in the query — NOT a folded host
-- call with SQLite as decoration (FLOW-DESIGN wrapper-guard).
--
-- The ladder's ARM ORDER is the spec's algorithm order (§5.2 steps 1→4, then §6.5 resolve →
-- check_permission), with the §4.10(b) structural depth pre-check first (a too-deep chain is a
-- 400 client-correctable excess, decided BEFORE the O(depth) authz walk — the one net-new rung
-- the whole v7.75 cohort had to add). The (status, code) tuples are pinned by §5.2a.
--
-- DETERMINISM (§5.10 / N8): the verdict is a PURE FUNCTION of (bound facts, request.now_ms).
-- now_ms is sampled ONCE at request entry (host) and read here as a column — never re-sampled
-- per link (v7.76), and ms-precision (A-PD-016). Same facts + same now → same verdict, always.
--
-- Bind: the single `request` row + the projected chain/signature/grant/handler facts. One row
-- out: {status TEXT, code TEXT}. The host maps it straight onto the response envelope.

WITH
req AS (SELECT * FROM request LIMIT 1),

-- ── §5.5 collect_authority_chain: recursive walk leaf→root (see chain_walk.sql) ──
chain(hash, granter, grantee, parent, created_at, expires_at, not_before,
      is_multi, multi_threshold, depth, reached_root) AS (
  SELECT c.hash, c.granter, c.grantee, c.parent, c.created_at, c.expires_at, c.not_before,
         c.is_multi, c.multi_threshold, 0, (c.parent IS NULL)
  FROM cap c, req WHERE c.hash = req.capability
  UNION ALL
  SELECT p.hash, p.granter, p.grantee, p.parent, p.created_at, p.expires_at, p.not_before,
         p.is_multi, p.multi_threshold, ch.depth + 1, (p.parent IS NULL)
  FROM cap p JOIN chain ch ON p.hash = ch.parent
  WHERE ch.depth <= 64                               -- lets a depth-65 row surface for the >64 gate
),

-- ── canonicalized grant scopes. FINDING (A-SQL-008): the canonicalization frame differs by
--    SCOPE KIND. PATH-scope dims (handlers, resources — §3.6 path-scope) canonicalize a peer-
--    relative pattern against a peer frame (§5.5a: the GRANTER frame for cap resources); their
--    matched VALUES are already absolute paths, so value-side canonicalize is a passthrough.
--    ID-scope dims (operations, peers — §3.6 id-scope) are IDENTIFIERS, not paths — they match
--    RAW (no path canonicalization): 'get' GLOB 'get', op GLOB '*'. Canonicalizing an identifier
--    as a path ('/{peer}/get') is symmetric-but-meaningless and only obscures the match. The
--    two scope TYPES the spec gives (path-scope vs id-scope, §3.6) map cleanly onto two SQL
--    match strategies — a place the relational encoding makes the distinction sharper than the
--    prose's single uniform matches_scope(canonicalize(value), canonicalize(pattern)). ──
-- §5.5a's per-link granter frame scopes the RESOURCE dimension ONLY. This used to read
-- `dim IN ('handlers','resources')`, and the two are byte-identical whenever child and
-- parent share a granter -- i.e. on every self-issued path -- which is why 753 of 755
-- checks passed with it wrong. It breaks for exactly one case: a DELEGATED cap whose
-- granter is the caller. Measured 2026-08-28: the CAP-5 probe presents a cap granted by
-- the oracle whose handlers scope is `system/capability`; under the granter frame that
-- canonicalized to `/{oracle}/system/capability` while the §6.6-resolved handler path is
-- `/{local}/system/capability`, so the GLOB could never match, `perm` was empty, and the
-- ladder's last rung returned 403 capability_denied. It reads as a mint bug (the oracle
-- reports "over-long ttl_ms rejected instead of clamping") and is an authz bug.
--
-- The HANDLERS dimension is matched against the §6.6-resolved handler path, which is
-- always LOCAL -- so it canonicalizes against the verifier, never the granter. §5.5a
-- names its three surfaces explicitly and all three are resource-pattern surfaces
-- (dispatch-time resource match, chain attenuation, handler-internal re-check); the
-- handlers dimension is not among them. Same defect swift carried (ded3e07), reached
-- from check_permission rather than from grantSubset.
-- §5.4's canonicalize is TOTAL (0.8.2.20): its return domain is "a canonical path OR
-- NEVER_MATCH". The sentinel '/never-match' is unreachable as a canonical path by
-- CONSTRUCTION -- its only segment cannot be a peer_id, which needs >= 46 Base58
-- characters, and '-' is outside the Base58 alphabet.
--
-- THE RESERVED ARM IS SCOPED TO THE PATH-SCOPE DIMENSIONS (0.8.2.24, N2/N3). It used to
-- be unconditional, transcribing §5.2's loop before that loop grew its type dispatch --
-- which is what the text then said. 0.8.2.24 scoped it: "a capability carrying an
-- unmatchable PATH-SCOPE pattern is INVALID ... It does NOT reach `operations` or `peers`
-- [MUST]". NEVER_MATCH is a §5.4 PATH-canonicalization sentinel and has no meaning on an
-- id dimension, whose patterns are literal identifiers §5.2's own id arm forbids putting
-- through the §5.4 transforms. Asking it outside the type dispatch ran an id pattern
-- through those transforms purely to classify it and then DENIED THE WHOLE DIMENSION on a
-- property unrelated to whether the exclude carves anything out: an `operations` exclude
-- of `*/apply` -- an ordinary namespaced operation name -- canonicalized to the sentinel
-- and denied every operation. Over-denial, invisible on any well-formed grant.
sc AS (
  SELECT cap_hash, grant_idx, dim, kind,
         CASE WHEN dim IN ('handlers','resources')
                   AND (substr(pattern,1,2)='./' OR substr(pattern,1,3)='../'
                        OR substr(pattern,1,2)='*/')
              THEN '/never-match'                              -- §5.4 reserved, PATH-scope only
              WHEN dim='resources' AND pattern NOT LIKE '/%'
              THEN '/' || granter_peer_id || '/' || pattern    -- §5.5a: GRANTER frame
              WHEN dim='handlers'  AND pattern NOT LIKE '/%'
              THEN '/' || (SELECT local_peer_id FROM req) || '/' || pattern  -- verifier frame
              ELSE pattern END AS canon                        -- id-scope + absolute: raw
  FROM grant_scope
),

-- ── §5.2's EFFECTIVE TARGET LIST (0.8.2.20): the caller's own `resource.exclude` removes
--    entries from `resource.targets` BEFORE anything else looks at the request. Every
--    reader of the request's resource below reads THIS, never `request_resource` directly
--    -- a check that counts the effective list and then reads the raw one has implemented
--    the arithmetic completely and is still looking at a target the caller withdrew.
--
--    THE CALLER-EXCLUDE ARM IS FAIL-OPEN ON AN UNMATCHABLE PATTERN, and §5.4 rules it
--    separately from the GRANT arm below: a caller exclude of '../nope' canonicalizes to
--    the sentinel, `path_match` refuses the sentinel in EITHER operand, and the target
--    simply SURVIVES. The grant arm reads the same value the other way (deny), which is
--    why the reading is chosen where the POSITION is known rather than made a property of
--    the string. ──
eff AS (
  SELECT t.ord, t.raw, t.path
  FROM request_resource t
  WHERE t.kind='target'
    AND NOT EXISTS (SELECT 1 FROM request_resource x
                    WHERE x.kind='exclude' AND path_match(t.path, x.path)=1)
),

-- ── §5.2 check_permission: does SOME single grant on the LEAF cap cover op+handler+peer(+res)? ──
perm AS (
  SELECT g.grant_idx
  FROM cap_grant g, req
  WHERE g.cap_hash = req.capability
    -- AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is fail-CLOSED
    -- in an include (covers nothing -> the grant grants nothing) and fail-OPEN in an
    -- exclude (carves out nothing -> the grant is SILENTLY WIDER than its author wrote).
    -- Same value, same matcher, opposite safety direction, so the reading is chosen HERE,
    -- where the POSITION is known, and `path_match` stays uniform over its operands.
    --
    -- THE "NO CANONICAL PATH IS THAT STRING" ARGUMENT IS NOT AVAILABLE IN SQL AND THIS
    -- LINE USED TO REST ON IT. SQLite GLOB's star is not segment-anchored, so a grant
    -- pattern of `/*` GLOBs '/never-match' like any other absolute path. The sentinel arm
    -- lives inside `path_match`, over BOTH operands, which is why every path-scope test
    -- below calls it rather than GLOB.
    -- (PATH-SCOPE ONLY since 0.8.2.24 -- `sc` no longer emits the sentinel for an id
    -- dimension at all, so this test can never see one there.)
    AND NOT EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                    AND sc.kind='exclude' AND sc.canon='/never-match')
    -- operation dimension (§3.6 ID-SCOPE): id_match, NOT GLOB. GLOB treats `*` as a free
    -- wildcard anywhere, so `*/apply` -- a LITERAL under the id grammar -- would match any
    -- value ending in `/apply` (F50 / 0.8.2.16).
    AND     EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                    AND sc.dim='operations' AND sc.kind='include' AND id_match(req.operation, sc.canon)=1)
    AND NOT EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                    AND sc.dim='operations' AND sc.kind='exclude' AND id_match(req.operation, sc.canon)=1)
    -- handler dimension: match the §6.6-resolved handler pattern (longest-prefix)
    AND     EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                    AND sc.dim='handlers' AND sc.kind='include'
                    AND path_match((SELECT path FROM handler h
                         WHERE req.uri=h.path OR req.uri GLOB h.path||'/*'
                         ORDER BY length(h.path) DESC LIMIT 1), sc.canon)=1)
    -- peer dimension (§3.6 ID-SCOPE, same matcher as operations): explicit peers scope,
    -- else default {local_peer_id}
    AND ( CASE
            WHEN EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                         AND sc.dim='peers' AND sc.kind='include')
            THEN EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                         AND sc.dim='peers' AND sc.kind='include'
                         AND id_match((CASE WHEN instr(substr(req.uri,2),'/')>0
                                   THEN substr(req.uri,2,instr(substr(req.uri,2),'/')-1)
                                   ELSE substr(req.uri,2) END), sc.canon)=1)
            ELSE (CASE WHEN instr(substr(req.uri,2),'/')>0
                       THEN substr(req.uri,2,instr(substr(req.uri,2),'/')-1)
                       ELSE substr(req.uri,2) END) = req.local_peer_id
          END )
    -- resource dimension: only when a resource-target is present (§3.2). Every concrete
    -- target must be covered by resources.include and not in resources.exclude (§5.2
    -- check_resource_scope, concrete-target arm; the pattern-overlap arm is authored +
    -- tested in the harness — A-SQL-009).
    --
    -- OVER THE EFFECTIVE SET (0.8.2.20), NOT OVER `request_resource`. This read the raw
    -- targets, so a caller who excluded the one target its capability does not cover was
    -- still refused HERE — the right answer reached by a mechanism the spec does not name.
    -- §5.2 says the caller's exclusions are applied FIRST and calls the consequence out:
    -- this check can be made VACUOUS by caller-controlled input, which is why §6.3's
    -- handler-level `check_path_permission` exists and is "the sole enforcement wherever
    -- the subject is derived after dispatch". Reading the effective set here is what makes
    -- that layer load-bearing rather than redundant.
    AND ( NOT EXISTS (SELECT 1 FROM eff)
          OR NOT EXISTS (
               SELECT 1 FROM eff rt
               WHERE NOT (
                 EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                         AND sc.dim='resources' AND sc.kind='include' AND path_match(rt.path, sc.canon)=1)
                 AND NOT EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                         AND sc.dim='resources' AND sc.kind='exclude' AND path_match(rt.path, sc.canon)=1)
               )) )
)

-- ── the §5.2/§6.5 CASE ladder — arms in the spec's algorithm order. The ladder computes the
--    CODE; the (status) is then mapped from the code via the fixed §5.2a table below. ──
, verdict AS (SELECT
  CASE

  -- §4.10(b) STRUCTURAL PRE-CHECK (before authz): a too-deep chain is a client-correctable
  -- excess → 400 chain_depth_exceeded, NOT 403. The single net-new v7.75 rung.
  WHEN (SELECT max(depth) FROM chain) > 64 THEN 'chain_depth_exceeded'

  -- §5.2 step 1: content-hash tamper → AUTHZ_DENY → 403 (envelope structurally corrupt)
  WHEN (SELECT content_hash FROM req) IS NOT (SELECT wire_hash FROM req) THEN 'capability_denied'

  -- §5.2 step 2: signature (auth-class → 401 authentication_failed). Author present, signer==author,
  -- signature targets the EXECUTE hash, verifies against author's pubkey (ed25519_verify INLINE).
  WHEN NOT EXISTS (SELECT 1 FROM signature s JOIN peer a ON a.hash=(SELECT author FROM req)
                   WHERE s.target=(SELECT content_hash FROM req) AND s.signer=(SELECT author FROM req)
                     AND ed25519_verify(a.public_key, s.target, s.sig)=1)
       THEN 'authentication_failed'

  -- §5.2 step 3: capability present (authz → 403 capability_denied)
  WHEN NOT EXISTS (SELECT 1 FROM cap WHERE hash=(SELECT capability FROM req)) THEN 'capability_denied'

  -- §5.5 chain: unresolvable grantee on ANY link → 401 unresolvable_grantee (the §5.2 PR-3 authz
  -- carve-out). RESOLVED A-SQL-010: this arm precedes the grantee==author (403) arm — when the
  -- leaf grantee is itself unresolvable the spec pins 401 (AUTHZ-GRANTEE-1), not the 403 mismatch.
  WHEN EXISTS (SELECT 1 FROM chain c WHERE NOT EXISTS (SELECT 1 FROM peer p WHERE p.hash=c.grantee))
       THEN 'unresolvable_grantee'

  -- §5.2 step 3 (cont.): leaf grantee == author (authz → 403 capability_denied)
  WHEN (SELECT grantee FROM cap WHERE hash=(SELECT capability FROM req))
       IS NOT (SELECT author FROM req) THEN 'capability_denied'

  -- §5.5 chain otherwise invalid → 403 capability_denied:
  --   (a) unreachable — no parent-null root row collected
  WHEN NOT EXISTS (SELECT 1 FROM chain WHERE reached_root=1) THEN 'capability_denied'
  --   (b) root not granted by the local peer (single-sig root-trust; multi-sig root via K-of-N below)
  WHEN NOT ( EXISTS (SELECT 1 FROM chain r JOIN peer g ON g.hash=r.granter
                     WHERE r.reached_root=1 AND r.is_multi=0 AND g.peer_id=(SELECT local_peer_id FROM req))
             OR EXISTS (SELECT 1 FROM chain r WHERE r.reached_root=1 AND r.is_multi=1
                        AND EXISTS (SELECT 1 FROM multi_signer m JOIN peer g2 ON g2.hash=m.signer
                                    JOIN signature s ON s.target=r.hash AND s.signer=m.signer
                                    WHERE m.cap_hash=r.hash AND g2.peer_id=(SELECT local_peer_id FROM req)
                                      AND ed25519_verify(g2.public_key,s.target,s.sig)=1)) )
       THEN 'capability_denied'
  --   (c) single-sig link missing a valid granter signature
  WHEN EXISTS (SELECT 1 FROM chain c WHERE c.is_multi=0 AND NOT EXISTS (
                 SELECT 1 FROM signature s JOIN peer g ON g.hash=c.granter
                 WHERE s.target=c.hash AND s.signer=c.granter AND ed25519_verify(g.public_key,s.target,s.sig)=1))
       THEN 'capability_denied'
  --   (d) multi-sig link failing the K-of-N threshold (see k_of_n.sql — GROUP BY … HAVING)
  WHEN EXISTS (SELECT 1 FROM chain c WHERE c.is_multi=1 AND NOT EXISTS (
                 SELECT 1 FROM signature s
                 JOIN multi_signer m ON m.cap_hash=c.hash AND m.signer=s.signer
                 JOIN peer p ON p.hash=s.signer
                 WHERE s.target=c.hash AND ed25519_verify(p.public_key,s.target,s.sig)=1
                 GROUP BY s.target HAVING COUNT(DISTINCT s.signer) >= c.multi_threshold))
       THEN 'capability_denied'
  --   (e) delegation linkage broken: parent.grantee != child.granter (§5.5)
  WHEN EXISTS (SELECT 1 FROM chain c JOIN chain pc ON pc.hash=c.parent
               WHERE c.is_multi=0 AND (pc.grantee IS NOT c.granter)) THEN 'capability_denied'

  --   (f) §5.5 / §5.5a SURFACE 2 — per-link RESOURCE attenuation, each side
  --       canonicalized against THAT LINK'S OWN granter frame.
  --
  --       This rung did not exist. Until 2026-08-28 the ladder walked signatures and
  --       linkage but never checked that a child's authority is a SUBSET of its
  --       parent's, and the three AUTHZ-ATTENUATION-FOREIGN-GRANTER-* vectors passed
  --       anyway -- because the `sc` CTE was over-canonicalizing the HANDLERS dimension
  --       against the granter frame, so a foreign-granted cap failed check_permission
  --       and was denied for the wrong reason. Fixing the frame bug is what exposed
  --       this: the three security vectors went 200-ACCEPTED, which is what they had
  --       always been testing for and never caught. A wrong denial had been standing in
  --       for a missing check.
  --
  --       Subset arithmetic: a child include is covered iff its CANONICALIZED pattern
  --       matches some parent include pattern as a GLOB (pattern-as-value). That is
  --       exact for the pattern classes the core gate exercises -- `*`, `/*/*`, an exact
  --       path, and a trailing subtree -- and is the same shape the imperative cohort
  --       uses in grant_subset. The per-side frames are what make it a §5.5a check
  --       rather than a string comparison: a foreign-granted bare `*` canonicalizes to
  --       `/{granter}/*` and therefore cannot cover a leaf naming `/{verifier}/...`,
  --       which is precisely the escalation the vectors probe.
  --
  --       A child grant with NO resources include contributes no resource authority and
  --       is not an escalation, so it is skipped rather than denied.
  --
  --       SCOPE KIND: this rung is the RESOURCES dimension only, which is PATH-scope, so
  --       GLOB against the canonicalized pattern is the right matcher and is named here
  --       rather than assumed (F50 / 0.8.2.16). The two ID-scope dimensions are compared
  --       by `id_match` at the mint-bound rung below; neither matcher is a default.
  WHEN EXISTS (
    SELECT 1
    FROM chain c
    JOIN chain pc ON pc.hash = c.parent
    JOIN cap_grant cg ON cg.cap_hash = c.hash
    JOIN sc cs ON cs.cap_hash = c.hash AND cs.grant_idx = cg.grant_idx
              AND cs.dim = 'resources' AND cs.kind = 'include'
    WHERE NOT EXISTS (
      SELECT 1
      FROM cap_grant pg
      JOIN sc ps ON ps.cap_hash = pc.hash AND ps.grant_idx = pg.grant_idx
                AND ps.dim = 'resources' AND ps.kind = 'include'
      WHERE pg.cap_hash = pc.hash
        AND path_match(cs.canon, ps.canon)=1))
       THEN 'capability_denied'

  -- §6.2 CAP-6a: a RECEIVED token carrying a temporal field that is present but not
  -- uint64-representable is MALFORMED and MUST be refused. This rung MUST precede the
  -- range comparison below, because the range comparison is what the ambiguity defeats:
  -- an unrepresentable field projects as NULL, NULL is the "no expiry" spelling, and
  -- `expires_at IS NOT NULL AND expires_at < now` therefore never fires. The peer
  -- honored a hostile expires_at:-1 with 200. §6.2: "A verifier MUST refuse it and MUST
  -- NOT treat the unrepresentable field as absent."
  WHEN EXISTS (SELECT 1 FROM chain c JOIN cap k ON k.hash=c.hash WHERE k.temporal_malformed=1)
       THEN 'capability_denied'

  -- §5.2 temporal validity (t sampled once — §5.10): expired or not-yet-valid → 403
  WHEN EXISTS (SELECT 1 FROM chain c WHERE
                 (c.not_before IS NOT NULL AND (SELECT now_ms FROM req) < c.not_before)
              OR (c.expires_at IS NOT NULL AND c.expires_at < (SELECT now_ms FROM req)))
       THEN 'capability_denied'

  -- §5.2 step 4: revocation (when supported) — marker present for any chain link → 403.
  -- capability_revoked is the preferred-when-known code (v7.72 Class C); we know it here.
  WHEN (SELECT supports_revocation FROM req)=1
       AND EXISTS (SELECT 1 FROM chain c JOIN revocation r ON r.cap_hash=c.hash)
       THEN 'capability_revoked'

  -- §6.6 handler resolution (AFTER verify_request passes, §6.5 order): no handler → 404
  --
  -- The code is `handler_not_found` (§3.3's 404 row, 0.8.2.7), NOT `not_found`. The two
  -- are different rows with different remedies: this one says no handler governs the path
  -- at all, while `not_found` is a bound-path miss INSIDE a resolved handler (tree get,
  -- handlers.inc.c). THIS rung is the one the wire observes -- the host carries the same
  -- refusal at peer.c's resolve_handler() miss, but the ladder runs FIRST and the host arm
  -- is unreachable for an unregistered path. Correcting only the host site left the peer
  -- answering `not_found` and read as if the fix had not landed.
  WHEN (SELECT path FROM handler h
        WHERE (SELECT uri FROM req)=h.path OR (SELECT uri FROM req) GLOB h.path||'/*'
        ORDER BY length(h.path) DESC LIMIT 1) IS NULL THEN 'handler_not_found'

  -- §5.2 check_permission: no single grant covers op+handler+peer(+resource) → 403
  WHEN NOT EXISTS (SELECT 1 FROM perm) THEN 'capability_denied'

  -- §6.2 MINT-BOUND: a `capability` request/delegate MUST NOT issue authority the
  -- PRESENTED capability does not already carry. Distinct code (403
  -- scope_exceeds_authority), not capability_denied -- the request is authorized, the
  -- SCOPE it asks for is not.
  --
  -- This rung did not exist either. Like the attenuation rung above, it was masked: the
  -- handlers over-scoping in `sc` denied the widening request for the wrong reason, so
  -- request_rejects_scope_widening and AUTHZ-SCOPE-EXCEEDS-1 both read as passing. The
  -- handler passed the requested grants through VERBATIM -- there was no subset check
  -- anywhere in the peer.
  --
  -- Both sides canonicalize on the LOCAL frame (child = parent = local), because the
  -- mint is SELF-ISSUED: the granter is this peer on both sides. Note that this rung
  -- therefore reads `grant_scope` directly rather than the `sc` CTE -- `sc` carries the
  -- §5.5a GRANTER frame, which is right for dispatch-time resource matching and WRONG
  -- here. Measured: using `sc` for the parent side denied the CAP-5 probe outright,
  -- because the presented cap's `resources: ["*"]` canonicalized to `/{caller}/*` while
  -- the identical requested pattern canonicalized to `/{local}/*`. That is the swift bug
  -- (ded3e07) at the mint site rather than the dispatch site, in the direction that
  -- refuses legitimate requests rather than admitting illegitimate ones.
  WHEN EXISTS (
    SELECT 1
    FROM requested_grant rg, req
    JOIN requested_scope rs ON rs.cap_hash = rg.cap_hash AND rs.grant_idx = rg.grant_idx
                           AND rs.kind = 'include'
    WHERE rg.cap_hash = req.content_hash
      AND NOT EXISTS (
        SELECT 1
        FROM cap_grant pg
        JOIN grant_scope ps ON ps.cap_hash = pg.cap_hash AND ps.grant_idx = pg.grant_idx
                           AND ps.dim = rs.dim AND ps.kind = 'include'
        WHERE pg.cap_hash = req.capability
          -- THE SUBSET COMPARISON IS TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16;
          -- `entity-core-formalization` K-7). §3.6's id-scope grammar binds the scope
          -- TYPE, not one function, so the rule F40 landed on `matches_scope` reaches the
          -- SUBSET check too, with delegation-chain WIDENING named as the reason: on the
          -- GLOB reading `/tree/get` is covered by `*` in one direction and `*/apply` is
          -- not, and a child grant can come out wider than its parent. The kind is read
          -- off the DIMENSION at each side and never defaulted -- a default is how the
          -- next dimension inherits the wrong matcher silently, the original F40 defect.
          AND (CASE WHEN rs.dim IN ('handlers','resources')
                    THEN path_match(
                           (CASE WHEN rs.pattern NOT LIKE '/%'
                                 THEN '/' || req.local_peer_id || '/' || rs.pattern
                                 ELSE rs.pattern END),
                           (CASE WHEN ps.pattern NOT LIKE '/%'
                                 THEN '/' || req.local_peer_id || '/' || ps.pattern
                                 ELSE ps.pattern END))=1
                    ELSE id_match(rs.pattern, ps.pattern)=1     -- operations, peers
               END)))
       THEN 'scope_exceeds_authority'

  ELSE 'ok'
  END AS code
)
-- §5.2a verdict-to-status mapping (the fixed table — the §3.3 status row is the source of truth).
SELECT
  CASE verdict.code
    WHEN 'chain_depth_exceeded'   THEN '400'   -- §4.10(b) structural excess (NOT 403 by design)
    WHEN 'authentication_failed'  THEN '401'   -- §5.2 step-2 auth-class
    WHEN 'unresolvable_grantee'   THEN '401'   -- §5.5 PR-3 authz carve-out
    WHEN 'handler_not_found'      THEN '404'   -- §6.6 no handler resolved (§3.3 404 row)
    WHEN 'scope_exceeds_authority' THEN '403'  -- §6.2 mint-bound (authz, distinct code)
    WHEN 'ok'                     THEN '200'
    ELSE                               '403'   -- capability_denied / capability_revoked (authz)
  END AS status,
  verdict.code AS code
FROM verdict;
