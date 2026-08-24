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
sc AS (
  SELECT cap_hash, grant_idx, dim, kind,
         CASE WHEN dim IN ('handlers','resources') AND pattern NOT LIKE '/%'
              THEN '/' || granter_peer_id || '/' || pattern    -- path-scope: canonicalize (granter frame, §5.5a)
              ELSE pattern END AS canon                        -- id-scope + absolute paths: raw
  FROM grant_scope
),

-- ── §5.2 check_permission: does SOME single grant on the LEAF cap cover op+handler+peer(+res)? ──
perm AS (
  SELECT g.grant_idx
  FROM cap_grant g, req
  WHERE g.cap_hash = req.capability
    -- operation dimension (§5.4 id-scope)
    AND     EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                    AND sc.dim='operations' AND sc.kind='include' AND req.operation GLOB sc.canon)
    AND NOT EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                    AND sc.dim='operations' AND sc.kind='exclude' AND req.operation GLOB sc.canon)
    -- handler dimension: match the §6.6-resolved handler pattern (longest-prefix)
    AND     EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                    AND sc.dim='handlers' AND sc.kind='include'
                    AND (SELECT path FROM handler h
                         WHERE req.uri=h.path OR req.uri GLOB h.path||'/*'
                         ORDER BY length(h.path) DESC LIMIT 1) GLOB sc.canon)
    -- peer dimension: explicit peers scope, else default {local_peer_id} (§3.6)
    AND ( CASE
            WHEN EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                         AND sc.dim='peers' AND sc.kind='include')
            THEN EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                         AND sc.dim='peers' AND sc.kind='include'
                         AND (CASE WHEN instr(substr(req.uri,2),'/')>0
                                   THEN substr(req.uri,2,instr(substr(req.uri,2),'/')-1)
                                   ELSE substr(req.uri,2) END) GLOB sc.canon)
            ELSE (CASE WHEN instr(substr(req.uri,2),'/')>0
                       THEN substr(req.uri,2,instr(substr(req.uri,2),'/')-1)
                       ELSE substr(req.uri,2) END) = req.local_peer_id
          END )
    -- resource dimension: only when a resource-target is present (§3.2). Every concrete target
    -- must be covered by resources.include and not in resources.exclude (§5.2 check_resource_scope,
    -- concrete-target arm; the pattern-overlap arm is authored + tested in the harness — A-SQL-009).
    AND ( NOT EXISTS (SELECT 1 FROM request_resource WHERE kind='target')
          OR NOT EXISTS (
               SELECT 1 FROM request_resource rt WHERE rt.kind='target'
               AND NOT (
                 EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                         AND sc.dim='resources' AND sc.kind='include' AND rt.path GLOB sc.canon)
                 AND NOT EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                         AND sc.dim='resources' AND sc.kind='exclude' AND rt.path GLOB sc.canon)
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
  WHEN (SELECT path FROM handler h
        WHERE (SELECT uri FROM req)=h.path OR (SELECT uri FROM req) GLOB h.path||'/*'
        ORDER BY length(h.path) DESC LIMIT 1) IS NULL THEN 'not_found'

  -- §5.2 check_permission: no single grant covers op+handler+peer(+resource) → 403
  WHEN NOT EXISTS (SELECT 1 FROM perm) THEN 'capability_denied'

  ELSE 'ok'
  END AS code
)
-- §5.2a verdict-to-status mapping (the fixed table — the §3.3 status row is the source of truth).
SELECT
  CASE verdict.code
    WHEN 'chain_depth_exceeded'   THEN '400'   -- §4.10(b) structural excess (NOT 403 by design)
    WHEN 'authentication_failed'  THEN '401'   -- §5.2 step-2 auth-class
    WHEN 'unresolvable_grantee'   THEN '401'   -- §5.5 PR-3 authz carve-out
    WHEN 'not_found'              THEN '404'   -- §6.6 no handler resolved
    WHEN 'ok'                     THEN '200'
    ELSE                               '403'   -- capability_denied / capability_revoked (authz)
  END AS status,
  verdict.code AS code
FROM verdict;
