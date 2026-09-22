-- scope_match.sql — §5.4 matches_scope / matches_pattern as a JOIN + GLOB over grant_scope.
--
-- WRAPPER-GUARD (profile [authored].scope_match = "sql-glob-join"): grant-scope matching is
-- authored as canonicalize()-then-GLOB over the normalized grant_scope rows. matches_scope
-- (§5.2) is "value is covered by some include AND not covered by any exclude" — a
-- correlated EXISTS(include) AND NOT EXISTS(exclude). matches_pattern (§5.4) reduces, for the
-- pattern classes the core surface uses, to a single GLOB against the CANONICAL pattern:
--
--   canonicalize(pattern, frame):                          -- §5.4 / §5.5a (GRANTER frame, not verifier!)
--     pattern LIKE '/%'  →  pattern                          (absolute / universal form)
--     else               →  '/' || frame || '/' || pattern   (peer-relative → granter-local)
--
--   matches_pattern(P, canon)  ≡  P GLOB canon
--     · exact   "/F/system/tree"     → GLOB has no metachars → exact match           (§5.4 exact)
--     · subtree "/F/system/type/*"   → GLOB "…/*" = P starts with "…/"               (§5.4 pattern/*)
--     · local-* "*" → "/F/*"         → GLOB "/F/*" = all of frame F's namespace       (§5.4 bare *)
--     · universal "/*/*"             → GLOB "/*/*" = every absolute path (all peers)   (§5.4 /*/*)
--
-- §5.5a is BAKED IN by carrying grant_scope.granter_peer_id as the canonicalization frame:
-- a cap's bare '*' resolves to the GRANTER's namespace (/{granter}/*), never the verifier's —
-- so a foreign-granted bare '*' does NOT authorize the local peer (the A-PD-017 / foreign-
-- granter subtlety). The open/debug seed's DUAL form ["*","/*/*"] is what actually yields
-- universal coverage (A-PD-017): '*'→/{granter}/* (granter-local) UNION '/*/*' (all peers).
--
-- EXPRESSIBILITY EDGE (A-SQL-007, logged): §5.4's peer-wildcard "/*/REST" is SEGMENT-anchored
-- (the '*' is exactly ONE segment — the peer id). SQLite GLOB '*' is NOT segment-anchored (it
-- crosses '/'), so GLOB "/*/specific/path" over-matches "/PEER/x/specific/path". For the
-- patterns the core gate exercises ('*', '/*/*', exact, trailing-subtree) GLOB is byte-exact;
-- only a "/*/specific" middle-wildcard would need segment-anchoring (a recursive-CTE tokenizer
-- or an app-defined matches_pattern). Named, bounded — the finding, not a blocker.
--
-- Bind: :value (the path/operation/peer to test), :cap_hash, :grant_idx, :dim,
--       :local_peer_id (the verifier frame for the handlers dimension).
-- Returns 1 iff :value is matched by the (cap,grant,dim) scope.

-- SCOPE TYPE (F40 / F50): `handlers` and `resources` are PATH-scope and match by GLOB
-- against a canonicalized pattern; `operations` and `peers` are ID-scope and match by the
-- `id_match` app-defined function (§3.6's literal matcher with exactly two wildcard forms
-- -- bare `*` and a trailing `/*`). GLOB on an id dimension treats `*` as a free wildcard
-- anywhere, so `*/apply` -- a literal under the id grammar -- would match any value ending
-- in `/apply`. The kind is read off `:dim` and is never defaulted.
WITH canon(kind, pattern) AS (
  SELECT kind,
         -- A-SQL-008, CORRECTED 2026-08-28: §5.5a's granter frame scopes the RESOURCE
         -- dimension ONLY. This read `:dim IN ('handlers','resources')`, which is
         -- byte-identical to the correct form whenever child and parent share a granter
         -- (every self-issued path) and wrong the moment a DELEGATED cap arrives -- see
         -- the note on `sc` in verify_ladder.sql for the measured symptom. The handlers
         -- dimension is matched against the §6.6-resolved handler path, which is always
         -- LOCAL, so it canonicalizes against the verifier. ID-scope dims (operations,
         -- peers) and already-absolute patterns match RAW.
         CASE WHEN :dim = 'resources' AND pattern NOT LIKE '/%'
              THEN '/' || granter_peer_id || '/' || pattern
              WHEN :dim = 'handlers' AND pattern NOT LIKE '/%'
              THEN '/' || :local_peer_id || '/' || pattern
              ELSE pattern
         END
  FROM grant_scope
  WHERE cap_hash = :cap_hash AND grant_idx = :grant_idx AND dim = :dim
)
SELECT
  ( EXISTS (SELECT 1 FROM canon WHERE kind='include'
            AND (CASE WHEN :dim IN ('handlers','resources') THEN path_match(:value, pattern)=1
                      ELSE id_match(:value, pattern)=1 END))                    -- covered by an include
    AND NOT EXISTS (SELECT 1 FROM canon WHERE kind='exclude'
            AND (CASE WHEN :dim IN ('handlers','resources') THEN path_match(:value, pattern)=1
                      ELSE id_match(:value, pattern)=1 END)) )                  -- and not excluded
  AS matched;
