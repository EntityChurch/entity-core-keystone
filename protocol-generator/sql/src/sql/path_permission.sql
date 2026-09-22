-- path_permission.sql — §6.3's handler-level `check_path_permission`, authored as a query.
--
-- IT IS NOT A SECONDARY CHECK (§5.2, 0.8.2.20). It is the SOLE enforcement wherever the
-- subject is derived AFTER dispatch, because the dispatch-level check in verify_ladder.sql
-- can be made VACUOUS by caller-controlled input: a caller who excludes the one target its
-- capability does not cover removes that target from the `eff` CTE entirely, and a handler
-- that then acts on it has authorized nothing. §6.3 calls this layer "the sole enforcement",
-- not a belt-and-braces second opinion.
--
-- THREE DIMENSIONS, NOT FOUR. `peers` is NOT consulted here: the path is local by
-- construction at this point (§1.4's inbound rule refuses a foreign namespace at §6.5
-- step 3, before any handler runs), and §6.3's own signature names only handlers,
-- operations and resources.
--
-- THE FRAME IS THE LOCAL PEER, NOT THE GRANTER, AND THAT IS THE SPEC'S SIGNATURE RATHER
-- THAN A CHOICE. §6.3's block reads
--   matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)
-- — there is no granter parameter to pass. §5.5a governs chain ATTENUATION, where the
-- subject is a PATTERN compared against a parent's pattern; this call site compares a
-- CONCRETE LOCAL PATH the handler is about to touch. Note that this is the OPPOSITE frame
-- from the `sc` CTE in verify_ladder.sql, which carries the §5.5a granter frame for the
-- resources dimension — reusing `sc` here would be the swift over-scoping bug (ded3e07)
-- at a third site.
--
-- There is no caller-exclude set at this call site: the subject is a single concrete path
-- and the caller's own exclusions were already applied in deriving it.
--
-- SCOPE TYPE (F40 / F50): handlers + resources are PATH-scope (GLOB over a canonicalized
-- pattern); operations is ID-scope (`id_match`, §3.6's literal matcher). Named per
-- dimension, never defaulted.
--
-- An empty `resources.include` is a LEGAL grant shape (§5.2: handlers that touch no tree
-- paths) and DENIES every path here — EXISTS over an empty include set is false, which is
-- what that note says it should do.
--
-- A malformed subject canonicalizes to '/never-match' before it is bound (the host's
-- canonicalize is total, 0.8.2.20). The sentinel is a GLOB with no metacharacter, so it
-- matches only the literal string and no grant pattern is that string — it falls through
-- to DENY rather than being matched against anything.
--
-- Bind: :value (the concrete, canonical, local path), :operation, :handler_pattern,
--       :cap_hash (the CALLER's capability), :local_peer_id.
-- Returns one row, `allowed` = 1 iff some SINGLE grant covers all three dimensions.

WITH sc AS (
  SELECT cap_hash, grant_idx, dim, kind,
         CASE
           -- §5.4 reserved forms -> the unmatchable sentinel, PATH-SCOPE ONLY
           -- (0.8.2.24 N2/N3: "It does NOT reach `operations` or `peers` [MUST]").
           WHEN dim IN ('handlers','resources')
                AND (substr(pattern,1,2)='./' OR substr(pattern,1,3)='../'
                     OR substr(pattern,1,2)='*/')
           THEN '/never-match'
           -- BOTH path dimensions take the LOCAL frame here (see the header).
           WHEN dim IN ('handlers','resources') AND pattern NOT LIKE '/%'
           THEN '/' || :local_peer_id || '/' || pattern
           ELSE pattern
         END AS canon
  FROM grant_scope
  WHERE cap_hash = :cap_hash
)
SELECT EXISTS (
  SELECT 1
  FROM cap_grant g
  WHERE g.cap_hash = :cap_hash
    -- AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21), and only a PATH-scope one
    -- can be unmatchable at all — `sc` no longer emits the sentinel for an id dimension.
    AND NOT EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                    AND sc.kind='exclude' AND sc.canon='/never-match')
    -- handlers (PATH-scope): the OWNING handler's pattern (§6.3, 0.8.2.23)
    AND     EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                    AND sc.dim='handlers' AND sc.kind='include' AND path_match(:handler_pattern, sc.canon)=1)
    AND NOT EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                    AND sc.dim='handlers' AND sc.kind='exclude' AND path_match(:handler_pattern, sc.canon)=1)
    -- operations (ID-scope)
    AND     EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                    AND sc.dim='operations' AND sc.kind='include' AND id_match(:operation, sc.canon)=1)
    AND NOT EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                    AND sc.dim='operations' AND sc.kind='exclude' AND id_match(:operation, sc.canon)=1)
    -- resources (PATH-scope): the concrete path the handler is about to touch
    AND     EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                    AND sc.dim='resources' AND sc.kind='include' AND path_match(:value, sc.canon)=1)
    AND NOT EXISTS (SELECT 1 FROM sc WHERE sc.cap_hash=g.cap_hash AND sc.grant_idx=g.grant_idx
                    AND sc.dim='resources' AND sc.kind='exclude' AND path_match(:value, sc.canon)=1)
) AS allowed;
