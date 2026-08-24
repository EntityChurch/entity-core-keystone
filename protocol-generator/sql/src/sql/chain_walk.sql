-- chain_walk.sql — §5.5 collect_authority_chain as WITH RECURSIVE (SQL's home turf).
--
-- WRAPPER-GUARD (profile [authored].chain_walk = "sql-recursive-cte"): the delegation chain-
-- walk is authored as the CANONICAL transitive-closure pattern — a recursive CTE from the
-- presented leaf cap up its parent pointers to the root (parent IS NULL). This is precisely
-- collect_authority_chain(cap, resolve_fn): "walk the full authority chain from cap to root;
-- returns ordered [cap, parent, …, root]." The recursion IS the walk; no host loop.
--
-- §4.10(b) DEPTH BOUND (16 MiB / 64 default): the recursion carries a depth counter and the
-- host maps depth-overflow to 400 chain_depth_exceeded — a STRUCTURAL excess (client-
-- correctable), NOT 403. Critically this is the §4.10 pre-check done BEFORE the per-link authz
-- walk: `SELECT max(depth) > 64` over this CTE is the structural gate; only if it passes does
-- verify_ladder.sql run the O(depth) signature/attenuation walk. (The recursion also self-
-- limits at depth <= 64 so an attacker-controlled cycle/over-deep chain can't run unbounded.)
--
-- Reachability (§5.5 collect_authority_chain error cases):
--   · a link whose parent hash is not present in `cap`  →  the walk stops early WITHOUT a
--     root row (no parent-null link reached) → ChainUnreachable → the host reads
--     `reached_root = 0` and denies (403 capability_denied; §5.5 fail-closed).
--   · depth exceeds 64 → ChainTooDeep → 400 (the depth column crosses the bound).
--
-- Bind: :leaf_cap = execute.data.capability (the presented leaf cap hash).
-- Emits the ordered chain [leaf … root] with per-link depth + a reached_root flag on the row
-- whose parent IS NULL. verify_ladder.sql inlines this CTE for the full per-link verdict.

WITH RECURSIVE chain(hash, granter, grantee, parent, created_at, expires_at, not_before,
                     is_multi, multi_threshold,
                     no_delegation, max_delegation_depth, max_delegation_ttl,
                     depth, reached_root) AS (
  -- anchor: the presented leaf capability, depth 0
  SELECT hash, granter, grantee, parent, created_at, expires_at, not_before,
         is_multi, multi_threshold,
         no_delegation, max_delegation_depth, max_delegation_ttl,
         0                          AS depth,
         (parent IS NULL)           AS reached_root
  FROM   cap
  WHERE  hash = :leaf_cap

  UNION ALL

  -- recursive step: resolve the parent link and climb one level (§5.5 current = resolve(parent))
  SELECT p.hash, p.granter, p.grantee, p.parent, p.created_at, p.expires_at, p.not_before,
         p.is_multi, p.multi_threshold,
         p.no_delegation, p.max_delegation_depth, p.max_delegation_ttl,
         ch.depth + 1               AS depth,
         (p.parent IS NULL)         AS reached_root
  FROM   cap p
  JOIN   chain ch ON p.hash = ch.parent          -- climb: this row's parent becomes next current
  WHERE  ch.depth < 64                            -- §4.10(b) depth self-limit (default 64)
)
SELECT hash, granter, grantee, parent, created_at, expires_at, not_before,
       is_multi, multi_threshold,
       no_delegation, max_delegation_depth, max_delegation_ttl,
       depth, reached_root
FROM   chain
ORDER  BY depth;                                  -- [leaf(0) … root]
