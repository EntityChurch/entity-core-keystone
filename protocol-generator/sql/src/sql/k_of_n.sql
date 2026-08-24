-- k_of_n.sql — §3.6 / §5.5 M4-M7 multi-signature K-of-N threshold as GROUP BY … HAVING.
--
-- WRAPPER-GUARD (profile [authored].k_of_n = "sql-having-count"): the K-of-N verdict is the
-- aggregate SQL was built for — "count DISTINCT valid signers, require >= threshold". The
-- signature-validity rung (ed25519_verify) is called INLINE from SQL via the S2 app-defined
-- function, so even the crypto sequencing stays in the query.
--
-- §5.5 multi-sig path: for a cap whose granter is a system/capability/multi-granter, find K
-- valid signatures whose signer ∈ the cap's signers[] set. A signature is valid iff it targets
-- the cap's content_hash, its signer resolves to a present peer, and ed25519_verify passes
-- against that peer's public key. Each constituent signs the SAME target, so signatures are
-- located by (target, signer) — find_signature_by_signer (§5.5), here a JOIN on both columns.
--
-- ACCEPT-PATH DISCIPLINE (A-SQL-004): the validate-peer `multisig` category is rejection-only
-- (100% malformed→403), so a fail-closed peer passes WITHOUT implementing this aggregate at all
-- (vacuous green). The authority harness therefore drives a genuine 2-of-3 ACCEPT: three real
-- Ed25519 signers, threshold 2, two valid signatures → this query MUST return satisfied=1 (the
-- direction the oracle cannot cover). See src/test/authority_test.c.
--
-- Bind: :cap_hash (the multi-sig cap). Returns one row {n_valid, threshold, satisfied}
-- IFF the DISTINCT valid-signer count meets threshold; zero rows otherwise (the HAVING gate).

SELECT s.target                          AS cap,
       c.multi_threshold                 AS threshold,        -- K
       COUNT(DISTINCT s.signer)          AS n_valid,          -- N' = distinct VALID signers
       1                                 AS satisfied
FROM   signature s
JOIN   cap          c ON c.hash = s.target AND c.is_multi = 1
JOIN   multi_signer m ON m.cap_hash = s.target AND m.signer = s.signer   -- signer ∈ signers[]
JOIN   peer         p ON p.hash = s.signer                              -- signer resolves (§3.5)
WHERE  s.target = :cap_hash
  AND  ed25519_verify(p.public_key, s.target, s.sig) = 1                -- §5.5 verify_signature INLINE
GROUP  BY s.target
HAVING COUNT(DISTINCT s.signer) >= c.multi_threshold;                   -- the K-of-N threshold gate
