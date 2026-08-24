-- resolve.sql — §6.6 Path Dispatch: handler resolution as the VISIBLE longest-prefix walk.
--
-- WRAPPER-GUARD (profile [authored].handler_resolution = "sql-longest-prefix"): the §6.6
-- resolution is authored AS this query — NOT hidden behind a host resolve() if-ladder. The
-- spec walks path segments backward, checking each prefix in the tree for a system/handler
-- entity; "the first match is the longest prefix — depth gives priority naturally." That is
-- exactly ORDER BY length(path) DESC LIMIT 1 over the handler table: the relational statement
-- of "longest matching prefix wins". No match → zero rows → the host maps to 404 not_found.
--
-- Bind: :uri = the canonicalized absolute dispatch path (/{peer_id}/rest...).
-- The handler.path rows are the literal registration prefixes (§6.6 "Registration paths vs
-- spec-advertised patterns": the bound path is the literal prefix, no trailing /*).
--
-- Match predicate: a handler at prefix H governs :uri iff :uri == H (suffix "") OR :uri is
-- under H's subtree (:uri starts with H || '/'). GLOB H||'/*' expresses the subtree case;
-- the OR :uri = H arm is the exact-hit case. Both canonicalized-absolute already (§5.4).

SELECT path                         AS handler_pattern,
       substr(:uri, length(path)+1) AS suffix          -- §6.6 the remainder after the handler location
FROM   handler
WHERE  :uri = path
   OR  :uri GLOB path || '/*'
ORDER  BY length(path) DESC         -- longest prefix first — the whole of §6.6 in one clause
LIMIT  1;
