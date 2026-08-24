/* entity-core-protocol-rexx — packed-list collection helper.
 *
 * Classic Rexx has no list/array VALUE type (only stems, which are compound
 * variables that cannot be passed by value or returned). The peer layers (S3) pass
 * "lists" — the envelope `included` set, a token's grants, a chain of caps — through
 * many functions, so we need a list that IS a plain string. A packed list stores each
 * item length-prefixed (4-byte big-endian) so items may contain arbitrary bytes
 * (entities, TVs) and stay self-delimiting; the empty string is the empty list. All
 * ops are pure (return a NEW list) — no aliasing surprises across the value-copy calls.
 */

/* Lst_Add: append item -> a new list. */
Lst_Add: procedure
  parse arg lst, item
  return lst || d2c(length(item), 4) || item

/* Lst_Count: number of items in the packed list. */
Lst_Count: procedure
  parse arg lst
  numeric digits 20
  n = 0; p = 1; ll = length(lst)
  do while p <= ll
    il = c2d(substr(lst, p, 4))
    p = p + 4 + il
    n = n + 1
  end
  return n

/* Lst_Item: the i-th item (1-indexed), or '' if out of range. */
Lst_Item: procedure
  parse arg lst, i
  numeric digits 20
  p = 1; ll = length(lst); k = 0
  do while p <= ll
    il = c2d(substr(lst, p, 4))
    k = k + 1
    if k == i then return substr(lst, p + 4, il)
    p = p + 4 + il
  end
  return ''
