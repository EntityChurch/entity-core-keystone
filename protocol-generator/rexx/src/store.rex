/* entity-core-protocol-rexx — storage (foundation, §1.7): the two layers.
 *
 *   Content Store: hash -> entity   (immutable, content-addressed, dedup)
 *   Entity Tree:   path -> hash      (mutable location index)
 *
 * In-memory minimal impl over Regina compound variables (stems). A store is a HANDLE
 * ("store<n>") into the global EC. stem, so a process may hold several stores (the
 * two-store foundation self-test) without a class/object system. Keys use distinctive
 * literal tail components (!SC/!ST/...) so a caller variable can never shadow them; the
 * handle + a NUL-free path/hex are value-substituted tail components.
 *
 *   EC.!SC.h.hex   -> entity        (content store; hex = lowercase content_hash)
 *   EC.!ST.h.path  -> hex | ''      (entity tree; '' == unbound)
 *   EC.!SPATHS.h   -> packed list of every path ever bound (for the listing walk)
 *
 * Path/hex are lowercase-hex + case-sensitive base58 (A-CL-009): C2X yields UPPERCASE
 * hex, so we lowercase it to match §3.4/§3.5 tree-path convention.
 *
 * == §4.8 store data-race safety — STRUCTURAL. The peer is one Rexx process driven by
 * a single-threaded serve loop (one frame dispatched to completion before the next),
 * so these stems are never accessed concurrently — the §4.8 MUST holds by construction.
 *
 * == EMIT PATHWAY (§6.10 / §6.13(c)) — the Core Extensibility Boundary. Tree/content
 * writes bump a per-store event counter (live even with ZERO consumers) AND, if a
 * consumer routine name is registered, invoke it — so a future extension observes
 * store writes WITHOUT rebuilding the peer.
 */

Hexlc: procedure
  parse arg b
  return translate(c2x(b), 'abcdef', 'ABCDEF')

Store_New: procedure expose EC.
  EC.!STORE_CTR = EC.!STORE_CTR + 1
  h = 'store' || EC.!STORE_CTR
  EC.!SPATHS.h = ''
  EC.!STREE_EVENTS.h = 0
  EC.!SCONTENT_EVENTS.h = 0
  EC.!STREE_CONSUMER.h = ''
  EC.!SCONTENT_CONSUMER.h = ''
  return h

Store_RegisterTreeConsumer: procedure expose EC.
  parse arg h, routine
  EC.!STREE_CONSUMER.h = routine
  return
Store_RegisterContentConsumer: procedure expose EC.
  parse arg h, routine
  EC.!SCONTENT_CONSUMER.h = routine
  return
Store_TreeEventCount: procedure expose EC.
  parse arg h
  return EC.!STREE_EVENTS.h
Store_ContentEventCount: procedure expose EC.
  parse arg h
  return EC.!SCONTENT_EVENTS.h

/* ── content store (§6.10 Store step: event only when the entity is NEW) ── */
Store_PutEntity: procedure expose EC.
  parse arg h, e
  hex = Hexlc(Ent_Hash(e))
  if EC.!SC_HAS.h.hex == 1 then return
  EC.!SC_HAS.h.hex = 1
  EC.!SC.h.hex = e
  EC.!SCONTENT_EVENTS.h = EC.!SCONTENT_EVENTS.h + 1
  if EC.!SCONTENT_CONSUMER.h \== '' then interpret 'call' EC.!SCONTENT_CONSUMER.h
  return

Store_GetByHash: procedure expose EC.
  parse arg h, hbytes
  hex = Hexlc(hbytes)
  if EC.!SC_HAS.h.hex == 1 then return EC.!SC.h.hex
  return ''

/* ── entity tree (§6.10 Bind step: event when the binding at the path changes) ── */
Store_Bind: procedure expose EC.
  parse arg h, path, e
  call Store_PutEntity h, e
  next = Hexlc(Ent_Hash(e))
  if EC.!ST_HAS.h.path == 1 then prev = EC.!ST.h.path
  else do
    prev = ''
    EC.!ST_HAS.h.path = 1
    EC.!SPATHS.h = Lst_Add(EC.!SPATHS.h, path)
  end
  EC.!ST.h.path = next
  if next \== prev then do
    EC.!STREE_EVENTS.h = EC.!STREE_EVENTS.h + 1
    if EC.!STREE_CONSUMER.h \== '' then interpret 'call' EC.!STREE_CONSUMER.h
  end
  return

Store_Unbind: procedure expose EC.
  parse arg h, path
  if EC.!ST_HAS.h.path \== 1 then return
  if EC.!ST.h.path == '' then return
  EC.!ST.h.path = ''
  EC.!STREE_EVENTS.h = EC.!STREE_EVENTS.h + 1
  if EC.!STREE_CONSUMER.h \== '' then interpret 'call' EC.!STREE_CONSUMER.h
  return

Store_HashAt: procedure expose EC.
  parse arg h, path
  if EC.!ST_HAS.h.path == 1 then return EC.!ST.h.path
  return ''

Store_GetAt: procedure expose EC.
  parse arg h, path
  if EC.!ST_HAS.h.path \== 1 then return ''
  hex = EC.!ST.h.path
  if hex == '' then return ''
  if EC.!SC_HAS.h.hex == 1 then return EC.!SC.h.hex
  return ''

/* one-level listing under `prefix` (trailing slash added if absent), returned as a
 * packed list of "segment<TAB>hashHexOrEmpty<TAB>hasChildren" rows sorted by segment
 * (§3.9). '09'x (TAB) is the row field separator (paths never contain it). */
Store_Listing: procedure expose EC.
  parse arg h, prefix
  if right(prefix, 1) \== '/' then p = prefix || '/'
  else p = prefix
  plen = length(p)
  EC.!LACC.0 = 0                                  /* reset the listing scratch stem */
  paths = EC.!SPATHS.h
  n = Lst_Count(paths)
  do i = 1 to n
    path = Lst_Item(paths, i)
    if EC.!ST.h.path == '' then iterate          /* unbound */
    if length(path) <= plen then iterate
    if substr(path, 1, plen) \== p then iterate
    rest = substr(path, plen + 1)
    slash = pos('/', rest)
    if slash > 0 then do
      seg = substr(rest, 1, slash - 1)
      call _list_acc seg, '', 1
    end
    else call _list_acc rest, EC.!ST.h.path, 0
  end
  /* sort segments + emit rows */
  m = EC.!LACC.0
  do i = 1 to m
    ii = i
    ord.ii = i
  end
  do i = 2 to m
    j = i
    do while j > 1
      jm = j - 1
      a = ord.j; b = ord.jm
      if EC.!LSEG.a << EC.!LSEG.b then do; ord.j = b; ord.jm = a; j = jm; end
      else leave
    end
  end
  out = ''
  do i = 1 to m
    k = ord.i
    out = Lst_Add(out, EC.!LSEG.k || '09'x || EC.!LHASH.k || '09'x || EC.!LCHILD.k)
  end
  return out

/* accumulate a listing row keyed by segment (merge hasChildren / hash). Uses the
 * EC.!LACC.* scratch stem — the caller (Store_Listing) resets it via EC.!LACC.0 = 0. */
_list_acc: procedure expose EC.
  parse arg seg, hashhex, haschild
  m = EC.!LACC.0
  do i = 1 to m
    if EC.!LSEG.i == seg then do
      if haschild then EC.!LCHILD.i = 1
      if hashhex \== '' then EC.!LHASH.i = hashhex
      return
    end
  end
  m = m + 1
  EC.!LACC.0 = m
  EC.!LSEG.m = seg
  EC.!LHASH.m = hashhex
  EC.!LCHILD.m = haschild
  return
