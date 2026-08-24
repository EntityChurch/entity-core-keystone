## Content-addressed store + tree index (§6.5 verify_ctx surface, §4.8/§7b
## store-safety).
##
## §7b store-safety is STRUCTURAL on this substrate (profile [async]): the peer
## runs a single-threaded `asyncdispatch` event loop, so every store mutation is
## serialized by the one event thread — there is no concurrent writer, hence no
## data race, hence NO lock (the PHP/Tcl/Dart event-loop class, not the
## raw-thread RW-lock/sharded class). The store is a plain `std/tables Table`.
## (A --threads:on variant would need a lock; that is the out-of-scope substrate,
## A-NIM-006.)
##
## SPDX-License-Identifier: Apache-2.0

import std/[tables, options, strutils]
import ./model

type
  Store* = ref object
    content*: Table[string, Entity]   ## content-addressed: key = hexLower(hash)
    tree*: Table[string, Entity]      ## path-addressed: key = absolute tree path

proc newStore*(): Store =
  Store(content: initTable[string, Entity](), tree: initTable[string, Entity]())

proc put*(s: Store; e: Entity) =
  ## Idempotent content-store put (keyed on content_hash).
  s.content[hexLower(e.hash)] = e

proc getHash*(s: Store; h: openArray[byte]): Option[Entity] =
  let k = hexLower(h)
  if s.content.hasKey(k): some(s.content[k]) else: none(Entity)

proc bindAt*(s: Store; path: string; e: Entity) =
  ## Bind an entity at an absolute tree path (§6.6 dispatch surface).
  s.tree[path] = e
  s.put(e)

proc getAt*(s: Store; path: string): Option[Entity] =
  if s.tree.hasKey(path): some(s.tree[path]) else: none(Entity)

proc removeAt*(s: Store; path: string) =
  ## Remove a tree binding (§6.3 deletion). Content-store entries are left (§6.5).
  s.tree.del(path)

type TreeEntry* = object
  name*: string
  hash*: seq[byte]
  hasHash*: bool
  hasChildren*: bool

proc listChildren*(s: Store; prefix: string): seq[TreeEntry] =
  ## Direct children of an absolute tree prefix (§6.3 listing). A child bound to an
  ## entity carries its hash; a child that only prefixes deeper paths is a pure
  ## branch (hasChildren, no hash). Order is by first appearance (deterministic
  ## enough for the listing shape — the validator matches on membership, not order).
  var pre = prefix
  if not pre.endsWith("/"): pre.add "/"
  var idx = initTable[string, int]()
  for path, ent in s.tree:
    if path.len > pre.len and path.startsWith(pre):
      let rest = path[pre.len .. ^1]
      let slash = rest.find('/')
      let name = if slash < 0: rest else: rest[0 ..< slash]
      let deeper = slash >= 0
      if not idx.hasKey(name):
        idx[name] = result.len
        result.add TreeEntry(name: name)
      let i = idx[name]
      if deeper:
        result[i].hasChildren = true
      else:
        result[i].hasHash = true
        result[i].hash = ent.hash
