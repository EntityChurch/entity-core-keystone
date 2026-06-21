/-
  Peer assembly — bootstrap (§6.9), the system handlers (§6.2: connect, tree,
  handler, capability), the dispatch chain (§6.5), and per-connection state. The
  unproven IO shell; the §5 verdict it consults is the PURE `Capability` core.

  ── The resolve layer (the pure/shell boundary) ──────────────────────────────
  `verifyRequest` is where the factoring lands: the shell resolves the chain
  (parent walk via store∪included), resolves each link's §5.5a granter frame,
  verifies each signature over the FFI, and checks grantee resolvability — turning
  the wire envelope into a `Capability.ResolvedChain`. It samples `now` ONCE
  (Net.nowMs — A-LEAN-1 realized: a single time, not per-link), then calls the
  pure total `Capability.verifyChain`. Revocation (store read) + the §5.2 author
  authn (crypto) stay in this shell (A-LEAN-2). The pure core decides ALLOW/DENY/
  unresolvable; the shell maps to 403/401/400.
-/
import EntityCore.Capability
import EntityCore.Identity
import EntityCore.Store
import EntityCore.Wire
import EntityCore.Net
import EntityCore.TypeDefs

namespace EntityCore.Peer

open EntityCore (Value)
open EntityCore.Model
open EntityCore.Store (Store)

structure Peer where
  identity : EntityCore.Identity.Self
  store : Store
  localPeer : String
  openGrants : Bool
  conformance : Bool

/-- Per-connection state (§4.2). -/
structure Conn where
  established : IO.Ref Bool
  issuedNonce : IO.Ref (Option ByteArray)
  helloPeerId : IO.Ref (Option String)
  outbound : IO.Ref (Option (Envelope → IO (Option Envelope)))
  outCounter : IO.Ref Nat

def Conn.new : IO Conn := do
  pure { established := ← IO.mkRef false, issuedNonce := ← IO.mkRef none,
         helloPeerId := ← IO.mkRef none, outbound := ← IO.mkRef none,
         outCounter := ← IO.mkRef 0 }

/-- A handler outcome: status, result entity, and bundled protocol entities. -/
structure Outcome where
  status : Nat
  result : Entity
  included : List (ByteArray × Entity)

def ok (result : Entity) (included : List (ByteArray × Entity) := []) : Outcome :=
  { status := 200, result, included }
def err (status : Nat) (code : String) (message : Option String := none) : Outcome :=
  { status, result := EntityCore.Wire.errorResult code message, included := [] }

-- ── small helpers ─────────────────────────────────────────────────────────────

/-- Parse an entity-valued field (a nested CBOR entity). -/
def entityField (e : Entity) (key : String) : Option Entity := (field e key).bind ofCbor

/-- String path canonicalization for store keys (§1.4): relative → /{local}/path. -/
def canonPath (localPeer path : String) : String :=
  if path.startsWith "/" then path else "/" ++ localPeer ++ "/" ++ path

def textListV (v : Value) : List String :=
  match v with
  | .array xs => xs.filterMap (fun x => match x with | .text s => some s | _ => none)
  | _ => []

-- ── grant construction (§4.4 / §5.4) ──────────────────────────────────────────

def scopeV (incl : List String) (excl : List String) : Value :=
  .map ((.text "include", .array (incl.map (.text ·))) ::
        (match excl with | [] => [] | _ => [(.text "exclude", .array (excl.map (.text ·)))]))

def grantV (handlers resources operations : List String) (peers : Option (List String) := none) : Value :=
  .map ([(.text "handlers", scopeV handlers []),
         (.text "resources", scopeV resources []),
         (.text "operations", scopeV operations [])]
        ++ (match peers with | some p => [(.text "peers", scopeV p [])] | none => []))

/-- The §4.4 discovery floor: every authenticated identity gets at least this. -/
def discoveryFloor : List Value :=
  [ grantV ["system/tree"] ["system/type/*", "system/handler/*"] ["get"],
    grantV ["system/capability"] [] ["request"] ]

/-- Wide-open admin scope — the degenerate `default → *` (= retired --debug-open-grants). -/
def openGrantsScope : List Value :=
  [ grantV ["*"] ["*", "/*/*"] ["*"] (some ["*"]) ]

/-- Full owner authority over the local namespace `/{peer_id}/*` (§6.9a). -/
def ownerGrants (peer : Peer) : List Value :=
  [ grantV ["*"] ["*"] ["*"] (some [peer.localPeer]) ]

-- ── token minting (§6.9 / §6.2) ───────────────────────────────────────────────

/-- Mint a root capability token granted by us to `granteeHash`; sign it. -/
def mintToken (peer : Peer) (granteeHash : ByteArray) (parent : Option ByteArray)
    (grants : List Value) : IO (Entity × Entity) := do
  let now ← EntityCore.Net.nowMs ()
  let data := [(.text "granter", .bytes peer.identity.identityHash),
               (.text "grantee", .bytes granteeHash),
               (.text "grants", .array grants),
               (.text "created_at", .uint now)]
              ++ (match parent with | some p => [(.text "parent", .bytes p)] | none => [])
  let token := make "system/capability/token" (.map data)
  pure (token, EntityCore.Identity.signEntity peer.identity token)

-- ── §6.9a seed policy ─────────────────────────────────────────────────────────

/-- Raw grants from a seed-policy entry (§6.9a.0 detached-sig token: verify the
sig at the §3.5 pointer; or a policy-entry scope template). -/
def seedEntryGrants (peer : Peer) (e : Entity) : IO (List Value) := do
  let grantsOf : List Value := match field e "grants" with | some (.array l) => l | _ => []
  if e.typ == "system/capability/token" then
    let sigPath := "/" ++ peer.localPeer ++ "/system/signature/" ++ hex e.hash
    match ← EntityCore.Store.getAt peer.store sigPath with
    | some sgn => if EntityCore.Identity.verifySignature sgn peer.identity.peerEntity then pure grantsOf else pure []
    | none => pure []
  else if e.typ == "system/capability/policy-entry" then pure grantsOf
  else pure []

/-- §6.9a authenticate-time derivation: dual-form lookup (hex → Base58 → default),
then UNION the matched scope with the §4.4 discovery floor (v7.62 §8). -/
def deriveSeedGrants (peer : Peer) (remotePeer : Entity) (remotePeerId : String) : IO (List Value) := do
  let base := "/" ++ peer.localPeer ++ "/system/capability/policy/"
  let entry ← do
    match ← EntityCore.Store.getAt peer.store (base ++ hex remotePeer.hash) with
    | some e => pure (some e)
    | none => match ← EntityCore.Store.getAt peer.store (base ++ remotePeerId) with
              | some e => pure (some e)
              | none => EntityCore.Store.getAt peer.store (base ++ "default")
  let policyGrants ← match entry with | none => pure [] | some e => seedEntryGrants peer e
  if policyGrants.isEmpty then pure discoveryFloor else pure (discoveryFloor ++ policyGrants)

-- ── resolution (included ∪ store) ─────────────────────────────────────────────

def resolveHash (peer : Peer) (env : Envelope) (h : ByteArray) : IO (Option Entity) := do
  match includedGet env h with
  | some e => pure (some e)
  | none => EntityCore.Store.getByHash peer.store h

/-- Find a `system/signature` in `included` targeting `target`. -/
def findSignature (env : Envelope) (target : ByteArray) : Option Entity :=
  (env.included.find? (fun ke =>
    ke.2.typ == "system/signature"
    && (match bytesField ke.2 "target" with | some t => baEq t target | none => false))).map (·.2)

/-- Find ALL `system/signature` entities in `included` targeting `target` (the
§3.6 quorum needs every signature, not the first). -/
def findSignatures (env : Envelope) (target : ByteArray) : List Entity :=
  (env.included.filter (fun ke =>
    ke.2.typ == "system/signature"
    && (match bytesField ke.2 "target" with | some t => baEq t target | none => false))).map (·.2)

-- ── §5.5 resolve layer: build the ResolvedChain for the pure verdict ──────────

inductive ChainErr | unreachable | tooDeep

/-- Collect the authority chain leaf→root (§5.5), resolving parents via store∪
included; structural only (no sig work). `tooDeep` past 64, `unreachable` on a
missing parent. -/
partial def collectChain (peer : Peer) (env : Envelope) (cap : Entity) :
    IO (Except ChainErr (List Entity)) := do
  let rec go (current : Entity) (depth : Nat) (acc : List Entity) :
      IO (Except ChainErr (List Entity)) := do
    if depth > 64 then pure (.error .tooDeep)
    else
      let acc := current :: acc
      match bytesField current "parent" with
      | none => pure (.ok acc.reverse)
      | some ph => match ← resolveHash peer env ph with
                   | some parent => go parent (depth + 1) acc
                   | none => pure (.error .unreachable)
  go cap 0 []

/-- §5.5a per-link granter frame: no granter field → local (multisig M3 root);
single-sig granter resolves to its identity's peer_id; unresolvable / no pubkey
→ none (hard-fail). -/
def linkGranterPeer (peer : Peer) (env : Envelope) (cap : Entity) : IO (Option String) := do
  match bytesField cap "granter" with
  | none => pure (some peer.localPeer)
  | some gh => match ← resolveHash peer env gh with
               | some g => match bytesField g "public_key" with
                           | some pk => pure (some (EntityCore.Identity.peerIdOfPubkey pk))
                           | none => pure none
               | none => pure none

/-- Resolve one chain entity into a `Capability.ResolvedLink` (granter frame, sig
validity over the FFI, grantee resolvability). -/
def resolveLink (peer : Peer) (env : Envelope) (cap : Entity) : IO EntityCore.Capability.ResolvedLink := do
  let granterPeer ← linkGranterPeer peer env cap
  -- §5.5 signature: signer == granter, verify against the granter identity
  let sigValid ← do
    match bytesField cap "granter" with
    | some gh => match findSignature env cap.hash, ← resolveHash peer env gh with
                 | some sgn, some granter =>
                     let signerOk := match bytesField sgn "signer" with | some s => baEq s gh | none => false
                     pure (signerOk && EntityCore.Identity.verifySignature sgn granter)
                 | _, _ => pure false
    | none => pure false
  let granteeResolvable ← do
    match bytesField cap "grantee" with
    | some gh => pure (← resolveHash peer env gh).isSome
    | none => pure false
  let isMultiSig := match field cap "granter" with | some (.map _) => true | _ => false
  pure { entity := cap, granterPeer, sigValid, granteeResolvable, isMultiSig }

/-- Build the §5.5 / §3.6 root authority for the chain root: a single-granter root
resolves the granter identity → its peer_id == localPeer (single-sig); a §3.6
multi-granter root parses {signers, threshold} + resolves each signer's peer_id
(M6 local-in-quorum) and counts valid signatures over the cap content hash (M4),
with M3 structure carried as fields for the pure `multiSigRootOk` gate. -/
def rootAuthorityOf (peer : Peer) (env : Envelope) (root : Entity) : IO EntityCore.Capability.RootAuthority := do
  match field root "granter" with
  | some (.map _) => do
      -- §3.6 multi-granter: parse signers + threshold, resolve each signer.
      let mg := field root "granter"
      let signersHashes : List ByteArray :=
        match mg.bind (fun g => mapGet g "signers") with
        | some (.array xs) => xs.filterMap (fun x => match x with | .bytes b => some b | _ => none)
        | _ => []
      let threshold : Nat :=
        match mg.bind (fun g => mapGet g "threshold") with | some (.uint t) => t.toNat | _ => 0
      let parentNull := (bytesField root "parent").isNone
      let sigs := findSignatures env root.hash
      let signers ← signersHashes.mapM (fun sh => do
        let p ← resolveHash peer env sh
        let isLocal := match p with
          | some pe => (match bytesField pe "public_key" with
                        | some pk => EntityCore.Identity.peerIdOfPubkey pk == peer.localPeer
                        | none => false)
          | none => false
        let signed := match p with
          | some pe => sigs.any (fun sgn =>
              (match bytesField sgn "signer" with | some s => baEq s sh | none => false)
              && EntityCore.Identity.verifySignature sgn pe)
          | none => false
        pure ({ key := hex sh, isLocal, signed } : EntityCore.Capability.ResolvedSigner))
      pure (.multi signers threshold parentNull)
  | _ => do
      -- single-sig: existing behavior
      let isLocal ← (do
        match bytesField root "granter" with
        | some gh => match ← resolveHash peer env gh with
                     | some g => match bytesField g "public_key" with
                                 | some pk => pure (EntityCore.Identity.peerIdOfPubkey pk == peer.localPeer)
                                 | none => pure false
                     | none => pure false
        | none => pure false)
      pure (.single isLocal)

/-- §5.1 revocation marker check (leaf + chain root) — store read, the A-LEAN-2
boundary kept OUT of the pure verdict core. -/
def isRevoked (peer : Peer) (env : Envelope) (cap : Entity) : IO Bool := do
  let rootHash ← do
    match ← collectChain peer env cap with
    | .ok chain => pure ((chain.getLast? ).map (·.hash) |>.getD cap.hash)
    | .error _ => pure cap.hash
  let check (h : ByteArray) : IO Bool := do
    pure (← EntityCore.Store.getAt peer.store
      ("/" ++ peer.localPeer ++ "/system/capability/revocations/" ++ hex h)).isSome
  pure ((← check cap.hash) || (← check rootHash))

/-- §5.2 request verdict (the §4.6/F20 401-vs-403 split + 400 depth + the §5.5
401 unresolvable-grantee carve-out). -/
inductive ReqVerdict | allow | authnFail | authzDeny | chainTooDeep | unresolvableGrantee

/-- The resolve layer: envelope → ResolvedChain → pure `Capability.verifyChain`,
plus §5.2 author authn (crypto, shell) + revocation (store, shell). -/
def verifyRequest (peer : Peer) (env : Envelope) : IO ReqVerdict := do
  let exec := env.root
  -- §5.2 step 2: author authentication (signature over the exec) — 401 class.
  match findSignature env exec.hash with
  | none => pure .authnFail
  | some sgn =>
    let authorH := bytesField exec "author"
    let signerOk := match bytesField sgn "signer", authorH with
      | some s, some a => baEq s a | _, _ => false
    if !signerOk then pure .authnFail
    else match authorH.bind (includedGet env) with
    | none => pure .authnFail
    | some author =>
      if !EntityCore.Identity.verifySignature sgn author then pure .authnFail
      else
        -- §5.2 step 3: capability / chain — 403 class.
        match (bytesField exec "capability").bind (includedGet env) with
        | none => pure .authzDeny
        | some cap =>
          match ← collectChain peer env cap with
          | .error .tooDeep => pure .chainTooDeep         -- §4.10(b) → 400
          | .error .unreachable => pure .authzDeny        -- broken chain → 403
          | .ok chain =>
            let links ← chain.mapM (resolveLink peer env)
            let auth ← match chain.getLast? with
              | some root => rootAuthorityOf peer env root
              | none => pure (.single false)
            let now ← EntityCore.Net.nowMs ()
            match EntityCore.Capability.verifyChain { links, rootAuthority := auth } peer.localPeer now with
            | .unresolvableGrantee => pure .unresolvableGrantee   -- §5.5 401 carve-out
            | .deny => pure .authzDeny
            | .allow =>
              -- §5.2: grantee == author, then revocation (store).
              let granteeOk := match bytesField cap "grantee", authorH with
                | some g, some a => baEq g a | _, _ => false
              if !granteeOk then pure .authzDeny
              else if ← isRevoked peer env cap then pure .authzDeny
              else pure .allow

-- ── §6.13(b) handler-facing outbound dispatch ─────────────────────────────────

def outboundDispatch (peer : Peer) (conn : Conn) (uri operation : String) (params : Entity)
    (resource : Option Value) (capability granterPeer capabilitySignature : Entity) :
    IO (Option Envelope) := do
  match ← conn.outbound.get with
  | none => pure none
  | some send =>
    conn.outCounter.modify (· + 1)
    let requestId := s!"out-{← conn.outCounter.get}"
    let exec := EntityCore.Wire.makeExecute requestId uri operation params
                  peer.identity.identityHash capability.hash resource
    let execSig := EntityCore.Identity.signEntity peer.identity exec
    let included := [ (capability.hash, capability),
                      (granterPeer.hash, granterPeer),
                      (peer.identity.identityHash, peer.identity.peerEntity),
                      (capabilitySignature.hash, capabilitySignature),
                      (execSig.hash, execSig) ]
    send { root := exec, included }

-- ── connect handler (§4.1, §4.6) ──────────────────────────────────────────────

def connectHandler (peer : Peer) (conn : Conn) (exec : Entity)
    (included : List (ByteArray × Entity)) : IO Outcome := do
  let op := (textField exec "operation").getD ""
  match op with
  | "hello" =>
    if ← conn.established.get then pure (err 409 "connection_already_established")
    else do
      let params := entityField exec "params"
      let strArray (key : String) : Option (List String) :=
        match params.bind (fun p => field p key) with
        | some (.array l) => some (l.filterMap (fun x => match x with | .text s => some s | _ => none))
        | _ => none
      let hashOk := match strArray "hash_formats" with | some fmts => fmts.contains "ecfv1-sha256" | none => true
      let keyOk := match strArray "key_types" with | some kts => kts.contains "ed25519" | none => true
      if !hashOk then pure (err 400 "incompatible_hash_format")
      else if !keyOk then pure (err 400 "unsupported_key_type")
      else do
        conn.helloPeerId.set (params.bind (fun p => textField p "peer_id"))
        let nonce ← EntityCore.Net.randomBytes 32
        conn.issuedNonce.set (some nonce)
        let now ← EntityCore.Net.nowMs ()
        let hello := make "system/protocol/connect/hello"
          (.map [(.text "peer_id", .text peer.localPeer),
                 (.text "nonce", .bytes nonce),
                 (.text "protocols", .array [.text "entity-core/1.0"]),
                 (.text "timestamp", .uint now),
                 (.text "hash_formats", .array [.text "ecfv1-sha256"]),
                 (.text "key_types", .array [.text "ed25519"])])
        pure (ok hello)
  | "authenticate" =>
    if ← conn.established.get then pure (err 409 "connection_already_established")
    else match ← conn.issuedNonce.get with
    | none => pure (err 401 "invalid_nonce")
    | some issued => match entityField exec "params" with
      | none => pure (err 401 "authentication_failed")
      | some auth =>
        -- §4.6 hardening (AGILITY-UNKNOWN-1): reject an unsupported key_type carried
        -- in the field, a non-32-byte public_key, or the claimed peer_id's leading
        -- key_type varint (the 0xFD case — the field still says "ed25519").
        let badKeyType := (textField auth "key_type").isSome && textField auth "key_type" != some "ed25519"
        let badPubLen := match bytesField auth "public_key" with | some p => p.size != 32 | none => false
        let badPidKeyType := match textField auth "peer_id" with
          | some pid => match EntityCore.Identity.peerIdKeyType pid with | some kt => kt != 1 | none => false
          | none => false
        if badKeyType || badPubLen || badPidKeyType then pure (err 400 "unsupported_key_type")
        else
          let echoed := bytesField auth "nonce"
          let claimedPeer := textField auth "peer_id"
          if (match echoed with | some e => !baEq e issued | none => true) then pure (err 401 "invalid_nonce")
          else match bytesField auth "public_key" with
          | none => pure (err 401 "authentication_failed")
          | some publicKey =>
            -- step 2: proof of possession
            let sigOk := match findSignature { root := auth, included } auth.hash with
              | some sgn => match bytesField sgn "signature" with
                            | some sb => EntityCore.Crypto.ed25519Verify publicKey auth.hash sb
                            | none => false
              | none => false
            if !sigOk then pure (err 401 "authentication_failed")
            -- step 3: identity binding
            else if claimedPeer != some (EntityCore.Identity.peerIdOfPubkey publicKey) then
              pure (err 401 "identity_mismatch")
            else if (← conn.helloPeerId.get).isSome && (← conn.helloPeerId.get) != claimedPeer then
              pure (err 401 "identity_mismatch")
            else do
              let remotePeer := EntityCore.Identity.peerEntityOfPubkey publicKey
              let grants ← deriveSeedGrants peer remotePeer (claimedPeer.getD "")
              let (token, sgn) ← mintToken peer remotePeer.hash none grants
              conn.established.set true
              let grantResult := make "system/capability/grant" (.map [(.text "token", .bytes token.hash)])
              pure (ok grantResult [ (token.hash, token),
                                     (peer.identity.identityHash, peer.identity.peerEntity),
                                     (sgn.hash, sgn) ])
  | other => pure (err 501 "unsupported_operation" (some s!"connect: {other}"))

-- ── tree handler (§6.3) ───────────────────────────────────────────────────────

def resourceTarget (exec : Entity) : Option String :=
  match field exec "resource" with
  | some r => match mapGet r "targets" with
              | some (.array (.text t :: _)) => some t | _ => none
  | none => none

/-- §1.4/§5.4 path validation before canonicalize. -/
def pathFlexOk (target : String) : Bool :=
  if target.toList.contains (Char.ofNat 0) then false
  else
    let segs0 := target.splitOn "/"
    let res : Bool × List String :=
      if target.startsWith "/" then
        match segs0 with
        | "" :: first :: _ => (EntityCore.Capability.isPeerId first, segs0.drop 1)
        | _ => (false, segs0)
      else (true, segs0)
    if !res.1 then false
    else
      let body := match res.2.reverse with | "" :: rest => rest.reverse | _ => res.2
      body.all (fun s => s != "" && s != "." && s != "..")

def isDeletionMarker (peer : Peer) (h : ByteArray) : IO Bool := do
  match ← EntityCore.Store.getByHash peer.store h with
  | some e => pure (e.typ == "system/deletion-marker")
  | none => pure false

/-- One-level listing under `pfx` (§3.9): (segment, bound hash?, hasChildren). -/
def treeListing (snapshot : List (String × ByteArray)) (pfx0 : String) :
    List (String × Option ByteArray × Bool) :=
  let pfx := if pfx0.endsWith "/" then pfx0 else pfx0 ++ "/"
  let plen := pfx.length
  -- accumulate per child-segment: (boundHash?, deeper)
  let upd (acc : List (String × Option ByteArray × Bool)) (seg : String)
      (h : Option ByteArray) (deeper : Bool) : List (String × Option ByteArray × Bool) :=
    match acc.find? (·.1 == seg) with
    | some (_, h0, d0) =>
        let h' := match h with | some _ => h | none => h0
        (seg, h', d0 || deeper) :: acc.filter (·.1 != seg)
    | none => (seg, h, deeper) :: acc
  let folded := snapshot.foldl (fun acc (path, hash) =>
    if path.length > plen && path.startsWith pfx then
      let rest := (path.drop plen).toString
      match rest.splitOn "/" with
      | [seg] => upd acc seg (some hash) false           -- direct child, bound
      | seg :: _ => upd acc seg none true                -- deeper child path
      | [] => acc
    else acc) []
  folded.toArray.qsort (fun a b => a.1 < b.1) |>.toList

def buildListing (peer : Peer) (path : String) : IO Outcome := do
  let snap ← EntityCore.Store.treeSnapshot peer.store
  let entries0 := treeListing snap path
  -- filter deletion-marker-bound leaves (CORE-TREE-DELETE-1)
  let entries ← entries0.filterM (fun (_, hash, hasChildren) => do
    match hash with
    | some h => if !hasChildren && (← isDeletionMarker peer h) then pure false else pure true
    | none => pure true)
  let entryMap := entries.map (fun (seg, hash, hasChildren) =>
    (Value.text seg,
     toCbor (make "system/tree/listing-entry"
       (.map ((.text "has_children", .bool hasChildren) ::
              (match hash with | some h => [(.text "hash", .bytes h)] | none => []))))))
  pure (ok (make "system/tree/listing"
    (.map [(.text "path", .text path),
           (.text "entries", .map entryMap),
           (.text "count", .uint (UInt64.ofNat entries.length)),
           (.text "offset", .uint 0)])))

def treeHandler (peer : Peer) (exec : Entity) : IO Outcome := do
  let op := (textField exec "operation").getD ""
  let tgt := resourceTarget exec
  match op, tgt with
  | "get", none => buildListing peer ("/" ++ peer.localPeer ++ "/")
  | "get", some target =>
    if !pathFlexOk target then pure (err 400 "invalid_path" (some target))
    else if target == "" || target.endsWith "/" then
      buildListing peer (canonPath peer.localPeer target)
    else do
      let path := canonPath peer.localPeer target
      match ← EntityCore.Store.getAt peer.store path with
      | some e =>
        let mode := (entityField exec "params").bind (fun p => textField p "mode")
        if mode == some "hash" then pure (ok (make "system/hash" (.bytes e.hash)))
        else pure (ok e)
      | none => pure (err 404 "not_found" (some path))
  | "put", some target =>
    if !pathFlexOk target then pure (err 400 "invalid_path" (some target))
    else do
      let path := canonPath peer.localPeer target
      let params := entityField exec "params"
      let entity := params.bind (fun p => entityField p "entity")
      let expected := params.bind (fun p => bytesField p "expected_hash")
      let current ← EntityCore.Store.hashAt peer.store path
      let zero33 := ByteArray.mk (List.replicate 33 (0 : UInt8)).toArray
      let casOk := match expected with
        | none => true
        | some h => if baEq h zero33 then current.isNone
                    else match current with | some c => baEq c h | none => false
      if !casOk then pure (err 409 "hash_mismatch" (some path))
      else match entity with
           | some e => do EntityCore.Store.bind peer.store path e
                          pure (ok (make "system/hash" (.bytes e.hash)))
           | none => pure (err 400 "unexpected_params" (some "put: missing entity"))
  | "put", none => pure (err 400 "ambiguous_resource" (some "tree: missing resource target"))
  | other, _ => pure (err 501 "unsupported_operation" (some s!"tree: {other}"))

-- ── capability handler (§6.2) ─────────────────────────────────────────────────

def isZeroHash (h : ByteArray) : Bool := h.data.all (· == 0)

def reqGrantsOf (params : Option Entity) : List Value :=
  match params.bind (fun p => field p "grants") with | some (.array l) => l | _ => []

def mintBounded (peer : Peer) (callerCap : Option Entity) (reqGrants : List Value)
    (granteeHash : ByteArray) (parent : Option ByteArray) : IO Outcome := do
  let bounded := match callerCap with
    | none => false
    | some cap =>
        let parentGrants := EntityCore.Capability.grantsOfToken cap
        reqGrants.all (fun cg =>
          let c := EntityCore.Capability.parseGrant cg
          parentGrants.any (fun pg =>
            EntityCore.Capability.grantSubset peer.localPeer peer.localPeer peer.localPeer c pg))
  if !bounded then pure (err 403 "scope_exceeds_authority")
  else do
    let (token, sgn) ← mintToken peer granteeHash parent reqGrants
    pure (ok (make "system/capability/grant" (.map [(.text "token", .bytes token.hash)]))
             [(token.hash, token), (peer.identity.identityHash, peer.identity.peerEntity), (sgn.hash, sgn)])

def capabilityHandler (peer : Peer) (exec : Entity) (callerCap : Option Entity) : IO Outcome := do
  let op := (textField exec "operation").getD ""
  let params := entityField exec "params"
  let author := bytesField exec "author"
  match op with
  | "request" =>
    (match author with
     | none => pure (err 403 "capability_denied")
     | some granteeHash => mintBounded peer callerCap (reqGrantsOf params) granteeHash none)
  | "delegate" =>
    (match params.bind (fun p => bytesField p "parent") with
     | none => pure (err 400 "unexpected_params" (some "delegate: parent required"))
     | some ph =>
       if isZeroHash ph then pure (err 400 "unexpected_params" (some "delegate: zero parent"))
       else if author != some peer.identity.identityHash then
         pure (err 501 "unsupported_operation" (some "delegate: same-peer-only in v1"))
       else match author with
            | none => pure (err 403 "capability_denied")
            | some granteeHash => mintBounded peer callerCap (reqGrantsOf params) granteeHash (some ph))
  | "revoke" =>
    (match params.bind (fun p => bytesField p "token") with
     | none => pure (err 400 "unexpected_params" (some "revoke: missing token"))
     | some tokenH =>
       if isZeroHash tokenH then pure (err 400 "unexpected_params" (some "revoke: zero token"))
       else do
         let now ← EntityCore.Net.nowMs ()
         let marker := make "system/capability/revocation"
           (.map [(.text "token", .bytes tokenH), (.text "revoked_at", .uint now)])
         EntityCore.Store.bind peer.store
           ("/" ++ peer.localPeer ++ "/system/capability/revocations/" ++ hex tokenH) marker
         pure (ok EntityCore.Wire.emptyParams))
  | "configure" =>
    (match params.bind (fun p => textField p "peer_pattern") with
     | none => pure (err 400 "unexpected_params" (some "configure: missing peer_pattern"))
     | some pp =>
       let isHex := pp.length == 66 && pp.toList.all (fun c => (c ≥ '0' && c ≤ '9') || (c ≥ 'a' && c ≤ 'f'))
       if !(pp == "default" || isHex || EntityCore.Capability.isPeerId pp) then
         pure (err 400 "invalid_peer_pattern" (some pp))
       else match params with
            | some p => do
                EntityCore.Store.bind peer.store ("/" ++ peer.localPeer ++ "/system/capability/policy/" ++ pp) p
                pure (ok EntityCore.Wire.emptyParams)
            | none => pure (err 400 "unexpected_params"))
  | other => pure (err 501 "unsupported_operation" (some s!"capability: {other}"))

-- ── handlers handler (§6.13(a)) — register/unregister ─────────────────────────

def registerPattern (exec : Entity) : Except Outcome String :=
  match resourceTarget exec with
  | none => .error (err 400 "ambiguous_resource" (some "register/unregister require exactly one resource target"))
  | some target =>
    let pfx := "system/handler/"
    if !target.startsWith pfx || target.length == pfx.length then
      .error (err 400 "invalid_resource" (some "resource target MUST be system/handler/{pattern}"))
    else .ok (target.drop pfx.length).toString

def register (peer : Peer) (exec : Entity) : IO Outcome := do
  match registerPattern exec with
  | .error e => pure e
  | .ok pattern => match entityField exec "params" with
    | none => pure (err 400 "unexpected_params" (some "register: missing params"))
    | some req =>
      if req.typ != "system/handler/register-request" then
        pure (err 400 "unexpected_params" (some s!"register expects register-request, got {req.typ}"))
      else do
        let manifest := (field req "manifest").getD (.map [])
        let name := match mapGet manifest "name" with | some (.text s) => s | _ => pattern
        let operations := (mapGet manifest "operations").getD (.map [])
        let expressionPath := match mapGet manifest "expression_path" with | some (.text s) => some s | _ => none
        let internalScope := mapGet manifest "internal_scope"
        let grantScope : List Value := match field req "requested_scope", internalScope with
          | some (.array l), _ => l
          | _, some (.array l) => l
          | _, _ => []
        let interfaceRel := "system/handler/" ++ pattern
        let abs (rel : String) : String := "/" ++ peer.localPeer ++ "/" ++ rel
        -- (1) handler manifest at the pattern path
        let handlerE := make "system/handler"
          (.map ((.text "interface", .text interfaceRel) ::
                 (match expressionPath with | some p => [(.text "expression_path", .text p)] | none => [])
                 ++ (match internalScope with | some s => [(.text "internal_scope", s)] | none => [])))
        EntityCore.Store.bind peer.store (abs pattern) handlerE
        -- (2) associated types
        (match field req "types" with
         | some (.map kvs) => kvs.forM (fun kv =>
             match kv.1 with
             | .text tn => EntityCore.Store.bind peer.store (abs ("system/type/" ++ tn)) (make "system/type" kv.2)
             | _ => pure ())
         | _ => pure ())
        -- (3) self-issued signed grant + (4) grant-signature at the §3.5 pointer
        let (token, sgn) ← mintToken peer peer.identity.identityHash none grantScope
        EntityCore.Store.bind peer.store (abs ("system/capability/grants/" ++ pattern)) token
        EntityCore.Store.bind peer.store (abs ("system/signature/" ++ hex token.hash)) sgn
        -- (5) handler interface entity (discovery index)
        let ifaceE := make "system/handler/interface"
          (.map [(.text "pattern", .text pattern), (.text "name", .text name), (.text "operations", operations)])
        EntityCore.Store.bind peer.store (abs interfaceRel) ifaceE
        pure (ok (make "system/handler/register-result"
          (.map [(.text "pattern", .text pattern), (.text "grant", token.data)])))

def unregister (peer : Peer) (exec : Entity) : IO Outcome := do
  match registerPattern exec with
  | .error e => pure e
  | .ok pattern => do
    let abs (rel : String) : String := "/" ++ peer.localPeer ++ "/" ++ rel
    match ← EntityCore.Store.getAt peer.store (abs ("system/capability/grants/" ++ pattern)) with
    | some g => do
        EntityCore.Store.unbind peer.store (abs ("system/signature/" ++ hex g.hash))
        EntityCore.Store.unbind peer.store (abs ("system/capability/grants/" ++ pattern))
    | none => pure ()
    EntityCore.Store.unbind peer.store (abs pattern)
    EntityCore.Store.unbind peer.store (abs ("system/handler/" ++ pattern))
    pure (ok EntityCore.Wire.emptyParams)

def handlersHandler (peer : Peer) (exec : Entity) : IO Outcome := do
  match (textField exec "operation").getD "" with
  | "register" => register peer exec
  | "unregister" => unregister peer exec
  | other => pure (err 501 "unsupported_operation" (some s!"handler: {other}"))

/-- Entity-native dispatch (§6.13(a)): a registered handler's body at its
expression_path; the minimal compute/literal seam (A-OC-010). -/
def entityNativeDispatch (peer : Peer) (handlerPath : String) : IO Outcome := do
  match ← EntityCore.Store.getAt peer.store handlerPath with
  | none => pure (err 404 "handler_not_found" (some handlerPath))
  | some he => match textField he "expression_path" with
    | none => pure (err 501 "no_handler_body" (some handlerPath))
    | some exprPath => do
        let abs := canonPath peer.localPeer exprPath
        match ← EntityCore.Store.getAt peer.store abs with
        | none => pure (err 404 "expression_not_found" (some abs))
        | some expr =>
          if expr.typ == "compute/literal" then
            match field expr "value" with
            | some value => pure (ok (make "compute/result"
                (.map [(.text "value", value), (.text "expression", .bytes expr.hash)])))
            | none => pure (err 400 "unexpected_params" (some "compute/literal missing value"))
          else pure (err 501 "unsupported_expression" (some expr.typ))

def typesHandler (_peer : Peer) (exec : Entity) : IO Outcome := do
  let op := (textField exec "operation").getD ""
  pure (err 501 "unsupported_operation" (some s!"type: {op}"))

-- ── §6.5 dispatcher-level signature ingestion ─────────────────────────────────

def ingestSignatures (peer : Peer) (env : Envelope) : IO Unit := do
  for ke in env.included do
    let e := ke.2
    -- Skip the EPHEMERAL request signature (the one over this exec): it is unique
    -- per request and never re-read (chain verification reads sigs from the
    -- envelope `included`, not the store), so persisting it is an unbounded
    -- per-request store leak → the §6.11 sustained-load latency runaway. Durable
    -- chain/cap signatures (which DO persist across requests) still ingest.
    let isEphemeral := match bytesField e "target" with | some t => baEq t env.root.hash | none => false
    if e.typ == "system/signature" && !isEphemeral then do
      EntityCore.Store.putEntity peer.store e
      match bytesField e "signer" with
      | some signerH => match includedGet env signerH with
        | some signerPeer => do
            EntityCore.Store.putEntity peer.store signerPeer
            match bytesField e "target", bytesField signerPeer "public_key" with
            | some target, some pk =>
                let pid := EntityCore.Identity.peerIdOfPubkey pk
                EntityCore.Store.bind peer.store ("/" ++ pid ++ "/system/signature/" ++ hex target) e
            | _, _ => pure ()
        | none => pure ()
      | none => pure ()

-- ── §6.6 handler resolution (backward tree-walk) ──────────────────────────────

partial def resolveHandlerGo (peer : Peer) (path : String) (segs : List String) :
    Nat → IO (Option (String × String))
  | 0 => pure none
  | i+1 => do
    let pfx := String.intercalate "/" (segs.take (i+1))
    match ← EntityCore.Store.getAt peer.store pfx with
    | some e => if e.typ == "system/handler" then pure (some (pfx, (path.drop pfx.length).toString))
                else resolveHandlerGo peer path segs i
    | none => resolveHandlerGo peer path segs i

def resolveHandler (peer : Peer) (path : String) : IO (Option (String × String)) :=
  let segs := path.splitOn "/"
  resolveHandlerGo peer path segs segs.length

def stripLocal (peer : Peer) (pattern : String) : String :=
  let pfx := "/" ++ peer.localPeer ++ "/"
  if pattern.startsWith pfx then (pattern.drop pfx.length).toString else pattern

/-- The §PR-8 dispatch frame: the leaf cap's granter peer_id, or local on failure. -/
def dispatchGranterPeer (peer : Peer) (env : Envelope) (cap : Entity) : IO String := do
  match bytesField cap "granter" with
  | some gh => match ← resolveHash peer env gh with
    | some g => match bytesField g "public_key" with
                | some pk => pure (EntityCore.Identity.peerIdOfPubkey pk)
                | none => pure peer.localPeer
    | none => pure peer.localPeer
  | none => pure peer.localPeer

-- ── §7a conformance handlers (the system/validate namespace) ──────────────────

def echoHandler (_peer : Peer) (exec : Entity) : IO Outcome := do
  match entityField exec "params" with
  | some p => pure (ok p)
  | none => pure (err 400 "invalid_params" (some "echo requires a params entity"))

def dispatchOutboundHandler (peer : Peer) (conn : Conn) (exec : Entity) : IO Outcome := do
  match entityField exec "params" with
  | none => pure (err 400 "invalid_params" (some "dispatch-outbound requires a params entity"))
  | some p =>
    let target := (textField p "target").getD ""
    let operation := (textField p "operation").getD ""
    match field p "value", entityField p "reentry_capability",
          entityField p "reentry_granter", entityField p "reentry_cap_signature" with
    | some value, some capability, some granterPeer, some capabilitySignature => do
        let inner := make "primitive/any" value
        let resource : Value := .map [(.text "targets", .array [.text ("system/handler/" ++ target)])]
        match ← outboundDispatch peer conn target operation inner (some resource)
                 capability granterPeer capabilitySignature with
        | none => pure (err 503 "no_outbound_seam" (some "no live §6.11 reentry connection"))
        | some env =>
            let status := (uintField env.root "status").getD 0
            let resultCbor := (field env.root "result").getD (.map [])
            pure (ok (make "primitive/any"
              (.map [(.text "status", .uint status), (.text "result", resultCbor)])))
    | _, _, _, _ => pure (err 400 "invalid_params" (some "dispatch-outbound requires value + reentry authority"))

-- ── dispatch chain (§6.5) ─────────────────────────────────────────────────────

def internalErrorResponse (env : Envelope) : Option Envelope :=
  let requestId := (textField env.root "request_id").getD ""
  some { root := EntityCore.Wire.makeResponse requestId 500 (EntityCore.Wire.errorResult "internal_error"),
         included := [] }

def dispatch (peer : Peer) (conn : Conn) (env : Envelope) : IO (Option Envelope) := do
  let exec := env.root
  if exec.typ != "system/protocol/execute" then pure none
  else do
    let requestId := (textField exec "request_id").getD ""
    let uri := (textField exec "uri").getD ""
    let outcome ← do
      if uri == "system/protocol/connect" then connectHandler peer conn exec env.included
      else do
        ingestSignatures peer env
        match ← verifyRequest peer env with
        | .unresolvableGrantee => pure (err 401 "unresolvable_grantee")
        | .authnFail => pure (err 401 "authentication_failed")
        | .authzDeny => pure (err 403 "capability_denied")
        | .chainTooDeep => pure (err 400 "chain_depth_exceeded")
        | .allow => do
          let path := canonPath peer.localPeer (EntityCore.Capability.normalizeUri uri)
          if EntityCore.Capability.extractPeer peer.localPeer path != peer.localPeer then
            pure (err 404 "handler_not_found" (some "not local peer"))
          else match ← resolveHandler peer path with
          | none => pure (err 404 "handler_not_found" (some path))
          | some (pattern, _suffix) =>
            let callerCap := (bytesField exec "capability").bind (includedGet env)
            match callerCap with
            | none => pure (err 403 "capability_denied")
            | some cap => do
              let granterPeer ← dispatchGranterPeer peer env cap
              match EntityCore.Capability.checkPermission peer.localPeer granterPeer exec cap (stripLocal peer pattern) with
              | .deny => pure (err 403 "capability_denied")
              | .allow => match stripLocal peer pattern with
                | "system/tree" => treeHandler peer exec
                | "system/capability" => capabilityHandler peer exec callerCap
                | "system/handler" => handlersHandler peer exec
                | "system/type" => typesHandler peer exec
                | "system/validate/echo" => echoHandler peer exec
                | "system/validate/dispatch-outbound" => dispatchOutboundHandler peer conn exec
                | _ => entityNativeDispatch peer pattern
    let response := EntityCore.Wire.makeResponse requestId outcome.status outcome.result
    pure (some { root := response, included := outcome.included })

-- ── bootstrap (§6.9) ──────────────────────────────────────────────────────────

def opSpec (input output : Option String) : Value :=
  .map ((match input with | some s => [(.text "input_type", .text s)] | none => [])
        ++ (match output with | some s => [(.text "output_type", .text s)] | none => []))

/-- (pattern, name, [(op, (input?, output?))]). -/
def bootstrapHandlers : List (String × String × List (String × Option String × Option String)) :=
  [ ("system/tree", "Tree", [("get", none, none), ("put", none, none)]),
    ("system/handler", "Handlers",
     [("register", some "system/handler/register-request", some "system/handler/register-result"),
      ("unregister", some "system/handler/unregister-request", none)]),
    ("system/type", "Types",
     [("validate", some "system/type/validate-request", some "system/type/validate-result")]),
    ("system/capability", "Capability",
     [("request", some "system/capability/request", some "system/capability/grant"),
      ("revoke", some "system/capability/revoke-request", none),
      ("configure", some "system/capability/policy-entry", none),
      ("delegate", some "system/capability/delegate-request", some "system/capability/grant")]),
    ("system/protocol/connect", "Connect", [("hello", none, none), ("authenticate", none, none)]) ]

/-- Bootstrap one handler's tree entities (manifest at pattern, interface at index,
empty grant) — shared by the core handlers and the §7a conformance handlers. -/
def bootstrapHandler (peer : Peer)
    (entry : String × String × List (String × Option String × Option String)) : IO Unit := do
  let (pattern, name, ops) := entry
  let operations : Value := .map (ops.map (fun (o, i, ou) => (.text o, opSpec i ou)))
  let handlerE := make "system/handler" (.map [(.text "interface", .text ("system/handler/" ++ pattern))])
  EntityCore.Store.bind peer.store ("/" ++ peer.localPeer ++ "/" ++ pattern) handlerE
  let interfaceE := make "system/handler/interface"
    (.map [(.text "pattern", .text pattern), (.text "name", .text name), (.text "operations", operations)])
  EntityCore.Store.bind peer.store ("/" ++ peer.localPeer ++ "/system/handler/" ++ pattern) interfaceE
  let (token, _) ← mintToken peer peer.identity.identityHash none []
  EntityCore.Store.bind peer.store ("/" ++ peer.localPeer ++ "/system/capability/grants/" ++ pattern) token

def create (openGrants : Bool) (conformance : Bool) (seed : Option ByteArray := none) : IO Peer := do
  -- A `--name` seed gives a *persistent* identity (deterministic peer_id);
  -- otherwise mint a fresh per-boot keypair.
  let identity ← match seed with
    | some s => pure (EntityCore.Identity.ofSeed s)
    | none => EntityCore.Identity.generate
  let store ← EntityCore.Store.create
  let peer : Peer := { identity, store, localPeer := identity.peerId, openGrants, conformance }
  -- local identity entity in the store (root-granter resolution)
  EntityCore.Store.putEntity store identity.peerEntity
  -- publish the 53 core types (§9.5)
  for (name, data) in EntityCore.TypeDefs.coreTypes do
    EntityCore.Store.bind store ("/" ++ peer.localPeer ++ "/system/type/" ++ name) (make "system/type" data)
  -- bootstrap the core handlers
  for entry in bootstrapHandlers do bootstrapHandler peer entry
  -- §6.9a Peer Authority Bootstrap (L0): self-owner cap (detached-sig shape) + default policy
  let policyBase := "/" ++ peer.localPeer ++ "/system/capability/policy/"
  let (ownerToken, ownerSig) ← mintToken peer identity.identityHash none (ownerGrants peer)
  EntityCore.Store.bind store (policyBase ++ hex identity.identityHash) ownerToken
  EntityCore.Store.bind store ("/" ++ peer.localPeer ++ "/system/signature/" ++ hex ownerToken.hash) ownerSig
  let defaultGrants := if openGrants then openGrantsScope else discoveryFloor
  let defaultEntry := make "system/capability/policy-entry"
    (.map [(.text "peer_pattern", .text "default"), (.text "grants", .array defaultGrants)])
  EntityCore.Store.bind store (policyBase ++ "default") defaultEntry
  -- §7a conformance handlers — bootstrap ONLY under --validate
  if conformance then
    for entry in [ ("system/validate/echo", "validate-echo", [("echo", none, none)]),
                   ("system/validate/dispatch-outbound", "validate-dispatch-outbound", [("dispatch", none, none)]) ] do
      bootstrapHandler peer entry
  pure peer

end EntityCore.Peer
