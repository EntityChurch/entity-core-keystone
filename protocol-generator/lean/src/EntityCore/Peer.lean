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
def mintTokenAt (peer : Peer) (createdAt : UInt64) (granteeHash : ByteArray)
    (parent : Option ByteArray) (expiresAt : Option UInt64)
    (grants : List Value) : Entity × Entity :=
  let data := [(.text "granter", .bytes peer.identity.identityHash),
               (.text "grantee", .bytes granteeHash),
               (.text "grants", .array grants),
               (.text "created_at", .uint createdAt)]
              ++ (match expiresAt with | some e => [(.text "expires_at", .uint e)] | none => [])
              ++ (match parent with | some p => [(.text "parent", .bytes p)] | none => [])
  let token := make "system/capability/token" (.map data)
  (token, EntityCore.Identity.signEntity peer.identity token)

def mintToken (peer : Peer) (granteeHash : ByteArray) (parent : Option ByteArray)
    (grants : List Value) : IO (Entity × Entity) := do
  let now ← EntityCore.Net.nowMs ()
  pure (mintTokenAt peer now granteeHash parent none grants)

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
with M3 structure carried as fields for the pure `multiSigRootOk` gate.

`rootPeer` is the peer the ROOT granter must derive. It defaults to the local peer;
§1.4's PD-2 presented-authority arm passes the TARGET, because the credential it
evaluates was minted there. The quorum arm is UNCHANGED and still resolves M6
against the LOCAL peer — §1.4 refuses a multi-signature root in a foreign frame
outright, and `Capability.verifyChainRootedAt` is where that lands. -/
def rootAuthorityOf (peer : Peer) (env : Envelope) (root : Entity)
    (rootPeer : String := peer.localPeer) : IO EntityCore.Capability.RootAuthority := do
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
                                 | some pk => pure (EntityCore.Identity.peerIdOfPubkey pk == rootPeer)
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

/-- Send an outbound EXECUTE through the §6.11 reentry seam.

`granterPeers` and `capabilitySignatures` are PLURAL (GUIDE-CONFORMANCE §7a.1,
0.8.2.19) so a K-of-N root can present every granter identity and every link
signature; the ordinary single-granter case is a list of one. Every member goes into
`included` because §5.5's chain walk resolves granters and signers BY HASH out of that
map — a granter left out is a link the verifier cannot reach, which fails closed and
reads as the peer refusing the credential form rather than as a carrier we truncated.

The AMBIENT arm carries no credential (`capability = none` selects it), so the EXECUTE
carries no `capability` field and the bundle carries no cap, granter or cap-signature.
It still authenticates as this peer — §5.2a's auth class is a separate question from
whether any capability covers the request. -/
def outboundDispatch (peer : Peer) (conn : Conn) (uri operation : String) (params : Entity)
    (resource : Option Value) (capability : Option Entity)
    (granterPeers capabilitySignatures : List Entity) :
    IO (Option Envelope) := do
  match ← conn.outbound.get with
  | none => pure none
  | some send =>
    conn.outCounter.modify (· + 1)
    let requestId := s!"out-{← conn.outCounter.get}"
    let exec := EntityCore.Wire.makeExecute requestId uri operation params
                  peer.identity.identityHash (capability.map (·.hash)) resource
    let execSig := EntityCore.Identity.signEntity peer.identity exec
    let credCarried : List (ByteArray × Entity) :=
      match capability with
      | none => []
      | some cap => (cap.hash, cap) :: (granterPeers ++ capabilitySignatures).map (fun e => (e.hash, e))
    let included := credCarried ++
                    [ (peer.identity.identityHash, peer.identity.peerEntity),
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
      -- §4.5 mutual verifiability, the direction that is NOT the array. key_types
      -- is an ACCEPT-SET; the initiator's OWN key_type is not in it — it rides in
      -- its peer_id — so a hello may advertise a perfectly good accept-set and
      -- still name an identity we cannot verify. We already reject this at
      -- `authenticate` (three surfaces), which §4.5 calls conformant but
      -- NON-CANONICAL; hello is the canonical earliest reject point and is where
      -- the "symmetric earliest-reject guarantee" lives. An UNPARSEABLE peer_id is
      -- left alone: that is a malformed field, not a key_type we lack.
      let initiatorKeyOk := match params.bind (fun p => textField p "peer_id") with
        | some pid => match EntityCore.Identity.peerIdKeyType pid with
          | some kt => kt == 1
          | none => true
        | none => true
      -- §4.5 `protocols` — the one negotiated field Required with NO default, so
      -- there is no floor to fall back to, and its two failure modes carry
      -- different codes on purpose (§4.5 table row / §4.7 row 1):
      --   absent or empty     -> 400 invalid_request       (a malformed hello)
      --   non-empty, disjoint -> 400 incompatible_protocol (we compared)
      -- "a caller that named no version cannot be told the comparison failed" —
      -- the remedies differ (send the field vs change the version) and §4.7 exists
      -- so the code selects the remedy. The vocabulary is §8.4's identifiers.
      let protos := strArray "protocols"
      -- §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a
      -- HALF-OPEN connection (hello done, authenticate not yet) is an operation we
      -- implement arriving in a state that forbids it — the same class as
      -- connection_already_established above, and it takes the same 409. A
      -- half-open connection is NOT established, so the guard above cannot reach
      -- it; §4.7 names this gap explicitly because two adjacent rules each look
      -- like they cover it and neither does.
      if (← conn.issuedNonce.get).isSome then pure (err 409 "connection_sequence_error")
      else if !hashOk then pure (err 400 "incompatible_hash_format")
      else if !keyOk then pure (err 400 "unsupported_key_type")
      else if !initiatorKeyOk then pure (err 400 "unsupported_key_type")
      -- ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. §4.5 states no
      -- precedence between the three, so a hello disjoint in more than one
      -- dimension may be refused on any of them — but the choice is OBSERVABLE,
      -- and the reference peer refuses key_types first. Checking protocols first
      -- makes AGILITY-UNKNOWN-1 answer incompatible_protocol, because that probe's
      -- own hello carries protocols ["entity-core/v7"] — a spec-line name, not a
      -- §8.4 identifier. Matching the reference's precedence is the interoperable
      -- choice; the probe's identifier is routed as F56.
      else if (match protos with | some l => l.isEmpty | none => true) then
        pure (err 400 "invalid_request" (some "hello: protocols absent or empty"))
      else if !((protos.getD []).contains "entity-core/1.0") then
        pure (err 400 "incompatible_protocol")
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
    -- RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
    -- single-use nonce. The anti-replay property is the MUST and the mechanism
    -- (established-state tracking) is impl-defined, but the STATUS is pinned to
    -- 401 invalid_nonce — a 409 state-conflict under-signals the replay.
    if ← conn.established.get then pure (err 401 "invalid_nonce")
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
  -- §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
  -- 400 invalid_request, not the 501 every other handler answers. The table
  -- separates a STATE conflict from an UNKNOWN operation because they select
  -- different remedies — "an unknown connect operation is not out of order at all;
  -- it exists in no state", so connection_sequence_error would point the caller at
  -- its ORDERING when the defect is its OPERATION NAME. Row 10 is scoped "in any
  -- state", so this arm covers pre-handshake AND established; the genuine sequence
  -- cases are refused above, with 409.
  --
  -- SCOPED TO THIS HANDLER DELIBERATELY. The generic registered-handler rule
  -- (§3.3's 501 row, §6.2) is a different contract and is separately gated; moving
  -- the shared 501 would trade one green check for another.
  | other => pure (err 400 "invalid_request" (some s!"connect: unknown operation {other}"))

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

/-- What the handler needs from the dispatch chain, CARRIED rather than recomputed
(§6.3, 0.8.2.23). The dispatch-level check already resolved both; recomputing invites
the two to drift, and §6.8 is explicit that the authority is selected by who named
the path. `pattern` is the OWNING handler's pattern — for the tree handler owner and
runner coincide, so the distinction is not observable on the wire here, but the field
is named for the owner because that is the reading. -/
structure DispatchCtx where
  exec : Entity
  /-- The caller's verified capability; `none` on an internal/bootstrap call. -/
  callerCap : Option Entity
  pattern : String

/-- §6.3's path check, applied only where a caller capability exists. An
unauthenticated context is the bootstrap/internal path and is NOT filtered: the
filter's subject is "the caller's verified capability", and where there is none there
is no caller to narrow. -/
def pathPermitted (peer : Peer) (ctx : DispatchCtx) (operation path : String) : Bool :=
  match ctx.callerCap with
  | none => true
  | some cap =>
    EntityCore.Capability.checkPathPermission peer.localPeer operation path cap ctx.pattern

/-- §6.3's per-entry listing check for one child segment (0.8.2.21/.22). -/
def entryVisible (peer : Peer) (ctx : DispatchCtx) (dir segment : String) : Bool :=
  let child := (if dir.isEmpty || dir.endsWith "/" then dir else dir ++ "/") ++ segment
  pathPermitted peer ctx "get" child

/-- Render a directory listing, FILTERED per §6.3 (0.8.2.21/.22).

"When any handler returns a multi-entry result whose entries are tree paths, each
entry MUST be individually checked using `check_path_permission`. Entries for which
`check_path_permission` returns DENY MUST be omitted. The result's `count` field MUST
reflect the filtered entry count, not the source tree's total count."

This is the read path at its highest volume and it is why 0.8.2.21 refused to carve
reads out of the caller-specified-path rule: an unfiltered listing discloses the
EXISTENCE of every binding under a prefix to a caller whose capability covers none of
them, and a `count` still reporting the source total is that same disclosure in one
field.

The DIRECTORY itself is deliberately NOT checked — §6.3 makes each ENTRY the subject,
and testing the prefix would deny a listing to a caller whose grant covers children
but not the node above them, which is the ordinary shape of a narrowed grant. -/
def buildListing (peer : Peer) (ctx : DispatchCtx) (path : String) : IO Outcome := do
  let snap ← EntityCore.Store.treeSnapshot peer.store
  let entries0 := treeListing snap path
  -- filter deletion-marker-bound leaves (CORE-TREE-DELETE-1)
  let entries1 ← entries0.filterM (fun (_, hash, hasChildren) => do
    match hash with
    | some h => if !hasChildren && (← isDeletionMarker peer h) then pure false else pure true
    | none => pure true)
  let entries := entries1.filter (fun (seg, _, _) => entryVisible peer ctx path seg)
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

/-- Digest byte length for a `content_hash_format` code per the §1.2 seed table,
or `none` when this peer cannot VERIFY that code. The total wire length is this
plus the varint prefix, which is not a constant of the code (§7.3): codes ≥ 0x80
occupy more than one byte. This peer computes SHA-256 only. -/
def hashDigestLen : Nat → Option Nat
  | 0x00 => some 32
  | _    => none

/-- §6.3's `put` admission ladder (normative, 0.8.2.11).

`put` is a RECEIPT path: the submitter authors the entity, the peer validates
what it received (§1.8 item 1) and MUST NOT author a submitted entity's
`content_hash` on the submitter's behalf. Two ordered steps:

1. STRUCTURE — a map carrying a non-empty text `type`, a PRESENT `data` (any
   CBOR value; null is a legal payload), and a `content_hash` that is a
   well-formed `system/hash` whose total byte length matches its format code
   (§1.2). Any failure → 400 `invalid_request`. A well-formed hash naming a
   format code this peer cannot verify is the separate §1.2 ingest-dispatch case
   → 400 `unsupported_content_hash_format`.
2. HASH — carried `content_hash` vs `content_hash({type, data})`. Disagreement →
   400 `hash_mismatch`.

Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step 2's
inputs are exactly what step 1 establishes, so a submission that is both
malformed and mis-hashed is step 1's and answers `invalid_request`.

Structural admission is not semantic validation: `data` is never checked against
the type named by `type`. -/
def admitPut (v : Value) : Except Outcome Entity :=
  let refuse (code msg : String) : Except Outcome Entity :=
    .error (err 400 code (some msg))
  match v with
  | .map _ =>
    match mapGet v "type" with
    | some (.text typ) =>
      if typ.isEmpty then
        refuse "invalid_request" "put: entity.type absent, empty or not a text string"
      else match mapGet v "data" with
      | none => refuse "invalid_request" "put: entity.data absent"
      | some dataV => match mapGet v "content_hash" with
        | some (.bytes carried) =>
          match EntityCore.Codec.Varint.varintDecode carried with
          | none => refuse "invalid_request" "put: entity.content_hash is not a well-formed system/hash"
          | some (code, n) => match hashDigestLen code with
            -- §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret
            -- it. NOT invalid_request: the shape is fine, the algorithm is what
            -- we lack.
            | none => .error (err 400 "unsupported_content_hash_format"
                                (some "put: unsupported content_hash_format"))
            | some digestLen =>
              if carried.size != n + digestLen then
                refuse "invalid_request" "put: content_hash length does not match its format code"
              else if baEq carried (EntityCore.ContentHash.contentHash code typ dataV) then
                -- The carried hash IS the entity's address; recomputing it into
                -- the store would be the authoring arm §6.3 forbids.
                .ok { typ, data := dataV, hash := carried }
              else
                refuse "hash_mismatch" "put: content_hash does not match content_hash({type, data})"
        | _ => refuse "invalid_request" "put: entity.content_hash absent or not a byte string"
    | _ => refuse "invalid_request" "put: entity.type absent, empty or not a text string"
  | _ => refuse "invalid_request" "put: entity is not a map"

/-- Is a resource target a §5.4 PATTERN rather than a concrete path? A
resource-requiring operation takes a concrete path (0.8.2.20); a trailing `/` is a
LISTING request rather than a pattern, so only a `*` makes it one. -/
def isPatternPath (t : String) : Bool := t.toList.contains '*'

/-- `get` (§6.3). §3.3's ladder runs on the EFFECTIVE list (0.8.2.20), never on
`resource.targets`: a handler that counts the effective list and then indexes
`targets[0]` has implemented the arithmetic completely and is still reading a path no
authorization covered. -/
def treeGet (peer : Peer) (ctx : DispatchCtx) : IO Outcome := do
  let (eff, hadResource) := EntityCore.Capability.effectiveTargets peer.localPeer ctx.exec
  match eff with
  | [] =>
    if !hadResource then
      -- THE TWO EMPTIES ARE DISTINCT HERE, AND THE OPERATION'S OWN SPECIFICATION IS
      -- WHAT SAYS SO. §3.3's "an empty effective list IS the absent case" is scoped
      -- "for an operation that REQUIRES a resource" (0.8.2.24, N7); `get` does not.
      -- For a resource-OPTIONAL operation 0.8.2.25 (N10) decides the
      -- present-but-empty case by whether the absent case is WIDER than the request
      -- — BROAD-RESULT refuses it, OPTIONAL-FILTER answers it empty — and requires
      -- the operation to declare which it is. EXTENSION-TREE §2.2a (v4.11) is that
      -- declaration: `get` is resource-OPTIONAL and BROAD-RESULT, absent-case answer
      -- "the root listing", self-excluded case "400 path_required". Both arms are
      -- pinned by text and neither is this peer's choice.
      buildListing peer ctx ("/" ++ peer.localPeer ++ "/")
    else
      -- The self-excluded request: `resource` PRESENT, every target carved out by
      -- the caller's OWN exclude. Serving it the absent case "answers a request for
      -- one excluded path with a listing of the tree" (EXTENSION-TREE §2.2a) — the
      -- root listing is wider than what was asked for, which is what BROAD-RESULT
      -- means.
      pure (err 400 "path_required" (some "tree: effective target list is empty"))
  | [target] =>
    if !pathFlexOk target then pure (err 400 "invalid_path" (some target))
    else if target == "" || target.endsWith "/" then
      buildListing peer ctx (canonPath peer.localPeer target)
    else if isPatternPath target then
      pure (err 400 "malformed_resource" (some target))
    else do
      let path := canonPath peer.localPeer target
      -- §6.3: the handler MUST verify the CALLER's capability covers the path it is
      -- about to read. Not a secondary check — the dispatch-level check never saw
      -- this path if the caller excluded it.
      if !pathPermitted peer ctx "get" path then
        pure (err 403 "capability_denied" (some path))
      else
      match ← EntityCore.Store.getAt peer.store path with
      | some e =>
        let mode := (entityField ctx.exec "params").bind (fun p => textField p "mode")
        if mode == some "hash" then pure (ok (make "system/hash" (.bytes e.hash)))
        else pure (ok e)
      | none => pure (err 404 "not_found" (some path))
  | _ => pure (err 400 "ambiguous_resource" (some "tree: more than one effective target"))

/-- `put` (§6.3). The same ladder as `treeGet`, with the two empties COLLAPSED rather
than split: EXTENSION-TREE §2.2a (v4.11) declares `put` resource-REQUIRED, so §3.3's
"an empty effective list IS the absent case" applies in its unscoped form and both
empties answer `path_required`. Same table `get`'s branch cites, read one row down —
the field is per-operation and neither answer is derivable from the handler's source.

NOTE THE CODE CHANGE 0.8.2.20 FORCED: this answered `ambiguous_resource` for a MISSING
target, which 0.8.2.20 names as the exact inversion it forbids. The remedies differ —
*supply a resource* is not *disambiguate your request* — and the code is what selects
between them. -/
def treePut (peer : Peer) (ctx : DispatchCtx) : IO Outcome := do
  -- `hadResource` is deliberately not consulted: both empties collapse here.
  let (eff, _) := EntityCore.Capability.effectiveTargets peer.localPeer ctx.exec
  match eff with
  | [] => pure (err 400 "path_required" (some "tree: put requires a resource target"))
  | [target] =>
    if !pathFlexOk target then pure (err 400 "invalid_path" (some target))
    else if isPatternPath target then
      pure (err 400 "malformed_resource" (some target))
    else do
      let path := canonPath peer.localPeer target
      if !pathPermitted peer ctx "put" path then
        pure (err 403 "capability_denied" (some path))
      else do
      let params := entityField ctx.exec "params"
      let entity := params.bind (fun p => field p "entity")
      let expected := params.bind (fun p => bytesField p "expected_hash")
      let current ← EntityCore.Store.hashAt peer.store path
      let zero33 := ByteArray.mk (List.replicate 33 (0 : UInt8)).toArray
      let casOk := match expected with
        | none => true
        | some h => if baEq h zero33 then current.isNone
                    else match current with | some c => baEq c h | none => false
      if !casOk then pure (err 409 "hash_mismatch" (some path))
      else match entity with
           | some raw => match admitPut raw with
             | .error refusal => pure refusal
             | .ok e => do EntityCore.Store.bind peer.store path e
                           pure (ok (make "system/hash" (.bytes e.hash)))
           | none => pure (err 400 "unexpected_params" (some "put: missing entity"))
  | _ => pure (err 400 "ambiguous_resource" (some "tree: more than one effective target"))

/-- RESOLVE THE OPERATION FIRST; only then run the §3.3 ladder. A peer that validates
the resource first answers a RESOURCE fault for every unknown operation. This handler
already keyed its no-resource arms to a specific operation rather than to `_`, so the
ordering was correct before this change and is now structural: the ladder lives inside
the per-operation functions and is unreachable from the unknown-operation arm. -/
def treeHandler (peer : Peer) (ctx : DispatchCtx) : IO Outcome := do
  match (textField ctx.exec "operation").getD "" with
  | "get" => treeGet peer ctx
  | "put" => treePut peer ctx
  | other => pure (err 501 "unsupported_operation" (some s!"tree: {other}"))

-- ── capability handler (§6.2) ─────────────────────────────────────────────────

def isZeroHash (h : ByteArray) : Bool := h.data.all (· == 0)

def reqGrantsOf (params : Option Entity) : List Value :=
  match params.bind (fun p => field p "grants") with | some (.array l) => l | _ => []

/-- §5.6: `request.ttl_ms` is a DURATION term. Absent (or non-uint) => no term. -/
def reqTtlOf (params : Option Entity) : Option UInt64 :=
  params.bind (fun p => uintField p "ttl_ms")

def mintBounded (peer : Peer) (callerCap : Option Entity) (reqGrants : List Value)
    (reqTtlMs : Option UInt64) (granteeHash : ByteArray) (parent : Option ByteArray) : IO Outcome := do
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
    -- §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). Sample created_at ONCE
    -- and convert the duration terms against that same instant.
    --
    -- Not an authorization decision: an over-long ttl_ms from a bounded caller
    -- MINTS a clamped token at 200 -- "rejecting it is non-conformant" (§5.6).
    let createdAt ← EntityCore.Net.nowMs ()
    let parentExpiry ← (match parent with
      | none => pure none
      | some ph => do
          match ← EntityCore.Store.getByHash peer.store ph with
          | some pe => pure (uintField pe "expires_at")
          | none => pure none)
    let callerExpiry := callerCap.bind (fun c => uintField c "expires_at")
    let reqExpiry := (reqTtlMs.bind (fun t => EntityCore.Capability.addTtl createdAt t))
    let expiresAt := EntityCore.Capability.minDefined [parentExpiry, callerExpiry, reqExpiry]
    let (token, sgn) := mintTokenAt peer createdAt granteeHash parent expiresAt reqGrants
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
     | some granteeHash => mintBounded peer callerCap (reqGrantsOf params) (reqTtlOf params) granteeHash none)
  | "delegate" =>
    (match params.bind (fun p => bytesField p "parent") with
     | none => pure (err 400 "unexpected_params" (some "delegate: parent required"))
     | some ph =>
       if isZeroHash ph then pure (err 400 "unexpected_params" (some "delegate: zero parent"))
       else if author != some peer.identity.identityHash then
         pure (err 501 "unsupported_operation" (some "delegate: same-peer-only in v1"))
       else match author with
            | none => pure (err 403 "capability_denied")
            | some granteeHash => mintBounded peer callerCap (reqGrantsOf params) (reqTtlOf params) granteeHash (some ph))
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

-- §6.2: user-installed handlers MUST NOT register at reserved system/* patterns.
def isReservedSystemPattern (pattern : String) : Bool :=
  pattern == "system" || pattern.startsWith "system/"

def register (peer : Peer) (exec : Entity) : IO Outcome := do
  match registerPattern exec with
  | .error e => pure e
  | .ok pattern =>
    if isReservedSystemPattern pattern then
      -- ASCII-ONLY WIRE STRING. The `§` that used to open this message is a
      -- wire-VISIBLE literal — the codec CBOR-text-encodes it and sends it — and
      -- that is the class AGENTS.md ratifies on two independent crashes (Oz's
      -- compiled string constant corrupted by a `§`; Io's own UTF-8 validator
      -- rejecting byte-correct UTF-8, killing the process and cascading 104 FAILs).
      -- `§` stays in COMMENTS, which are never encoded.
      pure (err 403 "forbidden_pattern"
        (some s!"section 6.2: user-installed handlers MUST NOT register at system/* paths: {pattern}"))
    else match entityField exec "params" with
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

/-- §1.4's PD-2 presented-authority arm: verify the reentry credential the caller
nested in params and answer the `peers` scope Dimension 4 relaxes to.

Every clause is required and failing any relaxes NOTHING:
* the chain ROOT `granter` resolves to the TARGET peer, and is NOT a multi-signature
  root — a K-of-N root is a GROUP's authority and never relaxes Dimension 4
  (`verifyChainRootedAt` refuses the quorum arm in a foreign frame);
* the LEAF `grantee` is the local peer;
* valid (per-link signatures, temporal, attenuation, caveats) and not revoked. -/
def targetMintedPeersRelaxation (peer : Peer) (env : Envelope) (targetPeer : String)
    (cred : Entity) : IO (Option EntityCore.Capability.Scope) := do
  -- Nothing to relax — the default already covers this peer. Treating a
  -- self-targeted credential as a relaxation would make the exemption reachable with
  -- no foreign mint at all.
  if targetPeer == peer.localPeer then pure none
  else match ← collectChain peer env cred with
  | .error _ => pure none
  | .ok chain => do
      let links ← chain.mapM (resolveLink peer env)
      let auth ← match chain.getLast? with
        | some root => rootAuthorityOf peer env root targetPeer
        | none => pure (.single false)
      let now ← EntityCore.Net.nowMs ()
      match EntityCore.Capability.verifyChainRootedAt { links, rootAuthority := auth }
              peer.localPeer now (frameIsLocal := false) with
      | .allow =>
          if ← isRevoked peer env cred then pure none
          else
            -- The LEAF grantee must be this peer.
            let granteeLocal ← match bytesField cred "grantee" with
              | some gh => match ← resolveHash peer env gh with
                           | some ge => match bytesField ge "public_key" with
                                        | some pk => pure (EntityCore.Identity.peerIdOfPubkey pk == peer.localPeer)
                                        | none => pure false
                           | none => pure false
              | none => pure false
            if !granteeLocal then pure none
            else
              -- The credential's own `peers` scope is what Dimension 4 relaxes TO.
              -- Absent means the granter -- the target peer -- which is the ordinary
              -- reentry shape: "you may dispatch back to me".
              match EntityCore.Capability.grantsOfToken cred with
              | g :: _ => pure (some (g.peers.getD { incl := [targetPeer], excl := [] }))
              | []     => pure none
      | _ => pure none

def dispatchOutboundHandler (peer : Peer) (conn : Conn) (exec : Entity)
    (handlerPattern : String) (env : Envelope) : IO Outcome := do
  match entityField exec "params" with
  | none => pure (err 400 "invalid_params" (some "dispatch-outbound requires a params entity"))
  | some p =>
    let target := (textField p "target").getD ""
    let operation := (textField p "operation").getD ""
    -- GUIDE-CONFORMANCE §7a.1: PLURAL carriers [0.8.2.19]. Arrays, and the
    -- single-granter case is an array of ONE. They were singular, which made §1.4's
    -- multi-signature-root rule ungateable on the wire: driving it needs two granter
    -- identities and two signatures, and a single-credential carrier cannot express
    -- that input.
    --
    -- TRANSITIONAL: the SINGULAR spellings are still accepted, as a list of one,
    -- because THE RENAME IS NOT INDEPENDENT OF THE ORACLE PIN. The pinned oracle is
    -- what all 46 tracked reports are measured against and it sends the SINGULAR
    -- names; a plural-only peer reads the triple as absent there, takes the ambient
    -- arm and refuses -- measured on the `go` vanguard as 2 of 778 severities moving
    -- PASS -> FAIL. Accepting both keeps the cohort 0-FAIL at BOTH check sets.
    -- REMOVE THIS FALLBACK AT THE ORACLE RE-PIN, and not before: the exit condition
    -- is that `tools/oracle-pin.env`'s `ref` names an oracle whose dispatch-outbound
    -- probe sends the plural carriers.
    let entityList (key : String) : Option (List Entity) :=
      match field p key with
      | some (.array xs) =>
          -- An array whose members do not all decode is a MALFORMED carrier and is
          -- `none`, never a silently shorter list -- the all-or-none test below would
          -- otherwise read a partial credential as a complete one.
          xs.foldr (fun x acc => match acc, ofCbor x with
                                 | some rest, some e => some (e :: rest)
                                 | _, _ => none) (some [])
      | _ => none
    let capability := entityField p "reentry_capability"
    let granterPeers := (entityList "reentry_granters").orElse (fun _ =>
      (entityField p "reentry_granter").map (fun g => [g]))
    let capSignatures := (entityList "reentry_cap_signatures").orElse (fun _ =>
      (entityField p "reentry_cap_signature").map (fun c => [c]))
    -- The triple is ALL-OR-NONE (§7a.1): all three present selects the PRESENTED arm,
    -- all three absent selects the AMBIENT arm, and a PARTIAL set is 400
    -- invalid_params -- a partial credential is malformed, not ambient. An empty array
    -- is partial, not present: it carries no credential.
    let nonEmpty (o : Option (List Entity)) : Bool :=
      match o with | some (_ :: _) => true | _ => false
    let nPresent := ([capability.isSome, nonEmpty granterPeers, nonEmpty capSignatures].filter id).length
    match field p "value" with
    | none => pure (err 400 "invalid_params" (some "dispatch-outbound requires value"))
    | some value =>
      if nPresent != 0 && nPresent != 3 then
        pure (err 400 "invalid_params" (some "dispatch-outbound reentry authority is all-or-none"))
      else do
        let hasCred := nPresent == 3
        let cred := if hasCred then capability else none
        let granters := if hasCred then granterPeers.getD [] else []
        let capSigs := if hasCred then capSignatures.getD [] else []
        let inner := make "primitive/any" value
        -- `target` arrives as any of §1.4's three spellings and the validator sends
        -- the SCHEMED ABSOLUTE form. Both the handler-pattern dimension and the
        -- resource target want the PEER-RELATIVE path -- §1.4's PD-2 block says so for
        -- Dimension 1, and a resource target carrying a scheme is not a path at all.
        let relTarget := EntityCore.Capability.peerRelativeOf target
        let resource : Value := .map [(.text "targets", .array [.text ("system/handler/" ++ relTarget)])]
        -- §7a.2a: the credential, its granters and its signatures arrive NESTED IN
        -- PARAMS (ratified shape (a), in-band), so they are not in the parent
        -- envelope's `included` and a verifier handed that alone cannot resolve a
        -- single link. The bundle merges them in.
        let credEntities := (match cred with | some c => [c] | none => []) ++ granters ++ capSigs
        let bundle : Envelope :=
          { root := env.root, included := credEntities.map (fun e => (e.hash, e)) ++ env.included }
        -- §1.4: target_peer = extract_peer(uri, local_peer_id). The validator sends the
        -- absolute form, so the URI names the target. Where the uri is PEER-RELATIVE
        -- there is no peer in it and the §6.11 seam's destination is the connection's
        -- remote, so that is the fallback -- without it Dimension 4 passes vacuously.
        let uriPeer := EntityCore.Capability.extractPeer peer.localPeer target
        let targetPeer ← if uriPeer == peer.localPeer then
                            pure ((← conn.helloPeerId.get).getD uriPeer)
                          else pure uriPeer
        -- §1.4 PD-2: check_permission runs BEFORE the sub-dispatch leaves the peer,
        -- all four dimensions, on THIS handler's own grant -- with a target-minted
        -- credential relaxing Dimension 4 and nothing else. Consulting only the
        -- presented credential here is the §6.8 confused-deputy bypass.
        let relaxTo ← match cred with
          | some c => targetMintedPeersRelaxation peer bundle targetPeer c
          | none => pure none
        match ← EntityCore.Store.getAt peer.store
                 (EntityCore.Capability.grantPathFor peer.localPeer handlerPattern) with
        -- §6.8: a handler with no valid grant does not run. Fail closed rather than
        -- falling back to the credential, which is the substitution §6.8 forbids.
        | none => pure (err 403 "capability_denied" (some ("no handler grant for " ++ handlerPattern)))
        | some ownGrant =>
          if !EntityCore.Capability.checkOutboundSubDispatch peer.localPeer targetPeer
               relTarget operation ownGrant resource relaxTo then
            -- §7a.1a: the surfaced code is the AUTHORIZATION domain's code. A generic
            -- transport- or gateway-class code would launder an authorization verdict
            -- into a route fault, and the ambient and presented branches would then
            -- disagree about what the same gate decided.
            pure (err 403 "capability_denied"
                   (some "outbound sub-dispatch not authorized by the handler grant"))
          else
            match ← outboundDispatch peer conn target operation inner (some resource)
                     cred granters capSigs with
            -- ASCII-ONLY WIRE STRING (see the forbidden_pattern note above): the
            -- `§6.11` this message used to carry is encoded and sent.
            | none => pure (err 503 "no_outbound_seam" (some "no live section 6.11 reentry connection"))
            | some renv =>
                let status := (uintField renv.root "status").getD 0
                let resultCbor := (field renv.root "result").getD (.map [])
                pure (ok (make "primitive/any"
                  (.map [(.text "status", .uint status), (.text "result", resultCbor)])))

-- ── dispatch chain (§6.5) ─────────────────────────────────────────────────────

def internalErrorResponse (env : Envelope) : Option Envelope :=
  let requestId := (textField env.root "request_id").getD ""
  some { root := EntityCore.Wire.makeResponse requestId 500 (EntityCore.Wire.errorResult "internal_error"),
         included := [] }

def dispatch (peer : Peer) (conn : Conn) (env : Envelope) : IO (Option Envelope) := do
  let exec := env.root
  if exec.typ != "system/protocol/execute" then
    -- §6.5's "Other type?" arm, as REWRITTEN at 0.8.2.25 (N12/N17): "400
    -- invalid_request, coded frame; MAY then close (§3.3, §4.11). NOT a bare close —
    -- that is indistinguishable from a network fault."
    --
    -- §3.3 used to read "the connection MUST be closed", assigning no code and
    -- requiring no frame, and that row was REPLACED at .25 (N18 — §9.1's floor row
    -- went with it). This peer did something weaker still: it returned `none`, the
    -- transport wrote NOTHING and kept the connection open, which is §4.11's other
    -- non-conformant behaviour — the SILENT DROP, "the weaker of the two precisely
    -- because nothing surfaces it".
    --
    -- This is a PRE-ADMISSION refusal: the root is not an EXECUTE, so nothing was
    -- ever admitted and §4.9(c) does not reach it. `request_id` is read best-effort
    -- — an arbitrary root type is under no obligation to carry one, and §4.11
    -- licenses the uncorrelated frame exactly there. We do NOT close: on a
    -- multiplexed connection that would cost every ADMITTED in-flight request its
    -- response, and §4.11 leaves the close to us.
    pure (some {
      root := EntityCore.Wire.makeResponse ((textField exec "request_id").getD "") 400
                (EntityCore.Wire.errorResult "invalid_request"
                  (some "root entity is neither EXECUTE nor EXECUTE_RESPONSE")),
      included := [] })
  else do
    let requestId := (textField exec "request_id").getD ""
    let uri := (textField exec "uri").getD ""
    let outcome ← do
      if uri == "system/protocol/connect" then connectHandler peer conn exec env.included
      else do
        ingestSignatures peer env
        -- §4.7 (0.8.2.6) — THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION. This gate used
        -- to sit inside the .allow arm, so a pre-establishment EXECUTE naming a FOREIGN
        -- namespace took the 401 an unauthenticated request takes. §4.7's own reason: "a
        -- 401 directs the caller to authenticate and retry, and for a foreign-namespace
        -- address that retry cannot succeed at any authentication state — so the 401 names
        -- a remedy that does not exist." §6.5 step 3 calls it "a gate, not an ordering
        -- preference" and §1.4 makes the downstream permission check unreachable here.
        let addrPath := canonPath peer.localPeer (EntityCore.Capability.normalizeUri uri)
        if EntityCore.Capability.extractPeer peer.localPeer addrPath != peer.localPeer then
          pure (err 400 "invalid_request" (some "not local peer"))
        else
        match ← verifyRequest peer env with
        | .unresolvableGrantee => pure (err 401 "unresolvable_grantee")
        | .authnFail => pure (err 401 "authentication_failed")
        | .authzDeny => pure (err 403 "capability_denied")
        | .chainTooDeep => pure (err 400 "chain_depth_exceeded")
        | .allow => do
          -- (The §1.4 address gate that used to sit here has moved ABOVE the verdict —
          -- §4.7 0.8.2.6 orders it before authentication. Reaching this arm at all now
          -- means the path is local.)
          let path := addrPath
          match ← resolveHandler peer path with
          | none => pure (err 404 "handler_not_found" (some path))
          | some (pattern, _suffix) =>
            let callerCap := (bytesField exec "capability").bind (includedGet env)
            match callerCap with
            | none => pure (err 403 "capability_denied")
            | some cap => do
              let granterPeer ← dispatchGranterPeer peer env cap
              match EntityCore.Capability.checkPermission peer.localPeer granterPeer exec cap (stripLocal peer pattern) with
              | .deny => pure (err 403 "capability_denied")
              -- §6.3 needs the OWNING handler's pattern and the caller's
              -- capability; both were just computed here, so they are CARRIED
              -- rather than recomputed (0.8.2.23).
              | .allow => match stripLocal peer pattern with
                | "system/tree" =>
                  treeHandler peer { exec, callerCap, pattern := stripLocal peer pattern }
                | "system/capability" => capabilityHandler peer exec callerCap
                | "system/handler" => handlersHandler peer exec
                | "system/type" => typesHandler peer exec
                | "system/validate/echo" => echoHandler peer exec
                -- §1.4 PD-2 needs the OWNING handler's peer-relative pattern (Dimension
                -- 1 is matched peer-relative) and the parent envelope (the §7a.2a
                -- bundle base). Both were computed above, so they are CARRIED.
                | "system/validate/dispatch-outbound" =>
                    dispatchOutboundHandler peer conn exec (stripLocal peer pattern) env
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

/-- A handler's OWN grant (§6.8) — the authority it spends when it dispatches onward,
as distinct from any capability a caller presents. §6.8 row 1: an access in service of
a caller's request needs the caller's verified capability AND this grant, and BOTH must
pass.

NARROW BY DESIGN for `dispatch-outbound`, and the narrowness is what makes the
intersection MEASURABLE. GUIDE-CONFORMANCE §7a.1 makes it a scaffold-contract
requirement: with a wide grant, consulting it and skipping it give the same answer on
every input, so the confused-deputy discriminator cannot fire and a bypass reads as
conformant. Every other handler keeps the empty list, which is the right default for a
handler that never dispatches onward. -/
def ownGrantsFor (pattern : String) : List Value :=
  if pattern == "system/validate/dispatch-outbound" then
    [ .map [ (.text "handlers", .map [(.text "include", .array [.text "system/validate/echo"])]),
             (.text "operations", .map [(.text "include", .array [.text "echo"])]),
             (.text "resources", .map [(.text "include", .array [.text "system/handler/system/validate/echo"])]) ] ]
  else []

/-- Bootstrap one handler's tree entities (manifest at pattern, interface at index,
own grant) — shared by the core handlers and the §7a conformance handlers. -/
def bootstrapHandler (peer : Peer)
    (entry : String × String × List (String × Option String × Option String)) : IO Unit := do
  let (pattern, name, ops) := entry
  let operations : Value := .map (ops.map (fun (o, i, ou) => (.text o, opSpec i ou)))
  let handlerE := make "system/handler" (.map [(.text "interface", .text ("system/handler/" ++ pattern))])
  EntityCore.Store.bind peer.store ("/" ++ peer.localPeer ++ "/" ++ pattern) handlerE
  let interfaceE := make "system/handler/interface"
    (.map [(.text "pattern", .text pattern), (.text "name", .text name), (.text "operations", operations)])
  EntityCore.Store.bind peer.store ("/" ++ peer.localPeer ++ "/system/handler/" ++ pattern) interfaceE
  let (token, _) ← mintToken peer peer.identity.identityHash none (ownGrantsFor pattern)
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
