%% entity-core-protocol-oz — peer.oz
%% Peer assembly: bootstrap (§6.9 / §6.9a), the MUST system handlers (§6.2:
%% connect, tree, handler, capability, type), the §6.5 dispatch chain, §6.6
%% longest-prefix resolution, the §6.9a seed policy, and the §7a conformance
%% handlers. The pure protocol brain — dispatch is a function from an inbound
%% envelope to an outbound response envelope; transport lives in transport.oz.
%%
%% Handlers return an OUTCOME (out(status:N result:Ent included:[Ent])). ctx is
%% ctx(conn:Conn env:Env callerCap:Cap|absent). §4.8 store-safety is structural
%% (the store is a port agent — store.oz); dataflow threads dispatch concurrently
%% but every store touch serializes through its one owning thread.
functor
import
   System
   Val at 'val.ozf'
   Ent at 'entity.ozf'
   Env at 'envelope.ozf'
   Wire at 'wire.ozf'
   Hp at 'hexpath.ozf'
   Id at 'identity.ozf'
   Peerid at 'peerid.ozf'
   Store at 'store.ozf'
   Cap at 'capability.ozf'
   TypeStore at 'typestore.ozf'
   Conn at 'conn.ozf'
   Crypto at 'crypto.ozf'
   Util at 'util.ozf'
   Varint at 'varint.ozf'
export
   Create Identity StoreOf LocalPeer Dispatch RandomBytes
define
   %% ── outcome helpers ──
   fun {OutMake Status Result Included} out(status:Status result:Result included:Included) end
   fun {OutOk Result Included} out(status:200 result:Result included:Included) end
   fun {OutErr Status Code Message} out(status:Status result:{Wire.errorResult Code Message} included:nil) end

   fun {HexOf H}
      HexD = "0123456789abcdef"
   in
      case H of nil then nil
      [] B|Br then {Nth HexD (B div 16)+1}|{Nth HexD (B mod 16)+1}|{HexOf Br}
      end
   end
   fun {IsZeroHash H} {All H fun {$ B} B == 0 end} andthen H \= nil end

   %% ── peer record + accessors ──
   fun {Create Seed OpenGrants Conformance}
      Ident = {Id.ofSeed Seed}
      St = {Store.new}
      P = peer(identity:Ident store:St localPeer:{Id.peerId Ident}
               openGrants:OpenGrants conformance:Conformance
               handlers:{NewDictionary})    % patternAtom -> routineAtom
   in
      {Bootstrap P}
      P
   end
   fun {Identity P} P.identity end
   fun {StoreOf P} P.store end
   fun {LocalPeer P} P.localPeer end
   fun {Abs P Rel} {Append &/|P.localPeer &/|Rel} end
   fun {RandomBytes N} {Crypto.random N} end

   %% ── grant construction (§4.4 / §5.4) ──
   fun {DiscoveryFloor}
      [{Cap.mkGrant ["system/tree"] ["system/type/*" "system/handler/*"] ["get"] absent}
       {Cap.mkGrant ["system/capability"] nil ["request"] absent}]
   end
   fun {OpenGrantsScope} [{Cap.mkGrant ["*"] ["*" "/*/*"] ["*"] ["*"]}] end
   fun {OwnerGrants P} [{Cap.mkGrant ["*"] ["*"] ["*"] [P.localPeer]}] end

   %% ── token mint (§4.4 / §6.9a) -> minted(token:Ent sig:Ent) ──
   %% MintTokenAt at the current instant with no section 5.6 ceiling. Used by the paths
   %% that mint a self-issued grant from local authority (bootstrap, handler
   %% registration, the section 4.4 handshake), where no MIN_DEFINED term is in play.
   fun {MintToken P GranteeHash Grants Parent}
      {MintTokenAt P {Cap.nowMs} GranteeHash Grants Parent absent}
   end

   %% Mint at a caller-supplied instant, carrying section 5.6's MIN_DEFINED ceiling.
   %%
   %% ExpiresAt == absent means no term was defined and the token genuinely has no expiry
   %% (the ONLY "no bound" spelling). A present value is emitted verbatim -- including one
   %% equal to CreatedAt, which section 5.6 rule 2 requires for ttl_ms == 0 and which
   %% means "already expired at every observable instant", not "unbounded".
   %%
   %% CreatedAt is supplied rather than sampled here so a computed expiry is guaranteed to
   %% be relative to the SAME instant that lands in the token; sampling the clock twice
   %% skews the two.
   fun {MintTokenAt P CreatedAt GranteeHash Grants Parent ExpiresAt}
      Ident = P.identity
      Base = [{Val.mkPair "granter" bytes({Id.idHash Ident})}
              {Val.mkPair "grantee" bytes(GranteeHash)}
              {Val.mkPair "grants" arr(Grants)}
              {Val.mkPair "created_at" int(CreatedAt)}]
      WithExp = if ExpiresAt == absent then Base
                else {Append Base [{Val.mkPair "expires_at" int(ExpiresAt)}]} end
      Full = if Parent == absent then WithExp
             else {Append WithExp [{Val.mkPair "parent" bytes(Parent)}]} end
      Token = {Ent.make "system/capability/token" map(Full)}
      Sig = {Id.sign Ident Token}
   in
      minted(token:Token sig:Sig)
   end

   fun {CapIncluded P M}
      [M.token {Id.peerEntity P.identity} M.sig]
   end

   %% ── §6.9a seed policy (authenticate-time grant derivation) ──
   fun {SeedEntryGrants P E}
      Ident = P.identity
      St = P.store
   in
      if {Ent.typeIs E "system/capability/token"} then
         local SigPath = {Append &/|P.localPeer {Append "/system/signature/" {HexOf {Ent.hash E}}}}
               Sgn = {Store.getAt St SigPath} in
            if Sgn \= absent andthen {Id.verifySignature Sgn {Id.peerEntity Ident}} then
               local GL = {Val.getArr {Ent.dataMap E} "grants"} in
                  if GL == absent then nil else GL end
               end
            else nil end
         end
      elseif {Ent.typeIs E "system/capability/policy-entry"} then
         local GL = {Val.getArr {Ent.dataMap E} "grants"} in
            if GL == absent then nil else GL end
         end
      else nil end
   end

   fun {DeriveSeedGrants P RemotePeer RemotePeerId}
      St = P.store
      Base = {Append &/|P.localPeer "/system/capability/policy/"}
      Entry1 = {Store.getAt St {Append Base {HexOf {Ent.hash RemotePeer}}}}
      Entry2 = if Entry1 == absent then {Store.getAt St {Append Base RemotePeerId}} else Entry1 end
      Entry = if Entry2 == absent then {Store.getAt St {Append Base "default"}} else Entry2 end
      Floor = {DiscoveryFloor}
   in
      if Entry == absent then Floor
      else
         local Policy = {SeedEntryGrants P Entry} in
            if Policy == nil then Floor else {Append Floor Policy} end
         end
      end
   end

   %% ── §6.13(b) handler-facing outbound dispatch (§6.11 reentry) ──
   fun {OutboundDispatch P C Uri Operation Params Capability GranterPeer CapSig Resource}
      Ident = P.identity
      ReqId = {Append "out-" {Int.toString {Conn.nextOut C}}}
      Exec = {Wire.makeExecute ReqId Uri Operation Params {Id.idHash Ident} {Ent.hash Capability} Resource}
      ExecSig = {Id.sign Ident Exec}
      Inc = [Capability GranterPeer {Id.peerEntity Ident} CapSig ExecSig]
   in
      {Conn.outbound C {Env.make Exec Inc}}
   end

   %% ── dispatcher-level signature ingestion (§6.5) — persist only the granter/
   %% signer PEER entities (bounded, dedup by hash); NOT the signatures (unbounded
   %% per-request growth; verified straight from the envelope's included). ──
   proc {IngestSignatures P E}
      St = P.store
   in
      {ForAll {Env.included E}
       proc {$ Ent0}
          if {Ent.typeIs Ent0 "system/signature"} then
             local SignerH = {Ent.getBytes Ent0 "signer"} in
                if SignerH \= absent then
                   local SP = {Env.includedGet E SignerH} in
                      if SP \= absent then {Store.putEntity St SP} end
                   end
                end
             end
          end
       end}
   end

   %% ── §6.6 handler resolution (backward tree-walk) ──
   fun {ResolveHandler P Path}
      St = P.store
      Segs = {Hp.splitSegs Path}
      N = {Length Segs}
      %% join the first K segments with "/" separators. The first segment of an
      %% absolute path is "" (== nil in Oz), so we seed the fold with the head and
      %% append "/"‖S for the rest — preserving the leading slash (a nil-sentinel
      %% fold would silently drop it).
      fun {JoinFirst K}
         case {List.take Segs K} of nil then nil
         [] H|T then {FoldL T fun {$ Acc S} {Append Acc &/|S} end H}
         end
      end
      fun {Go I}
         if I < 1 then absent
         else
            local Prefix = {JoinFirst I}
                  E = {Store.getAt St Prefix} in
               if E \= absent andthen {Ent.typeIs E "system/handler"} then Prefix
               else {Go I-1} end
            end
         end
      end
   in
      {Go N}
   end

   %% ── dispatch chain (§6.5) — returns an EXECUTE_RESPONSE envelope, or absent ──
   fun {Dispatch P C E}
      Exec = {Env.root E}
   in
      if {Not {Ent.typeIs Exec "system/protocol/execute"}} then absent
      else
         local
            ReqId = {Ent.getText Exec "request_id"}
            ReqIdS = if ReqId == absent then "" else ReqId end
            Outcome
         in
            try
               Outcome = {DispatchInner P C E Exec}
            catch error(entityCore(kind:K ...) ...) then
               Outcome = {MapExc K}
            [] _ then
               %% any other exception -> 500, never silently drop (§4.9(c))
               Outcome = {OutErr 500 "internal_error" ""}
            end
            {Env.make {Wire.makeResponse ReqIdS Outcome.status Outcome.result} Outcome.included}
         end
      end
   end

   fun {MapExc K}
      if K == unresolvableGrantee then {OutErr 401 "unresolvable_grantee" ""}
      elseif K == reservedRelative orelse K == ambiguousWildcard then {OutErr 400 "invalid_path" ""}
      elseif {IsCodecExc K} then {OutErr 400 "non_canonical_ecf" ""}
      else {OutErr 500 "internal_error" {Atom.toString K}} end
   end
   fun {IsCodecExc K}
      {Member K [notAMap missingRoot missingType missingData contentHashMismatch
                 includedKeyNotBytes includedValueNotMap includedKeyMismatch
                 nonCanonicalEcf tagRejected truncatedInput]}
   end

   fun {DispatchInner P C E Exec}
      St = P.store
      Uri = {Ent.getText Exec "uri"}
      Operation = {Ent.getText Exec "operation"}
   in
      if Uri == "system/protocol/connect" then
         {CallHandler P 'connect' Operation ctx(conn:C env:E callerCap:absent)}
      else
         {IngestSignatures P E}
         local Rv = {Cap.verifyRequest P.localPeer St E} in
            if Rv == 'authnFail' then {OutErr 401 "authentication_failed" ""}
            elseif Rv == 'authzDeny' then {OutErr 403 "capability_denied" ""}
            elseif Rv == 'chainTooDeep' then {OutErr 400 "chain_depth_exceeded" ""}
            else
               local Path = {Hp.canonicalize P.localPeer {Hp.normalizeUri Uri}} in
                  if {Hp.extractPeer P.localPeer Path} \= P.localPeer then
                     {OutErr 400 "invalid_request" "not local peer"}
                  else
                     local Pattern = {ResolveHandler P Path} in
                        if Pattern == absent then {OutErr 404 "handler_not_found" Path}
                        else
                           local
                              CapH = {Ent.getBytes Exec "capability"}
                              CallerCap = if CapH \= absent then {Env.includedGet E CapH} else absent end
                           in
                              if CallerCap == absent then {OutErr 403 "capability_denied" ""}
                              else
                                 local
                                    GP0 = {Cap.resolveGranterPeerId {Env.included E} St CallerCap}
                                    GranterPeer = if GP0 == absent then P.localPeer else GP0 end
                                 in
                                    if {Cap.checkPermission P.localPeer GranterPeer Exec CallerCap Pattern} == 'DENY' then
                                       {OutErr 403 "capability_denied" ""}
                                    else
                                       local Stripped = {Hp.stripLocal P.localPeer Pattern}
                                             SA = {String.toAtom Stripped} in
                                          if {Dictionary.member P.handlers SA} then
                                             {CallHandler P {Dictionary.get P.handlers SA} Operation
                                              ctx(conn:C env:E callerCap:CallerCap)}
                                          else {OutErr 501 "no_handler_body" Stripped} end
                                       end
                                    end
                                 end
                              end
                           end
                        end
                     end
                  end
               end
            end
         end
      end
   end

   %% ── handler dispatch table ──
   fun {CallHandler P Routine Operation Ctx}
      case Routine
      of 'connect' then {HConnect P Operation Ctx}
      [] 'tree' then {HTree P Operation Ctx}
      [] 'handlers' then {HHandlers P Operation Ctx}
      [] 'type' then {HType P Operation Ctx}
      [] 'capability' then {HCapability P Operation Ctx}
      [] 'echo' then {HEcho P Operation Ctx}
      [] 'dispatch_outbound' then {HDispatchOutbound P Operation Ctx}
      else {OutErr 501 "unsupported_operation" {Atom.toString Routine}} end
   end

   fun {CtxExec Ctx} {Env.root Ctx.env} end
   fun {CtxIncluded Ctx} {Env.included Ctx.env} end
   fun {HParams Ctx} {Ent.getEntity {CtxExec Ctx} "params"} end

   fun {ExecResourceTarget Exec}
      R = {Ent.getMap Exec "resource"}
   in
      if R == absent then absent
      else
         local Ts = case {Val.getArr R "targets"} of absent then nil [] L then L end in
            case Ts of nil then absent
            [] T|_ then case T of text(L) then L else absent end
            end
         end
      end
   end

   %% ═════ §4.1 / §4.6 connect handler ═════
   fun {HConnect P Operation Ctx}
      if Operation == "hello" then {ConnectHello P Ctx}
      elseif Operation == "authenticate" then {ConnectAuthenticate P Ctx}
      %% §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
      %% 400 invalid_request, not the 501 every other handler answers. The table
      %% separates a STATE conflict from an UNKNOWN operation because they select
      %% different remedies -- "an unknown connect operation is not out of order at
      %% all; it exists in no state", so connection_sequence_error would point the
      %% caller at its ORDERING when the defect is its OPERATION NAME. Row 10 is
      %% scoped "in any state", so this arm covers pre-handshake AND established; the
      %% genuine sequence cases are refused in the two functions below, with 409.
      %%
      %% SCOPED TO THIS FUNCTION DELIBERATELY. The generic registered-handler rule
      %% (section 3.3's 501 row, section 6.2) is a different contract and is
      %% separately gated; moving the other handlers' 501 would trade one green check
      %% for another.
      %%
      %% (The message text stays ASCII: a non-ASCII byte in an Oz string constant has
      %% crashed this peer at runtime before -- A-OZ-008.)
      else {OutErr 400 "invalid_request" {Util.vsToBytes "connect: unknown operation "#Operation}} end
   end

   %% section 4.5 `protocols`: is it present at all -- a non-empty array carrying at
   %% least one text? Separates the MALFORMED-hello case from the we-compared-and-
   %% disagreed case, which take different section 4.7 codes. NegotiationDisjoint
   %% deliberately conflates the two (absent means "no constraint" there), so
   %% `protocols`, which is Required with NO default, needs this asked first.
   fun {ProtocolsPresent Params}
      if Params == absent then false
      else
         local D = {Ent.dataMap Params} in
            if {Not {Val.has D "protocols"}} then false
            else
               case {Val.getArr D "protocols"} of absent then false
               [] L then {FoldR L fun {$ V Acc} case V of text(_) then true else Acc end end false} end
            end
         end
      end
   end

   fun {NegotiationDisjoint Params Key Supported}
      if Params == absent then false
      else
         local D = {Ent.dataMap Params} in
            if {Not {Val.has D Key}} then false
            else
               local Declared = case {Val.getArr D Key} of absent then nil
                                [] L then {FoldR L fun {$ V Acc} case V of text(S) then S|Acc else Acc end end nil} end in
                  {Not {Member {Util.vsToBytes Supported} Declared}}
               end
            end
         end
      end
   end

   fun {ConnectHello P Ctx}
      C = Ctx.conn
      Exec = {CtxExec Ctx}
   in
      %% section 4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a
      %% HALF-OPEN connection (hello done, authenticate not yet) is an operation we
      %% implement arriving in a state that forbids it -- the same class as
      %% connection_already_established, taking the same 409. A half-open connection is
      %% NOT established, so the established guard cannot reach it; section 4.7 names
      %% this gap explicitly because two adjacent rules each look like they cover it and
      %% neither does.
      if {Conn.get C established} then {OutErr 409 "connection_already_established" ""}
      elseif {Conn.get C issuedNonce} \= unit then {OutErr 409 "connection_sequence_error" ""}
      else
         local Params = {Ent.getEntity Exec "params"}
               %% section 4.5 mutual verifiability, the direction that is NOT the
               %% array. `key_types` is an ACCEPT-SET; the initiator's OWN key_type is
               %% not in it -- it rides in its `peer_id` -- so a hello may advertise a
               %% perfectly good accept-set and still name an identity we cannot
               %% verify. An UNPARSEABLE peer_id is left alone: that is a malformed
               %% field, not a key_type we lack, and authenticate already refuses it.
               HelloPid = if Params == absent then absent
                          else {Ent.getText Params "peer_id"} end
               HelloKt = if HelloPid == absent then 1
                         else
                            try KT HT DG in {Peerid.parse HelloPid ?KT ?HT ?DG} KT
                            catch _ then 1 end
                         end
         in
            if {NegotiationDisjoint Params "hash_formats" "ecfv1-sha256"} then {OutErr 400 "incompatible_hash_format" ""}
            elseif {NegotiationDisjoint Params "key_types" "ed25519"} then {OutErr 400 "unsupported_key_type" ""}
            elseif HelloKt \= 1 then {OutErr 400 "unsupported_key_type" ""}
            %% section 4.5 `protocols` -- the one negotiated field Required with NO
            %% default, so there is no floor to fall back to, and its two failure modes
            %% carry different codes on purpose (section 4.5 table row / 4.7 row 1):
            %%
            %%   absent or empty     -> 400 invalid_request       (a malformed hello)
            %%   non-empty, disjoint -> 400 incompatible_protocol (we compared)
            %%
            %% The remedies differ (send the field vs change the version) and section
            %% 4.7 exists so the code selects the remedy. The vocabulary is section
            %% 8.4's protocol version identifiers, today the single entity-core/1.0.
            %%
            %% ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. Section 4.5
            %% states no precedence between the three, so a hello disjoint in more than
            %% one dimension may be refused on any of them -- but the choice is
            %% OBSERVABLE, and the reference peer refuses key_types first. Checking
            %% protocols first makes AGILITY-UNKNOWN-1 answer incompatible_protocol,
            %% because that probe's hello carries ["entity-core/v7"] -- a spec-line
            %% name, not a section 8.4 identifier (F56).
            elseif {Not {ProtocolsPresent Params}} then
               {OutErr 400 "invalid_request" {Util.vsToBytes "hello: protocols absent or empty"}}
            elseif {NegotiationDisjoint Params "protocols" "entity-core/1.0"} then
               {OutErr 400 "incompatible_protocol" ""}
            else
               local Nonce = {RandomBytes 32} in
                  if Params \= absent then {Conn.set C helloPeerId {Ent.getText Params "peer_id"}} end
                  {Conn.set C issuedNonce Nonce}
                  {OutOk {Ent.make "system/protocol/connect/hello"
                          map([{Val.mkPair "peer_id" {Val.txt P.localPeer}}
                               {Val.mkPair "nonce" bytes(Nonce)}
                               {Val.mkPair "protocols" {Val.textArray [{Util.vsToBytes "entity-core/1.0"}]}}
                               {Val.mkPair "timestamp" int({Cap.nowMs})}
                               {Val.mkPair "hash_formats" {Val.textArray [{Util.vsToBytes "ecfv1-sha256"}]}}
                               {Val.mkPair "key_types" {Val.textArray [{Util.vsToBytes "ed25519"}]}}])}
                   nil}
               end
            end
         end
      end
   end

   fun {ConnectAuthenticate P Ctx}
      C = Ctx.conn
      Exec = {CtxExec Ctx}
      Included = {CtxIncluded Ctx}
   in
      %% RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
      %% single-use nonce — pinned to 401 invalid_nonce, not a 409 state-conflict
      %% which under-signals the replay.
      if {Conn.get C established} then {OutErr 401 "invalid_nonce" ""}
      else
         local IssuedNonce = {Conn.get C issuedNonce} in
            if IssuedNonce == unit then {OutErr 401 "invalid_nonce" ""}
            else
               local Auth = {Ent.getEntity Exec "params"} in
                  if Auth == absent then {OutErr 401 "authentication_failed" ""}
                  else
                     local
                        Kt = {Ent.getText Auth "key_type"}
                        Pub = {Ent.getBytes Auth "public_key"}
                        Claimed = {Ent.getText Auth "peer_id"}
                        %% decode the claimed peer_id's varint key_type; a non-ed25519
                        %% (!= 0x01) claim is an unsupported key_type (§4.6 SHOULD 400,
                        %% AGILITY-UNKNOWN-1) rather than an identity mismatch.
                        ClaimedKt = if Claimed == absent then 1
                                    else
                                       try KT HT DG in {Peerid.parse Claimed ?KT ?HT ?DG} KT
                                       catch _ then 1 end
                                    end
                        BadKt = (Kt \= absent andthen Kt \= "ed25519")
                                orelse (Pub \= absent andthen {Length Pub} \= 32)
                                orelse ClaimedKt \= 1
                     in
                        if BadKt then {OutErr 400 "unsupported_key_type" ""}
                        else
                           local Echoed = {Ent.getBytes Auth "nonce"} in
                              if {Not (Echoed \= absent andthen Echoed == IssuedNonce)} then {OutErr 401 "invalid_nonce" ""}
                              elseif Pub == absent then {OutErr 401 "authentication_failed" ""}
                              else
                                 local
                                    Sgn = {Cap.findSignature {Ent.hash Auth} Included}
                                    SigOk = if Sgn == absent then false
                                            else
                                               local Sb = {Ent.getBytes Sgn "signature"} in
                                                  Sb \= absent andthen {Length Sb} == 64
                                                  andthen {Crypto.ed25519Verify Pub Sb {Ent.hash Auth}}
                                               end
                                            end
                                 in
                                    if {Not SigOk} then {OutErr 401 "authentication_failed" ""}
                                    elseif Claimed \= absent andthen Claimed \= {Id.peerIdOfPubkey Pub} then {OutErr 401 "identity_mismatch" ""}
                                    else
                                       local HelloPid = {Conn.get C helloPeerId} in
                                          if HelloPid \= unit andthen HelloPid \= "" andthen Claimed \= absent andthen HelloPid \= Claimed then
                                             {OutErr 401 "identity_mismatch" ""}
                                          else
                                             local
                                                RemotePeer = {Id.peerEntityOfPubkey Pub}
                                                ClaimedS = if Claimed == absent then {Id.peerIdOfPubkey Pub} else Claimed end
                                                Grants = {DeriveSeedGrants P RemotePeer ClaimedS}
                                                M = {MintToken P {Ent.hash RemotePeer} Grants absent}
                                             in
                                                {Conn.set C established true}
                                                {OutOk {Ent.make "system/capability/grant"
                                                        map([{Val.mkPair "token" bytes({Ent.hash M.token})}])}
                                                 {CapIncluded P M}}
                                             end
                                          end
                                       end
                                    end
                                 end
                              end
                           end
                        end
                     end
                  end
               end
            end
         end
      end
   end

   %% ═════ §6.3 tree handler ═════
   fun {HTree P Operation Ctx}
      if Operation == "get" then {TreeGet P Ctx}
      elseif Operation == "put" then {TreePut P Ctx}
      else {OutErr 501 "unsupported_operation" Operation} end
   end

   fun {TreeGet P Ctx}
      Exec = {CtxExec Ctx}
      Local = P.localPeer
      St = P.store
      Target = {ExecResourceTarget Exec}
   in
      if Target == absent then {TreeListing P {Append &/|Local "/"}}
      elseif Target == nil orelse Target == "/" then {TreeListing P "/"}   % empty/"/" = universal root listing
      elseif {Not {Hp.pathFlexOk Target}} then {OutErr 400 "invalid_path" Target}
      elseif {List.last Target} == &/ then {TreeListing P {Hp.canonicalize Local Target}}
      else
         local Path = {Hp.canonicalize Local Target}
               E = {Store.getAt St Path} in
            if E == absent then {OutErr 404 "not_found" Path}
            else
               local Params = {Ent.getEntity Exec "params"}
                     Mode = if Params == absent then absent else {Ent.getText Params "mode"} end in
                  if Mode == "hash" then
                     {OutOk {Ent.make "system/hash" map([{Val.mkPair "hash" bytes({Ent.hash E})}])} nil}
                  else {OutOk E nil} end
               end
            end
         end
      end
   end

   %% Digest byte length for a content_hash_format code per the §1.2 seed table,
   %% or absent when this peer cannot VERIFY that code. The total wire length is
   %% this plus the varint prefix, which is not a constant of the code (§7.3):
   %% codes >= 0x80 occupy more than one byte. {Ent.contentHash} emits the
   %% SHA-256 floor unconditionally, so 0x00 is the whole verifiable set here.
   fun {HashDigestLen Code}
      if Code == 0 then 32 else absent end
   end

   %% §6.3's `put` admission ladder (normative, 0.8.2.11).
   %%
   %% `put` is a RECEIPT path: the submitter authors the entity, the peer
   %% validates what it received (§1.8 item 1) and MUST NOT author a submitted
   %% entity's content_hash on the submitter's behalf. Two ordered steps:
   %%
   %%   1. STRUCTURE — a map carrying a non-empty text `type`, a PRESENT `data`
   %%      (any CBOR value; null is a legal payload), and a `content_hash` that
   %%      is a well-formed system/hash whose total byte length matches its
   %%      format code (§1.2). Any failure -> 400 invalid_request. A well-formed
   %%      hash naming a format code this peer cannot verify is the separate
   %%      §1.2 ingest-dispatch case -> 400 unsupported_content_hash_format.
   %%   2. HASH — carried content_hash vs contentHash({type, data}).
   %%      Disagreement -> 400 hash_mismatch.
   %%
   %% Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step
   %% 2's inputs are exactly what step 1 establishes, so a submission that is
   %% both malformed and mis-hashed is step 1's and answers invalid_request.
   %%
   %% Structural admission is not semantic validation: `data` is never checked
   %% against the type named by `type`.
   %%
   %% Returns admitted(E) or refused(Outcome).
   fun {AdmitPut V}
      fun {Refuse Code Msg} refused({OutErr 400 Code Msg}) end
   in
      case V of map(_) then
         local
            T = {Val.getText V "type"}
            D = {Val.get V "data"}
            Carried = {Val.getBytes V "content_hash"}
         in
            if T == absent orelse T == nil then
               {Refuse "invalid_request" "put: entity.type absent, empty or not a text string"}
            %% Presence, not truthiness: a CBOR null is a legal `data` payload and
            %% {Val.get} answers the null NODE for it, not absent.
            elseif D == absent then {Refuse "invalid_request" "put: entity.data absent"}
            elseif Carried == absent orelse Carried == nil then
               {Refuse "invalid_request" "put: entity.content_hash absent or not a byte string"}
            else
               local Code Rest DigestLen in
                  try
                     {Varint.decode Carried Code Rest}
                  catch _ then Code = absent Rest = nil
                  end
                  if Code == absent then
                     {Refuse "invalid_request"
                        "put: entity.content_hash is not a well-formed system/hash"}
                  else
                     DigestLen = {HashDigestLen Code}
                     %% §1.2 / §4.7 row 5 — well-formed, but this peer cannot
                     %% interpret it. NOT invalid_request: the shape is fine, the
                     %% algorithm is what we lack.
                     if DigestLen == absent then
                        {Refuse "unsupported_content_hash_format"
                           "put: unsupported content_hash_format"}
                     elseif {Length Rest} \= DigestLen then
                        {Refuse "invalid_request"
                           "put: content_hash length does not match its format code"}
                     elseif {Ent.contentHash T D} \= Carried then
                        {Refuse "hash_mismatch"
                           "put: content_hash does not match content_hash({type, data})"}
                     else
                        %% The carried hash IS the entity's address; recomputing it
                        %% into the store would be the authoring arm §6.3 forbids.
                        admitted({Ent.admitted T D Carried})
                     end
                  end
               end
            end
         end
      else {Refuse "invalid_request" "put: entity is not a map"}
      end
   end

   fun {TreePut P Ctx}
      Exec = {CtxExec Ctx}
      Local = P.localPeer
      St = P.store
      Target = {ExecResourceTarget Exec}
   in
      if Target == absent then {OutErr 400 "ambiguous_resource" "tree: missing resource target"}
      elseif {Not {Hp.pathFlexOk Target}} then {OutErr 400 "invalid_path" Target}
      else
         local
            Path = {Hp.canonicalize Local Target}
            Params = {Ent.getEntity Exec "params"}
            RawEntity = if Params == absent then absent else {Val.get {Ent.dataMap Params} "entity"} end
            Expected = if Params == absent then absent else {Ent.getBytes Params "expected_hash"} end
            CurrentA = {Store.hashAt St Path}
            Current = if CurrentA == unit then absent else CurrentA end
            CasOk = if Expected == absent then true
                    elseif {IsZeroHash Expected} then Current == absent
                    else Current \= absent andthen Current == {String.toAtom {HexOf Expected}} end
         in
            if {Not CasOk} then {OutErr 409 "hash_mismatch" Path}
            elseif RawEntity == absent then {OutErr 400 "unexpected_params" "put: missing entity"}
            else
               local Adm = {AdmitPut RawEntity} in
                  case Adm
                  of refused(O) then O
                  [] admitted(Entity) then
                     {Store.bind St Path Entity}
                     {OutOk {Ent.make "system/hash" map([{Val.mkPair "hash" bytes({Ent.hash Entity})}])} nil}
                  end
               end
            end
         end
      end
   end

   fun {TreeListing P Path}
      St = P.store
      Rows = {Store.listing St Path}
      fun {RowEntries Rs}
         case Rs of nil then nil
         [] R|Rr then
            %% row(seg:S hash:HexAtom|unit child:B)
            local
               HashBytes = if R.hash == unit then absent
                           else {Util.bytesOfHex {Atom.toString R.hash}} end
               Led = if HashBytes \= absent then
                        {Ent.make "system/tree/listing-entry"
                         map([{Val.mkPair "has_children" bool(R.child)}
                              {Val.mkPair "hash" bytes(HashBytes)}])}
                     else
                        {Ent.make "system/tree/listing-entry"
                         map([{Val.mkPair "has_children" bool(R.child)}])}
                     end
               %% deletion-marker filter (§6.3)
               Skip = if HashBytes \= absent andthen {Not R.child} then
                         local Me = {Store.getByHash St HashBytes} in
                            Me \= absent andthen {Ent.typeIs Me "system/deletion-marker"}
                         end
                      else false end
            in
               if Skip then {RowEntries Rr}
               else ({Val.mkPair R.seg {Ent.toCbor Led}})|{RowEntries Rr}
               end
            end
         end
      end
      Entries = {RowEntries Rows}
   in
      {OutOk {Ent.make "system/tree/listing"
              map([{Val.mkPair "path" {Val.txt Path}}
                   {Val.mkPair "entries" map(Entries)}
                   {Val.mkPair "count" int({Length Entries})}
                   {Val.mkPair "offset" int(0)}])} nil}
   end

   %% ═════ §6.2/§6.13(a) handlers handler ═════
   fun {RegisterPattern Exec}
      Target = {ExecResourceTarget Exec}
      Pfx = "system/handler/"
   in
      if Target == absent then absent
      elseif {Length Target} =< {Length Pfx} then absent
      elseif {List.take Target {Length Pfx}} \= Pfx then absent
      else {List.drop Target {Length Pfx}} end
   end
   fun {RegisterPatternError Exec}
      if {ExecResourceTarget Exec} == absent then
         {OutErr 400 "ambiguous_resource" "register/unregister require exactly one resource target"}
      else {OutErr 400 "invalid_resource" "resource target MUST be system/handler/{pattern}"} end
   end
   %% IsReservedSystemPattern — §6.2: user-installed handlers MUST NOT register at
   %% system/* paths. Pattern == "system" or begins with "system/". (The runtime
   %% error message below spells out "section 6.2" in plain ASCII, not "§6.2" --
   %% a literal U+00A7 baked into an Oz string constant crashes the peer with an
   %% internal "Tell: 403 = 500" unification failure inside OutErr, verified by
   %% isolated A/B: {OutErr 403 code "reserved pattern: "#Pattern} is clean, the
   %% same call with a leading "§6.2: ..." text is not -- reproducibly, every
   %% time. Comments are source text, never compiled into a runtime value, so §
   %% is safe here.)
   fun {IsReservedSystemPattern Pattern}
      Rpfx = "system/"
   in
      if Pattern == "system" then true
      elseif {Length Pattern} =< {Length Rpfx} then false
      else {List.take Pattern {Length Rpfx}} == Rpfx end
   end

   fun {HHandlers P Operation Ctx}
      if Operation == "register" then {HandlersRegister P Ctx}
      elseif Operation == "unregister" then {HandlersUnregister P Ctx}
      else {OutErr 501 "unsupported_operation" Operation} end
   end

   fun {HandlersRegister P Ctx}
      Exec = {CtxExec Ctx}
      St = P.store
      Ident = P.identity
      Pattern = {RegisterPattern Exec}
   in
      if Pattern == absent then {RegisterPatternError Exec}
      elseif {IsReservedSystemPattern Pattern} then
         {OutErr 403 "forbidden_pattern" "section 6.2: user-installed handlers MUST NOT register at system/* paths: "#Pattern}
      else
         local Req = {Ent.getEntity Exec "params"} in
            if Req == absent then {OutErr 400 "unexpected_params" "register: missing params"}
            elseif {Not {Ent.typeIs Req "system/handler/register-request"}} then {OutErr 400 "unexpected_params" "register expects register-request"}
            else
               local
                  Manifest0 = {Ent.getMap Req "manifest"}
                  Manifest = if Manifest0 == absent then map(nil) else Manifest0 end
                  Name0 = {Val.getText Manifest "name"}
                  Name = if Name0 == absent then Pattern else Name0 end
                  Operations0 = {Val.getMap Manifest "operations"}
                  Operations = if Operations0 == absent then map(nil) else Operations0 end
                  ExprPath = {Val.getText Manifest "expression_path"}
                  InternalScope = {Val.get Manifest "internal_scope"}
                  ReqScope0 = {Val.getArr {Ent.dataMap Req} "requested_scope"}
                  IntScopeList = {Val.getArr {Ent.dataMap Req} "internal_scope"}
                  GrantScope = if ReqScope0 \= absent then ReqScope0
                               elseif IntScopeList \= absent then IntScopeList
                               else nil end
                  IfaceRel = {Append "system/handler/" Pattern}
                  HpFields0 = [{Val.mkPair "interface" {Val.txt IfaceRel}}]
                  HpFields1 = if ExprPath \= absent then {Append HpFields0 [{Val.mkPair "expression_path" {Val.txt ExprPath}}]} else HpFields0 end
                  HpFields = if InternalScope \= absent then {Append HpFields1 [{Val.mkPair "internal_scope" InternalScope}]} else HpFields1 end
               in
                  {Store.bind St {Abs P Pattern} {Ent.make "system/handler" map(HpFields)}}
                  %% associated types
                  local Types = {Ent.getMap Req "types"} in
                     if Types \= absent then
                        {ForAll {Val.mapPairs Types}
                         proc {$ Pr}
                            case Pr.1 of text(TK) then
                               local Td = case Pr.2 of map(_) then Pr.2 else map([{Val.mkPair "def" Pr.2}]) end in
                                  {Store.bind St {Abs P {Append "system/type/" TK}} {Ent.make "system/type" Td}}
                               end
                            else skip end
                         end}
                     end
                  end
                  local M = {MintToken P {Id.idHash Ident} GrantScope absent} in
                     {Store.bind St {Abs P {Append "system/capability/grants/" Pattern}} M.token}
                     {Store.bind St {Abs P {Append "system/signature/" {HexOf {Ent.hash M.token}}}} M.sig}
                     {Store.bind St {Abs P IfaceRel}
                      {Ent.make "system/handler/interface"
                       map([{Val.mkPair "pattern" {Val.txt Pattern}} {Val.mkPair "name" {Val.txt Name}}
                            {Val.mkPair "operations" Operations}])}}
                     {OutOk {Ent.make "system/handler/register-result"
                             map([{Val.mkPair "pattern" {Val.txt Pattern}} {Val.mkPair "grant" {Ent.data M.token}}])} nil}
                  end
               end
            end
         end
      end
   end

   fun {HandlersUnregister P Ctx}
      Exec = {CtxExec Ctx}
      St = P.store
      Pattern = {RegisterPattern Exec}
   in
      if Pattern == absent then {RegisterPatternError Exec}
      else
         local G = {Store.getAt St {Abs P {Append "system/capability/grants/" Pattern}}} in
            if G \= absent then
               {Store.unbind St {Abs P {Append "system/signature/" {HexOf {Ent.hash G}}}}}
               {Store.unbind St {Abs P {Append "system/capability/grants/" Pattern}}}
            end
            {Store.unbind St {Abs P Pattern}}
            {Store.unbind St {Abs P {Append "system/handler/" Pattern}}}
            {OutOk {Wire.emptyParams} nil}
         end
      end
   end

   %% ═════ system/type:validate ═════
   fun {HType P Operation Ctx}
      if Operation \= "validate" then {OutErr 501 "unsupported_operation" Operation}
      else
         local
            St = P.store
            Req = {HParams Ctx}
         in
            if Req == absent then {OutErr 400 "invalid_params" "validate requires a params entity"}
            else
               local Subject = {Ent.getEntity Req "entity"} in
                  if Subject == absent then {OutErr 400 "unexpected_params" "validate-request missing entity"}
                  else
                     local
                        Tn0 = {Ent.getText Req "type_name"}
                        TypeName = if Tn0 == absent then {Ent.typ Subject} else Tn0 end
                        TnStr = if {IsByteList TypeName} then TypeName else TypeName end
                        TypeDef = {Store.getAt St {Abs P {Append "system/type/" TnStr}}}
                     in
                        if TypeDef == absent then
                           {OutOk {Ent.make "system/type/validate-result" map([{Val.mkPair "valid" bool(false)}])} nil}
                        else
                           local
                              Fields = {Ent.getMap TypeDef "fields"}
                              SubjData = {Ent.dataMap Subject}
                              Violations = if Fields == absent then nil
                                           else
                                              {FoldR {Val.mapPairs Fields}
                                               fun {$ Pr Acc}
                                                  case Pr.1 of text(FN) then
                                                     local
                                                        Spec = case Pr.2 of map(_) then Pr.2 else map(nil) end
                                                        Optional = {Val.boolIs Spec "optional"}
                                                        Present = {Val.has SubjData FN}
                                                     in
                                                        if {Not Optional} andthen {Not Present} then
                                                           map([{Val.mkPair "kind" {Val.txt "missing_required_field"}}
                                                                {Val.mkPair "field" text(FN)}])|Acc
                                                        else Acc end
                                                     end
                                                  else Acc end
                                               end nil}
                                           end
                              Valid = Violations == nil
                              Vm = if Violations == nil then [{Val.mkPair "valid" bool(Valid)}]
                                   else [{Val.mkPair "valid" bool(Valid)} {Val.mkPair "violations" arr(Violations)}] end
                           in
                              {OutOk {Ent.make "system/type/validate-result" map(Vm)} nil}
                           end
                        end
                     end
                  end
               end
            end
         end
      end
   end
   fun {IsByteList _} true end

   %% ═════ §6.2 capability handler ═════
   fun {HCapability P Operation Ctx}
      if Operation == "request" then {CapRequest P Ctx}
      elseif Operation == "delegate" then {CapDelegate P Ctx}
      elseif Operation == "revoke" then {CapRevoke P Ctx}
      elseif Operation == "configure" then {CapConfigure P Ctx}
      else {OutErr 501 "unsupported_operation" Operation} end
   end

   fun {ReqGrants Params}
      if Params == absent then nil
      else
         local GL = {Val.getArr {Ent.dataMap Params} "grants"} in
            if GL == absent then nil else GL end
         end
      end
   end

   fun {CapRequest P Ctx}
      Params = {HParams Ctx}
      Author = {Ent.getBytes {CtxExec Ctx} "author"}
   in
      if Author == absent then {OutErr 403 "capability_denied" ""}
      else {CapMintBounded P {CtxIncluded Ctx} Params Ctx.callerCap {ReqGrants Params} Author absent} end
   end

   fun {CapDelegate P Ctx}
      Params = {HParams Ctx}
      Author = {Ent.getBytes {CtxExec Ctx} "author"}
      Ph = if Params == absent then absent else {Ent.getBytes Params "parent"} end
   in
      if Ph == absent then {OutErr 400 "unexpected_params" "delegate: parent required"}
      elseif {IsZeroHash Ph} then {OutErr 400 "unexpected_params" "delegate: zero parent"}
      elseif {Not (Author \= absent andthen {Id.idHash P.identity} == Author)} then
         {OutErr 501 "unsupported_operation" "delegate: same-peer-only in v1"}
      else {CapMintBounded P {CtxIncluded Ctx} Params Ctx.callerCap {ReqGrants Params} Author Ph} end
   end

   fun {CapRevoke P Ctx}
      Params = {HParams Ctx}
      St = P.store
      TokenH = if Params == absent then absent else {Ent.getBytes Params "token"} end
   in
      if TokenH == absent then {OutErr 400 "unexpected_params" "revoke: missing token"}
      elseif {IsZeroHash TokenH} then {OutErr 400 "unexpected_params" "revoke: zero token"}
      else
         local Marker = {Ent.make "system/capability/revocation"
                         map([{Val.mkPair "token" bytes(TokenH)} {Val.mkPair "revoked_at" int({Cap.nowMs})}])} in
            {Store.bind St {Append &/|P.localPeer {Append "/system/capability/revocations/" {HexOf TokenH}}} Marker}
            {OutOk {Wire.emptyParams} nil}
         end
      end
   end

   fun {CapConfigure P Ctx}
      Params = {HParams Ctx}
      St = P.store
      Pp = if Params == absent then absent else {Ent.getText Params "peer_pattern"} end
   in
      if Pp == absent then {OutErr 400 "unexpected_params" "configure: missing peer_pattern"}
      else
         local
            IsHex = {Length Pp} == 66 andthen {All Pp fun {$ C} {Member C "0123456789abcdef"} end}
         in
            if {Not (Pp == "default" orelse IsHex orelse {Hp.isPeerId Pp})} then {OutErr 400 "invalid_peer_pattern" Pp}
            else
               {Store.bind St {Append &/|P.localPeer {Append "/system/capability/policy/" Pp}} Params}
               {OutOk {Wire.emptyParams} nil}
            end
         end
      end
   end

   fun {CapMintBounded P Included Params CallerCap ReqGr GranteeHash Parent}
      Local = P.localPeer
      Bounded = if CallerCap == absent orelse CallerCap == unit then false
                else
                   local ParentGrants = {Cap.grantsOfToken CallerCap} in
                      {All {Map ReqGr fun {$ M} {Cap.parseGrant M} end}
                       fun {$ Cg}
                          {Some ParentGrants fun {$ Pg} {Cap.grantSubset Local Local Local Cg Pg} end}
                       end}
                   end
                end
   in
      if {Not Bounded} then {OutErr 403 "scope_exceeds_authority" ""}
      else
         %% section 5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). Sample created_at
         %% ONCE and convert the duration term against that same instant.
         %%
         %% Note what this is NOT: an authorization decision. An over-long ttl_ms from a
         %% bounded caller MINTS a clamped token and returns 200 -- "rejecting it is
         %% non-conformant" (section 5.6). The bound exists because `request` mints a ROOT
         %% token (parent: null), so section 5.6's parent-child attenuation never reaches
         %% it; without this clamp, temporal attenuation is the one dimension a requester
         %% could escape, and policy withdrawal would have no bounded latency.
         local
            CreatedAt = {Cap.nowMs}
            fun {FoldMin Acc T}
               if T == absent then Acc
               elseif Acc == absent orelse T < Acc then T
               else Acc end
            end
            PT = if Parent == absent then absent
                 else {Cap.resolve Included P.store Parent} end
            C1 = if PT == absent then absent
                 else {FoldMin absent {Ent.getUint PT "expires_at"}} end
            C2 = if CallerCap == absent orelse CallerCap == unit then C1
                 else {FoldMin C1 {Ent.getUint CallerCap "expires_at"}} end
            Ttl = if Params == absent then absent else {Ent.getUint Params "ttl_ms"} end
            Ceiling = if Ttl == absent then C2
                      else {FoldMin C2 {Cap.addTtl CreatedAt Ttl}} end
            M = {MintTokenAt P CreatedAt GranteeHash ReqGr Parent Ceiling}
         in
            {OutOk {Ent.make "system/capability/grant" map([{Val.mkPair "token" bytes({Ent.hash M.token})}])}
             {CapIncluded P M}}
         end
      end
   end

   %% ═════ §7a conformance handlers (--validate only) ═════
   fun {HEcho P Operation Ctx}
      if Operation \= "echo" then {OutErr 501 "unsupported_operation" Operation}
      else
         local Pr = {HParams Ctx} in
            if Pr == absent then {OutErr 400 "invalid_params" "echo requires params"}
            else {OutOk Pr nil} end
         end
      end
   end

   fun {HDispatchOutbound P Operation Ctx}
      if Operation \= "dispatch" then {OutErr 501 "unsupported_operation" Operation}
      else
         local Pr = {HParams Ctx} in
            if Pr == absent then {OutErr 400 "invalid_params" "dispatch-outbound requires a params entity"}
            else
               local
                  Target = {Ent.getText Pr "target"}
                  Op = {Ent.getText Pr "operation"}
                  Value = {Ent.getField Pr "value"}
                  Capa = {Ent.getEntity Pr "reentry_capability"}
                  Granter = {Ent.getEntity Pr "reentry_granter"}
                  CapSig = {Ent.getEntity Pr "reentry_cap_signature"}
               in
                  if {Not (Value \= absent andthen Capa \= absent andthen Granter \= absent andthen CapSig \= absent)} then
                     {OutErr 400 "invalid_params" "dispatch-outbound requires value + reentry authority"}
                  else
                     local
                        InnerData = case Value of map(_) then Value else map([{Val.mkPair "value" Value}]) end
                        Inner = {Ent.make "primitive/any" InnerData}
                        Resource = {Wire.resourceTarget {Append "system/handler/" Target}}
                        Resp = {OutboundDispatch P Ctx.conn Target Op Inner Capa Granter CapSig Resource}
                     in
                        if Resp == absent then {OutErr 503 "no_outbound_seam" "no live reentry connection"}
                        else
                           local
                              Root = {Env.root Resp}
                              Status0 = {Ent.getUint Root "status"}
                              Status = if Status0 == absent then 0 else Status0 end
                              ResultCbor0 = {Ent.getField Root "result"}
                              ResultCbor = if ResultCbor0 == absent then map(nil) else ResultCbor0 end
                           in
                              {OutOk {Ent.make "primitive/any"
                                      map([{Val.mkPair "status" int(Status)} {Val.mkPair "result" ResultCbor}])} nil}
                           end
                        end
                     end
                  end
               end
            end
         end
      end
   end

   %% ── bootstrap (§6.9) ──
   fun {OpSpec Input Output}
      L0 = if Input == absent then nil else [{Val.mkPair "input_type" {Val.txt Input}}] end
      L1 = if Output == absent then L0 else {Append L0 [{Val.mkPair "output_type" {Val.txt Output}}]} end
   in
      map(L1)
   end

   proc {BootstrapHandler P Pattern Routine Name Ops}
      St = P.store
      Ident = P.identity
   in
      {Dictionary.put P.handlers {String.toAtom Pattern} Routine}
      local
         Operations = {FoldR Ops
                       fun {$ Op Acc}
                          %% Op = op(name:N input:I output:O)
                          {Val.mkPair Op.name {OpSpec Op.input Op.output}}|Acc
                       end nil}
      in
         {Store.bind St {Abs P Pattern}
          {Ent.make "system/handler" map([{Val.mkPair "interface" {Val.txt {Append "system/handler/" Pattern}}}])}}
         {Store.bind St {Abs P {Append "system/handler/" Pattern}}
          {Ent.make "system/handler/interface"
           map([{Val.mkPair "pattern" {Val.txt Pattern}} {Val.mkPair "name" {Val.txt Name}}
                {Val.mkPair "operations" map(Operations)}])}}
         local M = {MintToken P {Id.idHash Ident} nil absent} in
            {Store.bind St {Abs P {Append "system/capability/grants/" Pattern}} M.token}
         end
      end
   end

   proc {Bootstrap P}
      St = P.store
      Ident = P.identity
   in
      {Store.putEntity St {Id.peerEntity Ident}}
      {TypeStore.publish St P.localPeer}

      {BootstrapHandler P "system/tree" 'tree' "Tree"
       [op(name:"get" input:absent output:absent) op(name:"put" input:absent output:absent)]}
      {BootstrapHandler P "system/handler" 'handlers' "Handlers"
       [op(name:"register" input:"system/handler/register-request" output:"system/handler/register-result")
        op(name:"unregister" input:"system/handler/unregister-request" output:absent)]}
      {BootstrapHandler P "system/type" 'type' "Types"
       [op(name:"validate" input:"system/type/validate-request" output:"system/type/validate-result")]}
      {BootstrapHandler P "system/capability" 'capability' "Capability"
       [op(name:"request" input:"system/capability/request" output:"system/capability/grant")
        op(name:"revoke" input:"system/capability/revoke-request" output:absent)
        op(name:"configure" input:"system/capability/policy-entry" output:absent)
        op(name:"delegate" input:"system/capability/delegate-request" output:"system/capability/grant")]}
      {BootstrapHandler P "system/protocol/connect" 'connect' "Connect"
       [op(name:"hello" input:absent output:absent) op(name:"authenticate" input:absent output:absent)]}

      %% §6.9a Peer Authority Bootstrap: self-owner cap + default scope-template
      local
         PolicyBase = {Append &/|P.localPeer "/system/capability/policy/"}
         Owner = {MintToken P {Id.idHash Ident} {OwnerGrants P} absent}
         DefaultGrants = if P.openGrants then {OpenGrantsScope} else {DiscoveryFloor} end
      in
         {Store.bind St {Append PolicyBase {HexOf {Id.idHash Ident}}} Owner.token}
         {Store.bind St {Append &/|P.localPeer {Append "/system/signature/" {HexOf {Ent.hash Owner.token}}}} Owner.sig}
         {Store.bind St {Append PolicyBase "default"}
          {Ent.make "system/capability/policy-entry"
           map([{Val.mkPair "peer_pattern" {Val.txt "default"}} {Val.mkPair "grants" arr(DefaultGrants)}])}}
      end

      %% §7a conformance handlers — only under --validate
      if P.conformance then
         {BootstrapHandler P "system/validate/echo" 'echo' "validate-echo"
          [op(name:"echo" input:absent output:absent)]}
         {BootstrapHandler P "system/validate/dispatch-outbound" 'dispatch_outbound' "validate-dispatch-outbound"
          [op(name:"dispatch" input:absent output:absent)]}
      end
   end
end
