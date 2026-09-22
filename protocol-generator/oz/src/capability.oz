%% entity-core-protocol-oz — capability.oz
%% The §5 capability verification core: pattern matching (§5.4), request
%% verification (§5.2, 3-way verdict), delegation-chain verification (§5.5),
%% attenuation (§5.6), caveats (§5.7), revocation (§5.1), §3.6 M3 multi-sig
%% K-of-N. Derived from the §5 pseudocode.
%%
%% §PR-8 granter-frame: the RESOURCE dimension canonicalizes against the
%% GRANTER's peer_id; handlers/operations/peers stay local-framed. Self-issued
%% (granter == local) is byte-identical.
%%
%% Scope rep:  scope(incl:[Pattern] excl:[Pattern])   (Pattern = string)
%% Grant rep:  grant(handlers:S resources:S operations:S peers:S|absent)
%% Verdicts: 'ALLOW' | 'DENY'; request verdict adds authnFail | chainTooDeep,
%% with the unresolvable-grantee carve-out raised as entityCore(unresolvableGrantee).
functor
import
   Val at 'val.ozf'
   Ent at 'entity.ozf'
   Env at 'envelope.ozf'
   Hp at 'hexpath.ozf'
   Id at 'identity.ozf'
   Store at 'store.ozf'
   Crypto at 'crypto.ozf'
   Util at 'util.ozf'
export
   NowMs AddTtl TemporalFieldsRepresentable ParseScope ParseGrant GrantsOfToken MkGrant
   MatchesPattern MatchesScope CheckPermission CheckResourceScope CheckPathPermission
   Resolve ResolveGranterPeerId FindSignature
   VerifyChain ChainExceedsDepth IsRevoked VerifyRequest GrantSubset
   MaxChainDepth
define
   MaxChainDepth = 64

   %% section 6.2 CAP-6a: true iff every temporal field on a RECEIVED token is either
   %% absent (legal) or representable as a uint64.
   %%
   %% This is the reader-side half of CAP-6 and it is where a peer fails OPEN.
   %% Val.getUint answers `absent` BOTH when a field is ABSENT and when it is PRESENT but
   %% not a non-negative int -- `case V of int(N) then if N >= 0 then N else absent end`
   %% -- so a token carrying expires_at:-1 silently skipped the expiry check and was
   %% honored with 200. Section 6.2 CAP-6a is explicit: such a token "is malformed. A
   %% verifier MUST refuse it and MUST NOT treat the unrepresentable field as absent."
   %% An absent expires_at stays legal and is NOT rejected here.
   %%
   %% Oz integers are arbitrary-precision, so the >2^64 half is a DELIBERATE range check
   %% rather than an overflow trap.
   fun {TemporalFieldsRepresentable Tok}
      fun {Ok K}
         V = {Ent.getField Tok K}
      in
         if V == absent then true
         else case V of int(N) then N >= 0 andthen N < 18446744073709551616
              else false end
         end
      end
   in
      {Ok "expires_at"} andthen {Ok "not_before"} andthen {Ok "created_at"}
   end

   %% section 5.6 rule 1: convert a DURATION term (ttl_ms) to an absolute timestamp
   %% relative to CreatedAt. Rule 3: a conversion that is not representable is treated as
   %% ABSENT exactly as a null term is -- it MUST NOT wrap and MUST NOT saturate to a
   %% representable maximum, since saturation manufactures expires_at == 2^64-1, a finite
   %% bound no reader can distinguish from a deliberate one. Oz integers do not wrap, so
   %% this is a deliberate range check.
   %%
   %% Ttl == 0 is NOT a special case and deliberately so: rule 2 makes 0 a DEFINED value
   %% yielding CreatedAt (expire immediately). The absent field is the only "no bound"
   %% spelling, and falling out of the arithmetic is what keeps the two from collapsing.
   fun {AddTtl CreatedAt Ttl}
      if Ttl < 0 then absent
      else
         local Sum = CreatedAt + Ttl in
            if Sum >= 18446744073709551616 then absent else Sum end
         end
      end
   end

   fun {NowMs} {Crypto.nowMs} end

   %% ── scope / grant construction from wire maps ──
   fun {ScopeOfList Incl Excl} scope(incl:Incl excl:Excl) end

   fun {TextList M K}
      A = {Val.getArr M K}
   in
      if A == absent then nil
      else {FoldR A fun {$ V Acc} case V of text(L) then L|Acc else Acc end end nil} end
   end

   fun {ParseScope MTV}
      if MTV == absent then scope(incl:nil excl:nil)
      else scope(incl:{TextList MTV "include"} excl:{TextList MTV "exclude"}) end
   end

   fun {ParseGrant MTV}
      Peers = if MTV \= absent andthen {Val.get MTV "peers"} \= absent
              then {ParseScope {Val.getMap MTV "peers"}} else absent end
   in
      grant(handlers:{ParseScope {Val.getMap MTV "handlers"}}
            resources:{ParseScope {Val.getMap MTV "resources"}}
            operations:{ParseScope {Val.getMap MTV "operations"}}
            peers:Peers)
   end

   %% the list of parsed grants of a token entity
   fun {GrantsOfToken Token}
      GL = {Val.getArr {Ent.dataMap Token} "grants"}
   in
      if GL == absent then nil
      else {Map GL fun {$ M} {ParseGrant M} end} end
   end

   %% build a scope-map from a scope record (for minting)
   fun {ScopeMap S}
      map([{Val.mkPair "include" {Val.textArray {Map S.incl fun {$ P} {Util.vsToBytes P} end}}}
           {Val.mkPair "exclude" {Val.textArray {Map S.excl fun {$ P} {Util.vsToBytes P} end}}}])
   end

   %% MkGrant Handlers Resources Operations Peers (each a list of pattern strings;
   %% Peers=absent to omit)
   fun {MkGrant Hs Rs Os Ps}
      Base = [{Val.mkPair "handlers" {ScopeMap {ScopeOfList Hs nil}}}
              {Val.mkPair "resources" {ScopeMap {ScopeOfList Rs nil}}}
              {Val.mkPair "operations" {ScopeMap {ScopeOfList Os nil}}}]
   in
      if Ps == absent then map(Base)
      else map({Append Base [{Val.mkPair "peers" {ScopeMap {ScopeOfList Ps nil}}}]}) end
   end

   MatchesPattern = Hp.matchesPattern

   %% covered: canonical value cv covered by any pattern in Pats (framed by Frame)?
   fun {Covered Frame Pats Cv}
      {Some Pats fun {$ P} {MatchesPattern Cv {Hp.canonicalize Frame P}} end}
   end

   %% §5.2 id-scope match (0.8.1, F40) -- operations and peers. Literal comparison with
   %% exactly two wildcard forms: bare "*" and a trailing slash-star segment-prefix. None
   %% of the §5.4 path transforms apply, so a pattern carrying path syntax is matched as
   %% a literal string: a non-match, never a fault.
   fun {MatchesIdPattern Value Pattern}
      Plen = {Length Pattern}
   in
      if Pattern == "*" then true
      elseif Plen >= 2 andthen {List.drop Pattern Plen-2} == "/*" then
         Prefix = {List.take Pattern Plen-1}
      in
         {Length Value} >= Plen-1 andthen {List.take Value Plen-1} == Prefix
      else Value == Pattern
      end
   end

   fun {CoveredId Pats Value}
      {Some Pats fun {$ P} {MatchesIdPattern Value P} end}
   end

   %% §5.2 typed scope match. Kind is id (operations, peers) or path (handlers,
   %% resources) and is given at every call site -- there is no default, so a new one
   %% cannot inherit the wrong matcher silently, which is exactly the F40 defect.
   %% AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is
   %% fail-CLOSED in an include (covers nothing -> the grant grants nothing) and
   %% fail-OPEN in an exclude (carves out nothing), so the reading is chosen where the
   %% POSITION is known and MatchesPattern stays uniform over its operands.
   fun {ExcludeUnmatchable Frame Excl}
      {Some Excl fun {$ P} {Hp.canonicalize Frame P} == Hp.neverMatch end}
   end

   %% SCOPED TO PATH-SCOPE (0.8.2.24, N2/N3). This guard used to sit OUTSIDE the
   %% scope-type dispatch, transcribing 5.2s loop literally -- which was right until
   %% that loop grew a type dispatch of its own. neverMatch is a 5.4 PATH-
   %% canonicalization sentinel and has no meaning on an id-scope dimension, whose
   %% patterns are literal identifiers 5.2s own id-scope arm forbids putting through
   %% the 5.4 transforms. Asked outside the dispatch it ran an id pattern through
   %% those transforms purely to classify it and then DENIED THE WHOLE DIMENSION on a
   %% property unrelated to whether the exclude carves anything out: an `operations`
   %% exclude of star-slash-apply -- an ordinary namespaced operation name, a literal
   %% matching nothing under the id-scope grammar -- canonicalizes to the sentinel and
   %% denied every operation. Over-denial, and invisible on any well-formed grant.
   fun {MatchesScope LocalPeer Value S Kind}
      if Kind == id then
         {CoveredId S.incl Value} andthen {Not {CoveredId S.excl Value}}
      elseif {ExcludeUnmatchable LocalPeer S.excl} then false
      else
         Cv = {Hp.canonicalize LocalPeer Value}
      in
         {Covered LocalPeer S.incl Cv} andthen {Not {Covered LocalPeer S.excl Cv}}
      end
   end

   %% 6.3s handler-level path check, AND IT IS NOT A SECONDARY CHECK (0.8.2.20). It is
   %% the enforcement wherever the subject is derived after dispatch, because the
   %% dispatch-level check can be made VACUOUS by caller-controlled input: a caller who
   %% excludes the one target its capability does not cover removes that target from
   %% CheckPermissions view entirely, and a handler that then acts on it has authorized
   %% nothing.
   %%
   %% THREE DIMENSIONS, NOT FOUR, and the LOCAL frame -- both from 6.3s own signature,
   %% matches_scope(canonical_path, grant.resources, path-scope, local_peer_id), which
   %% has no granter parameter to pass. `peers` is not consulted: the path is local by
   %% construction here, since 1.4s inbound rule refused a foreign namespace at 6.5
   %% step 3 before any handler ran. 5.5a governs chain ATTENUATION, where the subject
   %% is a pattern compared against a parents pattern; this call site compares a
   %% CONCRETE local path the handler is about to touch.
   %%
   %% There is no caller-exclude set here: the subject is a single concrete path and
   %% the callers exclusions were applied in deriving it, so every grant exclude
   %% covering the subject denies -- which MatchesScope already implements, including
   %% 0.8.2.21s sentinel rule.
   fun {CheckPathPermission LocalPeer Operation Path Token HandlerPattern}
      Grants = {GrantsOfToken Token}
      fun {Go Gs}
         case Gs of nil then false
         [] G|Gr then
            if {Not {MatchesScope LocalPeer HandlerPattern G.handlers path}} then {Go Gr}
            elseif {Not {MatchesScope LocalPeer Operation G.operations id}} then {Go Gr}
            elseif {Not {MatchesScope LocalPeer Path G.resources path}} then {Go Gr}
            else true end
         end
      end
   in
      {Go Grants}
   end

   %% ── §5.2 check_permission ──
   fun {CheckResourceScope LocalPeer GranterPeer Resource S}
      Targets = {TextList Resource "targets"}
      CallerExcl = {TextList Resource "exclude"}
   in
      if Targets == nil then 'DENY'
      elseif {ExcludeUnmatchable GranterPeer S.excl} then 'DENY'   %% 0.8.2.21, FIRST
      else
         local
            fun {Go Ts}
               case Ts of nil then 'ALLOW'
               [] T|Tr then
                  local Ct = {Hp.canonicalize LocalPeer T} in
                     if CallerExcl \= nil andthen {Covered LocalPeer CallerExcl Ct} then {Go Tr}
                     elseif {Not {Covered GranterPeer S.incl Ct}} then 'DENY'
                     elseif {Covered GranterPeer S.excl Ct} then 'DENY'
                     else {Go Tr} end
                  end
               end
            end
         in
            {Go Targets}
         end
      end
   end

   fun {Resolve Included StoreH H}
      fun {Go L}
         case L of nil then {Store.getByHash StoreH H}
         [] X|Xr then if {Ent.hash X} == H then X else {Go Xr} end
         end
      end
   in
      {Go Included}
   end

   %% §PR-8: the granter's peer_id frames a cap's resource patterns
   fun {ResolveGranterPeerId Included StoreH Cap}
      GH = {Ent.getBytes Cap "granter"}
   in
      if GH == absent then absent
      else
         local G = {Resolve Included StoreH GH} in
            if G == absent then absent
            else
               local Pk = {Ent.getBytes G "public_key"} in
                  if Pk == absent then absent else {Id.peerIdOfPubkey Pk} end
               end
            end
         end
      end
   end

   fun {CheckPermission LocalPeer GranterPeer Exec Token HandlerPattern}
      Operation = {Ent.getText Exec "operation"}
      Uri = {Ent.getText Exec "uri"}
      TargetPeer = {Hp.extractPeer LocalPeer Uri}
      Resource = {Ent.getMap Exec "resource"}
      Grants = {GrantsOfToken Token}
      fun {Go Gs}
         case Gs of nil then 'DENY'
         [] G|Gr then
            if {Not {MatchesScope LocalPeer Operation G.operations id}} then {Go Gr}
            elseif {Not {MatchesScope LocalPeer HandlerPattern G.handlers path}} then {Go Gr}
            else
               local Peers = if G.peers == absent then scope(incl:[LocalPeer] excl:nil) else G.peers end in
                  if {Not {MatchesScope LocalPeer TargetPeer Peers id}} then {Go Gr}
                  elseif Resource \= absent andthen
                         {CheckResourceScope LocalPeer GranterPeer Resource G.resources} == 'DENY' then {Go Gr}
                  else 'ALLOW' end
               end
            end
         end
      end
   in
      {Go Grants}
   end

   %% ── §5.5 chain + signatures ──
   fun {FindSignature Target Included}
      fun {Go L}
         case L of nil then absent
         [] E|Er then
            if {Ent.typeIs E "system/signature"} andthen Target \= absent
               andthen {Ent.getBytes E "target"} == Target then E
            else {Go Er} end
         end
      end
   in
      {Go Included}
   end

   fun {SignaturesTargeting Target Included}
      {Filter Included
       fun {$ E}
          {Ent.typeIs E "system/signature"} andthen Target \= absent
          andthen {Ent.getBytes E "target"} == Target
       end}
   end

   %% ── §3.6 multi-sig granter ──
   %% granter field is a map -> multi-sig. Returns mg(signers:[Hash] threshold:N)
   %% or absent for single-sig.
   fun {MultiGranterOf Cap}
      G = {Ent.getField Cap "granter"}
   in
      case G of map(_) then
         local
            Arr = {Val.get G "signers"}
            Signers = case Arr of arr(L) then
                         {FoldR L fun {$ V Acc} case V of bytes(B) then B|Acc else Acc end end nil}
                      else nil end
            Th = {Val.getUint G "threshold"}
         in
            mg(signers:Signers threshold:if Th == absent then 0 else Th end)
         end
      else absent end
   end

   fun {HasDupSigners Signers}
      case Signers of nil then false
      [] X|Xr then {Member X Xr} orelse {HasDupSigners Xr}
      end
   end

   fun {PeerIdOfSigner Included StoreH SignerHash}
      P = {Resolve Included StoreH SignerHash}
   in
      if P == absent then absent
      else
         local Pk = {Ent.getBytes P "public_key"} in
            if Pk == absent then absent else {Id.peerIdOfPubkey Pk} end
         end
      end
   end

   %% validate + verify a multi-sig root (§3.6 M3 / §5.5 M4·M6) -> true/false
   fun {VerifyMultisigRoot LocalPeer Included StoreH Cap Mg}
      Signers = Mg.signers
      Threshold = Mg.threshold
      N = {Length Signers}
   in
      if {Ent.getBytes Cap "parent"} \= absent then false
      elseif N < 2 then false
      elseif Threshold < 2 orelse Threshold > N then false
      elseif {HasDupSigners Signers} then false
      elseif {Not {Some Signers fun {$ S} {PeerIdOfSigner Included StoreH S} == LocalPeer end}} then false
      else
         local
            Now = {NowMs}
            Nb = {Ent.getUint Cap "not_before"}
            Ex = {Ent.getUint Cap "expires_at"}
            Grantee = {Ent.getBytes Cap "grantee"}
         in
            if Nb \= absent andthen Now < Nb then false
            elseif Ex \= absent andthen Ex < Now then false
            elseif Grantee == absent orelse {Resolve Included StoreH Grantee} == absent then false
            else
               %% K distinct valid signatures over the cap hash
               local
                  Sigs = {SignaturesTargeting {Ent.hash Cap} Included}
                  fun {CountValid Ss Seen Acc}
                     case Ss of nil then Acc
                     [] SH|Sr then
                        if {Member SH Seen} then {CountValid Sr Seen Acc}
                        else
                           local SP = {Resolve Included StoreH SH} in
                              if SP == absent then {CountValid Sr SH|Seen Acc}
                              elseif {Some Sigs fun {$ Sg}
                                                   {Ent.getBytes Sg "signer"} == SH
                                                   andthen {Id.verifySignature Sg SP}
                                                end}
                              then {CountValid Sr SH|Seen Acc+1}
                              else {CountValid Sr SH|Seen Acc} end
                           end
                        end
                     end
                  end
               in
                  {CountValid Signers nil 0} >= Threshold
               end
            end
         end
      end
   end

   %% §PR-8 per-link frame = the cap's granter peer_id
   fun {LinkGranterPeer Included StoreH LocalPeer Cap}
      GH = {Ent.getBytes Cap "granter"}
   in
      if GH == absent then LocalPeer
      else
         local G = {Resolve Included StoreH GH} in
            if G == absent then absent
            else
               local Pk = {Ent.getBytes G "public_key"} in
                  if Pk == absent then absent else {Id.peerIdOfPubkey Pk} end
               end
            end
         end
      end
   end

   %% §5.6 scope_subset
   fun {ScopeSubset ChildPeer ParentPeer Child Parent}
      InclOk = {All Child.incl
                fun {$ Cp}
                   Cc = {Hp.canonicalize ChildPeer Cp}
                in
                   {Some Parent.incl fun {$ Pp} {MatchesPattern Cc {Hp.canonicalize ParentPeer Pp}} end}
                end}
   in
      if {Not InclOk} then false
      else
         %% child must inherit all parent excludes
         {All Parent.excl
          fun {$ Pe}
             Cp = {Hp.canonicalize ParentPeer Pe}
          in
             {Some Child.excl fun {$ Ce} {MatchesPattern Cp {Hp.canonicalize ChildPeer Ce}} end}
          end}
      end
   end

   fun {GrantSubset LocalPeer ChildPeer ParentPeer Child Parent}
      CP = if Child.peers == absent then scope(incl:[LocalPeer] excl:nil) else Child.peers end
      PP = if Parent.peers == absent then scope(incl:[LocalPeer] excl:nil) else Parent.peers end
   in
      {ScopeSubset LocalPeer LocalPeer Child.handlers Parent.handlers} andthen
      {ScopeSubset LocalPeer LocalPeer Child.operations Parent.operations} andthen
      {ScopeSubset ChildPeer ParentPeer Child.resources Parent.resources} andthen
      {ScopeSubset LocalPeer LocalPeer CP PP}
   end

   fun {IsAttenuated LocalPeer ChildPeer ParentPeer Child Parent}
      Cg = {GrantsOfToken Child}
      Pg = {GrantsOfToken Parent}
      GrantsOk = {All Cg
                  fun {$ C}
                     {Some Pg fun {$ P} {GrantSubset LocalPeer ChildPeer ParentPeer C P} end}
                  end}
   in
      if {Not GrantsOk} then false
      else
         local Pe = {Ent.getUint Parent "expires_at"}
               Ce = {Ent.getUint Child "expires_at"} in
            if Pe \= absent andthen Ce == absent then false
            elseif Pe \= absent then Ce =< Pe
            else true end
         end
      end
   end

   fun {CheckDelegationCaveats Parent Child Depth}
      Caveats = {Ent.getMap Parent "delegation_caveats"}
   in
      if Caveats == absent then true
      elseif {Val.boolIs Caveats "no_delegation"} then false
      else
         local
            Mdd = {Val.getUint Caveats "max_delegation_depth"}
            MaxTtl = {Val.getUint Caveats "max_delegation_ttl"}
            DepthOk = if Mdd == absent then true else Depth < Mdd end
            TtlOk = if MaxTtl == absent then true
                    else
                       local Ex = {Ent.getUint Child "expires_at"}
                             Cr = {Ent.getUint Child "created_at"} in
                          if Ex == absent then false
                          elseif Cr == absent then true
                          else (Ex - Cr) =< MaxTtl end
                       end
                    end
         in
            DepthOk andthen TtlOk
         end
      end
   end

   %% collect the parent chain [cap, parent, ..., root] or absent
   fun {CollectChain Cap Included StoreH}
      fun {Go Current Depth Acc}
         if Depth > MaxChainDepth then absent
         else
            local Ph = {Ent.getBytes Current "parent"} in
               if Ph == absent then {Reverse Current|Acc}
               else
                  local Parent = {Resolve Included StoreH Ph} in
                     if Parent == absent then absent
                     else {Go Parent Depth+1 Current|Acc} end
                  end
               end
            end
         end
      end
   in
      {Go Cap 0 nil}
   end

   %% §4.10(b) structural pre-check (walk parents, no sig verify)
   fun {ChainExceedsDepth StoreH Cap Included}
      fun {Go Current Depth}
         if Depth > MaxChainDepth then true
         else
            local Ph = {Ent.getBytes Current "parent"} in
               if Ph == absent then false
               else
                  local Parent = {Resolve Included StoreH Ph} in
                     if Parent == absent then false
                     else {Go Parent Depth+1} end
                  end
               end
            end
         end
      end
   in
      {Go Cap 0}
   end

   %% §5.5 chain verification -> 'ALLOW' | 'DENY' (may raise unresolvableGrantee)
   fun {VerifyChain LocalPeer StoreH Capability Included}
      Chain = {CollectChain Capability Included StoreH}
   in
      if Chain == absent then 'DENY'
      else
         local
            Root = {List.last Chain}
            RootMg = {MultiGranterOf Root}
            RootOk = if RootMg \= absent then {VerifyMultisigRoot LocalPeer Included StoreH Root RootMg}
                     else
                        local Rgh = {Ent.getBytes Root "granter"}
                              G = if Rgh \= absent then {Resolve Included StoreH Rgh} else absent end
                              Pk = if G \= absent then {Ent.getBytes G "public_key"} else absent end in
                           Pk \= absent andthen {Id.peerIdOfPubkey Pk} == LocalPeer
                        end
                     end
            N = {Length Chain}
            %% per-link validation
            fun {Link I Cur}
               if {MultiGranterOf Cur} \= absent then
                  %% multi-sig only valid as root
                  (I == N)
               else
                  local
                     Gh = {Ent.getBytes Cur "granter"}
                     SigOk =
                        if Gh == absent then false
                        else
                           local Sgn = {FindSignature {Ent.hash Cur} Included}
                                 Granter = {Resolve Included StoreH Gh} in
                              if Sgn == absent orelse Granter == absent then false
                              else
                                 local Signer = {Ent.getBytes Sgn "signer"} in
                                    Signer \= absent andthen Signer == Gh
                                    andthen {Id.verifySignature Sgn Granter}
                                 end
                              end
                           end
                        end
                  in
                     if {Not SigOk} then false
                     else
                        %% grantee resolution (per-link; unresolvable -> raise 401)
                        local Geh = {Ent.getBytes Cur "grantee"} in
                           if Geh == absent orelse {Resolve Included StoreH Geh} == absent then
                              {Util.reject unresolvableGrantee grantee} false
                           else
                              local
                                 Now = {NowMs}
                                 Nb = {Ent.getUint Cur "not_before"}
                                 Ex = {Ent.getUint Cur "expires_at"}
                                 %% CAP-6a FIRST (section 6.2): a present-but-
                                 %% unrepresentable expires_at / not_before / created_at
                                 %% is MALFORMED and must be refused outright. It has to
                                 %% be conjoined AHEAD of the two range tests, because
                                 %% those use getUint, which cannot tell "absent" from
                                 %% "present but not a uint64" -- on their own they skip
                                 %% and honor the token (fail-open).
                                 TempOk = {TemporalFieldsRepresentable Cur}
                                          andthen {Not (Nb \= absent andthen Now < Nb)}
                                          andthen {Not (Ex \= absent andthen Ex < Now)}
                              in
                                 if {Not TempOk} then false
                                 elseif I < N then
                                    %% delegation link check
                                    local
                                       Parent = {Nth Chain I+1}
                                       ChildPeer = {LinkGranterPeer Included StoreH LocalPeer Cur}
                                       ParentPeer = {LinkGranterPeer Included StoreH LocalPeer Parent}
                                    in
                                       if ChildPeer == absent orelse ParentPeer == absent then false
                                       else
                                          local
                                             Pg = {Ent.getBytes Parent "grantee"}
                                             Cg = {Ent.getBytes Cur "granter"}
                                             LinkOk = Pg \= absent andthen Cg \= absent andthen Pg == Cg
                                          in
                                             LinkOk
                                             andthen {IsAttenuated LocalPeer ChildPeer ParentPeer Cur Parent}
                                             andthen {CheckDelegationCaveats Parent Cur I}
                                          end
                                       end
                                    end
                                 else true end
                              end
                           end
                        end
                     end
                  end
               end
            end
            fun {Walk I}
               if I > N then true
               elseif {Not {Link I {Nth Chain I}}} then false
               else {Walk I+1} end
            end
         in
            if {Not RootOk} then 'DENY'
            elseif {Walk 1} then 'ALLOW'
            else 'DENY' end
         end
      end
   end

   fun {RevokeMarker LocalPeer StoreH H}
      Path = {Append &/|LocalPeer {Append "/system/capability/revocations/" {HexOf H}}}
   in
      {Store.getAt StoreH Path}
   end
   fun {HexOf H}
      HexD = "0123456789abcdef"
   in
      case H of nil then nil
      [] B|Br then {Nth HexD (B div 16)+1}|{Nth HexD (B mod 16)+1}|{HexOf Br}
      end
   end

   fun {IsRevoked LocalPeer StoreH Capability Included}
      Chain = {CollectChain Capability Included StoreH}
      RootHash = if Chain == absent then {Ent.hash Capability} else {Ent.hash {List.last Chain}} end
   in
      if {RevokeMarker LocalPeer StoreH {Ent.hash Capability}} \= absent then true
      else {RevokeMarker LocalPeer StoreH RootHash} \= absent end
   end

   %% ── §5.2 verify_request -> 'ALLOW'|'authnFail'|'authzDeny'|'chainTooDeep' ──
   %% (may raise unresolvableGrantee, mapped to 401 by the dispatcher)
   fun {VerifyRequest LocalPeer StoreH E}
      Exec = {Env.root E}
      Included = {Env.included E}
      Sgn = {FindSignature {Ent.hash Exec} Included}
   in
      if Sgn == absent then 'authnFail'
      else
         local
            AuthorH = {Ent.getBytes Exec "author"}
            Signer = {Ent.getBytes Sgn "signer"}
         in
            if {Not (Signer \= absent andthen AuthorH \= absent andthen Signer == AuthorH)} then 'authnFail'
            else
               local Author = {Env.includedGet E AuthorH} in
                  if Author == absent then 'authnFail'
                  elseif {Not {Id.verifySignature Sgn Author}} then 'authnFail'
                  else
                     local
                        Ch = {Ent.getBytes Exec "capability"}
                        Cap = if Ch \= absent then {Env.includedGet E Ch} else absent end
                     in
                        if Cap == absent then 'authzDeny'
                        elseif {ChainExceedsDepth StoreH Cap Included} then 'chainTooDeep'
                        elseif {VerifyChain LocalPeer StoreH Cap Included} == 'DENY' then 'authzDeny'
                        else
                           local Grantee = {Ent.getBytes Cap "grantee"} in
                              if {Not (Grantee \= absent andthen Grantee == AuthorH)} then 'authzDeny'
                              elseif {IsRevoked LocalPeer StoreH Cap Included} then 'authzDeny'
                              else 'ALLOW' end
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
