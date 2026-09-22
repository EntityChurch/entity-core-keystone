%% entity-core-protocol-oz — hexpath.oz
%% Path model (§1.4), canonicalization + pattern matching (§5.4), peer-id shape
%% checks, and string prefix/suffix helpers. Pure functions on Oz strings
%% (byte lists). Canonicalize raises entityCore on reserved/ambiguous forms.
functor
import
   Util at 'util.ozf'
export
   StartsWith EndsWith NormalizeUri Canonicalize IsPeerId MatchesPattern
   FirstSegment ExtractPeer PathFlexOk SplitSegs StripLocal DropChars
   NeverMatch
define
   Reject = Util.reject

   fun {StartsWith S P}
      case P of nil then true
      [] X|Pr then
         case S of Y|Sr then
            if X == Y then {StartsWith Sr Pr} else false end
         else false end
      end
   end
   fun {EndsWith S P}
      LS = {Length S} LP = {Length P}
   in
      LP == 0 orelse (LS >= LP andthen {List.drop S LS-LP} == P)
   end
   fun {DropChars S N} {List.drop S N} end

   %% "entity://x/y" -> "/x/y"; else unchanged
   fun {NormalizeUri U}
      if {StartsWith U "entity://"} then &/|{List.drop U 9}
      else U end
   end

   %% The unmatchable value (0.8.2.20). Unreachable as a canonical path by
   %% CONSTRUCTION: its first segment cannot be a peer_id, since IsPeerId requires
   %% >= 46 Base58 characters and &- is outside Base58Chars.
   NeverMatch = "/never-match"

   %% §5.4 canonicalize -- TOTAL (0.8.2.20): the return domain is "a canonical path
   %% OR NeverMatch". This used to RAISE, and the raise was reachable from the wire:
   %% every normative call site is a matcher with no error channel to consume one, so
   %% the exception escaped the matcher and any caller who put "../x" in a resource
   %% exclude got a 400 from the resilience frame rather than the 403 DENY 0.8.2.21
   %% pins for the GRANT arm. The diagnostic belongs at admission (6.5), which has a
   %% caller to answer.
   fun {Canonicalize LocalPeer Path}
      if {StartsWith Path "./"} orelse {StartsWith Path "../"} then NeverMatch
      elseif {StartsWith Path "*/"} then NeverMatch
      elseif {StartsWith Path "/"} then Path
      else {Append &/|LocalPeer &/|Path}
      end
   end

   Base58Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
   fun {IsPeerId Seg}
      {Length Seg} >= 46 andthen
      {All Seg fun {$ C} {Member C Base58Chars} end}
   end

   %% §5.4 matches_pattern — both sides canonical/absolute
   fun {MatchesPattern Path Pattern}
      %% NeverMatch never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
      %% rule rather than a property of the string: the arm below returns true for a
      %% bare "*", so safety must not rest on a value merely looking unmatchable.
      if Path == NeverMatch orelse Pattern == NeverMatch then false
      elseif Pattern == "*" then true
      elseif {StartsWith Pattern "/*/"} then
         local Remainder = {List.drop Pattern 3} in
            case Path of nil then false
            [] _|Pr then
               %% skip the peer segment: find the next '/' in Pr
               local
                  fun {AfterSlash L}
                     case L of nil then absent
                     [] C|Cr then if C == &/ then Cr else {AfterSlash Cr} end
                     end
                  end
                  Rest = {AfterSlash Pr}
               in
                  if Rest == absent then false
                  else {MatchesPattern Rest Remainder} end
               end
            end
         end
      elseif {Length Pattern} >= 2 andthen {EndsWith Pattern "/*"} then
         {StartsWith Path {List.take Pattern {Length Pattern}-1}}
      else Path == Pattern
      end
   end

   fun {FirstSegment Uri}
      U = if {StartsWith Uri "/"} then Uri.2 else Uri end
      fun {Go L}
         case L of nil then nil
         [] C|Cr then if C == &/ then nil else C|{Go Cr} end
         end
      end
   in
      {Go U}
   end

   fun {ExtractPeer LocalPeer Uri}
      F = {FirstSegment {NormalizeUri Uri}}
   in
      if {IsPeerId F} then F else LocalPeer end
   end

   %% split "a/b/c" (no leading /) into segments
   fun {SplitSegs Path}
      fun {Go L Cur}
         case L of nil then [{Reverse Cur}]
         [] C|Cr then
            if C == &/ then {Reverse Cur}|{Go Cr nil}
            else {Go Cr C|Cur} end
         end
      end
   in
      {Go Path nil}
   end

   %% §1.4 path-flex validation (tree-handler targets): no NUL; absolute paths
   %% peer-rooted; no empty / '.' / '..' segments (one trailing slash allowed).
   fun {PathFlexOk Target}
      if {Member 0 Target} then false
      else
         local AbsOk Body in
            if {StartsWith Target "/"} then
               local Rest = Target.2
                     fun {UpToSlash L} case L of nil then nil [] C|Cr then if C == &/ then nil else C|{UpToSlash Cr} end end end
                     fun {PastSlash L} case L of nil then nil [] C|Cr then if C == &/ then Cr else {PastSlash Cr} end end end
                     First = {UpToSlash Rest} in
                  AbsOk = {IsPeerId First}
                  Body = {PastSlash Rest}
               end
            else
               AbsOk = true
               Body = Target
            end
            if {Not AbsOk} then false
            else
               local B2 = if Body \= nil andthen {EndsWith Body "/"} then {List.take Body {Length Body}-1} else Body end in
                  if B2 == nil then true
                  else
                     {All {SplitSegs B2} fun {$ Seg}
                                            Seg \= nil andthen Seg \= "." andthen Seg \= ".."
                                         end}
                  end
               end
            end
         end
      end
   end

   %% strip a leading "/{local}/" if present
   fun {StripLocal LocalPeer Pattern}
      Pfx = {Append &/|LocalPeer "/"}
   in
      if {StartsWith Pattern Pfx} then {List.drop Pattern {Length Pfx}}
      else Pattern end
   end
end
