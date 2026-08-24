%% entity-core-protocol-oz — val.oz
%% Helpers over the tagged ECF value rep (cbor.oz): construction + typed reads.
%% `absent` (atom) is the uniform not-present sentinel.
functor
import
   Util at 'util.ozf'
export
   Txt Bts MkPair EmptyMap TextArray ArrOfList
   Get Has GetText GetBytes GetUint GetArr GetMapPairs GetMap BoolIs
   TextOf BytesOf UintOf UintOfD IntOf ArrItems MapPairs
define
   fun {Txt S} text({Util.vsToBytes S}) end
   fun {Bts B} bytes(B) end
   fun {MkPair K V} {Txt K}#V end
   EmptyMap = map(nil)
   fun {TextArray Strs} arr({Map Strs fun {$ S} text(S) end}) end
   fun {ArrOfList Vs} arr(Vs) end

   %% key lookup on map(Pairs) by ASCII key name
   fun {Get M Key}
      case M of map(Pairs) then
         local
            KB = {Util.vsToBytes Key}
            fun {Go Ps}
               case Ps of nil then absent
               [] P|Pr then
                  case P.1 of text(L) then
                     if L == KB then P.2 else {Go Pr} end
                  else {Go Pr} end
               end
            end
         in
            {Go Pairs}
         end
      else absent end
   end
   fun {Has M Key} {Get M Key} \= absent end

   %% typed extraction from a value (absent/wrong-type -> `absent`)
   fun {TextOf V} case V of text(L) then L else absent end end
   fun {BytesOf V} case V of bytes(L) then L else absent end end
   fun {UintOf V}
      case V of int(N) then if N >= 0 then N else absent end
      else absent end
   end
   fun {IntOf V} case V of int(N) then N else absent end end
   fun {ArrItems V} case V of arr(L) then L else absent end end
   fun {MapPairs V} case V of map(P) then P else absent end end
   fun {UintOfD V D}
      case V of int(N) then N else D end
   end

   %% typed map reads
   fun {GetText M K} {TextOf {Get M K}} end
   fun {GetBytes M K} {BytesOf {Get M K}} end
   fun {GetUint M K} {UintOf {Get M K}} end
   fun {GetArr M K} {ArrItems {Get M K}} end
   fun {GetMapPairs M K} {MapPairs {Get M K}} end
   fun {GetMap M K}
      V = {Get M K}
   in
      case V of map(_) then V else absent end
   end
   fun {BoolIs M K}
      case {Get M K} of bool(B) then B == true else false end
   end
end
