%% entity-core-protocol-oz — envelope.oz
%% The protocol envelope (§3.1): env(root:Ent included:[Ent]). On the wire,
%% `included` is a content_hash(bytes)->entity map; keys MUST equal each
%% entity's content_hash; duplicates dedup first-seen (the canonical codec
%% rejects duplicate map keys).
functor
import
   Val at 'val.ozf'
   Ent at 'entity.ozf'
   Util at 'util.ozf'
export
   Make Root Included IncludedGet ToCbor OfCbor
define
   fun {Make RootE Inc} env(root:RootE included:Inc) end
   fun {Root E} E.root end
   fun {Included E} E.included end

   fun {IncludedGet E H}
      fun {Go L}
         case L of nil then absent
         [] X|Xr then if {Ent.hash X} == H then X else {Go Xr} end
         end
      end
   in
      {Go E.included}
   end

   fun {DedupByHash Inc}
      fun {Go L Seen}
         case L of nil then nil
         [] X|Xr then
            local H = {Ent.hash X} in
               if {Member H Seen} then {Go Xr Seen}
               else X|{Go Xr H|Seen} end
            end
         end
      end
   in
      {Go Inc nil}
   end

   fun {ToCbor E}
      Ded = {DedupByHash E.included}
      IncPairs = {Map Ded fun {$ X} bytes({Ent.hash X})#{Ent.toCbor X} end}
   in
      map([{Val.mkPair "root" {Ent.toCbor E.root}}
           {Val.mkPair "included" map(IncPairs)}])
   end

   %% parse a wire envelope map; verifies included key == content_hash (§3.1)
   fun {OfCbor MTV}
      RootV = {Val.getMap MTV "root"}
   in
      if RootV == absent then {Util.reject missingRoot envelope} unit
      else
         local
            RootE = {Ent.ofCbor RootV}
            IncM = {Val.getMapPairs MTV "included"}
            fun {Go Ps}
               case Ps of nil then nil
               [] P|Pr then
                  case P.1 of bytes(KB) then
                     case P.2 of map(_) then
                        local X = {Ent.ofCbor P.2} in
                           if KB \= {Ent.hash X} then
                              {Util.reject includedKeyMismatch envelope} unit
                           else X|{Go Pr} end
                        end
                     else {Util.reject includedValueNotMap envelope} unit end
                  else {Util.reject includedKeyNotBytes envelope} unit end
               end
            end
            Inc = if IncM == absent then nil else {Go IncM} end
         in
            env(root:RootE included:{DedupByHash Inc})
         end
      end
   end
end
