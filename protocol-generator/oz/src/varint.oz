%% entity-core-protocol-oz — varint.oz
%% Unsigned LEB128 (the multikey format-code / key-type varint — N1, §7.3/§1.5).
%% Pure Oz bignum div/mod.
functor
import
   Util at 'util.ozf'
export
   Encode Decode
define
   %% non-negative integer -> LEB128 byte list
   fun {Encode N}
      if N < 0 then {Util.reject encodeError negativeVarint} nil
      elseif N < 128 then [N]
      else (N mod 128 + 128)|{Encode N div 128}
      end
   end

   %% {Decode Bytes ?Value ?Rest} — raises truncatedInput on a dangling
   %% continuation bit
   proc {Decode L ?Value ?Rest}
      fun {Go L Shift Acc}
         case L of B|Br then
            if B < 128 then (Acc + B*{Util.pow2 Shift})#Br
            else {Go Br Shift+7 Acc + (B mod 128)*{Util.pow2 Shift}}
            end
         else {Util.reject truncatedInput varint} unit
         end
      end
      R = {Go L 0 0}
   in
      Value = R.1
      Rest = R.2
   end
end
