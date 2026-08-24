%% entity-core-protocol-oz — base58.oz
%% Bitcoin-alphabet Base58 encode/decode, over Oz bignum arithmetic.
functor
import
   Util at 'util.ozf'
export
   Encode Decode
define
   Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

   %% byte list -> base58 char list
   fun {Encode Bytes}
      fun {LeadZeros L}
         case L of 0|Br then 1 + {LeadZeros Br} else 0 end
      end
      fun {Digits N Acc}
         if N == 0 then Acc
         else {Digits N div 58 {Nth Alphabet (N mod 58)+1}|Acc}
         end
      end
      Z = {LeadZeros Bytes}
      N = {Util.bEToInt Bytes}
      Body = {Digits N nil}
   in
      {AppendList {Map {List.number 1 Z 1} fun {$ _} &1 end} Body}
   end

   %% base58 char list -> byte list (raises on a non-alphabet char)
   fun {Decode Chars}
      fun {DigitVal C}
         fun {Go A I}
            case A of nil then {Util.reject badBase58 C} 0
            [] X|Xr then if X == C then I else {Go Xr I+1} end
            end
         end
      in
         {Go Alphabet 0}
      end
      fun {LeadOnes L}
         case L of &1|Br then 1 + {LeadOnes Br} else 0 end
      end
      Z = {LeadOnes Chars}
      N = {FoldL Chars fun {$ A C} A*58 + {DigitVal C} end 0}
      fun {ToBytes N Acc}
         if N == 0 then Acc else {ToBytes N div 256 (N mod 256)|Acc} end
      end
      Body = {ToBytes N nil}
   in
      {AppendList {Map {List.number 1 Z 1} fun {$ _} 0 end} Body}
   end

   fun {AppendList A B} {FoldL {Reverse A} fun {$ Acc X} X|Acc end B} end
end
