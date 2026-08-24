%% entity-core-protocol-oz — util.oz
%% Byte/bit/hex helpers over Oz bignum integers. Bytes travel as lists of
%% ints 0..255 (the Open.socket/Open.pipe native currency). Mozart has no
%% bitwise integer operators: all bit logic is div/mod arithmetic (exact on
%% bignums — A-OZ-002 discipline).
functor
export
   IntToBE BEToInt BitLen Pow2 HexOfBytes BytesOfHex ByteAt
   TakeN DropN Reject VsToBytes
define
   proc {Reject Kind Detail}
      {Exception.raiseError entityCore(kind:Kind detail:Detail)}
   end

   fun {Pow2 K} {Pow 2 K} end

   %% big-endian fixed-width octets of a non-negative integer
   fun {IntToBE N Width}
      fun {Go N W Acc}
         if W == 0 then Acc
         else {Go N div 256 W-1 (N mod 256)|Acc} end
      end
   in
      {Go N Width nil}
   end

   %% integer from big-endian octet list
   fun {BEToInt L}
      {FoldL L fun {$ A B} A*256 + B end 0}
   end

   %% number of significant bits (BitLen 0 = 0, BitLen 1 = 1, BitLen 255 = 8)
   fun {BitLen N}
      fun {Go N Acc} if N == 0 then Acc else {Go N div 2 Acc+1} end end
   in
      {Go N 0}
   end

   local
      HexD = "0123456789abcdef"
   in
      fun {HexOfBytes Bs}
         case Bs of nil then nil
         [] B|Br then {Nth HexD (B div 16)+1}|{Nth HexD (B mod 16)+1}|{HexOfBytes Br}
         end
      end
   end

   local
      fun {HexVal C}
         if C >= &0 andthen C =< &9 then C - &0
         elseif C >= &a andthen C =< &f then C - &a + 10
         elseif C >= &A andthen C =< &F then C - &A + 10
         else {Reject badHex C} 0 end
      end
   in
      fun {BytesOfHex H}
         case H of nil then nil
         [] A|B|Hr then ({HexVal A}*16 + {HexVal B})|{BytesOfHex Hr}
         [] _ then {Reject badHex oddLength} nil
         end
      end
   end

   fun {ByteAt L I} {Nth L I+1} end   % zero-based

   fun {TakeN L N} {List.take L N} end
   fun {DropN L N} {List.drop L N} end

   %% virtual string -> byte list (via ByteString; Oz atoms/strings are latin-1
   %% char lists — the peer only feeds ASCII through this)
   fun {VsToBytes Vs}
      {ByteString.toString {ByteString.make Vs}}
   end
end
