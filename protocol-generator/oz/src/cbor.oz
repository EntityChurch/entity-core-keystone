%% entity-core-protocol-oz — cbor.oz
%% Hand-rolled canonical ECF (RFC 8949 §4.2 deterministic + ENTITY-CBOR-ENCODING
%% v1.5): minimal int heads (Rule 1), length-then-lex map-key sort (Rule 2),
%% definite lengths only (Rule 3), shortest-float ladder + canonical specials
%% (Rule 4/4a), duplicate-key reject (Rule 5), recursive major-type-6 tag reject
%% (§6.3 Option B), UTF-8 validity on text.
%%
%% Tagged value rep (the wire currency inside the peer — Oz strings are
%% char-code lists indistinguishable from byte lists, so mt2-vs-mt3 intent is
%% explicit):
%%   int(N)        - bignum integer (mt0/mt1)
%%   float(Bits)   - the value's EXACT IEEE-754 binary64 bit pattern as a
%%                   bignum int; ALL float logic is integer bit arithmetic
%%                   (A-OZ-002 — VM float semantics never touch the wire)
%%   bytes(L)      - mt2, L = list of ints 0..255
%%   text(L)       - mt3, L = UTF-8 byte list
%%   arr(Vs)       - mt4, list of values
%%   map(Pairs)    - mt5, list of Key#Value (Key/Value are tagged values)
%%   bool(true) / bool(false) / null (atom)
%% "absent" is the atom `absent` (never encodable).
functor
import
   Util at 'util.ozf'
export
   Encode Decode DecodeCanonical MapGet MapGetD
define
   Reject = Util.reject
   Pow2   = Util.pow2
   BitLen = Util.bitLen

   %% ── iterative helpers (no deep recursion on long byte lists) ────────────
   fun {AppendIter L Tail}
      {FoldL {Reverse L} fun {$ A B} B|A end Tail}
   end

   %% take exactly N bytes; iterative (tail-recursive walk + reverse)
   proc {TakeExact L N ?Chunk ?Rest}
      fun {Go L N Acc}
         if N == 0 then Acc#L
         else
            case L of B|Br then {Go Br N-1 B|Acc}
            else {Reject truncatedInput body} unit end
         end
      end
      R = {Go L N nil}
   in
      Chunk = {Reverse R.1}
      Rest = R.2
   end

   %% ── head encoding (minimal, Rule 1) ─────────────────────────────────────
   fun {EncHead Major N Tail}
      B0 = Major * 32
   in
      if N < 24 then (B0 + N)|Tail
      elseif N < 256 then (B0 + 24)|N|Tail
      elseif N < 65536 then (B0 + 25)|{AppendIter {Util.intToBE N 2} Tail}
      elseif N < 4294967296 then (B0 + 26)|{AppendIter {Util.intToBE N 4} Tail}
      elseif N < 18446744073709551616 then (B0 + 27)|{AppendIter {Util.intToBE N 8} Tail}
      else {Reject encodeError intTooLarge} nil
      end
   end

   %% ── float bit logic (pure bignum integer arithmetic, A-OZ-002) ──────────
   fun {OddReduce N P}
      if N mod 2 == 0 then {OddReduce N div 2 P+1} else N#P end
   end

   %% classify a binary64 pattern: nan | inf(S) | zero(S) | fin(s:S n:N p:P)
   %% where value = (-1)^S * N * 2^P, N odd.
   fun {ClassifyF64 Bits}
      S   = Bits div {Pow2 63}
      E11 = (Bits div {Pow2 52}) mod {Pow2 11}
      M52 = Bits mod {Pow2 52}
   in
      if E11 == 2047 then
         if M52 == 0 then inf(S) else nan end
      elseif E11 == 0 andthen M52 == 0 then zero(S)
      else
         local Sig P NP in
            if E11 == 0 then Sig = M52 P = ~1074
            else Sig = {Pow2 52}+M52 P = E11 - 1075
            end
            NP = {OddReduce Sig P}
            fin(s:S n:NP.1 p:NP.2)
         end
      end
   end

   %% can value (n odd, p) be represented exactly at (ManBits, Bias, EMax)?
   fun {FitsAt N P ManBits Bias EMax}
      BL = {BitLen N}
      E  = BL - 1 + P
   in
      if E > EMax then false
      elseif E >= 1 - Bias then BL =< ManBits + 1    % normal: mantissa fits
      else P >= 1 - Bias - ManBits                   % subnormal: no bits lost
      end
   end

   %% fixed-width pattern from (S, N odd, P) at (ExpBits, ManBits, Bias);
   %% assumes {FitsAt} said yes
   fun {BuildBits S N P ExpBits ManBits Bias}
      BL   = {BitLen N}
      E    = BL - 1 + P
      SBit = S * {Pow2 ExpBits + ManBits}
   in
      if E >= 1 - Bias then                          % normal
         SBit + (E + Bias) * {Pow2 ManBits}
              + N * {Pow2 ManBits - (BL - 1)} - {Pow2 ManBits}
      else                                           % subnormal
         SBit + N * {Pow2 P - (1 - Bias - ManBits)}
      end
   end

   %% shortest-form float encode — Rule 4 / 4a
   fun {EncFloat Bits Tail}
      case {ClassifyF64 Bits}
      of nan     then 249|126|0|Tail                              % f9 7e00
      [] inf(S)  then if S == 0 then 249|124|0|Tail else 249|252|0|Tail end
      [] zero(S) then if S == 0 then 249|0|0|Tail else 249|128|0|Tail end
      [] fin(s:S n:N p:P) then
         if {FitsAt N P 10 15 15} then
            249|{AppendIter {Util.intToBE {BuildBits S N P 5 10 15} 2} Tail}
         elseif {FitsAt N P 23 127 127} then
            250|{AppendIter {Util.intToBE {BuildBits S N P 8 23 127} 4} Tail}
         else
            251|{AppendIter {Util.intToBE Bits 8} Tail}
         end
      end
   end

   %% widen an f16/f32 pattern to the exact binary64 pattern
   fun {WidenToF64 Bits ExpBits ManBits Bias}
      S = Bits div {Pow2 ExpBits + ManBits}
      E = (Bits div {Pow2 ManBits}) mod {Pow2 ExpBits}
      M = Bits mod {Pow2 ManBits}
   in
      if E == {Pow2 ExpBits} - 1 then                             % inf / nan
         if M == 0 then S*{Pow2 63} + 2047*{Pow2 52}
         else 9221120237041090560                                 % canonical qNaN
         end
      elseif E == 0 andthen M == 0 then S*{Pow2 63}               % ±0
      elseif E == 0 then                                          % subnormal
         local BL Etrue in
            BL = {BitLen M}
            Etrue = BL - 1 + (1 - Bias - ManBits)
            S*{Pow2 63} + (Etrue + 1023)*{Pow2 52}
                        + M * {Pow2 52 - (BL - 1)} - {Pow2 52}
         end
      else                                                        % normal
         S*{Pow2 63} + (E - Bias + 1023)*{Pow2 52} + M * {Pow2 52 - ManBits}
      end
   end

   %% ── UTF-8 validation (RFC 3629) ─────────────────────────────────────────
   fun {ValidUtf8 L}
      fun {Cont L K Min Acc}
         if K == 0 then
            if Acc < Min orelse (Acc >= 55296 andthen Acc =< 57343)
               orelse Acc > 1114111 then false
            else {ValidUtf8 L} end
         else
            case L of B|Br then
               if B >= 128 andthen B < 192 then {Cont Br K-1 Min Acc*64 + (B mod 64)}
               else false end
            else false end
         end
      end
   in
      case L of nil then true
      [] B|Br then
         if B < 128 then {ValidUtf8 Br}
         elseif B < 194 then false
         elseif B < 224 then {Cont Br 1 128 (B mod 32)}
         elseif B < 240 then {Cont Br 2 2048 (B mod 16)}
         elseif B < 245 then {Cont Br 3 65536 (B mod 8)}
         else false
         end
      end
   end

   %% ── ordering: encoded length first, then bytewise lex (Rule 2) ──────────
   fun {LexLess A B}
      case A of nil then B \= nil
      [] X|Xr then
         case B of nil then false
         [] Y|Yr then
            if X < Y then true elseif X > Y then false else {LexLess Xr Yr} end
         end
      end
   end
   fun {KeyLess A B}
      LA = {Length A} LB = {Length B}
   in
      if LA \= LB then LA < LB else {LexLess A B} end
   end

   proc {CheckDups Sorted}
      case Sorted of T1|T2|R then
         if T1.1 == T2.1 then {Reject nonCanonicalEcf duplicateMapKey}
         else {CheckDups T2|R} end
      else skip end
   end

   %% ── encode ──────────────────────────────────────────────────────────────
   fun {Enc V Tail}
      case V
      of int(N) then
         if N >= 0 then {EncHead 0 N Tail}
         else {EncHead 1 (~N - 1) Tail} end
      [] float(Bits) then {EncFloat Bits Tail}
      [] bytes(L) then {EncHead 2 {Length L} {AppendIter L Tail}}
      [] text(L) then
         if {ValidUtf8 L} then {EncHead 3 {Length L} {AppendIter L Tail}}
         else {Reject encodeError invalidUtf8} nil end
      [] arr(Vs) then
         {EncHead 4 {Length Vs} {FoldR Vs fun {$ It T} {Enc It T} end Tail}}
      [] map(Pairs) then
         local EK Sorted in
            EK = {Map Pairs fun {$ Pr} {Enc Pr.1 nil}#Pr.2 end}
            Sorted = {Sort EK fun {$ A B} {KeyLess A.1 B.1} end}
            {CheckDups Sorted}
            {EncHead 5 {Length Pairs}
             {FoldR Sorted fun {$ T Acc} {AppendIter T.1 {Enc T.2 Acc}} end Tail}}
         end
      [] bool(B) then if B then 245|Tail else 244|Tail end
      [] null then 246|Tail
      else {Reject encodeError unencodableValue} nil
      end
   end

   fun {Encode V} {Enc V nil} end

   %% ── decode ──────────────────────────────────────────────────────────────
   proc {DecHead L ?Major ?Arg ?Rest}
      case L of B|Br then
         Minor = B mod 32
      in
         Major = B div 32
         if Minor < 24 then Arg = Minor Rest = Br
         elseif Minor == 24 then
            case Br of A|R then Arg = A Rest = R
            else {Reject truncatedInput head} end
         elseif Minor =< 27 then
            local W C in
               W = {Pow2 Minor - 24}          % 25->2, 26->4, 27->8
               {TakeExact Br W ?C ?Rest}
               Arg = {Util.bEToInt C}
            end
         else
            {Reject nonCanonicalEcf indefiniteOrReservedMinor}
         end
      else {Reject truncatedInput emptyInput} end
   end

   proc {DecN N Lin ?Items ?Lout}
      if N == 0 then Items = nil Lout = Lin
      else
         local It R1 Ir in
            {Dec Lin ?It ?R1}
            Items = It|Ir
            {DecN N-1 R1 ?Ir ?Lout}
         end
      end
   end

   proc {DecPairs N Lin Seen ?Pairs ?Lout}
      if N == 0 then Pairs = nil Lout = Lin
      else
         local K R1 Val R2 Pr EncK in
            {Dec Lin ?K ?R1}
            {Dec R1 ?Val ?R2}
            EncK = {Encode K}
            if {Member EncK Seen} then
               {Reject nonCanonicalEcf duplicateMapKey}
            end
            Pairs = (K#Val)|Pr
            {DecPairs N-1 R2 EncK|Seen ?Pr ?Lout}
         end
      end
   end

   proc {Dec L ?V ?Rest}
      Major Arg R0
   in
      {DecHead L ?Major ?Arg ?R0}
      case Major
      of 0 then V = int(Arg) Rest = R0
      [] 1 then V = int(~1 - Arg) Rest = R0
      [] 2 then local C in {TakeExact R0 Arg ?C ?Rest} V = bytes(C) end
      [] 3 then
         local C in
            {TakeExact R0 Arg ?C ?Rest}
            if {ValidUtf8 C} then V = text(C)
            else {Reject nonCanonicalEcf invalidUtf8} end
         end
      [] 4 then local Items in {DecN Arg R0 ?Items ?Rest} V = arr(Items) end
      [] 5 then local Pairs in {DecPairs Arg R0 nil ?Pairs ?Rest} V = map(Pairs) end
      [] 6 then {Reject tagRejected Arg}
      [] 7 then
         case L of B|_ then
            Minor = B mod 32
         in
            if Minor == 20 then V = bool(false) Rest = R0
            elseif Minor == 21 then V = bool(true) Rest = R0
            elseif Minor == 22 then V = null Rest = R0
            elseif Minor == 25 then V = float({WidenToF64 Arg 5 10 15}) Rest = R0
            elseif Minor == 26 then V = float({WidenToF64 Arg 8 23 127}) Rest = R0
            elseif Minor == 27 then V = float(Arg) Rest = R0
            else {Reject nonCanonicalEcf unsupportedSimpleValue}
            end
         else skip end
      else {Reject nonCanonicalEcf badMajor}
      end
   end

   %% structural decode; rejects trailing bytes
   fun {Decode Bytes}
      V Rest
   in
      {Dec Bytes ?V ?Rest}
      if Rest \= nil then {Reject nonCanonicalEcf trailingBytes} end
      V
   end

   %% strict decode: structural + byte-identical canonical re-encode
   fun {DecodeCanonical Bytes}
      V = {Decode Bytes}
   in
      if {Encode V} == Bytes then V
      else {Reject nonCanonicalEcf reencodeMismatch} V end
   end

   %% ── map helpers on the tagged rep ───────────────────────────────────────
   fun {MapGet M Key}
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
   fun {MapGetD M Key Default}
      R = {MapGet M Key}
   in
      if R == absent then Default else R end
   end
end
