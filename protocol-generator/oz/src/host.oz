%% entity-core-protocol-oz — host.oz (standalone S4-ready host root functor).
%% Boots ONE peer on a localhost port, prints `LISTENING <port>` (transport), then
%% runs the native Open.socket accept loop forever (dataflow-thread-per-connection).
%%
%% Flags (parsed off {Application.getArgs plain}):
%%   --port N               bind port (0 = ephemeral)
%%   --name NAME            load the Ed25519 identity from ~/.entity/peers/NAME/keypair
%%                          (entity-core PEM = base64 of a 32-byte seed)
%%   --seed HH              fallback: a hex byte repeated 32x for a deterministic seed
%%   --daemon PATH          the entity-codec-daemon binary (crypto/clock/entropy seam)
%%   --debug-open-grants    degenerate [default -> *] admin seed policy (non-conformant)
%%   --validate             bootstrap the §7a system-validate conformance handlers
functor
import
   System Application Open OS
   Crypto at 'crypto.ozf'
   Peer at 'peer.ozf'
   Transport at 'transport.ozf'
define
   fun {Replicate N X} if N =< 0 then nil else X|{Replicate N-1 X} end end
   %% ── read a whole file to a byte list ──
   fun {ReadFile Path}
      F = {New Open.file init(name:Path flags:[read])}
      fun {Go}
         Xs M
      in
         {F read(list:?Xs size:65536 len:?M)}
         if M == 0 then nil else {Append Xs {Go}} end
      end
      R = {Go}
   in
      {F close}
      R
   end

   %% RFC-4648 base64 decode -> byte list (Mozart has no base64)
   fun {B64Decode S}
      Alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
      fun {Val C}
         fun {Go A I} case A of nil then ~1 [] X|Xr then if X == C then I else {Go Xr I+1} end end end
      in
         {Go Alpha 0}
      end
      %% collect 6-bit groups until '=' or end
      fun {Bits Cs}
         case Cs of nil then nil
         [] C|Cr then
            if C == &= then nil
            else
               local V = {Val C} in
                  if V < 0 then {Bits Cr}
                  else {Append {SixBits V} {Bits Cr}} end
               end
            end
         end
      end
      fun {SixBits V}
         [V div 32 mod 2  V div 16 mod 2  V div 8 mod 2  V div 4 mod 2  V div 2 mod 2  V mod 2]
      end
      AllBits = {Bits S}
      %% take whole bytes (8 bits)
      fun {Bytes Bs}
         if {Length Bs} < 8 then nil
         else
            local B8 = {List.take Bs 8}
                  N = {FoldL B8 fun {$ A X} A*2 + X end 0} in
               N|{Bytes {List.drop Bs 8}}
            end
         end
      end
   in
      {Bytes AllBits}
   end

   %% strip PEM armor, base64-decode, require 32-byte seed
   fun {LoadSeedFromName Nm}
      Home0 = {OS.getEnv "HOME"}
      Home = if Home0 == false then "/root" else {Atom.toString Home0} end
      NmS = {VirtualString.toString Nm}
      Path = {Append Home {Append "/.entity/peers/" {Append NmS "/keypair"}}}
      Raw = {ReadFile Path}
      %% keep only non-armor lines (drop lines starting with '-')
      fun {StripArmor L Cur InLineStart}
         case L of nil then {Reverse Cur}
         [] C|Cr then
            if C == 10 then {StripArmor Cr Cur true}
            elseif InLineStart andthen C == &- then {StripArmor {DropLine Cr} Cur true}
            else {StripArmor Cr C|Cur false} end
         end
      end
      fun {DropLine L} case L of nil then nil [] C|Cr then if C == 10 then Cr else {DropLine Cr} end end end
      Body = {Filter {StripArmor Raw nil true} fun {$ C} C \= 13 andthen C \= 32 end}
      Seed = {B64Decode Body}
   in
      if {Length Seed} \= 32 then
         {System.showError "peer: --name "#Nm#" — expected 32-byte seed, got "#{Length Seed}}
         {Application.exit 2} nil
      else Seed end
   end

   fun {HexByte Hh}
      fun {V C} if C >= &0 andthen C =< &9 then C - &0 elseif C >= &a andthen C =< &f then C-&a+10 else C-&A+10 end end
   in
      case Hh of A|B|_ then {V A}*16 + {V B} else 0 end
   end

   %% ── parse args ──
   Args = {Application.getArgs plain}
   fun {Parse L Acc}
      case L of nil then Acc
      [] Flag|Rest then
         case Flag
         of "--port" then case Rest of V|R2 then {Parse R2 {AdjoinAt Acc port {String.toInt V}}} else Acc end
         [] "--name" then case Rest of V|R2 then {Parse R2 {AdjoinAt Acc name V}} else Acc end
         [] "--seed" then case Rest of V|R2 then {Parse R2 {AdjoinAt Acc seed V}} else Acc end
         [] "--daemon" then case Rest of V|R2 then {Parse R2 {AdjoinAt Acc daemon V}} else Acc end
         [] "--debug-open-grants" then {Parse Rest {AdjoinAt Acc open true}}
         [] "--validate" then {Parse Rest {AdjoinAt Acc validate true}}
         else {Parse Rest Acc} end
      end
   end
   Opts = {Parse Args opts(port:0 name:unit seed:unit daemon:"build/eccodecd" open:false validate:false)}
in
   %% boot the crypto daemon FIRST (bootstrap hashing crosses it)
   {Crypto.init Opts.daemon}
   local
      Seed = if Opts.name \= unit then {LoadSeedFromName Opts.name}
             elseif Opts.seed \= unit then {Replicate 32 {HexByte Opts.seed}}
             else {Replicate 32 17} end     % 0x11 x 32 default
      P = {Peer.create Seed Opts.open Opts.validate}
   in
      {Transport.serve P Opts.port}
   end
end
