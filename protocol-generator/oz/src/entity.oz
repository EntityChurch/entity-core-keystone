%% entity-core-protocol-oz — entity.oz
%% Materialized entity {type, data, content_hash} (§1.1, §3.4) over the S2 codec.
%% Record rep: ent(typ:TypeBytes data:TV hash:HashBytes33); `absent` when missing.
%% content_hash = 0x00 ‖ SHA256(ECF({type,data})) (§7.1) — SHA via the daemon.
functor
import
   Cbor at 'cbor.ozf'
   Val at 'val.ozf'
   Util at 'util.ozf'
   Crypto at 'crypto.ozf'
export
   Make Admitted Typ Hash Data DataMap ToCbor OfCbor ContentHash
   GetText GetBytes GetUint GetField GetMap GetEntity TypeIs
define
   %% content hash of (type-bytes, data-TV)
   fun {ContentHash TypeBytes DataTV}
      Ecf = {Cbor.encode map([{Val.mkPair "type" text(TypeBytes)}
                              {Val.mkPair "data" DataTV}])}
   in
      0|{Crypto.sha256 Ecf}
   end

   %% {Make "system/peer" DataTV}
   fun {Make TypeVs DataTV}
      TB = {Util.vsToBytes TypeVs}
   in
      ent(typ:TB data:DataTV hash:{ContentHash TB DataTV})
   end

   %% The §6.3 RECEIPT constructor: bind an entity to a content_hash the CALLER
   %% has already verified against {ContentHash Type Data}.
   %%
   %% {Make} AUTHORS a hash. On the system/tree:put path that is exactly what
   %% §6.3 (0.8.2.11) forbids — the submitter authors, the peer verifies. This
   %% takes the carried bytes verbatim and is reachable only from the admission
   %% ladder, which has just proved they match.
   fun {Admitted TypeBytes DataTV VerifiedHash}
      ent(typ:TypeBytes data:DataTV hash:VerifiedHash)
   end

   fun {Typ E} E.typ end
   fun {Hash E} E.hash end
   fun {Data E} E.data end
   fun {TypeIs E Name} E.typ == {Util.vsToBytes Name} end

   %% data as map view (empty map for scalar data)
   fun {DataMap E}
      case E.data of map(_) then E.data else map(nil) end
   end

   %% wire entity map {type, data, content_hash}
   fun {ToCbor E}
      map([{Val.mkPair "type" text(E.typ)}
           {Val.mkPair "data" E.data}
           {Val.mkPair "content_hash" bytes(E.hash)}])
   end

   %% parse a wire entity map; recompute + validate the hash (§1.8 fidelity)
   fun {OfCbor MTV}
      T = {Val.getText MTV "type"}
      D = {Val.get MTV "data"}
   in
      if T == absent then {Util.reject missingType entity} unit
      elseif D == absent then {Util.reject missingData entity} unit
      else
         local E = ent(typ:T data:D hash:{ContentHash T D})
               Carried = {Val.getBytes MTV "content_hash"} in
            if Carried \= absent andthen Carried \= E.hash then
               {Util.reject contentHashMismatch entity} unit
            else E end
         end
      end
   end

   %% field reads off the data map view
   fun {GetText E K} {Val.getText {DataMap E} K} end
   fun {GetBytes E K} {Val.getBytes {DataMap E} K} end
   fun {GetUint E K} {Val.getUint {DataMap E} K} end
   fun {GetField E K} {Val.get {DataMap E} K} end
   fun {GetMap E K} {Val.getMap {DataMap E} K} end

   %% decode a nested wire-entity map carried at K, or absent
   fun {GetEntity E K}
      M = {GetMap E K}
   in
      if M == absent then absent else {OfCbor M} end
   end
end
