%% entity-core-protocol-oz — wire.oz
%% Wire framing (§1.6) + the two message builders (§3.2 EXECUTE, §3.3
%% EXECUTE_RESPONSE). Frame := [4-byte BE len][canonical-ECF envelope]. Only
%% EXECUTE / EXECUTE_RESPONSE are wire message types (§3.3).
functor
import
   Cbor at 'cbor.ozf'
   Val at 'val.ozf'
   Ent at 'entity.ozf'
   Env at 'envelope.ozf'
   Util at 'util.ozf'
export
   FrameOfEnvelope EnvelopeOfFrame Frame
   MakeExecute MakeResponse ErrorResult EmptyParams ResourceTarget
   ResponseStatus ResponseResult
define
   fun {FrameOfEnvelope E} {Cbor.encode {Env.toCbor E}} end

   fun {EnvelopeOfFrame Payload}
      V = {Cbor.decode Payload}
   in
      case V of map(_) then {Env.ofCbor V}
      else {Util.reject notAMap frame} unit end
   end

   %% prefix with 4-byte BE length
   fun {Frame Payload}
      {Append {Util.intToBE {Length Payload} 4} Payload}
   end

   %% EXECUTE builder — author/capability raw hash bytes (absent to omit);
   %% Resource a map value (absent to omit); Params a materialized entity.
   fun {MakeExecute ReqId Uri Operation Params Author Capability Resource}
      Base = [{Val.mkPair "request_id" {Val.txt ReqId}}
              {Val.mkPair "uri" {Val.txt Uri}}
              {Val.mkPair "operation" {Val.txt Operation}}
              {Val.mkPair "params" {Ent.toCbor Params}}]
      WithA = if Author == absent then Base
              else {Append Base [{Val.mkPair "author" bytes(Author)}]} end
      WithC = if Capability == absent then WithA
              else {Append WithA [{Val.mkPair "capability" bytes(Capability)}]} end
      WithR = if Resource == absent then WithC
              else {Append WithC [{Val.mkPair "resource" Resource}]} end
   in
      {Ent.make "system/protocol/execute" map(WithR)}
   end

   fun {MakeResponse ReqId Status Result}
      {Ent.make "system/protocol/execute/response"
       map([{Val.mkPair "request_id" {Val.txt ReqId}}
            {Val.mkPair "status" int(Status)}
            {Val.mkPair "result" {Ent.toCbor Result}}])}
   end

   fun {ErrorResult Code Message}
      D = if Message == "" then [{Val.mkPair "code" {Val.txt Code}}]
          else [{Val.mkPair "code" {Val.txt Code}} {Val.mkPair "message" {Val.txt Message}}] end
   in
      {Ent.make "system/protocol/error" map(D)}
   end

   %% empty-params (§3.2): primitive/any whose data is the canonical empty map
   fun {EmptyParams} {Ent.make "primitive/any" map(nil)} end

   fun {ResourceTarget Target}
      map([{Val.mkPair "targets" {Val.textArray [{Util.vsToBytes Target}]}}])
   end

   fun {ResponseStatus E}
      S = {Ent.getUint {Env.root E} "status"}
   in
      if S == absent then 0 else S end
   end
   fun {ResponseResult E}
      M = {Ent.getMap {Env.root E} "result"}
   in
      if M == absent then absent else {Ent.ofCbor M} end
   end
end
