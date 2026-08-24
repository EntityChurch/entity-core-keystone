%% entity-core-protocol-oz — conn.oz
%% Per-connection state carried through the §6.5 dispatch chain: §4.1/§4.6
%% handshake state (issued nonce + hello-declared peer_id), the `established`
%% post-authenticate gate, an outbound request_id counter, and the §6.11 reentry
%% OUTBOUND seam — a one-arg function {Outbound Env} -> ResponseEnv injected by
%% the transport (keeps the peer transport-agnostic; the seam is a dataflow
%% send+wait on the SAME connection).
%%
%% State lives in single-owner cells; each connection is served by exactly one
%% dataflow thread (transport reader-per-connection), so no locks are needed —
%% one frame fully dispatched before the next is read on that connection.
functor
export
   New Get Set NextOut Outbound SetOutbound HasOutbound
define
   fun {New}
      conn(established:{NewCell false}
           issuedNonce:{NewCell unit}
           helloPeerId:{NewCell unit}
           outCounter:{NewCell 0}
           outbound:{NewCell unit})
   end

   fun {Get C Key}
      case Key of established then @(C.established)
      [] issuedNonce then @(C.issuedNonce)
      [] helloPeerId then @(C.helloPeerId)
      end
   end
   proc {Set C Key V}
      Cel = case Key of established then C.established
            [] issuedNonce then C.issuedNonce
            [] helloPeerId then C.helloPeerId
            end
   in
      Cel := V
   end

   fun {NextOut C} Cel = C.outCounter in Cel := @Cel + 1 @Cel end

   proc {SetOutbound C F} Cel = C.outbound in Cel := F end
   fun {HasOutbound C} @(C.outbound) \= unit end
   %% {Outbound C Env} -> response envelope | absent
   fun {Outbound C Env}
      if @(C.outbound) == unit then absent else {@(C.outbound) Env} end
   end
end
