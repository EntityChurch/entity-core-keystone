%% entity-core-protocol-oz — transport.oz (L4)
%% NATIVE Oz sockets (Open.socket) — the paradigm axis. DATAFLOW-THREAD-PER-
%% CONNECTION:
%%   * one acceptor thread; each accepted socket gets a READER thread that
%%     de-frames §1.6 and ROUTES each frame — it never blocks on dispatch.
%%   * each inbound EXECUTE frame is dispatched in its OWN worker thread
%%     (inbound-concurrent-with-outbound, §4.8/N6 — structural).
%%   * §6.11 demux IS a dataflow variable: a pending outbound request registers
%%     ReqId -> Var in the connection's pending agent; the worker {Wait Var}s and
%%     the reader thread binds Var when the correlated EXECUTE_RESPONSE arrives.
%%     No correlation pump, no callbacks — the variable is the demux.
%%   * per-connection WRITER port agent serializes frame writes so frames from
%%     concurrent workers never interleave.
%% §4.8 store-safety is structural (the store is its own port agent — store.oz);
%% no locks anywhere.
functor
import
   Open
   System
   Wire at 'wire.ozf'
   Env at 'envelope.ozf'
   Ent at 'entity.ozf'
   Conn at 'conn.ozf'
   Peer at 'peer.ozf'
   Util at 'util.ozf'
export
   Serve
define
   FrameCap = 16 * 1024 * 1024        % §1.6 / §4.10(a) 16 MiB limit
   HardCeil = 64 * 1024 * 1024        % buffer ceiling to recover request_id for 413

   %% read exactly N bytes off a socket; returns byte list, or absent on EOF/close
   fun {ReadExact Sock N}
      fun {Go Need Acc}
         if Need == 0 then {Reverse Acc}
         else
            Xs M
         in
            try {Sock read(list:?Xs size:Need len:?M)}
            catch _ then M = 0 Xs = nil end
            if M == 0 then absent
            else {Go Need-M {FoldL Xs fun {$ A B} B|A end Acc}}
            end
         end
      end
   in
      {Go N nil}
   end

   %% BE u32 from 4 bytes
   fun {BE4 L} {Util.bEToInt L} end

   %% per-connection pending-reply agent (owns ReqId -> Var). register / resolve.
   fun {NewPending}
      S P = {NewPort S}
      D = {NewDictionary}
   in
      thread
         {ForAll S
          proc {$ Msg}
             case Msg
             of register(Rid Var) then {Dictionary.put D {String.toAtom Rid} Var}
             [] resolve(Rid E) then
                local K = {String.toAtom Rid} in
                   if {Dictionary.member D K} then
                      {Dictionary.get D K} = E
                      {Dictionary.remove D K}
                   end
                end
             end
          end}
      end
      P
   end

   %% per-connection writer agent (serializes socket writes)
   fun {NewWriter Sock}
      S P = {NewPort S}
   in
      thread
         {ForAll S
          proc {$ Payload}
             try {Sock write(vs:{Wire.frame Payload})} catch _ then skip end
          end}
      end
      P
   end

   %% handle one decoded inbound frame on connection C
   proc {OnFrame PeerH C Writer Pending Payload}
      Env0
   in
      try Env0 = {Wire.envelopeOfFrame Payload} catch _ then Env0 = absent end
      if Env0 == absent then
         %% section 6.3: "Rejection returns 400 non_canonical_ecf" -- a rejected frame is
         %% owed a STATUS, not silence. This used to be a bare `skip`, which rejected the
         %% frame (correct) and then dropped it on the floor (wrong): the sender saw no
         %% response at all and blocked until its own timeout, violating section 6.3's
         %% second sentence and section 4.9(c) deliver-or-signal. It also made a refusal
         %% indistinguishable from a dead peer, and on a single-connection oracle run it
         %% poisons every later request on the same connection.
         %%
         %% The frame is still REJECTED -- only enough is salvaged to correlate the
         %% response. If even the request_id is unrecoverable the frame is unattributable
         %% and silence is the only option left.
         %%
         %% Every literal here is ASCII by discipline (A-OZ-008): a non-ASCII byte in a
         %% wire-visible Oz string constant crashed this peer's encode path once already.
         local Rid in
            try Rid = {Wire.salvageRequestId Payload} catch _ then Rid = absent end
            if Rid \= absent then
               try
                  {Send Writer {Wire.frameOfEnvelope
                     {Env.make {Wire.makeResponse Rid 400
                                {Wire.errorResult "non_canonical_ecf" ""}} nil}}}
               catch _ then skip end
            end
         end
      else
         local Root = {Env.root Env0} in
            if {Ent.typeIs Root "system/protocol/execute/response"} then
               local Rid = {Ent.getText Root "request_id"} in
                  if Rid \= absent then {Send Pending resolve(Rid Env0)} end
               end
            else
               %% dispatch in a worker thread — the reader thread keeps reading,
               %% so a §6.11 reentry inside dispatch never deadlocks.
               thread
                  Resp = {Peer.dispatch PeerH C Env0}
               in
                  if Resp \= absent then {Send Writer {Wire.frameOfEnvelope Resp}} end
               end
            end
         end
      end
   end

   %% reader loop for one accepted socket
   proc {ServeConn PeerH Sock}
      C = {Conn.new}
      Writer = {NewWriter Sock}
      Pending = {NewPending}
      %% inject the §6.11 reentry outbound seam: send + wait on a dataflow var
      proc {InjectOutbound}
         {Conn.setOutbound C
          fun {$ OutEnv}
             Rid = {Ent.getText {Env.root OutEnv} "request_id"}
             Var
          in
             {Send Pending register(Rid Var)}
             {Send Writer {Wire.frameOfEnvelope OutEnv}}
             {Wait Var}
             Var
          end}
      end
      proc {Loop}
         Hdr = {ReadExact Sock 4}
      in
         if Hdr == absent then skip     % connection closed
         else
            local Len = {BE4 Hdr} in
               if Len =< FrameCap then
                  local Payload = {ReadExact Sock Len} in
                     if Payload == absent then skip
                     else {OnFrame PeerH C Writer Pending Payload} {Loop} end
                  end
               elseif Len =< HardCeil then
                  %% over the frame cap but recoverable: buffer, extract request_id,
                  %% emit 413 payload_too_large, keep serving (§4.10(a))
                  local Payload = {ReadExact Sock Len} in
                     if Payload == absent then skip
                     else
                        local
                           Rid = try {Ent.getText {Env.root {Wire.envelopeOfFrame Payload}} "request_id"} catch _ then absent end
                           RidS = if Rid == absent then "" else Rid end
                           Resp = {Env.make {Wire.makeResponse RidS 413 {Wire.errorResult "payload_too_large" ""}} nil}
                        in
                           {Send Writer {Wire.frameOfEnvelope Resp}}
                           {Loop}
                        end
                     end
                  end
               else
                  %% grotesquely oversize: close this connection (peer keeps serving)
                  skip
               end
            end
         end
      end
   in
      {InjectOutbound}
      {Loop}
      try {Sock close} catch _ then skip end
   end

   %% accept loop — blocks the calling thread (keeps ozengine alive)
   proc {Serve PeerH Port}
      Server = {New Open.socket init}
      Bound
      proc {AcceptLoop}
         A
      in
         {Server accept(acceptClass:Open.socket accepted:?A)}
         thread {ServeConn PeerH A} end
         {AcceptLoop}
      end
   in
      {Server bind(takePort:Port port:?Bound)}
      {Server listen}
      {System.showInfo "LISTENING "#Bound}
      {AcceptLoop}
   end
end
