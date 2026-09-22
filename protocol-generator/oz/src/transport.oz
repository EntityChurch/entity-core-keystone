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

   %% read exactly N bytes off a socket.
   %%   byte list -> the N bytes
   %%   absent    -> the stream ended with NOTHING read for this call
   %%   short     -> the stream ended PART WAY THROUGH
   %%
   %% A CLEAN CLOSE AT A FRAME BOUNDARY AND A STREAM THAT ENDED MID-FRAME ARE DIFFERENT
   %% EVENTS AND THIS USED TO COLLAPSE THEM INTO `absent` (0.8.2.25, section 4.11). The
   %% first is an ordinary hangup, owed nothing -- there is no refusal and nobody to
   %% answer. The second is a TRUNCATED frame, which section 4.11's framing arm names in
   %% as many words ("a length prefix that never completes") and answers 400
   %% invalid_request. Only the frame boundary knows which, so the distinction has to be
   %% made HERE, where the caller can still tell the header read from the body read.
   fun {ReadExact Sock N}
      fun {Go Need Acc}
         if Need == 0 then {Reverse Acc}
         else
            Xs M
         in
            try {Sock read(list:?Xs size:Need len:?M)}
            catch _ then M = 0 Xs = nil end
            if M == 0 then (if Acc == nil then absent else short end)
            else {Go Need-M {FoldL Xs fun {$ A B} B|A end Acc}}
            end
         end
      end
   in
      {Go N nil}
   end

   %% The (status, code) section 4.11 assigns a pre-admission failure's CAUSE.
   %%
   %% "The frame obligation belongs to the class; the CODE belongs to the cause [MUST]" --
   %% a single code for the class answers an honest caller under the wrong reason and sends
   %% them to the wrong layer. This peer answered `non_canonical_ecf` for every
   %% decode-boundary refusal until 0.8.2.24/.25 pinned them apart:
   %%
   %%   a mis-keyed included entry        400 hash_mismatch      (section 5.2a, N4/N5)
   %%   a CBOR tag in a data field        400 non_canonical_ecf  (ENTITY-CBOR-ENCODING)
   %%   anything else that never becomes
   %%     an Envelope                     400 invalid_request    (sections 4.7, 4.11)
   %%
   %% The tag arm keeps its own code deliberately: section 4.11 rules `non_canonical_ecf`
   %% non-conformant "on the framing arm" and gives its reason in the same sentence --
   %% ENTITY-CBOR-ENCODING defines that code for CBOR tag-policy violations specifically,
   %% which section 6.3 still MUSTs at decode time. The two rows are disjoint by CAUSE.
   %%
   %% Every literal is ASCII by discipline (A-OZ-008): a non-ASCII byte in a wire-visible
   %% Oz string constant crashed this peer's encode path once already.
   fun {PreAdmissionCode K}
      if K == contentHashMismatch orelse K == includedKeyMismatch then "hash_mismatch"
      elseif K == tagRejected then "non_canonical_ecf"
      else "invalid_request" end
   end

   %% Put section 4.11's coded EXECUTE_RESPONSE on the wire. An empty Rid IS the
   %% best-effort uncorrelated form the section PRESCRIBES where no id can be recovered,
   %% not a failure: an uncorrelated coded frame still tells the sender its frame was
   %% REFUSED rather than lost, and that is the distinction a silent drop destroys.
   proc {RefusePreAdmission Writer Rid Status Code}
      try
         {Send Writer {Wire.frameOfEnvelope
            {Env.make {Wire.makeResponse Rid Status {Wire.errorResult Code ""}} nil}}}
      catch _ then skip end
   end

   %% Block until every frame queued on this writer has reached the socket.
   %%
   %% Required ONLY on the arms that close afterwards -- the two framing refusals. On the
   %% decode-boundary arms the loop keeps running and the socket stays open, so the queue
   %% drains on its own. Calling it there would be harmless and would also be noise.
   proc {FlushWriter Writer}
      X in {Send Writer flush(X)} {Wait X}
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
          proc {$ Msg}
             %% `flush(X)` is a SYNCHRONIZATION message, not a frame. The writer is an
             %% asynchronous port agent, so {Send Writer Frame} QUEUES a write and returns
             %% -- which is exactly right for dispatch and exactly wrong for a refusal the
             %% caller then closes the socket after. Measured: the section 4.11 framing
             %% refusals were composed, queued, and lost, because {Sock close} ran first
             %% and the probe saw a bare close. Binding X is the barrier: the sender waits
             %% on it and knows every earlier message in this port's stream has been
             %% written, because a port stream is ordered.
             case Msg
             of flush(X) then X = unit
             else try {Sock write(vs:{Wire.frame Msg})} catch _ then skip end
             end
          end}
      end
      P
   end

   %% handle one decoded inbound frame on connection C
   proc {OnFrame PeerH C Writer Pending Payload}
      Env0
      Kind0
   in
      try Env0 = {Wire.envelopeOfFrame Payload} Kind0 = absent
      catch error(entityCore(kind:K ...) ...) then Env0 = absent Kind0 = K
      [] _ then Env0 = absent Kind0 = unknown end
      if Env0 == absent then
         %% A COMPLETE frame the decoder refused. The framing is intact, so we answer and
         %% keep serving -- this used to be a bare `skip`, which rejected the frame
         %% (correct) and then dropped it on the floor (wrong): the sender saw no response
         %% at all and blocked until its own timeout, so a refusal was indistinguishable
         %% from a dead peer, and on a single-connection oracle run it poisons every later
         %% request on the same connection. Section 4.9(c) deliver-or-signal says the same
         %% from the other direction, and section 4.11 (0.8.2.25) makes the coded frame a
         %% MUST for the whole pre-admission class.
         %%
         %% THE CODE IS THE CAUSE'S -- see PreAdmissionCode. This arm answered
         %% `non_canonical_ecf` for every cause until 0.8.2.24/.25.
         %%
         %% AND AN UNRECOVERABLE request_id IS NO LONGER SILENCE. It used to be, on the
         %% reading that an unattributable frame has nobody to answer; section 4.11 rules
         %% otherwise and prescribes the uncorrelated best-effort frame for exactly that
         %% case. The frame is still REJECTED -- only enough is salvaged to correlate.
         local Rid RidS in
            try Rid = {Wire.salvageRequestId Payload} catch _ then Rid = absent end
            RidS = if Rid == absent then "" else Rid end
            {RefusePreAdmission Writer RidS 400 {PreAdmissionCode Kind0}}
         end
      else
         local Root = {Env.root Env0} in
            if {Ent.typeIs Root "system/protocol/execute/response"} then
               local Rid = {Ent.getText Root "request_id"} in
                  if Rid \= absent then {Send Pending resolve(Rid Env0)} end
               end
            elseif {Not {Ent.typeIs Root "system/protocol/execute"}} then
               %% A frame that DECODED cleanly and is not a request (section 3.3). It used
               %% to fall into dispatch, which answered nothing -- a silent drop, and the
               %% weaker of section 4.11's two named non-conformant behaviours PRECISELY
               %% BECAUSE NOTHING SURFACES IT. The caller is correlatable: the request_id
               %% sits in a root we decoded successfully.
               local Rid RidS in
                  Rid = {Ent.getText Root "request_id"}
                  RidS = if Rid == absent then "" else Rid end
                  {RefusePreAdmission Writer RidS 400 "invalid_request"}
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
         if Hdr == absent then skip     % clean close at a frame boundary -- owed nothing
         elseif Hdr == short then
            %% A PARTIAL LENGTH PREFIX. Section 4.11's framing arm names this input
            %% explicitly and answers 400 invalid_request; there is no request_id by
            %% construction, so this is the uncorrelated best-effort form. The stream is
            %% desynchronized, so the frame goes out and THEN the loop ends: section 4.11
            %% makes the frame mandatory and leaves the close to us, and closing is the
            %% only sound choice once the framing is lost -- a CHOICE rather than an
            %% alternative to answering.
            {RefusePreAdmission Writer "" 400 "invalid_request"}
            {FlushWriter Writer}
         else
            local Len = {BE4 Hdr} in
               if Len =< FrameCap then
                  local Payload = {ReadExact Sock Len} in
                     %% The header arrived, so a frame was BEGUN: both `absent` (nothing of
                     %% the body) and `short` (part of it) are truncation here, unlike at
                     %% the header read above where `absent` is an ordinary hangup.
                     if Payload == absent orelse Payload == short then
                        {RefusePreAdmission Writer "" 400 "invalid_request"}
                        {FlushWriter Writer}
                     else {OnFrame PeerH C Writer Pending Payload} {Loop} end
                  end
               elseif Len =< HardCeil then
                  %% over the frame cap but recoverable: buffer, extract request_id,
                  %% emit 413 payload_too_large, keep serving (§4.10(a))
                  local Payload = {ReadExact Sock Len} in
                     if Payload == absent orelse Payload == short then
                        %% The declared body never arrived. That is a TRUNCATION, and it is
                        %% owed 400 invalid_request rather than the 413 this arm was about
                        %% to compute -- the cause the caller needs told is that their frame
                        %% did not finish, not that it was too big.
                        {RefusePreAdmission Writer "" 400 "invalid_request"}
                        {FlushWriter Writer}
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
                  %% GROTESQUELY OVERSIZE: emit 413, THEN close this connection.
                  %%
                  %% This was a bare `skip` -- a close with no coded frame, which section
                  %% 4.11 names as one of its two separately-non-conformant behaviours and
                  %% which is indistinguishable from a network fault (section 4.6).
                  %% Section 4.10(a)'s "SHOULD ... and otherwise MAY close after a
                  %% best-effort coded frame" became a MUST at 0.8.2.25 (N14) precisely
                  %% because the condition is detected AT THE LENGTH PREFIX with the
                  %% connection intact and nothing spent.
                  %%
                  %% Nothing is read: the body is not buffered here and MUST NOT be --
                  %% section 4.10(a) requires the rejection BEFORE fully buffering, and the
                  %% arm above (which does buffer, to recover a correlation id up to
                  %% HardCeil) is the bounded exception rather than the rule. So there is
                  %% no request_id, and this is the uncorrelated best-effort frame.
                  {RefusePreAdmission Writer "" 413 "payload_too_large"}
                  {FlushWriter Writer}
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
