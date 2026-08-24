%% entity-core-protocol-oz — crypto.oz
%% Client for the entity-codec-daemon co-process (src/daemon/eccodecd.c, framing
%% per src/daemon/DAEMON-PROTOCOL.md). The daemon is spawned once via Open.pipe;
%% the pipe is a shared serial resource, so ALL access goes through a PORT AGENT:
%% one owning thread does the pipe I/O, each caller's request carries a dataflow
%% variable the agent binds with the result (the dataflow answer to "many
%% threads, one pipe"). Blocking pipe reads live in that one thread only —
%% Mozart VM threads are preemptive, so a blocked daemon call never starves the
%% scheduler.
functor
import
   Open
   Util at 'util.ozf'
export
   Init Sha256 Sha384 Ed25519Pub Ed25519Sign Ed25519Verify
   Ed448Pub Ed448Sign Ed448Verify NowMs Random
define
   AgentPort = {NewCell unit}

   proc {ReadExact P N ?Bytes}
      if N == 0 then Bytes = nil
      else
         local Xs M Rest in
            {P read(list:?Xs size:N len:?M)}
            if M == 0 then {Util.reject daemonError eof}
            else
               Bytes = {Append Xs Rest}
               {ReadExact P N-M ?Rest}
            end
         end
      end
   end

   proc {DoCall P Op Payload ?Reply}
      try
         Hdr Status Len Body
      in
         {P write(vs:Op|{Append {Util.intToBE {Length Payload} 4} Payload})}
         {ReadExact P 5 ?Hdr}
         Status = Hdr.1
         Len = {Util.bEToInt {Util.dropN Hdr 1}}
         {ReadExact P Len ?Body}
         if Status == 0 then Reply = ok(Body)
         else Reply = err(Body) end
      catch E then
         Reply = exn(E)
      end
   end

   %% {Init DaemonPath} — spawn the daemon + start its owning agent thread
   proc {Init DaemonPath}
      P = {New Open.pipe init(cmd:DaemonPath args:nil)}
      S Prt
   in
      Prt = {NewPort S}
      AgentPort := Prt
      thread
         {ForAll S proc {$ Msg}
                      case Msg of req(Op Payload Reply) then
                         {DoCall P Op Payload ?Reply}
                      end
                   end}
      end
   end

   fun {Call Op Payload}
      Reply
   in
      {Send @AgentPort req(Op Payload Reply)}
      case Reply
      of ok(B) then B
      [] err(B) then {Util.reject daemonError {String.toAtom B}} nil
      [] exn(E) then raise E end nil
      end
   end

   fun {Sha256 Msg} {Call 1 Msg} end
   fun {Sha384 Msg} {Call 2 Msg} end
   fun {Ed25519Pub Seed} {Call 3 Seed} end
   fun {Ed25519Sign Seed Msg} {Call 4 {Append Seed Msg}} end
   fun {Ed25519Verify Pub Sig Msg}
      {Call 5 {Append Pub {Append Sig Msg}}} == [1]
   end
   fun {Ed448Pub Seed} {Call 6 Seed} end
   fun {Ed448Sign Seed Msg} {Call 7 {Append Seed Msg}} end
   fun {Ed448Verify Pub Sig Msg}
      {Call 8 {Append Pub {Append Sig Msg}}} == [1]
   end
   fun {NowMs} {Util.bEToInt {Call 16 nil}} end
   fun {Random N} {Call 17 {Util.intToBE N 2}} end
end
