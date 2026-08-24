%% entity-core-protocol-oz — store.oz
%% Foundation storage (§1.7): Content Store (hash -> entity, immutable, dedup)
%% + Entity Tree (path -> hash, mutable location index).
%%
%% §4.8 STORE-SAFETY — THE DATAFLOW ANSWER: the store is a PORT AGENT. One
%% owning thread folds all mutations over the port's stream (a dataflow list);
%% every request carries a dataflow variable the agent binds with the reply.
%% Concurrent per-request dispatch threads can never race the dictionaries —
%% serialization is by construction, with no locks anywhere (the profile's
%% [async] store_model claim).
%%
%% EMIT PATHWAY (§6.10 / §6.13(c)): tree/content writes bump per-store event
%% counters (live with ZERO consumers) and invoke a registered consumer
%% procedure if present — the extensibility hook stays reachable.
functor
export
   New PutEntity GetByHash Bind Unbind HashAt GetAt Listing
   TreeEventCount ContentEventCount RegisterTreeConsumer RegisterContentConsumer
define
   fun {HexAtomOfHash H}
      HexD = "0123456789abcdef"
      fun {Go Bs}
         case Bs of nil then nil
         [] B|Br then {Nth HexD (B div 16)+1}|{Nth HexD (B mod 16)+1}|{Go Br}
         end
      end
   in
      {String.toAtom {Go H}}
   end

   %% agent state is captured in the consumer thread's closures
   fun {New}
      S P = {NewPort S}
      Content = {NewDictionary}    % hexAtom -> ent
      Tree = {NewDictionary}       % pathAtom -> hash-hex-atom | unit (unbound)
      PathsC = {NewCell nil}       % every path-string ever bound (rev order)
      TreeEv = {NewCell 0}
      ContEv = {NewCell 0}
      TreeCons = {NewCell unit}
      ContCons = {NewCell unit}

      proc {DoPut E}
         K = {HexAtomOfHash E.hash}
      in
         if {Dictionary.member Content K} then skip
         else
            {Dictionary.put Content K E}
            ContEv := @ContEv + 1
            if @ContCons \= unit then {@ContCons} end
         end
      end

      proc {DoBind Path E ?Prev}
         PK = {String.toAtom Path}
         NextA = {HexAtomOfHash E.hash}
      in
         {DoPut E}
         if {Dictionary.member Tree PK} then Prev = {Dictionary.get Tree PK}
         else
            Prev = unit
            PathsC := Path|@PathsC
         end
         {Dictionary.put Tree PK NextA}
         if NextA \= Prev then
            TreeEv := @TreeEv + 1
            if @TreeCons \= unit then {@TreeCons} end
         end
      end

      %% one-level listing rows under Prefix: row(seg:S hash:HexAtom|unit child:B)
      fun {DoListing Prefix}
         P = if Prefix \= nil andthen {List.last Prefix} == &/ then Prefix
             else {Append Prefix "/"} end
         PLen = {Length P}
         Acc = {NewDictionary}     % segAtom -> row
         Order = {NewCell nil}
         %% split Rest at the first '/': seg#hasMore  (hasMore=true => child path)
         fun {FirstSeg L Cur}
            case L of nil then {Reverse Cur}#false
            [] C|Cr then
               if C == &/ then {Reverse Cur}#true else {FirstSeg Cr C|Cur} end
            end
         end
         proc {AccRow Seg HashA Child}
            SA = {String.toAtom Seg}
         in
            if {Dictionary.member Acc SA} then
               local Old = {Dictionary.get Acc SA} in
                  {Dictionary.put Acc SA
                   row(seg:Seg
                       hash:if HashA \= unit then HashA else Old.hash end
                       child:(Old.child orelse Child))}
               end
            else
               {Dictionary.put Acc SA row(seg:Seg hash:HashA child:Child)}
               Order := Seg|@Order
            end
         end
      in
         {ForAll {Reverse @PathsC}
          proc {$ Path}
             PK = {String.toAtom Path}
             BoundA = {Dictionary.condGet Tree PK unit}
          in
             if BoundA == unit then skip
             elseif {Length Path} =< PLen then skip
             elseif {List.take Path PLen} \= P then skip
             else
                local Rest = {List.drop Path PLen}
                      SM = {FirstSeg Rest nil} in
                   if SM.2 then {AccRow SM.1 unit true}       % child path
                   else {AccRow SM.1 BoundA false}            % leaf
                   end
                end
             end
          end}
         {Sort {Map {Reverse @Order} fun {$ Seg} {Dictionary.get Acc {String.toAtom Seg}} end}
          fun {$ A B} {LexLess A.seg B.seg} end}
      end

      fun {LexLess A B}
         case A of nil then B \= nil
         [] X|Xr then
            case B of nil then false
            [] Y|Yr then
               if X < Y then true elseif X > Y then false else {LexLess Xr Yr} end
            end
         end
      end
   in
      thread
         {ForAll S
          proc {$ Msg}
             case Msg
             of putEntity(E R) then {DoPut E} R = unit
             [] getByHash(H R) then
                R = {Dictionary.condGet Content {HexAtomOfHash H} absent}
             [] bind(Path E R) then local Prev in {DoBind Path E Prev} end R = unit
             [] unbind(Path R) then
                local PK = {String.toAtom Path} in
                   if {Dictionary.member Tree PK} andthen {Dictionary.get Tree PK} \= unit then
                      {Dictionary.put Tree PK unit}
                      TreeEv := @TreeEv + 1
                      if @TreeCons \= unit then {@TreeCons} end
                   end
                end
                R = unit
             [] hashAt(Path R) then
                R = {Dictionary.condGet Tree {String.toAtom Path} unit}
             [] getAt(Path R) then
                local HA = {Dictionary.condGet Tree {String.toAtom Path} unit} in
                   if HA == unit then R = absent
                   else R = {Dictionary.condGet Content HA absent} end
                end
             [] listing(Prefix R) then R = {DoListing Prefix}
             [] treeEvents(R) then R = @TreeEv
             [] contentEvents(R) then R = @ContEv
             [] regTreeConsumer(Pr R) then TreeCons := Pr R = unit
             [] regContentConsumer(Pr R) then ContCons := Pr R = unit
             end
          end}
      end
      P
   end

   %% ── client API (each call blocks on its own dataflow reply variable) ──
   proc {PutEntity St E} R in {Send St putEntity(E R)} {Wait R} end
   fun {GetByHash St H} R in {Send St getByHash(H R)} R end
   proc {Bind St Path E} R in {Send St bind(Path E R)} {Wait R} end
   proc {Unbind St Path} R in {Send St unbind(Path R)} {Wait R} end
   fun {HashAt St Path} R in {Send St hashAt(Path R)} R end       % hex-atom | unit
   fun {GetAt St Path} R in {Send St getAt(Path R)} R end         % ent | absent
   fun {Listing St Prefix} R in {Send St listing(Prefix R)} R end
   fun {TreeEventCount St} R in {Send St treeEvents(R)} R end
   fun {ContentEventCount St} R in {Send St contentEvents(R)} R end
   proc {RegisterTreeConsumer St Pr} R in {Send St regTreeConsumer(Pr R)} {Wait R} end
   proc {RegisterContentConsumer St Pr} R in {Send St regContentConsumer(Pr R)} {Wait R} end
end
