%% entity-core-protocol-oz — multisig ACCEPT-path unit test.
%%
%% The oracle's `multisig` category is rejection-heavy (malformed K-of-N -> 403),
%% so a fail-closed peer can pass it WITHOUT ever executing a successful K-of-N
%% verification (the "conformance-green can be vacuous" lesson). This test drives
%% the ACCEPT direction the oracle can't cover: a genuine 2-of-3 multi-signature
%% ROOT capability, signed by 2 of the 3 constituent signers (one of whom is the
%% local peer, per §5.5 M6), MUST verify to 'ALLOW' through Cap.verifyChain.
%% Usage: ozengine build/multisig_accept.ozf <daemon>
functor
import
   System Application
   Crypto at 'crypto.ozf'
   Peer at 'peer.ozf'
   Id at 'identity.ozf'
   Ent at 'entity.ozf'
   Val at 'val.ozf'
   Cap at 'capability.ozf'
   Store at 'store.ozf'
define
   fun {Rep N X} if N =< 0 then nil else X|{Rep N-1 X} end end
   Args = {Application.getArgs plain}
in
   {Crypto.init Args.1}
   local
      %% local peer (a constituent signer, per M6) + two other constituents
      P = {Peer.create {Rep 32 17} false false}
      St = {Peer.storeOf P}
      Local = {Peer.localPeer P}
      I0 = {Peer.identity P}                       % the local peer's identity
      I1 = {Id.ofSeed {Rep 32 34}}                 % 0x22 x 32
      I2 = {Id.ofSeed {Rep 32 51}}                 % 0x33 x 32
      %% a grantee that resolves in `included`
      Grantee = {Id.ofSeed {Rep 32 68}}            % 0x44 x 32
      H0 = {Id.idHash I0} H1 = {Id.idHash I1} H2 = {Id.idHash I2}
      GH = {Id.idHash Grantee}
      %% a 2-of-3 multi-granter root capability
      MultiGranter = map([{Val.mkPair "signers" arr([bytes(H0) bytes(H1) bytes(H2)])}
                          {Val.mkPair "threshold" int(2)}])
      Token = {Ent.make "system/capability/token"
               map([{Val.mkPair "grants" arr([{Cap.mkGrant ["system/tree"] ["*"] ["get"] absent}])}
                    {Val.mkPair "granter" MultiGranter}
                    {Val.mkPair "grantee" bytes(GH)}
                    {Val.mkPair "created_at" int({Cap.nowMs})}])}
      %% two of the three constituents co-sign the cap's content hash
      Sig0 = {Id.sign I0 Token}
      Sig1 = {Id.sign I1 Token}
      Included = [Token
                  {Id.peerEntity I0} {Id.peerEntity I1} {Id.peerEntity I2}
                  {Id.peerEntity Grantee} Sig0 Sig1]
      Verdict = {Cap.verifyChain Local St Token Included}
   in
      {System.showInfo "multisig 2-of-3 ACCEPT verdict = "#Verdict}
      if Verdict == 'ALLOW' then
         {System.showInfo "PASS: genuine K-of-N accept path verified"}
         %% negative control: threshold met by only 1 signature must DENY
         local
            Token1 = {Ent.make "system/capability/token"
                      map([{Val.mkPair "grants" arr([{Cap.mkGrant ["system/tree"] ["*"] ["get"] absent}])}
                           {Val.mkPair "granter" MultiGranter}
                           {Val.mkPair "grantee" bytes(GH)}
                           {Val.mkPair "created_at" int({Cap.nowMs})}])}
            Inc1 = [Token1 {Id.peerEntity I0} {Id.peerEntity I1} {Id.peerEntity I2}
                    {Id.peerEntity Grantee} {Id.sign I0 Token1}]   % only 1 of 2 required
            V1 = {Cap.verifyChain Local St Token1 Inc1}
         in
            if V1 == 'DENY' then
               {System.showInfo "PASS: sub-threshold (1-of-3, need 2) correctly DENIED"}
               {Application.exit 0}
            else
               {System.showInfo "FAIL: sub-threshold should DENY, got "#V1}
               {Application.exit 1}
            end
         end
      else
         {System.showInfo "FAIL: expected ALLOW, got "#Verdict}
         {Application.exit 1}
      end
   end
end
