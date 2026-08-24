⍝ entity-core-protocol-apl — bin/peer.apl (the standalone S4-ready host).
⍝
⍝ Boots ONE peer on a localhost port, prints `LISTENING <port>` (a harness — run-s4.sh —
⍝ scrapes it), then runs the single ⎕FIO select-pump forever (PeerServe). One GNU APL
⍝ image = one peer (the profile [async] single-image model). CLI args come from ⎕ARG.
⍝ Flags: --port N (0=ephemeral) · --name NAME (Ed25519 identity at
⍝ ~/.entity/peers/NAME/keypair) · --seed HH (deterministic seed) · --port-file PATH (writes
⍝ "<port>\n<peer_id>\n" for the smoke) · --validate (§7a conformance handlers, OFF by
⍝ default) · --debug-open-grants (deprecated degenerate default→* policy).

∇Z←ArgVal flag;a;i
 Z←'' ⋄ a←⎕ARG ⋄ i←0
 lp:→(i≥(≢a)-1)/0
 i←i+1 ⋄ →(~(i⊃a)≡flag)/lp
 Z←(i+1)⊃a ⋄ →0
∇
∇Z←ArgHas flag;a;i
 Z←0 ⋄ a←⎕ARG ⋄ i←0
 lp:→(i≥≢a)/0
 i←i+1 ⋄ →(~(i⊃a)≡flag)/lp
 Z←1 ⋄ →0
∇
∇Z←StrToInt s
 Z←0
 →(0=≢s)/0
 Z←10⊥¯1+'0123456789'⍳s
∇

∇PeerMain;name;seedhex;portS;port;portfile;validate;openg;seed;bound;pf
 name←ArgVal'--name' ⋄ seedhex←ArgVal'--seed' ⋄ portS←ArgVal'--port'
 portfile←ArgVal'--port-file'
 validate←ArgHas'--validate' ⋄ openg←ArgHas'--debug-open-grants'
 port←StrToInt portS
 →(0=≢name)/ns
 seed←KeystoreSeedOfName name ⋄ →mk
 ns:→(0=≢seedhex)/dfl
 seed←KeystoreSeedOfHexbyte seedhex ⋄ →mk
 dfl:seed←KeystoreSeedOfHexbyte'11'
 mk:seed PeerCreate(openg validate)
 bound←PeerListen port
 →(bound≥0)/ok
 ⎕←'peer: LISTEN failed'
 →0
 ok:⎕←'LISTENING ',⍕bound
 →(0=≢portfile)/serve
 zz←((⍕bound)(gLocal))⎕FIO[56]portfile
 serve:PeerServe
∇

PeerMain
)OFF
