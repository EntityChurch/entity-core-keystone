⍝ entity-core-protocol-apl — test/s3_initiator.apl (the S3 phase-exit gate: initiator side).
⍝
⍝ Boots a second peer, dials the responder over REAL loopback TCP through the full §6.5
⍝ dispatch chain (both peers on their own ⎕FIO select-pump), drives the §4.1 forward
⍝ handshake (hello -> authenticate), then:
⍝   - handshake both directions established (a capability was minted server-side);
⍝   - remote peer_id is a base58 peer id and matches the responder;
⍝   - 404 on an unregistered path (chain-verify still ALLOWs, then no handler resolved);
⍝   - 8-way request_id demux of concurrently-issued replies (N7, §6.11) — 8 EXECUTEs in
⍝     flight on the one connection, resolved out of order by the pump.
⍝ Reads --port / --seed / --peerid from ⎕ARG. Output is file-redirected by smoke.sh
⍝ (never piped — A-APL-013).

∇Z←ArgVal flag;a;i
 Z←'' ⋄ a←⎕ARG ⋄ i←0
 lp:→(i≥(≢a)-1)/0
 i←i+1 ⋄ →(~(i⊃a)≡flag)/lp
 Z←(i+1)⊃a ⋄ →0
∇
∇Z←StrToInt s
 Z←0 ⋄ →(0=≢s)/0 ⋄ Z←10⊥¯1+'0123456789'⍳s
∇

nPass←0 ⋄ nFail←0
∇name Check cond
 →(cond)/ok
 nFail←nFail+1 ⋄ ⎕←'  [FAIL] ',name ⋄ →0
 ok:nPass←nPass+1 ⋄ ⎕←'  [PASS] ',name
∇

∇InitMain;port;expected;seedhex;seed;ok;remote;resp;r;rids;k;rid;correlated;sr;found
 port←StrToInt ArgVal'--port'
 expected←ArgVal'--peerid'
 seedhex←ArgVal'--seed' ⋄ →(0<≢seedhex)/hs ⋄ seedhex←'22'
 hs:seed←KeystoreSeedOfHexbyte seedhex
 seed PeerCreate 0 0
 ok←PeerDial port
 →(ok)/dialed
 ⎕←'SMOKE: DIAL/handshake FAILED'
 ⎕FIO[42]2 ⋄ →bye0
 dialed:remote←gSessRemote
 'session established both ways (capability minted)'Check EntPresent gSessCap
 'remote peer_id is a base58 peer id'Check CapIsPeerId remote
 →(0=≢expected)/skipm
 'remote peer_id matches responder'Check remote≡expected
 skipm:r←SessExecute('/',remote,'/does/not/exist')('noop')(WireEmptyParams)(EV_ABSENT ⍬)
 'unregistered path -> 404'Check(2⊃r)∧404=WireResponseStatus 1⊃r
 ⍝ 8-way request_id demux (N7, §6.11) — 8 EXECUTEs in flight at once
 rids←⍬ ⋄ k←0
 fl:→(k≥8)/await
 k←k+1
 rid←SessExecuteAsync('/',remote,'/does/not/exist')('noop')(WireEmptyParams)(EV_ABSENT ⍬)
 rids←rids,⊂rid ⋄ →fl
 await:k←0
 al:→(k≥8)/corr
 k←k+1 ⋄ zz←SessAwait k⊃rids ⋄ →al
 corr:correlated←0 ⋄ k←0
 cl:→(k≥8)/done
 k←k+1
 sr←SessResponse k⊃rids ⋄ found←2⊃sr
 →(~found)/cl
 →(404≠WireResponseStatus 1⊃sr)/cl
 →(~((EnvRoot 1⊃sr)EntText'request_id')≡k⊃rids)/cl
 correlated←correlated+1 ⋄ →cl
 done:'8 interleaved requests each correlated by request_id'Check correlated=8
 PeerShutdown
 ⎕←''
 →(nFail>0)/bad
 ⎕←'SMOKE: PASS (',(⍕nPass),'/',(⍕nPass+nFail),')'
 →bye
 bad:⎕←'SMOKE: FAIL (',(⍕nPass),'/',(⍕nPass+nFail),')'
 →bye0
 bye0:
 bye:
∇

InitMain
)OFF
