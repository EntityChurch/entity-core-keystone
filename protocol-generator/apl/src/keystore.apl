⍝ entity-core-protocol-apl — src/keystore.apl (L1 keystore primitive).
⍝
⍝ Persistent Ed25519 identity at the peer-manager convention path
⍝ ~/.entity/peers/NAME/keypair — an entity-core PEM = base64 of the 32-byte seed between
⍝ `-----BEGIN ENTITY PRIVATE KEY-----` / `-----END ENTITY PRIVATE KEY-----` (the Go
⍝ entity-peer `--name` convention, so the validator's multisig accept-path probe can
⍝ co-sign AS the peer at S4). Base64 is hand-rolled here; the seed never crosses the C-ABI.
⍝ File I/O rides ⎕FIO (fopen/fread/fwrite); randomness rides /dev/urandom (⎕FIO[60]'s
⍝ vector form crashes GNU APL 1.9 — A-APL-015).

B64AL←'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

⍝ a deterministic 32-byte seed = one hex byte repeated 32× (the smoke/test convention).
∇Z←KeystoreSeedOfHexbyte hh
 Z←32⍴HexToBytes hh
∇

∇Z←B64Encode b;B;i;n;v
 B←B64AL ⋄ n←≢b ⋄ Z←'' ⋄ i←1
 lp:→(i>n)/0
 v←65536×b[i]
 →((i+1)>n)/one
 v←v+256×b[i+1]
 →((i+2)>n)/two
 v←v+b[i+2]
 Z←Z,B[1+64|⌊v÷262144],B[1+64|⌊v÷4096],B[1+64|⌊v÷64],B[1+64|v]
 i←i+3 ⋄ →lp
 two:Z←Z,B[1+64|⌊v÷262144],B[1+64|⌊v÷4096],B[1+64|⌊v÷64],'=' ⋄ →0
 one:Z←Z,B[1+64|⌊v÷262144],B[1+64|⌊v÷4096],'==' ⋄ →0
∇

∇Z←B64Decode s;B;acc;bits;i;c;n
 B←B64AL ⋄ Z←⍬ ⋄ acc←0 ⋄ bits←0 ⋄ i←0 ⋄ n←≢s
 lp:→(i≥n)/0
 i←i+1
 →(s[i]='=')/0
 c←¯1+B⍳s[i]
 →(c<0)/lp
 acc←(acc×64)+c ⋄ bits←bits+6
 →(bits<8)/lp
 bits←bits-8
 Z←Z,256|⌊acc÷2*bits
 acc←(2*bits)|acc                       ⍝ drop the emitted byte — keep acc bounded (< 2^7)
 →lp
∇

⍝ 32 random bytes from /dev/urandom (A-APL-015: never 1 ⎕FIO[60] Bi — it crashes).
∇Z←RandomBytes n;h
 h←'r'⎕FIO[3]'/dev/urandom'
 Z←n ⎕FIO[6] h
 zz←⎕FIO[4] h
∇

∇Z←HomeDir;e
 Z←'/root'
 e←⎕ENV'HOME'
 →(2>≢e)/0
 Z←2⊃e
∇

⍝ load the seed for NAME from the keypair PEM, creating one (random) if absent.
∇Z←KeystoreSeedOfName name;dir;path;h;raw;txt;b64;dec;seed;wh;lines
 dir←(HomeDir),'/.entity/peers/',name
 path←dir,'/keypair'
 h←'r'⎕FIO[3]path
 →(h<0)/fresh
 raw←⎕FIO[6]h
 zz←⎕FIO[4]h
 txt←⎕UCS raw
 b64←PemBody txt
 dec←B64Decode b64
 →(32>≢dec)/fresh
 Z←32↑dec ⋄ →0
 fresh:seed←RandomBytes 32
 zz←⎕FIO[20](HomeDir),'/.entity'          ⍝ mkdir -p (ignore already-exists)
 zz←⎕FIO[20](HomeDir),'/.entity/peers'
 zz←⎕FIO[20]dir
 lines←('-----BEGIN ENTITY PRIVATE KEY-----')(B64Encode seed)('-----END ENTITY PRIVATE KEY-----')
 zz←lines ⎕FIO[56]path
 Z←seed
∇

⍝ split a char vector on newline (⎕UCS 10) -> nested vector of lines (⊆ absent in GNU APL).
∇Z←SplitLines txt;i;n;s;nl
 Z←⍬ ⋄ n←≢txt ⋄ i←1 ⋄ s←1 ⋄ nl←⎕UCS 10
 lp:→(i>n)/last
 →(txt[i]≠nl)/adv
 Z←Z,⊂txt[(s-1)+⍳i-s] ⋄ s←i+1
 adv:i←i+1 ⋄ →lp
 last:→(s>n)/0 ⋄ Z←Z,⊂txt[(s-1)+⍳(n+1)-s]
∇

⍝ concatenate the base64 body lines of a PEM text, dropping BEGIN/END + blanks.
∇Z←PemBody txt;lines;i;ln
 Z←'' ⋄ lines←SplitLines txt ⋄ i←0
 lp:→(i≥≢lines)/0
 i←i+1 ⋄ ln←i⊃lines
 →(∨/'BEGIN'⍷ln)/lp
 →(∨/'END'⍷ln)/lp
 Z←Z,(ln~' ',⎕UCS 13)
 →lp
∇
