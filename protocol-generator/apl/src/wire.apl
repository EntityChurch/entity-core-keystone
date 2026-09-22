⍝ entity-core-protocol-apl — src/wire.apl (§1.6 framing payload + §3.1 envelope + the two
⍝ message builders §3.2 EXECUTE / §3.3 EXECUTE_RESPONSE).
⍝
⍝ A wire payload is a canonical-ECF system/protocol/envelope (§3.1): a `root` entity plus
⍝ an `included` content_hash -> entity map. The included map has BYTE-string keys (the
⍝ §3.1 major-2 seam, NOT text keys — the §5.8 authority carrier: caps, peer identities,
⍝ signatures travel here). N5: `included` is preserved request+result side, deduped
⍝ first-seen, and every content_hash is verified == its key on decode.
⍝
⍝ ONLY EXECUTE and EXECUTE_RESPONSE are wire message types (§3.3). hello/authenticate are
⍝ OPERATIONS on system/protocol/connect, NOT message types — any other root type → the
⍝ dispatcher closes/ignores. The 4-byte length frame prefix lives in transport.apl.

EnvMake←{⍺ ⍵}                                    ⍝ (root inc) — inc is a nested vector of entities
EnvRoot←{1⊃⍵} ⋄ EnvInc←{2⊃⍵}

⍝ find the included entity whose content_hash = `⍵` (EntAbsent if none / empty key).
∇Z←env EnvIncludedGet h;inc;i
 Z←EntAbsent
 →(0=≢h)/0
 inc←2⊃env ⋄ i←0
 lp:→(i≥≢inc)/0
 i←i+1
 →(~(EntHash i⊃inc)HashEq h)/lp
 Z←i⊃inc ⋄ →0
∇

⍝ the wire envelope map {root, included}; dedup `included` by content_hash (first-seen)
⍝ so no duplicate byte key reaches the canonical codec (which would reject it).
∇Z←EnvToCbor env;inc;pay;i;e;hb;seen;dup;j;top;incmap
 inc←2⊃env ⋄ pay←⍬ ⋄ seen←⍬ ⋄ i←0
 lp:→(i≥≢inc)/done
 i←i+1 ⋄ e←i⊃inc ⋄ hb←EntHash e
 dup←0 ⋄ j←0
 dl:→(j≥≢seen)/notdup
 j←j+1 ⋄ →(~(j⊃seen)HashEq hb)/dl
 dup←1
 notdup:→(dup)/lp
 seen←seen,⊂hb
 pay←pay,(⊂VBytes hb),(⊂EntToCbor e)
 →lp
 done:incmap←EV_MAP pay
 top←VMapEmpty
 top←top VmPut('root')(EntToCbor 1⊃env)
 top←top VmPut('included')incmap
 Z←top
∇

⍝ parse a wire envelope map -> (env rc); verify each included hash == its byte key (N5).
∇Z←EnvOfCbor top;rootv;re;incm;pay;np;i;kv;vv;er;e;kb;acc;seen;dup;j
 Z←(EntAbsent(⍬))EC_DECODE_ERROR
 →(EV_MAP≠1⊃top)/0
 rootv←top MSubmap'root'
 →(EV_MAP≠1⊃rootv)/0
 re←EntOfCbor rootv
 →(EC_OK≠2⊃re)/0
 acc←⍬ ⋄ seen←⍬
 incm←top MSubmap'included'
 →(EV_MAP≠1⊃incm)/finish
 pay←2⊃incm ⋄ np←⌊(≢pay)÷2 ⋄ i←0
 lp:→(i≥np)/finish
 i←i+1
 kv←(¯1+2×i)⊃pay ⋄ vv←(2×i)⊃pay
 →(EV_BYTES≠1⊃kv)/0
 →(EV_MAP≠1⊃vv)/0
 er←EntOfCbor vv
 →(EC_OK≠2⊃er)/0
 e←1⊃er ⋄ kb←,2⊃kv
 →(~kb HashEq EntHash e)/hashbad
 dup←0 ⋄ j←0
 dl:→(j≥≢seen)/nd
 j←j+1 ⋄ →(~(j⊃seen)HashEq kb)/dl
 dup←1
 nd:→(dup)/lp
 seen←seen,⊂kb ⋄ acc←acc,⊂e
 →lp
 hashbad:Z←(EntAbsent(⍬))EC_HASH_MISMATCH ⋄ →0
 finish:Z←((1⊃re)acc)EC_OK
∇

WireFrameOfEnvelope←{CborEncode EnvToCbor ⍵}    ⍝ envelope -> canonical-ECF payload bytes

⍝ decode a payload -> (env ok); §6.3 full-consumption reject (A-FTN-012 discipline).
∇Z←WireEnvelopeOfFrame payload;d;v;consumed;rc;r
 Z←(EntAbsent(⍬))0
 d←CborDecode payload ⋄ v←1⊃d ⋄ consumed←2⊃d ⋄ rc←3⊃d
 →(EC_OK≠rc)/0
 →(consumed≠≢payload)/0
 r←EnvOfCbor v
 Z←(1⊃r)(EC_OK=2⊃r)
∇

⍝ peek root type + request_id from a raw payload WITHOUT hash validation — the §6.11
⍝ demux needs only these. Returns (rootType requestId isResponse ok).
∇Z←WirePeek payload;d;v;rootv;rt;datav;rid
 Z←('' '' 0 0)
⍝ SALVAGE decode, deliberately: a frame carrying a major-type-6 tag in a data
⍝ field is rejected — but §6.3 requires the rejection to be a 400
⍝ non_canonical_ecf RESPONSE, and answering needs the request_id. Peeking with
⍝ the strict decoder returned ok=0 here, so OnFrame dropped the frame on the
⍝ floor and its existing 400 branch was unreachable: the sender then blocked
⍝ until its own timeout, making a refusal indistinguishable from a dead peer.
⍝ The frame is still rejected — WireEnvelopeOfFrame below is strict and unchanged.
 d←CborDecodeSalvage payload
 →(EC_OK≠3⊃d)/0
 v←1⊃d
 →(EV_MAP≠1⊃v)/0
 rootv←v MSubmap'root'
 →(EV_MAP≠1⊃rootv)/0
 rt←rootv MText'type'
 datav←rootv MSubmap'data'
 rid←''
 →(EV_MAP≠1⊃datav)/norid
 rid←datav MText'request_id'
 norid:Z←rt rid(rt≡'system/protocol/execute/response')1
∇

⍝ ── EXECUTE builder (§3.2). ⍵ = (requestId uri operation paramsEnt authorH capH resourceV).
⍝ authorH/capH: raw hashes (⍬ to omit); resourceV: a map value (EV_ABSENT to omit). ──
∇Z←WireMakeExecute a;rid;uri;op;params;author;cap;res;m
 rid←1⊃a ⋄ uri←2⊃a ⋄ op←3⊃a ⋄ params←4⊃a ⋄ author←5⊃a ⋄ cap←6⊃a ⋄ res←7⊃a
 m←VMapEmpty
 m←m VmPut('request_id')(VText rid)
 m←m VmPut('uri')(VText uri)
 m←m VmPut('operation')(VText op)
 m←m VmPut('params')(EntToCbor params)
 →(0=≢author)/nca
 m←m VmPut('author')(VBytes author)
 nca:→(0=≢cap)/nrs
 m←m VmPut('capability')(VBytes cap)
 nrs:→(EV_MAP≠1⊃res)/fin
 m←m VmPut('resource')res
 fin:Z←'system/protocol/execute'EntMake m
∇

⍝ EXECUTE_RESPONSE builder (§3.3). ⍵ = (requestId status resultEnt).
∇Z←WireMakeResponse a;m
 m←VMapEmpty
 m←m VmPut('request_id')(VText 1⊃a)
 m←m VmPut('status')(VUint 2⊃a)
 m←m VmPut('result')(EntToCbor 3⊃a)
 Z←'system/protocol/execute/response'EntMake m
∇

⍝ error result entity system/protocol/error {code, message?}.
∇Z←WireErrorResult cm;m
 m←VMapEmpty
 m←m VmPut('code')(VText 1⊃cm)
 →(0=≢2⊃cm)/fin
 m←m VmPut('message')(VText 2⊃cm)
 fin:Z←'system/protocol/error'EntMake m
∇

WireEmptyParams←{'primitive/any'EntMake VMapEmpty}

⍝ a resource map {targets: [target]} for a single target path string.
∇Z←WireResourceTarget target;m
 m←VMapEmpty
 m←m VmPut('targets')(VArrEmpty VArrAdd VText target)
 Z←m
∇

∇Z←WireResponseStatus env;r
 r←(EnvRoot env)EntUint'status'
 Z←(1+2⊃r)⊃(0)(1⊃r)
∇
WireResponseResult←{(EnvRoot ⍵)EntEntityField'result'}
