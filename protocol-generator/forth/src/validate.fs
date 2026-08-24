\ entity-core-protocol-forth — §7a conformance handlers (behind --validate).
\
\ Two handlers the Go validator drives black-box (GUIDE-CONFORMANCE §7a):
\   system/validate/echo:echo                 — verbatim echo of the params entity (§7a.1).
\   system/validate/dispatch-outbound:dispatch — originate exactly ONE outbound EXECUTE back to
\     the validator's echo over the SAME inbound connection (§6.11 reentry; §7a.2a), then wrap
\     the downstream {status, result} in a primitive/any result entity.
\
\ Cap-passing (§7a.2a Go ruling): the three reentry-authority entities travel IN-BAND, nested
\ as CBOR-encoded entity blobs under the params keys reentry_capability / reentry_granter /
\ reentry_cap_signature — NOT via envelope `included`. We decode them, then re-emit them into
\ the OUTBOUND EXECUTE's included set (so the validator-as-B finds its own cap chain there).
\
\ These handlers are registered only under --validate (peer.fs), off in production.

\ blob->entity ( b-tv -- eaddr | 0 )  a nested `b` TV whose payload is the raw ECF wire of an
\ entity map {type,data,content_hash}: decode the CBOR, parse the entity (re-validate the hash).
: blob->entity { btv -- eaddr }
  btv 0= if 0 exit then
  btv c@ [char] m = if btv ent<-wire exit then         \ nested entity wire-map directly
  btv c@ [char] b = if                                  \ a byte-string blob of the entity CBOR
    btv tv-payload { pa pu }
    pa pu cbor-decode drop { mtv }
    mtv c@ [char] m <> if 0 exit then
    mtv ent<-wire exit
  then
  0 ;

\ ── system/validate/echo:echo — verbatim (§7a.1) ──
\ The oracle asserts result.data byte-equals params.data; returning the params ENTITY itself
\ (a primitive/any {value: X}) satisfies that with no decode/re-encode round-trip.
: hnd-validate-echo { conn exec arr lens nvar -- status result-eaddr result-eu }
  exec s" echo" op-eq 0= if 501 s" unsupported_operation" 0 0 error-result exit then
  exec params-of dup 0= if drop 400 s" invalid_params" 0 0 error-result exit then { p }
  200 p p ent-len ;

\ build-outbound-exec ( conn ta tu oa ou vtv capent -- exaddr exu )  build+sign the outbound
\ EXECUTE (fresh request_id, author=us, capability=cap hash, params=primitive/any(value blob))
\ and populate incB with the reentry cap chain + our exec signature.
: build-outbound-exec { conn ta tu oa ou vtv capent granter capsig -- exaddr exu }
  \ vtv is the {value:X} map TV directly (a nested ECF map in params, NOT a byte blob); it
  \ becomes the outbound EXECUTE's primitive/any params data verbatim.
  TYPE-ANY vtv vtv tv-node-len ent-make { opaddr opu }
  conn conn-next-out 0 <# #s [char] o hold #> { ridu } { ridaddr }   \ request_id "o<n>"
  ridaddr ridu  ta tu  oa ou  opaddr opu
    id-idhash  capent ent-hash  wire-execute { exu } { exaddr }
  exaddr ent-hash id-sign { esu } { esaddr }
  resp-inc-reset
  capent  capent ent-len resp-inc-add
  granter granter ent-len resp-inc-add
  capsig  capsig ent-len resp-inc-add
  id-peer resp-inc-add
  esaddr  esu resp-inc-add
  exaddr exu ;

\ wrap-reply ( reply -- status raddr ru )  wrap the downstream {status, result} into a
\ primitive/any result entity (§7a.1 result shape), status 200.
: wrap-reply { reply -- status raddr ru }
  reply resp-status drop { dstatus }
  reply s" result" ent-field dup 0= if drop 0 then { drtv }
  am-mark { mk }
  [char] m b,  2 4 >be
  s" status" tv-text 2drop  dstatus tv-uint 2drop
  s" result" tv-text 2drop
    drtv 0= if am-mark [char] m b, 0 4 >be drop
    else drtv drtv tv-node-len bytes, then
  mk am-span  TYPE-ANY 2swap ent-make  200 -rot ;

\ ── system/validate/dispatch-outbound:dispatch (§7a.2a reentry) ──
\ params (primitive/any) data: {target, operation, value, reentry_capability, reentry_granter,
\ reentry_cap_signature}. value is a `b` blob = the ECF of {value:X} — the downstream echo's
\ params data; we wrap it as a primitive/any entity for the outbound EXECUTE.
: hnd-validate-dispatch-outbound { conn exec arr lens nvar -- status raddr ru }
  exec s" dispatch" op-eq 0= if 501 s" unsupported_operation" 0 0 error-result exit then
  exec params-of dup 0= if drop 400 s" invalid_params" 0 0 error-result exit then { p }
  p s" target"    ent-text dup 0= if 2drop 400 s" invalid_params" 0 0 error-result exit then { tu } { ta }
  p s" operation" ent-text dup 0= if 2drop 400 s" invalid_params" 0 0 error-result exit then { ou } { oa }
  p s" value" ent-field { vtv }
  p s" reentry_capability"    ent-field blob->entity { capent }
  p s" reentry_granter"       ent-field blob->entity { granter }
  p s" reentry_cap_signature" ent-field blob->entity { capsig }
  vtv 0= capent 0= or granter 0= or capsig 0= or
    if 400 s" invalid_params" 0 0 error-result exit then
  conn ta tu oa ou vtv capent granter capsig build-outbound-exec { exu } { exaddr }
  conn exaddr  incB-addr incB-len incB-n  dispatch-outbound { reply }
  reply 0= if 503 s" no_outbound_seam" 0 0 error-result exit then
  reply wrap-reply ;
