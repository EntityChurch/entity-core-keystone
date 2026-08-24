\ entity-core-protocol-forth — the two wire message builders (§3.2 EXECUTE, §3.3
\ EXECUTE_RESPONSE) as materialized entities. Only these two are wire message ROOTS
\ (§3.3): hello/authenticate are OPERATIONS on system/protocol/connect, NOT message types;
\ any other root type is invalid → the connection is closed (handled in dispatch.fs).
\
\ These build the root entity's data-map TV in the arena, then wrap with ent-make.

s" system/protocol/execute"          2constant TYPE-EXECUTE
s" system/protocol/execute/response" 2constant TYPE-RESPONSE
s" system/protocol/error"            2constant TYPE-ERROR
s" primitive/any"                    2constant TYPE-ANY

\ empty-params ( -- eaddr eu )  §3.2: params with no content is a primitive/any whose data
\ is the canonical empty map (single byte 0xa0). Build {} as the data TV.
: empty-params ( -- eaddr eu )
  am-mark { mk }  [char] m b,  0 4 >be  mk am-span   \ empty map TV
  TYPE-ANY 2swap ent-make ;

\ wire-execute ( request_id$ uri$ operation$ params-eaddr params-eu [author-h$|0 0]
\                [cap-h$|0 0] -- eaddr eu )
\ Build a system/protocol/execute entity. author/capability are content-hash byte spans;
\ pass 0 0 to omit (connect-path requests carry neither). params is a materialized entity.
\ request_id/uri/operation/params are always present (4); author/capability are optional.
: wire-execute { ridaddr ridu uriaddr uriu opaddr opu paddr pu authaddr authu capaddr capu -- eaddr eu }
  4 authu 0<> - capu 0<> - { nf }
  am-mark { mk }
  [char] m b,  nf 4 >be
  s" request_id" tv-text 2drop  ridaddr ridu tv-text 2drop
  s" uri"        tv-text 2drop  uriaddr uriu tv-text 2drop
  s" operation"  tv-text 2drop  opaddr opu tv-text 2drop
  s" params"     tv-text 2drop  paddr ent->wire 2drop
  authu 0<> if  s" author"     tv-text 2drop  authaddr authu tv-bytes 2drop  then
  capu  0<> if  s" capability" tv-text 2drop  capaddr capu tv-bytes 2drop  then
  mk am-span
  TYPE-EXECUTE 2swap ent-make ;

\ wire-response ( request_id$ status result-eaddr result-eu -- eaddr eu )
\ Build a system/protocol/execute/response entity (§3.3). status is a uint.
: wire-response { ridaddr ridu status raddr ru -- eaddr eu }
  am-mark { mk }
  [char] m b,  3 4 >be
  s" request_id" tv-text 2drop  ridaddr ridu tv-text 2drop
  s" status"     tv-text 2drop  status tv-uint 2drop
  s" result"     tv-text 2drop  raddr ent->wire 2drop
  mk am-span
  TYPE-RESPONSE 2swap ent-make ;

\ error-result ( code$ message$ -- eaddr eu )  a system/protocol/error entity. Pass 0 0
\ message to omit it.
: error-result { caddr cu maddr mu -- eaddr eu }
  am-mark { mk }
  mu 0<> if 2 else 1 then { nf }
  [char] m b,  nf 4 >be
  s" code"    tv-text 2drop  caddr cu tv-text 2drop
  mu 0<> if  s" message" tv-text 2drop  maddr mu tv-text 2drop  then
  mk am-span
  TYPE-ERROR 2swap ent-make ;

\ ── response-side reads (initiator) ──
: resp-status ( root-eaddr -- status present? )  s" status" ent-uint ;
: resp-request-id ( root-eaddr -- addr u )  s" request_id" ent-text ;
: exec-request-id ( root-eaddr -- addr u )  s" request_id" ent-text ;
: exec-uri ( root-eaddr -- addr u )  s" uri" ent-text ;
: exec-operation ( root-eaddr -- addr u )  s" operation" ent-text ;
