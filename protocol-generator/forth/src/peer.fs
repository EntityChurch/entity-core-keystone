\ entity-core-protocol-forth — peer assembly: install the identity, register the MUST
\ handlers (§4.1/§6.13), and expose the boot + serve entry points.

\ peer-bootstrap ( seed-addr seed-u validate? -- )  install identity, publish the §9.5 core
\ type floor, register the core handlers, and (under --validate) the §7a conformance handlers.
: peer-bootstrap { saddr su validate -- }
  store-reset conn-reset hnd-reset pend-reset
  saddr su id-init
  id-peerid ct-publish                          \ §9.5: publish the 53-type core floor
  EC-TRACE? if ." [boot types=" st-count @ . ." peer=" id-peerid type ." ]" cr then
  \ §4.1 the sole pre-auth path + the §4.4 authority-gated handlers.
  s" system/protocol/connect" ['] hnd-connect    register-handler
  s" system/tree"             ['] hnd-tree       register-handler
  s" system/capability"       ['] hnd-capability register-handler
  s" system/type"             ['] hnd-type       register-handler
  s" system/handler"          ['] hnd-handlers   register-handler
  \ §6.2 handler-manifest interfaces at /<peer>/system/handler/<pattern> (the `handlers` gate).
  s" system/protocol/connect" s" connect"    s" hello authenticate"     publish-handler-iface
  s" system/tree"             s" tree"       s" get put"                publish-handler-iface
  s" system/capability"       s" capability" s" request delegate revoke" publish-handler-iface
  s" system/handler"          s" handler"    s" register unregister"    publish-handler-iface
  s" system/type"             s" type"       s" validate"               publish-handler-iface
  \ §6.2 N2 dispatch entities at /<peer>/<pattern> (handler_<name>_dispatch_type / _interface_ref).
  s" system/protocol/connect" publish-handler-dispatch
  s" system/tree"             publish-handler-dispatch
  s" system/capability"       publish-handler-dispatch
  validate if
    s" system/validate/echo"              ['] hnd-validate-echo              register-handler
    s" system/validate/dispatch-outbound" ['] hnd-validate-dispatch-outbound register-handler
    \ publish their §6.2 interfaces so the validator's HasConformanceHandlers probe (a tree.get
    \ on system/handler/system/validate/dispatch-outbound) detects --validate and runs the
    \ §7a.2a reentry probe instead of honest-SKIPping.
    s" system/validate/echo"              s" validate/echo"     s" echo"     publish-handler-iface
    s" system/validate/dispatch-outbound" s" validate/dispatch" s" dispatch" publish-handler-iface
  then ;

\ peer-listen ( port -- bound )  bind + listen; install the listen fd. THROWs E-NET on fail.
: peer-listen { port -- bound }
  port net-listen { boundport } { lfd }
  lfd listen-fd !
  boundport ;

\ peer-serve ( -- )  run the select loop forever (the serve loop).
: peer-serve ( -- )  serve-forever ;
