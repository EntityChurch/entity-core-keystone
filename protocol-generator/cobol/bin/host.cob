>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — standalone peer host (S4 conformance target).
*>
*> Boots one peer (ps-init) and serves the live wire surface so the entity-core-go
*> validate-peer oracle can drive it. Single LISTENING line on stdout signals
*> readiness; the C poll() loop (ec_serve) multiplexes connections.
*>
*>   --port N             listen port (default 7777)
*>   --name NAME          load the Ed25519 seed from ~/.entity/peers/NAME/keypair
*>                        (entity-core PEM: base64 of a 32-byte seed). Without it
*>                        a fixed test seed (0x11 x 32) gives a stable peer_id.
*>   --debug-open-grants  mint a wide-open admin capability on authenticate
*>                        (degenerate default->* seed policy; deprecated).
*>   --validate           register the §7a conformance handlers (off by default).
*> ===================================================================
identification division.
program-id. host.
data division.
working-storage section.
01 seed       pic x(32).
01 port       pic 9(9) comp-5 value 7777.
01 open-flag  pic 9(1) value 0.
01 conf-flag  pic 9(1) value 0.
01 argc       pic 9(4) comp-5.
01 argi       pic 9(4) comp-5.
01 arg        pic x(256).
01 next-is    pic x(8) value spaces.
01 namez      pic x(256).
01 nlen       pic 9(9) comp-5.
01 rc         pic s9(9) comp-5.
01 lfd        pic s9(9) comp-5.
01 peerid     pic x(128).
01 peerid-len pic 9(9) comp-5.
01 disp-port  pic z(8)9.
01 disp-open  pic 9.
01 disp-conf  pic 9.
procedure division.
    move all x"11" to seed
    *> ---- parse arguments ----
    accept argc from argument-number
    perform varying argi from 1 by 1 until argi > argc
        display argi upon argument-number
        accept arg from argument-value
        evaluate true
            when next-is = "port"
                move function numval(arg) to port
                move spaces to next-is
            when next-is = "name"
                move function trim(arg) to namez
                move function length(function trim(arg)) to nlen
                move x"00" to namez(nlen + 1:1)
                call "ec_load_seed" using by reference namez
                    by reference seed returning rc
                if rc not = 0
                    display "error: --name: cannot load seed" upon syserr
                    stop run returning 2
                end-if
                move spaces to next-is
            when arg(1:6) = "--port"
                move "port" to next-is
            when arg(1:6) = "--name"
                move "name" to next-is
            when arg(1:19) = "--debug-open-grants"
                move 1 to open-flag
            when arg(1:10) = "--validate"
                move 1 to conf-flag
            when other
                continue
        end-evaluate
    end-perform

    *> ---- boot the peer ----
    call "ps-init" using seed open-flag conf-flag
    call "bootstrap"
    call "ps-peerid" using peerid peerid-len

    *> ---- listen ----
    call "ec_tcp_listen" using by value port returning lfd
    if lfd < 0
        display "error: listen failed" upon syserr
        stop run returning 1
    end-if
    move port to disp-port
    move open-flag to disp-open
    move conf-flag to disp-conf
    display "LISTENING 127.0.0.1:" function trim(disp-port)
        " peer_id=" peerid(1:peerid-len)
        " open_grants=" disp-open " validate=" disp-conf
    *> serve forever (poll loop, calls back into dispatch)
    call "ec_serve" using by value lfd returning rc
    stop run.
end program host.
