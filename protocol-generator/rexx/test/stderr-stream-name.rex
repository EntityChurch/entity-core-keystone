/* stderr-stream-name.rex — which spelling actually reaches fd 2 under Regina?

   This peer emitted every diagnostic it has (unknown flag, LISTEN failed, unreadable
   keypair, bad seed length, and the PEER FATAL SYNTAX handler) with

       call lineout stderr, '...'

   `stderr` there is an UNSET REXX VARIABLE, so it evaluates to the literal string
   STDERR -- which lineout treats as a FILENAME. Every one of those messages had been
   landing in a file called STDERR in the working directory, never on fd 2, for as long
   as the peer has existed. Measured 2026-09-02, and it is invisible in both directions:
   the harness cats /tmp/host.err and finds it empty, and the file it went to instead is
   untracked, so it reads as a peer that failed silently. That is one level below the
   cohort-wide "keep the peer stderr" fix landed the same week -- the harness now keeps
   fd 2 faithfully and this peer was not writing to it.

   Run:  rexx protocol-generator/rexx/test/stderr-stream-name.rex 2>/tmp/e 1>/tmp/o
   Expect on fd 2: B and D only. A and C create ./STDERR.                            */
call lineout stderr, 'A: bare unset variable stderr -- becomes the FILENAME "STDERR"'
call lineout '<stderr>', 'B: angle-bracket special stream -- reaches fd 2'
call lineout 'STDERR', 'C: quoted literal STDERR -- also the filename'
call charout '<stderr>', 'D: charout angle-bracket -- reaches fd 2' || '0a'x
exit 0
