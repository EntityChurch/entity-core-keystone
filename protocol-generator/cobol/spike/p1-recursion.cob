>>SOURCE FORMAT FREE
*> ===================================================================
*> SPIKE PROBE 1 — Can GnuCOBOL recurse with correct per-frame state?
*>
*> The core peer needs genuine recursion in two places:
*>   - the §5.5 capability chain-walk (attenuation), and
*>   - the §6.3 recursive CBOR tag/nesting reject (depth-bounded).
*> Both require each recursive frame to keep its OWN local state.
*>
*> KEY COBOL FACT under test: WORKING-STORAGE is STATIC (shared across
*> recursive invocations); only LOCAL-STORAGE is allocated per call.
*> A naive recursive program using WORKING-STORAGE corrupts. We prove
*> RECURSIVE + LOCAL-STORAGE gives correct per-frame isolation.
*>
*> NOTE (-x): under cobc -x the FIRST program is the entry point and may
*> not have a USING clause, so the driver is declared first; the
*> recursive subprogram follows and is CALLed by literal name.
*> ===================================================================
identification division.
program-id. p1-driver.
data division.
working-storage section.
01 in-n      pic 9(4) value 10.
01 out-r     pic 9(18).
procedure division.
    call 'p1-recursion' using in-n out-r
    display "P1 factorial(10) = " out-r
    display "P1 expected      = 0000000003628800"
    if out-r = 3628800
        display "P1 RESULT: PASS (RECURSIVE + LOCAL-STORAGE isolates frames)"
    else
        display "P1 RESULT: FAIL (frame state corrupted)"
    end-if
    stop run.
end program p1-driver.

*> ---- recursive subprogram -----------------------------------------
identification division.
program-id. p1-recursion recursive.
data division.
working-storage section.
01 ws-n            pic 9(4).
01 ws-sub-result   pic 9(18).
local-storage section.
*> per-invocation copy of the input; if recursion shared this we'd see corruption
01 ls-n-snapshot   pic 9(4).
linkage section.
01 lk-n            pic 9(4).
01 lk-result       pic 9(18).
procedure division using lk-n lk-result.
    move lk-n to ls-n-snapshot
    if lk-n <= 1
        move 1 to lk-result
    else
        subtract 1 from lk-n giving ws-n
        call 'p1-recursion' using ws-n ws-sub-result
        *> after the recursive call returns, ls-n-snapshot MUST still be
        *> our frame's n (proves LOCAL-STORAGE per-frame isolation)
        multiply ls-n-snapshot by ws-sub-result giving lk-result
    end-if
    goback.
end program p1-recursion.
