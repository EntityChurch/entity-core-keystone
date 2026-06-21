>>SOURCE FORMAT FREE
*> ===================================================================
*> SPIKE PROBE 3 — Does COBOL's decimal/PIC numeric model fight the
*> CBOR integer head-form carrier (full unsigned 64-bit)?
*>
*> This is the candidate DISCOVERY axis for COBOL. Every prior peer
*> hit a native-int trap at the uint64 boundary (OCaml int63, C# ulong,
*> TS bigint, Zig overflow-trap). COBOL is decimal-first: PIC 9(n) is
*> a DECIMAL-DIGIT width, not a bit width.
*>
*> Findings this probe pins down empirically:
*>   - 2^64 - 1 = 18446744073709551615  -> TWENTY decimal digits.
*>   - The comfortable COBOL'85 ceiling is PIC 9(18) (10^18-1), which
*>     is ONE DIGIT CLASS SHORT of uint64 max: a peer reaching for the
*>     "obvious" 18-digit field SILENTLY TRUNCATES uint64.
*>   - You CANNOT declare a >18-digit USAGE COMP-5/binary field at all
*>     (cobc: "binary field cannot be larger than 18 digits"). So uint64
*>     cannot be a wide *decimal-binary*; it must ride an 8-BYTE field
*>     (PIC 9(18) COMP-5) whose physical storage holds the full 2^64
*>     range, with -fno-binary-truncate so MOVEs don't clamp to 10^18.
*>   - COMP-5 is NATIVE byte order, matching a C uint64_t over the FFI
*>     boundary (the codec does CBOR's big-endian on the C side).
*>   - For DISPLAY / comparison beyond 18 digits, a PIC 9(20+) DISPLAY
*>     decimal is fine (decimal arithmetic goes to 38 digits); only the
*>     BINARY usage is capped at 18.
*> ===================================================================
identification division.
program-id. p3-uint64.

data division.
working-storage section.
*> raw 8 bytes = 0xFF * 8  ==  uint64 max in native binary
01 raw8.
   05 raw8-bytes  pic x occurs 8.
01 u64-comp5 redefines raw8 pic 9(18) comp-5.

01 lit-max     pic 9(20)  value 18446744073709551615.
01 trap18      pic 9(18).
01 disp20      pic 9(20).

01 i           pic 9(2) comp.

procedure division.
    display "P3 uint64 max (20-digit DISPLAY literal) = " lit-max
    display "P3 expected                              = 18446744073709551615"

    *> --- the trap: 20-digit uint64 max into the 'obvious' 18-digit field
    move lit-max to trap18
    display "P3 same value MOVEd to PIC 9(18)         = " trap18
            "  <- TRUNCATED, high digits lost"

    *> --- 8-byte COMP-5 from raw 0xFF bytes carries the full value
    *>     (requires -fno-binary-truncate; see run-spike.sh) ---
    perform varying i from 1 by 1 until i > 8
        move x"ff" to raw8-bytes(i)
    end-perform
    move u64-comp5 to disp20
    display "P3 raw 0xFFx8 via 8-byte COMP-5          = " disp20

    evaluate true
        when u64-comp5 = lit-max and trap18 not = lit-max
            display "P3 RESULT: PASS (uint64 rides an 8-byte COMP-5; the "
                    "9(18)-decimal path truncates -> the discovery trap)"
        when other
            display "P3 RESULT: ANOMALY (see values above)"
    end-evaluate
    stop run.
end program p3-uint64.
