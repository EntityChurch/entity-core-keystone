>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — peer-id + varint + base58 (V7 §1.2/§1.5/§7.3).
*>
*> peer_id = Base58(varint(key_type) || varint(hash_type) || digest)  (§7.4)
*> Ed25519 canonical form (§1.5 v7.65 identity-multihash): key_type=0x01,
*> hash_type=0x00 (identity), digest = the RAW 32-byte public key. (§7.4's
*> pseudocode still shows the pre-v7.65 SHA-256 form — the §1.5/§7.4 divergence
*> is A-OC-007, ratified to follow §1.5.)
*>
*> Sub-programs:
*>   varint-encode      LEB128 (N1) — appends to a buffer
*>   base58-encode      byte-array long division (Bitcoin b58alpha), no bignum
*>   peer-id-of-pubkey  the §1.5 Ed25519 canonical peer_id
*> ===================================================================

*> ---- varint-encode -------------------------------------------------
*> Append the LEB128 encoding of LK-VALUE to LK-OUT, advancing LK-OUT-LEN.
identification division.
program-id. varint-encode.
data division.
working-storage section.
01 ws-n         pic 9(18) comp-5.
01 ws-low       pic 9(4) comp-5.
01 ws-ob.
   05 ws-ob-char pic x.
01 ws-on redefines ws-ob pic 9(2) comp-x.
linkage section.
01 lk-out       pic x(65535).
01 lk-out-len   pic 9(9) comp-5.
01 lk-value     pic 9(18) comp-5.
procedure division using lk-out lk-out-len lk-value.
    move lk-value to ws-n
    perform until ws-n < 128
        compute ws-low = function mod(ws-n 128) + 128
        move ws-low to ws-on
        add 1 to lk-out-len
        move ws-ob-char to lk-out(lk-out-len:1)
        compute ws-n = ws-n / 128
    end-perform
    move ws-n to ws-on
    add 1 to lk-out-len
    move ws-ob-char to lk-out(lk-out-len:1)
    goback.
end program varint-encode.

*> ---- base58-encode -------------------------------------------------
*> Encode LK-IN(1:LK-IN-LEN) to Base58 text into LK-STR, length LK-STR-LEN.
*> Standard byte-array long division; leading 0x00 bytes -> leading '1'.
identification division.
program-id. base58-encode.
data division.
working-storage section.
01 b58alpha pic x(58) value
   "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".
01 ws-size      pic 9(9) comp-5.
01 ws-zeros     pic 9(9) comp-5.
01 ws-i         pic 9(9) comp-5.
01 ws-j         pic s9(9) comp-5.
01 ws-high      pic s9(9) comp-5.
01 ws-carry     pic 9(18) comp-5.
01 ws-start     pic 9(9) comp-5.
01 ws-d         pic 9(4) comp-5.
01 ws-bc.
   05 ws-byte   pic x.
01 ws-bn redefines ws-bc pic 9(2) comp-x.
01 ws-digits.
   05 ws-dig occurs 128 pic 9(4) comp-5.
linkage section.
01 lk-in        pic x(65535).
01 lk-in-len    pic 9(9) comp-5.
01 lk-str       pic x(128).
01 lk-str-len   pic 9(9) comp-5.
procedure division using lk-in lk-in-len lk-str lk-str-len.
    *> count leading zero bytes
    move 0 to ws-zeros
    perform varying ws-i from 1 by 1 until ws-i > lk-in-len
        if lk-in(ws-i:1) = x"00"
            add 1 to ws-zeros
        else
            exit perform
        end-if
    end-perform
    *> size = len*138/100 + 1
    compute ws-size = (lk-in-len * 138) / 100 + 1
    perform varying ws-i from 1 by 1 until ws-i > ws-size
        move 0 to ws-dig(ws-i)
    end-perform
    compute ws-high = ws-size - 1
    perform varying ws-i from 1 by 1 until ws-i > lk-in-len
        move lk-in(ws-i:1) to ws-byte
        move ws-bn to ws-carry
        compute ws-j = ws-size - 1
        perform until not (ws-j > ws-high or ws-carry not = 0)
            *> ws-dig index is 1-based: digit slot (ws-j+1)
            compute ws-carry = ws-carry + 256 * ws-dig(ws-j + 1)
            compute ws-d = function mod(ws-carry 58)
            move ws-d to ws-dig(ws-j + 1)
            compute ws-carry = ws-carry / 58
            subtract 1 from ws-j
        end-perform
        move ws-j to ws-high
    end-perform
    *> skip leading zero digits
    move 1 to ws-start
    perform until ws-start > ws-size or ws-dig(ws-start) not = 0
        add 1 to ws-start
    end-perform
    *> emit: one '1' per leading zero byte, then b58alpha[digit]
    move 0 to lk-str-len
    perform varying ws-i from 1 by 1 until ws-i > ws-zeros
        add 1 to lk-str-len
        move "1" to lk-str(lk-str-len:1)
    end-perform
    perform varying ws-i from ws-start by 1 until ws-i > ws-size
        compute ws-d = ws-dig(ws-i) + 1
        add 1 to lk-str-len
        move b58alpha(ws-d:1) to lk-str(lk-str-len:1)
    end-perform
    goback.
end program base58-encode.

*> ---- base58-decode -------------------------------------------------
*> Decode LK-STR(1:LK-STR-LEN) Base58 text to bytes in LK-OUT (len LK-OUT-LEN).
*> Mirror of the encoder: digit-array long multiply-by-58/add; leading '1' -> 0x00.
identification division.
program-id. base58-decode.
data division.
working-storage section.
01 b58alpha pic x(58) value
   "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".
01 ws-size      pic 9(9) comp-5.
01 ws-zeros     pic 9(9) comp-5.
01 ws-i         pic 9(9) comp-5.
01 ws-p         pic 9(9) comp-5.
01 ws-j         pic s9(9) comp-5.
01 ws-high      pic s9(9) comp-5.
01 ws-carry     pic 9(18) comp-5.
01 ws-start     pic 9(9) comp-5.
01 ws-di        pic 9(4) comp-5.
01 ws-found     pic 9(1).
01 ws-ob.
   05 ws-ob-char pic x.
01 ws-on redefines ws-ob pic 9(2) comp-x.
01 ws-digits.
   05 ws-dig occurs 256 pic 9(4) comp-5.
linkage section.
01 lk-str       pic x(128).
01 lk-str-len   pic 9(9) comp-5.
01 lk-out       pic x(256).
01 lk-out-len   pic 9(9) comp-5.
procedure division using lk-str lk-str-len lk-out lk-out-len.
    *> leading '1' chars -> leading 0x00 bytes
    move 0 to ws-zeros
    perform varying ws-i from 1 by 1 until ws-i > lk-str-len
        if lk-str(ws-i:1) = "1" then add 1 to ws-zeros else exit perform end-if
    end-perform
    compute ws-size = (lk-str-len * 733) / 1000 + 1
    perform varying ws-i from 1 by 1 until ws-i > ws-size
        move 0 to ws-dig(ws-i)
    end-perform
    compute ws-high = ws-size - 1
    perform varying ws-i from 1 by 1 until ws-i > lk-str-len
        *> digit value of this char
        move 0 to ws-found
        perform varying ws-p from 1 by 1 until ws-p > 58
            if lk-str(ws-i:1) = b58alpha(ws-p:1)
                compute ws-di = ws-p - 1
                move 1 to ws-found
                exit perform
            end-if
        end-perform
        if ws-found = 0 then move 0 to lk-out-len  goback end-if
        move ws-di to ws-carry
        compute ws-j = ws-size - 1
        perform until not (ws-j > ws-high or ws-carry not = 0)
            compute ws-carry = ws-carry + 58 * ws-dig(ws-j + 1)
            compute ws-dig(ws-j + 1) = function mod(ws-carry 256)
            compute ws-carry = ws-carry / 256
            subtract 1 from ws-j
        end-perform
        move ws-j to ws-high
    end-perform
    *> skip leading zero digits
    move 1 to ws-start
    perform until ws-start > ws-size or ws-dig(ws-start) not = 0
        add 1 to ws-start
    end-perform
    move 0 to lk-out-len
    perform varying ws-i from 1 by 1 until ws-i > ws-zeros
        add 1 to lk-out-len
        move x"00" to lk-out(lk-out-len:1)
    end-perform
    perform varying ws-i from ws-start by 1 until ws-i > ws-size
        move ws-dig(ws-i) to ws-on
        add 1 to lk-out-len
        move ws-ob-char to lk-out(lk-out-len:1)
    end-perform
    goback.
end program base58-decode.

*> ---- peer-id-of-pubkey ---------------------------------------------
*> §1.5 Ed25519 canonical peer_id from a 32-byte public key.
identification division.
program-id. peer-id-of-pubkey.
data division.
working-storage section.
01 ws-raw       pic x(64).
01 ws-raw-len   pic 9(9) comp-5.
01 kt           pic 9(18) comp-5 value 1.
01 ht           pic 9(18) comp-5 value 0.
01 one          pic 9(9) comp-5 value 1.
linkage section.
01 lk-pub       pic x(64).
01 lk-pub-len   pic 9(9) comp-5.
01 lk-str       pic x(128).
01 lk-str-len   pic 9(9) comp-5.
procedure division using lk-pub lk-pub-len lk-str lk-str-len.
    move 0 to ws-raw-len
    call "varint-encode" using ws-raw ws-raw-len kt
    call "varint-encode" using ws-raw ws-raw-len ht
    call "cbor-append" using ws-raw ws-raw-len lk-pub one lk-pub-len
    call "base58-encode" using ws-raw ws-raw-len lk-str lk-str-len
    goback.
end program peer-id-of-pubkey.
