## Base58 (Bitcoin alphabet) — hand-rolled, used for peer-id formatting.
## Standard byte-array long-division; no bignum dependency (profile
## [codec].base58_library = hand-rolled). Leading zero bytes map to leading '1'.
##
## SPDX-License-Identifier: Apache-2.0

const Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

proc base58Encode*(input: openArray[byte]): string =
  let n = input.len
  var zeros = 0
  while zeros < n and input[zeros] == 0'u8: inc zeros

  let size = (n * 138 div 100) + 1
  var b58 = newSeq[byte](size)  # zero-initialised

  var high = size - 1
  for i in 0 ..< n:
    var carry = int(input[i])
    var j = size - 1
    while j > high or carry != 0:
      carry += 256 * int(b58[j])
      b58[j] = byte(carry mod 58)
      carry = carry div 58
      if j == 0: break
      dec j
    high = j

  var start = 0
  while start < size and b58[start] == 0'u8: inc start

  result = newStringOfCap(zeros + (size - start))
  for _ in 0 ..< zeros: result.add '1'
  for k in start ..< size: result.add Alphabet[int(b58[k])]

proc b58Value(c: char): int =
  case c
  of '1'..'9': int(c) - int('1')
  of 'A'..'H': int(c) - int('A') + 9
  of 'J'..'N': int(c) - int('J') + 17
  of 'P'..'Z': int(c) - int('P') + 22
  of 'a'..'k': int(c) - int('a') + 33
  of 'm'..'z': int(c) - int('m') + 44
  else: -1

proc base58Decode*(s: string): seq[byte] =
  let n = s.len
  var ones = 0
  while ones < n and s[ones] == '1': inc ones

  let size = (n * 733 div 1000) + 1  # log(58)/log(256) ~= 0.733
  var b256 = newSeq[byte](size)

  var high = size - 1
  for i in 0 ..< n:
    let d = b58Value(s[i])
    if d < 0: raise newException(ValueError, "invalid base58 character")
    var carry = d
    var j = size - 1
    while j > high or carry != 0:
      carry += 58 * int(b256[j])
      b256[j] = byte(carry and 0xff)
      carry = carry shr 8
      if j == 0: break
      dec j
    high = j

  var start = 0
  while start < size and b256[start] == 0'u8: inc start

  result = newSeq[byte](ones + (size - start))
  for k in start ..< size: result[ones + (k - start)] = b256[k]
