## The two L2 wire message builders (§3.2 EXECUTE, §3.3 EXECUTE_RESPONSE) plus the
## small result entities. There are ONLY two root message types on the wire
## (§3.3): `system/protocol/execute` and `system/protocol/execute/response`.
## `hello`/`authenticate` are OPERATIONS on `system/protocol/connect`, not message
## types (§4.1).
##
## Frame := [4-byte big-endian length][ECF-encoded envelope] (§1.6) — the framing
## itself lives in transport.nim.
##
## SPDX-License-Identifier: Apache-2.0

import std/options
import ./ecf
import ./model

const
  ExecuteType* = "system/protocol/execute"
  ResponseType* = "system/protocol/execute/response"
  ConnectUri* = "system/protocol/connect"

proc emptyParams*(): Entity =
  ## Canonical empty params (§3.2): a primitive/any whose data is the empty map.
  makeEntity("primitive/any", mapV(@[]))

proc makeResponse*(requestId: string; status: uint64; resultEntity: Entity): Entity =
  ## EXECUTE_RESPONSE (§3.3): data {request_id, status, result}.
  makeEntity(ResponseType, mapV(@[
    EcPair(key: textV("request_id"), val: textV(requestId)),
    EcPair(key: textV("status"), val: uintV(status)),
    EcPair(key: textV("result"), val: resultEntity.toValue()),
  ]))

proc makeExecute*(requestId, uri, operation: string; params: Entity;
                  author = none(seq[byte]); capability = none(seq[byte]);
                  resource = EcValue(nil)): Entity =
  ## EXECUTE (§3.2). `author`/`capability` are absent on the pre-authorized
  ## `system/protocol/connect` path (§4.2); `resource` is optional.
  var pairs = @[
    EcPair(key: textV("request_id"), val: textV(requestId)),
    EcPair(key: textV("uri"), val: textV(uri)),
    EcPair(key: textV("operation"), val: textV(operation)),
    EcPair(key: textV("params"), val: params.toValue()),
  ]
  if author.isSome: pairs.add EcPair(key: textV("author"), val: bytesV(author.get))
  if capability.isSome: pairs.add EcPair(key: textV("capability"), val: bytesV(capability.get))
  if resource != nil: pairs.add EcPair(key: textV("resource"), val: resource)
  makeEntity(ExecuteType, mapV(pairs))

proc errorResult*(code: string; message = none(string)): Entity =
  ## system/protocol/error result entity (§3.3): {code, message?}.
  var pairs = @[EcPair(key: textV("code"), val: textV(code))]
  if message.isSome: pairs.add EcPair(key: textV("message"), val: textV(message.get))
  makeEntity("system/protocol/error", mapV(pairs))
