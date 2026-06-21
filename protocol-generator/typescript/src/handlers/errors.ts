import { Entity, Ecf, TypeNames } from "../model/index.js";
import { HandlerResult } from "./handler-abstractions.js";

/** Build a handler result carrying a `system/protocol/error` entity (V7 §3.3). */
export function errorResult(status: number, code: string, message: string | null = null): HandlerResult {
  const error = Entity.create(
    TypeNames.Error,
    Ecf.map(["code", Ecf.text(code)], ["message", message === null ? null : Ecf.text(message)]),
  );
  return HandlerResult.of(status, error);
}
