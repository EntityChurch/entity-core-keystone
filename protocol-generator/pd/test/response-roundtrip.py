#!/usr/bin/env python3
"""S3.3 respond gate — send a spec-shaped EXECUTE envelope to the real `pd`
running spine-test.pd, receive the §3.3 EXECUTE_RESPONSE frame it builds, decode
it, and assert status/code/request_id. Proves the CBOR *write* direction
(build_response) + the full decode→respond round-trip. Inline canonical-CBOR
encoder + a minimal decoder (no cbor2 dependency; offline).

Usage: response-roundtrip.py <port>   (pd must already be listening)."""
import socket, sys, time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 15102


# ── tiny CBOR encoder ────────────────────────────────────────────────────────
def head(major, n):
    if n < 24:    return bytes([(major << 5) | n])
    if n < 256:   return bytes([(major << 5) | 24, n])
    if n < 65536: return bytes([(major << 5) | 25, n >> 8, n & 255])
    return bytes([(major << 5) | 26, (n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255])


def txt(s):    b = s.encode(); return head(3, len(b)) + b
def bstr(b):   return head(2, len(b)) + b
def cmap(prs): return head(5, len(prs)) + b"".join(k + v for k, v in prs)


# ── tiny CBOR decoder (returns (value, next_pos)) ────────────────────────────
def dec(b, p):
    ib = b[p]; major = ib >> 5; ai = ib & 0x1f; p += 1
    if ai < 24:   arg = ai
    elif ai == 24: arg = b[p]; p += 1
    elif ai == 25: arg = int.from_bytes(b[p:p+2], "big"); p += 2
    elif ai == 26: arg = int.from_bytes(b[p:p+4], "big"); p += 4
    elif ai == 27: arg = int.from_bytes(b[p:p+8], "big"); p += 8
    else: raise ValueError("bad ai")
    if major == 0: return arg, p
    if major == 2: return b[p:p+arg], p + arg
    if major == 3: return b[p:p+arg].decode(), p + arg
    if major == 4:
        out = []
        for _ in range(arg): v, p = dec(b, p); out.append(v)
        return out, p
    if major == 5:
        out = {}
        for _ in range(arg):
            k, p = dec(b, p); v, p = dec(b, p); out[k] = v
        return out, p
    raise ValueError("unsupported major %d" % major)


# ── build the EXECUTE envelope (unknown path → expect 404) ───────────────────
H = bstr(bytes(33))
params = cmap([(txt("type"), txt("primitive/any")), (txt("data"), cmap([])), (txt("content_hash"), H)])
exec_data = cmap([(txt("request_id"), txt("req-777")), (txt("uri"), txt("alice/local/nope")),
                  (txt("operation"), txt("get")), (txt("author"), H), (txt("capability"), H),
                  (txt("params"), params)])
execute = cmap([(txt("type"), txt("system/protocol/execute")), (txt("data"), exec_data), (txt("content_hash"), H)])
# Wire envelope (§1.1/§3.1) is the bare {root, included} data map — no entity triple.
envelope = cmap([(txt("root"), execute), (txt("included"), cmap([]))])
frame = len(envelope).to_bytes(4, "big") + envelope

s = socket.socket(); s.settimeout(4); s.connect(("127.0.0.1", port))
s.sendall(frame); time.sleep(0.6)
resp = b""
try:
    while len(resp) < 4 or len(resp) < 4 + int.from_bytes(resp[:4], "big"):
        chunk = s.recv(4096)
        if not chunk: break
        resp += chunk
except socket.timeout:
    pass
s.close()

if len(resp) < 4:
    print("FAIL: no response frame"); sys.exit(1)
n = int.from_bytes(resp[:4], "big")
payload = resp[4:4 + n]
env, _ = dec(payload, 0)
root = env["root"]
status = root["data"]["status"]
code = root["data"]["result"]["data"]["code"]
rid = root["data"]["request_id"]
print(f"  response frame: {n} bytes  root_type={root['type']}")
print(f"  status={status}  code={code}  request_id={rid}")
ok = (root["type"] == "system/protocol/execute/response" and status == 404
      and code == "not_found" and rid == "req-777")
print("RESPONSETEST OK" if ok else "RESPONSETEST FAIL")
sys.exit(0 if ok else 1)
