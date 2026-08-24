#!/usr/bin/env python3
"""S3.3 §6.6 tree-walk gate — send two EXECUTEs to the real `pd` running
treewalk-test.pd and assert the canvas tree-walk discriminates:
  * a known handler prefix (uri under system/tree)  -> resolves -> 501 (placeholder)
  * an unknown path (local/nope)                    -> no handler -> 404 not_found
Sequential connections (one at a time) so reply targeting is unambiguous (A-PD-002
deferred). Inline canonical-CBOR encoder + minimal decoder; offline.

Usage: treewalk-roundtrip.py <port>."""
import socket, sys, time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 15103


def head(major, n):
    if n < 24:    return bytes([(major << 5) | n])
    if n < 256:   return bytes([(major << 5) | 24, n])
    if n < 65536: return bytes([(major << 5) | 25, n >> 8, n & 255])
    return bytes([(major << 5) | 26, (n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255])


def txt(s):    b = s.encode(); return head(3, len(b)) + b
def bstr(b):   return head(2, len(b)) + b
def cmap(prs): return head(5, len(prs)) + b"".join(k + v for k, v in prs)


def dec(b, p):
    ib = b[p]; major = ib >> 5; ai = ib & 0x1f; p += 1
    if ai < 24:   arg = ai
    elif ai == 24: arg = b[p]; p += 1
    elif ai == 25: arg = int.from_bytes(b[p:p+2], "big"); p += 2
    elif ai == 26: arg = int.from_bytes(b[p:p+4], "big"); p += 4
    elif ai == 27: arg = int.from_bytes(b[p:p+8], "big"); p += 8
    else: raise ValueError("bad ai")
    if major == 0: return arg, p
    if major in (2, 3):
        v = b[p:p+arg]; return (v if major == 2 else v.decode()), p + arg
    if major == 4:
        out = []
        for _ in range(arg): v, p = dec(b, p); out.append(v)
        return out, p
    if major == 5:
        out = {}
        for _ in range(arg):
            k, p = dec(b, p); v, p = dec(b, p); out[k] = v
        return out, p
    raise ValueError("major %d" % major)


def execute_frame(request_id, uri):
    H = bstr(bytes(33))
    params = cmap([(txt("type"), txt("primitive/any")), (txt("data"), cmap([])), (txt("content_hash"), H)])
    ed = cmap([(txt("request_id"), txt(request_id)), (txt("uri"), txt(uri)), (txt("operation"), txt("get")),
               (txt("author"), H), (txt("capability"), H), (txt("params"), params)])
    ex = cmap([(txt("type"), txt("system/protocol/execute")), (txt("data"), ed), (txt("content_hash"), H)])
    # Wire envelope (§1.1/§3.1): bare {root, included} data map, no entity triple.
    env = cmap([(txt("root"), ex), (txt("included"), cmap([]))])
    return len(env).to_bytes(4, "big") + env


def send_expect(uri, rid):
    s = socket.socket(); s.settimeout(4); s.connect(("127.0.0.1", port))
    s.sendall(execute_frame(rid, uri)); time.sleep(0.5)
    resp = b""
    try:
        while len(resp) < 4 or len(resp) < 4 + int.from_bytes(resp[:4], "big"):
            c = s.recv(4096)
            if not c: break
            resp += c
    except socket.timeout:
        pass
    s.close()
    n = int.from_bytes(resp[:4], "big")
    env, _ = dec(resp[4:4 + n], 0)
    root = env["root"]
    return root["data"]["status"], root["data"]["result"]["data"]["code"], root["data"]["request_id"]


ok = True
st, code, rid = send_expect("system/tree/instances/x", "rid-known")
print(f"  known handler prefix (system/tree/...): status={st} code={code} rid={rid}")
ok &= (st == 501 and rid == "rid-known")
st, code, rid = send_expect("local/nope", "rid-unknown")
print(f"  unknown path (local/nope):              status={st} code={code} rid={rid}")
ok &= (st == 404 and code == "not_found" and rid == "rid-unknown")

print("TREEWALK OK" if ok else "TREEWALK FAIL")
sys.exit(0 if ok else 1)
