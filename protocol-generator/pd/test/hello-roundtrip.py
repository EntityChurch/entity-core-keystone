#!/usr/bin/env python3
"""S3.4 handshake leg-1 gate — send an EXECUTE hello (operation "hello", uri
system/protocol/connect, no auth per §4.2) to the real `pd` running
handshake-test.pd, and assert the §4.4 hello EXECUTE_RESPONSE: status 200,
result type system/protocol/connect/hello, a base58 peer_id present, the
protocols array, and request_id echoed. Inline CBOR encoder/decoder; offline.

Usage: hello-roundtrip.py <port>."""
import socket, sys, time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 15104


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


# EXECUTE hello — connect path, no auth (§4.2). params carry the §4.5 negotiated
# fields. `protocols` is the one Required with NO default, so a hello without it is
# refused 400 invalid_request: this fixture sent empty params until the §4.7 ladder
# landed and then measured the peer as broken. A test client is a peer too.
hello_data = cmap([(txt("key_types"), head(4, 1) + txt("ed25519")),
                   (txt("protocols"), head(4, 1) + txt("entity-core/1.0")),
                   (txt("hash_formats"), head(4, 1) + txt("ecfv1-sha256"))])
params = cmap([(txt("type"), txt("primitive/any")), (txt("data"), hello_data),
               (txt("content_hash"), bstr(bytes(33)))])
ed = cmap([(txt("request_id"), txt("hello-001")), (txt("uri"), txt("system/protocol/connect")),
           (txt("operation"), txt("hello")), (txt("params"), params)])
ex = cmap([(txt("type"), txt("system/protocol/execute")), (txt("data"), ed), (txt("content_hash"), bstr(bytes(33)))])
# Wire envelope (§1.1/§3.1): bare {root, included} data map, no entity triple.
env = cmap([(txt("root"), ex), (txt("included"), cmap([]))])
frame = len(env).to_bytes(4, "big") + env

s = socket.socket(); s.settimeout(4); s.connect(("127.0.0.1", port))
s.sendall(frame); time.sleep(0.6)
resp = b""
try:
    while len(resp) < 4 or len(resp) < 4 + int.from_bytes(resp[:4], "big"):
        c = s.recv(4096)
        if not c: break
        resp += c
except socket.timeout:
    pass
s.close()

if len(resp) < 4:
    print("FAIL: no response"); sys.exit(1)
n = int.from_bytes(resp[:4], "big")
env, _ = dec(resp[4:4 + n], 0)
root = env["root"]
status = root["data"]["status"]
result = root["data"]["result"]
rid = root["data"]["request_id"]
peer_id = result["data"].get("peer_id", "")
protocols = result["data"].get("protocols", [])
print(f"  status={status}  result_type={result['type']}")
print(f"  peer_id={peer_id}  protocols={protocols}  request_id={rid}")
ok = (root["type"] == "system/protocol/execute/response" and status == 200
      and result["type"] == "system/protocol/connect/hello"
      and isinstance(peer_id, str) and len(peer_id) > 20
      and protocols == ["entity-core/1.0"] and rid == "hello-001")
print("HELLO OK" if ok else "HELLO FAIL")
sys.exit(0 if ok else 1)
