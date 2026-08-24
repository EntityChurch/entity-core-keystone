#!/usr/bin/env python3
"""S3.3 envelope-decode gate — build a spec-shaped §3.1 envelope frame (root =
EXECUTE), send it to the real `pd` running decode-test.pd, and assert [ecodec]
extracts root_type + request_id/uri/operation onto the canvas. Uses a tiny inline
canonical-CBOR encoder (no cbor2 dependency; runs offline). The peer prints the
decoded fields; this script drives the frame and the Makefile greps pd's stdout.

Usage: decode-roundtrip.py <port>   (pd must already be listening)."""
import socket, sys, time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 15101


def head(major, n):
    if n < 24:    return bytes([(major << 5) | n])
    if n < 256:   return bytes([(major << 5) | 24, n])
    if n < 65536: return bytes([(major << 5) | 25, n >> 8, n & 255])
    return bytes([(major << 5) | 26, (n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255])


def txt(s):    b = s.encode(); return head(3, len(b)) + b
def bstr(b):   return head(2, len(b)) + b
def cmap(prs): return head(5, len(prs)) + b"".join(k + v for k, v in prs)


H = bstr(bytes(33))                       # dummy 33-byte content_hash / hash ref
params = cmap([(txt("type"), txt("primitive/any")), (txt("data"), cmap([])),
               (txt("content_hash"), H)])
exec_data = cmap([(txt("request_id"), txt("req-123")), (txt("uri"), txt("alice/local/nope")),
                  (txt("operation"), txt("get")), (txt("author"), H),
                  (txt("capability"), H), (txt("params"), params)])
execute = cmap([(txt("type"), txt("system/protocol/execute")), (txt("data"), exec_data),
                (txt("content_hash"), H)])
# Wire envelope (§1.1/§3.1) is the bare {root, included} data map — NOT an entity
# triple (its type/content_hash are elided on the wire per §3.1 transport opt).
envelope = cmap([(txt("root"), execute), (txt("included"), cmap([]))])
frame = len(envelope).to_bytes(4, "big") + envelope

s = socket.socket(); s.settimeout(4); s.connect(("127.0.0.1", port))
s.sendall(frame); time.sleep(0.6); s.close()
print("sent envelope frame (%d-byte payload); expect on pd stdout:" % len(envelope))
print("  DECODED: system/protocol/execute   RID: req-123   URI: alice/local/nope   OP: get")
sys.exit(0)
