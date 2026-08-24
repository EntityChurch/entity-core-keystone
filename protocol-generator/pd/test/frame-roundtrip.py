#!/usr/bin/env python3
"""S3.2 frame-assembler gate — drive the real `pd` running frame-assembler.pd and
assert the §1.6 header→body state machine reassembles frames byte-exact (single
frame + back-to-back frames that must reset the phase/count state). The peer echoes
each frame's body; we check the echo equals the bodies we sent.

Usage: frame-roundtrip.py <port>   (pd must already be listening on <port>)
Exit 0 on pass, 1 on mismatch."""
import socket, sys, time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 15100


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def roundtrip(payload: bytes, expect: bytes, label: str) -> bool:
    s = socket.socket()
    s.settimeout(4)
    s.connect(("127.0.0.1", port))
    s.sendall(payload)
    time.sleep(0.6)
    back = b""
    try:
        while len(back) < len(expect):
            chunk = s.recv(256)
            if not chunk:
                break
            back += chunk
    except socket.timeout:
        pass
    s.close()
    ok = back == expect
    print(f"  {label}: expect {expect!r} got {back!r} -> {'OK' if ok else 'FAIL'}")
    return ok


ok = True
ok &= roundtrip(frame(b"hello"), b"hello", "single frame")
ok &= roundtrip(frame(b"abc") + frame(b"de"), b"abcde", "back-to-back frames (state reset)")
ok &= roundtrip(frame(bytes([0, 255, 10, 200])), bytes([0, 255, 10, 200]), "binary-clean body")

print("FRAMETEST OK" if ok else "FRAMETEST FAIL")
sys.exit(0 if ok else 1)
