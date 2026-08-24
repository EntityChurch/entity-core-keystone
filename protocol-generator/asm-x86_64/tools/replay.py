#!/usr/bin/env python3
# replay.py — throwaway: replay a captured connection's c2s frames to a live peer in order,
# reading each response, to find the frame that crashes/hangs the peer. Frames are raw ECF
# bodies (teeproxy stripped the 4-byte length prefix); we re-add it.
import socket, struct, sys, os, glob, time

dumpdir = sys.argv[1]
conn = sys.argv[2] if len(sys.argv) > 2 else "c0"
port = int(sys.argv[3]) if len(sys.argv) > 3 else 8811

frames = sorted(glob.glob(f"{dumpdir}/c2s_{conn}_f*.bin"),
                key=lambda p: int(p.split("_f")[1].split(".")[0]))
s = socket.create_connection(("127.0.0.1", port), timeout=5)
for i, fp in enumerate(frames):
    body = open(fp, "rb").read()
    fn = os.path.basename(fp)
    try:
        s.sendall(struct.pack(">I", len(body)) + body)
    except Exception as e:
        print(f"SEND FAIL at {fn}: {e}"); break
    # read the 4-byte length then the body
    try:
        s.settimeout(3)
        hdr = b""
        while len(hdr) < 4:
            r = s.recv(4 - len(hdr))
            if not r:
                print(f"EOF (peer closed) after sending {fn} (frame #{i})"); sys.exit(0)
            hdr += r
        rlen = struct.unpack(">I", hdr)[0]
        got = b""
        while len(got) < rlen:
            r = s.recv(rlen - len(got))
            if not r: break
            got += r
    except socket.timeout:
        print(f"TIMEOUT waiting for response to {fn} (frame #{i})"); sys.exit(0)
    except Exception as e:
        print(f"RECV FAIL at {fn} (frame #{i}): {e}"); sys.exit(0)
print(f"replayed {len(frames)} frames OK, no crash")
