#!/usr/bin/env python3
# cbdec.py — throwaway canonical-CBOR pretty-printer for harvested wire frames.
# Decodes entity-core envelope/data maps; 33-byte content-hash bytes shown as b58-ish hex.
import sys, base64

def rd(b, i):
    ib = b[i]; mt = ib >> 5; ai = ib & 0x1f; i += 1
    if ai < 24: val = ai
    elif ai == 24: val = b[i]; i += 1
    elif ai == 25: val = int.from_bytes(b[i:i+2],'big'); i += 2
    elif ai == 26: val = int.from_bytes(b[i:i+4],'big'); i += 4
    elif ai == 27: val = int.from_bytes(b[i:i+8],'big'); i += 8
    else: val = None
    return mt, val, i

def dec(b, i, depth):
    mt, val, i = rd(b, i)
    pad = '  '*depth
    if mt == 0: return repr(val), i
    if mt == 1: return repr(-1-val), i
    if mt == 2:
        s = b[i:i+val]; i += val
        if val <= 40: return 'h:'+s.hex(), i
        return f'bytes[{val}]', i
    if mt == 3:
        s = b[i:i+val].decode('utf8','replace'); i += val
        return repr(s), i
    if mt == 4:
        parts=[]
        for _ in range(val):
            v,i = dec(b,i,depth+1); parts.append(v)
        return '['+', '.join(parts)+']', i
    if mt == 5:
        out='{\n'
        for _ in range(val):
            k,i = dec(b,i,depth+1)
            v,i = dec(b,i,depth+1)
            out += pad+'  '+str(k)+': '+str(v)+'\n'
        out += pad+'}'
        return out, i
    if mt == 6:  # tag
        v,i = dec(b,i,depth)
        return f'tag({val}){v}', i
    if mt == 7:
        return {20:'false',21:'true',22:'null'}.get(val,f'simple{val}'), i
    return '?', i

for path in sys.argv[1:]:
    b = open(path,'rb').read()
    print(f'===== {path} ({len(b)} bytes) =====')
    try:
        v,_ = dec(b,0,0)
        print(v)
    except Exception as e:
        print('DECODE ERR', e, b[:64].hex())
