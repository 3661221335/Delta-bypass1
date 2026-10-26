import re
import time
import json
import base64
import random
import urllib.parse

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None

MIN_TICKET_LEN = 33
DEFAULT_CLIENT_VERSION = "8.2.4"

def extract_ticket(url):
    m = re.search(r"[?&]d=([A-Za-z0-9_\-]+)", url or "")
    if not m:
        m = re.search(r"([A-Za-z0-9_\-]{33,})", url or "")
    if not m:
        raise ValueError("no ticket")
    return m.group(1)

def parse_new_ticket(url):
    try:
        return extract_ticket(url)
    except Exception:
        return None

SBOX = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")

def _xt(a):
    a <<= 1
    return (a ^ 0x11b) & 0xff if a & 0x100 else a

def _expand(key):
    nk, nr = 4, 10
    w = [list(key[i * 4:i * 4 + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xt(rcon)
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w

def _enc(block, w):
    s = [block[i] ^ w[i // 4][i % 4] for i in range(16)]
    for r in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]
        if r != 10:
            n = []
            for c in range(4):
                a = s[c * 4:c * 4 + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                n += [a[i] ^ t ^ _xt(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            s = n
        s = [s[i] ^ w[r * 4 + i // 4][i % 4] for i in range(16)]
    return bytes(s)

def ctr_hex(plain, ticket, off):
    kb = ticket[off:off + 16].encode()
    iv = bytearray(ticket[off + 16:off + 32].encode())
    w = _expand(kb)
    data = plain.encode()
    out = bytearray()
    for i in range(0, len(data), 16):
        ks = _enc(bytes(iv), w)
        for j, b in enumerate(data[i:i + 16]): out.append(b ^ ks[j])
        for j in range(15, -1, -1):
            iv[j] = (iv[j] + 1) & 0xff
            if iv[j]: break
    return out.hex()

def build_meta_payload(ticket, off=0):
    info = {"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "screen": "1920x1080", "touch": True, "lang": "zh-CN", "tz": "Asia/Shanghai", "hardwareConcurrency": 8}
    return ctr_hex(json.dumps({"browserInfo": [info]}, separators=(",", ":")), ticket, off)

def build_stream_payload(ticket, off=1):
    now = int(time.time() * 1000)
    events = [{"t": now - 4000, "type": "pointerdown", "x": 960, "y": 540}]
    payload = {"events": events, "codecProof": "webgl2:ok"}
    return ctr_hex(json.dumps(payload, separators=(",", ":")), ticket, off)

def start_version_watcher():
    pass
