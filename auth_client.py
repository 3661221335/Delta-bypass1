import os
import re
import time
import json
import random
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from Crypto.Cipher import AES
from Crypto.Util import Counter

MIN_TICKET_LEN = 33

_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11b
    return a & 0xff

def _encrypt_block(block, expanded_key):
    state = [block[i] ^ expanded_key[i] for i in range(16)]
    for round_num in range(1, 11):
        state = [_SBOX[b] for b in state]
        state = [state[(i + 4 * (i % 4)) % 16] for i in range(16)]
        if round_num != 10:
            new_state = []
            for c in range(4):
                a = state[c * 4:c * 4 + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                for i in range(4):
                    new_state.append(a[i] ^ t ^ _xtime(a[i] ^ a[(i + 1) % 4]))
            state = new_state
        state = [state[i] ^ expanded_key[round_num * 16 + i] for i in range(16)]
    return state

def _expand_key(key):
    expanded = list(key)
    rcon = 1
    for i in range(4, 44):
        temp = expanded[(i - 1) * 4:i * 4]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        for j in range(4):
            expanded.append(expanded[(i - 4) * 4 + j] ^ temp[j])
    return expanded

def _aes_ctr_encrypt(data, key, iv):
    expanded_key = _expand_key(key)
    counter = int.from_bytes(iv, 'big')
    result = bytearray()
    for i in range(0, len(data), 16):
        counter_bytes = counter.to_bytes(16, 'big')
        keystream = _encrypt_block(list(counter_bytes), expanded_key)
        chunk = data[i:i + 16]
        for j, b in enumerate(chunk):
            result.append(b ^ keystream[j])
        counter = (counter + 1) & ((1 << 128) - 1)
    return bytes(result)

def build_meta_stream(ticket, min_len=MIN_TICKET_LEN):
    if len(ticket) < min_len:
        return None
    try:
        key1 = ticket[0:16].encode()
        iv1 = ticket[16:32].encode()
        key2 = ticket[32:48].encode()
        iv2 = ticket[48:64].encode()
    except Exception:
        return None
    meta_plain = '{"browserInfo":[]}'
    stream_plain = '{"events":[],"codecProof":null}'
    try:
        meta_enc = _aes_ctr_encrypt(meta_plain.encode(), key1, iv1).hex()
        stream_enc = _aes_ctr_encrypt(stream_plain.encode(), key2, iv2).hex()
    except Exception:
        return None
    return {
        "meta": meta_enc,
        "stream": stream_enc,
    }

_version_cache = {"version": None, "ts": 0}

def get_client_version():
    now = time.time()
    if _version_cache["version"] and now - _version_cache["ts"] < 3600:
        return _version_cache["version"]
    fallback = "8.2.5"
    try:
        r = requests.get("https://auth.platorelay.com", timeout=10, verify=False)
        m = re.search(r'(\d+\.\d+\.\d+)', r.text)
        if m:
            version = m.group(1)
            _version_cache["version"] = version
            _version_cache["ts"] = now
            return version
    except Exception:
        pass
    return fallback

def create_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(pool_connections=20, pool_maxsize=20, max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Client-Name": "platoboost webclient",
    })
    return session

def do_step(session, ticket, service=3, timeout=20):
    payload = build_meta_stream(ticket)
    if payload is None:
        return {"success": False, "message": "invalid ticket length"}
    version = get_client_version()
    headers = {
        "X-Client-Version": version,
    }
    url = f"https://auth.platorelay.com/api/session/step?ticket={ticket}&service={service}"
    body = {
        "captcha": None,
        "meta": payload["meta"],
        "stream": payload["stream"],
        "resolved": True,
    }
    try:
        r = session.put(url, json=body, headers=headers, timeout=timeout)
        return r.json()
    except Exception as e:
        return {"success": False, "message": str(e)}

def extract_ticket(url):
    m = re.search(r'[?&]d=([A-Za-z0-9_\-]+)', url or "")
    if not m:
        raise ValueError("no ticket found")
    return m.group(1)

def parse_new_ticket(url):
    try:
        return extract_ticket(url)
    except Exception:
        return None
