import os
import time
import json
import random
import re
import socket
import ssl
import struct
import base64
import string
import threading
import itertools
import urllib.parse
import requests
import urllib3
from Crypto.Cipher import AES as AES
from fastapi import FastAPI, Query

try:
    from curl_cffi import requests as cffi_requests
    _HAS_CFFI = True
except ImportError:
    _HAS_CFFI = False
    cffi_requests = None

try:
    from fake_useragent import UserAgent
    UA_SOURCES = (
        UserAgent(browsers=['Mobile Safari'], platforms='mobile'),
        UserAgent(browsers=['Chrome Mobile'], platforms='mobile', min_version=100.0),
    )
except Exception:
    UA_SOURCES = ()

AUTH_API = "https://auth.platorelay.com/api"
APP_URL = "https://auth.platorelay.com/a"
FALLBACK_VERSION = "8.1.1"
VER_TTL = 3600.0

MIN_TICKET_LEN = 33

FALLBACK_UA = ('Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) '
               'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Mobile/15E148 Safari/604.1')

SCREENS_IPHONE = ('390x844', '393x852', '375x812', '414x896', '430x932', '428x926', '360x780')
SCREENS_IPAD = ('820x1180', '834x1194', '768x1024', '744x1133', '1024x1366')
SCREENS_ANDROID = ('360x800', '412x915', '393x873', '384x854', '360x780', '412x892', '432x960')

UA_POOL = []
UA_IDX = itertools.count()
UA_SCREEN = {}

_client_version = FALLBACK_VERSION
_client_version_at = time.time()


def _env_proxy_url():
    proxy_list = (os.environ.get('PROXY_LIST') or '').strip()
    if proxy_list:
        items = [p.strip() for p in proxy_list.split(',') if p.strip()]
        if items:
            return random.choice(items)
    return None


def screens_for(platform, os_name):
    p = (platform or '').lower()
    o = (os_name or '').lower()
    if 'ipad' in p or 'tablet' in p:
        return SCREENS_IPAD
    if 'iphone' in p or 'ipod' in p or 'ios' in o:
        return SCREENS_IPHONE
    return SCREENS_ANDROID


def build_ua_pool(size=32):
    pool = []
    if not UA_SOURCES:
        return [FALLBACK_UA]
    per = max(1, size // len(UA_SOURCES))
    for src in UA_SOURCES:
        got = 0
        tried = 0
        while got < per and tried < per * 8:
            tried += 1
            try:
                rec = src.getRandom
            except Exception:
                break
            if not isinstance(rec, dict):
                break
            s = rec.get('useragent')
            if not s or s in UA_SCREEN:
                continue
            cands = screens_for(rec.get('platform'), rec.get('os'))
            UA_SCREEN[s] = cands[hash(s) % len(cands)]
            pool.append(s)
            got += 1
    if not pool:
        pool = [FALLBACK_UA]
        UA_SCREEN.setdefault(FALLBACK_UA, SCREENS_IPHONE[0])
    return pool


def rand_ua():
    global UA_POOL
    if not UA_POOL:
        UA_POOL = build_ua_pool()
    return UA_POOL[next(UA_IDX) % len(UA_POOL)]


def pick_screen(user_agent):
    s = UA_SCREEN.get(user_agent)
    if s:
        return s
    low = (user_agent or '').lower()
    if 'ipad' in low:
        cands = SCREENS_IPAD
    elif 'iphone' in low or 'ipod' in low:
        cands = SCREENS_IPHONE
    else:
        cands = SCREENS_ANDROID
    return cands[hash(user_agent or '') % len(cands)]


class _CffiResp:
    def __init__(self, r):
        self.status = r.status_code
        self.data = r.content
        self.headers = dict(r.headers)


class _CffiPool:
    def __init__(self, impersonate="chrome"):
        self.impersonate = impersonate

    def _resolve_timeout(self, timeout):
        if timeout is None:
            return 30
        if hasattr(timeout, 'read') and hasattr(timeout, 'connect'):
            return timeout.read or timeout.connect or 30
        try:
            return float(timeout)
        except Exception:
            return 30

    def request(self, method, url, body=None, headers=None, timeout=None, redirect=False, **kwargs):
        t = self._resolve_timeout(timeout)
        proxy_url = _env_proxy_url()
        proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
        r = cffi_requests.request(
            method=method.upper(),
            url=url,
            data=body,
            headers=headers or {},
            impersonate=self.impersonate,
            proxies=proxies,
            timeout=t,
            allow_redirects=bool(redirect),
        )
        return _CffiResp(r)


def _http_get(url, headers=None):
    try:
        if _HAS_CFFI:
            r = cffi_requests.get(url, headers=headers or {}, impersonate="chrome", timeout=8)
            if r.status_code != 200:
                return None
            return r.text
        r = requests.get(url, headers=headers or {}, timeout=8)
        if r.status_code != 200:
            return None
        return r.text
    except Exception:
        return None


def _version_candidates(text):
    found = []
    i = 0
    data = text
    n = len(data)
    while i < n:
        if data[i] == "'":
            j = data.find("'", i + 1)
            if j < 0:
                break
            token = data[i + 1:j]
            parts = token.split('.')
            if (len(parts) == 3
                    and all(p.isdigit() for p in parts)
                    and token not in found):
                found.append(token)
            i = j + 1
            continue
        i += 1
    return found


def aes_ctr_encrypt(plaintext, key_bytes, iv_bytes):
    key = bytearray(key_bytes) if isinstance(key_bytes, (bytes, bytearray)) else bytearray(key_bytes)
    iv = bytearray(iv_bytes) if isinstance(iv_bytes, (bytes, bytearray)) else bytearray(iv_bytes)
    data = plaintext.encode() if isinstance(plaintext, str) else plaintext
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = AES.new(bytes(key), AES.MODE_ECB).encrypt(bytes(iv))
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], blk))
        j = 15
        while True:
            iv[j] = (iv[j] + 1) & 0xFF
            if iv[j] != 0:
                break
            j -= 1
            if j < 0:
                break
    return bytes(out)


def build_meta_stream(ticket, now_ms=None, user_agent=None, screen=None):
    if len(ticket) < MIN_TICKET_LEN:
        return None
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    if user_agent is None:
        user_agent = rand_ua()
    if screen is None:
        screen = pick_screen(user_agent)

    key_meta = ticket[:16]
    ctr_meta = ticket[16:32]
    key_stream = ticket[1:17]
    ctr_stream = ticket[17:33]

    meta_plain = json.dumps({"browserInfo": [{"screen": screen, "ua": user_agent, "time": now_ms}]}, separators=(',', ':'))
    stream_plain = json.dumps({"events": [{"event": 1, "data": {"time": now_ms}}]}, separators=(',', ':'))

    meta = aes_ctr_encrypt(meta_plain, [ord(c) for c in key_meta], [ord(c) for c in ctr_meta]).hex()
    stream = aes_ctr_encrypt(stream_plain, [ord(c) for c in key_stream], [ord(c) for c in ctr_stream]).hex()
    return meta, stream


def _version_works(version, ua):
    letters = string.ascii_letters + string.digits
    fake = ''.join(random.choice(letters) for _ in range(64))
    built = build_meta_stream(fake, user_agent=ua)
    if built is None:
        return False
    meta, stream = built
    url = f"{AUTH_API}/session/step?ticket={urllib.parse.quote(fake)}&service=3"
    body = json.dumps({"captcha": None, "meta": meta, "stream": stream, "resolved": True}).encode()
    try:
        r = step_pool.request('PUT', url, body=body, redirect=False, headers={
            'User-Agent': ua,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'x-client-name': 'platoboost webclient',
            'x-client-version': version,
        })
        return b'outdated client' not in r.data
    except Exception:
        return False


def _refresh_client_version():
    global _client_version, _client_version_at
    try:
        html = _http_get(APP_URL, {'User-Agent': FALLBACK_UA})
        if not html:
            return
        i = html.find('/assets/index-')
        if i < 0:
            return
        j = html.find('"', i)
        if j < 0:
            return
        script_url = 'https://auth.platorelay.com' + html[i:j]

        candidates = []
        try:
            if _HAS_CFFI:
                r = cffi_requests.get(script_url, headers={
                    'User-Agent': FALLBACK_UA, 'Range': 'bytes=0-262143'
                }, impersonate="chrome", timeout=8)
            else:
                r = requests.get(script_url, headers={
                    'User-Agent': FALLBACK_UA, 'Range': 'bytes=0-262143'
                }, timeout=8)
            if r.status_code in (200, 206):
                candidates = _version_candidates(r.text)
        except Exception:
            pass
        if not candidates:
            body = _http_get(script_url, {'User-Agent': FALLBACK_UA})
            if body:
                candidates = _version_candidates(body)
        if not candidates:
            return

        for cand in candidates:
            if _version_works(cand, FALLBACK_UA):
                _client_version = cand
                _client_version_at = time.time()
                return
    except Exception:
        pass


def client_version():
    return _client_version


def start_version_watcher():
    def worker():
        while True:
            try:
                _refresh_client_version()
            except Exception:
                pass
            time.sleep(VER_TTL)
    t = threading.Thread(target=worker, daemon=True)
    t.start()


if _HAS_CFFI:
    step_pool = _CffiPool(impersonate="chrome")
else:
    _proxy_url = _env_proxy_url()
    if _proxy_url:
        step_pool = urllib3.ProxyManager(_proxy_url, num_pools=8, maxsize=64, block=False, retries=False, timeout=urllib3.Timeout(connect=3.0, read=20.0))
    else:
        step_pool = urllib3.PoolManager(num_pools=8, maxsize=64, block=False, retries=False, timeout=urllib3.Timeout(connect=3.0, read=20.0))


def do_step(ticket, service=3, now_ms=None):
    step_ua = rand_ua()
    built = build_meta_stream(ticket, now_ms, user_agent=step_ua)
    if built is None:
        return {"success": False, "error": "ticket 长度不足"}
    meta, stream = built
    url = f"{AUTH_API}/session/step?ticket={urllib.parse.quote(ticket)}&service={service}"
    body = json.dumps({"captcha": None, "meta": meta, "stream": stream, "resolved": True}).encode()
    last_err = None
    for attempt in range(3):
        try:
            r = step_pool.request('PUT', url, body=body, redirect=False, headers={
                'User-Agent': step_ua,
                'Content-Type': 'application/json',
                'Accept': 'application/json, text/plain, */*',
                'x-client-name': 'platoboost webclient',
                'x-client-version': client_version()
            })
            if r.status != 200:
                last_err = f"http {r.status}"
                time.sleep(0.5)
                continue
            try:
                return json.loads(r.data)
            except Exception:
                last_err = "non-json response"
                time.sleep(0.5)
                continue
        except Exception as e:
            last_err = str(e)
            time.sleep(0.5)
            continue
    return {"success": False, "error": last_err or "step failed"}


def get_json(path_qs, retries=2):
    last_err = None
    for attempt in range(retries + 1):
        try:
            r = step_pool.request('GET', f"{AUTH_API}/{path_qs}", redirect=False, headers={'User-Agent': rand_ua(), 'Accept': 'application/json'})
            if r.status != 200:
                last_err = f"http {r.status}"
                time.sleep(0.25)
                continue
            return json.loads(r.data)
        except Exception as e:
            last_err = str(e)
            time.sleep(0.25)
            continue
    return {"success": False, "error": last_err or "get failed", "transient": True}


def get_session_metadata(ticket):
    return get_json(f"session/metadata?ticket={urllib.parse.quote(ticket)}")


def get_session_status(ticket):
    return get_json(f"session/status?ticket={urllib.parse.quote(ticket)}")


INVALID_MARKERS = ('invalid payload', 'expired', 'not found', 'invalid session', 'invalid ticket', 'does not exist')


def check_ticket_valid(ticket):
    try:
        meta = get_session_metadata(ticket)
    except Exception:
        return True, None
    if not isinstance(meta, dict):
        return True, None
    if meta.get('success') is True:
        return True, None
    if meta.get('transient'):
        return True, None
    if meta.get('success') is False:
        msg = str(meta.get('message') or meta.get('error') or '').lower()
        if any(m in msg for m in INVALID_MARKERS):
            return False, str(meta.get('message') or meta.get('error') or 'invalid link')
        return True, None
    return True, None


def extract_ticket(arg):
    t = arg.strip()
    if t.startswith('http'):
        parsed = urllib.parse.urlparse(t)
        qs = urllib.parse.parse_qs(parsed.query)
        if 'd' in qs:
            return qs['d'][0]
        return t
    return t


def solve_chain(ticket, max_rounds=8):
    current_ticket = ticket
    deadline = time.time() + 40
    for round_idx in range(max_rounds):
        if time.time() > deadline:
            break
        valid, reason = check_ticket_valid(current_ticket)
        if not valid:
            return {"key": None, "error": reason}
        r = do_step(current_ticket)
        if isinstance(r, dict):
            if r.get("success") and r.get("key"):
                return {"key": r["key"], "error": None}
            if r.get("key"):
                return {"key": r["key"], "error": None}
            url = (r.get("data") or {}).get("url", "")
            if url == "about:blank":
                for _ in range(10):
                    st = get_session_status(current_ticket)
                    st_data = st.get('data', st) if isinstance(st, dict) else {}
                    k = st_data.get('key', '')
                    if k and k != 'KEY_NOT_FOUND':
                        return {"key": k, "error": None}
                    time.sleep(0.2)
                continue
            err = str(r.get("error", ""))
            lower = err.lower()
            if "invalid" in lower or "expired" in lower:
                return {"key": None, "error": err}
        time.sleep(0.5)
    st = get_session_status(current_ticket)
    st_data = st.get('data', st) if isinstance(st, dict) else {}
    k = st_data.get('key', '')
    if k and k != 'KEY_NOT_FOUND':
        return {"key": k, "error": None}
    return {"key": None, "error": "solve failed"}


app = FastAPI()


@app.on_event("startup")
def startup_event():
    start_version_watcher()


@app.get("/health")
@app.get("/healthz")
@app.get("/")
def health_check():
    return {"status": "ok"}


@app.get("/delta")
def delta(url: str = Query(...)):
    try:
        ticket = extract_ticket(url)
        if not ticket or len(ticket) < MIN_TICKET_LEN:
            return {"key": None, "error": "invalid url (no ticket)"}
        return solve_chain(ticket)
    except Exception as e:
        return {"key": None, "error": f"solve exception: {type(e).__name__} - {str(e)}"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
