import base64
import json
import random
import threading
import time
import ssl
import urllib.parse

import requests
from requests.adapters import HTTPAdapter

from auth_client import (
    api_step, api_status, extract_ticket, parse_new_ticket, MIN_TICKET_LEN,
    build_meta_payload, build_stream_payload, DEFAULT_CLIENT_VERSION
)

try:
    import orjson
    def json_loads(s):
        return orjson.loads(s)
except ImportError:
    def json_loads(s):
        return json.loads(s)

# 代理设置（如果你之前有代理，可以在这里放开）
PROXY = None
# PROXY = "http://user:pass@ip:port"

_session = None
_session_lock = threading.Lock()

def get_session():
    global _session
    if _session is None:
        with _session_lock:
            if _session is None:
                s = requests.Session()
                adapter = HTTPAdapter(pool_connections=50, pool_maxsize=50)
                s.mount('http://', adapter)
                s.mount('https://', adapter)
                if PROXY:
                    s.proxies = {"http": PROXY, "https": PROXY}
                _session = s
    return _session

class Timer:
    def __init__(self):
        self.t0 = time.time()
        self._total = 0.0
    def total(self):
        return time.time() - self.t0

def solve_chain(ticket, use_proxy=False, max_retries=3):
    timer = Timer()
    
    if not ticket or len(ticket) < MIN_TICKET_LEN:
        res = type('obj', (object,), {'invalid_reason': 'ticket too short'})
        return None, res

    session = get_session()
    step_url = "https://auth.platorelay.com/api/session/step?ticket=%s&service=1" % ticket
    
    for attempt in range(max_retries):
        try:
            meta = build_meta_payload(ticket, 0)
            stream = build_stream_payload(ticket, 1)
            
            payload = {
                "captcha": None,
                "meta": meta,
                "stream": stream,
                "resolved": True
            }
            
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-Client-Name": "platoboost webclient",
                "X-Client-Version": DEFAULT_CLIENT_VERSION
            }

            r = session.put(step_url, json=payload, headers=headers, timeout=15)
            res_json = r.json()

            if not res_json.get("success"):
                msg = str(res_json)
                if "expired" in msg or "invalid" in msg:
                    obj = type('obj', (object,), {'invalid_reason': msg})
                    return None, obj
                
                time.sleep(2)
                continue

            data = res_json.get("data") or {}
            new_url = data.get("url")
            if new_url and new_url != "about:blank":
                nd = parse_new_ticket(new_url)
                if nd:
                    ticket = nd
            
            # 轮询状态
            status_url = "https://auth.platorelay.com/api/session/status?ticket=%s" % ticket
            for _ in range(10):
                time.sleep(1.2)
                sr = session.get(status_url, headers=headers, timeout=10)
                sres = sr.json()
                key = (sres.get("data") or {}).get("key")
                if key and key != "KEY_NOT_FOUND":
                    return key, timer
                
                if "expired" in str(sres):
                    obj = type('obj', (object,), {'invalid_reason': 'expired during status'})
                    return None, obj
                    
        except Exception as e:
            time.sleep(2)
            continue

    return None, timer
