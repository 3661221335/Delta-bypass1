import time
import json
import requests
from requests.adapters import HTTPAdapter
from auth_client import extract_ticket, parse_new_ticket, MIN_TICKET_LEN, build_meta_payload, build_stream_payload

PROXY = None

_session = None
def get_session():
    global _session
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
    def total(self):
        return time.time() - self.t0

def solve_chain(ticket, use_proxy=False, max_retries=3):
    timer = Timer()
    
    if not ticket or len(ticket) < MIN_TICKET_LEN:
        return None, timer

    session = get_session()
    step_url = f"https://auth.platorelay.com/api/session/step?ticket={ticket}&service=1"
    
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
                "X-Client-Version": "8.2.1"
            }

            r = session.put(step_url, json=payload, headers=headers, timeout=15)
            res_json = r.json()

            if not res_json.get("success"):
                msg = str(res_json)
                if "expired" in msg or "invalid" in msg:
                    return None, timer
                time.sleep(2)
                continue

            data = res_json.get("data") or {}
            new_url = data.get("url")
            if new_url and new_url != "about:blank":
                nd = parse_new_ticket(new_url)
                if nd:
                    ticket = nd
            
            status_url = f"https://auth.platorelay.com/api/session/status?ticket={ticket}"
            for _ in range(10):
                time.sleep(1.2)
                sr = session.get(status_url, headers=headers, timeout=10)
                sres = sr.json()
                key = (sres.get("data") or {}).get("key")
                if key and key != "KEY_NOT_FOUND":
                    return key, timer
                if "expired" in str(sres):
                    return None, timer
                    
        except Exception as e:
            time.sleep(2)
            continue

    return None, timer
