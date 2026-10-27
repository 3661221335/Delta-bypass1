import time
import json
import re
import requests
from fastapi import FastAPI, Query
from Crypto.Cipher import AES
from Crypto.Util import Counter
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

app = FastAPI()

PLATOBOOST_HOST = "https://auth.platorelay.com"
MIN_TICKET_LEN = 33

_version_cache = {"version": "8.2.5", "ts": 0}

def get_client_version():
    now = time.time()
    if now - _version_cache["ts"] < 3600:
        return _version_cache["version"]
    try:
        r = requests.get(PLATOBOOST_HOST, timeout=5)
        m = re.search(r'(\d+\.\d+\.\d+)', r.text)
        if m:
            _version_cache["version"] = m.group(1)
            _version_cache["ts"] = now
            return _version_cache["version"]
    except Exception:
        pass
    return _version_cache["version"]

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

def extract_ticket(url: str) -> str:
    m = re.search(r"[?&]d=([A-Za-z0-9_\-]+)", url or "")
    if not m:
        return ""
    return m.group(1)

def aes_ctr_encrypt(plain_text: str, key: bytes, iv: bytes) -> str:
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(plain_text.encode()).hex()

def build_meta_stream(ticket: str):
    if len(ticket) < 64:
        return None, None
    try:
        key1 = ticket[0:16].encode()
        iv1 = ticket[16:32].encode()
        key2 = ticket[32:48].encode()
        iv2 = ticket[48:64].encode()
    except Exception:
        return None, None

    meta_plain = '{"browserInfo":[]}'
    stream_plain = '{"events":[],"codecProof":null}'
    
    meta_enc = aes_ctr_encrypt(meta_plain, key1, iv1)
    stream_enc = aes_ctr_encrypt(stream_plain, key2, iv2)
    return meta_enc, stream_enc

def solve_delta(url: str):
    ticket = extract_ticket(url)
    if not ticket or len(ticket) < MIN_TICKET_LEN:
        return {"key": None, "error": "invalid url (no ticket)"}

    session = create_session()
    current_ticket = ticket
    last_step_time = 0

    for round_num in range(12):
        gap = time.time() - last_step_time
        if gap < 5.0:
            time.sleep(5.0 - gap)

        meta_enc, stream_enc = build_meta_stream(current_ticket)
        if meta_enc is None:
            return {"key": None, "error": "ticket too short for encryption"}

        version = get_client_version()
        step_url = f"{PLATOBOOST_HOST}/api/session/step?ticket={current_ticket}&service=3"
        payload = {
            "captcha": None,
            "meta": meta_enc,
            "stream": stream_enc,
            "resolved": True
        }
        headers = {"X-Client-Version": version}

        try:
            r = session.put(step_url, json=payload, headers=headers, timeout=15)
            res_json = r.json()
            last_step_time = time.time()
        except Exception as e:
            return {"key": None, "error": f"net error: {str(e)}"}

        if not res_json.get("success"):
            msg = str(res_json.get("message", ""))
            if "finishing checkpoints too fast" in msg:
                time.sleep(5)
                continue
            return {"key": None, "error": f"step failed: {msg}"}

        data = res_json.get("data") or {}
        new_url = data.get("url")
        if new_url and new_url != "about:blank":
            new_ticket = extract_ticket(new_url)
            if new_ticket:
                current_ticket = new_ticket
                continue

        status_url = f"{PLATOBOOST_HOST}/api/session/status?ticket={current_ticket}"
        for _ in range(10):
            time.sleep(0.5)
            try:
                sr = session.get(status_url, timeout=10)
                sres = sr.json()
                key = (sres.get("data") or {}).get("key")
                if key and key != "KEY_NOT_FOUND":
                    return {"key": key, "error": None}
                if "expired" in str(sres):
                    return {"key": None, "error": "expired"}
            except Exception:
                continue
        
        current_ticket = ticket

    return {"key": None, "error": "timeout, no key issued"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/delta")
def delta(url: str = Query(...)):
    try:
        return solve_delta(url)
    except Exception as e:
        return {"key": None, "error": f"exception: {str(e)}"}
