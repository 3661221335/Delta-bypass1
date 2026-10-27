import time
import json
import re
import requests
from fastapi import FastAPI, Query
from Crypto.Cipher import AES
from Crypto.Util import Counter

app = FastAPI()

PLATOBOOST_HOST = "https://auth.platorelay.com"
MIN_TICKET_LEN = 33

# 动态版本缓存
_version_cache = {"version": "8.3.2", "ts": 0}

def get_latest_version():
    now = time.time()
    if now - _version_cache["ts"] < 1800:
        return _version_cache["version"]
    try:
        # 扒官方前端 JS 拿最新版本
        r = requests.get(PLATOBOOST_HOST, timeout=10)
        js_files = re.findall(r'src="([^"]+\.js)"', r.text)
        for js in js_files:
            js_url = PLATOBOOST_HOST + js if js.startswith("/") else js
            js_res = requests.get(js_url, timeout=10)
            m = re.search(r'"(\d+\.\d+\.\d+)"', js_res.text)
            if m:
                ver = m.group(1)
                _version_cache["version"] = ver
                _version_cache["ts"] = now
                return ver
    except Exception:
        pass
    return "8.3.2" # 兜底强制最新版本

def extract_ticket(url: str) -> str:
    m = re.search(r"[?&]d=([A-Za-z0-9_\-]+)", url or "")
    if not m:
        return ""
    return m.group(1)

def aes_ctr_encrypt(plain_text: str, key: bytes, iv: bytes) -> str:
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(plain_text.encode()).hex()

def build_payload(ticket: str):
    if len(ticket) < 64:
        return None, None
    # 官方的 AES 密钥派生逻辑
    key1 = ticket[0:16].encode()
    iv1 = ticket[16:32].encode()
    key2 = ticket[32:48].encode()
    iv2 = ticket[48:64].encode()

    # 官方最新的 payload 结构
    meta_plain = '{"browserInfo":[]}'
    stream_plain = '{"events":[],"codecProof":null}'
    
    meta_enc = aes_ctr_encrypt(meta_plain, key1, iv1)
    stream_enc = aes_ctr_encrypt(stream_plain, key2, iv2)
    return meta_enc, stream_enc

def solve_delta(url: str):
    ticket = extract_ticket(url)
    if not ticket or len(ticket) < MIN_TICKET_LEN:
        return {"key": None, "error": "invalid link"}

    version = get_latest_version()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Client-Name": "platoboost webclient",
        "X-Client-Version": version
    }

    current_ticket = ticket
    last_step_time = 0

    for _ in range(8):
        gap = time.time() - last_step_time
        if gap < 5.0:
            time.sleep(5.0 - gap)

        meta_enc, stream_enc = build_payload(current_ticket)
        if not meta_enc:
            return {"key": None, "error": "ticket format invalid"}

        step_url = f"{PLATOBOOST_HOST}/api/session/step?ticket={current_ticket}&service=3"
        payload = {
            "captcha": None,
            "meta": meta_enc,
            "stream": stream_enc,
            "resolved": True
        }

        try:
            r = requests.put(step_url, headers=headers, json=payload, timeout=15)
            res = r.json()
            last_step_time = time.time()
        except Exception as e:
            return {"key": None, "error": f"net error: {str(e)}"}

        if not res.get("success"):
            msg = str(res.get("message", ""))
            # 如果是太快了，等一会儿重试
            if "finishing checkpoints too fast" in msg:
                time.sleep(6)
                continue
            return {"key": None, "error": f"step failed: {msg}"}

        # 检查是否有新链接下发
        data = res.get("data") or {}
        new_url = data.get("url")
        if new_url and new_url != "about:blank":
            new_ticket = extract_ticket(new_url)
            if new_ticket:
                current_ticket = new_ticket
                continue

        # 轮询卡密
        status_url = f"{PLATOBOOST_HOST}/api/session/status?ticket={current_ticket}"
        for _ in range(8):
            time.sleep(0.8)
            try:
                sr = requests.get(status_url, headers=headers, timeout=10)
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
