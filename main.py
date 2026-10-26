import time
import json
import urllib.parse
import requests
from fastapi import FastAPI, Query

app = FastAPI()

# 官方接口
BASE_URL = "https://auth.platorelay.com"
CLIENT_VERSION = "8.2.1"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json",
    "Content-Type": "application/json",
    "X-Client-Name": "platoboost webclient",
    "X-Client-Version": CLIENT_VERSION,
}

# 缓存机制（24小时）
CACHE = {}

def get_ticket(url: str):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    return qs.get("d", [""])[0]

def solve_delta(ticket: str):
    if not ticket or len(ticket) < 33:
        return {"error": "invalid url (no ticket)"}

    # 查缓存
    if ticket in CACHE:
        cached_time, key = CACHE[ticket]
        if time.time() - cached_time < 86400:
            return {"key": key, "cached": True, "error": None}

    # 1. 发送 Step 请求
    step_url = f"{BASE_URL}/api/session/step?ticket={ticket}&service=1"
    payload = {
        "captcha": None,
        "meta": "",
        "stream": "",
        "resolved": True
    }
    
    try:
        r = requests.put(step_url, headers=HEADERS, json=payload, timeout=15)
        res = r.json()
    except Exception as e:
        return {"error": f"net error: {e}"}

    if not res.get("success"):
        msg = str(res)
        if "expired" in msg: return {"error": "链接已过期"}
        if "account-unlock-required" in msg: return {"error": "需要账号验证(IP被风控)"}
        return {"error": f"step failed: {msg}"}

    # 如果官方下发了新会话
    data = res.get("data") or {}
    new_url = data.get("url")
    if new_url and new_url != "about:blank":
        new_ticket = get_ticket(new_url)
        if new_ticket:
            ticket = new_ticket

    # 2. 轮询查卡
    status_url = f"{BASE_URL}/api/session/status?ticket={ticket}"
    for _ in range(15):
        time.sleep(2)
        try:
            sr = requests.get(status_url, headers=HEADERS, timeout=10)
            sres = sr.json()
        except Exception:
            continue
            
        key = (sres.get("data") or {}).get("key")
        if key and key != "KEY_NOT_FOUND":
            CACHE[ticket] = (time.time(), key)
            return {"key": key, "cached": False, "error": None}
            
        if "expired" in str(sres):
            return {"error": "链接已过期"}

    return {"error": "未签发卡密 (not issued)"}

@app.get("/delta")
def api_delta(url: str = Query(...)):
    ticket = get_ticket(url)
    if not ticket:
        return {"key": None, "error": "缺少 d= 参数"}
    
    result = solve_delta(ticket)
    return result

@app.get("/health")
def health():
    return {"status": "ok"}
