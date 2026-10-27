import time
import json
import re
import requests
from fastapi import FastAPI, Query

app = FastAPI()

PLATOBOOST_HOST = "https://auth.platorelay.com"

# 版本号缓存，避免频繁请求
_version_cache = {"version": "8.2.5", "ts": 0}  # 默认值可改为你已知的最新版本

def get_latest_version():
    now = time.time()
    if now - _version_cache["ts"] < 3600:  # 缓存1小时
        return _version_cache["version"]

    try:
        # 尝试从多个可能的来源获取版本号
        urls = [
            PLATOBOOST_HOST,
            f"{PLATOBOOST_HOST}/",
            f"{PLATOBOOST_HOST}/api/session/step",  # 可能会返回版本信息
        ]
        for url in urls:
            try:
                r = requests.get(url, timeout=10, allow_redirects=True)
                if r.status_code == 200:
                    # 更宽松的匹配规则，可能匹配 v8.2.5、version: 8.2.5 等格式
                    m = re.search(r'v?(\d+\.\d+\.\d+)', r.text)
                    if m:
                        ver = m.group(1)
                        _version_cache["version"] = ver
                        _version_cache["ts"] = now
                        return ver
            except Exception:
                continue
    except Exception:
        pass

    # 如果都失败了，返回缓存中的版本
    return _version_cache["version"]

def extract_ticket(url: str) -> str:
    m = re.search(r"[?&]d=([A-Za-z0-9_\-]+)", url or "")
    if not m:
        return ""
    return m.group(1)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/delta")
def delta(url: str = Query(...)):
    ticket = extract_ticket(url)
    if not ticket or len(ticket) < 33:
        return {"key": None, "error": "invalid url (no ticket)"}

    version = get_latest_version()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Client-Name": "platoboost webclient",
        "X-Client-Version": version  # 使用动态获取的版本号
    }

    step_url = f"{PLATOBOOST_HOST}/api/session/step?ticket={ticket}&service=1"
    try:
        payload = {"captcha": None, "meta": "", "stream": "", "resolved": True}
        r = requests.put(step_url, headers=headers, json=payload, timeout=15)
        res_json = r.json()

        if not res_json.get("success"):
            msg = str(res_json.get("message", ""))
            return {"key": None, "error": f"step failed: {msg}"}

        data = res_json.get("data") or {}
        new_url = data.get("url")
        if new_url and new_url != "about:blank":
            new_ticket = extract_ticket(new_url)
            if new_ticket: ticket = new_ticket

        status_url = f"{PLATOBOOST_HOST}/api/session/status?ticket={ticket}"
        for _ in range(10):
            time.sleep(1.2)
            sr = requests.get(status_url, headers=headers, timeout=10)
            sres = sr.json()
            key = (sres.get("data") or {}).get("key")
            if key and key != "KEY_NOT_FOUND":
                return {"key": key, "error": None}
            if "expired" in str(sres):
                return {"key": None, "error": "expired"}

        return {"key": None, "error": "not issued (timeout)"}
    except Exception as e:
        return {"key": None, "error": f"exception: {str(e)}"}
