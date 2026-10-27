import time
import json
import re
import requests
from fastapi import FastAPI, Query

app = FastAPI()

PLATOBOOST_HOST = "https://auth.platorelay.com"

def get_latest_version():
    try:
        r = requests.get(PLATOBOOST_HOST, timeout=10)
        m = re.search(r'(\d+\.\d+\.\d+)', r.text)
        if m: return m.group(1)
    except Exception:
        pass
    return "8.2.5"

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
        "X-Client-Version": version
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
