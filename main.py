import time
import json
import re
import requests
from fastapi import FastAPI, Query

app = FastAPI()

PLATOBOOST_HOST = "https://auth.platorelay.com"
CLIENT_VERSION = "8.2.1"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json",
    "Content-Type": "application/json",
    "X-Client-Name": "platoboost webclient",
    "X-Client-Version": CLIENT_VERSION
}

def extract_ticket(url: str) -> str:
    m = re.search(r"[?&]d=([A-Za-z0-9_\-]+)", url or "")
    if not m:
        m = re.search(r"([A-Za-z0-9_\-]{33,})", url or "")
    if not m:
        return ""
    return m.group(1)

def bypass_with_code(url: str):
    ticket = extract_ticket(url)
    if not ticket or len(ticket) < 33:
        return {"success": False, "error": "invalid url (no ticket)", "source": "Code"}

    step_url = f"{PLATOBOOST_HOST}/api/session/step?ticket={ticket}&service=1"
    try:
        payload = {"captcha": None, "meta": "", "stream": "", "resolved": True}
        r = requests.put(step_url, headers=HEADERS, json=payload, timeout=15)
        res_json = r.json()

        if not res_json.get("success"):
            msg = str(res_json.get("message", ""))
            if "expired" in msg or "invalid" in msg:
                return {"success": False, "error": "expired", "source": "Code"}
            if "account-unlock-required" in msg:
                return {"success": False, "error": "account-unlock-required", "source": "Code"}
            return {"success": False, "error": f"step failed: {msg}", "source": "Code"}

        data = res_json.get("data") or {}
        new_url = data.get("url")
        if new_url and new_url != "about:blank":
            new_ticket = extract_ticket(new_url)
            if new_ticket: ticket = new_ticket

        status_url = f"{PLATOBOOST_HOST}/api/session/status?ticket={ticket}"
        for _ in range(10):
            time.sleep(1.2)
            sr = requests.get(status_url, headers=HEADERS, timeout=10)
            sres = sr.json()
            key = (sres.get("data") or {}).get("key")
            if key and key != "KEY_NOT_FOUND":
                return {"success": True, "key": key, "source": "Code"}
            if "expired" in str(sres):
                return {"success": False, "error": "expired", "source": "Code"}
        return {"success": False, "error": "not issued (timeout)", "source": "Code"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "network timeout", "source": "Code"}
    except Exception as e:
        return {"success": False, "error": f"exception: {str(e)}", "source": "Code"}

def bypass_with_token(url: str, token: str):
    ticket = extract_ticket(url)
    if not ticket or len(ticket) < 33:
        return {"success": False, "error": "invalid url (no ticket)", "source": "Token"}

    step_url = f"{PLATOBOOST_HOST}/api/session/step?ticket={ticket}&service=1"
    try:
        payload = {"captcha": token, "meta": "", "stream": "", "resolved": True}
        r = requests.put(step_url, headers=HEADERS, json=payload, timeout=15)
        res_json = r.json()

        if not res_json.get("success"):
            msg = str(res_json.get("message", ""))
            if "account-unlock-required" in msg:
                return {"success": False, "error": "token invalid or ip blocked", "source": "Token"}
            return {"success": False, "error": f"step failed: {msg}", "source": "Token"}

        data = res_json.get("data") or {}
        new_url = data.get("url")
        if new_url and new_url != "about:blank":
            new_ticket = extract_ticket(new_url)
            if new_ticket: ticket = new_ticket

        status_url = f"{PLATOBOOST_HOST}/api/session/status?ticket={ticket}"
        for _ in range(10):
            time.sleep(1.2)
            sr = requests.get(status_url, headers=HEADERS, timeout=10)
            sres = sr.json()
            key = (sres.get("data") or {}).get("key")
            if key and key != "KEY_NOT_FOUND":
                return {"success": True, "key": key, "source": "Token"}
            if "expired" in str(sres):
                return {"success": False, "error": "expired", "source": "Token"}
        return {"success": False, "error": "not issued (timeout)", "source": "Token"}
    except Exception as e:
        return {"success": False, "error": f"exception: {str(e)}", "source": "Token"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/delta")
def delta(url: str = Query(...), token: str = Query(None)):
    code_result = bypass_with_code(url)
    if code_result.get("success"):
        return {"key": code_result["key"], "error": None, "source": "Code"}

    if token:
        token_result = bypass_with_token(url, token)
        if token_result.get("success"):
            return {"key": token_result["key"], "error": None, "source": "Token"}
        return {"key": None, "error": token_result.get("error"), "source": "Token"}

    return {"key": None, "error": f"Code failed ({code_result.get('error')}), try adding &token=xxx"}
