from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
import base64
import json
import re
import secrets
import time
import requests
import asyncio
from urllib.parse import unquote

app = FastAPI()

HOST = "auth.platorelay.com"
ORIGIN = f"https://{HOST}"
START_URL = f"{ORIGIN}/api/session/google/start"
D_PATTERN = re.compile(r"[A-Za-z0-9_\-]{20,}")
URL_RE = re.compile(r"auth\.platorelay\.com/a\?(?:[^&\s]*&)*d=([^&\s#]+)")

def gen_secret() -> str:
    raw = secrets.token_bytes(32)
    b64 = base64.b64encode(raw).decode("ascii")
    return b64.replace("+", "-").replace("/", "_").rstrip("=")

def extract_d(token_or_link: str):
    token_or_link = token_or_link.strip()
    m = URL_RE.search(token_or_link)
    if m:
        return m.group(1)
    cand = token_or_link.strip()
    cand = unquote(cand) if "%" in cand else cand
    if D_PATTERN.fullmatch(cand):
        return cand
    hits = D_PATTERN.findall(cand)
    if hits:
        return max(hits, key=len)
    return None

def redeem(d: str, max_retry: int = 3):
    secret = gen_secret()
    payload = json.dumps({"ticket": d, "secret": secret})
    headers = {
        "Content-Type": "application/json",
        "Origin": ORIGIN,
        "Referer": f"{ORIGIN}/a?d={d}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
    }

    for attempt in range(1, max_retry + 1):
        try:
            res = requests.post(START_URL, data=payload, headers=headers, timeout=15)
            if res.status_code == 429:
                time.sleep(3 * attempt)
                continue
                
            data = res.json()
            if data.get("success") and data.get("data", {}).get("flow"):
                flow = data["data"]["flow"]
                url = data["data"].get("url") or f"{ORIGIN}/api/session/google/authorize?state={flow}"
                return {"ok": True, "flow": flow, "authorize_url": url}
            
            return {"ok": False, "error": data.get("message") or data.get("error")}
            
        except requests.exceptions.RequestException as e:
            if attempt == max_retry:
                return {"ok": False, "error": f"Network Error: {str(e)}"}
            time.sleep(1)
            
    return {"ok": False, "error": "重试次数耗尽"}

def run_engine(url: str):
    start_t = time.time()
    d = extract_d(url)
    if not d:
        return {"key": None, "error": "无法从链接中解析出 d 参数", "elapsed": 0}
        
    result = redeem(d)
    if result["ok"]:
        return {
            "key": result["authorize_url"],
            "flow": result["flow"],
            "error": None, 
            "elapsed": round(time.time() - start_t, 2)
        }
    else:
        return {
            "key": None, 
            "error": result["error"], 
            "elapsed": round(time.time() - start_t, 2)
        }

@app.get("/bypass")
async def bypass_get(url: str = Query(...)):
    return await asyncio.to_thread(run_engine, url)

@app.post("/bypass")
async def bypass_post(request: Request):
    try:
        data = await request.json()
        url = data.get("url")
        if not url:
            return JSONResponse(status_code=400, content={"key": None, "error": "Missing url parameter"})
        return await asyncio.to_thread(run_engine, url)
    except Exception as e:
        return JSONResponse(status_code=400, content={"key": None, "error": str(e)})
