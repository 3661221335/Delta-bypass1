from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
import base64
import json
import re
import secrets
import time
import asyncio
from urllib.parse import unquote
from curl_cffi import requests
import os
import uvicorn

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

def redeem_oauth(d: str):
    secret = gen_secret()
    payload = json.dumps({"ticket": d, "secret": secret})
    headers = {
        "Content-Type": "application/json",
        "Origin": ORIGIN,
        "Referer": f"{ORIGIN}/a?d={d}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "application/json",
    }

    try:
        res = requests.post(START_URL, data=payload, headers=headers, timeout=15, impersonate="chrome124")
        
        if "does not require account verification" in res.text:
            return {"ok": False, "error": "NEED_THIRD_PARTY", "msg": "无需账号验证，尝试暴力破解"}
            
        if res.status_code == 429:
            return {"ok": False, "error": "THROTTLE", "msg": "请求过于频繁"}
            
        data = res.json()
        if data.get("success") and data.get("data", {}).get("flow"):
            flow = data["data"]["flow"]
            url = data["data"].get("url") or f"{ORIGIN}/api/session/google/authorize?state={flow}"
            return {"ok": True, "key": url, "flow": flow}
        
        return {"ok": False, "error": "OAUTH_FAILED", "msg": data.get("message") or data.get("error") or "未知错误"}
        
    except Exception as e:
        return {"ok": False, "error": "NETWORK", "msg": str(e)}

def bypass_vip(url: str):
    try:
        res = requests.post(
            'https://api.bypass.vip/bypass', 
            json={'url': url}, 
            timeout=20, 
            impersonate="chrome124"
        )
        if res.status_code == 200:
            data = res.json()
            if data.get('destination'):
                return {"ok": True, "key": data['destination']}
    except Exception:
        pass
    return {"ok": False, "error": "BYPASS_FAILED", "msg": "第三方接口解密失败"}

def run_engine(url: str):
    start_t = time.time()
    d = extract_d(url)
    if not d:
        return {"key": None, "error": "无法从链接中解析出 d 参数", "elapsed": 0}
        
    result = redeem_oauth(d)
    
    if result["ok"]:
        return {
            "key": result["key"],
            "flow": result["flow"],
            "error": None, 
            "elapsed": round(time.time() - start_t, 2)
        }
    
    if result.get("error") in ("NEED_THIRD_PARTY", "OAUTH_FAILED"):
        fallback = bypass_vip(url)
        if fallback["ok"]:
            return {
                "key": fallback["key"],
                "flow": None,
                "error": None, 
                "elapsed": round(time.time() - start_t, 2)
            }
        return {
            "key": None, 
            "error": fallback["msg"], 
            "elapsed": round(time.time() - start_t, 2)
        }
        
    return {
        "key": None, 
        "error": result.get("msg", "解卡异常"), 
        "elapsed": round(time.time() - start_t, 2)
    }

@app.get("/")
def health_check():
    return {"status": "ok", "engine": "running"}

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

if __name__ == "__main__":
    port = int(os.getenv("PORT", 3000))
    uvicorn.run(app, host="0.0.0.0", port=port)
