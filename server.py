import time
import json
import hashlib
import threading
import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI
import uvicorn

from main import solve_chain
from auth_client import extract_ticket, MIN_TICKET_LEN

app = FastAPI(title="Delta Cardkey")
executor = ThreadPoolExecutor(max_workers=10)
lock = threading.Lock()
CACHE_TTL = 24 * 3600
key_cache = {}

def cache_get(ticket):
    h = hashlib.md5(ticket.encode()).hexdigest()
    with lock:
        rec = key_cache.get(h)
        if rec and time.time() - rec.get("ts", 0) < CACHE_TTL:
            return rec.get("key")
    return None

def cache_put(ticket, key):
    if not key: return
    h = hashlib.md5(ticket.encode()).hexdigest()
    with lock:
        key_cache[h] = {"key": key, "ts": time.time()}

def solo_pass(ticket):
    try:
        key, timer = solve_chain(ticket, False, 3)
        return key, None
    except Exception as e:
        return None, f"内部代码异常: {type(e).__name__} - {str(e)}"

@app.get("/delta")
async def delta(url: str):
    t0 = time.time()
    try:
        ticket = extract_ticket(url)
    except Exception:
        return {"key": None, "error": "无效链接(未提取到d参数)", "times": f"{round(time.time()-t0, 2)}s"}

    if len(ticket) < MIN_TICKET_LEN:
        return {"key": None, "error": "无效链接(长度不足)", "times": f"{round(time.time()-t0, 2)}s"}

    cached = cache_get(ticket)
    if cached:
        return {"key": cached, "cached": True, "error": None, "times": f"{round(time.time()-t0, 2)}s"}

    loop = asyncio.get_running_loop()
    key, err = await loop.run_in_executor(executor, solo_pass, ticket)
    
    if key:
        cache_put(ticket, key)
        
    # 统一返回格式，拦截所有报错，保证前端不崩溃
    return {
        "key": key, 
        "cached": False,
        "error": err,
        "times": f"{round(time.time()-t0, 2)}s"
    }

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
