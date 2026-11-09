import os
import time
import re
import json
import asyncio
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
from playwright.sync_api import sync_playwright

app = FastAPI()

BASE = "https://baconbypass.xyz"
DELTA = re.compile(r"(platorelay|platoboost|pandauth|pandadevelopment)", re.I)
NOISE = re.compile(r"(baconbypass|cloudflare|discord|vsphone|bauval|cloudpiko|show-sb)", re.I)
RESULT = re.compile(r"https?://[^\s\"'<>]+|FREE_[0-9a-f]{20,}", re.I)

def pick(text):
    hits = [h for h in RESULT.findall(text or "") if not NOISE.search(h)]
    return hits[-1] if hits else None

def solve_with_bacon(link):
    start_t = time.time()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=False,  
                args=[
                    "--disable-blink-features=AutomationControlled", 
                    "--no-sandbox", 
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage"
                ]
            )
            ctx = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 800},
                locale="en-US"
            )
            page = ctx.new_page()
            
            page.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            if DELTA.search(link):
                page.goto(f"{BASE}/delta?url={link}", wait_until="domcontentloaded", timeout=60000)
                page.wait_for_selector("#deltaUrl", timeout=60000)
                page.fill("#deltaUrl", link)
                page.click("#deltaBypassBtn")
            else:
                page.goto(BASE, wait_until="domcontentloaded", timeout=60000)
                page.wait_for_selector("#urlInput", timeout=60000)
                page.fill("#urlInput", link)
                page.click("#bypassBtn")
                
            
            page.wait_for_selector("text=Bypass successful", timeout=180000)
            
            body = page.inner_text("body")
            vals = page.eval_on_selector_all("input,textarea", "els => els.map(e => e.value || '')")
            result = pick(body + "\n" + "\n".join(vals))
            
            browser.close()
            
            if result:
                return {"key": result, "elapsed": round(time.time() - start_t, 2)}
            else:
                return {"key": None, "error": "页面成功但未匹配到结果，可能DOM改版了", "elapsed": round(time.time() - start_t, 2)}
                
    except Exception as e:
        return {"key": None, "error": f"BROWSER_ERROR: {str(e)[:100]}", "elapsed": round(time.time() - start_t, 2)}

@app.get("/bypass")
async def bypass_get(url: str = Query(...)):
    return await asyncio.to_thread(solve_with_bacon, url)

@app.post("/bypass")
async def bypass_post(request: Request):
    try:
        data = await request.json()
        url = data.get("url")
        if not url:
            return JSONResponse(status_code=400, content={"key": None, "error": "Missing url parameter"})
        return await asyncio.to_thread(solve_with_bacon, url)
    except Exception as e:
        return JSONResponse(status_code=400, content={"key": None, "error": str(e)})

@app.get("/")
def read_root():
    return {"status": "ok", "engine": "running with xvfb"}
