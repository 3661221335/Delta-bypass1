import time
import json
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, Query
from playwright.sync_api import sync_playwright
import asyncio

app = FastAPI()
executor = ThreadPoolExecutor(max_workers=2) # 限制并发，防止内存爆炸

SITE = "https://izen.lol"
SITEKEY = "0x4AAAAAADNEi_2N24gpQqY0"
UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
      "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")
HDRS = {
    "Content-Type": "application/json",
    "Origin": SITE,
    "Referer": SITE + "/",
    "User-Agent": UA,
}

JS_RENDER = """
async () => {
  await new Promise(res => {
    if (window.turnstile) return res();
    const s = document.createElement('script');
    s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    s.onload = res;
    document.head.appendChild(s);
  });
  const d = document.createElement('div');
  d.id = 'tsbox';
  document.body.appendChild(d);
  return await new Promise(res => {
    turnstile.render('#tsbox', {
      sitekey: '%s',
      callback: t => res(t),
      'error-callback': e => res('ERR:' + e)
    });
  });
}
""" % SITEKEY

def get_token_sync():
    try:
        with sync_playwright() as p:
            # 使用无头模式，并添加节省内存的参数
            b = p.chromium.launch(headless=True, args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-software-rasterizer",
                "--disable-extensions"
            ])
            ctx = b.new_context(
                user_agent=UA,
                viewport={"width": 390, "height": 844},
                device_scale_factor=3,
                has_touch=True,
                is_mobile=True,
            )
            pg = ctx.new_page()
            pg.goto(SITE, wait_until="domcontentloaded", timeout=20000)
            pg.wait_for_timeout(1000)
            tok = pg.evaluate(JS_RENDER)
            b.close()
            
            tok = str(tok or "")
            if tok.startswith("ERR:"):
                return None
            return tok
    except Exception as e:
        print("Playwright 内部报错:", str(e))
        return None

def bypass_captcha_sync(url, token):
    body = json.dumps({"url": url, "captchaToken": token}).encode()
    req = urllib.request.Request(SITE + "/api/bypass", data=body, headers=HDRS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return {"success": True, "data": json.loads(r.read())}
    except urllib.error.HTTPError as e:
        return {"success": False, "error": e.read().decode("utf-8", "ignore")[:200]}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/delta")
async def delta(url: str = Query(...)):
    loop = asyncio.get_running_loop()
    
    # 1. 在线程池里跑 Playwright，绝对不卡死主程序
    token = await loop.run_in_executor(executor, get_token_sync)
    
    if not token:
        return {"key": None, "error": "获取Token失败(IP被CF拦截或内存溢出)", "source": "izen"}
    
    # 2. 在线程池里请求 izen 接口
    res = await loop.run_in_executor(executor, bypass_captcha_sync, url, token)
    
    if not res.get("success"):
        return {"key": None, "error": res.get("error"), "source": "izen"}
    
    data = res.get("data", {})
    if data.get("success") and data.get("key"):
        return {"key": data["key"], "error": None, "source": "izen"}
    else:
        return {"key": None, "error": data.get("error", "izen解析失败"), "source": "izen"}
