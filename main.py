import time
import json
import urllib.parse
import urllib.request
import urllib.error
from fastapi import FastAPI, Query
from playwright.sync_api import sync_playwright

app = FastAPI()

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

def get_token(headless=True, timeout=60000):
    try:
        with sync_playwright() as p:
            b = p.chromium.launch(headless=headless, timeout=timeout, args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-networking",
            ])
            ctx = b.new_context(
                user_agent=UA,
                viewport={"width": 390, "height": 844},
                device_scale_factor=3,
                has_touch=True,
                is_mobile=True,
                locale="en-US",
                timezone_id="Asia/Shanghai",
            )
            ctx.add_init_script(
                "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
                "Object.defineProperty(navigator,'maxTouchPoints',{get:()=>5});"
            )
            pg = ctx.new_page()
            pg.goto(SITE, wait_until="domcontentloaded", timeout=timeout)
            pg.wait_for_timeout(1500)
            tok = pg.evaluate(JS_RENDER)
            b.close()
        tok = str(tok or "")
        if not tok or tok.startswith("ERR:"):
            return None
        return tok
    except Exception as e:
        print("Playwright Error:", str(e))
        return None

def bypass_captcha(url, token, timeout=45):
    body = json.dumps({"url": url, "captchaToken": token}).encode()
    req = urllib.request.Request(SITE + "/api/bypass", data=body, headers=HDRS, method="POST")
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"success": True, "data": json.loads(r.read()), "cost": round(time.time() - t0, 2)}
    except urllib.error.HTTPError as e:
        return {"success": False, "error": e.read().decode("utf-8", "ignore")[:400], "cost": round(time.time() - t0, 2)}
    except Exception as e:
        return {"success": False, "error": str(e), "cost": round(time.time() - t0, 2)}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/delta")
def delta(url: str = Query(...)):
    # 1. 启动浏览器获取 Token
    token = get_token()
    if not token:
        return {"key": None, "error": "Playwright获取Token失败(可能被风控)", "source": "izen"}
    
    # 2. 带着 Token 请求 izen 的破解接口
    res = bypass_captcha(url, token)
    if not res.get("success"):
        return {"key": None, "error": res.get("error"), "source": "izen"}
    
    # 3. 解析返回的数据
    data = res.get("data", {})
    if data.get("success") and data.get("key"):
        return {"key": data["key"], "error": None, "source": "izen"}
    else:
        return {"key": None, "error": data.get("error", "izen解析失败"), "source": "izen"}
