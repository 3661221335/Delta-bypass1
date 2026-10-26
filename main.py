import os, re, json, time, base64, hashlib, ssl, random, urllib.request, urllib.parse, urllib.error
from fastapi import FastAPI, Query
from pydantic import BaseModel
from typing import List
from playwright.sync_api import sync_playwright

HOST = "https://auth.platorelay.com"
UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
SSLCTX = ssl.create_default_context()
SSLCTX.check_hostname = False
SSLCTX.verify_mode = ssl.CERT_NONE
POOL = os.environ.get("KEY_POOL", "/tmp/keys_pool.jsonl")

SCREENS = ["390x844", "393x852", "428x926", "430x932"]
CORES = [4, 6]
LANGS = ["zh-CN", "zh-Hans-CN", "en-US"]
TZS = ["Asia/Shanghai", "Asia/Hong_Kong", "Asia/Taipei"]
CODECS = ["webgl2:ok", "webgl2:mali-g78", "webgl2:apple-gpu", "webgl1:ok"]

def get_latest_version():
    try:
        req = urllib.request.Request(HOST, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=10, context=SSLCTX) as r:
            html = r.read().decode("utf-8", "ignore")
            m = re.search(r'v?(\d+\.\d+\.\d+)', html)
            if m: return m.group(1)
    except Exception:
        pass
    return "8.2.4"

def http(method, url, data=None, timeout=25):
    h = {
        "User-Agent": UA,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Client-Name": "platoboost webclient",
        "X-Client-Version": get_latest_version(),
        "Origin": "https://auth.platorelay.com",
        "Referer": "https://auth.platorelay.com/"
    }
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSLCTX) as r:
            return r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", "ignore")
    except Exception as e:
        return json.dumps({"success": False, "message": "net:%s" % e})

def jload(txt):
    try: return json.loads(txt)
    except Exception: return {"raw": (txt or "")[:300]}

SBOX = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")

def _xt(a):
    a <<= 1
    return (a ^ 0x11b) & 0xff if a & 0x100 else a

def _expand(key):
    nk, nr = 4, 10
    w = [list(key[i * 4:i * 4 + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xt(rcon)
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w

def _enc(block, w):
    s = [block[i] ^ w[i // 4][i % 4] for i in range(16)]
    for r in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]
        if r != 10:
            n = []
            for c in range(4):
                a = s[c * 4:c * 4 + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                n += [a[i] ^ t ^ _xt(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            s = n
        s = [s[i] ^ w[r * 4 + i // 4][i % 4] for i in range(16)]
    return bytes(s)

def ctr_hex(plain, ticket, off):
    kb = ticket[off:off + 16].encode()
    iv = bytearray(ticket[off + 16:off + 32].encode())
    w = _expand(kb)
    data = plain.encode()
    out = bytearray()
    for i in range(0, len(data), 16):
        ks = _enc(bytes(iv), w)
        for j, b in enumerate(data[i:i + 16]): out.append(b ^ ks[j])
        for j in range(15, -1, -1):
            iv[j] = (iv[j] + 1) & 0xff
            if iv[j]: break
    return out.hex()

def build_meta(ticket, fp=None):
    fp = fp or {}
    info = {"ua": UA, "screen": fp.get("screen") or random.choice(SCREENS), "touch": True, "lang": fp.get("lang") or random.choice(LANGS), "tz": fp.get("tz") or random.choice(TZS), "hardwareConcurrency": fp.get("cores") or random.choice(CORES)}
    return ctr_hex(json.dumps({"browserInfo": [info]}, separators=(",", ":")), ticket, 0)

def build_stream(ticket, fp=None):
    fp = fp or {}
    now = int(time.time() * 1000)
    w, h = (fp.get("screen") or random.choice(SCREENS)).split("x")
    cx, cy = int(w) // 2 + random.randint(-24, 24), int(h) // 2 + random.randint(-40, 40)
    events = [
        {"t": now - random.randint(3200, 4200), "type": "pointerdown", "x": cx, "y": cy},
        {"t": now - random.randint(2900, 3100), "type": "pointerup", "x": cx, "y": cy},
        {"t": now - random.randint(1800, 2400), "type": "pointerdown", "x": cx + random.randint(-8, 8), "y": cy + random.randint(-8, 8)},
        {"t": now - random.randint(1500, 1750), "type": "pointerup", "x": cx + random.randint(-8, 8), "y": cy + random.randint(-8, 8)},
        {"t": now - random.randint(700, 1100), "type": "checkpoint", "id": random.randint(1, 3)},
    ]
    payload = {"events": events, "codecProof": fp.get("codec") or random.choice(CODECS)}
    return ctr_hex(json.dumps(payload, separators=(",", ":")), ticket, 1)

def pick_d(url):
    try:
        r = urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("r", [""])[0]
        if not r: return None
        raw = base64.urlsafe_b64decode(r + "=" * (-len(r) % 4)).decode("utf-8", "ignore")
        m = re.search(r"[?&]d=([A-Za-z0-9_\-]+)", raw)
        return m.group(1) if m else None
    except Exception: return None

def get_turnstile_token(log):
    log("启动 Playwright 完全自研提取 Token...")
    token = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False, args=[
                "--no-sandbox", 
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--window-size=1920,1080"
            ])
            context = browser.new_context(user_agent=UA)
            page = context.new_page()
            
            html_content = """
            <!DOCTYPE html>
            <html>
            <head><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script></head>
            <body><div class="cf-turnstile" data-sitekey="0x4AAAAAAFT_fRNIBSxl5V8M"></div></body>
            </html>
            """
            page.set_content(html_content, timeout=60000)
            log("本地页面已生成，等待 Turnstile...")
            
            for _ in range(25):
                token = page.evaluate('document.querySelector(\'[name="cf-turnstile-response"]\')?.value')
                if token and len(token) > 20:
                    log(f"成功抓取到 Token（长度 {len(token)}）")
                    break
                time.sleep(1)
            
            if not token:
                content = page.content()
                if "Cloudflare" in content or "Just a moment" in content:
                    log("报错：被 Cloudflare 拦截，机房 IP 风控")
                else:
                    log("报错：验证码组件未加载")
            
            browser.close()
    except Exception as e:
        log(f"自动抓取异常: {e}")
    return token

class Session:
    def __init__(self, sid=None):
        self.sid = sid or (hashlib.md5(os.urandom(16)).hexdigest()[:8] + "%x" % int(time.time()))
        self.fp = {"screen": random.choice(SCREENS), "lang": random.choice(LANGS), "tz": random.choice(TZS), "cores": random.choice(CORES), "codec": random.choice(CODECS)}
    def call(self, method, path, body=None):
        return jload(http(method, HOST + path, body))
    def step(self, ticket, captcha_token=None):
        return self.call("PUT", "/api/session/step?ticket=%s&service=1" % ticket, {
            "captcha": captcha_token, 
            "meta": build_meta(ticket, self.fp), 
            "stream": build_stream(ticket, self.fp), 
            "resolved": True
        })
    def status(self, ticket): return self.call("GET", "/api/session/status?ticket=%s" % ticket)

def reject(js):
    if isinstance(js, dict) and js.get("success") is True: return None
    raw = json.dumps(js, ensure_ascii=False) if isinstance(js, dict) else str(js)
    if re.search(r"exp\D*claim|expired|jwt", raw, re.I): return {"tag": "expired", "msg": "链接已过期", "soft": False}
    if re.search(r"account-unlock-required", raw, re.I): return {"tag": "need_verify", "msg": "要求账号验证", "soft": True, "unlock": True}
    if re.search(r"invalid link", raw, re.I): return {"tag": "invalid_link", "msg": "链接不完整", "soft": False}
    if re.search(r"a key for this identifier already exists", raw, re.I): return {"tag": "already_issued", "msg": "已签发过", "soft": True}
    return {"tag": "unknown", "msg": raw[:160], "soft": True}

def solves(s, link, max_wait=180, log=lambda m: None, turnstile_token=None):
    m = re.search(r"[?&]d=([A-Za-z0-9_\-]+)", link or "")
    ticket = m.group(1) if m else (link or "").strip()
    out = {"success": False, "ticket": ticket, "key": None, "minutes_left": 0, "stage": "init", "message": "", "log": []}
    def L(msg):
        out["log"].append("[%6.2fs] %s" % (time.time() - t0, msg))
        log(msg)
    t0 = time.time()
    if not ticket: out.update(stage="bad_input", message="未找到 d="); return out

    if not turnstile_token:
        token = get_turnstile_token(L)
        if token:
            turnstile_token = token
        else:
            out.update(stage="need_turnstile", message="自动获取 Token 失败")
            return out

    js = s.step(ticket, turnstile_token)
    L("直连官方 Step -> %s" % json.dumps(js, ensure_ascii=False)[:200])
    rj = reject(js)
    
    if rj and rj.get("tag") == "need_verify":
        out["stage"] = "account_unlock_required"
        out["message"] = "官方要求账号验证"
        return out
    if rj and not rj.get("soft"):
        out.update(stage=rj["tag"], message=rj["msg"])
        return out

    url = (js.get("data") or {}).get("url") if isinstance(js.get("data"), dict) else None
    if js.get("success") and url and url != "about:blank":
        nd = pick_d(url)
        if nd: 
            ticket = nd
            out["ticket"] = ticket
            time.sleep(3)

    key = None
    deadline = time.time() + max_wait
    while time.time() < deadline:
        st = s.status(ticket)
        L("直连官方 Status -> %s" % json.dumps(st, ensure_ascii=False)[:200])
        k = (st.get("data") or {}).get("key") if isinstance(st.get("data"), dict) else None
        if k and k != "KEY_NOT_FOUND": key = k; break
        time.sleep(1.2)

    if not key:
        out.update(stage="not_issued", message="未签发卡密")
        return out
        
    out["key"] = key
    out["stage"] = "issued"
    out["success"] = True
    out["message"] = "解卡成功"
    return out

app = FastAPI()

@app.get("/health")
def health_check(): return {"status": "ok"}

@app.get("/delta")
def delta(url: str = Query(...), token: str = Query(None)):
    try:
        s = Session()
        data = solves(s, url, max_wait=180, turnstile_token=token)
        return data
    except Exception as e:
        return {"key": None, "error": "exception", "message": str(e)}
