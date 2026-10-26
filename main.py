import os, re, json, time, base64, hashlib, ssl, random, urllib.request, urllib.parse, urllib.error
from fastapi import FastAPI, Query
from pydantic import BaseModel
from typing import List

EZSOLVER_HOST = "delta-bypass-production-5949.up.railway.app"

SITE = "https://ninjak.dpdns.org"
HOST = "https://auth.platorelay.com"
UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
HDRS = {"Accept": "application/json", "Content-Type": "application/json", "X-Client-Name": "platoboost webclient", "X-Client-Version": "8.2.1"}
SSLCTX = ssl.create_default_context()
SSLCTX.check_hostname = False
SSLCTX.verify_mode = ssl.CERT_NONE
GAP_MIN, GAP_MAX = 3.0, 30.0
COOLTOO_FAST = "you are finishing checkpoints too fast"
POOL = os.environ.get("KEY_POOL", "/tmp/keys_pool.jsonl")

SCREENS = ["390x844", "393x852", "428x926", "430x932"]
CORES = [4, 6]
LANGS = ["zh-CN", "zh-Hans-CN", "en-US"]
TZS = ["Asia/Shanghai", "Asia/Hong_Kong", "Asia/Taipei"]
CODECS = ["webgl2:ok", "webgl2:mali-g78", "webgl2:apple-gpu", "webgl1:ok"]

def http(method, url, data=None, headers=None, timeout=25, form=False):
    h = {"User-Agent": UA}
    if headers: h.update(headers)
    body = None
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        elif isinstance(data, (bytes, str)):
            body = data.encode() if isinstance(data, str) else data
        else:
            body = json.dumps(data).encode()
            h.setdefault("Content-Type", "application/json")
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

SBOX = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16".replace(" ", ""))

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

def get_turnstile_token(log=lambda m: None):
    payload = {"sitekey": "0x4AAAAAAFT_fRNIBSxl5V8M", "url": "https://ninjak.dpdns.org/"}
    for ep in ["/turnstile", "/solve", "/"]:
        try:
            req = urllib.request.Request(f"https://{EZSOLVER_HOST}{ep}", data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
            log(f"正在请求 A号 {EZSOLVER_HOST}{ep} ...")
            with urllib.request.urlopen(req, timeout=90) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                token = result.get("token") or (result.get("solution") or {}).get("token")
                if token:
                    log(f"EzSolver 成功！拿到 token（长度 {len(token)}）")
                    return token, None
        except urllib.error.HTTPError as e:
            if e.code != 404: log(f"请求 {ep} 失败: HTTP {e.code}")
        except Exception as e: log(f"请求 {ep} 出错: {e}")
    log("所有尝试都失败了")
    return None, "request_failed"

class Session:
    def __init__(self, sid=None):
        self.sid = sid or (hashlib.md5(os.urandom(16)).hexdigest()[:8] + "%x" % int(time.time()))
        self.fp = {"screen": random.choice(SCREENS), "lang": random.choice(LANGS), "tz": random.choice(TZS), "cores": random.choice(CORES), "codec": random.choice(CODECS)}
    def fp_sig(self):
        w, h = self.fp["screen"].split("x")
        return "%s,%s,%d,5,%d,Apple GPU" % (w, h, self.fp["cores"], self.fp["cores"])
    def ts_config(self): return jload(http("GET", SITE + "/ts.php?t=%d" % int(time.time() * 1000), headers={"Referer": SITE + "/"}))
    def gate(self): return jload(http("GET", SITE + "/stats.php?act=gate&sid=" + urllib.parse.quote(self.sid), headers={"Referer": SITE + "/"}))
    def ts_verify(self, token): return jload(http("GET", SITE + "/stats.php?act=ts&token=" + urllib.parse.quote(token) + "&sid=" + urllib.parse.quote(self.sid), headers={"Referer": SITE + "/"}))
    def helpreq(self, ft, sig=None):
        if sig is None: sig = self.fp_sig()
        return jload(http("GET", SITE + "/stats.php?act=helpreq&sid=" + urllib.parse.quote(self.sid) + "&ft=" + urllib.parse.quote(ft) + "&sig=" + urllib.parse.quote(sig), headers={"Referer": SITE + "/"}))
    def claim(self, key, ct, ft=""):
        return jload(http("GET", SITE + "/stats.php?act=claim&key=" + urllib.parse.quote(key) + "&sid=" + urllib.parse.quote(self.sid) + "&ct=" + urllib.parse.quote(ct) + ("&ft=" + urllib.parse.quote(ft) if ft else ""), headers={"Referer": SITE + "/"}))
    def call(self, method, path, body=None, use_proxy=False):
        if use_proxy:
            return jload(http("POST", SITE + "/proxy.php", {"method": method, "path": path, "body": body}, headers={"Referer": SITE + "/", "Origin": SITE}))
        return jload(http(method, HOST + path, None if body is None else body, headers=HDRS))
    def step(self, ticket, use_proxy=False):
        return self.call("PUT", "/api/session/step?ticket=%s&service=1" % ticket, {"captcha": None, "meta": build_meta(ticket, self.fp), "stream": build_stream(ticket, self.fp), "resolved": True}, use_proxy)
    def status(self, ticket, use_proxy=False): return self.call("GET", "/api/session/status?ticket=%s" % ticket, None, use_proxy)
    def metadata(self, ticket, use_proxy=False): return self.call("GET", "/api/session/metadata?ticket=%s" % ticket, None, use_proxy)

def reject(js):
    if isinstance(js, dict) and js.get("success") is True: return None
    raw = json.dumps(js, ensure_ascii=False) if isinstance(js, dict) else str(js)
    m = js.get("message", "") if isinstance(js, dict) else ""
    if re.search(r"exp\D*claim|expired|jwt", raw, re.I): return {"tag": "expired", "msg": "链接已过期", "soft": False}
    if re.search(r"account-unlock-required", raw, re.I): return {"tag": "need_verify", "msg": "要求账号验证", "soft": True, "unlock": True}
    if re.search(r"invalid link", raw, re.I): return {"tag": "invalid_link", "msg": "链接不完整", "soft": False}
    if re.search(r"a key for this identifier already exists", raw, re.I): return {"tag": "already_issued", "msg": "已签发过", "soft": True}
    if re.search(r"invalid payload|unable to process", raw, re.I): return {"tag": "invalid_payload", "msg": m or "未接受 payload", "soft": True}
    if re.search(r"page not found", raw, re.I): return {"tag": "api_changed", "msg": "接口已变更", "soft": False}
    return {"tag": "unknown", "msg": m or raw[:160], "soft": True}

def probe_gap(s, ticket, use_proxy, log):
    g = GAP_MIN
    round_ = 0
    while g <= GAP_MAX + 1e-9:
        round_ += 1
        wait = g * random.uniform(0.85, 1.45)
        time.sleep(wait)
        js = s.step(ticket, use_proxy)
        raw = json.dumps(js, ensure_ascii=False)
        if "rate-limited" in raw or "rate limit" in raw: time.sleep(3); continue
        if COOLTOO_FAST in raw: g = round(g + 0.1, 1); continue
        log("wait %.2fs 通过" % wait)
        return js
    return None

def store_key(key, mins=0):
    try:
        with open(POOL, "a", encoding="utf-8") as f: f.write(json.dumps({"t": int(time.time()), "key": key, "minutes_left": mins}, ensure_ascii=False) + "\n")
    except Exception: pass

def try_helpreq(s, ft, log, attempts=3):
    h = {}
    for i in range(attempts):
        h = s.helpreq(ft)
        log("helpreq#%d sid=%s -> %s" % (i + 1, s.sid, json.dumps(h, ensure_ascii=False)))
        if h.get("allow") or h.get("private"): return True, h, s
        if h.get("why") == "need_verify": return False, h, s
        if i < attempts - 1:
            time.sleep(random.uniform(2.0, 3.5))
            s = Session()
    return False, h, s

def solves(s, link, use_proxy=False, max_wait=180, log=lambda m: None, turnstile_token=None, auto_token=False):
    m = re.search(r"[?&]d=([A-Za-z0-9_\-]+)", link or "")
    ticket = m.group(1) if m else (link or "").strip()
    out = {"success": False, "ticket": ticket, "key": None, "minutes_left": 0, "proxy": use_proxy, "stage": "init", "message": "", "log": []}
    def L(msg):
        out["log"].append("[%6.2fs] %s" % (time.time() - t0, msg))
        log(msg)
    t0 = time.time()
    if not ticket: out.update(stage="bad_input", message="未找到 d="); return out
    cfg = s.ts_config()
    ts_on = bool(cfg.get("enabled"))
    ct = None
    if ts_on:
        if not turnstile_token and auto_token:
            tok, err = get_turnstile_token(L)
            if tok: turnstile_token = tok
            else: L("EzSolver 未拿到 token：%s" % err)
        if turnstile_token:
            st = s.ts_verify(turnstile_token)
            if st.get("ok"): ct = st.get("claim")
            else:
                out["stage"] = "turnstile_rejected"
                out["message"] = st.get("msg") or "验签失败"
                return out
        else:
            out["stage"] = "need_turnstile"
            return out
    g = s.gate()
    ft = g.get("ft") or ""
    js = s.step(ticket, use_proxy)
    rj = reject(js)
    if rj and rj.get("tag") == "need_verify" and not use_proxy:
        ok, h, s = try_helpreq(s, ft, log, attempts=3)
        if ok:
            use_proxy = True
            js = s.step(ticket, use_proxy)
            rj = reject(js)
        else:
            out["stage"] = "helpreq_denied"
            out["message"] = json.dumps(h, ensure_ascii=False)
            return out
    if rj and not rj.get("soft"):
        out.update(stage=rj["tag"], message=rj["msg"])
        return out
    url = (js.get("data") or {}).get("url") if isinstance(js.get("data"), dict) else None
    if js.get("success") and url and url != "about:blank":
        nd = pick_d(url)
        if nd: ticket = nd; probe_gap(s, ticket, use_proxy, L)
    key = None
    deadline = time.time() + max_wait
    while time.time() < deadline:
        st = s.status(ticket, use_proxy)
        k = (st.get("data") or {}).get("key") if isinstance(st.get("data"), dict) else None
        if k and k != "KEY_NOT_FOUND": key = k; break
        rj2 = reject(st)
        if rj2 and not rj2.get("soft"): out.update(stage=rj2["tag"]); return out
        time.sleep(1.2)
    if not key:
        out.update(stage="not_issued", message="未签发卡密")
        return out
    out["key"] = key
    out["stage"] = "issued"
    if ct is None:
        out["success"] = True; store_key(key); return out
    cl = s.claim(key, ct, ft)
    if cl.get("ok"):
        out["key"] = cl.get("key") or key
        out["success"] = True
        out["message"] = "已放行"
    else:
        out["stage"] = "claim_blocked"
        out["message"] = cl.get("msg") or "未放行"
        store_key(key)
    return out

app = FastAPI()
@app.get("/health")
def health_check(): return {"status": "ok", "ezsolver": EZSOLVER_HOST}

@app.get("/delta")
def delta(url: str = Query(...), token: str = Query(None)):
    try:
        s = Session()
        data = solves(s, url, max_wait=180, turnstile_token=token, auto_token=True)
        return data
    except Exception as e:
        return {"key": None, "error": "exception", "message": str(e)}
