#!/usr/bin/env python3
import os, re, json, time, base64, hashlib, ssl, urllib.request, urllib.parse, urllib.error
from fastapi import FastAPI, Query
from pydantic import BaseModel
from typing import List

SITE = "https://ninjak.dpdns.org"
HOST = "https://auth.platorelay.com"
UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
HDRS = {"Accept": "application/json", "Content-Type": "application/json",
        "X-Client-Name": "platoboost webclient", "X-Client-Version": "8.2.1"}
SSLCTX = ssl.create_default_context()
SSLCTX.check_hostname = False
SSLCTX.verify_mode = ssl.CERT_NONE
GAP_MIN, GAP_MAX = 1.0, 30.0
COOLTOO_FAST = "you are finishing checkpoints too fast"
POOL = os.environ.get("KEY_POOL", "/tmp/keys_pool.jsonl")


def http(method, url, data=None, headers=None, timeout=25, form=False):
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
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
    try:
        return json.loads(txt)
    except Exception:
        return {"raw": (txt or "")[:300]}


SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")


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
        for j, b in enumerate(data[i:i + 16]):
            out.append(b ^ ks[j])
        for j in range(15, -1, -1):
            iv[j] = (iv[j] + 1) & 0xff
            if iv[j]:
                break
    return out.hex()


def pick_d(url):
    try:
        r = urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("r", [""])[0]
        if not r:
            return None
        raw = base64.urlsafe_b64decode(r + "=" * (-len(r) % 4)).decode("utf-8", "ignore")
        m = re.search(r"[?&]d=([A-Za-z0-9_\-]+)", raw)
        return m.group(1) if m else None
    except Exception:
        return None


class Session:
    def __init__(self, sid=None):
        self.sid = sid or (hashlib.md5(os.urandom(16)).hexdigest()[:8] + "%x" % int(time.time()))

    def ts_config(self):
        return jload(http("GET", SITE + "/ts.php?t=%d" % int(time.time() * 1000),
                          headers={"Referer": SITE + "/"}))

    def gate(self):
        return jload(http("GET", SITE + "/stats.php?act=gate&sid=" + urllib.parse.quote(self.sid),
                          headers={"Referer": SITE + "/"}))

    def ts_verify(self, token):
        return jload(http("GET", SITE + "/stats.php?act=ts&token=" + urllib.parse.quote(token) +
                          "&sid=" + urllib.parse.quote(self.sid), headers={"Referer": SITE + "/"}))

    def helpreq(self, ft, sig):
        return jload(http("GET", SITE + "/stats.php?act=helpreq&sid=" + urllib.parse.quote(self.sid) +
                          "&ft=" + urllib.parse.quote(ft) + "&sig=" + urllib.parse.quote(sig),
                          headers={"Referer": SITE + "/"}))

    def claim(self, key, ct, ft=""):
        return jload(http("GET", SITE + "/stats.php?act=claim&key=" + urllib.parse.quote(key) +
                          "&sid=" + urllib.parse.quote(self.sid) + "&ct=" + urllib.parse.quote(ct) +
                          ("&ft=" + urllib.parse.quote(ft) if ft else ""), headers={"Referer": SITE + "/"}))

    def call(self, method, path, body=None, use_proxy=False):
        if use_proxy:
            txt = http("POST", SITE + "/proxy.php",
                       {"method": method, "path": path, "body": body},
                       headers={"Referer": SITE + "/", "Origin": SITE})
            return jload(txt)
        txt = http(method, HOST + path, None if body is None else body, headers=HDRS)
        return jload(txt)

    def step(self, ticket, use_proxy=False):
        return self.call("PUT", "/api/session/step?ticket=%s&service=1" % ticket,
                         {"captcha": None,
                          "meta": ctr_hex('{"browserInfo":[]}', ticket, 0),
                          "stream": ctr_hex('{"events":[],"codecProof":null}', ticket, 1),
                          "resolved": True}, use_proxy)

    def status(self, ticket, use_proxy=False):
        return self.call("GET", "/api/session/status?ticket=%s" % ticket, None, use_proxy)

    def metadata(self, ticket, use_proxy=False):
        return self.call("GET", "/api/session/metadata?ticket=%s" % ticket, None, use_proxy)


def reject(js):
    if isinstance(js, dict) and js.get("success") is True:
        return None
    raw = ""
    if isinstance(js, dict):
        raw = " ".join(str(js.get(k)) for k in ("message", "error", "error_description", "code", "type") if js.get(k))
        raw = raw or json.dumps(js, ensure_ascii=False)
    else:
        raw = str(js)
    m = js.get("message", "") if isinstance(js, dict) else ""
    if re.search(r"exp\D*claim|expired|jwt", raw, re.I):
        return {"tag": "expired", "msg": "链接已过期，需重新取链接", "soft": False}
    if re.search(r"account-unlock-required", raw, re.I):
        return {"tag": "need_verify", "msg": "平台按出口 IP 要求账号验证", "soft": True, "unlock": True}
    if re.search(r"invalid link", raw, re.I):
        return {"tag": "invalid_link", "msg": "链接不完整", "soft": False}
    if re.search(r"a key for this identifier already exists", raw, re.I):
        return {"tag": "already_issued", "msg": "该标识已签发过卡密", "soft": True}
    if re.search(r"invalid payload|unable to process", raw, re.I):
        return {"tag": "invalid_payload", "msg": m or "服务端未接受 payload", "soft": True}
    if re.search(r"page not found", raw, re.I):
        return {"tag": "api_changed", "msg": "接口已变更", "soft": False}
    return {"tag": "unknown", "msg": m or raw[:160], "soft": True}


def probe_gap(s, ticket, use_proxy, log):
    g = GAP_MIN
    round_ = 0
    while g <= GAP_MAX + 1e-9:
        round_ += 1
        deadline = time.time() + g
        while time.time() < deadline:
            time.sleep(min(0.05, max(0, deadline - time.time())))
        js = s.step(ticket, use_proxy)
        raw = json.dumps(js, ensure_ascii=False)
        if "rate-limited" in raw or "rate limit" in raw:
            log("gap %.1fs 命中限流，退避 3s" % g)
            time.sleep(3)
            continue
        if COOLTOO_FAST in raw:
            g = round(g + 0.1, 1)
            continue
        log("gap %.1fs 通过（第 %d 次）" % (g, round_))
        return js
    log("扫到 %.1fs 仍未通过" % GAP_MAX)
    return None


def store_key(key, mins=0):
    try:
        with open(POOL, "a", encoding="utf-8") as f:
            f.write(json.dumps({"t": int(time.time()), "key": key, "minutes_left": mins}, ensure_ascii=False) + "\n")
    except Exception:
        pass


def solves(s, link, use_proxy=False, max_wait=180, log=lambda m: None, turnstile_token=None):
    m = re.search(r"[?&]d=([A-Za-z0-9_\-]+)", link or "")
    ticket = m.group(1) if m else (link or "").strip()
    out = {"success": False, "ticket": ticket, "key": None, "minutes_left": 0,
           "proxy": use_proxy, "stage": "init", "message": "", "log": []}

    def L(msg):
        out["log"].append("[%6.2fs] %s" % (time.time() - t0, msg))
        log(msg)

    t0 = time.time()
    if not ticket:
        out.update(stage="bad_input", message="链接里没有找到 d= 票据")
        return out
    L("票据长度 %d" % len(ticket))

    cfg = s.ts_config()
    ts_on = bool(cfg.get("enabled"))
    L("站点人机验证 %s sitekey=%s" % ("开启" if ts_on else "关闭", cfg.get("sitekey")))
    ct = None
    if ts_on:
        if turnstile_token:
            st = s.ts_verify(turnstile_token)
            L("act=ts -> %s" % json.dumps(st, ensure_ascii=False)[:160])
            if st.get("ok"):
                ct = st.get("claim")
                L("人机验证通过，取到 claim 凭证")
            else:
                out["stage"] = "turnstile_rejected"
                out["message"] = st.get("msg") or json.dumps(st, ensure_ascii=False)
                L("token 未通过 siteverify：%s" % out["message"])
                return out
        else:
            out["stage"] = "collected"
            out["message"] = "无 token，仅采集 key（claim 留到 release）"
            L("无 token：改为只采集卡密，claim 步骤跳过")

    g = s.gate()
    if g.get("allow") is False:
        L("gate 未放行（%s），流程票继续用 ft" % (g.get("msg") or "not verified"))
    ft = g.get("ft") or ""

    md = s.metadata(ticket, use_proxy)
    if md.get("data"):
        L("会话: name=%s duration=%s completed=%s locking=%s" % (
            md["data"].get("name"), md["data"].get("duration"),
            md["data"].get("completed"), md["data"].get("enableLocking")))

    js = s.step(ticket, use_proxy)
    L("PUT#1 -> %s" % json.dumps(js, ensure_ascii=False)[:200])
    rj = reject(js)
    if rj and rj.get("tag") == "need_verify" and not use_proxy:
        h = s.helpreq(ft, "390,844,3,5,4,Apple GPU")
        L("申请同源代理：%s" % json.dumps(h, ensure_ascii=False)[:160])
        if h.get("allow") or h.get("private"):
            use_proxy = True
            out["proxy"] = True
            js = s.step(ticket, use_proxy)
            L("PUT#1(proxy) -> %s" % json.dumps(js, ensure_ascii=False)[:200])
            rj = reject(js)
        else:
            out["stage"] = "ip_flagged"
            out["message"] = h.get("msg") or "出口 IP 被平台标记，代理额度不可用"
            L(out["message"])
            return out
    if rj and not rj.get("soft"):
        out.update(stage=rj["tag"], message=rj["msg"])
        L("硬拒：%s" % rj["msg"])
        return out

    url = (js.get("data") or {}).get("url") if isinstance(js.get("data"), dict) else None
    if js.get("success") and url and url != "about:blank":
        nd = pick_d(url)
        if nd:
            ticket = nd
            out["ticket"] = ticket
            L("服务端下发新会话，进入间隔扫描")
            js = probe_gap(s, ticket, use_proxy, L) or js
    elif COOLTOO_FAST in json.dumps(js, ensure_ascii=False):
        L("首跳撞冷却，转入间隔扫描")
        probe_gap(s, ticket, use_proxy, L)
        js2 = s.step(ticket, use_proxy)
        L("PUT#2 -> %s" % json.dumps(js2, ensure_ascii=False)[:200])
    elif js.get("success") and url == "about:blank":
        L("会话已签发过，直接查卡")

    key = None
    deadline = time.time() + max_wait
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        st = s.status(ticket, use_proxy)
        L("status#%d -> %s" % (attempt, json.dumps(st, ensure_ascii=False)[:200]))
        k = (st.get("data") or {}).get("key") if isinstance(st.get("data"), dict) else None
        out["minutes_left"] = (st.get("data") or {}).get("minutesLeft", 0) if isinstance(st.get("data"), dict) else 0
        if k and k != "KEY_NOT_FOUND":
            key = k
            break
        rj2 = reject(st)
        if rj2 and not rj2.get("soft"):
            out.update(stage=rj2["tag"], message=rj2["msg"])
            return out
        time.sleep(1.2)

    if not key:
        out.update(stage="not_issued", message="平台未签发卡密（该会话已签发过或需稍后重试）")
        return out

    out["key"] = key
    out["stage"] = "issued"
    if ct is None:
        out["success"] = True
        out["message"] = "已取到卡密（未走 claim 校验，可直接使用）"
        L("卡密：" + key)
        store_key(key, out.get("minutes_left", 0))
        return out
    cl = s.claim(key, ct, ft)
    L("claim -> %s" % json.dumps(cl, ensure_ascii=False)[:160])
    if cl.get("ok"):
        out["key"] = cl.get("key") or key
        out["success"] = True
        out["message"] = "卡密已放行"
    else:
        out["stage"] = "claim_blocked"
        out["message"] = cl.get("msg") or "claim 未放行"
        store_key(key, out.get("minutes_left", 0))
    return out


app = FastAPI()


@app.get("/health")
@app.get("/healthz")
@app.get("/")
def health_check():
    return {"status": "ok"}


@app.get("/delta")
def delta(url: str = Query(...)):
    try:
        s = Session()
        data = solves(s, url, max_wait=180)
        if data.get("success"):
            return {"key": data.get("key"), "error": None, "stage": data.get("stage")}
        return {"key": None, "error": data.get("stage"), "message": data.get("message")}
    except Exception as e:
        return {"key": None, "error": "exception", "message": "%s - %s" % (type(e).__name__, e)}


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatMessage]


@app.post("/v1/chat/completions")
def chat_completions(req: ChatCompletionRequest):
    user_text = ""
    for msg in req.messages:
        if msg.role == "user":
            user_text = msg.content
            break

    url_match = re.search(r'https?://[^\s]+', user_text)
    if not url_match:
        content = user_text
    else:
        try:
            s = Session()
            result = solves(s, url_match.group(0), max_wait=180)
            if result.get("success"):
                content = "解卡成功！\nKey: %s" % result.get("key", "")
            else:
                content = "解卡失败：%s - %s" % (result.get("stage"), result.get("message"))
        except Exception as e:
            content = "解卡出错：%s" % str(e)

    return {
        "id": "chatcmpl-001",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
