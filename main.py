import time
import json
import requests
from requests.adapters import HTTPAdapter
from auth_client import extract_ticket, parse_new_ticket, MIN_TICKET_LEN, build_meta_payload, build_stream_payload

_session = None

def get_session():
    global _session
    if _session is None:
        s = requests.Session()
        adapter = HTTPAdapter(pool_connections=50, pool_maxsize=50)
        s.mount('http://', adapter)
        s.mount('https://', adapter)
        _session = s
    return _session

class Timer:
    def __init__(self):
        self.t0 = time.time()
    def total(self):
        return time.time() - self.t0

# 自动获取官方最新版本号
def get_latest_version():
    try:
        r = requests.get("https://auth.platorelay.com", timeout=5)
        import re
        m = re.search(r'(\d+\.\d+\.\d+)', r.text)
        if m: return m.group(1)
    except Exception:
        pass
    return "8.2.1"

def solve_chain(ticket, use_proxy=False, max_retries=3):
    timer = Timer()
    if not ticket or len(ticket) < MIN_TICKET_LEN:
        return None, timer

    session = get_session()
    version = get_latest_version()
    step_url = f"https://auth.platorelay.com/api/session/step?ticket={ticket}&service=1"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Client-Name": "platoboost webclient",
        "X-Client-Version": version
    }

    try:
        meta = build_meta_payload(ticket, 0)
        stream = build_stream_payload(ticket, 1)
        
        payload = {
            "captcha": None,  # 最新逻辑：直接给 null
            "meta": meta,
            "stream": stream,
            "resolved": True
        }

        r = session.put(step_url, json=payload, headers=headers, timeout=15)
        res_json = r.json()

        if not res_json.get("success"):
            msg = str(res_json.get("message", ""))
            if "expired" in msg: return "链接已过期", timer
            if "invalid payload" in msg: return "官方风控(无效载荷)", timer
            if "account-unlock-required" in msg: return "要求账号验证(风控)", timer
            return f"Step失败: {msg}", timer

        data = res_json.get("data") or {}
        new_url = data.get("url")
        if new_url and new_url != "about:blank":
            nd = parse_new_ticket(new_url)
            if nd: ticket = nd
        
        status_url = f"https://auth.platorelay.com/api/session/status?ticket={ticket}"
        last_status = None
        
        for _ in range(15):
            time.sleep(1.2)
            sr = session.get(status_url, headers=headers, timeout=10)
            sres = sr.json()
            last_status = sres
            
            key = (sres.get("data") or {}).get("key")
            if key and key != "KEY_NOT_FOUND":
                return key, timer
            
            if "expired" in str(sres):
                return "链接已过期", timer

        return "超时未签发(风控黑洞)", timer

    except Exception as e:
        return f"网络异常: {type(e).__name__}", timer
