import json
import time
import re
import websocket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import secrets
import requests
from requests.exceptions import ProxyError, ConnectTimeout, Timeout

PROXY_HOST = "global.lycheeip.com"
PROXY_PORT = 10000
PROXY_USER = "PR3QPWg8NP6-zone-custom-region-US-st-WestVirginia"
PROXY_PASS = "2c39c20068fb"

PROXY_URL = f"http://{PROXY_USER}:{PROXY_PASS}@{PROXY_HOST}:{PROXY_PORT}"

USE_PROXY = True

def solve_lootlabs_core(link: str):
    start_t = time.time()
    
    proxies = {
        "http": PROXY_URL,
        "https": PROXY_URL
    } if USE_PROXY else None
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }

    try:
        session = requests.Session()
        session.headers.update(headers)
        if proxies:
            session.proxies.update(proxies)
        
        try:
            session.get("https://lootlabs.gg/", timeout=10)
        except Exception:
            pass
            
        res = session.get(link, timeout=15, allow_redirects=True)
        
        if res.status_code == 204:
            time.sleep(1.5)
            headers["Sec-Fetch-Site"] = "same-origin"
            headers["Referer"] = "https://lootlabs.gg/"
            session.headers.update(headers)
            res = session.get(link, timeout=15, allow_redirects=True)
            
        if res.status_code != 200:
            return {
                "ok": False, 
                "error": f"HTTP_{res.status_code}", 
                "message": f"Headers: {dict(res.headers)}",
                "elapsed": round(time.time() - start_t, 2)
            }

        html = res.text
        
        direct_matches = re.findall(r'https?://(?!lootlabs|auth\.platorelay)[^\s"\'<>\\]+', html)
        if direct_matches:
            for url in direct_matches:
                if not any(url.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.svg']):
                    return {"ok": True, "key": url, "elapsed": round(time.time() - start_t, 2)}

        ws_url_match = re.search(r'wss://[^\s"\'<>]+', html)
        if not ws_url_match:
            return {"ok": False, "error": "LOOTLABS_PARSE_FAILED", "message": "No WS or link", "elapsed": 0}
            
        ws_url = ws_url_match.group(0).replace('\\/', '/')
        
        key_match = re.search(r'[a-fA-F0-9]{32}', html)
        if key_match:
            aes_key = bytes.fromhex(key_match.group(0))
        else:
            STATIC_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
            aes_key = STATIC_KEY + STATIC_KEY

        ws_headers = [
            "Origin: https://lootlabs.gg",
            f"User-Agent: {headers['User-Agent']}"
        ]
        
        ws_kwargs = {
            "timeout": 10,
            "header": ws_headers
        }
        
        if USE_PROXY:
            ws_kwargs.update({
                "http_proxy_host": PROXY_HOST,
                "http_proxy_port": PROXY_PORT,
                "http_proxy_auth": (PROXY_USER, PROXY_PASS)
            })

        ws = websocket.create_connection(ws_url, **ws_kwargs)
        
        try:
            botd_data = json.dumps({
                "botd": "spoofed",
                "timestamp": int(time.time() * 1000),
                "fingerprint": "Chrome124_Windows_1920x1080"
            }).encode('utf-8')
            
            aes_iv = secrets.token_bytes(12)
            aesgcm = AESGCM(aes_key)
            ciphertext = aesgcm.encrypt(aes_iv, botd_data, None)
            encrypted_payload = base64.b64encode(aes_iv + ciphertext).decode('utf-8')
            
            payload = json.dumps({
                "type": "verify",
                "payload": encrypted_payload
            })
            
            ws.send(payload)
            result = ws.recv()
            ws.close()
            
            data = json.loads(result)
            if "url" in data:
                return {"ok": True, "key": data["url"], "elapsed": round(time.time() - start_t, 2)}
            elif "destination" in data:
                 return {"ok": True, "key": data["destination"], "elapsed": round(time.time() - start_t, 2)}
            else:
                return {"ok": False, "error": "WS_REJECTED", "message": str(result), "elapsed": 0}
                 
        except Exception as inner_e:
            try: ws.close()
            except: pass
            return {"ok": False, "error": "LOOTLABS_WS_EXCEPTION", "message": str(inner_e), "elapsed": 0}

    except (ProxyError, ConnectTimeout, Timeout) as pe:
        return {
            "ok": False,
            "error": "PROXY_FAILED",
            "message": f"代理连接失败，请检查代理IP或额度: {str(pe)}",
            "elapsed": round(time.time() - start_t, 2)
        }
    except Exception as e:
        return {"ok": False, "error": "LOOTLABS_NETWORK_ERR", "message": str(e), "elapsed": round(time.time() - start_t, 2)}
