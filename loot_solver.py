import json
import time
import re
import websocket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import secrets
import requests

def solve_lootlabs_core(link: str):
    start_t = time.time()
    try:
        session = requests.Session()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        }
        session.headers.update(headers)
        
        res = session.get(link, timeout=15)
        if res.status_code != 200:
            return {"ok": False, "error": f"HTTP_{res.status_code}", "message": "Session request blocked"}

        html = res.text
        
        direct_matches = re.findall(r'https?://(?!lootlabs|auth\.platorelay)[^\s"\'<>\\]+', html)
        if direct_matches:
            for url in direct_matches:
                if not any(url.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.svg']):
                    return {"ok": True, "key": url, "elapsed": round(time.time() - start_t, 2)}

        ws_url_match = re.search(r'wss://[^\s"\'<>]+', html)
        if not ws_url_match:
            return {"ok": False, "error": "PARSE_FAILED", "message": "No WebSocket URL found"}
        
        ws_url = ws_url_match.group(0).replace('\\/', '/')
        ws = websocket.create_connection(ws_url, timeout=10, header=["Origin: https://lootlabs.gg"])
        
        try:
            botd_payload = json.dumps({
                "botd": "spoofed",
                "timestamp": int(time.time() * 1000),
                "fingerprint": "Chrome124_Windows_1920x1080"
            }).encode('utf-8')
            
            aes_key = b"YOUR_REAL_AES_KEY_HERE_32_BYTES!!"
            aes_iv = secrets.token_bytes(12)
            aesgcm = AESGCM(aes_key)
            ciphertext = aesgcm.encrypt(aes_iv, botd_payload, None)
            encrypted_payload = base64.b64encode(aes_iv + ciphertext).decode('utf-8')
            
            ws.send(json.dumps({"type": "verify", "payload": encrypted_payload}))
            result = ws.recv()
            ws.close()
            
            data = json.loads(result)
            if "url" in data:
                return {"ok": True, "key": data["url"], "elapsed": round(time.time() - start_t, 2)}
            elif "destination" in data:
                return {"ok": True, "key": data["destination"], "elapsed": round(time.time() - start_t, 2)}
            else:
                return {"ok": False, "error": "WS_REJECTED", "message": str(result)}
        except Exception as inner_e:
            try: ws.close()
            except: pass
            return {"ok": False, "error": "WS_EXCEPTION", "message": str(inner_e)}
    except Exception as e:
        return {"ok": False, "error": "NETWORK_ERR", "message": str(e)}
