import time
import json
import sys
from auth_client import extract_ticket, do_step, create_session, MIN_TICKET_LEN

POLL_MAX_ATTEMPTS = 10
POLL_INTERVAL = 0.1
MIN_STEP_GAP = 5.0
STEP_THROTTLE_RETRIES = 2
MAX_ROUNDS_HARD_CAP = 12

def solve_one(ticket, session=None, verbose=False):
    if len(ticket) < MIN_TICKET_LEN:
        return None, "ticket too short"
    if session is None:
        session = create_session()

    last_step_time = 0
    current_ticket = ticket

    for round_num in range(1, MAX_ROUNDS_HARD_CAP + 1):
        gap = time.time() - last_step_time
        if gap < MIN_STEP_GAP:
            time.sleep(MIN_STEP_GAP - gap)

        result = do_step(session, current_ticket)
        last_step_time = time.time()

        if not result.get("success"):
            msg = result.get("message", "")
            if "finishing checkpoints too fast" in msg:
                if verbose:
                    print(f"  [round {round_num}] throttled, retrying...")
                for _ in range(STEP_THROTTLE_RETRIES):
                    time.sleep(MIN_STEP_GAP)
                    result = do_step(session, current_ticket)
                    last_step_time = time.time()
                    if result.get("success"):
                        break
                if not result.get("success"):
                    return None, f"step failed after retry: {msg}"
            else:
                return None, f"step failed: {msg}"

        data = result.get("data", {})
        url = data.get("url")
        if url and url != "about:blank":
            new_ticket = extract_ticket(url)
            if new_ticket:
                current_ticket = new_ticket
                if verbose:
                    print(f"  [round {round_num}] new ticket: {current_ticket[:20]}...")
                continue

        status_url = f"https://auth.platorelay.com/api/session/status?ticket={current_ticket}"
        for attempt in range(POLL_MAX_ATTEMPTS):
            time.sleep(POLL_INTERVAL)
            try:
                sr = session.get(status_url, timeout=10)
                sres = sr.json()
            except Exception:
                continue
            key = (sres.get("data") or {}).get("key")
            if key and key != "KEY_NOT_FOUND":
                return key, None
            if "expired" in str(sres):
                return None, "expired"

        if verbose:
            print(f"  [round {round_num}] poll timeout, next round...")
        current_ticket = ticket

    return None, "max rounds exceeded"

def main():
    if len(sys.argv) < 2:
        print("usage: python main.py <auth_url>")
        sys.exit(1)
    url = sys.argv[1]
    try:
        ticket = extract_ticket(url)
    except ValueError as e:
        print(f"error: {e}")
        sys.exit(1)

    print(f"solving ticket: {ticket[:20]}...")
    start = time.time()
    key, error = solve_one(ticket, verbose=True)
    elapsed = time.time() - start

    if key:
        print(json.dumps({"key": key, "error": None, "times": f"{elapsed:.2f}s"}, ensure_ascii=False))
    else:
        print(json.dumps({"key": None, "error": error, "times": f"{elapsed:.2f}s"}, ensure_ascii=False))
        sys.exit(1)

if __name__ == "__main__":
    main()
