#!/usr/bin/env python3
import json, subprocess, sys

BASE = "http://localhost:8002"

def curl_json(path: str, payload: dict) -> dict:
    cmd = [
        "curl","-sS","-X","POST", f"{BASE}{path}",
        "-H","Content-Type: application/json",
        "-d", json.dumps(payload),
    ]
    out = subprocess.check_output(cmd).decode()
    return json.loads(out)

def main():
    decide = curl_json("/api/rtp/decide", {
        "tool_name": "read.me",
        "agent_id": "smoke",
        "signals": {"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99},
    })

    print("decision", decide.get("decision"))
    ticket = decide.get("ticket")
    if not ticket:
        print("NO_TICKET", file=sys.stderr)
        sys.exit(2)

    consume1 = curl_json("/api/rtp/consume", {"ticket": ticket, "tool_name": "read.me"})
    consume2 = curl_json("/api/rtp/consume", {"ticket": ticket, "tool_name": "read.me"})

    print("consume1", consume1)
    print("consume2", consume2)

if __name__ == "__main__":
    main()
