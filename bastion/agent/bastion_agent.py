#!/usr/bin/env python3
"""
Bastion sensor agent
=====================
Runs on each sensor (a box on the network running Suricata). It:

  1. Tails Suricata's eve.json and keeps recent 'alert' events in memory.
  2. Serves those alerts + the blocklist over a small HTTP API the console reads.
  3. In IPS mode, drops attacker IPs at the kernel with nftables (and can undo it).

This is the piece that turns the Bastion console from a demo into a real product.
The console's data layer (the makeAlert()/tick() functions) gets replaced by
polling this agent's /api/alerts endpoint.

Requirements:  Python 3.9+, Suricata installed and logging eve.json,
               nftables (for IPS blocking), and root (for nft commands).
Install:       pip install flask
Run:           sudo python3 bastion_agent.py --eve /var/log/suricata/eve.json --mode ips
"""

import argparse
import json
import os
import subprocess
import threading
import time
from collections import deque, Counter
from datetime import datetime, timezone

try:
    from flask import Flask, jsonify, request
except ImportError:
    raise SystemExit("Flask is required:  pip install flask")

# ---------------------------------------------------------------- config / state
app = Flask(__name__)

STATE = {
    "mode": "ids",                 # "ids" = detect only, "ips" = detect + block
    "alerts": deque(maxlen=2000),  # recent alert events
    "blocked": {},                 # ip -> {reason, since, sensor}
    "sensor": os.uname().nodename, # this sensor's name
    "sev_min_to_block": 2,         # auto-block severity <= this (1=crit,2=high) in IPS mode
}
LOCK = threading.Lock()

# Bastion's severity model is 1=critical … 4=low. Suricata alert.severity is
# 1=high … 3=low, so we normalise it here.
def normalize_severity(suri_sev: int) -> int:
    return {1: 1, 2: 2, 3: 3}.get(suri_sev, 4)

# ---------------------------------------------------------------- nftables blocking
def _nft(*args) -> bool:
    """Run an nft command; return True on success. Safe no-op if nft is missing."""
    try:
        subprocess.run(["nft", *args], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        print("[warn] nftables not found — running in detect-only (no real blocking)")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[warn] nft failed: {e.stderr.decode().strip()}")
        return False

def ensure_nft_setup():
    """Create a dedicated table+set so we never touch the user's other rules."""
    _nft("add", "table", "inet", "bastion")
    _nft("add", "set", "inet", "bastion", "blocklist",
         "{ type ipv4_addr; flags timeout; }")
    _nft("add", "chain", "inet", "bastion", "input",
         "{ type filter hook input priority -150; }")
    _nft("add", "rule", "inet", "bastion", "input",
         "ip saddr @blocklist drop")

def block_ip(ip: str, reason: str):
    with LOCK:
        if ip in STATE["blocked"]:
            return
        STATE["blocked"][ip] = {
            "reason": reason, "since": _now_iso(), "sensor": STATE["sensor"]
        }
    if STATE["mode"] == "ips":
        _nft("add", "element", "inet", "bastion", "blocklist", "{ " + ip + " }")
    print(f"[block] {ip} — {reason}")

def unblock_ip(ip: str):
    with LOCK:
        STATE["blocked"].pop(ip, None)
    _nft("delete", "element", "inet", "bastion", "blocklist", "{ " + ip + " }")
    print(f"[unblock] {ip}")

# ---------------------------------------------------------------- eve.json tailer
def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def tail_eve(path: str):
    """Follow eve.json like `tail -f`, surviving log rotation."""
    while not os.path.exists(path):
        print(f"[wait] {path} not found yet — waiting for Suricata…")
        time.sleep(3)

    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)  # start at the end; only new events
        inode = os.fstat(f.fileno()).st_ino
        while True:
            line = f.readline()
            if not line:
                # detect rotation
                try:
                    if os.stat(path).st_ino != inode:
                        f.close()
                        f = open(path, "r")
                        inode = os.fstat(f.fileno()).st_ino
                        continue
                except FileNotFoundError:
                    pass
                time.sleep(0.4)
                continue
            _handle_line(line)

def _handle_line(line: str):
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return
    if ev.get("event_type") != "alert":
        return

    a = ev.get("alert", {})
    sev = normalize_severity(a.get("severity", 3))
    alert = {
        "id": ev.get("flow_id", int(time.time() * 1000)),
        "sig": a.get("signature", "Unknown signature"),
        "cat": a.get("category", "Uncategorized"),
        "sev": sev,
        "src": ev.get("src_ip", "?"),
        "dst": ev.get("dest_ip", "?"),
        "port": ev.get("dest_port", 0),
        "sensor": STATE["sensor"],
        "time": ev.get("timestamp", _now_iso()),
        "blocked": False,
    }

    with LOCK:
        STATE["alerts"].append(alert)

    # IPS auto-block on high/critical
    if STATE["mode"] == "ips" and sev <= STATE["sev_min_to_block"]:
        block_ip(alert["src"], alert["sig"])
        alert["blocked"] = True

# ---------------------------------------------------------------- HTTP API
@app.get("/api/status")
def api_status():
    with LOCK:
        return jsonify({
            "sensor": STATE["sensor"], "mode": STATE["mode"],
            "alert_count": len(STATE["alerts"]), "blocked_count": len(STATE["blocked"]),
        })

@app.get("/api/alerts")
def api_alerts():
    limit = int(request.args.get("limit", 100))
    with LOCK:
        recent = list(STATE["alerts"])[-limit:][::-1]
        talkers = Counter(a["src"] for a in STATE["alerts"]).most_common(5)
    return jsonify({"alerts": recent, "top_talkers": talkers})

@app.get("/api/blocked")
def api_blocked():
    with LOCK:
        return jsonify([{"ip": ip, **info} for ip, info in STATE["blocked"].items()])

@app.post("/api/block")
def api_block():
    ip = (request.json or {}).get("ip")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    block_ip(ip, "Manual block from console")
    return jsonify({"ok": True, "ip": ip})

@app.post("/api/unblock")
def api_unblock():
    ip = (request.json or {}).get("ip")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    unblock_ip(ip)
    return jsonify({"ok": True, "ip": ip})

@app.post("/api/mode")
def api_mode():
    mode = (request.json or {}).get("mode", "ids").lower()
    if mode not in ("ids", "ips"):
        return jsonify({"error": "mode must be ids or ips"}), 400
    STATE["mode"] = mode
    if mode == "ips":
        ensure_nft_setup()
        # re-apply any existing blocks
        for ip in list(STATE["blocked"]):
            _nft("add", "element", "inet", "bastion", "blocklist", "{ " + ip + " }")
    return jsonify({"ok": True, "mode": mode})

# ---------------------------------------------------------------- main
def main():
    p = argparse.ArgumentParser(description="Bastion IDS/IPS sensor agent")
    p.add_argument("--eve", default="/var/log/suricata/eve.json",
                   help="path to Suricata eve.json")
    p.add_argument("--mode", choices=["ids", "ips"], default="ids")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8787)
    args = p.parse_args()

    STATE["mode"] = args.mode
    if args.mode == "ips":
        ensure_nft_setup()

    t = threading.Thread(target=tail_eve, args=(args.eve,), daemon=True)
    t.start()

    print(f"[bastion] sensor '{STATE['sensor']}' | mode={args.mode} | reading {args.eve}")
    print(f"[bastion] API on http://{args.host}:{args.port}  (point the console here)")
    app.run(host=args.host, port=args.port, threaded=True)

if __name__ == "__main__":
    main()
