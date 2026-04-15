#!/usr/bin/env python3
import json
import subprocess
import os
from datetime import datetime, timedelta

API = "https://149.0.0.10:12443"
TOKEN = "58k4Hm09rzwrndzkzgrNfGp0qxyz80"
DATA_DIR = "/opt/forti_collector/data"
WEB_DIR = "/tmp"
RETENTION_DAYS = 60

VDOMS = ["root", "APN"]

ENDPOINTS = [
    "firewall/policy",
    "firewall/address",
    "firewall/addrgrp",
    "firewall/service/custom",
    "firewall/service/group",
    "system/interface",
    "router/static",
    "firewall/ippool",
    "firewall/vip",
    "user/local",
    "user/group",
    "vpn.ipsec/phase1-interface",
    "vpn.ipsec/phase2-interface",
]

MONITOR_ENDPOINTS = [
    "monitor/system/status",
    "monitor/system/interface",
    "monitor/firewall/session?count=1000&start=0",
    "monitor/firewall/session?count=1000&start=1000",
    "monitor/firewall/session?count=1000&start=2000",
    "monitor/firewall/session?count=1000&start=3000",
    "monitor/firewall/session?count=1000&start=4000",
    "monitor/router/ipv4",
    "monitor/vpn/ipsec",
    "monitor/system/ha-status",
    "monitor/system/resource/usage",
    "monitor/vpn/ipsec/phase1",
]

CMDB_ENDPOINTS = [
    "system/ha",
    "vpn.ipsec/phase1-interface",
    "vpn.ipsec/phase2-interface",
]

VPN_ENDPOINTS = [
    "vpn.ipsec/phase1-interface",
    "vpn.ipsec/phase2-interface",
]

os.makedirs(DATA_DIR, exist_ok=True)

def fetch_cmdb(endpoint, vdom):
    url = f"{API}/api/v2/cmdb/{endpoint}?vdom={vdom}"
    r = subprocess.run(
        ["curl", "-sk", "--max-time", "30", "-H", f"Authorization: Bearer {TOKEN}", url],
        capture_output=True, text=True
    )
    try:
        return json.loads(r.stdout)
    except:
        return {"error": str(r.stdout)[:200]}

def fetch_monitor(endpoint, vdom="root"):
    url = f"{API}/api/v2/{endpoint}?vdom={vdom}"
    r = subprocess.run(
        ["curl", "-sk", "--max-time", "30", "-H", f"Authorization: Bearer {TOKEN}", url],
        capture_output=True, text=True
    )
    try:
        return json.loads(r.stdout)
    except:
        return {"error": str(r.stdout)[:200]}

def fetch_cmdb_only(endpoint, vdom="root"):
    url = f"{API}/api/v2/cmdb/{endpoint}?vdom={vdom}"
    r = subprocess.run(
        ["curl", "-sk", "--max-time", "30", "-H", f"Authorization: Bearer {TOKEN}", url],
        capture_output=True, text=True
    )
    try:
        return json.loads(r.stdout)
    except:
        return {"error": str(r.stdout)[:200]}

def cleanup_old_files():
    cutoff = datetime.now() - timedelta(days=RETENTION_DAYS)
    for f in os.listdir(DATA_DIR):
        if f.endswith('.json'):
            path = os.path.join(DATA_DIR, f)
            mtime = datetime.fromtimestamp(os.path.getmtime(path))
            if mtime < cutoff:
                os.remove(path)
                print(f"Removed: {f}")

def save_snapshot():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    snapshot = {"timestamp": timestamp, "vdoms": {}, "system": {}}
    
    for vdom in VDOMS:
        snapshot["vdoms"][vdom] = {}
        for ep in ENDPOINTS:
            data = fetch_cmdb(ep, vdom)
            snapshot["vdoms"][vdom][ep] = data
        for ep in MONITOR_ENDPOINTS:
            data = fetch_monitor(ep, vdom)
            snapshot["vdoms"][vdom][ep] = data
    
    for ep in MONITOR_ENDPOINTS:
        data = fetch_monitor(ep, "root")
        snapshot["system"][ep] = data
    
    for ep in CMDB_ENDPOINTS:
        data = fetch_cmdb_only(ep, "root")
        snapshot["system"][ep] = data
    
    snapshot["system"]["vpn_monitor"] = {}
    for ep in ["monitor/vpn/ipsec", "monitor/vpn/ipsec/phase1"]:
        data = fetch_monitor(ep, "root")
        snapshot["system"]["vpn_monitor"][ep] = data
    
    filename = f"{DATA_DIR}/snapshot_{timestamp}.json"
    with open(filename, 'w') as f:
        json.dump(snapshot, f)
    
    latest_file = os.path.join(WEB_DIR, "latest.json")
    with open(latest_file, 'w') as f:
        json.dump(snapshot, f)
    
    print(f"Saved: {filename}")
    cleanup_old_files()

if __name__ == "__main__":
    save_snapshot()
