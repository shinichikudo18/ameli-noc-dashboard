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
STATE_FILE = "/tmp/interface_state.json"

VDOMS = ["root", "APN"]

os.makedirs(DATA_DIR, exist_ok=True)

def fetch(url):
    r = subprocess.run(
        ["curl", "-sk", "--max-time", "30", "-H", f"Authorization: Bearer {TOKEN}", url],
        capture_output=True, text=True
    )
    try:
        return json.loads(r.stdout)
    except:
        return {"error": str(r.stdout)[:200]}

def get_interface_stats():
    data = fetch(f"{API}/api/v2/monitor/system/interface?vdom=root")
    if "results" in data:
        return data["results"]
    return {}

def calculate_bandwidth(current_stats):
    if not os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'w') as f:
            json.dump({"timestamp": None, "interfaces": {}}, f)
    
    with open(STATE_FILE, 'r') as f:
        state = json.load(f)
    
    prev_time = state.get("timestamp")
    prev_interfaces = state.get("interfaces", {})
    current_time = datetime.now().timestamp()
    
    bandwidth_data = []
    
    for name, iface in current_stats.items():
        tx_bytes = iface.get("tx_bytes", 0)
        rx_bytes = iface.get("rx_bytes", 0)
        
        bw = {"name": name, "tx_bytes": tx_bytes, "rx_bytes": rx_bytes}
        
        if name in prev_interfaces and prev_time:
            dt = current_time - prev_time
            if dt > 0:
                prev_tx = prev_interfaces[name].get("tx_bytes", 0)
                prev_rx = prev_interfaces[name].get("rx_bytes", 0)
                bw["tx_rate"] = max(0, (tx_bytes - prev_tx) / dt)
                bw["rx_rate"] = max(0, (rx_bytes - prev_rx) / dt)
            else:
                bw["tx_rate"] = 0
                bw["rx_rate"] = 0
        else:
            bw["tx_rate"] = 0
            bw["rx_rate"] = 0
        
        bandwidth_data.append(bw)
    
    with open(STATE_FILE, 'w') as f:
        json.dump({"timestamp": current_time, "interfaces": {k: {"tx_bytes": v["tx_bytes"], "rx_bytes": v["rx_bytes"]} for k, v in current_stats.items()}}, f)
    
    return bandwidth_data

def cleanup_old_files():
    cutoff = datetime.now() - timedelta(days=RETENTION_DAYS)
    for f in os.listdir(DATA_DIR):
        if f.endswith('.json'):
            path = os.path.join(DATA_DIR, f)
            mtime = datetime.fromtimestamp(os.path.getmtime(path))
            if mtime < cutoff:
                os.remove(path)

def save_snapshot():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    snapshot = {"timestamp": timestamp, "vdoms": {}, "system": {}, "bandwidth": []}
    
    for vdom in VDOMS:
        snapshot["vdoms"][vdom] = {}
        endpoints = [
            "firewall/policy", "firewall/address", "firewall/addrgrp",
            "firewall/service/custom", "firewall/service/group", "system/interface",
            "router/static", "firewall/ippool", "firewall/vip",
            "user/local", "user/group",
            "vpn.ipsec/phase1-interface", "vpn.ipsec/phase2-interface",
        ]
        for ep in endpoints:
            data = fetch(f"{API}/api/v2/cmdb/{ep}?vdom={vdom}")
            snapshot["vdoms"][vdom][ep] = data
        
        session_endpoints = [
            f"monitor/system/session?count=1000&start=0",
            f"monitor/system/session?count=1000&start=1000",
            f"monitor/system/session?count=1000&start=2000",
            f"monitor/system/session?count=1000&start=3000",
            f"monitor/system/session?count=1000&start=4000",
        ]
        for ep in session_endpoints:
            data = fetch(f"{API}/api/v2/{ep}?vdom={vdom}")
            snapshot["vdoms"][vdom][ep] = data
    
    monitor_endpoints = [
        "monitor/system/status", "monitor/system/interface",
        "monitor/router/ipv4", "monitor/vpn/ipsec",
        "monitor/system/ha-status", "monitor/system/resource/usage",
        "monitor/vpn/ipsec/phase1",
    ]
    for ep in monitor_endpoints:
        data = fetch(f"{API}/api/v2/{ep}?vdom=root")
        snapshot["system"][ep] = data
    
    cmdb_endpoints = ["system/ha", "vpn.ipsec/phase1-interface", "vpn.ipsec/phase2-interface"]
    for ep in cmdb_endpoints:
        data = fetch(f"{API}/api/v2/cmdb/{ep}?vdom=root")
        snapshot["system"][ep] = data
    
    snapshot["system"]["vpn_monitor"] = {}
    for ep in ["monitor/vpn/ipsec", "monitor/vpn/ipsec/phase1"]:
        data = fetch(f"{API}/api/v2/{ep}?vdom=root")
        snapshot["system"]["vpn_monitor"][ep] = data
    
    interface_stats = get_interface_stats()
    snapshot["bandwidth"] = calculate_bandwidth(interface_stats)
    
    with open(os.path.join(WEB_DIR, "latest.json"), 'w') as f:
        json.dump(snapshot, f)
    
    print(f"Saved: {timestamp}")
    cleanup_old_files()

if __name__ == "__main__":
    save_snapshot()
