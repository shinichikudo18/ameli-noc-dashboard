#!/usr/bin/env python3
import argparse
import binascii
import json
import os
import socket
from datetime import datetime, timezone

OUT_DEFAULT = "/tmp/multiboost_snmp.json"

TRAP_OIDS = {
    "1.3.6.1.4.1.45401.2.0.0.1": "MultiboostInitializedNotification",
    "1.3.6.1.4.1.45401.2.0.0.2": "MultiboostMultipleOscillationNotification",
    "1.3.6.1.4.1.45401.2.0.0.3": "MultiboostBadIsolationNotification",
    "1.3.6.1.4.1.45401.2.0.0.4": "MultiboostNewFirmwareNotification",
    "1.3.6.1.4.1.45401.2.0.0.5": "MultiboostNewChannelListNotification",
}

OID_NAMES = {
    "1.3.6.1.4.1.45401.2.0.1.1": "MultiboostNotificationType",
    "1.3.6.1.4.1.45401.2.0.1.2": "MultiboostNotificationBand",
    "1.3.6.1.6.3.1.1.4.1.0": "snmpTrapOID",
}


def ensure_dir(path):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_length(buf, idx):
    first = buf[idx]
    idx += 1
    if first < 0x80:
        return first, idx
    n = first & 0x7F
    return int.from_bytes(buf[idx:idx + n], "big"), idx + n


def read_tlv(buf, idx):
    tag = buf[idx]
    idx += 1
    length, idx = read_length(buf, idx)
    value = buf[idx:idx + length]
    return tag, value, idx + length


def parse_integer(value):
    if not value:
        return 0
    return int.from_bytes(value, "big", signed=True)


def parse_oid(value):
    if not value:
        return ""
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    current = 0
    for b in value[1:]:
        current = (current << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(str(current))
            current = 0
    return ".".join(parts)


def parse_value(tag, value):
    if tag == 0x02:
        return parse_integer(value)
    if tag == 0x04:
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return binascii.hexlify(value).decode()
    if tag == 0x06:
        return parse_oid(value)
    if tag == 0x05:
        return None
    if tag == 0x40:
        return ".".join(str(b) for b in value)
    if tag == 0x41 or tag == 0x42 or tag == 0x46:
        return parse_integer(value)
    if tag == 0x43:
        return {"ticks": parse_integer(value), "seconds": round(parse_integer(value) / 100.0, 2)}
    return {"tag": hex(tag), "hex": binascii.hexlify(value).decode()}


def decode_varbinds(buf):
    idx = 0
    varbinds = []
    while idx < len(buf):
        tag, vb, idx = read_tlv(buf, idx)
        if tag != 0x30:
            continue
        j = 0
        oid_tag, oid_val, j = read_tlv(vb, j)
        if oid_tag != 0x06:
            continue
        val_tag, val_val, j = read_tlv(vb, j)
        oid = parse_oid(oid_val)
        varbinds.append({
            "oid": oid,
            "name": OID_NAMES.get(oid, oid),
            "value": parse_value(val_tag, val_val),
        })
    return varbinds


def parse_v2_packet(data):
    idx = 0
    tag, seq, idx = read_tlv(data, idx)
    if tag != 0x30:
        raise ValueError("not a sequence")
    j = 0
    ver_tag, ver_val, j = read_tlv(seq, j)
    version = parse_integer(ver_val)
    comm_tag, comm_val, j = read_tlv(seq, j)
    community = parse_value(comm_tag, comm_val)
    pdu_tag, pdu_val, j = read_tlv(seq, j)

    p = 0
    req_tag, req_val, p = read_tlv(pdu_val, p)
    _req = parse_value(req_tag, req_val)
    err_tag, err_val, p = read_tlv(pdu_val, p)
    _err = parse_value(err_tag, err_val)
    idx_tag, idx_val, p = read_tlv(pdu_val, p)
    _idx = parse_value(idx_tag, idx_val)
    vb_tag, vb_val, p = read_tlv(pdu_val, p)
    varbinds = decode_varbinds(vb_val) if vb_tag == 0x30 else []

    trap_oid = None
    notification_type = None
    band = None
    for vb in varbinds:
        if vb["oid"] == "1.3.6.1.6.3.1.1.4.1.0":
            trap_oid = vb["value"]
        elif vb["name"] == "MultiboostNotificationType":
            notification_type = vb["value"]
        elif vb["name"] == "MultiboostNotificationBand":
            band = vb["value"]

    trap_name = TRAP_OIDS.get(trap_oid, trap_oid or "unknown")
    return {
        "version": f"v{version}c" if version == 1 else f"v{version}",
        "community": community,
        "trap_oid": trap_oid or "-",
        "trap_name": trap_name,
        "notification_type": notification_type or "-",
        "band": band or "-",
        "varbinds": varbinds,
    }


def parse_v1_packet(data):
    idx = 0
    tag, seq, idx = read_tlv(data, idx)
    if tag != 0x30:
        raise ValueError("not a sequence")
    j = 0
    ver_tag, ver_val, j = read_tlv(seq, j)
    version = parse_integer(ver_val)
    comm_tag, comm_val, j = read_tlv(seq, j)
    community = parse_value(comm_tag, comm_val)
    pdu_tag, pdu_val, j = read_tlv(seq, j)
    p = 0
    enterprise_tag, enterprise_val, p = read_tlv(pdu_val, p)
    enterprise = parse_value(enterprise_tag, enterprise_val)
    agent_tag, agent_val, p = read_tlv(pdu_val, p)
    agent = parse_value(agent_tag, agent_val)
    gen_tag, gen_val, p = read_tlv(pdu_val, p)
    generic = parse_value(gen_tag, gen_val)
    spec_tag, spec_val, p = read_tlv(pdu_val, p)
    specific = parse_value(spec_tag, spec_val)
    time_tag, time_val, p = read_tlv(pdu_val, p)
    timeticks = parse_value(time_tag, time_val)
    vb_tag, vb_val, p = read_tlv(pdu_val, p)
    varbinds = decode_varbinds(vb_val) if vb_tag == 0x30 else []
    return {
        "version": f"v{version}c" if version == 1 else f"v{version}",
        "community": community,
        "trap_oid": f"{enterprise}.{specific}",
        "trap_name": f"v1-generic-{generic}",
        "notification_type": generic,
        "band": agent,
        "varbinds": varbinds,
        "timeticks": timeticks,
    }


def decode_snmp(data):
    tag, seq, idx = read_tlv(data, 0)
    if tag != 0x30:
        raise ValueError("not snmp")
    j = 0
    ver_tag, ver_val, j = read_tlv(seq, j)
    version = parse_integer(ver_val)
    if version == 0:
        return parse_v1_packet(data)
    if version == 1:
        return parse_v2_packet(data)
    raise ValueError(f"unsupported SNMP version {version}")


def format_event(src, decoded, raw_hex):
    event = {
        "timestamp": now_iso(),
        "source": src,
        "community": decoded.get("community", "-"),
        "version": decoded.get("version", "-"),
        "trap_oid": decoded.get("trap_oid", "-"),
        "trap_name": decoded.get("trap_name", "unknown"),
        "notification_type": decoded.get("notification_type", "-"),
        "band": decoded.get("band", "-"),
        "varbinds": decoded.get("varbinds", []),
        "raw_hex": raw_hex,
    }
    return event


def write_state(path, events):
    ensure_dir(path)
    payload = {
        "updated": now_iso(),
        "events": events[:100],
        "last": events[0] if events else None,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=162)
    parser.add_argument("--out", default=OUT_DEFAULT)
    args = parser.parse_args()

    ensure_dir(args.out)
    events = []
    if os.path.exists(args.out):
        try:
            with open(args.out, "r", encoding="utf-8") as f:
                current = json.load(f)
                events = current.get("events", [])
        except Exception:
            events = []
    write_state(args.out, events)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    print(f"Listening on {args.host}:{args.port}")

    while True:
        data, addr = sock.recvfrom(65535)
        try:
            decoded = decode_snmp(data)
            event = format_event(addr[0], decoded, binascii.hexlify(data).decode())
            events.insert(0, event)
            del events[100:]
            write_state(args.out, events)
            print(f"Trap from {addr[0]}: {event['trap_name']} {event['band']}")
        except Exception as e:
            err = {
                "timestamp": now_iso(),
                "source": addr[0],
                "community": "-",
                "version": "-",
                "trap_oid": "-",
                "trap_name": "parse-error",
                "notification_type": str(e),
                "band": "-",
                "varbinds": [],
                "raw_hex": binascii.hexlify(data).decode(),
            }
            events.insert(0, err)
            del events[100:]
            write_state(args.out, events)


if __name__ == "__main__":
    main()
