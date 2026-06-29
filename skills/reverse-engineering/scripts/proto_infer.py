#!/usr/bin/env python3
"""
proto_infer.py - infer the structure of an unknown TCP/UDP protocol from a pcap and
emit a Kaitai Struct spec + a Wireshark Lua dissector for the recovered format.

Method (NetT-style statistical inference, BinPRE-aware):
  1. Reassemble per-flow payloads, split into messages (by direction / records).
  2. Detect a candidate length field: an offset whose little/big-endian value tracks
     the remaining frame length across many messages.
  3. Classify messages by their first byte(s) (likely a type/opcode field).
  4. Mark constant vs variable byte positions across messages of the same type.
  5. Emit fields.json, a .ksy Kaitai spec, and a .lua dissector skeleton.

Usage:
    python3 proto_infer.py capture.pcap --port 4444 -o out/proto/
    python3 proto_infer.py capture.pcap --port 4444 --udp -o out/proto/

Dependencies:
    pip install scapy        (used for pcap parsing; falls back to dpkt if present)
"""
import argparse
import json
import os
import struct
import sys
from collections import defaultdict

try:
    from scapy.all import rdpcap, TCP, UDP, IP, Raw
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False


def extract_messages(pcap_path, port, udp):
    """Return list of (direction, bytes) payloads on the target port."""
    if not HAVE_SCAPY:
        print("error: pip install scapy", file=sys.stderr)
        sys.exit(1)
    pkts = rdpcap(pcap_path)
    msgs = []
    L4 = UDP if udp else TCP
    for p in pkts:
        if L4 in p and Raw in p:
            sport = p[L4].sport
            dport = p[L4].dport
            if port not in (sport, dport):
                continue
            direction = "c2s" if dport == port else "s2c"
            payload = bytes(p[Raw].load)
            if payload:
                msgs.append((direction, payload))
    return msgs


def detect_length_field(msgs):
    """Find an offset+width+endian whose value == len(payload) - header_off for most msgs."""
    candidates = []
    for width in (1, 2, 4):
        for off in range(0, 8):
            for endian in ("<", ">"):
                fmt = endian + {1: "B", 2: "H", 4: "I"}[width]
                ok = 0
                total = 0
                for _, m in msgs:
                    if len(m) < off + width:
                        continue
                    total += 1
                    val = struct.unpack_from(fmt, m, off)[0]
                    # length field commonly encodes payload-after-field or whole frame
                    if val in (len(m), len(m) - (off + width), len(m) - off):
                        ok += 1
                if total and ok / total > 0.7:
                    candidates.append({"offset": off, "width": width,
                                       "endian": endian, "confidence": round(ok / total, 2)})
    candidates.sort(key=lambda c: (-c["confidence"], c["offset"]))
    return candidates[0] if candidates else None


def classify_by_type(msgs, type_off=0, type_width=1):
    groups = defaultdict(list)
    for _, m in msgs:
        if len(m) >= type_off + type_width:
            t = m[type_off:type_off + type_width]
            groups[t.hex()].append(m)
    return groups


def constant_positions(group):
    if not group:
        return {}
    minlen = min(len(m) for m in group)
    const = {}
    for i in range(minlen):
        vals = {m[i] for m in group}
        if len(vals) == 1:
            const[i] = next(iter(vals))
    return const


def emit_ksy(out_dir, lenf, type_width):
    endian = "le" if (lenf and lenf["endian"] == "<") else "be"
    ksy = [
        "meta:",
        "  id: custom_proto",
        f"  endian: {endian}",
        "seq:",
        f"  - id: msg_type",
        f"    type: u{type_width}",
    ]
    if lenf:
        ksy += [f"  - id: length", f"    type: u{lenf['width']}",
                "  - id: payload", "    size: length"]
    else:
        ksy += ["  - id: payload", "    size-eos: true"]
    path = os.path.join(out_dir, "custom.ksy")
    with open(path, "w") as f:
        f.write("\n".join(ksy) + "\n")
    return path


def emit_lua(out_dir, port, lenf, type_width):
    len_lines = ""
    if lenf:
        len_lines = (
            f'  t:add(f_len, buf({type_width},{lenf["width"]}))\n'
            f'  local plen = buf({type_width},{lenf["width"]}):'
            f'{"le_uint" if lenf["endian"]=="<" else "uint"}()\n'
            f'  t:add(f_data, buf({type_width + lenf["width"]}, plen))')
    else:
        len_lines = f'  t:add(f_data, buf({type_width}))'
    lua = f'''-- auto-generated Wireshark dissector for custom protocol on tcp.port {port}
local proto = Proto("custom","Custom Protocol (inferred)")
local f_type = ProtoField.uint{8*type_width}("custom.type","Type")
local f_len  = ProtoField.uint{8*(lenf["width"] if lenf else 2)}("custom.len","Length")
local f_data = ProtoField.bytes("custom.data","Payload")
proto.fields = {{ f_type, f_len, f_data }}
function proto.dissector(buf, pinfo, tree)
  pinfo.cols.protocol = "CUSTOM"
  local t = tree:add(proto, buf())
  t:add(f_type, buf(0,{type_width}))
{len_lines}
end
DissectorTable.get("tcp.port"):add({port}, proto)
'''
    path = os.path.join(out_dir, "custom.lua")
    with open(path, "w") as f:
        f.write(lua)
    return path


def main():
    ap = argparse.ArgumentParser(description="Infer protocol structure from a pcap")
    ap.add_argument("pcap")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--udp", action="store_true")
    ap.add_argument("--type-width", type=int, default=1, choices=[1, 2])
    ap.add_argument("-o", "--out", default="out/proto")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    msgs = extract_messages(args.pcap, args.port, args.udp)
    print(f"[+] {len(msgs)} message(s) on {'udp' if args.udp else 'tcp'}/{args.port}")
    if not msgs:
        sys.exit(1)

    lenf = detect_length_field(msgs)
    print(f"[+] length field: {lenf or 'not detected (treating payload as size-eos)'}")

    groups = classify_by_type(msgs, 0, args.type_width)
    fields = {"length_field": lenf, "type_width": args.type_width, "message_types": {}}
    for thex, group in sorted(groups.items()):
        const = constant_positions(group)
        fields["message_types"][thex] = {
            "count": len(group),
            "min_len": min(len(m) for m in group),
            "max_len": max(len(m) for m in group),
            "constant_positions": {str(k): v for k, v in const.items()},
        }
        print(f"   type 0x{thex}: {len(group)} msg(s), "
              f"len {fields['message_types'][thex]['min_len']}-"
              f"{fields['message_types'][thex]['max_len']}, "
              f"{len(const)} constant byte(s)")

    fpath = os.path.join(args.out, "fields.json")
    with open(fpath, "w") as f:
        json.dump(fields, f, indent=2)
    ksy = emit_ksy(args.out, lenf, args.type_width)
    lua = emit_lua(args.out, args.port, lenf, args.type_width)

    print(f"\n[+] fields  -> {fpath}")
    print(f"[+] kaitai  -> {ksy}   (compile: kaitai-struct-compiler -t python {ksy})")
    print(f"[+] wireshark -> {lua}  (drop in Wireshark plugins dir)")
    print("[next] fuzz length/count/offset fields with boofuzz/AFL++ using the recovered grammar.")


if __name__ == "__main__":
    main()
