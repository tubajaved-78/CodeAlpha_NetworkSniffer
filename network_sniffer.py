"""
=======================================================
  CodeAlpha Internship — Task 2: Basic Network Sniffer
  Author  : [Tuba Javed ]
  GitHub  : CodeAlpha_NetworkSniffer
=======================================================

Requirements:
    pip install scapy

Run with admin/root privileges:
    sudo python network_sniffer.py          # Linux/macOS
    python network_sniffer.py (as Admin)    # Windows
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, ARP, DNS, DNSQR
from datetime import datetime
import argparse
import sys


# ─────────────────────────────────────────────
#  Colour helpers (works on most terminals)
# ─────────────────────────────────────────────
class C:
    HEADER  = "\033[95m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


# ─────────────────────────────────────────────
#  Packet counter (global)
# ─────────────────────────────────────────────
stats = {"total": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0}


def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════╗
║        CodeAlpha — Basic Network Sniffer         ║
║             Task 2 | Cyber Security              ║
╚══════════════════════════════════════════════════╝
{C.RESET}""")


def get_protocol_name(packet) -> str:
    """Return a human-readable protocol label."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    elif packet.haslayer(ARP):
        return "ARP"
    else:
        return "Other"


def get_tcp_flags(tcp_layer) -> str:
    """Decode TCP flags into a readable string."""
    flags = []
    if tcp_layer.flags.S:  flags.append("SYN")
    if tcp_layer.flags.A:  flags.append("ACK")
    if tcp_layer.flags.F:  flags.append("FIN")
    if tcp_layer.flags.R:  flags.append("RST")
    if tcp_layer.flags.P:  flags.append("PSH")
    if tcp_layer.flags.U:  flags.append("URG")
    return "|".join(flags) if flags else "—"


def decode_payload(raw_bytes: bytes, max_len: int = 80) -> str:
    """Try to decode payload as UTF-8; fall back to hex."""
    try:
        text = raw_bytes.decode("utf-8", errors="ignore").strip()
        text = " ".join(text.split())          # collapse whitespace
        return text[:max_len] + ("…" if len(text) > max_len else "")
    except Exception:
        return raw_bytes.hex()[:max_len * 2]


def process_packet(packet):
    """Callback invoked for every captured packet."""
    stats["total"] += 1
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    proto = get_protocol_name(packet)
    stats[proto] += 1

    # ── IP-based packets ──────────────────────────────────────────────────
    if packet.haslayer(IP):
        src_ip  = packet[IP].src
        dst_ip  = packet[IP].dst
        ttl     = packet[IP].ttl
        ip_len  = packet[IP].len

        # ── TCP ──────────────────────────────────────────────────────────
        if packet.haslayer(TCP):
            tcp     = packet[TCP]
            flags   = get_tcp_flags(tcp)
            color   = C.GREEN

            print(f"{color}[{timestamp}] TCP  {src_ip}:{tcp.sport}  →  {dst_ip}:{tcp.dport}")
            print(f"           Flags: {flags} | TTL: {ttl} | Len: {ip_len} bytes{C.RESET}")

            # Show payload preview (e.g. HTTP)
            if packet.haslayer(Raw):
                payload = decode_payload(bytes(packet[Raw]))
                if payload:
                    print(f"           Payload: {C.YELLOW}{payload}{C.RESET}")

            # Detect HTTP
            if tcp.dport == 80 or tcp.sport == 80:
                print(f"           {C.CYAN}► HTTP traffic detected{C.RESET}")
            elif tcp.dport == 443 or tcp.sport == 443:
                print(f"           {C.CYAN}► HTTPS (TLS) traffic detected{C.RESET}")
            elif tcp.dport == 22 or tcp.sport == 22:
                print(f"           {C.CYAN}► SSH traffic detected{C.RESET}")
            elif tcp.dport == 21 or tcp.sport == 21:
                print(f"           {C.RED}► FTP traffic detected (unencrypted!){C.RESET}")

        # ── UDP ──────────────────────────────────────────────────────────
        elif packet.haslayer(UDP):
            udp   = packet[UDP]
            color = C.BLUE

            print(f"{color}[{timestamp}] UDP  {src_ip}:{udp.sport}  →  {dst_ip}:{udp.dport}")
            print(f"           TTL: {ttl} | Len: {ip_len} bytes{C.RESET}")

            # Detect DNS queries
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                dns_query = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                print(f"           {C.CYAN}► DNS Query: {dns_query}{C.RESET}")

        # ── ICMP ─────────────────────────────────────────────────────────
        elif packet.haslayer(ICMP):
            icmp  = packet[ICMP]
            types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable",
                     11: "Time Exceeded", 5: "Redirect"}
            icmp_type = types.get(icmp.type, f"Type {icmp.type}")
            color = C.RED

            print(f"{color}[{timestamp}] ICMP {src_ip}  →  {dst_ip}")
            print(f"           Type: {icmp_type} | TTL: {ttl}{C.RESET}")

    # ── ARP packets ──────────────────────────────────────────────────────
    elif packet.haslayer(ARP):
        arp   = packet[ARP]
        op    = "Request" if arp.op == 1 else "Reply"
        color = C.YELLOW

        print(f"{color}[{timestamp}] ARP  {arp.psrc} ({arp.hwsrc})  →  {arp.pdst}")
        print(f"           Operation: {op}{C.RESET}")

    # ── Unknown ──────────────────────────────────────────────────────────
    else:
        print(f"[{timestamp}] OTHER packet (len={len(packet)} bytes)")

    print()   # blank line for readability


def print_stats():
    """Print a summary of captured packets."""
    print(f"\n{C.BOLD}{C.HEADER}{'─'*50}")
    print("  Capture Summary")
    print(f"{'─'*50}{C.RESET}")
    print(f"  Total Packets : {stats['total']}")
    print(f"  TCP           : {stats['TCP']}")
    print(f"  UDP           : {stats['UDP']}")
    print(f"  ICMP          : {stats['ICMP']}")
    print(f"  ARP           : {stats['ARP']}")
    print(f"  Other         : {stats['Other']}")
    print(f"{C.BOLD}{C.HEADER}{'─'*50}{C.RESET}\n")


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="CodeAlpha Task 1 — Basic Network Sniffer"
    )
    parser.add_argument(
        "-i", "--interface",
        default=None,
        help="Network interface to sniff on (e.g. eth0, wlan0). Default: auto"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited, Ctrl+C to stop)"
    )
    parser.add_argument(
        "-f", "--filter",
        default="",
        help='BPF filter string (e.g. "tcp", "udp port 53", "icmp")'
    )
    args = parser.parse_args()

    print_banner()

    iface_msg = args.interface if args.interface else "default"
    count_msg = str(args.count) if args.count > 0 else "unlimited (Ctrl+C to stop)"
    filter_msg = args.filter if args.filter else "none (all traffic)"

    print(f"  Interface : {C.BOLD}{iface_msg}{C.RESET}")
    print(f"  Packets   : {C.BOLD}{count_msg}{C.RESET}")
    print(f"  Filter    : {C.BOLD}{filter_msg}{C.RESET}")
    print(f"\n  {C.YELLOW}Starting capture…{C.RESET}\n")
    print("─" * 60)

    try:
        sniff(
            iface=args.interface,
            prn=process_packet,
            count=args.count,
            filter=args.filter,
            store=False         # don't store in memory — saves RAM
        )
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Capture stopped by user.{C.RESET}")
    except PermissionError:
        print(f"\n{C.RED}[✗] Permission denied. Run as root/Administrator.{C.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{C.RED}[✗] Error: {e}{C.RESET}")
        sys.exit(1)
    finally:
        print_stats()


if __name__ == "__main__":
    main()
