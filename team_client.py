#!/usr/bin/env python3
"""
================================================================================
CYBER SENTINEL - HACKATHON TEAM REMOTE ATTACK & PACKET TRANSMITTER
Multi-Node Dual-Live Client for Hackathon Teammates
================================================================================
Run this script on ANY teammate's laptop or mobile machine connected to the
same Wi-Fi / Hotspot as the Cyber Sentinel server.

Usage:
  python team_client.py --server 192.168.1.50
  python team_client.py --server 10.117.226.23 --attack syn_flood
  python team_client.py --server 10.117.226.23 --interactive
================================================================================
"""

import sys
import os
import time
import json
import socket
import argparse
import urllib.request
import urllib.error
from typing import Dict, Any, List

try:
    import psutil
except Exception:
    psutil = None


class TeamRemoteClient:
    def __init__(self, server_ip: str, port: int = 8000):
        self.server_ip = server_ip
        self.port = port
        self.base_url = f"http://{server_ip}:{port}"

    def test_connection(self) -> bool:
        """Check if Cyber Sentinel server is reachable over Wi-Fi."""
        url = f"{self.base_url}/api/status"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "CyberSentinel-TeamClient/1.0"})
            with urllib.request.urlopen(req, timeout=3.0) as res:
                if res.status == 200:
                    data = json.loads(res.read().decode())
                    print(f"\n[+] Successfully connected to Cyber Sentinel Server at {self.base_url}!")
                    print(f"    Server Uptime: {data.get('uptime_sec', 0)}s | Total Alerts: {data.get('total_alerts', 0)}")
                    return True
        except Exception as e:
            print(f"\n[-] Failed to connect to {self.base_url}: {e}")
            print("    [!] Make sure both laptops are on the SAME Wi-Fi or Mobile Hotspot.")
            print(f"    [!] Check that Cyber Sentinel server is running with 'python run.py --web'.")
            return False
        return False

    def get_local_ip(self) -> str:
        """Return the local source IP used to reach the Cyber Sentinel server."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.server_ip, self.port))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"

    def send_remote_packet(self, pkt_dict: Dict[str, Any]) -> bool:
        """Send a synthetic or real frame directly into Cyber Sentinel's remote diode queue."""
        url = f"{self.base_url}/api/ingest-remote"
        try:
            payload = json.dumps(pkt_dict).encode("utf-8")
            req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=2.0) as res:
                return res.status == 200
        except Exception:
            return False

    def trigger_attack_scenario(self, attack_type: str) -> Dict[str, Any]:
        """Trigger multi-vector cyber attack simulation across the Wi-Fi link."""
        url = f"{self.base_url}/api/inject"
        payload = json.dumps({"attack_name": attack_type}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3.0) as res:
            return json.loads(res.read().decode())

    def launch_real_socket_port_scan(self, count: int = 25):
        """Fires genuine TCP socket connection attempts against Cyber Sentinel's open decoy ports."""
        target_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9000, 9200, 27017]
        print(f"\n[+] Launching LIVE TCP Port Scan from this laptop against {self.server_ip}...")
        swept = 0
        for port in target_ports[:count]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect_ex((self.server_ip, port))
                s.close()
                swept += 1
                print(f"    -> Probed TCP port {port:5d} ... OK")
                time.sleep(0.04)
            except Exception:
                pass
        print(f"[+] Swept {swept} ports! Check Cyber Sentinel dashboard for the PORT_SCAN_RECON alert!")

    def launch_real_dns_tunnel_simulation(self, domain_count: int = 10):
        """Sends real high-entropy DGA & DNS queries to the server."""
        print(f"\n[+] Transmitting High-Entropy DGA & Exfiltration DNS queries to {self.server_ip}...")
        domains = [
            "v3x89a1c90df03b418a.malicious-c2.net",
            "99f8e7d6c5b4a3.tunnel-exfil.org",
            "c3ZjcmV0X3Bhc3N3b3Jk.dns-leak.com",
            "d8f319ac7b8e14f092e3.dga-bot.biz",
            "aHR0cHM6Ly9leGZpbC5jb20=.covert.xyz"
        ]
        for d in domains:
            self.send_remote_packet({
                "src_ip": socket.gethostbyname(socket.gethostname()) if not socket.gethostname().startswith("127.") else "192.168.1.150",
                "dst_ip": self.server_ip,
                "src_port": 5353,
                "dst_port": 53,
                "protocol": "UDP",
                "size": 76,
                "dns_query": d
            })
            print(f"    -> Smuggled High-Entropy Query: {d}")
            time.sleep(0.1)
        print("[+] DNS Exfiltration queries transmitted!")

    def stream_live_connections(self, interval: float = 1.0, duration: float = 0.0):
        """Continuously stream real host connection metadata into the diode ingest API."""
        if psutil is None:
            print("\n[-] psutil is not installed. Install requirements first: pip install -r requirements.txt")
            return

        local_ip = self.get_local_ip()
        stop_at = time.monotonic() + duration if duration and duration > 0 else None
        total_sent = 0
        print(f"\n[+] Streaming live host connections from {local_ip} to {self.base_url}/api/ingest-remote")
        print("    Open a browser or run network tools on this laptop to feed fresh live flows. Press Ctrl+C to stop.")

        try:
            while True:
                if stop_at and time.monotonic() >= stop_at:
                    break

                sent_this_round = 0
                seen = set()
                try:
                    connections = psutil.net_connections(kind="inet")
                except Exception as e:
                    print(f"[-] Could not read live connections: {e}")
                    break

                for conn in connections:
                    if not conn.raddr:
                        continue

                    laddr = conn.laddr
                    raddr = conn.raddr
                    src_ip = getattr(laddr, "ip", laddr[0] if len(laddr) > 0 else local_ip)
                    src_port = getattr(laddr, "port", laddr[1] if len(laddr) > 1 else 0)
                    dst_ip = getattr(raddr, "ip", raddr[0] if len(raddr) > 0 else "")
                    dst_port = getattr(raddr, "port", raddr[1] if len(raddr) > 1 else 0)

                    if not dst_ip or dst_ip.startswith("127."):
                        continue
                    if dst_ip == self.server_ip and dst_port == self.port:
                        continue
                    if src_ip.startswith(("0.", "127.")):
                        src_ip = local_ip

                    protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    key = (src_ip, src_port, dst_ip, dst_port, protocol)
                    if key in seen:
                        continue
                    seen.add(key)

                    ok = self.send_remote_packet({
                        "timestamp": time.time(),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "size": 128,
                        "tcp_flags": {"ACK": True} if protocol == "TCP" else {},
                        "source": "team_client_live_connections"
                    })
                    if ok:
                        sent_this_round += 1
                        total_sent += 1

                print(f"    -> sent {sent_this_round:3d} live flow observations; total={total_sent}")
                time.sleep(max(interval, 0.2))
        except KeyboardInterrupt:
            pass

        print(f"[+] Live connection stream stopped. Total observations sent: {total_sent}")


def interactive_menu(client: TeamRemoteClient):
    print("=" * 70)
    print("   🛡️ CYBER SENTINEL - DUAL-NODE HACKATHON TEAM CLIENT")
    print(f"   Connected Server: {client.base_url}")
    print("=" * 70)
    
    while True:
        print("\nChoose an action to demonstrate live multi-node cyber defense:")
        print("  [1] ⚡ Send Live Volumetric TCP SYN Flood Attack")
        print("  [2] 📡 Send Live Botnet C2 Periodic Beaconing Heartbeats")
        print("  [3] 🚇 Send High-Entropy Covert DNS Tunneling & DGA Queries")
        print("  [4] 🔒 Send Cobalt Strike JA3 Encrypted Malware Handshake")
        print("  [5] 🔍 Launch Real Multi-Port TCP Scan against Server")
        print("  [6] 🚀 Stream This Laptop's Live Network Connections")
        print("  [7] ▶️ Start Server PCAP Replay Stream")
        print("  [8] 🛑 Stop Server PCAP Replay Stream")
        print("  [9] 🔄 Check Server Live Threat Telemetry")
        print("  [0] ❌ Exit")
        
        choice = input("\nEnter choice [0-9]: ").strip()
        
        if choice == "1":
            res = client.trigger_attack_scenario("syn_flood")
            print(f"[+] SYN Flood Injected! Result: {res}")
        elif choice == "2":
            res = client.trigger_attack_scenario("c2_beacon")
            print(f"[+] Botnet C2 Beaconing Injected! Result: {res}")
        elif choice == "3":
            client.launch_real_dns_tunnel_simulation()
        elif choice == "4":
            res = client.trigger_attack_scenario("tls_malware")
            print(f"[+] JA3 Encrypted Malware Injected! Result: {res}")
        elif choice == "5":
            client.launch_real_socket_port_scan()
        elif choice == "6":
            client.stream_live_connections(interval=1.0, duration=60.0)
        elif choice == "7":
            req = urllib.request.Request(f"{client.base_url}/api/stream/start?rate_pps=100", method="POST")
            with urllib.request.urlopen(req) as r:
                print(f"[+] Continuous Stream Started: {json.loads(r.read().decode())}")
        elif choice == "8":
            req = urllib.request.Request(f"{client.base_url}/api/stream/stop", method="POST")
            with urllib.request.urlopen(req) as r:
                print(f"[+] Continuous Stream Stopped: {json.loads(r.read().decode())}")
        elif choice == "9":
            client.test_connection()
        elif choice == "0":
            print("\nExiting. Good luck with the Hackathon presentation!")
            break
        else:
            print("[-] Invalid choice. Please select 0 to 8.")


def main():
    parser = argparse.ArgumentParser(description="Cyber Sentinel Hackathon Remote Team Client")
    parser.add_argument("--server", type=str, default="127.0.0.1", help="IP address of Cyber Sentinel Server (e.g. 192.168.1.50)")
    parser.add_argument("--port", type=int, default=8000, help="Port of Cyber Sentinel Server (default: 8000)")
    parser.add_argument("--attack", type=str, choices=["syn_flood", "c2_beacon", "dns_tunnel", "tls_malware", "port_scan"], help="Directly trigger an attack")
    parser.add_argument("--live", action="store_true", help="Continuously stream this laptop's real active connections into the diode API")
    parser.add_argument("--duration", type=float, default=0.0, help="Seconds to run --live; 0 means until Ctrl+C")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between live connection snapshots")
    parser.add_argument("--interactive", action="store_true", help="Launch interactive hackathon demo menu")
    args = parser.parse_args()

    client = TeamRemoteClient(args.server, args.port)
    if not client.test_connection():
        sys.exit(1)

    if args.live:
        client.stream_live_connections(interval=args.interval, duration=args.duration)
    elif args.attack:
        if args.attack == "port_scan":
            client.launch_real_socket_port_scan()
        elif args.attack == "dns_tunnel":
            client.launch_real_dns_tunnel_simulation()
        else:
            res = client.trigger_attack_scenario(args.attack)
            print(f"[+] Attack '{args.attack}' triggered successfully! Server response: {res}")
    else:
        interactive_menu(client)


if __name__ == "__main__":
    main()
