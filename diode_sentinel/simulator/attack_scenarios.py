"""
DiodeSentinel - Synthetic Attack Scenario Generators
Generates high-fidelity packet sequences for all 6 threat vectors
"""

import time
import random
import string
import struct
import socket
from typing import List
from diode_sentinel.engine.diode_ingest import DiodePacket
from diode_sentinel.engine.feature_extractor import FeatureExtractor
from diode_sentinel.models.threat_db import KNOWN_MALICIOUS_JA3


class AttackScenarios:
    """Generates synthetic DiodePacket bursts mimicking real-world APT & cyber attack campaigns."""

    @staticmethod
    def generate_benign_packet() -> DiodePacket:
        """Generate ordinary enterprise background traffic (HTTPS, DNS, SSH, Internal APIs)."""
        src_subnets = ["10.0.1.", "10.0.2.", "192.168.10."]
        src_ip = random.choice(src_subnets) + str(random.randint(10, 240))
        dst_ip = f"{random.randint(50, 180)}.{random.randint(1, 250)}.{random.randint(1, 250)}.{random.randint(1, 250)}"
        
        # 75% HTTPS, 15% DNS, 10% Other
        roll = random.random()
        now = time.time()
        
        if roll < 0.70:
            # Benign HTTPS Web Traffic
            src_port = random.randint(35000, 64000)
            dst_port = 443
            size = random.randint(64, 1460)
            tls_info = {
                "tls_version": "0x0303",
                "sni": random.choice(["api.github.com", "slack.com", "docs.google.com", "cdn.cloudflare.net", "login.microsoftonline.com"]),
                "ja3_hash": "b32309a26951912be7dba376398abc10",
                "ciphers_count": 16,
                "extensions_count": 12
            }
            return DiodePacket(
                timestamp=now,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="TCP",
                size=size,
                tcp_flags={"ack": True, "psh": True},
                tls_info=tls_info
            )
        elif roll < 0.88:
            # Benign DNS Resolution
            domain = random.choice(["google.com", "aws.amazon.com", "apple.com", "github.com", "wikipedia.org", "internal-auth.corp.local"])
            dns_info = FeatureExtractor.extract_dns_features(domain, "A")
            return DiodePacket(
                timestamp=now,
                src_ip=src_ip,
                src_port=random.randint(40000, 60000),
                dst_ip="8.8.8.8",
                dst_port=53,
                protocol="UDP",
                size=random.randint(60, 110),
                dns_info=dns_info
            )
        else:
            # Standard internal or HTTP / NTP traffic
            dst_port = random.choice([80, 123, 22, 8080])
            proto = "UDP" if dst_port == 123 else "TCP"
            return DiodePacket(
                timestamp=now,
                src_ip=src_ip,
                src_port=random.randint(30000, 60000),
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                size=random.randint(70, 800),
                tcp_flags={"ack": True} if proto == "TCP" else None
            )

    @staticmethod
    def generate_syn_flood(target_ip: str = "10.0.1.50", target_port: int = 443, count: int = 50) -> List[DiodePacket]:
        """Threat A1: High-rate TCP SYN Flood."""
        packets = []
        now = time.time()
        for i in range(count):
            # Spoofed source IPs
            src_ip = f"198.51.100.{random.randint(1, 254)}"
            src_port = random.randint(1024, 65530)
            packets.append(DiodePacket(
                timestamp=now + (i * 0.001),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=target_ip,
                dst_port=target_port,
                protocol="TCP",
                size=64,
                tcp_flags={"syn": True, "ack": False}
            ))
        return packets

    @staticmethod
    def generate_udp_reflection(target_ip: str = "10.0.1.50", count: int = 40) -> List[DiodePacket]:
        """Threat A2: High-volume NTP / DNS UDP reflection."""
        packets = []
        now = time.time()
        reflector_ip = "192.0.2.88"
        for i in range(count):
            packets.append(DiodePacket(
                timestamp=now + (i * 0.002),
                src_ip=reflector_ip,
                src_port=123,  # NTP monlist reflection
                dst_ip=target_ip,
                dst_port=random.randint(1024, 65000),
                protocol="UDP",
                size=1400  # Large amplified payload
            ))
        return packets

    @staticmethod
    def generate_c2_beacon(
        bot_ip: str = "10.0.1.105",
        c2_ip: str = "198.51.100.22",
        interval_sec: float = 3.0,
        beacon_count: int = 6
    ) -> List[DiodePacket]:
        """Threat B: Botnet C2 Beaconing with strict periodic inter-arrival."""
        packets = []
        now = time.time()
        for i in range(beacon_count):
            # Very small jitter (+- 0.02s)
            jitter = random.uniform(-0.03, 0.03)
            ts = now - ((beacon_count - 1 - i) * interval_sec) + jitter
            
            # Encrypted TLS C2 Beacon
            packets.append(DiodePacket(
                timestamp=ts,
                src_ip=bot_ip,
                src_port=49210,
                dst_ip=c2_ip,
                dst_port=443,
                protocol="TCP",
                size=random.choice([184, 212, 198]),
                tcp_flags={"ack": True, "psh": True}
            ))
        return packets

    @staticmethod
    def generate_dns_tunnel(source_ip: str = "10.0.1.77", count: int = 5) -> List[DiodePacket]:
        """Threat C1: Covert DNS Tunneling carrying Base64/Hex exfiltration payload in subdomains."""
        packets = []
        now = time.time()
        for i in range(count):
            # High-entropy random base64 / hex string
            payload_chunk = ''.join(random.choices(string.ascii_letters + string.digits, k=38))
            domain = f"{payload_chunk}.exfil-tunnel.darknet-c2.cc"
            dns_info = FeatureExtractor.extract_dns_features(domain, "TXT")
            
            packets.append(DiodePacket(
                timestamp=now + (i * 0.1),
                src_ip=source_ip,
                src_port=random.randint(40000, 60000),
                dst_ip="8.8.8.8",
                dst_port=53,
                protocol="UDP",
                size=128,
                dns_info=dns_info
            ))
        return packets

    @staticmethod
    def generate_dga_queries(source_ip: str = "10.0.1.77", count: int = 5) -> List[DiodePacket]:
        """Threat C2: Algorithmic DGA malware queries."""
        packets = []
        now = time.time()
        tlds = ["xyz", "biz", "top", "ru", "cc"]
        consonants = "bcdfghjklmnpqrstvwxyz"
        for i in range(count):
            # High consonant density pseudo-random string
            sub = ''.join(random.choices(consonants, k=14)) + ''.join(random.choices(string.digits, k=4))
            domain = f"{sub}.{random.choice(tlds)}"
            dns_info = FeatureExtractor.extract_dns_features(domain, "A")
            
            packets.append(DiodePacket(
                timestamp=now + (i * 0.08),
                src_ip=source_ip,
                src_port=random.randint(40000, 60000),
                dst_ip="1.1.1.1",
                dst_port=53,
                protocol="UDP",
                size=85,
                dns_info=dns_info
            ))
        return packets

    @staticmethod
    def generate_tls_malware_session(
        source_ip: str = "10.0.1.18",
        c2_ip: str = "203.0.113.89",
        malware_family: str = "Cobalt Strike"
    ) -> List[DiodePacket]:
        """Threat D: Malware Encrypted Session (Cobalt Strike / Emotet / AsyncRAT JA3)."""
        packets = []
        now = time.time()
        
        # Pick JA3 hash corresponding to family
        ja3_map = {
            "Cobalt Strike": "a0e9f5d64349fb13191bc781f81f42e1",
            "Emotet": "4d7a28d6f22da2d5ee1e847c20c0fef5",
            "AsyncRAT": "b32309a26951912be7dba376398abc3b",
            "RedLine Stealer": "6734f37431670b3ab4292b8f60f29984"
        }
        ja3_hash = ja3_map.get(malware_family, "a0e9f5d64349fb13191bc781f81f42e1")
        
        tls_info = {
            "tls_version": "0x0303",
            "sni": "",  # Hidden SNI / Direct IP
            "ja3_hash": ja3_hash,
            "ciphers_count": 14,
            "extensions_count": 8
        }
        
        # 1. TLS Client Hello Handshake packet
        packets.append(DiodePacket(
            timestamp=now,
            src_ip=source_ip,
            src_port=51420,
            dst_ip=c2_ip,
            dst_port=443,
            protocol="TCP",
            size=517,
            tcp_flags={"syn": True, "ack": True},
            tls_info=tls_info
        ))
        
        # 2. Subsequent Encrypted Command exchange packets
        for i in range(1, 8):
            packets.append(DiodePacket(
                timestamp=now + (i * 0.2),
                src_ip=source_ip,
                src_port=51420,
                dst_ip=c2_ip,
                dst_port=443,
                protocol="TCP",
                size=random.choice([140, 230, 185]),
                tcp_flags={"ack": True, "psh": True}
            ))
            
        return packets

    @staticmethod
    def generate_port_scan(
        scanner_ip: str = "10.0.1.99",
        target_ip: str = "10.0.1.200",
        scan_type: str = "vertical"
    ) -> List[DiodePacket]:
        """Threat E: Horizontal subnet sweep or vertical port scan."""
        packets = []
        now = time.time()
        
        if scan_type == "vertical":
            # Scanning 25 common ports
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9000, 27017]
            for i, p in enumerate(ports):
                packets.append(DiodePacket(
                    timestamp=now + (i * 0.02),
                    src_ip=scanner_ip,
                    src_port=random.randint(35000, 62000),
                    dst_ip=target_ip,
                    dst_port=p,
                    protocol="TCP",
                    size=60,
                    tcp_flags={"syn": True, "ack": False}
                ))
        else:
            # Horizontal sweep across 15 internal hosts on port 445 (SMB)
            for i in range(15):
                target = f"10.0.1.{10 + i}"
                packets.append(DiodePacket(
                    timestamp=now + (i * 0.03),
                    src_ip=scanner_ip,
                    src_port=random.randint(35000, 62000),
                    dst_ip=target,
                    dst_port=445,
                    protocol="TCP",
                    size=60,
                    tcp_flags={"syn": True, "ack": False}
                ))
                
        return packets

    @staticmethod
    def generate_data_exfiltration(
        source_ip: str = "10.0.1.44",
        dropzone_ip: str = "185.220.101.5",
        volume_mb: float = 3.5
    ) -> List[DiodePacket]:
        """Threat F: High-Volume Asymmetric Data Egress."""
        packets = []
        now = time.time()
        total_bytes = int(volume_mb * 1024 * 1024)
        bytes_sent = 0
        pkt_idx = 0
        
        while bytes_sent < total_bytes and pkt_idx < 40:
            chunk = 1460
            packets.append(DiodePacket(
                timestamp=now + (pkt_idx * 0.005),
                src_ip=source_ip,
                src_port=48920,
                dst_ip=dropzone_ip,
                dst_port=8443,
                protocol="TCP",
                size=chunk,
                tcp_flags={"ack": True, "psh": True}
            ))
            bytes_sent += chunk
            pkt_idx += 1
            
        # Give it a tiny 1KB inbound response to make asymmetry stark (3.5MB out vs 1KB in)
        packets.append(DiodePacket(
            timestamp=now + 0.1,
            src_ip=dropzone_ip,
            src_port=8443,
            dst_ip=source_ip,
            dst_port=48920,
            protocol="TCP",
            size=1024,
            tcp_flags={"ack": True}
        ))
        
        return packets
